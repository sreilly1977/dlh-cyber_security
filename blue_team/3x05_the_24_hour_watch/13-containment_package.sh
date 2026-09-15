#!/bin/bash
# Name: 13-containment_package.sh
# Purpose: Produce the prioritized containment action list and the shareable
#          IOC package for the shift. Reads campaign_assessment.json for
#          cluster attribution, incidents.json for incident IDs and host
#          lists, and the three investigation findings for event timelines
#          and ioc_matches. Derives containment actions mechanically from
#          the findings: immediate (block confirmed feed IOC IPs at the
#          perimeter, isolate compromised hosts), short-term (reset
#          credentials for accounts identified in findings, audit services
#          matching IOC service-name patterns), medium-term (tighten
#          firewall rules for affected zones, deploy additional Sysmon
#          rules on affected hosts). Caps total actions at 12, validates
#          every cited incident_id exists in incidents.json, and words the
#          approval field to match the three approval tiers (no change
#          approval / standard change / architecture review). For the IOC
#          package, enumerates IP/domain/hash/account/service indicators
#          observed in the findings, defangs network indicators only,
#          computes per-indicator first/last-seen from the events where
#          each value was observed, and requires per-IOC event_ref
#          backing (timeline refs, falling back to the owning finding's
#          event_refs), exiting non-zero otherwise. Private/internal
#          addresses (RFC 1918 10/8, 172.16/12, 192.168/16, loopback,
#          link-local, multicast) are excluded from the shareable package;
#          the check is a manual octet test, NOT ipaddress.is_private,
#          because Python flags TEST-NET blocks (192.0.2.0/24,
#          198.51.100.0/24, 203.0.113.0/24) as private and this
#          environment's threat intel uses those ranges for external
#          adversary infrastructure.
# Author: Steve - Cybersecurity Engineer
# Date: 15 September 2026

set -euo pipefail

err_trap() { printf '[resp][ERROR] command failed at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'err_trap $LINENO $?' ERR

WS="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE not set}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR not set}"

CAMPAIGN_FILE="$WS/campaign/campaign_assessment.json"
INC_FILE="$WS/alerts/incidents.json"
F_A="$WS/investigations/incident_A.json"
F_B="$WS/investigations/incident_B.json"
F_C="$WS/investigations/incident_C_cli.json"
IOC_FEED="$ASSETS/ioc_feed.json"
ASSET_FILE="$ASSETS/assets.json"   # optional: zone lookup for firewall actions
OUT_CONTAINMENT="$WS/response/containment.json"
OUT_IOC="$WS/response/ioc_package.json"

for f in "$CAMPAIGN_FILE" "$INC_FILE" "$F_A" "$F_B" "$F_C" "$IOC_FEED"; do
    [[ -f "$f" && -s "$f" ]] || { printf '[resp][ERROR] required input missing or empty: %s\n' "$f" >&2; exit 1; }
done

# assets.json is optional: findings already handle absent inventory as UNKNOWN
[[ -f "$ASSET_FILE" && -s "$ASSET_FILE" ]] || ASSET_FILE=""

mkdir -p "$WS/response"

python3 - "$CAMPAIGN_FILE" "$INC_FILE" "$F_A" "$F_B" "$F_C" "$IOC_FEED" "$ASSET_FILE" \
    "$OUT_CONTAINMENT" "$OUT_IOC" <<'PY'
import json
import re
import sys
from datetime import datetime, timezone

# ---------- Section 1: constants and helpers ----------

MAX_ACTIONS = 12
MAX_CHARS = 160

IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{32,64}$")
DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")
PROCESS_FILE_RE = re.compile(r"^[A-Za-z0-9_.\- ]+\.(exe|dll|sys)$", re.IGNORECASE)

def log(msg):
    print(f"[resp] {msg}")

def fail(msg):
    print(f"[resp][ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def clip(text):
    if len(text) <= MAX_CHARS:
        return text
    return text[: MAX_CHARS - 3] + "..."

def is_shareable_ip(value):
    # Gate for the H-ISAC package: reject unambiguously internal/unusable
    # addresses. Deliberately NOT ipaddress.is_private (see header comment):
    # TEST-NET blocks are treated as external because the IOC feed uses
    # 198.51.100.0/24 and 203.0.113.0/24 for adversary infrastructure.
    if not IP_RE.fullmatch(value):
        return False
    o = [int(x) for x in value.split(".")]
    if o[0] == 10:
        return False
    if o[0] == 172 and 16 <= o[1] <= 31:
        return False
    if o[0] == 192 and o[1] == 168:
        return False
    if o[0] == 127:
        return False
    if o[0] == 169 and o[1] == 254:
        return False
    if o[0] >= 224:
        return False
    return True

def classify_value(value, feed_type_map):
    # Feed-known values take the feed's own type (authoritative).
    fv = value.strip()
    for cand, ftype in feed_type_map.items():
        if cand.lower() == fv.lower():
            return ftype
    # Heuristics for shift-discovered values only.
    if IP_RE.fullmatch(value):
        return "ip"
    if HEX_RE.fullmatch(value):
        return "hash"
    if PROCESS_FILE_RE.fullmatch(value):
        return "service_name"
    if value.isdigit():
        return "port"
    if "@" in value or "\\" in value:
        return "account"
    if DOMAIN_RE.fullmatch(value):
        return "domain"
    if fv.lower().startswith(("svc_", "med_")):
        return "account"
    return "service_name"

# ---------- Section 2: load inputs ----------

def main(campaign_path, inc_path, fa_path, fb_path, fc_path, feed_path,
         asset_path, out_containment, out_ioc):

    log("loading campaign_assessment and incidents")
    campaign = load(campaign_path)
    incidents_doc = load(inc_path)
    feed_doc = load(feed_path)

    incident_recs = {}
    for rec in incidents_doc.get("incidents", []):
        iid = rec.get("incident_id")
        if iid:
            incident_recs[iid] = rec
    if not incident_recs:
        fail("incidents.json contains no incident records")

    cluster_id = campaign.get("cluster_id", "unknown")
    shift_id = campaign.get("shift_id") or "SHIFT-20260401"

    feed_entries = [e for e in (feed_doc.get("iocs") or []) if e.get("value")]
    feed_values = {e["value"] for e in feed_entries}
    feed_conf = {e["value"]: e.get("confidence", "medium") for e in feed_entries}
    feed_type = {e["value"].lower(): e.get("type", "service_name") for e in feed_entries}
    feed_accounts = {e["value"].lower() for e in feed_entries if e.get("type") == "account"}
    feed_services = {e["value"].lower() for e in feed_entries if e.get("type") == "service_name"}

    findings = []
    for path in (fa_path, fb_path, fc_path):
        f = load(path)
        iid = f.get("incident_id")
        if not iid:
            fail(f"finding {path} has no incident_id")
        if iid not in incident_recs:
            fail(f"finding {path} cites incident_id not in incidents.json: {iid}")
        findings.append(f)

    zone_map = {}
    if asset_path:
        try:
            assets = load(asset_path)
            for a in assets.get("assets", []):
                h = a.get("hostname")
                if h:
                    zone_map[h] = a.get("zone", "UNKNOWN")
        except (OSError, json.JSONDecodeError):
            pass  # absent inventory is a documented gap; zones degrade to UNKNOWN

    # ---------- Section 3: collect IOC observations from the findings ----------

    def evidence_of(f):
        ev = f.get("evidence")
        return ev if isinstance(ev, dict) else {}

    def ioc_matches_of(f):
        vals = []
        for holder in (evidence_of(f), f):
            v = holder.get("ioc_matches")
            if isinstance(v, list):
                vals.extend(x for x in v if isinstance(x, str))
        seen = set()
        out = []
        for v in vals:
            if v not in seen:
                seen.add(v)
                out.append(v)
        return out

    def timeline_of(f):
        tl = evidence_of(f).get("timeline") or f.get("timeline") or []
        return [e for e in tl if isinstance(e, dict)]

    observations = {}

    def observe(value, inc_id, ts=None, ref=None):
        if not value or not isinstance(value, str):
            return
        obs = observations.setdefault(value, {"incidents": [], "times": [], "refs": []})
        if inc_id not in obs["incidents"]:
            obs["incidents"].append(inc_id)
        if ts:
            obs["times"].append(ts)
        if ref:
            obs["refs"].append(ref)

    for f in findings:
        inc_id = f["incident_id"]
        # feed-matched indicators seen in this finding
        for value in ioc_matches_of(f):
            observe(value, inc_id)
        # timeline-derived indicators, each carrying its event ref and time
        for ev in timeline_of(f):
            ts = ev.get("timestamp")
            rid = ev.get("record_id") or ev.get("event_ref")
            dst = ev.get("dst_ip")
            if dst and is_shareable_ip(dst):
                observe(dst, inc_id, ts, rid)
            src = ev.get("src_ip")
            if src and is_shareable_ip(src):
                observe(src, inc_id, ts, rid)
            proc = ev.get("process_name")
            if isinstance(proc, str) and proc:
                base = proc.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                if base.lower() in feed_services:
                    observe(base, inc_id, ts, rid)
            usr = ev.get("user")
            if isinstance(usr, str) and (usr.lower() in feed_accounts
                                       or usr.lower().startswith(("svc_", "med_"))):
                observe(usr, inc_id, ts, rid)

    # ---------- Section 4: build the IOC package ----------

    iocs = []
    for value in sorted(observations.keys()):
        obs = observations[value]
        in_feed = value in feed_values
        ftype = classify_value(value, feed_type)

        times = sorted(t for t in obs["times"] if t)
        refs = list(dict.fromkeys(r for r in obs["refs"] if r))
        # Traceability fallback: the owning finding's event_refs
        if not refs:
            for f in findings:
                if f.get("incident_id") in obs["incidents"]:
                    refs.extend(r for r in (f.get("event_refs") or [])
                                if isinstance(r, str) and r)
        if not refs:
            fail(f"IOC {value} has no event_ref backing for traceability")

        inc_id = obs["incidents"][0] if obs["incidents"] else "unknown"
        inc_rec = incident_recs.get(inc_id, {})
        first_seen = times[0] if times else (inc_rec.get("first_seen") or "unknown")
        last_seen = times[-1] if times else (inc_rec.get("last_seen") or "unknown")

        display = value.replace(".", "[.]") if ftype in ("ip", "domain") else value
        confidence = feed_conf.get(value, "medium") if in_feed else "medium"

        iocs.append({
            "type": ftype,
            "value": display,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "incident_id": inc_id,
            "source": "ioc_feed" if in_feed else "shift_discovered",
            "confidence": confidence
        })

    ip_count = sum(1 for i in iocs if i["type"] == "ip")
    domain_count = sum(1 for i in iocs if i["type"] == "domain")
    hash_count = sum(1 for i in iocs if i["type"] == "hash")
    account_count = sum(1 for i in iocs if i["type"] == "account")
    service_count = sum(1 for i in iocs if i["type"] == "service_name")
    new_count = sum(1 for i in iocs if i["source"] == "shift_discovered")

    # ---------- Section 5: build containment actions ----------

    actions = []
    action_counter = 1
    priority_order = {"immediate": 0, "short_term": 1, "medium_term": 2}

    for f in findings:
        inc_id = f["incident_id"]
        inc_rec = incident_recs.get(inc_id, {})
        hosts = (inc_rec.get("host_list") or [])[:4]
        matches = ioc_matches_of(f)
        techniques = f.get("attack_techniques") or []

        # Immediate: block confirmed feed IOC IPs at the perimeter
        for val in matches[:2]:
            if IP_RE.fullmatch(val) and val in feed_values and is_shareable_ip(val):
                actions.append({
                    "action_id": f"ACT-{action_counter:03d}",
                    "priority": "immediate",
                    "action": clip(f"Block IP {val} at perimeter firewall (confirmed HC-RED7 IOC)"),
                    "target_type": "ip",
                    "target_value": val.replace(".", "[.]"),
                    "incident_id": inc_id,
                    "operational_impact": clip("External traffic to this IP blocked; monitor for legitimate service disruption."),
                    "requires_approval_from": "SOC Manager on-call (no change approval required)"
                })
                action_counter += 1

        # Immediate: isolate confirmed compromised hosts
        for host in hosts[:2]:
            actions.append({
                "action_id": f"ACT-{action_counter:03d}",
                "priority": "immediate",
                "action": clip(f"Isolate host {host} from network pending forensic examination"),
                "target_type": "host",
                "target_value": host,
                "incident_id": inc_id,
                "operational_impact": clip("Host removed from production; business operations may be disrupted."),
                "requires_approval_from": "SOC Manager on-call (no change approval required)"
            })
            action_counter += 1

        # Short-term: credential reset when valid-account abuse is in play
        if any("T1078" in t for t in techniques):
            actions.append({
                "action_id": f"ACT-{action_counter:03d}",
                "priority": "short_term",
                "action": clip(f"Reset credentials for accounts identified in {inc_id} findings (T1078 valid accounts)"),
                "target_type": "user",
                "target_value": "svc_* and med_* accounts in findings",
                "incident_id": inc_id,
                "operational_impact": clip("Service account sessions invalidated; scheduled tasks may fail until redeployed."),
                "requires_approval_from": "Identity Management team (standard change approval)"
            })
            action_counter += 1

        # Short-term: audit services matching IOC service-name patterns
        svc_targets = [v for v in matches if v.lower() in feed_services]
        if svc_targets:
            actions.append({
                "action_id": f"ACT-{action_counter:03d}",
                "priority": "short_term",
                "action": clip(f"Audit service accounts matching IOC service patterns: {', '.join(svc_targets[:2])}"),
                "target_type": "service",
                "target_value": ", ".join(svc_targets[:2]),
                "incident_id": inc_id,
                "operational_impact": clip("Service audit may require maintenance windows if persistence is confirmed."),
                "requires_approval_from": "Identity Management team (standard change approval)"
            })
            action_counter += 1

        # Medium-term: zone firewall review
        zone = zone_map.get(hosts[0], "UNKNOWN") if hosts else "UNKNOWN"
        actions.append({
            "action_id": f"ACT-{action_counter:03d}",
            "priority": "medium_term",
            "action": clip(f"Review and tighten outbound firewall rules for the {zone} zone ({inc_id})"),
            "target_type": "rule",
            "target_value": "outbound_traffic_control",
            "incident_id": inc_id,
            "operational_impact": clip("May restrict legitimate egress; requires app team coordination for whitelist exceptions."),
            "requires_approval_from": "Security Architecture Review Board"
        })
        action_counter += 1

        # Medium-term: additional Sysmon rules on affected hosts
        for host in hosts[:1]:
            actions.append({
                "action_id": f"ACT-{action_counter:03d}",
                "priority": "medium_term",
                "action": clip(f"Deploy additional Sysmon rules on host {host}"),
                "target_type": "host",
                "target_value": host,
                "incident_id": inc_id,
                "operational_impact": clip("Minimal performance impact; additional logging increases storage requirements."),
                "requires_approval_from": "Endpoint Security team"
            })
            action_counter += 1

    actions.sort(key=lambda a: (priority_order.get(a["priority"], 99), a["action_id"]))
    actions = actions[:MAX_ACTIONS]

    for action in actions:
        if action["incident_id"] not in incident_recs:
            fail(f"action cites incident_id not in incidents.json: {action['incident_id']}")

    imm = sum(1 for a in actions if a["priority"] == "immediate")
    short = sum(1 for a in actions if a["priority"] == "short_term")
    med = sum(1 for a in actions if a["priority"] == "medium_term")

    # ---------- Section 6: summary and outputs (spec log order) ----------

    log(f"actions: immediate={imm} short_term={short} medium_term={med} total={len(actions)}")
    log(f"IOCs: ip={ip_count} domain={domain_count} hash={hash_count} "
        f"account={account_count} service={service_count} total={len(iocs)}")
    log(f"newly discovered (not in feed): {new_count}")
    log("all IOCs traced to events: OK")

    with open(out_containment, "w", encoding="utf-8") as fh:
        json.dump({"shift_id": shift_id, "generated_at": now_iso(), "actions": actions},
                  fh, indent=2)
        fh.write("\n")
    log("containment.json written")

    with open(out_ioc, "w", encoding="utf-8") as fh:
        json.dump({"shift_id": shift_id, "tlp": "AMBER", "cluster_id": cluster_id,
                   "generated_at": now_iso(), "iocs": iocs},
                  fh, indent=2)
        fh.write("\n")
    log("ioc_package.json written")

if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) != 9:
        print(f"[resp][ERROR] expected 9 file arguments, got {len(args)}", file=sys.stderr)
        sys.exit(1)
    main(*args)
PY

exit 0
