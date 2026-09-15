#!/bin/bash
# Name: 11-incident_reports.sh
# Purpose: Generate one bounded incident report per incident (incident_A.md,
#          incident_B.md, incident_C.md) conforming to the Locked Incident
#          Report Schema with enforced per-section caps: executive summary
#          3-5 sentences; timeline <= 15 one-line events; affected assets
#          <= 10 rows (HOST|CRITICALITY|DATA_CLASS|ZONE); IOCs <= 15 rows
#          (TYPE|VALUE|CONFIDENCE|SOURCE) with all IP addresses defanged as
#          a[.]b[.]c[.]d; ATT&CK mapping <= 8 techniques (TECHNIQUE|NAME|
#          EVIDENCE); detection performance (one line per rule that fired,
#          plus rules that should have fired but produced zero alerts in
#          the incident); recommended actions <= 6; evidence references
#          <= 12 event IDs. Content assembles mechanically from the three
#          investigation findings, incidents.json, assets.json, the IOC
#          feed, the alert queue, the Sigma catalog rule ids, and the
#          3x02 attack coverage map - no incident-specific values are
#          hardcoded. Every emitted event reference is verified in a single
#          streaming pass over the enriched event store (non-empty
#          enriched_events.jsonl preferred, falling back to
#          enriched_events.json). Exit is non-zero if any reference is
#          missing or any section cap is exceeded.
# Author: Steve - Cybersecurity Engineer
# Date: 15 September 2026

set -euo pipefail

err_trap() { printf '[report][ERROR] command failed at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'err_trap $LINENO $?' ERR

WS="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE not set}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR not set}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

F_A="$WS/investigations/incident_A.json"
F_B="$WS/investigations/incident_B.json"
F_C="$WS/investigations/incident_C_cli.json"
INC_FILE="$WS/alerts/incidents.json"
ASSET_FILE="$ASSETS/assets.json"
IOC_FILE="$ASSETS/ioc_feed.json"
ALERT_QUEUE="$WS/alerts/alert_queue.json"
COVERAGE_FILE="$CATALOG_DIR/coverage/attack_coverage.json"
RULES_DIR="$CATALOG_DIR/rules"
ENRICHED_JSONL="$WS/enriched/enriched_events.jsonl"
ENRICHED_JSON="$WS/enriched/enriched_events.json"
OUT_DIR="$WS/reports"

for f in "$F_A" "$F_B" "$F_C" "$INC_FILE" "$ASSET_FILE" "$IOC_FILE" "$ALERT_QUEUE"; do
    [[ -f "$f" && -s "$f" ]] || { printf '[report][ERROR] required input missing or empty: %s\n' "$f" >&2; exit 1; }
done

if [[ -s "$ENRICHED_JSONL" ]]; then
    ENRICHED_FILE="$ENRICHED_JSONL"
else
    ENRICHED_FILE="$ENRICHED_JSON"
fi
[[ -s "$ENRICHED_FILE" ]] || { printf '[report][ERROR] enriched events file not found\n' >&2; exit 1; }

mkdir -p "$OUT_DIR"

WS="$WS" F_A="$F_A" F_B="$F_B" F_C="$F_C" INC_FILE="$INC_FILE" \
ASSET_FILE="$ASSET_FILE" IOC_FILE="$IOC_FILE" ALERT_QUEUE="$ALERT_QUEUE" \
COVERAGE_FILE="$COVERAGE_FILE" RULES_DIR="$RULES_DIR" ENRICHED_FILE="$ENRICHED_FILE" \
OUT_DIR="$OUT_DIR" \
python3 - <<'PY'
import json
import os
import re
import sys
from collections import Counter

CAPS = {"timeline": 15, "assets": 10, "iocs": 15, "techniques": 8, "actions": 6, "refs": 12}
FINDING_FILES = {"A": os.environ["F_A"], "B": os.environ["F_B"], "C": os.environ["F_C"]}
OUT_DIR = os.environ["OUT_DIR"]
ENRICHED_FILE = os.environ["ENRICHED_FILE"]

IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def log(msg):
    print(f"[report] {msg}")


def fail(msg):
    print(f"[report][ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def defang(text):
    return IP_RE.sub(lambda m: m.group(1).replace(".", "[.]"), text)


# Embedded MITRE ATT&CK name table (taxonomy reference data, not incident
# specific). Augmented below by the 3x02 attack coverage map when present.
TECH_NAMES = {
    "T1005": "Data from Local System",
    "T1021": "Remote Services",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1078": "Valid Accounts",
    "T1078.002": "Domain Accounts",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1110": "Brute Force",
    "T1110.001": "Password Guessing",
    "T1110.003": "Password Spraying",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Windows Service",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1571": "Non-Standard Port",
}

# Technique-family -> evidence event category for the ATT&CK EVIDENCE column.
TECH_CATEGORY = {
    "T1110": "authentication",
    "T1078": "authentication",
    "T1021": "authentication",
    "T1543": "process",
    "T1053": "process",
    "T1547": "process",
    "T1059": "process",
    "T1071": "network",
    "T1041": "network",
    "T1571": "network",
}

ACTION_MAP = [
    (r"^T1110", "Reset credentials for targeted accounts and enforce MFA on remote access."),
    (r"^T1543\.003$", "Review and remove unauthorized Windows services on affected hosts."),
    (r"^T1053\.005$", "Audit scheduled tasks on affected hosts for persistence."),
    (r"^T1078", "Validate privileged account usage; disable accounts not tied to approved activity."),
    (r"^T1071\.001$", "Block identified C2 endpoints at the perimeter and monitor egress traffic."),
    (r"^T1041$", "Hunt for staged data and quantify egress volume before remediation."),
    (r"^T1021\.002$", "Restrict SMB administrative access between network zones."),
]


def classify_ioc(value):
    if re.fullmatch(r"[0-9a-fA-F]{32,64}", value or ""):
        return "hash"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value or ""):
        return "ip"
    if value and "." in value and " " not in value:
        return "domain"
    return "process/service"


def technique_name(tid):
    return TECH_NAMES.get(tid, "(name not in bundled taxonomy)")


def build_actions(techniques):
    actions = ["Escalate to Tier 2 with this report and the investigation finding artifacts."]
    for tid in techniques:
        for pat, action in ACTION_MAP:
            if re.match(pat, tid) and action not in actions:
                actions.append(action)
    actions.append("Preserve evidence: retain the event references listed below for forensic follow-up.")
    return actions[:CAPS["actions"]]


def build_report(letter, finding, inc, assets, event_asset, feed_by_value, feed_source,
                 alert_by_id, sig_map, coverage, coverage_names):
    inc_id = inc.get("incident_id", f"UNKNOWN-{letter}")
    hosts = inc.get("host_list", []) or []
    alert_ids = inc.get("alert_ids", []) or []
    evidence = finding.get("evidence", {}) or {}
    tl_all = sorted(evidence.get("timeline", []) or [], key=lambda e: e.get("timestamp", ""))
    techniques = finding.get("attack_techniques", []) or []

    # --- Executive Summary (3-5 sentences, composed) ------------------------
    tmo = finding.get("ticket_match_outcome")
    if isinstance(tmo, dict) and tmo.get("ticket_id"):
        ticket_sentence = (f"Activity aligned with change ticket {tmo.get('ticket_id')}, "
                           "so approved maintenance remains a possible explanation.")
    else:
        ticket_sentence = "No change ticket covered this activity, ruling out approved maintenance."
    hyp = finding.get("hypothesis", "").strip()
    if hyp and not hyp.endswith("."):
        hyp += "."
    sentences = [
        (f"Incident {inc_id} consolidated {len(alert_ids)} alert(s) across {len(hosts)} host(s) "
         f"between {inc.get('first_seen', 'unknown')} and {inc.get('last_seen', 'unknown')}."),
        (f"The Tier 1 investigation assessed this activity as {finding.get('verdict', 'unknown')} "
         f"with {finding.get('confidence', 'unknown')} confidence."),
        f"Hypothesis: {hyp}",
        ticket_sentence,
    ]
    exec_summary = " ".join(s for s in sentences if s)
    n_sent = len(re.findall(r"[.!?](?:\s|$)", exec_summary))
    if not (3 <= n_sent <= 5):
        fail(f"{letter}: executive summary has {n_sent} sentences (cap 3-5)")

    # --- Timeline -------------------------------------------------------------
    tl_rows = tl_all[:CAPS["timeline"]]
    for ev in tl_rows:
        desc = str(ev.get("raw_message") or ev.get("event_id") or "event")[:90]
        ev["_desc"] = f"{ev.get('event_category', 'event')}: {desc}"
    timeline_lines = [f"{ev.get('timestamp', '')} | {ev.get('hostname', '')} | {ev['_desc']}"
                      for ev in tl_rows]

    # --- Affected Assets -------------------------------------------------------
    asset_rows = []
    for h in hosts[:CAPS["assets"]]:
        inv = assets.get(h) or {}
        ea = event_asset.get(h) or {}
        asset_rows.append((
            h,
            inv.get("criticality") or ea.get("criticality") or "UNKNOWN",
            inv.get("data_class") or inv.get("data_classification") or "UNKNOWN",
            inv.get("zone") or ea.get("zone") or "UNKNOWN",
        ))

    # --- Indicators of Compromise ----------------------------------------------
    seen = set()
    ioc_vals = []
    for v in list(evidence.get("ioc_matches", []) or []) + list(inc.get("ioc_list", []) or []):
        if v and v not in seen:
            seen.add(v)
            ioc_vals.append(v)
    ioc_rows = []
    for v in ioc_vals[:CAPS["iocs"]]:
        feed_hit = feed_by_value.get(v)
        if feed_hit:
            conf, src = feed_hit.get("confidence", "unknown"), feed_source
        else:
            conf, src = "medium", "shift investigation"
        ioc_rows.append((classify_ioc(v), v, conf, src))

    # --- ATT&CK Mapping ----------------------------------------------------------
    tech_rows = []
    for tid in techniques[:CAPS["techniques"]]:
        cat = TECH_CATEGORY.get(tid.split(".")[0])
        n_ev = sum(1 for e in tl_all if e.get("event_category") == cat) if cat else 0
        cov = coverage.get(tid, {})
        det = cov.get("detected_by", [])
        if n_ev:
            ev_str = f"{n_ev} {cat} event(s) in evidence timeline"
        else:
            ev_str = "no direct events in retained timeline (see finding ambiguity notes)"
        if det:
            ev_str += f"; catalog coverage: {', '.join(det)}"
        tech_rows.append((tid, technique_name(tid), ev_str))

    # --- Detection Performance ---------------------------------------------------
    fired_titles = Counter()
    fired_files = set()
    resolved = 0
    for aid in alert_ids:
        a = alert_by_id.get(aid)
        if not a:
            continue
        rid = a.get("rule_id")
        title = a.get("rule_title") or (sig_map.get(rid, (None, None))[1]) or rid
        fired_titles[title] += 1
        if rid in sig_map:
            fired_files.add(sig_map[rid][0])
            resolved += 1
    perf_lines = [f"fired: {t} ({n} alert(s))" for t, n in fired_titles.most_common()]
    if resolved > 0 and coverage:
        cited = set()
        for tid in techniques:
            base = tid.split(".")[0]
            for c_tid, det in coverage.items():
                if c_tid == tid or c_tid.split(".")[0] == base:
                    for rule in det.get("detected_by", []):
                        if rule not in fired_files and rule not in cited:
                            cited.add(rule)
                            perf_lines.append(
                                f"did not fire: {rule} (catalog covers {c_tid}; zero alerts in this incident)")
    if not perf_lines:
        perf_lines = ["no rule attribution available for this incident"]

    # --- Recommended Actions / Evidence References -------------------------------
    actions = build_actions(techniques)
    refs = list(dict.fromkeys(finding.get("event_refs", []) or []))[:CAPS["refs"]]

    # --- Cap enforcement -----------------------------------------------------------
    counts = {"timeline": len(timeline_lines), "assets": len(asset_rows), "iocs": len(ioc_rows),
              "techniques": len(tech_rows), "actions": len(actions), "refs": len(refs)}
    for key, n in counts.items():
        if n > CAPS[key]:
            fail(f"{letter}: section {key} has {n} items (cap {CAPS[key]})")
    log(f"{letter}: timeline={counts['timeline']} assets={counts['assets']} IOCs={counts['iocs']} "
        f"techniques={counts['techniques']} actions={counts['actions']} refs={counts['refs']}")
    log(f"{letter}: section caps respected")

    # --- Assemble markdown ------------------------------------------------------
    lines = []
    lines.append(f"# Incident Report: {inc_id}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(defang(exec_summary))
    lines.append("")
    lines.append("## Timeline")
    lines.append("")
    lines.extend(defang(l) for l in timeline_lines)
    lines.append("")
    lines.append("## Affected Assets")
    lines.append("")
    lines.append("| HOST | CRITICALITY | DATA_CLASS | ZONE |")
    lines.append("|---|---|---|---|")
    lines.extend(f"| {h} | {c} | {d} | {z} |" for h, c, d, z in asset_rows)
    lines.append("")
    lines.append("## Indicators of Compromise")
    lines.append("")
    lines.append("| TYPE | VALUE | CONFIDENCE | SOURCE |")
    lines.append("|---|---|---|---|")
    lines.extend(f"| {t} | {defang(v)} | {c} | {s} |" for t, v, c, s in ioc_rows)
    lines.append("")
    lines.append("## ATT&CK Mapping")
    lines.append("")
    lines.append("| TECHNIQUE | NAME | EVIDENCE |")
    lines.append("|---|---|---|")
    lines.extend(f"| {t} | {n} | {defang(e)} |" for t, n, e in tech_rows)
    lines.append("")
    lines.append("## Detection Performance")
    lines.append("")
    lines.extend(defang(p) for p in perf_lines)
    lines.append("")
    lines.append("## Recommended Actions")
    lines.append("")
    for i, action in enumerate(actions, 1):
        lines.append(f"{i}. {action}")
    lines.append("")
    lines.append("## Evidence References")
    lines.append("")
    lines.extend(refs)
    lines.append("")

    out_path = os.path.join(OUT_DIR, f"incident_{letter}.md")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return refs


def main():
    inc_doc = load(os.environ["INC_FILE"])
    incidents = {inc["incident_id"][-1]: inc for inc in inc_doc.get("incidents", [])}

    assets_doc = load(os.environ["ASSET_FILE"])
    assets = {a["hostname"]: a for a in assets_doc.get("assets", []) if a.get("hostname")}

    feed_doc = load(os.environ["IOC_FILE"])
    feed_by_value = {i["value"]: i for i in feed_doc.get("iocs", []) if i.get("value")}
    feed_source = feed_doc.get("source", "ioc_feed.json")

    queue = load(os.environ["ALERT_QUEUE"])
    if isinstance(queue, dict):
        queue = queue.get("alerts", [])
    alert_by_id = {a.get("alert_id"): a for a in queue if isinstance(a, dict)}

    coverage = {}
    coverage_path = os.environ["COVERAGE_FILE"]
    if os.path.exists(coverage_path) and os.path.getsize(coverage_path) > 0:
        cov_doc = load(coverage_path)
        for tid, detail in (cov_doc.get("covered_techniques_detail") or {}).items():
            if isinstance(detail, dict):
                coverage[tid.upper()] = detail
                if detail.get("name"):
                    TECH_NAMES.setdefault(tid.upper(), detail["name"])

    # Sigma rule UUID -> (filename, title) from the catalog YAML id: lines.
    sig_map = {}
    rules_dir = os.environ["RULES_DIR"]
    if os.path.isdir(rules_dir):
        for root, _dirs, files in os.walk(rules_dir):
            for fn in sorted(files):
                if not fn.endswith(".yml"):
                    continue
                path = os.path.join(root, fn)
                rid = title = None
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            if line.startswith("id:"):
                                rid = line.split(":", 1)[1].strip()
                            elif line.startswith("title:") and title is None:
                                title = line.split(":", 1)[1].strip()
                            if rid and title:
                                break
                except OSError:
                    continue
                if rid:
                    sig_map[rid] = (fn, title)

    # Build event-embedded asset context (criticality/zone) from all findings'
    # timelines: covers hosts absent from the 8-entry asset inventory.
    event_asset = {}
    all_refs = []
    rendered = {}
    for letter in "ABC":
        path = FINDING_FILES[letter]
        if not (os.path.exists(path) and os.path.getsize(path) > 0):
            fail(f"finding file missing or empty: {path}")
        finding = load(path)
        if letter not in incidents:
            fail(f"incident -{letter} not found in incidents.json")
        inc = incidents[letter]
        for ev in (finding.get("evidence", {}) or {}).get("timeline", []) or []:
            host = ev.get("hostname")
            if host and host not in event_asset:
                ea = ev.get("asset") or {}
                if ea.get("criticality") or ea.get("zone"):
                    event_asset[host] = ea
        rendered[letter] = (finding, inc)

    for letter in "ABC":
        finding, inc = rendered[letter]
        log(f"generating incident_{letter}.md")
        refs = build_report(letter, finding, inc, assets, event_asset, feed_by_value,
                            feed_source, alert_by_id, sig_map, coverage, TECH_NAMES)
        all_refs.extend(refs)

    # --- Verify every emitted evidence reference exists in the enriched store ----
    # Single streaming pass; record-id set as O(1) hash lookup (grep -F prefilter
    # analog of the Task 10 fix: no index() membership over the full stream).
    wanted = set(all_refs)
    found = set()
    missing = []
    with open(os.environ["ENRICHED_FILE"], encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = rec.get("record_id")
            if rid in wanted:
                found.add(rid)
    missing = sorted(wanted - found)
    if missing:
        for rid in missing:
            print(f"[report][ERROR] evidence reference not in event store: {rid}", file=sys.stderr)
        fail(f"{len(missing)} evidence reference(s) missing from enriched events")
    log(f"{len(all_refs)} event references verified against {os.path.basename(os.environ['ENRICHED_FILE'])}")
    log("reports written")


main()
PY
