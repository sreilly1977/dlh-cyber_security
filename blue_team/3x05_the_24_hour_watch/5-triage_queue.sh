#!/bin/bash
# Name: 5-triage_queue.sh
# Purpose: Triage the full capstone alert queue with the 3x03 batch
#          methodology. Stages a capstone triage package (queue, enriched
#          events, baseline, asset inventory, IOC context) and redirects the
#          env-driven 3x03 batch scripts (2-context_assembly through
#          10-fp_tuning, plus TRIAGE_BIN itself for final incident assembly)
#          onto it. Ticket batches are then folded into the locked
#          triage_log.jsonl schema:
#            - classification vocabulary: true_positive->TP,
#              false_positive->FP, benign->NOISE (fatal on unknown vocab)
#            - representation policy (mirrors 11-incident_assembly.sh):
#              batch 6 incident membership governs member disposition;
#              otherwise batch 7 > 1 > 5 > 4 > 2 > 3 ticket precedence
#            - change tickets from shift_briefing.json set
#              change_ticket_match only on host match AND timestamp inside
#              [window_start, window_end]; host-match/window-miss is
#              annotated, never silently downgraded
#          Missing 3x03 context files are synthesized from capstone
#          equivalents (ioc_feed.json -> ioc_context.json with indicators
#          keyed by value per 2-context_assembly's collect_iocs contract,
#          assets.json -> asset_inventory, blanked management CIDRs).
#          Validates full coverage: zero unclassified alerts, schema
#          conformance, count integrity.
# Author: Steve - Cybersecurity Engineer
# Date: 14 September 2026

set -u

log() { printf '[triage] %s\n' "$*"; }
die() { printf '[triage][ERROR] %s\n' "$*" >&2; exit 1; }

for var in SHIFT_WORKSPACE ASSETS_DIR TRIAGE_BIN; do
    if [[ -z "${!var:-}" ]]; then
        die "environment variable $var is not set - source the environment contract first"
    fi
done

QUEUE_FILE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
BRIEFING_FILE="$SHIFT_WORKSPACE/alerts/shift_briefing.json"
LOG_FILE="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"

CAPSTONE_ASSETS="$ASSETS_DIR"
BATCH_DIR="$(cd "$(dirname "$(readlink -f "$TRIAGE_BIN")")" && pwd)"

STAGE="$SHIFT_WORKSPACE/triage_stage"
BATCH_LOG_DIR="$STAGE/logs"

for f in "$QUEUE_FILE" "$BRIEFING_FILE"; do
    [[ -f "$f" ]] || die "required input missing: $f"
done
[[ -d "$BATCH_DIR" ]] || die "3x03 batch directory not found: $BATCH_DIR"
for s in 2-context_assembly 3-triage_clearcut_tp 4-triage_clearcut_fp \
         5-triage_benign 6-triage_ambiguous_auth 7-triage_ambiguous_proc_net \
         8-triage_correlation 9-triage_priority_conflicts; do
    [[ -f "$BATCH_DIR/$s.sh" ]] || die "batch script missing: $BATCH_DIR/$s.sh"
done

alert_count=$(jq 'length' "$QUEUE_FILE")
(( alert_count > 0 )) || die "alert queue is empty: $QUEUE_FILE"
ioc_count=$(jq -r '.ioc_count // 0' "$BRIEFING_FILE")
ticket_count=$(jq -r '.active_change_tickets | length' "$BRIEFING_FILE")

log "alert_queue: $alert_count alerts"
log "briefing loaded ($ioc_count IOCs, $ticket_count change tickets)"

# ---------------------------------------------------------------------------
# Stage the capstone triage package. Discovery is overridable via env vars
# (EVENTS_SRC, BASELINE_SRC, INVENTORY_SRC, RULES_SRC, PRIMITIVES_SRC,
# ZONES_SRC); each adapter falls back gracefully and reports what it chose
# into $STAGE/staging_report.json.
# ---------------------------------------------------------------------------
rm -rf "$STAGE"
mkdir -p "$STAGE/logs" "$STAGE/catalog/alerts" "$STAGE/handoff/context" \
         "$STAGE/handoff/data" "$STAGE/baseline/baselines" "$STAGE/ioc" \
         "$STAGE/tickets"

cp "$QUEUE_FILE" "$STAGE/catalog/alerts/alert_queue.json"

stage_report=$(python3 - "$STAGE" "$SHIFT_WORKSPACE" "$CAPSTONE_ASSETS" \
    "$BRIEFING_FILE" << 'STAGE_PY'
import datetime
import glob
import json
import os
import shutil
import sys

stage, workspace, assets_dir, briefing_path = sys.argv[1:5]

report = {}

def find_one(patterns, env_key):
    override = os.environ.get(env_key)
    if override:
        return override, "env override"
    for pat in patterns:
        hits = sorted(glob.glob(os.path.join(workspace, "**", pat), recursive=True))
        hits = [h for h in hits if "/triage_stage/" not in h]
        if hits:
            return hits[0], "discovered"
    return None, "missing"

# --- enriched events ------------------------------------------------------
events_src, how = find_one(["enriched/enriched_events.json"], "EVENTS_SRC")
if not events_src:
    sys.exit("could not locate enriched_events.json - set EVENTS_SRC")
shutil.copy(events_src, os.path.join(stage, "handoff/data/enriched_events.json"))
report["events"] = {"src": events_src, "how": how}

# --- baseline summary -----------------------------------------------------
baseline_src, how = find_one(
    ["**/baseline_summary.json", "enriched/baseline.json"], "BASELINE_SRC")
if not baseline_src:
    sys.exit("could not locate baseline - set BASELINE_SRC")
shutil.copy(baseline_src, os.path.join(stage, "baseline/baselines/baseline_summary.json"))
report["baseline"] = {"src": baseline_src, "how": how}

# --- asset inventory ------------------------------------------------------
def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

def pick(d, *subs):
    for k, v in d.items():
        kl = k.lower()
        if any(s in kl for s in subs):
            return v
    return None

inventory_src, how = find_one(["**/asset_inventory.json"], "INVENTORY_SRC")
if inventory_src:
    shutil.copy(inventory_src, os.path.join(stage, "handoff/context/asset_inventory.json"))
    report["inventory"] = {"src": inventory_src, "how": how}
else:
    raw = load(os.path.join(assets_dir, "assets.json"))
    entries = raw.get("assets", raw) if isinstance(raw, dict) else raw
    if isinstance(entries, dict):
        entries = list(entries.values())
    inventory = []
    for a in entries:
        if not isinstance(a, dict):
            continue
        hostname = pick(a, "hostname", "host_name", "host")
        crit = pick(a, "criticality", "critical")
        dclass = pick(a, "data_class", "classification")
        zone = pick(a, "network_zone", "zone_id", "zone")
        if hostname is None:
            continue
        inventory.append({
            "hostname": str(hostname).lower(),
            "criticality": (str(crit).upper() if crit else "UNKNOWN"),
            "data_classification": (str(dclass).lower() if dclass else "internal"),
            "network_zone": zone if zone else "UNKNOWN",
        })
    if not inventory:
        sys.exit("assets.json adaptation failed - set INVENTORY_SRC to the "
                 "capstone asset inventory")
    out = os.path.join(stage, "handoff/context/asset_inventory.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"assets": inventory}, fh, indent=2)
        fh.write("\n")
    report["inventory"] = {"src": assets_dir + "/assets.json (synthesized)",
                           "how": "adapter", "assets": len(inventory)}

# --- network zones --------------------------------------------------------
zones_src, how = find_one(["**/network_zones.json"], "ZONES_SRC")
zones_out = os.path.join(stage, "handoff/context/network_zones.json")
if zones_src:
    shutil.copy(zones_src, zones_out)
    report["zones"] = {"src": zones_src, "how": how}
else:
    template_path = os.path.expanduser(
        "~/3x00_handoff/evidence_handoff/context/network_zones.json")
    if os.path.exists(template_path):
        zones = load(template_path)

        def blank_cidrs(node):
            if isinstance(node, list):
                if any(isinstance(x, str) and "/" in x for x in node):
                    return []
                return [blank_cidrs(x) for x in node]
            if isinstance(node, dict):
                return {k: blank_cidrs(v) for k, v in node.items()}
            return node

        zones = blank_cidrs(zones)
        how = "template with CIDRs blanked (management_subnet FP disabled)"
    else:
        zones = {"zones": []}
        how = "minimal stub"
    with open(zones_out, "w", encoding="utf-8") as fh:
        json.dump(zones, fh, indent=2)
        fh.write("\n")
    report["zones"] = {"how": how}

# --- rules directory (Sigma YAMLs for tactic tags) ------------------------
rules_env = os.environ.get("RULES_SRC")
if rules_env:
    rules_src, how = rules_env, "env override"
else:
    hits = []
    rules_src, how = None, "missing"
    for root in (workspace, os.path.expanduser("~/3x02_package")):
        hits = sorted(glob.glob(os.path.join(root, "**", "*.yml"), recursive=True))
        hits = [h for h in hits if "/triage_stage/" not in h]
        if hits:
            rules_src, how = os.path.dirname(hits[0]), "discovered"
            break
if rules_src:
    rules_dst = os.path.join(stage, "catalog/rules")
    os.makedirs(rules_dst, exist_ok=True)
    yamls = [y for y in glob.glob(os.path.join(rules_src, "*"))
             if y.endswith((".yml", ".yaml"))]
    for y in yamls:
        os.symlink(y, os.path.join(rules_dst, os.path.basename(y)))
    report["rules"] = {"src": rules_src, "how": how, "count": len(yamls)}
else:
    os.makedirs(os.path.join(stage, "catalog/rules"), exist_ok=True)
    report["rules"] = {"how": "EMPTY - batch 3 tactic tags unavailable"}

# --- correlation primitives (optional evidence chains) --------------------
prim_env = os.environ.get("PRIMITIVES_SRC")
prim_primary = os.path.expanduser("~/3x02_package/correlation_primitives.json")
if prim_env:
    prim, how = prim_env, "env override"
elif os.path.exists(prim_primary):
    prim, how = prim_primary, "primary package (capstone ids will not match - no-op)"
else:
    prim, how = None, "missing"
if prim:
    report["primitives"] = {"src": prim, "how": how}
else:
    with open(os.path.join(stage, "catalog/correlation_primitives.json"),
              "w", encoding="utf-8") as fh:
        fh.write("{}\n")
    prim = os.path.join(stage, "catalog/correlation_primitives.json")
    report["primitives"] = {"how": "empty stub"}
report["primitives_path"] = prim

# --- IOC context (ioc_feed.json -> ioc_context.json shape) ----------------
# Contract (from 2-context_assembly.py): ioc_doc["indicators"] must be a
# DICT keyed by indicator value; each entry is a dict with reputation,
# categories, etc. collect_iocs does indicators.get(indicator).
feed_path = os.path.join(assets_dir, "ioc_feed.json")
if not os.path.exists(feed_path):
    sys.exit("ioc_feed.json not found in $ASSETS_DIR")
feed = load(feed_path)

def walk_iocs(node, out):
    if isinstance(node, list):
        for item in node:
            walk_iocs(item, out)
    elif isinstance(node, dict):
        val = None
        typ = None
        for k, v in node.items():
            kl = k.lower()
            if kl in ("value", "indicator", "ioc"):
                val = v
            elif kl in ("type", "indicator_type", "ioc_type"):
                typ = v
        if isinstance(val, str) and val:
            out.append((typ or "unknown", val))
            return
        for v in node.values():
            walk_iocs(v, out)

pairs = []
walk_iocs(feed, pairs)
if not pairs:
    sys.exit("no IOC indicators extracted from ioc_feed.json")

CATEGORY_BY_TYPE = {
    "ip": ["c2"], "domain": ["c2"], "hash": [],
    "account": ["valid_accounts"], "service_name": [], "port": [],
}

indicators = {}
for typ, value in pairs:
    if value in indicators:
        continue
    indicators[value] = {
        "reputation": "malicious",
        "ioc_flag": True,
        "categories": CATEGORY_BY_TYPE.get(str(typ).lower(), []),
        "indicator_type": typ,
        "notes": "HC-RED7 advisory indicator",
        "first_seen": "2026-03-25T00:00:00Z",
        "last_seen": "2026-04-07T23:59:59Z",
        "source_feeds": ["hc-red7-advisory"],
    }

ioc_context = {
    "version": "1.0",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"),
    "description": "HC-RED7 IOC context staged for capstone triage",
    "indicators": indicators,
}

with open(os.path.join(stage, "ioc/ioc_context.json"), "w", encoding="utf-8") as fh:
    json.dump(ioc_context, fh, indent=2)
    fh.write("\n")
report["ioc_context"] = {"indicators": len(indicators),
                        "shape": "dict keyed by indicator value",
                        "types": sorted({t for t, _ in pairs})}

with open(os.path.join(stage, "staging_report.json"), "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")

print(json.dumps({"primitives_path": report["primitives_path"],
                  "ioc_indicators": len(indicators)}))
STAGE_PY
) || die "staging failed - see errors above (env overrides: EVENTS_SRC, BASELINE_SRC, INVENTORY_SRC, RULES_SRC, ZONES_SRC, PRIMITIVES_SRC)"

prim_path=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["primitives_path"])' <<<"$stage_report")

export TRIAGE_PKG="$STAGE"
export CATALOG_DIR="$STAGE/catalog"
export HANDOFF_DIR="$STAGE/handoff"
export BASELINE_PKG="$STAGE/baseline"
export ASSETS_DIR="$STAGE/ioc"
export PRIMITIVES_JSON="$prim_path"
export CLEARCUT_BANDS="critical,high,medium,low"

run_batch() {
    local name="$1"
    local log_f="$BATCH_LOG_DIR/${name%.sh}.log"
    if ! bash "$BATCH_DIR/$name" >"$log_f" 2>&1; then
        tail -20 "$log_f" >&2
        die "$name failed - full log: $log_f"
    fi
}

log "invoking $TRIAGE_BIN"

run_batch 2-context_assembly.sh
run_batch 3-triage_clearcut_tp.sh
run_batch 4-triage_clearcut_fp.sh
run_batch 5-triage_benign.sh
run_batch 6-triage_ambiguous_auth.sh
run_batch 7-triage_ambiguous_proc_net.sh
run_batch 8-triage_correlation.sh
run_batch 9-triage_priority_conflicts.sh
if ! bash "$BATCH_DIR/10-fp_tuning.sh" >"$BATCH_LOG_DIR/10-fp_tuning.log" 2>&1; then
    log "WARNING: fp_tuning failed (non-fatal) - see $BATCH_LOG_DIR/10-fp_tuning.log"
fi

# Final incident assembly via the entry point itself (staged package)
if ! bash "$TRIAGE_BIN" >"$BATCH_LOG_DIR/triage_sh.log" 2>&1; then
    log "WARNING: TRIAGE_BIN incident assembly failed (non-fatal) - see $BATCH_LOG_DIR/triage_sh.log"
fi

log "classifying $alert_count alerts"

# ---------------------------------------------------------------------------
# Fold ticket batches into triage_log.jsonl
# ---------------------------------------------------------------------------
: > "$LOG_FILE"

fold_result=$(python3 - "$QUEUE_FILE" "$BRIEFING_FILE" "$STAGE" "$LOG_FILE" << 'FOLD_PY'
import datetime
import json
import sys

queue_path, briefing_path, stage, log_path = sys.argv[1:5]

with open(queue_path, encoding="utf-8") as fh:
    queue = json.load(fh)
if isinstance(queue, dict):
    queue = queue.get("alerts", [])
with open(briefing_path, encoding="utf-8") as fh:
    briefing = json.load(fh)

CLASS_MAP = {
    "true_positive": "TP",
    "false_positive": "FP",
    "benign": "NOISE",
    "benign_activity": "NOISE",
    "monitor": "TP",
}

BATCH_FILES = [
    ("batch7_overrides.json", 1),
    ("batch1_clearcut_tp.json", 2),
    ("batch5_proc_net.json", 3),
    ("batch4_auth.json", 4),
    ("batch2_clearcut_fp.json", 5),
    ("batch3_benign.json", 6),
]

def norm_host(h):
    return str(h).replace("-", "").replace("_", "").lower() if h else None

# direct tickets by alert_id, precedence-ordered
direct = {}
for fname, prec in sorted(BATCH_FILES, key=lambda x: x[1]):
    path = "{}/tickets/{}".format(stage, fname)
    try:
        with open(path, encoding="utf-8") as fh:
            tickets = json.load(fh)
    except (OSError, json.JSONDecodeError):
        continue
    if not isinstance(tickets, list):
        continue
    for t in tickets:
        if not isinstance(t, dict):
            continue
        aid = t.get("alert_id")
        if aid and aid not in direct:
            t["_prec"] = prec
            direct[aid] = t

# incident membership from batch 6 (correlation incidents)
incident_of = {}
incident_tickets = {}
try:
    with open(stage + "/tickets/batch6_incidents.json", encoding="utf-8") as fh:
        incidents = json.load(fh)
    if isinstance(incidents, list):
        for inc in incidents:
            if not isinstance(inc, dict):
                continue
            iid = inc.get("ticket_id") or inc.get("incident_id")
            for aid in inc.get("contributing_alerts", []) or []:
                incident_of[aid] = iid
            if iid:
                incident_tickets[iid] = inc
except (OSError, json.JSONDecodeError):
    pass

# change tickets: exact host + window containment
change_tickets = []
for ct in briefing.get("active_change_tickets", []):
    hosts = {norm_host(h) for h in (ct.get("hosts") or [])}
    change_tickets.append({
        "ticket_id": ct.get("ticket_id"),
        "hosts": hosts,
        "window_start": ct.get("window_start") or "",
        "window_end": ct.get("window_end") or "",
    })

hot_hosts = set()
for hh in briefing.get("baseline_hot_hosts", []):
    if isinstance(hh, dict):
        hot_hosts.add(norm_host(hh.get("hostname") or hh.get("host")))
    else:
        hot_hosts.add(norm_host(hh))

SEVERITIES = {"critical", "high", "medium", "low"}

def alert_fields(a):
    es = a.get("event_summary") or {}
    host = a.get("host") or es.get("hostname") or es.get("host")
    user = (a.get("user") or es.get("user") or es.get("username")
            or a.get("account") or es.get("account"))
    ts = es.get("timestamp") or a.get("timestamp")
    sev = a.get("severity") or es.get("severity") or a.get("priority_band") \
        or a.get("rule_level")
    if sev is not None:
        sev = str(sev).lower()
    if sev not in SEVERITIES:
        sev = "medium"
    return (str(host).lower() if host else None,
            user if isinstance(user, str) else None,
            str(ts) if ts else None,
            sev)

def truncate(note, limit=200):
    note = " ".join(str(note).split())
    if len(note) <= limit:
        return note
    return note[: limit - 3] + "..."

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

counts = {"TP": 0, "FP": 0, "NOISE": 0}
unknown_vocab = set()
records_written = 0

for a in queue:
    aid = a.get("alert_id")
    host, user, ts, sev = alert_fields(a)
    rule_id = a.get("rule_id") or (a.get("rule") or {}).get("id")

    # authoritative ticket: incident membership > direct precedence chain
    ticket = None
    if aid in incident_of and incident_of[aid] in incident_tickets:
        ticket = incident_tickets[incident_of[aid]]
    if ticket is None:
        ticket = direct.get(aid)

    cls_label = None
    matches_ioc = []
    baseline_dev = False
    note_parts = []

    if ticket is not None:
        cls = str(ticket.get("classification", "")).strip().lower()
        if cls not in CLASS_MAP:
            unknown_vocab.add(cls)
            continue
        cls_label = CLASS_MAP[cls]
        for hit in ticket.get("ioc_hits", []) or []:
            ind = hit.get("indicator") if isinstance(hit, dict) else None
            if ind and ind not in matches_ioc:
                matches_ioc.append(ind)
        just = ticket.get("justification") or ticket.get("reason") or ""
        baseline_dev = "baseline" in just.lower() or (
            host is not None and norm_host(host) in hot_hosts
        )
        if just:
            note_parts.append(just)
        if ticket.get("grouped") or aid in incident_of:
            note_parts.append(
                "grouped into incident {}".format(incident_of.get(aid)))
    else:
        continue  # uncovered alert - surfaced by validation below

    # change-ticket cross-reference: host AND timestamp containment
    change_match = None
    partial = False
    if host and ts:
        nh = norm_host(host)
        for ct in change_tickets:
            if nh in ct["hosts"]:
                if ct["window_start"] <= ts <= ct["window_end"]:
                    change_match = ct["ticket_id"]
                    break
                partial = True
    if change_match and cls_label == "TP":
        note_parts.append(
            "NOTE: host+time inside approved change window {} - "
            "verify expected activity before escalation".format(change_match))
    if partial and cls_label == "FP":
        note_parts.append(
            "host appears in a change ticket but event time is outside the "
            "approved window - not closed as routine")

    note = "; ".join(note_parts) if note_parts else "no ticket note"
    rec = {
        "alert_id": aid,
        "rule_id": rule_id,
        "host": host,
        "user": user,
        "classification": cls_label,
        "severity": sev,
        "matches_ioc": matches_ioc,
        "baseline_deviation": bool(baseline_dev),
        "change_ticket_match": change_match,
        "analyst_note": truncate(note),
        "classified_at": now,
    }
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    counts[cls_label] = counts.get(cls_label, 0) + 1
    records_written += 1

print(json.dumps({
    "tp": counts.get("TP", 0),
    "fp": counts.get("FP", 0),
    "noise": counts.get("NOISE", 0),
    "records_written": records_written,
    "queue_total": len(queue),
    "unknown_vocab": sorted(unknown_vocab),
}))
FOLD_PY
) || die "ticket folding failed"

# ---------------------------------------------------------------------------
# Validation: coverage, schema, unclassified count
# ---------------------------------------------------------------------------
stats=$(python3 - "$QUEUE_FILE" "$LOG_FILE" << 'VAL_PY'
import json
import sys

queue_path, log_path = sys.argv[1:3]
with open(queue_path, encoding="utf-8") as fh:
    queue = json.load(fh)
if isinstance(queue, dict):
    queue = queue.get("alerts", [])
expected = {a.get("alert_id") for a in queue}

REQUIRED = ("alert_id", "rule_id", "host", "user", "classification",
            "severity", "matches_ioc", "baseline_deviation",
            "change_ticket_match", "analyst_note", "classified_at")
VALID = {"TP", "FP", "NOISE"}

seen = {}
errors = []
counts = {"TP": 0, "FP": 0, "NOISE": 0}
with open(log_path, encoding="utf-8", errors="replace") as fh:
    for lineno, line in enumerate(fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append("line {}: invalid JSON ({})".format(lineno, exc))
            continue
        missing = [k for k in REQUIRED if k not in rec]
        if missing:
            errors.append("line {}: missing {}".format(lineno, ",".join(missing)))
            continue
        if rec["classification"] not in VALID:
            errors.append("line {}: bad classification '{}'".format(
                lineno, rec["classification"]))
            continue
        if not isinstance(rec["matches_ioc"], list):
            errors.append("line {}: matches_ioc not a list".format(lineno))
            continue
        seen[rec["alert_id"]] = rec
        counts[rec["classification"]] += 1

unseen = sorted(expected - set(seen))
print(json.dumps({
    "tp": counts["TP"], "fp": counts["FP"], "noise": counts["NOISE"],
    "missing_count": len(unseen), "missing_sample": unseen[:5],
    "error_count": len(errors), "errors": errors[:5],
}))
VAL_PY
) || die "validation pass failed"

tp=$(jq -r '.tp' <<<"$stats")
fp=$(jq -r '.fp' <<<"$stats")
noise=$(jq -r '.noise' <<<"$stats")
missing=$(jq -r '.missing_count' <<<"$stats")
errs=$(jq -r '.error_count' <<<"$stats")
unknown_vocab=$(python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["unknown_vocab"]))' <<<"$fold_result")

if [[ -n "$unknown_vocab" ]]; then
    die "unknown ticket classification vocabulary encountered: $unknown_vocab - extend CLASS_MAP in the fold step"
fi
if (( missing + errs > 0 )); then
    jq -r '"missing: \(.missing_count) (\(.missing_sample | join(", "))) ; schema errors: \(.error_count) (\(.errors | join(" ; ")))"' \
        <<<"$stats" >&2
    die "$(( missing + errs )) alert(s) unclassified - $missing missing, $errs schema-invalid"
fi

log "TP=$tp FP=$fp NOISE=$noise unclassified=0"
log "triage_log.jsonl written"
exit 0
