#!/bin/bash
#
# Name: 15-generate_alerts.sh
# Purpose: Execute every active Sigma rule (tuned variant when present, base
#          otherwise) against the evaluation window, convert matches into
#          deduplicated, asset-enriched, risk-prioritized alerts, and emit
#          alert_queue.json plus alert_queue_schema.json as the 3x03 contract.
# Author: Steve - Cybersecurity Engineer
# Date: 2026/09/07
#
# Inputs:
#   $RUNNER                                - 3-sigma_runner.sh
#   $RULES_DIR (+ $RULES_DIR/tuned/)       - Sigma catalog
#   $HANDOFF_DIR/context/asset_inventory.json
#   $BASELINE_PKG/labeled_events.json      - evidence (runner auto-substitutes
#     for labeled-field rules; NOTE printed to stderr, intentionally not suppressed)
#   $HANDOFF_DIR/data/normalized_events.json - evidence for plain rules
#   $PKG_DIR/rule_prioritization.json      - T14 output
# Outputs:
#   $OUT_QUEUE  (alert_queue.json)
#   $OUT_SCHEMA (alert_queue_schema.json)
#
# Deviations (documented):
#   1. alert_id = uuid5(NAMESPACE_DNS, "meddefense.alerts.<rule-uuid>.<event_ref>").
#   2. evidence_hash = sha256 of the matched record's raw NDJSON line, collected
#      in a single streaming pass per evidence file keyed on record_id.
#   3. Dedup: sliding 60s window per (rule_id, hostname, user); earliest event
#      kept, absorbed events counted in dedup_suppressed_count; null user
#      participates as literal "null".
#   4. generated_at defaults to EVAL_END for idempotency; override via GENERATED_AT.
#   5. Priority is joined on (rule file stem, variant), the key used by
#      rule_prioritization.json (T14 entries carry "rule" and "variant").
#   6. All 13 rules execute uniformly; 010 fires 0 by design (honest queue).
#   7. Runner truncates match lists at 10000; if hit, the script warns on
#      stderr rather than silently under-reporting.
#   8. Any rule whose priority lookup misses is reported loudly to stderr.

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
RULES_DIR="${RULES_DIR:-$HOME/3x02_scripts/rules/sigma}"
SCRIPTS_DIR="${SCRIPTS_DIR:-$HOME/3x02_scripts}"
PKG_DIR="${PKG_DIR:-$HOME/3x02_package}"
RUNNER="${RUNNER:-$SCRIPTS_DIR/3-sigma_runner.sh}"
OUT_QUEUE="${OUT_QUEUE:-$PKG_DIR/alert_queue.json}"
OUT_SCHEMA="${OUT_SCHEMA:-$PKG_DIR/alert_queue_schema.json}"
EVAL_START="${EVAL_START:-2026-03-24T00:00:00Z}"
EVAL_END="${EVAL_END:-2026-03-27T00:00:00Z}"
GENERATED_AT="${GENERATED_AT:-$EVAL_END}"
EVIDENCE_LABELED="${EVIDENCE_LABELED:-$BASELINE_PKG/labeled_events.json}"
EVIDENCE_NORM="${EVIDENCE_NORM:-$HANDOFF_DIR/data/normalized_events.json}"
export HANDOFF_DIR RULES_DIR PKG_DIR SCRIPTS_DIR RUNNER OUT_QUEUE OUT_SCHEMA \
    EVAL_START EVAL_END GENERATED_AT EVIDENCE_LABELED EVIDENCE_NORM

for f in "$RUNNER" "$HANDOFF_DIR/context/asset_inventory.json" \
    "$PKG_DIR/rule_prioritization.json" "$EVIDENCE_LABELED"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

# Correlation primitives required for 010; regenerate if lost (known incident).
if [[ ! -f "$PKG_DIR/correlation_primitives.json" ]] && \
   [[ ! -f "$SCRIPTS_DIR/correlation_primitives.json" ]]; then
    echo "correlation_primitives.json missing; regenerating" >&2
    (cd "$SCRIPTS_DIR" && python3 8-correlation_primitives.py)
fi

cd "$SCRIPTS_DIR"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
export TMP_DIR

shopt -s nullglob
rules_executed=0
for base in "$RULES_DIR"/*.yml; do
    name="$(basename "$base")"
    active="$base"
    if [[ -f "$RULES_DIR/tuned/$name" ]]; then
        active="$RULES_DIR/tuned/$name"
    fi
    stem="${name%.yml}"
    rel="${active#"$RULES_DIR"/}"
    echo "executing $stem ($rel) ..."
    "$RUNNER" "$active" --window "$EVAL_START,$EVAL_END" \
        > "$TMP_DIR/run_${stem}.json"
    rules_executed=$((rules_executed + 1))
done
shopt -u nullglob
echo "rules executed            : $rules_executed"

python3 -W error - <<'PYEOF'
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime

try:
    import yaml
except ImportError:
    sys.stderr.write("error: PyYAML required\n")
    sys.exit(1)

tmp_dir = os.environ["TMP_DIR"]
rules_dir = os.environ["RULES_DIR"]
pkg_dir = os.environ["PKG_DIR"]
out_queue = os.environ["OUT_QUEUE"]
out_schema = os.environ["OUT_SCHEMA"]

def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

def parse_ts(raw):
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))

# Reconstruct the active rule list (tuned variant overrides base), capturing
# the variant explicitly for the priority join.
active_rules = []
for fname in sorted(os.listdir(rules_dir)):
    if not fname.endswith(".yml"):
        continue
    stem = fname[:-4]
    base_path = os.path.join(rules_dir, fname)
    tuned_path = os.path.join(rules_dir, "tuned", fname)
    if os.path.isfile(tuned_path):
        active_rules.append((stem, tuned_path, "tuned"))
    else:
        active_rules.append((stem, base_path, "base"))

priorities = load_json(os.path.join(pkg_dir, "rule_prioritization.json"))
prio_by_key = {
    (e.get("rule"), e.get("variant", "base")): e.get("priority_score", 0.0)
    for e in priorities.get("rules", [])
}

inventory = load_json(os.path.join(os.environ["HANDOFF_DIR"],
                                   "context", "asset_inventory.json"))
assets_by_host = {a.get("hostname"): a for a in inventory.get("assets", [])}

wanted = set()
runs = []
truncation_hits = []
for stem, path, variant in active_rules:
    run_path = os.path.join(tmp_dir, "run_%s.json" % stem)
    if not os.path.isfile(run_path):
        sys.stderr.write("error: runner output missing for %s\n" % stem)
        sys.exit(1)
    run = load_json(run_path)
    if run.get("match_count", 0) > len(run.get("matches", [])):
        truncation_hits.append(stem)
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if (stem, variant) not in prio_by_key:
        sys.stderr.write("warning: no priority entry for (%s, %s); "
                         "scored 0\n" % (stem, variant))
    runs.append((stem, path, variant, run, doc))
    for m in run.get("matches", []):
        if m.get("event_ref"):
            wanted.add(m["event_ref"])

if truncation_hits:
    sys.stderr.write(
        "WARNING: runner MAX_MATCHES truncation on: %s "
        "(queue under-reports these rules; counts via --count-only are uncapped)\n"
        % ", ".join(sorted(truncation_hits)))

# Single streaming pass to resolve record_ids and raw lines for hashing.
def stream_collect(ids_needed):
    found = {}
    still = set(ids_needed)
    for ev in [os.environ["EVIDENCE_LABELED"], os.environ["EVIDENCE_NORM"]]:
        if not still:
            break
        if not os.path.isfile(ev):
            sys.stderr.write("note: evidence file absent: %s\n" % ev)
            continue
        with open(ev, encoding="utf-8") as fh:
            for line in fh:
                line = line.rstrip("\n")
                idx = line.find('"record_id":"')
                if idx == -1:
                    continue
                start = idx + len('"record_id":"')
                end = line.find('"', start)
                if end == -1:
                    continue
                rid = line[start:end]
                if rid in still:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    found[rid] = (line, rec)
                    still.discard(rid)
                    if not still:
                        break
    return found

records = stream_collect(wanted)
unresolved = wanted - set(records)
if unresolved:
    sys.stderr.write("warning: %d event_refs unresolved in evidence files\n"
                     % len(unresolved))

generated_at = os.environ["GENERATED_AT"]
alerts = []
raw_matches = 0

for stem, path, variant, run, doc in runs:
    prio = prio_by_key.get((stem, variant), 0.0)
    techs = sorted(t.split(".", 1)[1] for t in (doc.get("tags") or [])
                   if isinstance(t, str) and t.lower().startswith("attack.t"))
    for m in run.get("matches", []):
        raw_matches += 1
        ref = m.get("event_ref")
        raw_line, record = records.get(ref, (None, {}))
        evidence_hash = (hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
                         if raw_line is not None else None)
        host = m.get("hostname")
        user = record.get("user")
        if user is None:
            user = (record.get("event_data") or {}).get("TargetUserName")
        alert_id = str(uuid.uuid5(
            uuid.NAMESPACE_DNS,
            "meddefense.alerts.%s.%s" % (run["rule_id"], ref)))
        alerts.append({
            "alert_id": alert_id,
            "generated_at": generated_at,
            "rule_id": run["rule_id"],
            "rule_title": run.get("rule_title"),
            "rule_display": stem,
            "rule_level": run.get("level"),
            "priority_score": prio,
            "event_ref": ref,
            "event_summary": {
                "timestamp": m.get("timestamp"),
                "hostname": host,
                "user": user,
                "src_ip": record.get("src_ip"),
                "dst_ip": record.get("dst_ip"),
                "process_name": record.get("process_name"),
                "canonical_label": record.get("canonical_label"),
                "event_category": record.get("event_category"),
            },
            "asset_context": assets_by_host.get(host),
            "attack_techniques": techs,
            "status": "new",
            "evidence_hash": evidence_hash,
            "dedup_suppressed_count": 0,
        })

# Sort into dedup groups: rule, host, user, then timestamp.
alerts.sort(key=lambda a: (
    a["rule_id"],
    a["event_summary"]["hostname"] or "",
    str(a["event_summary"]["user"]),
    a["event_summary"]["timestamp"] or "",
))

deduped = []
i = 0
while i < len(alerts):
    group = [alerts[i]]
    j = i + 1
    anchor = parse_ts(alerts[i]["event_summary"]["timestamp"])
    while (j < len(alerts)
           and alerts[j]["rule_id"] == alerts[i]["rule_id"]
           and (alerts[j]["event_summary"]["hostname"] or "")
               == (alerts[i]["event_summary"]["hostname"] or "")
           and str(alerts[j]["event_summary"]["user"])
               == str(alerts[i]["event_summary"]["user"])
           and (parse_ts(alerts[j]["event_summary"]["timestamp"])
                - anchor).total_seconds() <= 60):
        group.append(alerts[j])
        j += 1
    kept = group[0]
    kept["dedup_suppressed_count"] = len(group) - 1
    deduped.append(kept)
    i = j

deduped.sort(key=lambda a: (-a["priority_score"],
                            a["event_summary"]["timestamp"] or "",
                            a["alert_id"]))

FIELDS = ["alert_id", "generated_at", "rule_id", "rule_title", "rule_level",
          "priority_score", "event_ref", "event_summary", "asset_context",
          "attack_techniques", "status", "evidence_hash",
          "dedup_suppressed_count"]

queue = [{f: a[f] for f in FIELDS} for a in deduped]
stem_by_alert = {a["alert_id"]: a["rule_display"] for a in deduped}

with open(out_queue, "w", encoding="utf-8") as fh:
    json.dump(queue, fh, indent=2)
    fh.write("\n")

schema = {
    "contract": "MedDefense 3x02 alert queue for 3x03 triage",
    "version": "1.0",
    "generator": "15-generate_alerts.sh",
    "queue_shape": "JSON array of alert objects; sorted by priority_score "
                   "descending, then event_summary.timestamp ascending, then alert_id",
    "fields": {
        "alert_id": {"type": "string (uuid5)",
                     "derivation": "uuid5(NAMESPACE_DNS, "
                     "'meddefense.alerts.<rule_id>.<event_ref>')"},
        "generated_at": {"type": "string (ISO 8601 UTC)"},
        "rule_id": {"type": "string (Sigma rule UUID)"},
        "rule_title": {"type": "string"},
        "rule_level": {"type": "string", "enum": [
            "informational", "low", "medium", "high", "critical"]},
        "priority_score": {"type": "number",
                           "source": "rule_prioritization.json (T14), "
                           "joined on (rule stem, variant)"},
        "event_ref": {"type": "string",
                      "desc": "record_id of the matched event in the evidence file"},
        "event_summary": {"type": "object", "fields": [
            "timestamp", "hostname", "user", "src_ip", "dst_ip",
            "process_name", "canonical_label", "event_category"]},
        "asset_context": {"type": "object or null",
                          "source": "asset_inventory.json entry matching hostname"},
        "attack_techniques": {"type": "array of strings",
                              "desc": "ATT&CK technique IDs from rule tags (attack.tXXXX)"},
        "status": {"type": "string", "const": "new"},
        "evidence_hash": {"type": "string (sha256 hex)",
                          "derivation": "sha256 of the matched event's raw NDJSON record"},
        "dedup_suppressed_count": {"type": "integer",
                                   "desc": "events collapsed into this alert by the 60s dedup rule"},
    },
    "dedup_rule": "same (rule_id, hostname, user) within a sliding 60-second "
                  "window collapses to the earliest event",
}
with open(out_schema, "w", encoding="utf-8") as fh:
    json.dump(schema, fh, indent=2)
    fh.write("\n")

print("raw matches               : %d" % raw_matches)
print("after deduplication       : %d" % len(queue))
print("top 5 alerts")
for i, a in enumerate(queue[:5], start=1):
    print(" %d %6.1f  %-8s %s  %s" % (
        i, a["priority_score"], a["rule_level"] or "-",
        stem_by_alert[a["alert_id"]],
        a["event_summary"]["hostname"] or "-"))
print("%s        : %d alerts" % (os.path.basename(out_queue), len(queue)))
print("%s : written" % os.path.basename(out_schema))
PYEOF
