#!/bin/bash
# Name: 3-run_detections.sh
# Purpose: Execute the 3x02 Sigma detection catalog against the capstone
#          enriched events over the full pack span, produce the shift alert
#          queue, and write the machine-readable catalog_run.json record
#          with alert counts by severity and by rule. Labels evidence with
#          a taxonomy covering both Windows event-ID semantics and Linux
#          sshd/pam/sudo message vocabulary so auth-category rules evaluate
#          the correct dataset.
# Author: Steve - Cybersecurity Engineer
# Date: 14 September 2026

set -u

log() { printf '[detect] %s\n' "$*"; }
die() { printf '[detect][ERROR] %s\n' "$*" >&2; exit 1; }

for var in SHIFT_WORKSPACE CATALOG_DIR HANDOFF_DIR; do
    if [[ -z "${!var:-}" ]]; then
        die "environment variable $var is not set - source the environment contract first"
    fi
done

RUNTIME_DIR="$SHIFT_WORKSPACE/runtime"
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
ALERTS_DIR="$SHIFT_WORKSPACE/alerts"
OUT_QUEUE="$ALERTS_DIR/alert_queue.json"

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# ---------------------------------------------------------------------------
# 1. Pipeline check
# ---------------------------------------------------------------------------
pipeline_run="$RUNTIME_DIR/pipeline_run.json"
if [[ ! -f "$pipeline_run" ]]; then
    die "pipeline_run.json not found - run 1-run_pipeline.sh first"
fi

pipeline_exit=$(jq -r '.exit_status // 1' "$pipeline_run")
if (( pipeline_exit != 0 )); then
    die "pipeline did not exit cleanly (status $pipeline_exit)"
fi
log "pipeline check: OK"

# ---------------------------------------------------------------------------
# 2. Catalog inventory
# ---------------------------------------------------------------------------
RULES_SIGMA="$CATALOG_DIR/rules/sigma"
if [[ ! -d "$RULES_SIGMA" ]]; then
    die "sigma rules directory not found: $RULES_SIGMA"
fi

rule_count=$(find "$RULES_SIGMA" -maxdepth 1 -type f -name '*.yml' | wc -l)
if (( rule_count == 0 )); then
    die "no .yml rules found in $RULES_SIGMA"
fi
log "catalog loaded: $rule_count rules"

# ---------------------------------------------------------------------------
# 3. Persistent labeled events (regenerate if missing or older than evidence)
# ---------------------------------------------------------------------------
events_file=""
if [[ -s "$ENRICHED_DIR/enriched_events.json" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.json"
elif [[ -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.jsonl"
else
    die "no enriched events file found in $ENRICHED_DIR"
fi

labeled_file="$ENRICHED_DIR/labeled_events.json"

if [[ ! -s "$labeled_file" ]] || [[ "$events_file" -nt "$labeled_file" ]]; then
    log "generating persistent labeled events copy..."
    python3 - "$events_file" "$labeled_file" << 'PYEOF'
import json
import sys
from collections import Counter

events_path, output_path = sys.argv[1:3]

LABEL_MAP = {
    "authentication": "login_success",
    "process": "process_create",
    "network": "network_connection",
    "audit": "security_audit",
    "file_access": "file_read_sensitive",
    "network_alert": "ids_alert",
}

# Ordered: first keyword match wins. Linux sshd/pam/sudo vocabulary comes
# first because its phrasing ("failed password") does not contain the
# Windows-oriented keyword "failure" used by the original labeling pass.
auth_refinement = [
    ("failed password", "login_failure"),
    ("invalid user", "login_failure"),
    ("authentication failure", "login_failure"),
    ("res=failed", "login_failure"),
    ("failure", "login_failure"),
    ("failed to log on", "login_failure"),
    ("accepted password", "login_success"),
    ("sudo:", "sudo"),
    ("new session", "login_success"),
    ("session opened", "login_success"),
    ("privilege", "privilege_escalation"),
    ("service installed", "new_service"),
]

def refine_auth(msg, action, event_id):
    msg_lower = (msg or "").lower()
    action_lower = (action or "").lower()
    eid = str(event_id or "")

    for keyword, label in auth_refinement:
        if keyword in msg_lower or keyword in action_lower:
            return label
    if eid in ("4625", "529", "530"):
        return "login_failure"
    if eid in ("4672", "528"):
        return "privilege_escalation"
    if eid in ("4720", "4724"):
        return "account_creation"
    if eid in ("4726",):
        return "account_deletion"
    return "login_success"

label_counts = Counter()
processed = 0

with open(events_path, "r", errors="replace") as fin, \
     open(output_path, "w") as fout:
    for line in fin:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        cat = record.get("event_category", "")
        canon = LABEL_MAP.get(cat, "unknown")
        if cat == "authentication":
            canon = refine_auth(
                record.get("raw_message", ""),
                record.get("action", ""),
                record.get("event_id", ""))
        record["canonical_label"] = canon
        label_counts[canon] += 1
        fout.write(json.dumps(record) + "\n")
        processed += 1

sys.stderr.write(f"labeled {processed} events\n")
for lbl, cnt in label_counts.most_common():
    sys.stderr.write(f"  {lbl}: {cnt}\n")
PYEOF
    [[ -s "$labeled_file" ]] || die "failed to generate labeled events"
    log "labeled events written: $labeled_file"
fi

# ---------------------------------------------------------------------------
# 4. Stage the 3x02 package dir (priorities), correlation primitives, a
#    BASELINE_PKG whose labeled_events.json is the capstone copy, and a
#    staged HANDOFF_DIR whose normalized_events.json slot points at the
#    capstone enriched stream.
#
#    Why three staged directories:
#      a) detect_pkg/rule_prioritization.json - generator contract (T14).
#      b) detect_baseline/labeled_events.json - the sigma runner substitutes
#         $BASELINE_PKG/labeled_events.json for canonical_label rules; without
#         this override it uses the primary-pack reference dataset and those
#         rules match zero against capstone data. The baselines/ subdir is
#         symlinked from the reference package to keep the baseline_seen /
#         baseline_known_destination / baseline_known_port runtime fields
#         functional.
#      c) detect_handoff/data/normalized_events.json - the generator invokes
#         the runner WITHOUT an evidence argument, so the runner falls back
#         to its default $HANDOFF_DIR/data/normalized_events.json. Pointing
#         that slot at the capstone enriched events ensures plain-field
#         rules evaluate the correct pack (the primary-pack default lies
#         outside the capstone detection window, scoring zero). The
#         context/asset_inventory.json copy preserves the generator's
#         required input; asset enrichment (zone, criticality) needed by
#         tuned rules travels inside the enriched records themselves.
# ---------------------------------------------------------------------------
STAGE_PKG="$RUNTIME_DIR/detect_pkg"
mkdir -p "$STAGE_PKG"

if [[ ! -f "$STAGE_PKG/rule_prioritization.json" ]]; then
    if [[ -f "$CATALOG_DIR/coverage/rule_prioritization.json" ]]; then
        cp "$CATALOG_DIR/coverage/rule_prioritization.json" "$STAGE_PKG/"
    else
        die "rule_prioritization.json not found in $CATALOG_DIR/coverage/"
    fi
fi

# Correlation primitives: reuse a known-good copy rather than letting the
# generator regenerate against default (primary-pack) paths.
prim_candidates=(
    "$CATALOG_DIR/correlation_primitives.json"
    "$HOME/bt/3x02/correlation_primitives.json"
    "$HOME/3x02_package/correlation_primitives.json"
    "$HOME/3x02_scripts/correlation_primitives.json"
)
if [[ ! -f "$STAGE_PKG/correlation_primitives.json" ]]; then
    prim_found=0
    for cand in "${prim_candidates[@]}"; do
        if [[ -f "$cand" ]]; then
            cp "$cand" "$STAGE_PKG/correlation_primitives.json"
            prim_found=1
            log "correlation primitives staged from: $cand"
            break
        fi
    done
    if (( prim_found == 0 )); then
        log "WARNING: no existing correlation_primitives.json found - generator will regenerate (rule 010 impact)"
    fi
fi

# Staged BASELINE_PKG: capstone labeled events + reference baselines
STAGE_BASELINE="$RUNTIME_DIR/detect_baseline"
mkdir -p "$STAGE_BASELINE"
ln -sf "$labeled_file" "$STAGE_BASELINE/labeled_events.json"
ln -sfn "$HOME/3x01_package/baseline_package/baselines" "$STAGE_BASELINE/baselines"

# Staged HANDOFF_DIR: redirect the runner's default evidence slot to the
# capstone enriched events. RULES_DIR, SCRIPTS_DIR, and PKG_DIR are absolute
# so cd-ing is unaffected. Original HANDOFF_DIR captured first for the
# asset_inventory copy.
STAGE_HANDOFF="$RUNTIME_DIR/detect_handoff"
mkdir -p "$STAGE_HANDOFF/context" "$STAGE_HANDOFF/data"
cp "$HANDOFF_DIR/context/asset_inventory.json" "$STAGE_HANDOFF/context/"
ln -sf "$events_file" "$STAGE_HANDOFF/data/normalized_events.json"
HANDOFF_DIR="$STAGE_HANDOFF"

# ---------------------------------------------------------------------------
# 5. Full-pack detection window
# ---------------------------------------------------------------------------
eval_start=$(jq -r '.overall.first_event // empty' "$ENRICHED_DIR/source_stats.json")
eval_end=$(jq -r '.overall.last_event // empty' "$ENRICHED_DIR/source_stats.json")
if [[ -z "$eval_start" || -z "$eval_end" ]]; then
    eval_start=$(head -1 "$events_file" | jq -r '.timestamp // empty')
    eval_end=$(tail -1 "$events_file" | jq -r '.timestamp // empty')
fi
if [[ -z "$eval_start" || -z "$eval_end" ]]; then
    die "could not determine detection window from source stats or events"
fi
log "detection window: $eval_start -> $eval_end (full pack span)"

# ---------------------------------------------------------------------------
# 6. Invoke the 3x02 alert generator with all defaults overridden
# ---------------------------------------------------------------------------
log "invoking detection runner"

mkdir -p "$ALERTS_DIR"

export HANDOFF_DIR
export RULES_DIR="$RULES_SIGMA"
export SCRIPTS_DIR="$CATALOG_DIR/runtime"
export PKG_DIR="$STAGE_PKG"
export BASELINE_PKG="$STAGE_BASELINE"
export RUNNER="$CATALOG_DIR/runtime/3-sigma_runner.sh"
export OUT_QUEUE
export OUT_SCHEMA="$ALERTS_DIR/alert_queue_schema.json"
export EVAL_START="$eval_start"
export EVAL_END="$eval_end"
export GENERATED_AT="$eval_end"
export EVIDENCE_LABELED="$labeled_file"
export EVIDENCE_NORM="$events_file"

if ! bash "$CATALOG_DIR/runtime/15-generate_alerts.sh" 2>&1 \
        | tee "$RUNTIME_DIR/catalog_run.log"; then
    gen_exit=${PIPESTATUS[0]}
    die "detection runner failed (status $gen_exit) - see $RUNTIME_DIR/catalog_run.log"
fi

# ---------------------------------------------------------------------------
# 7. Verify alert queue
# ---------------------------------------------------------------------------
if [[ ! -s "$OUT_QUEUE" ]]; then
    die "alert_queue.json missing or empty: $OUT_QUEUE"
fi

# ---------------------------------------------------------------------------
# 8. Statistics: totals, by severity, by rule
# ---------------------------------------------------------------------------
stats_json=$(python3 - "$OUT_QUEUE" "$RULES_SIGMA" << 'PYEOF'
import json
import re
import sys
import os
from collections import Counter

queue_path, rules_dir = sys.argv[1:3]

with open(queue_path) as f:
    queue = json.load(f)

# Locate the alerts list regardless of container shape
if isinstance(queue, list):
    alerts = queue
elif isinstance(queue, dict):
    alerts = None
    for key in ("alerts", "queue", "alert_queue"):
        if isinstance(queue.get(key), list):
            alerts = queue[key]
            break
    if alerts is None:
        alerts = []
else:
    alerts = []

# Build UUID -> rule stem mapping from the catalog YAMLs
uuid_to_stem = {}
for name in os.listdir(rules_dir):
    if not name.endswith(".yml"):
        continue
    stem = name[:-4]
    with open(os.path.join(rules_dir, name), errors="replace") as f:
        for line in f:
            m = re.match(r"^id:\s*(\S+)", line)
            if m:
                uuid_to_stem[m.group(1).strip()] = stem
                break

severity_counter = Counter()
rule_counter = Counter()
for alert in alerts:
    level = str(alert.get("rule_level") or alert.get("severity") or "unknown").lower()
    if level == "informational":
        level = "low"
    severity_counter[level] += 1
    rid = alert.get("rule_id") or "unknown"
    key = uuid_to_stem.get(rid, rid)
    rule_counter[key] += 1

fired_rules = len(rule_counter)

print(json.dumps({
    "alerts_total": len(alerts),
    "fired_rules": fired_rules,
    "severity": {
        "critical": severity_counter.get("critical", 0),
        "high": severity_counter.get("high", 0),
        "medium": severity_counter.get("medium", 0),
        "low": severity_counter.get("low", 0),
        "unknown": severity_counter.get("unknown", 0),
    },
    "by_rule": dict(rule_counter),
}))
PYEOF
) || die "failed to compute alert statistics"

alerts_total=$(jq -r '.alerts_total' <<<"$stats_json")
fired_rules=$(jq -r '.fired_rules' <<<"$stats_json")
crit=$(jq -r '.severity.critical' <<<"$stats_json")
high=$(jq -r '.severity.high' <<<"$stats_json")
med=$(jq -r '.severity.medium' <<<"$stats_json")
low=$(jq -r '.severity.low' <<<"$stats_json")

if (( alerts_total == 0 )); then
    die "zero alerts fired - catalog failed against this pack (broken rules or malformed events)"
fi

log "matched: $fired_rules rules / $alerts_total alerts"
log "severity critical=$crit high=$high medium=$med low=$low"
log "top rules:"
jq -r '.by_rule | to_entries | sort_by(-.value) | .[] | "  \(.key)\t: \(.value) alerts"' <<<"$stats_json" \
    | head -15 | expand -t2

# ---------------------------------------------------------------------------
# 9. Write catalog_run.json
# ---------------------------------------------------------------------------
ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

by_rule_json=$(jq '.by_rule' <<<"$stats_json")

jq -n \
    --argjson catalog_rules_total "$rule_count" \
    --argjson catalog_rules_fired "$fired_rules" \
    --argjson alerts_total "$alerts_total" \
    --argjson crit "$crit" \
    --argjson high "$high" \
    --argjson med "$med" \
    --argjson low "$low" \
    --argjson by_rule "$by_rule_json" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    '{
        catalog_rules_total: $catalog_rules_total,
        catalog_rules_fired: $catalog_rules_fired,
        alerts_total: $alerts_total,
        alerts_by_severity: {
            critical: $crit,
            high: $high,
            medium: $med,
            low: $low
        },
        alerts_by_rule: $by_rule,
        started_at: $started_at,
        ended_at: $ended_at,
        exit_status: 0
    }' > "$RUNTIME_DIR/catalog_run.json" \
    || die "failed to write catalog_run.json"

log "alert_queue.json written"
log "catalog_run.json written"

exit 0
