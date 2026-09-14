#!/bin/bash
# Name: 2-run_baselines.sh
# Purpose: Execute the 3x01 baseline suite against enriched capstone events,
#          harvest deviation markers from the live_check anomaly outputs,
#          compute hot hosts and total deviation markers, and write the
#          machine-readable baseline_run.json record for triage consumption.
#          The staged baseline_summary.json is retargeted to the capstone
#          pack: windows recalculated from the observed event span and the
#          known_accounts list rebuilt from users observed in the baseline
#          window, so unknown_account markers reflect genuinely novel users
#          rather than a stale reference-pack user list.
# Author: Steve - Cybersecurity Engineer
# Date: 14 September 2026

set -u

log() { printf '[baseline] %s\n' "$*"; }
die() { printf '[baseline][ERROR] %s\n' "$*" >&2; exit 1; }

for var in SHIFT_WORKSPACE BASELINE_BIN; do
    if [[ -z "${!var:-}" ]]; then
        die "environment variable $var is not set - source the environment contract first"
    fi
done

RUNTIME_DIR="$SHIFT_WORKSPACE/runtime"
ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
TMP_BASELINE_DIR="$(mktemp -d)"

cleanup() {
    log "cleaning up temp directory: $TMP_BASELINE_DIR"
    rm -rf "$TMP_BASELINE_DIR"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Verify pipeline_run.json exists and exited successfully
# ---------------------------------------------------------------------------
pipeline_run="$RUNTIME_DIR/pipeline_run.json"
if [[ ! -f "$pipeline_run" ]]; then
    die "pipeline_run.json not found - run 1-run_pipeline.sh first"
fi

exit_status=$(jq -r '.exit_status // 1' "$pipeline_run")
if (( exit_status != 0 )); then
    die "pipeline did not exit cleanly (status $exit_status) - fix pipeline before running baselines"
fi
log "pipeline check: OK"

# ---------------------------------------------------------------------------
# 2. Locate enriched events file
# ---------------------------------------------------------------------------
events_file=""
if [[ -s "$ENRICHED_DIR/enriched_events.json" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.json"
elif [[ -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.jsonl"
else
    die "no enriched events file found in $ENRICHED_DIR"
fi

log "using events file: $events_file"

# ---------------------------------------------------------------------------
# 3. Extract timestamps from source_stats.json and calculate windows
# ---------------------------------------------------------------------------
first_event_raw=$(jq -r '.overall.first_event // empty' "$ENRICHED_DIR/source_stats.json" 2>/dev/null)
last_event_raw=$(jq -r '.overall.last_event // empty' "$ENRICHED_DIR/source_stats.json" 2>/dev/null)

if [[ -z "$first_event_raw" || -z "$last_event_raw" ]]; then
    first_event_raw=$(head -1 "$events_file" | jq -r '.timestamp // empty')
    last_event_raw=$(tail -1 "$events_file" | jq -r '.timestamp // empty')
fi

if [[ -z "$first_event_raw" || -z "$last_event_raw" ]]; then
    die "could not determine event timestamp range from $events_file"
fi

log "event span: $first_event_raw -> $last_event_raw"

# Baseline: first 7 days of the span; evaluation: next 24 hours
# Single Python invocation prints "baseline_end eval_start eval_end"
windows=$(python3 - "$first_event_raw" << 'PYEOF'
import sys
from datetime import datetime, timedelta

first_dt = datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
baseline_end = first_dt + timedelta(days=7)
eval_end = baseline_end + timedelta(days=1)
fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%SZ")
print(fmt(baseline_end), fmt(baseline_end), fmt(eval_end))
PYEOF
) || die "python window calculation failed"

baseline_start="$first_event_raw"
read -r baseline_end evaluation_start evaluation_end <<< "$windows"

if [[ -z "${baseline_end:-}" || -z "${evaluation_start:-}" || -z "${evaluation_end:-}" ]]; then
    die "failed to calculate baseline/evaluation windows (got: '${windows:-}')"
fi

log "baseline window: $baseline_start -> $baseline_end (7 days)"
log "evaluation window: $evaluation_start -> $evaluation_end (24 hours)"

# ---------------------------------------------------------------------------
# 4. Stage the baseline package directory (windows only; known_accounts is
#    patched after labeling once observed users are known)
# ---------------------------------------------------------------------------
cp ~/3x01_package/baseline_package/baseline_summary.json "$TMP_BASELINE_DIR/baseline_summary.json"

python3 - "$TMP_BASELINE_DIR" "$baseline_start" "$baseline_end" "$evaluation_start" "$evaluation_end" << 'PYEOF'
import json
import sys

tmpdir, base_start, base_end, eval_start, eval_end = sys.argv[1:6]
with open(f"{tmpdir}/baseline_summary.json") as f:
    summary = json.load(f)
summary["baseline_window"] = {"start": base_start, "end": base_end, "duration_days": 7}
summary["evaluation_window"] = {"start": eval_start, "end": eval_end, "duration_hours": 24}
with open(f"{tmpdir}/baseline_summary.json", "w") as f:
    json.dump(summary, f, indent=2)
print(f"Updated baseline window: {base_start} to {base_end}")
print(f"Updated evaluation window: {eval_start} to {eval_end}")
PYEOF

# ---------------------------------------------------------------------------
# 5. Quick-labeling: map event_category to canonical_label.
#    Also collects attributed users seen in the baseline window so the
#    known_accounts list can be retargeted to this pack's user population.
# ---------------------------------------------------------------------------
log "applying quick-label taxonomy to enriched events..."

labeled_output="$TMP_BASELINE_DIR/labeled_events.json"
observed_users_output="$TMP_BASELINE_DIR/known_accounts_observed.json"
python3 - "$events_file" "$labeled_output" "$observed_users_output" "$baseline_end" << 'PYEOF'
import json
import sys
from collections import Counter
from datetime import datetime

events_path, output_path, users_path, baseline_end_str = sys.argv[1:5]

baseline_end = datetime.fromisoformat(baseline_end_str.replace("Z", "+00:00"))

LABEL_MAP = {
    "authentication": "login_success",
    "process": "process_create",
    "network": "network_connection",
    "audit": "security_audit",
    "file_access": "file_read_sensitive",
    "network_alert": "ids_alert",
}

auth_refinement = {
    "failure": "login_failure",
    "privilege": "privilege_escalation",
    "sudo": "sudo",
    "create": "account_creation",
    "delete": "account_deletion",
}

def refine_auth(msg, action, event_id):
    msg_lower = (msg or "").lower()
    action_lower = (action or "").lower()
    eid = str(event_id or "")

    for keyword, label in auth_refinement.items():
        if keyword in msg_lower or keyword in action_lower:
            return label
    if eid in ("4625", "529", "530"):
        return "login_failure"
    if eid in ("4672", "528"):
        return "privilege_escalation"
    if eid in ("4720", "4724"):
        return "account_creation"
    return "login_success"

label_counts = Counter()
baseline_users = set()
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
                record.get("event_id", "")
            )

        record["canonical_label"] = canon
        label_counts[canon] += 1
        fout.write(json.dumps(record) + "\n")
        processed += 1

        # Collect attributed users observed before the baseline window ends
        user = record.get("user")
        if user:
            try:
                ts = datetime.fromisoformat(
                    (record.get("timestamp") or "").replace("Z", "+00:00"))
                if ts < baseline_end:
                    baseline_users.add(user)
            except ValueError:
                pass

        if processed % 50000 == 0:
            sys.stderr.write(f"  processed {processed} events...\n")

sys.stderr.write(f"Labeled {processed} events. Label distribution:\n")
for lbl, cnt in label_counts.most_common():
    sys.stderr.write(f"  {lbl}: {cnt}\n")

with open(users_path, "w") as f:
    json.dump(sorted(baseline_users), f, indent=2)

sys.stderr.write(f"Collected {len(baseline_users)} attributed users from baseline window\n")
PYEOF

if [[ ! -s "$labeled_output" ]]; then
    die "labeled_events.json was not produced or is empty"
fi

log "labeled events created: $labeled_output"

# ---------------------------------------------------------------------------
# 5b. Retarget known_accounts: union of observed baseline-window users with
#     the original reference list (keeps generic system/service accounts).
# ---------------------------------------------------------------------------
python3 - "$TMP_BASELINE_DIR" "$observed_users_output" << 'PYEOF'
import json
import sys

tmpdir, users_path = sys.argv[1:3]

with open(users_path) as f:
    observed = set(json.load(f))

summary_path = f"{tmpdir}/baseline_summary.json"
with open(summary_path) as f:
    summary = json.load(f)

original = set(summary.get("auth", {}).get("known_accounts", []))
merged = sorted(original | observed)

summary.setdefault("auth", {})["known_accounts"] = merged

with open(summary_path, "w") as f:
    json.dump(summary, f, indent=2)

print(f"known_accounts retargeted: {len(original)} original + "
      f"{len(observed) - len(observed & original)} new observed = {len(merged)} total")
PYEOF

log "known_accounts retargeted to capstone user population"

# ---------------------------------------------------------------------------
# 6. Set up environment and invoke the baseline validation runner
# ---------------------------------------------------------------------------
SCRIPTS_DIR="$(cd "$(dirname "$BASELINE_BIN")" && pwd)"
export BASELINE_PKG="$TMP_BASELINE_DIR"
export SCRIPTS_DIR
export HANDOFF_DIR="$SHIFT_WORKSPACE"

log "invoking $BASELINE_BIN"
log "input: $events_file"
log "output: $TMP_BASELINE_DIR"

BASELINE_PKG="$TMP_BASELINE_DIR" "$BASELINE_BIN" 2>&1 | tee "$RUNTIME_DIR/baseline_run.log"
baseline_exit=${PIPESTATUS[0]}

log "baseline suite exit status: $baseline_exit"

# ---------------------------------------------------------------------------
# 7. Harvest anomaly output files (paths only - never pass content via argv)
# ---------------------------------------------------------------------------
anomaly_paths=()
for src in auth process network; do
    if [[ -f "$TMP_BASELINE_DIR/live_check_${src}.json" ]]; then
        anomaly_paths+=("$TMP_BASELINE_DIR/live_check_${src}.json")
        log "harvesting live_check_${src}.json"
    elif [[ -f "$TMP_BASELINE_DIR/anomalies_${src}.json" ]]; then
        anomaly_paths+=("$TMP_BASELINE_DIR/anomalies_${src}.json")
        log "harvesting anomalies_${src}.json (fallback)"
    else
        log "WARNING: no anomaly output for ${src}"
    fi
done

if (( ${#anomaly_paths[@]} == 0 )); then
    die "no anomaly output files produced by baseline suite"
fi

# ---------------------------------------------------------------------------
# 8. Aggregate all anomalies into baseline.json with deviation markers
# ---------------------------------------------------------------------------
log "aggregating anomaly markers into baseline.json..."

python3 - "$ENRICHED_DIR/baseline.json" "$TMP_BASELINE_DIR/labeled_events.json" "${anomaly_paths[@]}" << 'PYEOF'
import json
import sys
from collections import defaultdict

output_path = sys.argv[1]
labeled_events_path = sys.argv[2]
anomaly_paths = sys.argv[3:]

# Parse anomalies from each anomaly file (each is a single JSON object)
anomalies_raw = []
for path in anomaly_paths:
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        sys.stderr.write(f"Warning: failed to load anomaly file {path}: {e}\n")
        continue
    if isinstance(data, dict):
        anomalies_raw.extend(data.get("anomalies", []))

deviation_markers = []
host_scores = defaultdict(float)
markers_by_type = defaultdict(int)
hosts_seen = set()

# Count all hosts processed from the labeled events
with open(labeled_events_path, "r", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = record.get("hostname")
        if host:
            hosts_seen.add(host)

if len(anomalies_raw) == 0:
    # Fallback: direct scan of labeled events for obvious deviations
    sys.stderr.write("No anomalies detected - performing direct scan of labeled events...\n")

    host_events = defaultdict(list)

    with open(labeled_events_path, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = record.get("hostname") or "unknown"
            host_events[host].append(record)

    for host, events in host_events.items():
        failures = [e for e in events if e.get("canonical_label") == "login_failure"]
        if len(failures) >= 5:
            deviation_markers.append({
                "host": host,
                "marker": "login_failure_burst",
                "field": "canonical_label",
                "observed_value": f"{len(failures)} failures",
                "baseline_reference": "< 5 failures expected",
                "deviation_score": min(len(failures), 10.0),
                "event_refs": [e.get("record_id", "") for e in failures[:5]]
            })
            host_scores[host] += min(len(failures), 10.0)
            markers_by_type["login_failure_burst"] += 1

    for host, events in host_events.items():
        unknown_procs = [e for e in events if "unknown" in (e.get("process_name") or "").lower()]
        if len(unknown_procs) >= 10:
            deviation_markers.append({
                "host": host,
                "marker": "unknown_process",
                "field": "process_name",
                "observed_value": f"{len(unknown_procs)} unknown processes",
                "baseline_reference": "< 10 unknown processes expected",
                "deviation_score": min(len(unknown_procs) / 2, 10.0),
                "event_refs": [e.get("record_id", "") for e in unknown_procs[:5]]
            })
            host_scores[host] += min(len(unknown_procs) / 2, 10.0)
            markers_by_type["unknown_process"] += 1

else:
    for an in anomalies_raw:
        marker_type = an.get("anomaly_type", an.get("type", "unknown"))
        host = an.get("host", "unknown")
        score = float(an.get("priority_score") or an.get("severity_score") or 1.0)
        deviation_markers.append({
            "host": host,
            "marker": marker_type,
            "field": an.get("field", "event_category"),
            "observed_value": str(an.get("observed_value", "")),
            "baseline_reference": str(an.get("baseline_value", "")),
            "deviation_score": score,
            "event_refs": an.get("event_refs", [])[:5]
        })
        host_scores[host] += score
        markers_by_type[marker_type] += 1

hosts_with_dev = {m["host"] for m in deviation_markers}
hot_hosts = sorted(host_scores.keys(), key=lambda h: -host_scores[h])[:5]

output = {
    "version": "1.0",
    "hosts_processed": len(hosts_seen),
    "hosts_with_deviations": len(hosts_with_dev),
    "total_markers": len(deviation_markers),
    "hot_hosts": hot_hosts,
    "markers_by_type": dict(markers_by_type),
    "deviation_markers": deviation_markers[:1000]
}

with open(output_path, "w") as f:
    json.dump(output, f, indent=2)

print(f"baseline.json written: {len(deviation_markers)} markers, {len(hosts_with_dev)} hosts with deviations")
print(f"markers_by_type: {dict(markers_by_type)}")
PYEOF

# ---------------------------------------------------------------------------
# 9. Compute metrics from baseline.json
# ---------------------------------------------------------------------------
baseline_json="$ENRICHED_DIR/baseline.json"
if [[ ! -s "$baseline_json" ]]; then
    die "baseline.json was not produced or is empty"
fi

hosts_total=$(jq -r '.hosts_processed // 0' "$baseline_json")
hosts_with_dev=$(jq -r '.hosts_with_deviations // 0' "$baseline_json")
total_markers=$(jq -r '.total_markers // 0' "$baseline_json")
hot_hosts_list=$(jq -r '.hot_hosts | join(" ")' "$baseline_json")
markers_by_type=$(jq -r '.markers_by_type | to_entries | map("\(.key)=\(.value)") | join(" ")' "$baseline_json")

if (( hosts_total == 0 )); then
    die "baseline processing yielded zero hosts - check labeled_events input"
fi

log "hosts processed: $hosts_total"
log "hosts with deviations: $hosts_with_dev"
log "hot hosts: $hot_hosts_list"
log "markers: $total_markers total ($markers_by_type)"

# ---------------------------------------------------------------------------
# 10. Write baseline_run.json
# ---------------------------------------------------------------------------
started_at=$(jq -r '.started_at' "$RUNTIME_DIR/shift_start.json" 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

markers_json=$(jq '[.deviation_markers[:50][] | {host, marker, field, observed_value, baseline_reference, deviation_score}]' "$baseline_json" 2>/dev/null || echo "[]")

jq -n \
    --arg version "1.0" \
    --argjson hosts_total "$hosts_total" \
    --argjson hosts_with_dev "$hosts_with_dev" \
    --argjson markers "$markers_json" \
    --argjson hot_hosts "$(jq '.hot_hosts' "$baseline_json")" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    '{
        baseline_version: $version,
        hosts_total: $hosts_total,
        hosts_with_deviations: $hosts_with_dev,
        deviation_markers: $markers,
        hot_hosts: $hot_hosts,
        started_at: $started_at,
        ended_at: $ended_at,
        exit_status: 0
    }' > "$RUNTIME_DIR/baseline_run.json" \
    || die "failed to write baseline_run.json"

log "baseline_run.json written"

exit 0
