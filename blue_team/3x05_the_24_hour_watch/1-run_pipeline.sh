#!/bin/bash
# Name: 1-run_pipeline.sh
# Purpose: Execute the 3x00 evidence pipeline against the capstone evidence pack,
#          capture runtime logs, verify enriched output files, summarize per-source
#          event counts, and write the machine-readable pipeline_run.json record
#          used as the substrate reference for every downstream shift task.
# Author: Steve - Cybersecurity Engineer
# Date: 14 September 2026

set -u

log() { printf '[pipeline] %s\n' "$*"; }
die() { printf '[pipeline][ERROR] %s\n' "$*" >&2; exit 1; }

for var in SHIFT_WORKSPACE CAPSTONE_PACK PIPELINE_BIN; do
    if [[ -z "${!var:-}" ]]; then
        die "environment variable $var is not set - source the environment contract first"
    fi
done

ENRICHED_DIR="$SHIFT_WORKSPACE/enriched"
RUNTIME_DIR="$SHIFT_WORKSPACE/runtime"
RUN_LOG="$RUNTIME_DIR/pipeline_run.log"

# ---------------------------------------------------------------------------
# 1. Intake check: shift_start.json must exist and be non-empty
# ---------------------------------------------------------------------------
shift_start="$RUNTIME_DIR/shift_start.json"
if [[ ! -f "$shift_start" ]]; then
    die "shift_start.json not found - run 0-shift_intake.sh first"
fi
if [[ ! -s "$shift_start" ]]; then
    die "shift_start.json is empty - run 0-shift_intake.sh first"
fi
log "intake check: OK"

# ---------------------------------------------------------------------------
# 2. Invoke the pipeline from the enriched output directory
#    evidence_pipeline.sh takes ONE argument (the pack) and writes all
#    outputs into the current working directory (WORKDIR=$PWD), so we cd in.
# ---------------------------------------------------------------------------
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
start_epoch=$(date +%s)

log "invoking $PIPELINE_BIN"
log "input: $CAPSTONE_PACK"
log "output: $ENRICHED_DIR/"

mkdir -p "$ENRICHED_DIR"

(
    cd "$ENRICHED_DIR" || exit 1
    "$PIPELINE_BIN" "$CAPSTONE_PACK" 2>&1 | tee "$RUN_LOG"
    exit "${PIPESTATUS[0]}"
)
pipe_status=$?

if (( pipe_status != 0 )); then
    die "pipeline exited with status $pipe_status - see $RUN_LOG"
fi

ended_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
end_epoch=$(date +%s)
duration=$((end_epoch - start_epoch))
log "duration ${duration}s"

# ---------------------------------------------------------------------------
# 3. Verify required output files exist and are non-empty
# ---------------------------------------------------------------------------
events_file=""
if [[ -s "$ENRICHED_DIR/enriched_events.jsonl" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.jsonl"
elif [[ -s "$ENRICHED_DIR/enriched_events.json" ]]; then
    events_file="$ENRICHED_DIR/enriched_events.json"
else
    die "missing or empty output file: $ENRICHED_DIR/enriched_events.jsonl (or .json)"
fi

timeline_file=""
if [[ -s "$ENRICHED_DIR/timeline.jsonl" ]]; then
    timeline_file="$ENRICHED_DIR/timeline.jsonl"
elif [[ -s "$ENRICHED_DIR/timeline_index.json" ]]; then
    timeline_file="$ENRICHED_DIR/timeline_index.json"
else
    die "missing or empty output file: $ENRICHED_DIR/timeline.jsonl (or timeline_index.json)"
fi

if [[ ! -s "$ENRICHED_DIR/source_stats.json" ]]; then
    die "missing or empty output file: $ENRICHED_DIR/source_stats.json"
fi

# ---------------------------------------------------------------------------
# 4. Source statistics: at least four source types with non-zero counts
# ---------------------------------------------------------------------------
source_stats="$ENRICHED_DIR/source_stats.json"

count_for() {
    # $1 = primary key, $2 = alternate key (optional)
    local primary alt
    primary=$(jq -r --arg k "$1" '.sources[$k].record_count // 0' "$source_stats" 2>/dev/null)
    if [[ "$primary" == "null" || "$primary" == "0" ]] && [[ -n "${2:-}" ]]; then
        alt=$(jq -r --arg k "$2" '.sources[$k].record_count // 0' "$source_stats" 2>/dev/null)
        [[ "$alt" != "null" && "$alt" != "0" ]] && primary="$alt"
    fi
    printf '%s' "$primary"
}

windows_json=$(count_for "windows_json")
linux_text=$(count_for "linux_text")
firewall=$(count_for "firewall")
suricata_alert=$(count_for "suricata_alert" "suricata")
pcap_flow=$(count_for "pcap_flow")

for c in "$windows_json" "$linux_text" "$firewall" "$suricata_alert" "$pcap_flow"; do
    [[ "$c" =~ ^[0-9]+$ ]] || c=0
done

non_zero=0
for c in "$windows_json" "$linux_text" "$firewall" "$suricata_alert" "$pcap_flow"; do
    (( c > 0 )) && ((non_zero++))
done

if (( non_zero < 4 )); then
    die "only $non_zero source types have non-zero event counts (need at least 4)"
fi

# One-line summary per source type, straight from source_stats.json
while IFS=$'\t' read -r stype scount; do
    [[ "$scount" =~ ^[0-9]+$ ]] || scount=0
    if (( scount > 0 )); then
        printf '[pipeline] source %s=%s\n' "$stype" "$scount"
    fi
done < <(jq -r '.sources | to_entries[] | "\(.key)\t\(.value.record_count // 0)"' "$source_stats")

# ---------------------------------------------------------------------------
# 5. Event counts: out from source_stats overall, dropped from cleaning_log
# ---------------------------------------------------------------------------
events_out=$(jq -r '.overall.record_count // 0' "$source_stats")
[[ "$events_out" =~ ^[0-9]+$ ]] || events_out=0
if (( events_out == 0 )); then
    events_out=$(wc -l < "$events_file")
fi

events_dropped=0
if [[ -f "$ENRICHED_DIR/cleaning_log.json" ]]; then
    dropped_probe=$(jq -r '
        .stats.stats_mal_dropped //
        .summary.dropped //
        .overall.dropped //
        0
    ' "$ENRICHED_DIR/cleaning_log.json" 2>/dev/null || echo 0)
    [[ "$dropped_probe" =~ ^[0-9]+$ ]] && events_dropped="$dropped_probe"
fi
events_in=$((events_out + events_dropped))

log "events_in=$events_in events_out=$events_out dropped=$events_dropped"

# ---------------------------------------------------------------------------
# 6. Dirty data detections: defect types from corrections/flagged/unrepairable
# ---------------------------------------------------------------------------
dirty_data='[]'
if [[ -f "$ENRICHED_DIR/cleaning_log.json" ]]; then
    dirty_data=$(jq '[
        (.corrections // [])[],
        (.flagged // [])[],
        (.unrepairable // [])[]
        | .defect_type // .defect_type_tag // null
        | select(. != null and . != "")
    ] | unique' "$ENRICHED_DIR/cleaning_log.json" 2>/dev/null || echo '[]')
    jq -e . >/dev/null 2>&1 <<<"$dirty_data" || dirty_data='[]'
fi

# ---------------------------------------------------------------------------
# 7. Pipeline version (best effort)
# ---------------------------------------------------------------------------
pipeline_version="unknown"
ver_probe=$("$PIPELINE_BIN" --version 2>/dev/null || true)
pipeline_version=$(grep -oE '[0-9]+([.][0-9]+)+' <<<"$ver_probe" | head -n 1)
[[ -n "$pipeline_version" ]] || pipeline_version="unknown"

# ---------------------------------------------------------------------------
# 8. Write pipeline_run.json
# ---------------------------------------------------------------------------
jq -n \
    --arg version "$pipeline_version" \
    --arg started_at "$started_at" \
    --arg ended_at "$ended_at" \
    --argjson duration "$duration" \
    --arg input_pack "$(cd "$CAPSTONE_PACK" && pwd)" \
    --argjson events_in "$events_in" \
    --argjson events_out "$events_out" \
    --argjson events_dropped "$events_dropped" \
    --argjson windows_json "$windows_json" \
    --argjson linux_text "$linux_text" \
    --argjson firewall "$firewall" \
    --argjson suricata_alert "$suricata_alert" \
    --argjson pcap_flow "$pcap_flow" \
    --argjson dirty_data "$dirty_data" \
    '{
        pipeline_version: $version,
        started_at: $started_at,
        ended_at: $ended_at,
        duration_seconds: $duration,
        input_pack: $input_pack,
        events_in: $events_in,
        events_out: $events_out,
        events_dropped: $events_dropped,
        source_counts: {
            windows_json: $windows_json,
            linux_text: $linux_text,
            firewall: $firewall,
            suricata_alert: $suricata_alert,
            pcap_flow: $pcap_flow
        },
        dirty_data_detected: $dirty_data,
        exit_status: 0
    }' > "$RUNTIME_DIR/pipeline_run.json" \
    || die "failed to write pipeline_run.json"

log "pipeline_run.json written"

exit 0
