#!/bin/bash
#
# Name: evidence_pipeline.sh
# Purpose: Orchestrator script that runs the full intake-to-handoff chain.
#          Validates evidence pack, runs all pipeline stages in order,
#          logs progress with timestamps, fails fast on first error.
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -euo pipefail

# --- Argument validation -----------------------------------------------------

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <evidence-pack-path>" >&2
    exit 1
fi

EVIDENCE_PACK="$1"

# Resolve to absolute path
EVIDENCE_PACK="$(cd "$EVIDENCE_PACK" 2>/dev/null && pwd)" || {
    echo "[ERROR] Evidence pack not found: $1" >&2
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="${PWD}"
RUN_LOG="${WORKDIR}/pipeline_run.log"

# Export for child scripts
export EVIDENCE_PACK
export WORKDIR

# --- Directory validation (silent) -------------------------------------------

REQUIRED_DIRS=("windows" "linux" "network" "context" "student_telemetry")
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "$EVIDENCE_PACK/$dir" ]]; then
        echo "[ERROR] Missing directory: $EVIDENCE_PACK/$dir" >&2
        exit 1
    fi
done

if [[ ! -f "$WORKDIR/event_schema.json" ]]; then
    echo "[ERROR] event_schema.json not found in $WORKDIR" >&2
    exit 1
fi

# --- Runtime tracking --------------------------------------------------------

PIPELINE_START=$(date +%s)

# Initialize run log
echo "Pipeline run started at $(date '+%Y-%m-%dT%H:%M:%SZ')" > "$RUN_LOG"
echo "Evidence pack: $EVIDENCE_PACK" >> "$RUN_LOG"
echo "Working directory: $WORKDIR" >> "$RUN_LOG"
echo "" >> "$RUN_LOG"

# --- Stage execution function ------------------------------------------------

run_stage() {
    local stage_num="$1"
    local desc="$2"

    local stage_start=$(date +%s)
    local stage_start_ts=$(date +"%H:%M:%S")

    # Run the stage, capturing stdout+stderr to run log
    "$SCRIPT_DIR/${stage_num}-${desc}.sh" >> "$RUN_LOG" 2>&1
    local exit_code=$?

    local stage_end=$(date +%s)
    local stage_duration=$((stage_end - stage_start))
    local stage_end_ts=$(date +"%H:%M:%S")

    if [[ $exit_code -eq 0 ]]; then
        printf "[%s] stage %-2s %-20s ... ok (%ds)\n" "$stage_end_ts" "$stage_num" "$desc" "$stage_duration"
    else
        echo "FAIL"
        echo "[ERROR] Stage $stage_num ($desc) exited with code $exit_code" >&2
        echo "" >&2
        echo "See pipeline_run.log for details:" >&2
        echo "  tail -50 $RUN_LOG" >&2
        exit $exit_code
    fi
}

# --- Stage definitions (number|description) -----------------------------------
# Note: stage 4 (schema design) is skipped — not a pipeline stage

run_stage "0"  "source_inventory"
run_stage "1"  "telemetry_import"
run_stage "2"  "windows_parse"
run_stage "3"  "linux_parse"
run_stage "5"  "normalize"
run_stage "6"  "network_normalize"
run_stage "7"  "schema_validate"
run_stage "8"  "data_quality"
run_stage "9"  "enrich"
run_stage "10" "timeline"
run_stage "11" "source_stats"

# --- Final reporting ---------------------------------------------------------

PIPELINE_END=$(date +%s)
TOTAL_DURATION=$((PIPELINE_END - PIPELINE_START))

ENRICHED_COUNT=0
if [[ -f "$WORKDIR/enriched_events.json" ]]; then
    ENRICHED_COUNT=$(wc -l < "$WORKDIR/enriched_events.json")
fi

echo "pipeline ok. ${ENRICHED_COUNT} enriched events in ${TOTAL_DURATION}s"

echo "" >> "$RUN_LOG"
echo "Pipeline completed at $(date '+%Y-%m-%dT%H:%M:%SZ')" >> "$RUN_LOG"
echo "Total runtime: ${TOTAL_DURATION}s" >> "$RUN_LOG"
echo "Enriched events: ${ENRICHED_COUNT}" >> "$RUN_LOG"

exit 0
