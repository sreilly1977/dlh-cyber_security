#!/bin/bash
#
# Name: evidence_pipeline.sh
# Purpose: Orchestrator script that runs the full intake-to-handoff chain.
#          Validates evidence pack, runs all pipeline stages in order,
#          logs progress with timestamps, fails fast on first error,
#          and verifies expected artifacts after each stage.
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -euo pipefail

# --- Argument validation -----------------------------------------------------

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <evidence-pack-path>" >&2
    exit 1
fi

EVIDENCE_PACK_INPUT="$1"

# Resolve to absolute path
if [[ ! -d "$EVIDENCE_PACK_INPUT" ]]; then
    echo "[ERROR] Evidence pack path is not a directory: $EVIDENCE_PACK_INPUT" >&2
    exit 1
fi

EVIDENCE_PACK="$(cd "$EVIDENCE_PACK_INPUT" && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="${PWD}"
RUN_LOG="${WORKDIR}/pipeline_run.log"

# Export for child scripts
export EVIDENCE_PACK
export WORKDIR

# --- Directory validation ----------------------------------------------------

REQUIRED_DIRS=("windows" "linux" "network" "context" "student_telemetry")
MISSING_DIRS=()
for dir in "${REQUIRED_DIRS[@]}"; do
    if [[ ! -d "$EVIDENCE_PACK/$dir" ]]; then
        MISSING_DIRS+=("$dir")
    fi
done

if [[ ${#MISSING_DIRS[@]} -gt 0 ]]; then
    echo "[ERROR] Missing required directories in evidence pack:" >&2
    for d in "${MISSING_DIRS[@]}"; do
        echo "  $EVIDENCE_PACK/$d" >&2
    done
    exit 1
fi

if [[ ! -f "$WORKDIR/event_schema.json" ]]; then
    echo "[ERROR] event_schema.json not found in $WORKDIR" >&2
    echo "        Task 4 (schema design) must be completed before running the pipeline." >&2
    exit 1
fi

# --- Stage definitions -------------------------------------------------------
# Each stage is: number|script_name|description|expected_artifact(s)
# Stage 4 (schema design) is intentionally excluded — it is a design task,
# not a data processing stage. Its output (event_schema.json) must already
# exist in the working directory when the pipeline runs.

STAGE_DEFINITIONS=(
    "0|0-source_inventory.sh|source_inventory|$WORKDIR/source_inventory.json"
    "1|1-telemetry_import.sh|telemetry_import|$WORKDIR/import_validation.json"
    "2|2-windows_parse.sh|windows_parse|$WORKDIR/windows_events.json"
    "3|3-linux_parse.sh|linux_parse|$WORKDIR/linux_events.json"
    "5|5-normalize.sh|normalize|$WORKDIR/normalized_events.json"
    "6|6-network_normalize.sh|network_normalize|$WORKDIR/network_events.json"
    "7|7-schema_validate.sh|schema_validate|$WORKDIR/validation_report.json"
    "8|8-data_quality.sh|data_quality|$WORKDIR/cleaned_events.json,$WORKDIR/cleaning_log.json"
    "9|9-enrich.sh|enrich|$WORKDIR/enriched_events.json"
    "10|10-timeline.sh|timeline|$WORKDIR/timeline_index.json"
    "11|11-source_stats.sh|source_stats|$WORKDIR/source_stats.json"
)

# --- Runtime tracking --------------------------------------------------------

PIPELINE_START=$(date +%s)

echo "Pipeline run started at $(date '+%Y-%m-%dT%H:%M:%SZ')" > "$RUN_LOG"
echo "Evidence pack: $EVIDENCE_PACK" >> "$RUN_LOG"
echo "Working directory: $WORKDIR" >> "$RUN_LOG"
echo "Schema: $WORKDIR/event_schema.json" >> "$RUN_LOG"
echo "" >> "$RUN_LOG"

# --- Stage execution function ------------------------------------------------

run_stage() {
    local stage_num="$1"
    local script_name="$2"
    local desc="$3"
    local artifacts_csv="$4"

    local script_path="${SCRIPT_DIR}/${script_name}"

    if [[ ! -f "$script_path" ]]; then
        echo "FAIL"
        echo "[ERROR] Stage $stage_num script not found: $script_path" >&2
        exit 1
    fi

    if [[ ! -x "$script_path" ]]; then
        echo "FAIL"
        echo "[ERROR] Stage $stage_num script not executable: $script_path" >&2
        exit 1
    fi

    local stage_start=$(date +%s)

    echo "--- Stage $stage_num ($desc) started at $(date '+%H:%M:%S') ---" >> "$RUN_LOG"
    if ! "$script_path" >> "$RUN_LOG" 2>&1; then
        local exit_code=$?
        echo "FAIL"
        echo "[ERROR] Stage $stage_num ($desc) exited with code $exit_code" >&2
        echo "" >&2
        echo "Last 20 lines of pipeline_run.log:" >&2
        tail -20 "$RUN_LOG" >&2
        exit "$exit_code"
    fi

    local stage_end=$(date +%s)
    local stage_duration=$((stage_end - stage_start))

    # Verify expected artifacts were produced
    local missing_artifacts=()
    IFS=',' read -ra artifacts <<< "$artifacts_csv"
    for artifact in "${artifacts[@]}"; do
        artifact="${artifact}"
        if [[ ! -f "$artifact" ]]; then
            missing_artifacts+=("$artifact")
        fi
    done

    if [[ ${#missing_artifacts[@]} -gt 0 ]]; then
        echo "FAIL"
        echo "[ERROR] Stage $stage_num ($desc) completed but expected artifacts missing:" >&2
        for a in "${missing_artifacts[@]}"; do
            echo "  $a" >&2
        done
        exit 1
    fi

    local stage_end_ts=$(date +"%H:%M:%S")
    printf "[%s] stage %-2s %-20s ... ok (%ds)\n" "$stage_end_ts" "$stage_num" "$desc" "$stage_duration"
}

# --- Run pipeline stages -----------------------------------------------------

for stage_def in "${STAGE_DEFINITIONS[@]}"; do
    IFS='|' read -r stage_num script_name desc artifacts <<< "$stage_def"
    run_stage "$stage_num" "$script_name" "$desc" "$artifacts"
done

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
