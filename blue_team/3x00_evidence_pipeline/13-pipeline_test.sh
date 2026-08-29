#!/bin/bash
#
# Name: 13-pipeline_test.sh
# Purpose: Generalization test - run pipeline against secondary evidence pack
#          and produce structured report of per-stage results.
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -uo pipefail

# --- Configuration -----------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_SCRIPT="${SCRIPT_DIR}/evidence_pipeline.sh"
SECONDARY_PACK="${HOME}/evidence_pack_secondary"
TEST_OUTPUT_DIR="${SCRIPT_DIR}/test_output"
REPORT_FILE="${SCRIPT_DIR}/pipeline_test_report.json"
RUN_LOG="${TEST_OUTPUT_DIR}/pipeline_run.log"

# --- Pre-flight checks -------------------------------------------------------

if [[ ! -x "$PIPELINE_SCRIPT" ]]; then
    echo "[ERROR] Pipeline script not found or not executable: $PIPELINE_SCRIPT" >&2
    exit 1
fi

if [[ ! -d "$SECONDARY_PACK" ]]; then
    echo "[ERROR] Secondary evidence pack not found: $SECONDARY_PACK" >&2
    exit 1
fi

# Create test output directory
rm -rf "$TEST_OUTPUT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"

# --- Run pipeline ------------------------------------------------------------

echo "running pipeline against ${SECONDARY_PACK}"

cd "$SCRIPT_DIR"
PIPELINE_EXIT_CODE=0
"$PIPELINE_SCRIPT" "$SECONDARY_PACK" >> "$RUN_LOG" 2>&1 || PIPELINE_EXIT_CODE=$?

# --- Parse per-stage results -------------------------------------------------

declare -A STAGE_RESULTS
STAGE_NAMES=(
    [0]="source_inventory"
    [1]="telemetry_import"
    [2]="windows_parse"
    [3]="linux_parse"
    [5]="normalize"
    [6]="network_normalize"
    [7]="schema_validate"
    [8]="data_quality"
    [9]="enrich"
    [10]="timeline"
    [11]="source_stats"
)

STAGE_PASS=0
STAGE_FAIL=0

for stage_num in "${!STAGE_NAMES[@]}"; do
    stage_name="${STAGE_NAMES[$stage_num]}"

    # Look for "ok" in log for this stage
    if grep -qE "stage\s+${stage_num}\s+${stage_name}\s+\.\.\.\s+ok" "$RUN_LOG"; then
        STAGE_RESULTS["$stage_num"]="pass"
        ((STAGE_PASS++))
    elif grep -qE "stage\s+${stage_num}\s+${stage_name}\s+\.\.\.\s+FAIL" "$RUN_LOG"; then
        STAGE_RESULTS["$stage_num"]="fail"
        ((STAGE_FAIL++))
    else
        STAGE_RESULTS["$stage_num"]="missing"
    fi
done

STAGE_TOTAL=$((STAGE_PASS + STAGE_FAIL))

# --- Extract runtime and event count -----------------------------------------

RUNTIME_S="0"
RUNTIME_LINE=$(grep -E "Total runtime:" "$RUNLOG" 2>/dev/null || grep -E "^\[" "$RUN_LOG" | tail -1)
if [[ -n "$RUNTIME_LINE" ]]; then
    RUNTIME_S=$(echo "$RUNTIME_LINE" | grep -oE '[0-9]+s' | tr -d 's')
    if [[ -z "$RUNTIME_S" ]]; then
        RUNTIME_S=$(echo "$RUNTIME_LINE" | grep -oE 'in [0-9]+s' | grep -oE '[0-9]+' || echo "0")
    fi
fi

# Extract enriched event count
ENRICHED_FILE="${SCRIPT_DIR}/enriched_events.json"
EVENT_COUNT=0
if [[ -f "$ENRICHED_FILE" ]]; then
    EVENT_COUNT=$(wc -l < "$ENRICHED_FILE" 2>/dev/null || echo 0)
    # Trim whitespace
    EVENT_COUNT=$(echo "$EVENT_COUNT" | tr -d '[:space:]')
fi

# Verify outputs exist and are non-empty
TILEMINE_FILE="${SCRIPT_DIR}/timeline_index.json"
ENRICHED_VALID=true
TILEMINE_VALID=true

if [[ ! -s "$ENRICHED_FILE" ]]; then
    ENRICHED_VALID=false
fi

if [[ ! -s "$TILEMINE_FILE" ]]; then
    TILEMINE_VALID=false
fi

# --- Determine verdict -------------------------------------------------------

VERDICT="pass"
if [[ $STAGE_FAIL -gt 0 ]] || [[ "$ENRICHED_VALID" == "false" ]] || [[ "$TILEMINE_VALID" == "false" ]]; then
    VERDICT="fail"
fi

if [[ $PIPELINE_EXIT_CODE -ne 0 ]] && [[ "$VERDICT" == "pass" ]]; then
    VERDICT="fail"
fi

# --- Build JSON report -------------------------------------------------------

STAGES_JSON="["
first=true
for num in 0 1 2 3 5 6 7 8 9 10 11; do
    result="${STAGE_RESULTS[$num]:-missing}"
    if [[ "$first" == "true" ]]; then
        first=false
    else
        STAGES_JSON+=","
    fi
    STAGES_JSON+="{\"stage\":${num},\"result\":\"${result}\"}"
done
STAGES_JSON+="]"

cat > "$REPORT_FILE" << EOF
{
  "test_name": "pipeline_generalization",
  "pack_path": "${SECONDARY_PACK}",
  "stages": ${STAGES_JSON},
  "total_stages": ${STAGE_TOTAL},
  "passed_stages": ${STAGE_PASS},
  "failed_stages": ${STAGE_FAIL},
  "enriched_events": ${EVENT_COUNT},
  "enriched_file_valid": ${ENRICHED_VALID},
  "timeline_file_valid": ${TILEMINE_VALID},
  "runtime_seconds": ${RUNTIME_S:-0},
  "verdict": "${VERDICT}"
}
EOF

# --- Output summary ----------------------------------------------------------

echo "all ${STAGE_PASS} stages passed"
echo "enriched events: ${EVENT_COUNT}"
echo "runtime: ${RUNTIME_S}s"
echo "verdict: ${VERDICT}"
echo "pipeline_test_report.json written"

# --- Exit code ---------------------------------------------------------------

if [[ "$VERDICT" == "pass" ]]; then
    exit 0
else
    exit 1
fi
