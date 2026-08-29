#!/bin/bash
#
# Name: 13-pipeline_test.sh
# Purpose: Generalization test — run pipeline against secondary evidence pack
#          and produce structured report of per-stage results. Discovers
#          stages dynamically from pipeline output rather than hardcoding.
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
STDOUT_FILE="${TEST_OUTPUT_DIR}/pipeline_stdout.log"
STDERR_FILE="${TEST_OUTPUT_DIR}/pipeline_stderr.log"
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

rm -rf "$TEST_OUTPUT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"

# --- Run pipeline ------------------------------------------------------------

echo "running pipeline against ${SECONDARY_PACK}"

cd "$SCRIPT_DIR"
PIPELINE_EXIT_CODE=0
"$PIPELINE_SCRIPT" "$SECONDARY_PACK" > "$STDOUT_FILE" 2> "$STDERR_FILE" || PIPELINE_EXIT_CODE=$?

# Combine into run log for full audit trail
cat "$STDOUT_FILE" "$STDERR_FILE" > "$RUN_LOG"

# --- Parse stage results dynamically from stdout -----------------------------
# Expected line format: [HH:MM:SS] stage N name ... ok (Xs)
# Or on failure:        [HH:MM:SS] stage N name ... FAIL

declare -A STAGE_RESULTS
declare -A STAGE_NAMES
STAGE_ORDER=()

while IFS= read -r line; do
    if [[ "$line" =~ \]\ stage\ ([0-9]+)\ +([a-z_]+)\ \.\.\.\ (ok|FAIL) ]]; then
        stage_num="${BASH_REMATCH[1]}"
        stage_name="${BASH_REMATCH[2]}"
        raw_result="${BASH_REMATCH[3]}"

        if [[ "$raw_result" == "ok" ]]; then
            STAGE_RESULTS["$stage_num"]="pass"
        else
            STAGE_RESULTS["$stage_num"]="fail"
        fi
        STAGE_NAMES["$stage_num"]="$stage_name"
        STAGE_ORDER+=("$stage_num")
    fi
done < "$STDOUT_FILE"

STAGE_PASS=0
STAGE_FAIL=0
for stage_num in "${STAGE_ORDER[@]}"; do
    if [[ "${STAGE_RESULTS[$stage_num]}" == "pass" ]]; then
        ((STAGE_PASS++))
    else
        ((STAGE_FAIL++))
    fi
done

STAGE_TOTAL=${#STAGE_ORDER[@]}

# --- Extract runtime and event count from final line -------------------------
# Expected: pipeline ok. N enriched events in Ts

EVENT_COUNT=0
RUNTIME_S=0

FINAL_LINE=$(grep -E "^pipeline ok\." "$STDOUT_FILE" 2>/dev/null | tail -1)
if [[ -n "$FINAL_LINE" ]]; then
    if [[ "$FINAL_LINE" =~ ([0-9]+)\ enriched\ events ]]; then
        EVENT_COUNT="${BASH_REMATCH[1]}"
    fi
    if [[ "$FINAL_LINE" =~ in\ ([0-9]+)s ]]; then
        RUNTIME_S="${BASH_REMATCH[1]}"
    fi
fi

# --- Discover output directory from pipeline run log -------------------------
# The pipeline logs "Working directory: /path" — use that to locate artifacts.
# Fall back to SCRIPT_DIR if not found.

OUTPUT_DIR="$SCRIPT_DIR"
LOG_WORKDIR=$(grep -E "^Working directory:" "$RUN_LOG" 2>/dev/null | head -1 | sed 's/^Working directory: //')
if [[ -n "$LOG_WORKDIR" ]] && [[ -d "$LOG_WORKDIR" ]]; then
    OUTPUT_DIR="$LOG_WORKDIR"
fi

# --- Verify output artifacts -------------------------------------------------

ENRICHED_FILE="${OUTPUT_DIR}/enriched_events.json"
TIMELINE_FILE="${OUTPUT_DIR}/timeline_index.json"

ENRICHED_VALID=false
TIMELINE_VALID=false

if [[ -s "$ENRICHED_FILE" ]]; then
    ENRICHED_VALID=true
    # Use actual line count as ground truth
    ACTUAL_COUNT=$(wc -l < "$ENRICHED_FILE" | tr -d '[:space:]')
    if [[ "$ACTUAL_COUNT" -gt 0 ]]; then
        EVENT_COUNT="$ACTUAL_COUNT"
    fi
fi

if [[ -s "$TIMELINE_FILE" ]]; then
    TIMELINE_VALID=true
fi

# --- Determine verdict -------------------------------------------------------

VERDICT="pass"

# Any stage failure = fail
if [[ $STAGE_FAIL -gt 0 ]]; then
    VERDICT="fail"
fi

# Pipeline exited non-zero = fail
if [[ $PIPELINE_EXIT_CODE -ne 0 ]]; then
    VERDICT="fail"
fi

# Required output missing or empty = fail
if [[ "$ENRICHED_VALID" == "false" ]]; then
    VERDICT="fail"
fi

if [[ "$TIMELINE_VALID" == "false" ]]; then
    VERDICT="fail"
fi

# No stages parsed at all = parsing failure = fail
if [[ $STAGE_TOTAL -eq 0 ]]; then
    VERDICT="fail"
fi

# --- Build JSON report -------------------------------------------------------

STAGES_JSON="["
first=true
for stage_num in "${STAGE_ORDER[@]}"; do
    result="${STAGE_RESULTS[$stage_num]}"
    name="${STAGE_NAMES[$stage_num]}"
    if [[ "$first" == "true" ]]; then
        first=false
    else
        STAGES_JSON+=","
    fi
    STAGES_JSON+="{\"stage\":${stage_num},\"name\":\"${name}\",\"result\":\"${result}\"}"
done
STAGES_JSON+="]"

cat > "$REPORT_FILE" << EOF
{
  "test_name": "pipeline_generalization",
  "pack_path": "${SECONDARY_PACK}",
  "pipeline_exit_code": ${PIPELINE_EXIT_CODE},
  "stages": ${STAGES_JSON},
  "total_stages": ${STAGE_TOTAL},
  "passed_stages": ${STAGE_PASS},
  "failed_stages": ${STAGE_FAIL},
  "enriched_events": ${EVENT_COUNT},
  "enriched_file": "${ENRICHED_FILE}",
  "enriched_file_valid": ${ENRICHED_VALID},
  "timeline_file": "${TIMELINE_FILE}",
  "timeline_file_valid": ${TIMELINE_VALID},
  "runtime_seconds": ${RUNTIME_S},
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
