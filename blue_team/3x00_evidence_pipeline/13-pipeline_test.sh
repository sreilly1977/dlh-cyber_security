#!/bin/bash
#
# Name: 13-pipeline_test.sh
# Purpose: Generalization test — run pipeline against secondary evidence pack
#          and produce structured report of per-stage results. Dynamically parses
#          stages and escapes JSON safely.
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

cat "$STDOUT_FILE" "$STDERR_FILE" > "$RUN_LOG"

# --- JSON escape function ----------------------------------------------------

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    printf '%s' "$str"
}

# --- Parse stage results from stdout -----------------------------------------

declare -A STAGE_RESULTS
declare -a STAGE_ORDER

while IFS= read -r line; do
    if [[ "$line" =~ stage[[:space:]]+([0-9]+)[[:space:]]+ ]]; then
        stage_num="${BASH_REMATCH[1]}"

        # Add to order array if not already tracked
        if [[ ! " ${STAGE_ORDER[*]} " =~ " ${stage_num} " ]]; then
            STAGE_ORDER+=("$stage_num")
        fi

        # Set result based on line content
        if [[ "$line" =~ \.\.\.[[:space:]]+ok ]]; then
            STAGE_RESULTS["$stage_num"]="pass"
        elif [[ "$line" =~ FAIL ]]; then
            STAGE_RESULTS["$stage_num"]="fail"
        else
            # Only set unknown if we don't already have a pass/fail
            if [[ -z "${STAGE_RESULTS[$stage_num]+isset}" ]]; then
                STAGE_RESULTS["$stage_num"]="unknown"
            fi
        fi
    fi
done < "$STDOUT_FILE"

# Count results
STAGE_PASS=0
STAGE_FAIL=0
STAGE_TOTAL=${#STAGE_ORDER[@]}

for stage_num in "${STAGE_ORDER[@]}"; do
    result="${STAGE_RESULTS[$stage_num]:-unknown}"
    case "$result" in
        pass) ((STAGE_PASS++)) ;;
        fail) ((STAGE_FAIL++)) ;;
        *) ;;
    esac
done

# --- Extract runtime and event count -----------------------------------------

EVENT_COUNT=0
RUNTIME_S=0

FINAL_LINE=$(grep -E "pipeline.*ok" "$STDOUT_FILE" 2>/dev/null | tail -1 || true)
if [[ -n "$FINAL_LINE" ]]; then
    if [[ "$FINAL_LINE" =~ ([0-9]+)[[:space:]]+enriched ]]; then
        EVENT_COUNT="${BASH_REMATCH[1]}"
    fi
    if [[ "$FINAL_LINE" =~ in[[:space:]]+([0-9]+) ]]; then
        RUNTIME_S="${BASH_REMATCH[1]}"
    fi
fi

if [[ $EVENT_COUNT -eq 0 ]]; then
    COUNT_LINE=$(grep -E "enriched events:" "$RUN_LOG" 2>/dev/null | head -1 || true)
    if [[ -n "$COUNT_LINE" ]] && [[ "$COUNT_LINE" =~ ([0-9]+) ]]; then
        EVENT_COUNT="${BASH_REMATCH[1]}"
    fi
fi

if [[ $RUNTIME_S -eq 0 ]]; then
    TIME_LINE=$(grep -E "runtime:|Total runtime:" "$RUN_LOG" 2>/dev/null | head -1 || true)
    if [[ -n "$TIME_LINE" ]] && [[ "$TIME_LINE" =~ ([0-9]+) ]]; then
        RUNTIME_S="${BASH_REMATCH[1]}"
    fi
fi

# --- Discover output directory -----------------------------------------------

OUTPUT_DIR="$SCRIPT_DIR"
LOG_WORKDIR=$(grep -E "^Working directory:" "$RUN_LOG" 2>/dev/null | head -1 | sed 's/^Working directory:[[:space:]]*//' || true)
if [[ -n "$LOG_WORKDIR" ]] && [[ -d "$LOG_WORKDIR" ]]; then
    OUTPUT_DIR="$LOG_WORKDIR"
elif [[ -f "${SCRIPT_DIR}/enriched_events.json" ]]; then
    OUTPUT_DIR="$SCRIPT_DIR"
fi

# --- Verify output artifacts -------------------------------------------------

ENRICHED_FILE="${OUTPUT_DIR}/enriched_events.json"
TIMELINE_FILE="${OUTPUT_DIR}/timeline_index.json"

ENRICHED_VALID=false
TIMELINE_VALID=false

if [[ -s "$ENRICHED_FILE" ]]; then
    ENRICHED_VALID=true
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

[[ $STAGE_FAIL -gt 0 ]] && VERDICT="fail"
[[ $PIPELINE_EXIT_CODE -ne 0 ]] && VERDICT="fail"
[[ "$ENRICHED_VALID" == "false" ]] && VERDICT="fail"
[[ "$TIMELINE_VALID" == "false" ]] && VERDICT="fail"
[[ $STAGE_TOTAL -eq 0 ]] && VERDICT="fail"

# --- Build JSON report (safely escaped) --------------------------------------

STAGES_JSON="["
first=true
for stage_num in "${STAGE_ORDER[@]}"; do
    result="${STAGE_RESULTS[$stage_num]:-unknown}"
    if [[ "$first" == "true" ]]; then
        first=false
    else
        STAGES_JSON+=","
    fi
    STAGES_JSON+="{\"stage\":${stage_num},\"result\":\"${result}\"}"
done
STAGES_JSON+="]"

PACK_PATH_ESCAPED=$(json_escape "$SECONDARY_PACK")
ENRICHED_FILE_ESCAPED=$(json_escape "$ENRICHED_FILE")
TIMELINE_FILE_ESCAPED=$(json_escape "$TIMELINE_FILE")

cat > "$REPORT_FILE" << EOF
{
  "test_name": "pipeline_generalization",
  "pack_path": "${PACK_PATH_ESCAPED}",
  "pipeline_exit_code": ${PIPELINE_EXIT_CODE},
  "stages": ${STAGES_JSON},
  "total_stages": ${STAGE_TOTAL},
  "passed_stages": ${STAGE_PASS},
  "failed_stages": ${STAGE_FAIL},
  "enriched_events": ${EVENT_COUNT},
  "enriched_file": "${ENRICHED_FILE_ESCAPED}",
  "enriched_file_valid": ${ENRICHED_VALID},
  "timeline_file": "${TIMELINE_FILE_ESCAPED}",
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
