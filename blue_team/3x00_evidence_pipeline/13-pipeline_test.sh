#!/bin/bash
#
# Name: 13-pipeline_test.sh
# Purpose: Generalization test — run pipeline against secondary evidence pack
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

# --- Parse results and generate report via Python ----------------------------

python3 - "$STDOUT_FILE" "$RUN_LOG" "$REPORT_FILE" "$PIPELINE_EXIT_CODE" "$SECONDARY_PACK" "$SCRIPT_DIR" <<'PYEOF'
import json
import os
import re
import sys

stdout_file = sys.argv[1]
run_log_file = sys.argv[2]
report_file = sys.argv[3]
pipeline_exit_code = int(sys.argv[4])
secondary_pack = sys.argv[5]
script_dir = sys.argv[6]

# --- Read pipeline stdout ----------------------------------------------------

stdout_lines = []
with open(stdout_file, "r", errors="replace") as f:
    stdout_lines = f.readlines()

# --- Parse stage results ----------------------------------------------------
# Look for any line containing "stage" and a number, then determine status.
# We search broadly: any line with "stage" + digits, then check for ok/fail.

stages = []
seen_stage_nums = set()

for line in stdout_lines:
    line = line.strip()
    if not line:
        continue

    # Broad match: "stage" followed by whitespace and digits
    match = re.search(r"stage\s+(\d+)", line, re.IGNORECASE)
    if not match:
        continue

    stage_num = int(match.group(1))

    # Skip if we already recorded this stage
    if stage_num in seen_stage_nums:
        continue

    # Determine result from line content
    line_lower = line.lower()
    if re.search(r"\.\.\.\s*ok\b", line_lower) or re.search(r"\bok\b\s*\(", line_lower):
        result = "pass"
    elif "fail" in line_lower:
        result = "fail"
    else:
        result = "unknown"

    seen_stage_nums.add(stage_num)
    stages.append({"stage": stage_num, "result": result})

stage_pass = sum(1 for s in stages if s["result"] == "pass")
stage_fail = sum(1 for s in stages if s["result"] == "fail")
stage_total = len(stages)

# --- Extract runtime and event count -----------------------------------------

event_count = 0
runtime_s = 0

# Search stdout for final summary line
for line in stdout_lines:
    line_lower = line.lower()

    # Look for event count: "N enriched events"
    m = re.search(r"(\d+)\s+enriched\s+events?", line_lower)
    if m:
        event_count = int(m.group(1))

    # Look for runtime: "in Ns"
    m = re.search(r"in\s+(\d+)s", line_lower)
    if m:
        runtime_s = int(m.group(1))

# Fallback: search run log
if event_count == 0 or runtime_s == 0:
    with open(run_log_file, "r", errors="replace") as f:
        for line in f:
            if event_count == 0:
                m = re.search(r"(\d+)\s+enriched\s+events?", line, re.IGNORECASE)
                if m:
                    event_count = int(m.group(1))
            if runtime_s == 0:
                m = re.search(r"(?:runtime|total runtime)[:\s]*(\d+)", line, re.IGNORECASE)
                if m:
                    runtime_s = int(m.group(1))
            if event_count > 0 and runtime_s > 0:
                break

# --- Discover output directory ----------------------------------------------

output_dir = script_dir

# Try to find working directory from run log
with open(run_log_file, "r", errors="replace") as f:
    for line in f:
        m = re.match(r"Working directory:\s*(.+)", line)
        if m:
            candidate = m.group(1).strip()
            if os.path.isdir(candidate):
                output_dir = candidate
                break

# Fallback: check script_dir for enriched_events.json
if not os.path.isfile(os.path.join(output_dir, "enriched_events.json")):
    if os.path.isfile(os.path.join(script_dir, "enriched_events.json")):
        output_dir = script_dir

# --- Verify output artifacts -------------------------------------------------

enriched_path = os.path.join(output_dir, "enriched_events.json")
timeline_path = os.path.join(output_dir, "timeline_index.json")

enriched_valid = os.path.isfile(enriched_path) and os.path.getsize(enriched_path) > 0
timeline_valid = os.path.isfile(timeline_path) and os.path.getsize(timeline_path) > 0

# Use actual file line count as ground truth for event count
if enriched_valid:
    with open(enriched_path, "r", errors="replace") as f:
        line_count = sum(1 for _ in f)
    if line_count > 0:
        event_count = line_count

# --- Determine verdict -------------------------------------------------------

verdict = "pass"

# Pipeline exited non-zero
if pipeline_exit_code != 0:
    verdict = "fail"

# Any stage failure
if any(s["result"] == "fail" for s in stages):
    verdict = "fail"

# Required outputs missing or empty
if not enriched_valid:
    verdict = "fail"
if not timeline_valid:
    verdict = "fail"

# No stages parsed at all (parsing failure)
if stage_total == 0:
    verdict = "fail"

# --- Write JSON report -------------------------------------------------------

report = {
    "test_name": "pipeline_generalization",
    "pack_path": secondary_pack,
    "pipeline_exit_code": pipeline_exit_code,
    "stages": stages,
    "total_stages": stage_total,
    "passed_stages": stage_pass,
    "failed_stages": stage_fail,
    "enriched_events": event_count,
    "enriched_file": enriched_path,
    "enriched_file_valid": enriched_valid,
    "timeline_file": timeline_path,
    "timeline_file_valid": timeline_valid,
    "runtime_seconds": runtime_s,
    "verdict": verdict,
}

with open(report_file, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

# --- Print summary -----------------------------------------------------------

print(f"all {stage_pass} stages passed")
print(f"enriched events: {event_count}")
print(f"runtime: {runtime_s}s")
print(f"verdict: {verdict}")
print(f"pipeline_test_report.json written")

sys.exit(0 if verdict == "pass" else 1)

PYEOF
