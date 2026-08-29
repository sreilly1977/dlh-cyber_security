#!/bin/bash
#
# Name: 13-pipeline_test.sh
# Purpose: Generalization test — run pipeline against secondary evidence pack
#          and produce structured report of per-stage results.
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_SCRIPT="${SCRIPT_DIR}/evidence_pipeline.sh"
SECONDARY_PACK="${HOME}/evidence_pack_secondary"
TEST_OUTPUT_DIR="${SCRIPT_DIR}/test_output"
REPORT_FILE="${SCRIPT_DIR}/pipeline_test_report.json"

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

echo "running pipeline against ${SECONDARY_PACK}"

cd "$SCRIPT_DIR"
PIPELINE_EXIT_CODE=0
"$PIPELINE_SCRIPT" "$SECONDARY_PACK" > "${TEST_OUTPUT_DIR}/pipeline_stdout.log" 2> "${TEST_OUTPUT_DIR}/pipeline_stderr.log" || PIPELINE_EXIT_CODE=$?

python3 - "$PIPELINE_EXIT_CODE" "$SECONDARY_PACK" "$SCRIPT_DIR" "$REPORT_FILE" <<'PYEOF'
import json
import os
import re
import sys

pipeline_exit_code = int(sys.argv[1])
secondary_pack = sys.argv[2]
script_dir = sys.argv[3]
report_file = sys.argv[4]

# Read pipeline's own run log
run_log_path = os.path.join(script_dir, "pipeline_run.log")
run_log_lines = []
if os.path.isfile(run_log_path):
    with open(run_log_path, "r", errors="replace") as f:
        run_log_lines = f.readlines()

# Read captured stdout
stdout_path = os.path.join(script_dir, "test_output", "pipeline_stdout.log")
stdout_lines = []
if os.path.isfile(stdout_path):
    with open(stdout_path, "r", errors="replace") as f:
        stdout_lines = f.readlines()

# Stage numbers in execution order (4 is design task, not a pipeline stage)
EXPECTED_STAGES = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11]

# Build a set of stage numbers that appear as completed in stdout.
# The pipeline prints "[HH:MM:SS] stage N name ... ok (Xs)" on success.
# On failure it prints "FAIL" and exits.
completed_stages = set()
failed_stage = None

for line in stdout_lines:
    # Match the pipeline's own output format precisely
    m = re.match(
        r"^\[\d{2}:\d{2}:\d{2}\]\s+stage\s+(\d+)\s+\S+\s+\.\.\.\s+ok\s*\(\d+s\)\s*$",
        line.strip()
    )
    if m:
        completed_stages.add(int(m.group(1)))
        continue

    # Check for FAIL line (pipeline prints "FAIL" then error to stderr)
    if "FAIL" in line:
        m2 = re.match(
            r"^\[\d{2}:\d{2}:\d{2}\]\s+stage\s+(\d+)\s+\S+\s+\.\.\.\s+FAIL",
            line.strip()
        )
        if m2:
            failed_stage = int(m2.group(1))

# Also check run log for stage markers as fallback
for line in run_log_lines:
    if line.startswith("--- Stage ") and "started" in line:
        m = re.search(r"---\s+Stage\s+(\d+)\s+\((\S+)\)\s+started", line)
        if m:
            num = int(m.group(1))
            if num not in completed_stages and num != failed_stage:
                # Stage started but we have no completion record
                pass

# Build stage results
stages = []
for num in EXPECTED_STAGES:
    if num in completed_stages:
        stages.append({"stage": num, "result": "pass"})
    elif num == failed_stage:
        stages.append({"stage": num, "result": "fail"})
    elif pipeline_exit_code == 0:
        stages.append({"stage": num, "result": "pass"})
    else:
        stages.append({"stage": num, "result": "not_reached"})

stage_pass = sum(1 for s in stages if s["result"] == "pass")
stage_fail_count = sum(1 for s in stages if s["result"] == "fail")

# Runtime: read directly from pipeline_run.log "Total runtime: Ns"
runtime_s = 0
for line in run_log_lines:
    m = re.match(r"^Total runtime:\s*(\d+)s\s*$", line)
    if m:
        runtime_s = int(m.group(1))
        break

# Event count from pipeline_run.log "Enriched events: N"
event_count = 0
for line in run_log_lines:
    m = re.match(r"^Enriched events:\s*(\d+)\s*$", line)
    if m:
        event_count = int(m.group(1))
        break


def validate_ndjson(path, required_fields):
    """Validate NDJSON: exists, non-empty, every line parseable, first record has required fields."""
    if not os.path.isfile(path):
        return False, 0
    if os.path.getsize(path) == 0:
        return False, 0
    count = 0
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                record = json.loads(stripped)
                count += 1
                if count == 1:
                    for field in required_fields:
                        if field not in record:
                            return False, count
    except (json.JSONDecodeError, IOError):
        return False, count
    return count > 0, count


enriched_path = os.path.join(script_dir, "enriched_events.json")
timeline_path = os.path.join(script_dir, "timeline_index.json")

required_fields = [
    "timestamp", "hostname", "source_type",
    "event_category", "severity", "summary", "event_ref"
]

enriched_valid, enriched_count = validate_ndjson(enriched_path, required_fields)
timeline_valid, timeline_count = validate_ndjson(timeline_path, required_fields)

if enriched_valid and enriched_count > 0:
    event_count = enriched_count

# Verdict
verdict = "pass"
if pipeline_exit_code != 0:
    verdict = "fail"
if not enriched_valid:
    verdict = "fail"
if not timeline_valid:
    verdict = "fail"

report = {
    "test_name": "pipeline_generalization",
    "pack_path": secondary_pack,
    "pipeline_exit_code": pipeline_exit_code,
    "stages": stages,
    "total_stages": len(stages),
    "passed_stages": stage_pass,
    "failed_stages": stage_fail_count,
    "enriched_events": event_count,
    "enriched_file": enriched_path,
    "enriched_file_valid": enriched_valid,
    "enriched_record_count": enriched_count if enriched_valid else 0,
    "timeline_file": timeline_path,
    "timeline_file_valid": timeline_valid,
    "timeline_record_count": timeline_count if timeline_valid else 0,
    "runtime_seconds": runtime_s,
    "verdict": verdict,
}

with open(report_file, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

print(f"all {stage_pass} stages passed")
print(f"enriched events: {event_count}")
print(f"runtime: {runtime_s}s")
print(f"verdict: {verdict}")
print(f"pipeline_test_report.json written")

sys.exit(0 if verdict == "pass" else 1)
PYEOF
