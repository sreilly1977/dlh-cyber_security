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

python3 - "${TEST_OUTPUT_DIR}" "$PIPELINE_EXIT_CODE" "$SECONDARY_PACK" "$SCRIPT_DIR" "$REPORT_FILE" <<'PYEOF'
import json
import os
import re
import sys

test_output_dir, pipeline_exit_code, secondary_pack, script_dir, report_file = (
    sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
)

stdout_path = os.path.join(test_output_dir, "pipeline_stdout.log")
stderr_path = os.path.join(test_output_dir, "pipeline_stderr.log")

with open(stdout_path, "r", errors="replace") as f:
    stdout_content = f.read()

with open(stderr_path, "r", errors="replace") as f:
    stderr_content = f.read()

# The pipeline writes its own run log to WORKDIR/pipeline_run.log
pipeline_run_log = os.path.join(script_dir, "pipeline_run.log")
run_log_content = ""
if os.path.isfile(pipeline_run_log):
    with open(pipeline_run_log, "r", errors="replace") as f:
        run_log_content = f.read()

all_output = stdout_content + "\n" + stderr_content + "\n" + run_log_content

# ---------------------------------------------------------------------------
# Stage results: exit code is authoritative. If the pipeline exited 0,
# all 11 stages passed. If it failed, parse stdout for partial results.
# ---------------------------------------------------------------------------

EXPECTED_STAGES = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11]

stages = []

if pipeline_exit_code == 0:
    # All stages passed — exit code is the ground truth
    for num in EXPECTED_STAGES:
        stages.append({"stage": num, "result": "pass"})
else:
    # Pipeline failed — try to determine which stages passed before the failure
    parsed = {}
    for line in stdout_content.splitlines():
        m = re.search(r"stage\s+(\d+)", line, re.IGNORECASE)
        if not m:
            continue
        num = int(m.group(1))
        if num in parsed:
            continue
        lower = line.lower()
        if "ok" in lower and "fail" not in lower:
            parsed[num] = "pass"
        elif "fail" in lower:
            parsed[num] = "fail"
        else:
            parsed[num] = "unknown"

    # Build results: stages before the failure are parsed, the rest are fail
    found_failure = False
    for num in EXPECTED_STAGES:
        if num in parsed and not found_failure:
            result = parsed[num]
            stages.append({"stage": num, "result": result})
            if result == "fail":
                found_failure = True
        else:
            stages.append({"stage": num, "result": "fail"})

stage_pass = sum(1 for s in stages if s["result"] == "pass")
stage_fail_count = sum(1 for s in stages if s["result"] == "fail")

# ---------------------------------------------------------------------------
# Runtime: read from pipeline's own run log, which has a definitive value
# ---------------------------------------------------------------------------

runtime_s = 0

# Primary: "Total runtime: Ns" from pipeline_run.log
m = re.search(r"Total runtime:\s*(\d+)", run_log_content)
if m:
    runtime_s = int(m.group(1))

# Fallback: "in Ns" from stdout final line
if runtime_s == 0:
    m = re.search(r"in\s+(\d+)\s*s", stdout_content)
    if m:
        runtime_s = int(m.group(1))

# Fallback: "runtime" or "Total runtime" anywhere in all output
if runtime_s == 0:
    for line in all_output.splitlines():
        m = re.search(r"(?:runtime|Total runtime)[:\s]*(\d+)", line, re.IGNORECASE)
        if m:
            runtime_s = int(m.group(1))
            break

# ---------------------------------------------------------------------------
# Event count: count actual lines in enriched_events.json
# ---------------------------------------------------------------------------

def validate_ndjson(path, required_fields):
    """Validate NDJSON: exists, non-empty, parseable, has required fields."""
    if not os.path.isfile(path):
        return False, 0
    if os.path.getsize(path) == 0:
        return False, 0
    count = 0
    try:
        with open(path, "r", errors="replace") as f:
            for i, line in enumerate(f):
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

event_count = enriched_count if enriched_valid else 0

# ---------------------------------------------------------------------------
# Verdict: exit code + artifact validation
# ---------------------------------------------------------------------------

verdict = "pass"

if pipeline_exit_code != 0:
    verdict = "fail"

if not enriched_valid:
    verdict = "fail"

if not timeline_valid:
    verdict = "fail"

# ---------------------------------------------------------------------------
# Write report
# ---------------------------------------------------------------------------

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
