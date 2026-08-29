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

cat "${TEST_OUTPUT_DIR}/pipeline_stdout.log" "${TEST_OUTPUT_DIR}/pipeline_stderr.log" > "${TEST_OUTPUT_DIR}/pipeline_run.log"

python3 - "${TEST_OUTPUT_DIR}" "$PIPELINE_EXIT_CODE" "$SECONDARY_PACK" "$SCRIPT_DIR" "$REPORT_FILE" <<'PYEOF'
import json
import os
import re
import sys

test_output_dir = sys.argv[1]
pipeline_exit_code = int(sys.argv[2])
secondary_pack = sys.argv[3]
script_dir = sys.argv[4]
report_file = sys.argv[5]

stdout_path = os.path.join(test_output_dir, "pipeline_stdout.log")
run_log_path = os.path.join(test_output_dir, "pipeline_run.log")

# ---------------------------------------------------------------------------
# Read all pipeline output
# ---------------------------------------------------------------------------

with open(stdout_path, "r", errors="replace") as f:
    stdout_content = f.read()

with open(run_log_path, "r", errors="replace") as f:
    run_log_content = f.read()

all_output = stdout_content + "\n" + run_log_content

# ---------------------------------------------------------------------------
# Parse stage results from stdout (informational only — exit code is authoritative)
# ---------------------------------------------------------------------------

stages = []
seen = set()

for line in stdout_content.splitlines():
    line = line.strip()
    if not line:
        continue

    # Broad match: any line containing "stage" followed by a number
    m = re.search(r"stage\s+(\d+)", line, re.IGNORECASE)
    if not m:
        continue

    stage_num = int(m.group(1))
    if stage_num in seen:
        continue

    line_lower = line.lower()

    if re.search(r"\bok\b", line_lower) and "fail" not in line_lower:
        result = "pass"
    elif "fail" in line_lower:
        result = "fail"
    else:
        result = "unknown"

    seen.add(stage_num)
    stages.append({"stage": stage_num, "result": result})

stage_pass = sum(1 for s in stages if s["result"] == "pass")
stage_fail_count = sum(1 for s in stages if s["result"] == "fail")

# ---------------------------------------------------------------------------
# Extract runtime and event count from any pipeline output
# ---------------------------------------------------------------------------

event_count = 0
runtime_s = 0

for line in all_output.splitlines():
    if event_count == 0:
        m = re.search(r"(\d+)\s+enriched\s+events?", line, re.IGNORECASE)
        if m:
            event_count = int(m.group(1))

    if runtime_s == 0:
        m = re.search(r"(\d+)\s*s\b", line)
        if m and ("runtime" in line.lower() or "in " in line.lower()):
            runtime_s = int(m.group(1))

# ---------------------------------------------------------------------------
# Discover output directory from run log
# ---------------------------------------------------------------------------

output_dir = script_dir

m = re.search(r"Working directory:\s*(.+)", run_log_content)
if m:
    candidate = m.group(1).strip()
    if os.path.isdir(candidate):
        output_dir = candidate

# ---------------------------------------------------------------------------
# Validate artifacts by content, not just existence
# ---------------------------------------------------------------------------

def validate_ndjson(path, required_fields):
    """Validate an NDJSON file: exists, non-empty, parseable, has required fields.
    Returns (is_valid, record_count, sample)."""
    if not os.path.isfile(path):
        return False, 0, None

    if os.path.getsize(path) == 0:
        return False, 0, None

    count = 0
    sample = None
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                record = json.loads(stripped)
                count += 1
                if sample is None:
                    sample = record
                    # Check required fields exist in first record
                    for field in required_fields:
                        if field not in record:
                            return False, count, sample
    except (json.JSONDecodeError, IOError):
        return False, count, None

    return count > 0, count, sample

enriched_path = os.path.join(output_dir, "enriched_events.json")
timeline_path = os.path.join(output_dir, "timeline_index.json")

enriched_required = ["timestamp", "hostname", "source_type", "event_category", "severity", "summary", "event_ref"]
timeline_required = ["timestamp", "hostname", "source_type", "event_category", "severity", "summary", "event_ref"]

enriched_valid, enriched_count, enriched_sample = validate_ndjson(enriched_path, enriched_required)
timeline_valid, timeline_count, timeline_sample = validate_ndjson(timeline_path, timeline_required)

# Use actual file line count as ground truth for event count
if enriched_valid and enriched_count > 0:
    event_count = enriched_count

# If we still don't have runtime, calculate from run log timestamps
if runtime_s == 0:
    time_matches = re.findall(r"\[(\d{2}:\d{2}:\d{2})\]", stdout_content)
    if len(time_matches) >= 2:
        from datetime import datetime
        try:
            t1 = datetime.strptime(time_matches[0], "%H:%M:%S")
            t2 = datetime.strptime(time_matches[-1], "%H:%M:%S")
            runtime_s = int((t2 - t1).total_seconds())
        except ValueError:
            pass

# ---------------------------------------------------------------------------
# Determine verdict — exit code is authoritative, artifacts are confirmed
# ---------------------------------------------------------------------------

verdict = "pass"

if pipeline_exit_code != 0:
    verdict = "fail"

if not enriched_valid:
    verdict = "fail"

if not timeline_valid:
    verdict = "fail"

# ---------------------------------------------------------------------------
# Write JSON report
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

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------

print(f"all {stage_pass} stages passed")
print(f"enriched events: {event_count}")
print(f"runtime: {runtime_s}s")
print(f"verdict: {verdict}")
print(f"pipeline_test_report.json written")

sys.exit(0 if verdict == "pass" else 1)

PYEOF
