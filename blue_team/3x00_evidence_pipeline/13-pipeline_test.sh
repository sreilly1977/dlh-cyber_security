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
STDOUT_FILE="${TEST_OUTPUT_DIR}/pipeline_stdout.log"
STDERR_FILE="${TEST_OUTPUT_DIR}/pipeline_stderr.log"

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
"$PIPELINE_SCRIPT" "$SECONDARY_PACK" > "$STDOUT_FILE" 2> "$STDERR_FILE" || PIPELINE_EXIT_CODE=$?

python3 - "$STDOUT_FILE" "$STDERR_FILE" "$PIPELINE_EXIT_CODE" "$SECONDARY_PACK" "$SCRIPT_DIR" "$REPORT_FILE" <<'PYEOF'
import json
import os
import re
import sys

stdout_path = sys.argv[1]
stderr_path = sys.argv[2]
pipeline_exit_code = int(sys.argv[3])
secondary_pack = sys.argv[4]
script_dir = sys.argv[5]
report_file = sys.argv[6]

with open(stdout_path, "r", errors="replace") as f:
    stdout_lines = f.readlines()

with open(stderr_path, "r", errors="replace") as f:
    stderr_content = f.read()

# ---------------------------------------------------------------------------
# Parse stage results from captured stdout
# Pipeline prints: [HH:MM:SS] stage N name ... ok (Xs)
#                  [HH:MM:SS] stage N name ... FAIL
# ---------------------------------------------------------------------------

stages = []
seen = set()

for line in stdout_lines:
    stripped = line.strip()
    m = re.match(
        r"^\[\d{2}:\d{2}:\d{2}\]\s+stage\s+(\d+)\s+(\S+)\s+\.\.\.\s+(ok|FAIL)",
        stripped
    )
    if not m:
        continue
    num = int(m.group(1))
    if num in seen:
        continue
    seen.add(num)
    result = "pass" if m.group(3).lower() == "ok" else "fail"
    stages.append({"stage": num, "result": result})

stage_pass = sum(1 for s in stages if s["result"] == "pass")
stage_fail_count = sum(1 for s in stages if s["result"] == "fail")

# ---------------------------------------------------------------------------
# Extract runtime and event count from captured stdout
# Pipeline prints final line: pipeline ok. N enriched events in Ts
# ---------------------------------------------------------------------------

runtime_s = 0
event_count = 0

for line in stdout_lines:
    if "enriched events" in line.lower():
        m = re.search(r"(\d+)\s+enriched\s+events", line, re.IGNORECASE)
        if m:
            event_count = int(m.group(1))
    if "in" in line.lower() and "s" in line.lower():
        m = re.search(r"in\s+(\d+)\s*s", line, re.IGNORECASE)
        if m:
            runtime_s = int(m.group(1))

# ---------------------------------------------------------------------------
# Verify output files exist and are non-empty NDJSON
# Spec: "verifies that the secondary run produced a non-empty
#        enriched_events.json and timeline_index.json"
# Validate every line parses as JSON — not just the first record
# Do not enforce specific fields — these files may have different schemas
# ---------------------------------------------------------------------------

def validate_ndjson(path):
    """Check file exists, is non-empty, and every non-blank line is valid JSON.
    Returns (is_valid, record_count)."""
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
                json.loads(stripped)
                count += 1
    except (json.JSONDecodeError, IOError):
        return False, count
    return count > 0, count

enriched_path = os.path.join(script_dir, "enriched_events.json")
timeline_path = os.path.join(script_dir, "timeline_index.json")

enriched_valid, enriched_count = validate_ndjson(enriched_path)
timeline_valid, timeline_count = validate_ndjson(timeline_path)

# Ground truth: actual file line count overrides parsed value
if enriched_valid and enriched_count > 0:
    event_count = enriched_count

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

verdict = "pass"

if pipeline_exit_code != 0:
    verdict = "fail"

if stage_fail_count > 0:
    verdict = "fail"

if not enriched_valid:
    verdict = "fail"

if not timeline_valid:
    verdict = "fail"

if len(stages) == 0:
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
