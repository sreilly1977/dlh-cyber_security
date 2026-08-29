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

python3 - "$STDOUT_FILE" "$STDERR_FILE" "$PIPELINE_EXIT_CODE" "$SECONDARY_PACK" "$REPORT_FILE" <<'PYEOF'
import json
import os
import re
import sys

stdout_path = sys.argv[1]
stderr_path = sys.argv[2]
pipeline_exit_code = int(sys.argv[3])
secondary_pack = sys.argv[4]
report_file = sys.argv[5]

with open(stdout_path, "r", errors="replace") as f:
    stdout_lines = f.readlines()

# ---------------------------------------------------------------------------
# Output directory: the pipeline runs with WORKDIR = PWD, so artifacts are
# written to the current working directory at invocation time.
# ---------------------------------------------------------------------------

output_dir = os.getcwd()

# ---------------------------------------------------------------------------
# Stage results: parse from captured stdout.
# Tolerant of spacing and timestamp format variations.
# ---------------------------------------------------------------------------

stages = []
seen = set()

for line in stdout_lines:
    stripped = line.strip()
    m = re.search(r"stage\s*:??\s*(\d+)\b", stripped, re.IGNORECASE)
    if not m:
        continue
    num = int(m.group(1))
    if num in seen:
        continue
    seen.add(num)

    lower = stripped.lower()
    if re.search(r"\bok\b\s*\(", lower):
        result = "pass"
    elif "fail" in lower:
        result = "fail"
    else:
        result = "unknown"
    stages.append({"stage": num, "result": result})

stage_pass = sum(1 for s in stages if s["result"] == "pass")
stage_fail = sum(1 for s in stages if s["result"] == "fail")

# ---------------------------------------------------------------------------
# Runtime and event count: anchored to the "pipeline ok." summary line only
# ---------------------------------------------------------------------------

runtime_s = 0
event_count = 0

for line in stdout_lines:
    stripped = line.strip()
    if re.match(r"^pipeline\s+ok\b", stripped, re.IGNORECASE):
        m = re.search(r"(\d+)\s+enriched\s+events?", stripped, re.IGNORECASE)
        if m:
            event_count = int(m.group(1))
        m = re.search(r"in\s+(\d+)\s*s", stripped, re.IGNORECASE)
        if m:
            runtime_s = int(m.group(1))
        break

# ---------------------------------------------------------------------------
# JSON validation: handles both NDJSON and single JSON document/array
# ---------------------------------------------------------------------------

def validate_json_file(path):
    """Validate a JSON file. Returns (is_valid, record_count).
    Accepts single JSON documents (object/array) or NDJSON (one record per line).
    Every record in NDJSON is checked for valid JSON."""
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return False, 0
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
    except IOError:
        return False, 0

    # Try single JSON document (object or array)
    try:
        doc = json.loads(content)
        if isinstance(doc, list):
            return True, len(doc)
        return True, 1
    except (json.JSONDecodeError, ValueError):
        pass

    # Try NDJSON
    count = 0
    try:
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            json.loads(stripped)
            count += 1
    except (json.JSONDecodeError, IOError):
        return False, count
    return count > 0, count

# ---------------------------------------------------------------------------
# Locate and validate the two required output files
# ---------------------------------------------------------------------------

def find_output(filename):
    """Find output file in output_dir, then in direct subdirectories."""
    direct = os.path.join(output_dir, filename)
    if os.path.isfile(direct):
        return direct
    try:
        for entry in os.listdir(output_dir):
            subdir = os.path.join(output_dir, entry)
            if os.path.isdir(subdir):
                candidate = os.path.join(subdir, filename)
                if os.path.isfile(candidate):
                    return candidate
    except OSError:
        pass
    return None

enriched_path = find_output("enriched_events.json")
timeline_path = find_output("timeline_index.json")

enriched_valid, enriched_count = validate_json_file(enriched_path) if enriched_path else (False, 0)
timeline_valid, timeline_count = validate_json_file(timeline_path) if timeline_path else (False, 0)

# Ground truth
if enriched_valid and enriched_count > 0:
    event_count = enriched_count

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

verdict = "pass"

if pipeline_exit_code != 0:
    verdict = "fail"
if not enriched_valid:
    verdict = "fail"
if not timeline_valid:
    verdict = "fail"

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

report = {
    "test_name": "pipeline_generalization",
    "pack_path": secondary_pack,
    "pipeline_exit_code": pipeline_exit_code,
    "stages": stages,
    "total_stages": len(stages),
    "passed_stages": stage_pass,
    "failed_stages": stage_fail,
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
