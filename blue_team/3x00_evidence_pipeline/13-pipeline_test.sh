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
STDOUT_CAPTURE="${TEST_OUTPUT_DIR}/pipeline_stdout.log"
STDERR_CAPTURE="${TEST_OUTPUT_DIR}/pipeline_stderr.log"

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
"$PIPELINE_SCRIPT" "$SECONDARY_PACK" > "$STDOUT_CAPTURE" 2> "$STDERR_CAPTURE" || PIPELINE_EXIT_CODE=$?

python3 - "$STDOUT_CAPTURE" "$STDERR_CAPTURE" "$PIPELINE_EXIT_CODE" "$SECONDARY_PACK" "$SCRIPT_DIR" "$REPORT_FILE" <<'PYEOF'
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
    stdout_content = f.read()
with open(stderr_path, "r", errors="replace") as f:
    stderr_content = f.read()

# ---------------------------------------------------------------------------
# Expected artifacts per stage (mirrors pipeline's own STAGE_DEFINITIONS)
# ---------------------------------------------------------------------------

EXPECTED_ARTIFACTS = {
    0:  ["source_inventory.json"],
    1:  ["import_validation.json"],
    2:  ["windows_events.json"],
    3:  ["linux_events.json"],
    5:  ["normalized_events.json"],
    6:  ["network_events.json"],
    7:  ["validation_report.json"],
    8:  ["cleaned_events.json", "cleaning_log.json"],
    9:  ["enriched_events.json"],
    10: ["timeline_index.json"],
    11: ["source_stats.json"],
}

STAGE_ORDER = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11]

# ---------------------------------------------------------------------------
# Parse stage status from captured stdout
# The pipeline prints: [HH:MM:SS] stage N name ... ok (Xs)
# ---------------------------------------------------------------------------

stdout_stage_status = {}  # stage_num -> "pass" or "fail"

for line in stdout_content.splitlines():
    stripped = line.strip()
    m = re.match(
        r"^\[\d{2}:\d{2}:\d{2}\]\s+stage\s+(\d+)\s+\S+\s+\.\.\.\s+(ok|FAIL)",
        stripped
    )
    if m:
        num = int(m.group(1))
        raw = m.group(2).lower()
        stdout_stage_status[num] = "pass" if raw == "ok" else "fail"

# ---------------------------------------------------------------------------
# Verify each stage's artifacts independently
# ---------------------------------------------------------------------------

def check_artifacts(artifacts):
    """Return list of missing or empty artifacts."""
    problems = []
    for name in artifacts:
        path = os.path.join(script_dir, name)
        if not os.path.isfile(path):
            problems.append(f"{name} (missing)")
        elif os.path.getsize(path) == 0:
            problems.append(f"{name} (empty)")
    return problems

def validate_ndjson(path, required_fields):
    """Validate NDJSON: exists, non-empty, every line parseable, first record has required fields."""
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
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

stages = []

for num in STAGE_ORDER:
    artifacts = EXPECTED_ARTIFACTS[num]
    artifact_problems = check_artifacts(artifacts)

    # Determine result from multiple signals:
    # 1. stdout status (if available)
    # 2. artifact verification
    # 3. pipeline exit code

    stdout_says = stdout_stage_status.get(num)

    if artifact_problems:
        # Artifacts missing or empty — stage failed regardless of exit code
        result = "fail"
    elif stdout_says == "fail":
        result = "fail"
    elif stdout_says == "pass":
        result = "pass"
    elif pipeline_exit_code == 0:
        # No stdout record but pipeline succeeded and artifacts exist
        result = "pass"
    else:
        # Pipeline failed, no stdout record, artifacts may exist from prior run
        result = "fail"

    stages.append({
        "stage": num,
        "result": result,
        "artifacts": artifacts,
        "artifact_problems": artifact_problems if artifact_problems else None,
    })

stage_pass = sum(1 for s in stages if s["result"] == "pass")
stage_fail_count = sum(1 for s in stages if s["result"] == "fail")

# ---------------------------------------------------------------------------
# Runtime and event count from captured stdout
# The pipeline prints: "pipeline ok. N enriched events in Ts"
# ---------------------------------------------------------------------------

runtime_s = 0
event_count = 0

final_line = ""
for line in stdout_content.splitlines():
    if "pipeline ok" in line.lower():
        final_line = line
        break

if final_line:
    m = re.search(r"(\d+)\s+enriched\s+events", final_line, re.IGNORECASE)
    if m:
        event_count = int(m.group(1))
    m = re.search(r"in\s+(\d+)s", final_line, re.IGNORECASE)
    if m:
        runtime_s = int(m.group(1))

# Ground truth: count actual lines in enriched_events.json
enriched_path = os.path.join(script_dir, "enriched_events.json")
timeline_path = os.path.join(script_dir, "timeline_index.json")

required_fields = [
    "timestamp", "hostname", "source_type",
    "event_category", "severity", "summary", "event_ref"
]

enriched_valid, enriched_record_count = validate_ndjson(enriched_path, required_fields)
timeline_valid, timeline_record_count = validate_ndjson(timeline_path, required_fields)

if enriched_valid and enriched_record_count > 0:
    event_count = enriched_record_count

# ---------------------------------------------------------------------------
# Verdict: all stages must pass AND artifacts must be valid
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

# ---------------------------------------------------------------------------
# Write report
# ---------------------------------------------------------------------------

report = {
    "test_name": "pipeline_generalization",
    "pack_path": secondary_pack,
    "pipeline_exit_code": pipeline_exit_code,
    "stages": [
        {
            "stage": s["stage"],
            "result": s["result"],
            "artifacts": s["artifacts"],
            "artifact_problems": s["artifact_problems"],
        }
        for s in stages
    ],
    "total_stages": len(stages),
    "passed_stages": stage_pass,
    "failed_stages": stage_fail_count,
    "enriched_events": event_count,
    "enriched_file": enriched_path,
    "enriched_file_valid": enriched_valid,
    "enriched_record_count": enriched_record_count if enriched_valid else 0,
    "timeline_file": timeline_path,
    "timeline_file_valid": timeline_valid,
    "timeline_record_count": timeline_record_count if timeline_valid else 0,
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
