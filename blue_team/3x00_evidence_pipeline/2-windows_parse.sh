#!/bin/bash
#
# Name: 2-windows_parse.sh
# Purpose: Merge Windows event log JSON files (security, sysmon, powershell)
#          and append student telemetry into a single windows_events.json file.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"

WINDOWS_DIR="${EVIDENCE_PACK}/windows"
STUDENT_DIR="${EVIDENCE_PACK}/student_telemetry"

OUTPUT_FILE="${WORKDIR}/windows_events.json"

if [[ ! -d "$WINDOWS_DIR" ]]; then
    echo "ERROR: Windows directory not found: $WINDOWS_DIR" >&2
    exit 1
fi

if [[ ! -d "$STUDENT_DIR" ]]; then
    echo "ERROR: Student telemetry directory not found: $STUDENT_DIR" >&2
    exit 1
fi

python3 - "${WORKDIR}" "${WINDOWS_DIR}" "${STUDENT_DIR}" "${OUTPUT_FILE}" <<'PYTHON_EOF'
import json
import os
import sys

workdir = sys.argv[1]
windows_dir = sys.argv[2]
student_dir = sys.argv[3]
output_file = sys.argv[4]

def parse_json_file(filepath):
    """Parse a JSON file that may be NDJSON or a single JSON array."""
    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    # Try single JSON document (array or object)
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    # Fall back to NDJSON
    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue
    return records

REQUIRED_FIELDS = [
    "timestamp_raw", "hostname", "event_id", "channel",
    "provider", "raw_message", "event_data", "source_origin"
]

DEFAULTS = {
    "event_id": 0,
    "channel": "",
    "provider": "",
    "raw_message": "",
    "event_data": {},
}

def normalize_record(record, forced_source_origin):
    """Normalize a single record: force source_origin, fill missing fields
    with sensible defaults, and map timestamp -> timestamp_raw if needed."""
    # Force source_origin to the correct value
    record["source_origin"] = forced_source_origin

    # Map timestamp -> timestamp_raw for student telemetry compatibility
    if "timestamp_raw" not in record and "timestamp" in record:
        record["timestamp_raw"] = record["timestamp"]

    # Fill in any missing required fields with appropriate defaults
    for field in REQUIRED_FIELDS:
        if field not in record:
            record[field] = DEFAULTS.get(field, None)

    return record

results = {}
total_records = 0
combined = []

# --- Process each Windows source file (single read + modify + store) -----------
for fname in ["security.json", "sysmon.json", "powershell.json"]:
    fpath = os.path.join(windows_dir, fname)

    if not os.path.isfile(fpath):
        print(f"WARNING: {fname} not found, skipping")
        results[fname] = {"status": "missing", "records": 0}
        continue

    records = parse_json_file(fpath)
    results[fname] = {"status": "read", "records": len(records)}

    for rec in records:
        normalize_record(rec, "evidence_pack")
        combined.append(rec)

    total_records += len(records)

# --- Process student telemetry (single read + modify + append) -----------------
student_file = os.path.join(student_dir, "windows_events.json")
student_records = 0

if os.path.isfile(student_file):
    records = parse_json_file(student_file)
    student_records = len(records)

    for rec in records:
        normalize_record(rec, "student_telemetry")
        combined.append(rec)

    results["student_telemetry"] = {"status": "appended", "records": student_records}
else:
    results["student_telemetry"] = {"status": "missing", "records": 0}

# --- Write output (from in-memory combined list) -------------------------------
with open(output_file, "w") as f:
    for rec in combined:
        json.dump(rec, f, separators=(",", ":"))
        f.write("\n")

# --- Print summary ------------------------------------------------------------
print(f"{'reading security.json':23s} ... {results.get('security.json', {}).get('records', 0):>6d} records")
print(f"{'reading sysmon.json':23s} ... {results.get('sysmon.json', {}).get('records', 0):>6d} records")
print(f"{'reading powershell.json':23s} ... {results.get('powershell.json', {}).get('records', 0):>6d} records")
print(f"{'appending student telemetry':23s} ... {student_records:>6d} records")
print(f"windows_events.json: {total_records} records")

PYTHON_EOF
