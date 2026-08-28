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

output_dir = os.path.dirname(output_file) or "."
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

REQUIRED_FIELDS = [
    "timestamp_raw", "hostname", "event_id", "channel",
    "provider", "raw_message", "event_data", "source_origin"
]

def parse_json_file(filepath):
    """Parse a JSON file that may be NDJSON or a single JSON array."""
    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [obj for obj in data if isinstance(obj, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    records = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            sys.stderr.write(f"WARNING: malformed line skipped in {filepath}\n")
    return records

def prepare_record(record, default_origin):
    """Preserve original structure; set source_origin only if absent,
    map timestamp -> timestamp_raw for compatibility."""
    if "source_origin" not in record or record["source_origin"] is None:
        record["source_origin"] = default_origin
    if "timestamp_raw" not in record and "timestamp" in record:
        record["timestamp_raw"] = record["timestamp"]
    return record

combined = []
counts = {}

# --- Process each Windows source file -----------------------------------------
for fname in ["security.json", "sysmon.json", "powershell.json"]:
    fpath = os.path.join(windows_dir, fname)

    if not os.path.isfile(fpath):
        counts[fname] = 0
        continue

    records = parse_json_file(fpath)
    for rec in records:
        prepare_record(rec, "evidence_pack")
        combined.append(rec)
    counts[fname] = len(records)

# --- Process student telemetry ------------------------------------------------
student_file = os.path.join(student_dir, "windows_events.json")
student_records = 0

if os.path.isfile(student_file):
    records = parse_json_file(student_file)
    for rec in records:
        prepare_record(rec, "student_telemetry")
        combined.append(rec)
    student_records = len(records)

counts["student_telemetry"] = student_records

# --- Write merged output -------------------------------------------------------
with open(output_file, "w") as f:
    for rec in combined:
        json.dump(rec, f, separators=(",", ":"))
        f.write("\n")

total_records = len(combined)

# --- Print summary (exact format per spec) ------------------------------------
print(f"reading security.json      ... {counts.get('security.json', 0):>6d} records")
print(f"reading sysmon.json        ... {counts.get('sysmon.json', 0):>6d} records")
print(f"reading powershell.json    ... {counts.get('powershell.json', 0):>6d} records")
print(f"appending student telemetry ... {student_records:>6d} records")
print(f"windows_events.json: {total_records} records")

PYTHON_EOF
