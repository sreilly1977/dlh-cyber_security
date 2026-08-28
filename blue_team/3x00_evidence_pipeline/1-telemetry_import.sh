#!/bin/bash
#
# Name: 1-telemetry_import.sh
# Purpose: Validate the pre-staged student telemetry files and confirm they
#          meet the data contract before they are merged into the pipeline.
#          Writes import_validation.json and exits 0 on pass, 1 on any failure.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
TELEMETRY_DIR="${EVIDENCE_PACK}/student_telemetry"
OUTPUT_FILE="${WORKDIR}/import_validation.json"

if [[ ! -d "$TELEMETRY_DIR" ]]; then
    echo "ERROR: telemetry directory not found: $TELEMETRY_DIR" >&2
    exit 1
fi

python3 - "${WORKDIR}" "${TELEMETRY_DIR}" "${OUTPUT_FILE}" <<'PYTHON_EOF'
import json
import os
import sys

workdir = sys.argv[1]
telemetry_dir = sys.argv[2]
output_file = sys.argv[3]

REQUIRED_FILES = [
    "windows_events.json",
    "linux_events.json",
    "attack_ground_truth.json",
]
REQUIRED_TELEMETRY_FIELDS = ["timestamp", "hostname", "source_type", "event_category"]

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

results = {}
all_pass = True

for fname in REQUIRED_FILES:
    fpath = os.path.join(telemetry_dir, fname)

    file_result = {
        "file": fname,
        "exists": False,
        "parseable": False,
        "record_count": 0,
        "has_records": False,
        "required_fields_present": False,
        "unique_source_types": [],
        "status": "fail",
        "errors": [],
    }

    # --- check existence ------------------------------------------------------
    if not os.path.isfile(fpath):
        file_result["errors"].append("file not found")
        results[fname] = file_result
        all_pass = False
        continue

    file_result["exists"] = True

    # --- check parseable JSON -------------------------------------------------
    try:
        records = parse_json_file(fpath)
        file_result["parseable"] = True
    except Exception as e:
        file_result["errors"].append(f"not parseable as JSON: {e}")
        results[fname] = file_result
        all_pass = False
        continue

    file_result["record_count"] = len(records)

    # --- check at least one record -------------------------------------------
    if len(records) < 1:
        file_result["errors"].append("contains no records")
        results[fname] = file_result
        all_pass = False
        continue

    file_result["has_records"] = True

    # --- attack_ground_truth.json: no field checks beyond parseable + records --
    if fname == "attack_ground_truth.json":
        file_result["required_fields_present"] = True
        file_result["status"] = "pass"
        results[fname] = file_result
        continue

    # --- windows_events.json and linux_events.json: check required fields -----
    missing_fields_per_record = []
    for i, rec in enumerate(records):
        missing = [f for f in REQUIRED_TELEMETRY_FIELDS if f not in rec or rec[f] is None]
        if missing:
            missing_fields_per_record.append(
                {"record_index": i, "missing_fields": missing}
            )

    if missing_fields_per_record:
        file_result["errors"].append(
            f"{len(missing_fields_per_record)} record(s) missing required fields"
        )
        file_result["required_fields_present"] = False
        results[fname] = file_result
        all_pass = False
        continue

    file_result["required_fields_present"] = True

    # --- collect unique source_type values -----------------------------------
    source_types = set()
    for rec in records:
        st = rec.get("source_type")
        if st is not None:
            source_types.add(str(st))

    file_result["unique_source_types"] = sorted(source_types)
    file_result["status"] = "pass"
    results[fname] = file_result

# --- write import_validation.json ----------------------------------------------
report = {
    "telemetry_dir": telemetry_dir,
    "files": results,
    "all_pass": all_pass,
}

with open(output_file, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

# --- print human-readable summary ----------------------------------------------
pass_count = sum(1 for r in results.values() if r["status"] == "pass")

for fname in REQUIRED_FILES:
    r = results[fname]
    if r["status"] == "pass":
        if fname == "attack_ground_truth.json":
            print(f"[OK] {fname:30s} {r['record_count']:>5} records")
        else:
            sources = ", ".join(r["unique_source_types"]) if r["unique_source_types"] else "none"
            print(f"[OK] {fname:30s} {r['record_count']:>5} records    sources: {sources}")
    else:
        errs = "; ".join(r["errors"])
        print(f"[FAIL] {fname:30s} {errs}")

print(f"{pass_count}/{len(REQUIRED_FILES)} files validated.", end="")
if all_pass:
    print(" Import OK.")
else:
    print(" Import FAILED.")

if all_pass:
    sys.exit(0)
else:
    sys.exit(1)

PYTHON_EOF
