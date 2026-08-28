#!/bin/bash
#
# Name: 7-schema_validate.sh
# Purpose: Validate every record in normalized_events.json against event_schema.json
#          and produce a machine-readable compliance report.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
NORMALIZED_FILE="${WORKDIR}/normalized_events.json"
SCHEMA_FILE="${WORKDIR}/event_schema.json"
REPORT_FILE="${WORKDIR}/validation_report.json"

python3 - "${WORKDIR}" "${NORMALIZED_FILE}" "${SCHEMA_FILE}" "${REPORT_FILE}" <<'PYTHON_EOF'
import json
import os
import re
import sys

workdir = sys.argv[1]
normalized_file = sys.argv[2]
schema_file = sys.argv[3]
report_file = sys.argv[4]

output_dir = os.path.dirname(report_file) or "."
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

# --- Load schema --------------------------------------------------------------
if not os.path.isfile(schema_file):
    sys.stderr.write(f"ERROR: schema file not found: {schema_file}\n")
    sys.exit(1)

with open(schema_file, "r") as f:
    schema = json.load(f)

schema_fields = {field["name"]: field for field in schema.get("fields", [])}
required_fields = [f["name"] for f in schema.get("fields", []) if f.get("required")]

# Valid enum values
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_SOURCE_TYPES = {"windows_json", "linux_text", "firewall", "suricata", "pcap_flow"}
VALID_EVENT_CATEGORIES = {
    "authentication", "process", "file", "network", "network_alert",
    "network_flow", "audit", "powershell", "service"
}

# --- Validation function ------------------------------------------------------
def validate_record(record):
    """Validate a single record against the schema.
    Returns (is_valid, error_messages)."""
    errors = []

    # Check required fields present and non-null
    for field_name in required_fields:
        if field_name not in record or record[field_name] is None:
            errors.append(f"missing required field: {field_name}")

    # Check type compatibility for each field
    for field_name, value in record.items():
        if field_name not in schema_fields:
            continue

        field_def = schema_fields[field_name]
        expected_type = field_def.get("type")

        if value is None:
            continue

        if expected_type == "string":
            if not isinstance(value, str):
                errors.append(f"{field_name}: expected string, got {type(value).__name__}")
        elif expected_type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                errors.append(f"{field_name}: expected integer, got {type(value).__name__}")
        elif expected_type == "float":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                errors.append(f"{field_name}: expected float, got {type(value).__name__}")
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                errors.append(f"{field_name}: expected boolean, got {type(value).__name__}")
        elif expected_type == "timestamp":
            if not isinstance(value, str):
                errors.append(f"{field_name}: expected string, got {type(value).__name__}")
            elif not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value):
                errors.append(f"{field_name}: invalid timestamp format")
        elif expected_type == "object":
            if not isinstance(value, dict):
                errors.append(f"{field_name}: expected object, got {type(value).__name__}")
        elif expected_type == "array":
            if not isinstance(value, list):
                errors.append(f"{field_name}: expected array, got {type(value).__name__}")

    # Enum constraint checks
    severity = record.get("severity")
    if severity is not None and severity not in VALID_SEVERITIES:
        errors.append(f"invalid severity: {severity}")

    source_type = record.get("source_type")
    if source_type is not None and source_type not in VALID_SOURCE_TYPES:
        errors.append(f"invalid source_type: {source_type}")

    event_category = record.get("event_category")
    if event_category is not None and event_category not in VALID_EVENT_CATEGORIES:
        errors.append(f"invalid event_category: {event_category}")

    return len(errors) == 0, errors

# --- Read and validate records ------------------------------------------------
if not os.path.isfile(normalized_file):
    sys.stderr.write(f"ERROR: normalized file not found: {normalized_file}\n")
    sys.exit(1)

total_records = 0
compliant_records = 0
non_compliant_records = 0
non_compliant_examples = []
field_presence = {field_name: 0 for field_name in schema_fields.keys()}
type_violations = {}
malformed_lines = []

with open(normalized_file, "r", errors="replace") as f:
    for line_num, line in enumerate(f, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as e:
            non_compliant_records += 1
            malformed_lines.append({
                "line": line_num,
                "error": str(e),
                "sample": stripped[:200] + "..." if len(stripped) > 200 else stripped,
            })
            if len(non_compliant_examples) < 20:
                non_compliant_examples.append({
                    "line": line_num,
                    "reason": "JSON parse error",
                    "sample": stripped[:200] + "..." if len(stripped) > 200 else stripped,
                })
            continue

        total_records += 1

        # Track field presence
        for field_name in schema_fields.keys():
            if field_name in record and record[field_name] is not None:
                field_presence[field_name] += 1

        # Validate against schema
        is_valid, errors = validate_record(record)
        if is_valid:
            compliant_records += 1
        else:
            non_compliant_records += 1
            if len(non_compliant_examples) < 20:
                non_compliant_examples.append({
                    "line": line_num,
                    "reasons": errors,
                    "sample": {k: v for k, v in list(record.items())[:5]},
                })

            # Track type violations per field
            for err in errors:
                field = err.split(":")[0] if ":" in err else "unknown"
                type_violations[field] = type_violations.get(field, 0) + 1

# --- Calculate per-field completeness ------------------------------------------
per_field_completeness = {}
for field_name in sorted(schema_fields.keys()):
    count = field_presence[field_name]
    pct = (count / total_records * 100) if total_records > 0 else 0
    per_field_completeness[field_name] = round(pct, 2)

# --- Build validation report --------------------------------------------------
report = {
    "normalized_file": normalized_file,
    "schema_file": schema_file,
    "total_records": total_records,
    "valid_records": compliant_records,
    "non_compliant_records": non_compliant_records,
    "malformed_json_lines": len(malformed_lines),
    "compliance_percentage": round(compliant_records / total_records * 100, 2) if total_records > 0 else 0,
    "per_field_completeness": per_field_completeness,
    "non_compliant_examples": non_compliant_examples[:20],
    "type_violations_by_field": type_violations,
}

with open(report_file, "w") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

# --- Print summary ------------------------------------------------------------
print(f"records checked       : {total_records}")
if total_records > 0:
    compliance_pct = compliant_records / total_records * 100
    print(f"fully compliant       : {compliant_records} ({compliance_pct:.2f}%)")
else:
    print(f"fully compliant       : 0 (0.00%)")
    compliance_pct = 0

print(f"non-compliant         : {non_compliant_records}")
print("per-field completeness:")
for field_name in sorted(per_field_completeness.keys()):
    pct = per_field_completeness[field_name]
    print(f"  {field_name:<16s} {pct:>6.2f}%")
print(f"validation_report.json written")

# --- Exit code based on compliance threshold (>= 99%, not > 99%) -----------------
if compliance_pct >= 99:
    sys.exit(0)
else:
    sys.exit(1)

PYTHON_EOF
