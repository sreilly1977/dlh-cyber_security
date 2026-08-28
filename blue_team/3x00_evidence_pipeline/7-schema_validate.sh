#!/bin/bash
#
# Name: 7-schema_validate.sh
# Purpose: Validate every record in normalized_events.json against event_schema.json
#          and produce a machine-readable compliance report. Uses streaming to avoid
#          memory exhaustion on large files.
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

# Build constraints from schema
ENUM_CONSTRAINTS = {}
for field_name, field_def in schema_fields.items():
    if field_def.get("enum"):
        ENUM_CONSTRAINTS[field_name] = set(field_def["enum"])

PATTERN_CONSTRAINTS = {}
for field_name, field_def in schema_fields.items():
    if field_def.get("pattern"):
        PATTERN_CONSTRAINTS[field_name] = re.compile(field_def["pattern"])

MIN_MAX_CONSTRAINTS = {}
for field_name, field_def in schema_fields.items():
    constraints = {}
    if field_def.get("min") is not None:
        constraints["min"] = field_def["min"]
    if field_def.get("max") is not None:
        constraints["max"] = field_def["max"]
    if constraints:
        MIN_MAX_CONSTRAINTS[field_name] = constraints

NESTED_RULES = {}
for field_name, field_def in schema_fields.items():
    if field_def.get("type") == "object" and field_def.get("properties"):
        NESTED_RULES[field_name] = field_def["properties"]

ARRAY_ITEM_TYPES = {}
for field_name, field_def in schema_fields.items():
    if field_def.get("type") == "array" and field_def.get("items"):
        ARRAY_ITEM_TYPES[field_name] = field_def["items"].get("type")

TYPE_MAP = {
    "string": str,
    "integer": int,
    "float": (int, float),
    "boolean": bool,
    "timestamp": str,
    "object": dict,
    "array": list,
}

def validate_record(record):
    """Validate a single record against the schema. Returns (is_valid, errors)."""
    errors = []

    for field_name in required_fields:
        if field_name not in record or record[field_name] is None:
            errors.append(f"missing required field: {field_name}")

    for field_name, value in record.items():
        if field_name not in schema_fields:
            continue

        field_def = schema_fields[field_name]
        expected_type = field_def.get("type")

        if value is None:
            continue

        if expected_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                errors.append(f"{field_name}: expected integer, got {type(value).__name__}")
        elif expected_type == "float":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                errors.append(f"{field_name}: expected float, got {type(value).__name__}")
        elif expected_type == "boolean":
            if not isinstance(value, bool):
                errors.append(f"{field_name}: expected boolean, got {type(value).__name__}")
        elif expected_type == "string":
            if not isinstance(value, str):
                errors.append(f"{field_name}: expected string, got {type(value).__name__}")
        elif expected_type == "object":
            if not isinstance(value, dict):
                errors.append(f"{field_name}: expected object, got {type(value).__name__}")
        elif expected_type == "array":
            if not isinstance(value, list):
                errors.append(f"{field_name}: expected array, got {type(value).__name__}")

        if expected_type == "timestamp" and isinstance(value, str):
            pattern = PATTERN_CONSTRAINTS.get(field_name)
            if pattern:
                if not pattern.match(value):
                    errors.append(f"{field_name}: invalid timestamp format: {value}")
            elif not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value):
                errors.append(f"{field_name}: invalid timestamp format: {value}")

        if field_name in ENUM_CONSTRAINTS and value not in ENUM_CONSTRAINTS[field_name]:
            errors.append(f"{field_name}: invalid value '{value}', expected one of {sorted(ENUM_CONSTRAINTS[field_name])}")

        if field_name in PATTERN_CONSTRAINTS and expected_type != "timestamp":
            if isinstance(value, str) and not PATTERN_CONSTRAINTS[field_name].match(value):
                errors.append(f"{field_name}: value does not match required pattern")

        if field_name in MIN_MAX_CONSTRAINTS:
            constraints = MIN_MAX_CONSTRAINTS[field_name]
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if "min" in constraints and value < constraints["min"]:
                    errors.append(f"{field_name}: value {value} below minimum {constraints['min']}")
                if "max" in constraints and value > constraints["max"]:
                    errors.append(f"{field_name}: value {value} above maximum {constraints['max']}")

        if field_name in NESTED_RULES and isinstance(value, dict):
            for prop_name, prop_def in NESTED_RULES[field_name].items():
                if prop_def.get("required") and prop_name not in value:
                    errors.append(f"{field_name}.{prop_name}: required nested property missing")

        if field_name in ARRAY_ITEM_TYPES and isinstance(value, list):
            expected_item_type = ARRAY_ITEM_TYPES[field_name]
            for idx, item in enumerate(value[:10]):  # Limit items checked to avoid slowdown
                if expected_item_type == "integer" and (isinstance(item, bool) or not isinstance(item, int)):
                    errors.append(f"{field_name}[{idx}]: expected integer, got {type(item).__name__}")
                elif expected_item_type == "string" and not isinstance(item, str):
                    errors.append(f"{field_name}[{idx}]: expected string, got {type(item).__name__}")

    return len(errors) == 0, errors

# --- Streaming validator for NDJSON files -------------------------------------

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
            malformed_lines.append({"line": line_num, "error": str(e)})
            if len(non_compliant_examples) < 20:
                non_compliant_examples.append({
                    "line": line_num,
                    "reason": "JSON parse error",
                    "sample": stripped[:200] + "..." if len(stripped) > 200 else stripped,
                })
            continue

        total_records += 1

        for field_name in schema_fields.keys():
            if field_name in record and record[field_name] is not None:
                field_presence[field_name] += 1

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
            for err in errors:
                field = err.split(":")[0] if ":" in err else "unknown"
                type_violations[field] = type_violations.get(field, 0) + 1

per_field_completeness = {}
for field_name in sorted(schema_fields.keys()):
    count = field_presence[field_name]
    pct = (count / total_records * 100) if total_records > 0 else 0
    per_field_completeness[field_name] = round(pct, 2)

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

print(f"records checked       : {total_records}")
if total_records > 0:
    compliance_pct = compliant_records / total_records * 100
    print(f"fully compliant       : {compliant_records} ({compliance_pct:.2f}%)")
else:
    print(f"fully compliant       : 0 (0.00%)")
    compliance_pct = 0

print(f"non-compliant         : {non_compliant_records}")
print(f"malformed lines       : {len(malformed_lines)}")
print("per-field completeness:")
for field_name in sorted(per_field_completeness.keys()):
    pct = per_field_completeness[field_name]
    print(f"  {field_name:<16s} {pct:>6.2f}%")
print(f"validation_report.json written")

sys.exit(0 if non_compliant_records == 0 else 1)

PYTHON_EOF
