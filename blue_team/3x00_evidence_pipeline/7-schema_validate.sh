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

def check_type(value, expected_type):
    """Check if value matches expected type, handling bool/int distinction."""
    if expected_type == "integer":
        return not isinstance(value, bool) and isinstance(value, int)
    elif expected_type == "float":
        return not isinstance(value, bool) and isinstance(value, (int, float))
    elif expected_type == "boolean":
        return isinstance(value, bool)
    elif expected_type == "string":
        return isinstance(value, str)
    elif expected_type == "timestamp":
        return isinstance(value, str)
    elif expected_type == "object":
        return isinstance(value, dict)
    elif expected_type == "array":
        return isinstance(value, list)
    return True

def validate_value(field_path, value, field_def):
    """Recursively validate a value against its schema field definition.
    Returns a list of error strings."""
    errors = []
    expected_type = field_def.get("type")

    if value is None:
        return errors

    # Type check
    if expected_type and not check_type(value, expected_type):
        errors.append(f"{field_path}: expected {expected_type}, got {type(value).__name__}")
        return errors  # No point checking further if the type is wrong

    # Timestamp format
    if expected_type == "timestamp" and isinstance(value, str):
        pattern = PATTERN_CONSTRAINTS.get(field_path.split(".")[-1])
        if pattern:
            if not pattern.match(value):
                errors.append(f"{field_path}: invalid timestamp format: {value}")
        elif not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value):
            errors.append(f"{field_path}: invalid timestamp format: {value}")

    # Enum check
    base_name = field_path.split(".")[-1]
    if base_name in ENUM_CONSTRAINTS and value not in ENUM_CONSTRAINTS[base_name]:
        errors.append(f"{field_path}: invalid value '{value}', expected one of {sorted(ENUM_CONSTRAINTS[base_name])}")

    # Pattern check (non-timestamp strings)
    if base_name in PATTERN_CONSTRAINTS and expected_type != "timestamp":
        if isinstance(value, str) and not PATTERN_CONSTRAINTS[base_name].match(value):
            errors.append(f"{field_path}: value does not match required pattern")

    # Min/max check
    if base_name in MIN_MAX_CONSTRAINTS:
        constraints = MIN_MAX_CONSTRAINTS[base_name]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "min" in constraints and value < constraints["min"]:
                errors.append(f"{field_path}: value {value} below minimum {constraints['min']}")
            if "max" in constraints and value > constraints["max"]:
                errors.append(f"{field_path}: value {value} above maximum {constraints['max']}")

    # Recursive object validation
    if expected_type == "object" and isinstance(value, dict):
        properties = field_def.get("properties")
        if properties:
            for prop_name, prop_def in properties.items():
                child_path = f"{field_path}.{prop_name}"
                if prop_def.get("required") and prop_name not in value:
                    errors.append(f"{child_path}: required nested property missing")
                if prop_name in value and value[prop_name] is not None:
                    errors.extend(validate_value(child_path, value[prop_name], prop_def))

        # Check additional properties if schema forbids them
        if field_def.get("additionalProperties") is False and properties:
            for key in value:
                if key not in properties:
                    errors.append(f"{field_path}.{key}: additional property not allowed")

    # Recursive array validation — all items, no truncation
    if expected_type == "array" and isinstance(value, list):
        items_def = field_def.get("items")
        if items_def:
            for idx, item in enumerate(value):
                errors.extend(validate_value(f"{field_path}[{idx}]", item, items_def))

    return errors

def validate_record(record):
    """Validate a single record against the schema. Returns (is_valid, errors)."""
    errors = []

    for field_name in required_fields:
        if field_name not in record or record[field_name] is None:
            errors.append(f"missing required field: {field_name}")

    for field_name, value in record.items():
        if field_name not in schema_fields:
            continue
        errors.extend(validate_value(field_name, value, schema_fields[field_name]))

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
