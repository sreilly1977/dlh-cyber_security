#!/bin/bash
#
# Name: 7-schema_validate.sh
# Purpose: Validate every record in normalized_events.json against event_schema.json
#          using pure Python recursive validation. Streams NDJSON line-by-line
#          to avoid memory exhaustion. No external dependencies.
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

# --- Load and detect schema format --------------------------------------------
if not os.path.isfile(schema_file):
    sys.stderr.write(f"ERROR: schema file not found: {schema_file}\n")
    sys.exit(1)

with open(schema_file, "r") as f:
    raw_schema = json.load(f)

# Detect schema format: custom {fields:[...]} vs JSON Schema Draft 7
IS_JSON_SCHEMA = "$schema" in raw_schema or "properties" in raw_schema or "required" in raw_schema
IS_CUSTOM_SCHEMA = "fields" in raw_schema and isinstance(raw_schema.get("fields"), list)

if not IS_CUSTOM_SCHEMA and not IS_JSON_SCHEMA:
    sys.stderr.write(f"ERROR: unrecognized schema format in {schema_file}\n")
    sys.stderr.write("Supported formats:\n")
    sys.stderr.write("  - Custom format: {{'fields': [{{'name': ..., 'type': ..., 'required': ...}}, ...]}}\n")
    sys.stderr.write("  - JSON Schema Draft 7: {{'$schema': '...', 'type': 'object', 'properties': {...}, 'required': [...]}}\n")
    sys.exit(1)

# --- Parse custom schema format -----------------------------------------------
if IS_CUSTOM_SCHEMA:
    schema_fields = {field["name"]: field for field in raw_schema.get("fields", [])}
    required_fields = [f["name"] for f in raw_schema.get("fields", []) if f.get("required")]

    # Build constraint lookup tables
    ENUM_CONSTRAINTS = {}
    PATTERN_CONSTRAINTS = {}
    MIN_MAX_CONSTRAINTS = {}
    NESTED_PROPERTIES = {}
    ARRAY_ITEM_TYPES = {}

    for field_name, field_def in schema_fields.items():
        if field_def.get("enum"):
            ENUM_CONSTRAINTS[field_name] = set(field_def["enum"])
        if field_def.get("pattern"):
            PATTERN_CONSTRAINTS[field_name] = re.compile(field_def["pattern"])
        if field_def.get("min") is not None or field_def.get("max") is not None:
            MIN_MAX_CONSTRAINTS[field_name] = {
                "min": field_def.get("min"),
                "max": field_def.get("max"),
            }
        if field_def.get("type") == "object" and field_def.get("properties"):
            NESTED_PROPERTIES[field_name] = field_def["properties"]
        if field_def.get("type") == "array" and field_def.get("items"):
            ARRAY_ITEM_TYPES[field_name] = field_def["items"].get("type")

# --- Parse JSON Schema format -------------------------------------------------
elif IS_JSON_SCHEMA:
    # Convert JSON Schema to our internal representation
    schema_fields = {}
    required_fields = []
    properties = raw_schema.get("properties", {})
    required_list = raw_schema.get("required", [])
    additional_properties = raw_schema.get("additionalProperties", True)

    def parse_json_schema_property(prop_name, prop_def):
        """Parse a single JSON Schema property definition."""
        field = {"name": prop_name}

        # Extract type(s)
        if isinstance(prop_def.get("type"), list):
            types = prop_def["type"]
            field["type"] = types[0] if len(types) == 1 else types
        elif isinstance(prop_def.get("type"), str):
            field["type"] = prop_def["type"]

        # Handle null in union type
        if isinstance(prop_def.get("type"), list) and "null" in prop_def.get("type"):
            field["nullable"] = True

        # Required flag
        field["required"] = prop_name in required_list

        # Enum
        if prop_def.get("enum"):
            field["enum"] = prop_def["enum"]

        # Pattern
        if prop_def.get("pattern"):
            field["pattern"] = prop_def["pattern"]

        # Min/max
        if prop_def.get("minimum") is not None:
            field["min"] = prop_def["minimum"]
        if prop_def.get("maximum") is not None:
            field["max"] = prop_def["maximum"]

        # Nested object properties
        if prop_def.get("type") == "object" and prop_def.get("properties"):
            field["properties"] = {}
            nested_required = prop_def.get("required", [])
            for pname, pdef in prop_def["properties"].items():
                field["properties"][pname] = parse_json_schema_property(pname, pdef)
            field["required"] = all(pname in nested_required for pname in field["properties"])

        # Array items
        if prop_def.get("type") == "array" and prop_def.get("items"):
            if isinstance(prop_def["items"], dict):
                field["items"] = {"type": prop_def["items"].get("type")}

        return field

    for prop_name, prop_def in properties.items():
        schema_fields[prop_name] = parse_json_schema_property(prop_name, prop_def)
        if prop_name in required_list:
            required_fields.append(prop_name)

    # Rebuild constraint tables for JSON Schema mode
    ENUM_CONSTRAINTS = {}
    PATTERN_CONSTRAINTS = {}
    MIN_MAX_CONSTRAINTS = {}
    NESTED_PROPERTIES = {}
    ARRAY_ITEM_TYPES = {}

    for field_name, field_def in schema_fields.items():
        if field_def.get("enum"):
            ENUM_CONSTRAINTS[field_name] = set(field_def["enum"])
        if field_def.get("pattern"):
            PATTERN_CONSTRAINTS[field_name] = re.compile(field_def["pattern"])
        if field_def.get("min") is not None or field_def.get("max") is not None:
            MIN_MAX_CONSTRAINTS[field_name] = {
                "min": field_def.get("min"),
                "max": field_def.get("max"),
            }
        if field_def.get("type") == "object" and field_def.get("properties"):
            NESTED_PROPERTIES[field_name] = field_def["properties"]
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

def check_type_match(value, expected_type):
    """Check if value matches expected type, respecting bool/int distinction."""
    if value is None:
        return True

    if isinstance(expected_type, list):
        for t in expected_type:
            if check_type_match(value, t):
                return True
        return False

    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    elif expected_type == "float":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
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
    """Recursively validate a value against its field definition."""
    errors = []

    if field_def is None:
        return errors

    expected_type = field_def.get("type")
    is_nullable = field_def.get("nullable", False)
    is_required = field_def.get("required", False)

    # Null check
    if value is None:
        if is_required and not is_nullable:
            errors.append(f"{field_path}: required field cannot be null")
        return errors

    # Type check
    if expected_type and not check_type_match(value, expected_type):
        errors.append(f"{field_path}: expected {expected_type}, got {type(value).__name__}")
        return errors

    # Timestamp format validation
    if expected_type == "timestamp" and isinstance(value, str):
        pattern = PATTERN_CONSTRAINTS.get(field_path.split(".")[-1])
        if pattern:
            if not pattern.match(value):
                errors.append(f"{field_path}: invalid timestamp format")
        elif not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", value):
            errors.append(f"{field_path}: invalid timestamp format")

    # Enum validation
    base_name = field_path.split(".")[-1]
    if base_name in ENUM_CONSTRAINTS and value not in ENUM_CONSTRAINTS[base_name]:
        errors.append(f"{field_path}: invalid value '{value}'")

    # Pattern validation
    if base_name in PATTERN_CONSTRAINTS and expected_type != "timestamp":
        if isinstance(value, str) and not PATTERN_CONSTRAINTS[base_name].match(value):
            errors.append(f"{field_path}: value does not match required pattern")

    # Min/max validation
    if base_name in MIN_MAX_CONSTRAINTS:
        constraints = MIN_MAX_CONSTRAINTS[base_name]
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if constraints["min"] is not None and value < constraints["min"]:
                errors.append(f"{field_path}: value {value} below minimum {constraints['min']}")
            if constraints["max"] is not None and value > constraints["max"]:
                errors.append(f"{field_path}: value {value} above maximum {constraints['max']}")

    # Nested object property validation
    if expected_type == "object" and isinstance(value, dict):
        properties = NESTED_PROPERTIES.get(base_name)
        if properties:
            for prop_name, prop_def in properties.items():
                child_path = f"{field_path}.{prop_name}"
                if prop_def.get("required") and prop_name not in value:
                    errors.append(f"{child_path}: required nested property missing")
                if prop_name in value:
                    child_value = value[prop_name]
                    errors.extend(validate_value(child_path, child_value, prop_def))

    # Array item validation
    if expected_type == "array" and isinstance(value, list):
        item_type = ARRAY_ITEM_TYPES.get(base_name)
        if item_type:
            for idx, item in enumerate(value):
                errors.extend(validate_value(f"{field_path}[{idx}]", item, {"type": item_type}))

    return errors

def validate_record(record):
    """Validate a single record against the schema."""
    errors = []

    # Check required top-level fields
    for field_name in required_fields:
        if field_name not in record or record[field_name] is None:
            errors.append(f"missing required field: {field_name}")

    # Validate each field present in the record
    for field_name, value in record.items():
        if field_name not in schema_fields:
            continue
        errors.extend(validate_value(field_name, value, schema_fields[field_name]))

    return len(errors) == 0, errors

# --- Stream NDJSON records -----------------------------------------------------

if not os.path.isfile(normalized_file):
    sys.stderr.write(f"ERROR: normalized file not found: {normalized_file}\n")
    sys.exit(1)

total_records = 0
compliant_records = 0
non_compliant_records = 0
malformed_json_lines = []
schema_violations = []
non_compliant_examples = []
field_presence = {fn: 0 for fn in schema_fields}
type_violations = {}
other_violations = {}

# Stream line-by-line (memory efficient)
with open(normalized_file, "r", errors="replace") as f:
    for line_num, line in enumerate(f, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as e:
            # MALFORMED JSON - separate from schema violations
            malformed_json_lines.append({"line": line_num, "error": str(e)})
            if len(non_compliant_examples) < 20:
                non_compliant_examples.append({
                    "ref": f"line {line_num}",
                    "error_type": "json_parse",
                    "errors": ["JSON parse error"],
                    "sample": stripped[:200] + "..." if len(stripped) > 200 else stripped,
                })
            continue

        total_records += 1

        # Track field presence
        for field_name in schema_fields:
            if field_name in record and record[field_name] is not None:
                field_presence[field_name] += 1

        # Validate against schema
        is_valid, errors = validate_record(record)
        if is_valid:
            compliant_records += 1
        else:
            non_compliant_records += 1
            schema_violations.append({"line": line_num, "errors": errors})
            if len(non_compliant_examples) < 20:
                non_compliant_examples.append({
                    "ref": f"line {line_num}",
                    "error_type": "schema_violation",
                    "errors": errors,
                    "sample": {k: v for k, v in list(record.items())[:5]},
                })

            # Categorize violations
            for err in errors:
                field_path = err.split(":")[0] if ":" in err else "unknown"
                if "expected" in err or ("got" in err.lower() and "type" in err.lower()):
                    type_violations[field_path] = type_violations.get(field_path, 0) + 1
                else:
                    other_violations[field_path] = other_violations.get(field_path, 0) + 1

# --- Calculate per-field completeness ------------------------------------------
per_field_completeness = {}
for field_name in sorted(schema_fields):
    count = field_presence[field_name]
    pct = (count / total_records * 100) if total_records > 0 else 0
    per_field_completeness[field_name] = round(pct, 2)

# --- Build validation report --------------------------------------------------
report = {
    "normalized_file": normalized_file,
    "schema_file": schema_file,
    "schema_format": "json_schema" if IS_JSON_SCHEMA else "custom_fields",
    "total_records": total_records,
    "valid_records": compliant_records,
    "malformed_json_lines": len(malformed_json_lines),
    "schema_violations": len(schema_violations),
    "total_non_compliant": len(malformed_json_lines) + len(schema_violations),
    "compliance_percentage": round(compliant_records / total_records * 100, 2) if total_records > 0 else 0,
    "per_field_completeness": per_field_completeness,
    "non_compliant_examples": non_compliant_examples[:20],
    "type_violations_by_field": type_violations,
    "other_violations_by_field": other_violations,
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

print(f"schema violations     : {len(schema_violations)}")
print(f"malformed json lines  : {len(malformed_json_lines)}")
print("per-field completeness:")
for field_name in sorted(per_field_completeness):
    pct = per_field_completeness[field_name]
    print(f"  {field_name:<16s} {pct:>6.2f}%")
print(f"validation_report.json written")

sys.exit(0 if (len(malformed_json_lines) + len(schema_violations)) == 0 else 1)

PYTHON_EOF
