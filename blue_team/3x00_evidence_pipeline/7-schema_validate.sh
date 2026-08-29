#!/bin/bash
#
# Name: 7-schema_validate.sh
# Purpose: Validate every record in normalized_events.json against event_schema.json
#          using the jsonschema library for full Draft 7 compliance.
#          Exits non-zero if schema violations are found or dependencies missing.
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -euo pipefail

# --- Dependency check --------------------------------------------------------

python3 -c "import jsonschema" 2>/dev/null || {
    echo "ERROR: jsonschema library not found." >&2
    echo "Install with: pip install --user jsonschema" >&2
    exit 2
}

WORKDIR="${WORKDIR:-$(pwd)}"
NORMALIZED_FILE="${WORKDIR}/normalized_events.json"
SCHEMA_FILE="${WORKDIR}/event_schema.json"
REPORT_FILE="${WORKDIR}/validation_report.json"

python3 - "${WORKDIR}" "${NORMALIZED_FILE}" "${SCHEMA_FILE}" "${REPORT_FILE}" <<'PYTHON_EOF'
# (rest of the original stage 7 script unchanged)
import json
import os
import site
import sys

# --- Locate jsonschema reliably ----------------------------------------------
user_site = site.getusersitepackages()
if user_site and os.path.isdir(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)

for candidate in [
    "/usr/lib/python3/dist-packages",
    "/usr/local/lib/python3/dist-packages",
    os.path.expanduser("~/.local/lib"),
]:
    if os.path.isdir(candidate) and candidate not in sys.path:
        sys.path.insert(0, candidate)

try:
    from jsonschema import Draft7Validator
except ImportError:
    sys.stderr.write("ERROR: jsonschema library not found.\n")
    sys.stderr.write("Install with: pip install --user jsonschema\n")
    sys.exit(2)

workdir = sys.argv[1]
normalized_file = sys.argv[2]
schema_file = sys.argv[3]
report_file = sys.argv[4]

output_dir = os.path.dirname(report_file) or "."
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

if not os.path.isfile(schema_file):
    sys.stderr.write(f"ERROR: schema file not found: {schema_file}\n")
    sys.exit(1)

with open(schema_file, "r") as f:
    raw_schema = json.load(f)

IS_CUSTOM = "fields" in raw_schema and isinstance(raw_schema.get("fields"), list)
IS_JSON_SCHEMA = "$schema" in raw_schema or "properties" in raw_schema

if not IS_CUSTOM and not IS_JSON_SCHEMA:
    sys.stderr.write(f"ERROR: unrecognized schema format in {schema_file}\n")
    sys.exit(1)

TYPE_MAP = {
    "string": "string",
    "integer": "integer",
    "float": "number",
    "boolean": "boolean",
    "timestamp": "string",
    "object": "object",
    "array": "array",
}

def convert_field(field_def):
    prop = {}
    field_type = field_def.get("type")
    is_required = field_def.get("required", False)

    if field_type == "timestamp":
        base = "string"
        prop["pattern"] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
    elif field_type == "object":
        base = "object"
        props = {}
        nested_req = []
        if field_def.get("properties"):
            for pname, pdef in field_def["properties"].items():
                props[pname] = convert_field(pdef)
                if isinstance(pdef, dict) and pdef.get("required"):
                    nested_req.append(pname)
        prop["properties"] = props
        if nested_req:
            prop["required"] = nested_req
        if "additionalProperties" in field_def:
            prop["additionalProperties"] = field_def["additionalProperties"]
        else:
            prop["additionalProperties"] = True
    elif field_type == "array":
        base = "array"
        if field_def.get("items"):
            prop["items"] = convert_field(field_def["items"])
        else:
            prop["items"] = True
    else:
        base = TYPE_MAP.get(field_type, "string")

    if base and not is_required:
        prop["type"] = [base, "null"]
    elif base:
        prop["type"] = base

    if field_def.get("enum"):
        if is_required:
            prop["enum"] = field_def["enum"]
        else:
            prop["enum"] = [*field_def["enum"], None]

    if field_def.get("pattern") and field_type != "timestamp":
        prop["pattern"] = field_def["pattern"]

    if field_def.get("min") is not None:
        prop["minimum"] = field_def["min"]
    if field_def.get("max") is not None:
        prop["maximum"] = field_def["max"]

    return prop

if IS_CUSTOM:
    properties = {}
    required = []
    for field in raw_schema.get("fields", []):
        properties[field["name"]] = convert_field(field)
        if field.get("required"):
            required.append(field["name"])

    json_schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }
    if required:
        json_schema["required"] = required
else:
    json_schema = raw_schema

validator = Draft7Validator(json_schema)

if not os.path.isfile(normalized_file):
    sys.stderr.write(f"ERROR: normalized file not found: {normalized_file}\n")
    sys.exit(1)

total_records = 0
compliant_records = 0
schema_violations_count = 0
malformed_json_count = 0
non_compliant_examples = []
field_presence = {}
type_violations = {}
other_violations = {}

for fname in json_schema.get("properties", {}):
    field_presence[fname] = 0

with open(normalized_file, "r", errors="replace") as f:
    for line_num, line in enumerate(f, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as e:
            malformed_json_count += 1
            if len(non_compliant_examples) < 20:
                non_compliant_examples.append({
                    "ref": f"line {line_num}",
                    "error_type": "json_parse",
                    "errors": [f"JSON parse error: {e}"],
                    "sample": stripped[:200] + "..." if len(stripped) > 200 else stripped,
                })
            continue

        total_records += 1

        for field_name in field_presence:
            if field_name in record and record[field_name] is not None:
                field_presence[field_name] += 1

        errors = sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))

        if not errors:
            compliant_records += 1
        else:
            schema_violations_count += 1
            if len(non_compliant_examples) < 20:
                non_compliant_examples.append({
                    "ref": f"line {line_num}",
                    "error_type": "schema_violation",
                    "errors": [
                        f"{e.message} (path: {'.'.join(str(p) for p in e.absolute_path) or 'root'}, validator: {e.validator})"
                        for e in errors
                    ],
                    "sample": {k: v for k, v in list(record.items())[:5]},
                })

            for err in errors:
                field_path = ".".join(str(p) for p in err.absolute_path) or "root"
                if err.validator == "type":
                    type_violations[field_path] = type_violations.get(field_path, 0) + 1
                else:
                    other_violations[field_path] = other_violations.get(field_path, 0) + 1

per_field_completeness = {}
for field_name in sorted(field_presence):
    count = field_presence[field_name]
    pct = (count / total_records * 100) if total_records > 0 else 0
    per_field_completeness[field_name] = round(pct, 2)

report = {
    "normalized_file": normalized_file,
    "schema_file": schema_file,
    "schema_format": "json_schema" if IS_JSON_SCHEMA else "custom_fields_converted",
    "total_records": total_records,
    "valid_records": compliant_records,
    "malformed_json_lines": malformed_json_count,
    "schema_violations": schema_violations_count,
    "total_non_compliant": malformed_json_count + schema_violations_count,
    "compliance_percentage": round(compliant_records / total_records * 100, 2) if total_records > 0 else 0,
    "per_field_completeness": per_field_completeness,
    "non_compliant_examples": non_compliant_examples[:20],
    "type_violations_by_field": type_violations,
    "other_violations_by_field": other_violations,
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

print(f"schema violations     : {schema_violations_count}")
print(f"malformed json lines  : {malformed_json_count}")
print("per-field completeness:")
for field_name in sorted(per_field_completeness):
    pct = per_field_completeness[field_name]
    print(f"  {field_name:<16s} {pct:>6.2f}%")
print(f"validation_report.json written")

sys.exit(0 if (malformed_json_count + schema_violations_count) == 0 else 1)

PYTHON_EOF
