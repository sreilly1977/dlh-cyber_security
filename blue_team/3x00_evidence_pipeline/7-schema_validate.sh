#!/bin/bash
#
# Name: 7-schema_validate.sh
# Purpose: Validate every record in normalized_events.json against event_schema.json
#          using standard JSON Schema validation. Converts the custom schema format
#          to JSON Schema Draft 7, then validates using the jsonschema library.
#          Streams NDJSON to avoid memory exhaustion on large files.
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
import subprocess
import sys

# Ensure jsonschema site-packages is in path
local_lib = os.path.expanduser("~/.local/lib/python3*/site-packages")
import glob
for path in glob.glob(local_lib):
    if path not in sys.path:
        sys.path.insert(0, path)

# Ensure jsonschema is available
try:
    from jsonschema import Draft7Validator
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "--user", "jsonschema"])
    # Re-add path after install
    for path in glob.glob(local_lib):
        if path not in sys.path:
            sys.path.insert(0, path)
    from jsonschema import Draft7Validator

workdir = sys.argv[1]
normalized_file = sys.argv[2]
schema_file = sys.argv[3]
report_file = sys.argv[4]

output_dir = os.path.dirname(report_file) or "."
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

# --- Load custom schema -------------------------------------------------------
if not os.path.isfile(schema_file):
    sys.stderr.write(f"ERROR: schema file not found: {schema_file}\n")
    sys.exit(1)

with open(schema_file, "r") as f:
    custom_schema = json.load(f)

# --- Convert custom {fields:[...]} schema to standard JSON Schema --------------

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
    """Recursively convert a custom field definition to a JSON Schema property."""
    prop = {}
    field_type = field_def.get("type")
    is_required = field_def.get("required", False)

    if field_type == "timestamp":
        base_type = "string"
        prop["pattern"] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
    elif field_type == "object":
        base_type = "object"
        if field_def.get("properties"):
            nested_props = {}
            nested_required = []
            for pname, pdef in field_def["properties"].items():
                nested_props[pname] = convert_field(pdef)
                if isinstance(pdef, dict) and pdef.get("required"):
                    nested_required.append(pname)
            prop["properties"] = nested_props
            if nested_required:
                prop["required"] = nested_required
        if "additionalProperties" in field_def:
            prop["additionalProperties"] = field_def["additionalProperties"]
    elif field_type == "array":
        base_type = "array"
        if field_def.get("items"):
            prop["items"] = convert_field(field_def["items"])
    else:
        base_type = TYPE_MAP.get(field_type)

    # Set type allowing null for non-required fields
    if base_type:
        if is_required:
            prop["type"] = base_type
        else:
            prop["type"] = [base_type, "null"]

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

def convert_to_json_schema(custom_schema):
    """Convert {fields: [...]} custom schema to standard JSON Schema Draft 7."""
    properties = {}
    required = []

    for field in custom_schema.get("fields", []):
        name = field["name"]
        properties[name] = convert_field(field)
        if field.get("required"):
            required.append(name)

    schema = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": properties,
        "additionalProperties": True,
    }
    if required:
        schema["required"] = required
    return schema

json_schema = convert_to_json_schema(custom_schema)
schema_fields = {field["name"]: field for field in custom_schema.get("fields", [])}
validator = Draft7Validator(json_schema)

# --- Detect input format (NDJSON vs JSON array vs single object) ---------------

if not os.path.isfile(normalized_file):
    sys.stderr.write(f"ERROR: normalized file not found: {normalized_file}\n")
    sys.exit(1)

with open(normalized_file, "r", errors="replace") as f:
    first_char = ""
    while True:
        ch = f.read(1)
        if not ch:
            break
        if not ch.isspace():
            first_char = ch
            break

# --- Counters -----------------------------------------------------------------
total_records = 0
compliant_records = 0
non_compliant_records = 0
non_compliant_examples = []
field_presence = {fn: 0 for fn in schema_fields}
type_violations = {}
all_violations = {}
malformed_lines = []

def process_record(record, line_ref):
    """Validate a single record and update counters."""
    global total_records, compliant_records, non_compliant_records

    total_records += 1

    for field_name in schema_fields:
        if field_name in record and record[field_name] is not None:
            field_presence[field_name] += 1

    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.absolute_path))

    if not errors:
        compliant_records += 1
        return

    non_compliant_records += 1

    if len(non_compliant_examples) < 20:
        non_compliant_examples.append({
            "ref": line_ref,
            "errors": [
                f"{e.message} (path: {'.'.join(str(p) for p in e.absolute_path) or 'root'}, validator: {e.validator})"
                for e in errors
            ],
            "sample": {k: v for k, v in list(record.items())[:5]},
        })

    for err in errors:
        field_path = ".".join(str(p) for p in err.absolute_path) or "root"
        all_violations[field_path] = all_violations.get(field_path, 0) + 1
        if err.validator == "type":
            type_violations[field_path] = type_violations.get(field_path, 0) + 1

# --- Validate records ---------------------------------------------------------

parsed_as_document = False
if first_char in ("[", "{"):
    # Try to parse as a single JSON document first (array or object)
    with open(normalized_file, "r", errors="replace") as f:
        try:
            data = json.load(f)
            parsed_as_document = True
        except json.JSONDecodeError:
            parsed_as_document = False  # Fall through to NDJSON streaming

    if parsed_as_document:
        records = data if isinstance(data, list) else [data]
        for idx, record in enumerate(records):
            if not isinstance(record, dict):
                malformed_lines.append({"index": idx, "error": "non-object element in JSON array"})
                non_compliant_records += 1
                continue
            process_record(record, f"index {idx}")

if not parsed_as_document:
    # NDJSON — stream line by line (memory-efficient)
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
                        "ref": f"line {line_num}",
                        "errors": ["JSON parse error"],
                        "sample": stripped[:200] + "..." if len(stripped) > 200 else stripped,
                    })
                continue
            process_record(record, f"line {line_num}")

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
    "total_records": total_records,
    "valid_records": compliant_records,
    "non_compliant_records": non_compliant_records,
    "malformed_json_lines": len(malformed_lines),
    "compliance_percentage": round(compliant_records / total_records * 100, 2) if total_records > 0 else 0,
    "per_field_completeness": per_field_completeness,
    "non_compliant_examples": non_compliant_examples[:20],
    "type_violations_by_field": type_violations,
    "all_violations_by_field": all_violations,
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

print(f"non-compliant         : {non_compliant_records}")
print(f"malformed lines       : {len(malformed_lines)}")
print("per-field completeness:")
for field_name in sorted(per_field_completeness):
    pct = per_field_completeness[field_name]
    print(f"  {field_name:<16s} {pct:>6.2f}%")
print(f"validation_report.json written")

sys.exit(0 if non_compliant_records == 0 else 1)

PYTHON_EOF
