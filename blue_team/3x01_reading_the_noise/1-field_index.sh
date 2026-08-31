#!/bin/bash
#
# Name: 1-field_index.sh
# Purpose: Build a reverse index of critical fields for fast lookup during triage
# Author: Steve - Cybersecurity Engineer
# Date: 31 August 2026
#

set -euo pipefail

# Resolve HANDOFF_DIR with default
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

ENRICHED_EVENTS="${HANDOFF_DIR}/data/enriched_events.json"

# Resolve BASELINE_PKG with default
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

if [[ ! -f "${ENRICHED_EVENTS}" ]]; then
    echo "ERROR: Enriched events file not found at ${ENRICHED_EVENTS}" >&2
    exit 1
fi

export ENRICHED_EVENTS BASELINE_PKG

python3 - << 'PYEOF'
import json
import os
import sys

CAP = 50

CRITICAL_FIELDS = [
    "hostname",
    "user",
    "process_name",
    "src_ip",
    "dst_ip",
    "event_category",
    "source_type",
]

def main():
    enriched_path = os.environ["ENRICHED_EVENTS"]
    output_pkg = os.environ["BASELINE_PKG"]

    index = {field: {} for field in CRITICAL_FIELDS}
    total_records = 0

    with open(enriched_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"WARNING: Skipping malformed JSON line: {e}", file=sys.stderr)
                continue

            total_records += 1
            ref = event.get("record_id", "")
            if not ref:
                ref = f"line_{total_records}"

            for field in CRITICAL_FIELDS:
                value = event.get(field)
                if value is None:
                    continue

                bucket = index[field]
                if value not in bucket:
                    bucket[value] = {
                        "count": 0,
                        "event_refs": [],
                        "capped": False,
                    }

                entry = bucket[value]
                entry["count"] += 1

                if not entry["capped"] and len(entry["event_refs"]) < CAP:
                    entry["event_refs"].append(ref)

                if entry["count"] > CAP:
                    entry["capped"] = True

    output_file = os.path.join(output_pkg, "field_index.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(index, f, indent=2)

    file_size_bytes = os.path.getsize(output_file)
    if file_size_bytes >= 1048576:
        size_str = f"{file_size_bytes / 1048576:.1f} MB"
    else:
        size_str = f"{file_size_bytes / 1024:.1f} KB"

    print(f"indexing {len(CRITICAL_FIELDS)} critical fields over {total_records} records")
    for field in CRITICAL_FIELDS:
        unique_count = len(index[field])
        print(f"  {field:<16} unique values : {unique_count:>8}")
    print(f"field_index.json written ({size_str})")

if __name__ == "__main__":
    main()
PYEOF

exit 0
