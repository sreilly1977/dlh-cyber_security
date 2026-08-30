#!/bin/bash
#
# Name: 0-format_analysis.sh
# Purpose: Profile every source type in the enriched dataset and produce format_analysis.json
# Author: Steve - Cybersecurity Engineer
# Date: 30 August 2026
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

# Export for Python access
export ENRICHED_EVENTS BASELINE_PKG

python3 - << 'PYEOF'
import json
import os
import sys
from collections import Counter
from datetime import datetime

CARD_CAP = 10000

def is_valid_ipv4(value):
    """Check if a string is a valid IPv4 address with octets 0-255."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def infer_type(value):
    """Infer JSON field type from sample value."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        if "T" in value and len(value) >= 19:
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
                return "timestamp"
            except (ValueError, TypeError):
                pass
        if is_valid_ipv4(value):
            return "ipv4"
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"

def flatten_dict(d, parent_key="", sep="_"):
    """Flatten nested dicts and lists for field profiling."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Handle non-empty lists of dicts by indexing
            if v and all(isinstance(item, dict) for item in v):
                for i, item in enumerate(v):
                    sub_key = f"{new_key}{sep}{i}"
                    items.extend(flatten_dict(item, sub_key, sep=sep).items())
            else:
                # Scalar or mixed list - store as-is
                items.append((new_key, v))
        else:
            items.append((new_key, v))
    return dict(items)

def serialize_example(value):
    """Preserve native JSON types for example_values; stringify only if non-serializable."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)

def main():
    enriched_path = os.environ["ENRICHED_EVENTS"]
    output_pkg = os.environ["BASELINE_PKG"]

    sources = {}

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

            st = event.get("source_type", "unknown")

            if st not in sources:
                sources[st] = {
                    "record_count": 0,
                    "first_event": None,
                    "last_event": None,
                    "hosts": set(),
                    "categories": Counter(),
                    "field_stats": {},
                }

            ss = sources[st]
            ss["record_count"] += 1

            ts = event.get("timestamp")
            if ts:
                if ss["first_event"] is None or ts < ss["first_event"]:
                    ss["first_event"] = ts
                if ss["last_event"] is None or ts > ss["last_event"]:
                    ss["last_event"] = ts

            host = event.get("hostname")
            if host:
                ss["hosts"].add(host)

            cat = event.get("event_category", "unknown")
            ss["categories"][cat] += 1

            flat = flatten_dict(event)
            for field, value in flat.items():
                if field not in ss["field_stats"]:
                    ss["field_stats"][field] = {
                        "count": 0,
                        "type_counter": Counter(),
                        "values": [],
                        "value_set": set(),
                    }
                fs = ss["field_stats"][field]
                fs["count"] += 1
                fs["type_counter"][infer_type(value)] += 1
                if value is not None:
                    if len(fs["values"]) < 3:
                        fs["values"].append(serialize_example(value))
                    if len(fs["value_set"]) < CARD_CAP:
                        fs["value_set"].add(str(value))

    results = {}

    for st, ss in sorted(sources.items()):
        rc = ss["record_count"]

        field_profile = {}
        for field, fs in sorted(ss["field_stats"].items()):
            presence_pct = round((fs["count"] / rc) * 100, 2)
            inferred_type = (
                fs["type_counter"].most_common(1)[0][0]
                if fs["type_counter"] else "unknown"
            )
            cardinality = len(fs["value_set"])

            field_profile[field] = {
                "presence_pct": presence_pct,
                "inferred_type": inferred_type,
                "cardinality": cardinality,
                "example_values": fs["values"][:3],
            }

        top_cats = [
            {"category": c, "count": n}
            for c, n in ss["categories"].most_common(5)
        ]

        results[st] = {
            "record_count": rc,
            "first_event": ss["first_event"],
            "last_event": ss["last_event"],
            "unique_hosts": len(ss["hosts"]),
            "field_profile": field_profile,
            "top_event_categories": top_cats,
        }

        del ss["field_stats"]
        del ss["hosts"]
        del ss["categories"]

    output_file = os.path.join(output_pkg, "format_analysis.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    total_sources = len(results)
    for st, data in sorted(results.items()):
        num_fields = len(data["field_profile"])
        print(
            f"{st:<20} "
            f"{data['record_count']:<10} records   "
            f"{data['unique_hosts']:<5} hosts   "
            f"{num_fields:<5} fields"
        )

    print(f"{total_sources} source types profiled")
    print("format_analysis.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
