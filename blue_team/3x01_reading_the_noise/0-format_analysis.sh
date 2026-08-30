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

CARD_CAP = 10000

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
                from datetime import datetime
                datetime.fromisoformat(value.replace("Z", "+00:00"))
                return "timestamp"
            except (ValueError, TypeError):
                pass
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts if p):
            return "ipv4"
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"

def flatten_dict(d, parent_key="", sep="_"):
    """Flatten nested dict for field profiling."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)

def main():
    enriched_path = os.environ["ENRICHED_EVENTS"]
    output_pkg = os.environ["BASELINE_PKG"]

    # Stream through NDJSON one line at a time - never hold full dataset in memory
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
                        fs["values"].append(value)
                    if len(fs["value_set"]) < CARD_CAP:
                        fs["value_set"].add(str(value))

    # Build results from accumulated stats
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
                "example_values": [str(v) for v in fs["values"][:3]],
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

        # Free per-source working sets
        del ss["field_stats"]
        del ss["hosts"]
        del ss["categories"]

    # Write JSON output
    output_file = os.path.join(output_pkg, "format_analysis.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    # Print human-readable summary to stdout
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
