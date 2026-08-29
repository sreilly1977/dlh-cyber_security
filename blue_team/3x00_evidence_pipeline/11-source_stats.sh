#!/bin/bash
#
# Name: 11-source_stats.sh
# Purpose: Produce per-source statistics from enriched events, including
#          record counts, time ranges, unique hosts, top categories,
#          ingest rates, and coverage gaps. Outputs source_stats.json
#          and a console summary table.
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
INPUT_FILE="${WORKDIR}/enriched_events.json"
OUTPUT_FILE="${WORKDIR}/source_stats.json"

python3 - "${INPUT_FILE}" "${OUTPUT_FILE}" <<'PYTHON_EOF'
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta

input_file = sys.argv[1]
output_file = sys.argv[2]

if not os.path.isfile(input_file):
    sys.stderr.write(f"ERROR: input file not found: {input_file}\n")
    sys.exit(1)

def parse_ts(ts_str):
    """Parse ISO 8601 timestamp to datetime UTC."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    ts_str = ts_str.strip()
    try:
        base = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(base)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    return None

def fmt_ts(dt):
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

# --- Collect per-source data -------------------------------------------------

source_records = defaultdict(list)  # source_type -> list of (dt, hostname, event_category)
total_count = 0

with open(input_file, "r", errors="replace") as f:
    for line in f:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            continue

        total_count += 1
        source_type = event.get("source_type") or "unknown"
        hostname = event.get("hostname") or ""
        category = event.get("event_category") or "unknown"
        dt = parse_ts(event.get("timestamp", ""))

        source_records[source_type].append((dt, hostname, category))

# --- Compute statistics ------------------------------------------------------

stats = {}
all_dts = []

for source_type, records in source_records.items():
    count = len(records)
    hosts = set()
    categories = Counter()
    dts = []

    for dt, hostname, category in records:
        if hostname:
            hosts.add(hostname)
        categories[category] += 1
        if dt:
            dts.append(dt)

    dts.sort()
    all_dts.extend(dts)

    if dts:
        first_dt = dts[0]
        last_dt = dts[-1]
        span_seconds = (last_dt - first_dt).total_seconds()
        span_hours = span_seconds / 3600.0 if span_seconds > 0 else 1.0
        events_per_hour = round(count / span_hours) if span_hours > 0 else count

        # Coverage gap: largest gap between consecutive events
        max_gap_seconds = 0
        for i in range(1, len(dts)):
            gap = (dts[i] - dts[i - 1]).total_seconds()
            if gap > max_gap_seconds:
                max_gap_seconds = gap
        coverage_gap_min = round(max_gap_seconds / 60.0)
    else:
        first_dt = None
        last_dt = None
        events_per_hour = 0
        coverage_gap_min = 0

    top_cats = categories.most_common(5)

    stats[source_type] = {
        "record_count": count,
        "first_event": fmt_ts(first_dt),
        "last_event": fmt_ts(last_dt),
        "unique_hosts": len(hosts),
        "top_event_categories": [
            {"category": cat, "count": cnt} for cat, cnt in top_cats
        ],
        "events_per_hour": events_per_hour,
        "coverage_gap_minutes": coverage_gap_min,
    }

# --- Overall section ---------------------------------------------------------

all_dts.sort()
all_hosts = set()
all_categories = Counter()

for source_type, records in source_records.items():
    for dt, hostname, category in records:
        if hostname:
            all_hosts.add(hostname)
        all_categories[category] += 1

if all_dts:
    overall_span_seconds = (all_dts[-1] - all_dts[0]).total_seconds()
    overall_span_hours = overall_span_seconds / 3600.0 if overall_span_seconds > 0 else 1.0
    overall_eph = round(total_count / overall_span_hours) if overall_span_hours > 0 else total_count

    overall_max_gap = 0
    for i in range(1, len(all_dts)):
        gap = (all_dts[i] - all_dts[i - 1]).total_seconds()
        if gap > overall_max_gap:
            overall_max_gap = gap
    overall_gap_min = round(overall_max_gap / 60.0)
else:
    overall_eph = 0
    overall_gap_min = 0

overall = {
    "record_count": total_count,
    "first_event": fmt_ts(all_dts[0]) if all_dts else None,
    "last_event": fmt_ts(all_dts[-1]) if all_dts else None,
    "unique_hosts": len(all_hosts),
    "top_event_categories": [
        {"category": cat, "count": cnt} for cat, cnt in all_categories.most_common(5)
    ],
    "events_per_hour": overall_eph,
    "coverage_gap_minutes": overall_gap_min,
}

# --- Write JSON output -------------------------------------------------------

output = {
    "sources": stats,
    "overall": overall,
}

with open(output_file, "w") as f:
    json.dump(output, f, indent=2)
    f.write("\n")

# --- Print summary table -----------------------------------------------------

# Define display order: known sources first, then any others
display_order = ["windows_json", "linux_text", "firewall", "suricata", "pcap_flow"]
for st in sorted(stats.keys()):
    if st not in display_order:
        display_order.append(st)

print(f"{'source':<18} {'records':>8} {'hosts':>8} {'ev/hour':>8} {'max_gap(min)':>13}")
for source_type in display_order:
    s = stats[source_type]
    print(f"{source_type:<18} {s['record_count']:>8} {s['unique_hosts']:>8} {s['events_per_hour']:>8} {s['coverage_gap_minutes']:>13}")
print(f"{'overall':<18} {overall['record_count']:>8} {overall['unique_hosts']:>8} {overall['events_per_hour']:>8} {overall['coverage_gap_minutes']:>13}")
print(f"source_stats.json written")

PYTHON_EOF
