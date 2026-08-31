#!/bin/bash
#
# Name: 8-temporal_profile.sh
# Purpose: Produce hourly and daily activity profiles per source type and canonical label
# Author: Steve - Cybersecurity Engineer
# Date: 31 August 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

LABELED_EVENTS="${BASELINE_PKG}/labeled_events.json"

if [[ ! -f "${LABELED_EVENTS}" ]]; then
    echo "ERROR: Labeled events file not found at ${LABELED_EVENTS}" >&2
    echo "Run 3-event_taxonomy.sh first." >&2
    exit 1
fi

export LABELED_EVENTS BASELINE_DAYS BASELINE_PKG

python3 -W error - << 'PYEOF'
import json
import os
import sys
from collections import defaultdict, Counter
from datetime import datetime, timedelta

BUSINESS_HOURS = set(range(6, 18))  # 06:00 - 17:59

DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def ascii_bar(value, max_value, width=40):
    """Render a simple ASCII bar chart."""
    if max_value <= 0:
        return ""
    bar_len = int((value / max_value) * width)
    return "#" * bar_len

def main():
    labeled_path = os.environ["LABELED_EVENTS"]
    baseline_pkg = os.environ["BASELINE_PKG"]

    baseline_days = int(os.environ.get("BASELINE_DAYS", "7"))
    if baseline_days < 1:
        print("ERROR: BASELINE_DAYS must be >= 1", file=sys.stderr)
        sys.exit(1)

    # Pass 1: derive window start from the earliest timestamp
    min_ts = None
    with open(labeled_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(event.get("timestamp"))
            if ts and (min_ts is None or ts < min_ts):
                min_ts = ts

    if min_ts is None:
        print("ERROR: No parsable events found", file=sys.stderr)
        sys.exit(1)

    window_start = min_ts.replace(hour=0, minute=0, second=0, microsecond=0)
    window_end = window_start + timedelta(days=baseline_days)
    start_str = window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Count distinct calendar days that appear in the baseline
    # for proper mean computation
    observed_dates = set()

    # Accumulators: (source_type, canonical_label) -> {
    #   hour_counts: Counter of 0-23,
    #   dow_counts: Counter of 0-6,
    #   bh_count: int, oh_count: int, total: int
    # }
    profiles = defaultdict(lambda: {
        "hour_counts": Counter(),
        "dow_counts": Counter(),
        "bh_count": 0,
        "oh_count": 0,
        "total": 0,
    })

    # Also track overall label totals for top-3 selection
    label_totals = Counter()

    with open(labeled_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = parse_ts(event.get("timestamp"))
            if ts is None or ts < window_start or ts >= window_end:
                continue

            source_type = event.get("source_type", "unknown")
            canonical_label = event.get("canonical_label", "unlabeled")
            key = (source_type, canonical_label)

            observed_dates.add(ts.strftime("%Y-%m-%d"))

            prof = profiles[key]
            prof["hour_counts"][ts.hour] += 1
            prof["dow_counts"][ts.weekday()] += 1
            prof["total"] += 1
            label_totals[canonical_label] += 1

            if ts.hour in BUSINESS_HOURS:
                prof["bh_count"] += 1
            else:
                prof["oh_count"] += 1

    num_days = max(len(observed_dates), 1)

    # Build output structure
    results = {
        "window": {"start": start_str, "end": end_str, "days": baseline_days},
        "observed_days": num_days,
        "profiles": {},
    }

    # Track per-source-type label counts for the summary
    source_labels = defaultdict(set)

    # Track top-3 labels by total count across all source types
    # for ASCII histogram output
    label_hour_profiles = defaultdict(lambda: Counter())

    for (source_type, canonical_label), prof in sorted(profiles.items()):
        source_labels[source_type].add(canonical_label)

        # Mean per hour of day (divide by num_days)
        hour_hist = []
        for h in range(24):
            hour_hist.append(round(prof["hour_counts"].get(h, 0) / num_days, 2))

        # Mean per day of week (divide by number of that weekday in baseline)
        dow_hist = []
        # Count how many of each weekday fall in the baseline window
        dow_in_window = [0] * 7
        d = window_start
        while d < window_end:
            dow_in_window[d.weekday()] += 1
            d += timedelta(days=1)

        for wd in range(7):
            divisor = max(dow_in_window[wd], 1)
            dow_hist.append(round(prof["dow_counts"].get(wd, 0) / divisor, 2))

        # Peak and quiet hours
        peak_hour = max(range(24), key=lambda h: prof["hour_counts"].get(h, 0))
        quiet_hour = min(range(24), key=lambda h: prof["hour_counts"].get(h, 0))

        # Business/off-hours ratio
        bh = prof["bh_count"]
        oh = prof["oh_count"]
        if oh > 0:
            ratio = round(bh / oh, 2)
        else:
            ratio = round(float(bh), 2) if bh > 0 else 0.0

        profile_entry = {
            "hour_of_day_histogram": hour_hist,
            "day_of_week_histogram": dow_hist,
            "peak_hour": peak_hour,
            "quiet_hour": quiet_hour,
            "business_offhours_ratio": ratio,
            "total_events": prof["total"],
        }

        # Key as "source_type/canonical_label" for JSON readability
        composite_key = f"{source_type}/{canonical_label}"
        results["profiles"][composite_key] = profile_entry

        # Accumulate hour profiles per canonical_label for ASCII output
        for h in range(24):
            label_hour_profiles[canonical_label][h] += prof["hour_counts"].get(h, 0)

    # Write JSON output
    output_file = os.path.join(baseline_pkg, "temporal_profile.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    # Print summary
    print(f"baseline window   : {start_str} -> {end_str}")
    print(f"source_type         labels profiled")
    for st in sorted(source_labels.keys()):
        print(f"  {st:<20} {len(source_labels[st])}")

    # ASCII histogram for top 3 most active canonical labels
    top3 = label_totals.most_common(3)
    print("top 3 labels temporal shape (per hour, baseline avg):")
    for label, _ in top3:
        hour_counts = label_hour_profiles[label]
        max_h = max(hour_counts.values()) if hour_counts else 0
        print(f"  {label}")
        for h in range(24):
            val = hour_counts.get(h, 0)
            mean_val = round(val / num_days, 1)
            bar = ascii_bar(val, max_h)
            print(f"    {h:02d}:00  {mean_val:>8.1f}  {bar}")
        peak = max(range(24), key=lambda h: hour_counts.get(h, 0))
        quiet = min(range(24), key=lambda h: hour_counts.get(h, 0))
        print(f"    peak={peak:02d}:00  quiet={quiet:02d}:00")

    print("temporal_profile.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
