#!/bin/bash
#
# Name: 4-baseline_auth.sh
# Purpose: Compute authentication baseline over the clean window (per-host, per-user, hourly patterns)
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
from collections import Counter, defaultdict
from datetime import datetime, timedelta

AUTH_LABELS = [
    "login_success",
    "login_failure",
    "logout",
    "account_lockout",
    "privilege_escalation",
]

BUSINESS_HOURS = set(range(6, 18))                       # 06:00 - 17:59
OFFHOURS_HOURS = set(range(18, 24)) | set(range(0, 6))   # 18:00 - 05:59

def parse_ts(raw):
    """Parse an ISO 8601 timestamp, returning None on failure."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def main():
    labeled_path = os.environ["LABELED_EVENTS"]
    baseline_pkg = os.environ["BASELINE_PKG"]

    baseline_days = int(os.environ.get("BASELINE_DAYS", "7"))
    if baseline_days < 1:
        print("ERROR: BASELINE_DAYS must be >= 1", file=sys.stderr)
        sys.exit(1)

    # Pass 1: derive window start from the earliest timestamp in the dataset
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

    host_counters = defaultdict(Counter)
    user_counters = defaultdict(Counter)
    known_accounts = set()
    bh_counter = Counter()
    oh_counter = Counter()
    failures_by_ip_hour = Counter()

    with open(labeled_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            label = event.get("canonical_label")
            if label not in AUTH_LABELS:
                continue

            ts = parse_ts(event.get("timestamp"))
            if ts is None or ts < window_start or ts >= window_end:
                continue

            host = event.get("hostname") or "unknown"
            host_counters[host][label] += 1

            user = event.get("user")
            if user:
                known_accounts.add(user)
                if label == "login_success":
                    user_counters[user]["success"] += 1
                elif label == "login_failure":
                    user_counters[user]["failure"] += 1

            hour = ts.hour
            if label == "login_success":
                if hour in BUSINESS_HOURS:
                    bh_counter["success"] += 1
                else:
                    oh_counter["success"] += 1
            elif label == "login_failure":
                if hour in BUSINESS_HOURS:
                    bh_counter["failure"] += 1
                else:
                    oh_counter["failure"] += 1
                src_ip = event.get("src_ip")
                if src_ip:
                    failures_by_ip_hour[(src_ip, ts.strftime("%Y-%m-%dT%H"))] += 1

    per_user = [
        {"user": u, "success": c.get("success", 0), "failure": c.get("failure", 0)}
        for u, c in sorted(user_counters.items())
    ]

    bh_hours = baseline_days * 12
    oh_hours = baseline_days * 12
    baseline = {
        "window": {"start": start_str, "end": end_str, "days": baseline_days},
        "per_host": {
            h: {lbl: c.get(lbl, 0) for lbl in AUTH_LABELS}
            for h, c in sorted(host_counters.items())
        },
        "per_user": per_user,
        "known_accounts": sorted(known_accounts),
        "business_hours_avg": {
            "success_per_hour": round(bh_counter.get("success", 0) / bh_hours, 2),
            "failure_per_hour": round(bh_counter.get("failure", 0) / bh_hours, 2),
        },
        "offhours_avg": {
            "success_per_hour": round(oh_counter.get("success", 0) / oh_hours, 2),
            "failure_per_hour": round(oh_counter.get("failure", 0) / oh_hours, 2),
        },
        "max_failures_1h_window": max(failures_by_ip_hour.values()) if failures_by_ip_hour else 0,
    }

    output_file = os.path.join(baseline_pkg, "baseline_auth.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(baseline, f, indent=2)

    print(f"baseline window : {start_str} -> {end_str}")
    print(f"hosts           : {len(host_counters)}")
    print(f"known accounts  : {len(known_accounts)}")
    print(f"business hours  : {baseline['business_hours_avg']['success_per_hour']} success/h  |  "
          f"{baseline['business_hours_avg']['failure_per_hour']} failure/h")
    print(f"off hours       : {baseline['offhours_avg']['success_per_hour']} success/h  |  "
          f"{baseline['offhours_avg']['failure_per_hour']} failure/h")
    print(f"max 1h src_ip failures : {baseline['max_failures_1h_window']}")
    print("baseline_auth.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
