#!/bin/bash
#
# Name: 5-baseline_process.sh
# Purpose: Compute per-host process execution baseline (expected processes, frequency, parent-child pairs)
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

def parse_ts(raw):
    """Parse an ISO 8601 timestamp, returning None on failure."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def basename(path):
    """Extract the filename from a Windows or Unix path."""
    if not path:
        return None
    path = str(path).replace("\\", "/")
    parts = path.rsplit("/", 1)
    return parts[-1] if parts[-1] else None

def extract_proc_name(event):
    """Extract the process name from multiple possible locations."""
    # Direct field
    proc = event.get("process_name")
    if proc:
        return str(proc)

    ed = event.get("event_data") or {}

    # Sysmon Image field (Event ID 1)
    image = ed.get("Image")
    if image:
        return basename(image)

    # Linux process_name in event_data
    pn = ed.get("process_name")
    if pn:
        return str(pn)

    # PowerShell script block logging (Event ID 4104)
    if ed.get("ScriptBlockText"):
        return "powershell_scriptblock"

    # Fallback: use event_id as a pseudo-process name
    eid = event.get("event_id")
    if eid:
        return f"event_{eid}"

    return "unknown"

def extract_parent(event):
    """Extract the parent process name from multiple possible locations."""
    ed = event.get("event_data") or {}

    # Sysmon ParentImage
    parent = ed.get("ParentImage")
    if parent:
        return basename(parent)

    # Alternative field names
    parent = ed.get("ParentProcessName") or ed.get("parent_process")
    if parent:
        return str(parent)

    # Try raw_message pattern: "Process Create: ... by parent.exe"
    raw = event.get("raw_message")
    if raw and " by " in str(raw):
        parts = str(raw).rsplit(" by ", 1)
        if len(parts) == 2:
            after_by = parts[1].strip()
            if " by " in after_by:
                after_by = after_by.rsplit(" by ", 1)[0]
            return basename(after_by) or after_by

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

    proc_stats = defaultdict(dict)
    global_counts = Counter()
    proc_hosts = defaultdict(set)
    parent_child_pairs = defaultdict(Counter)

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
            if label not in ("process_start", "child_process_spawn"):
                continue

            ts = parse_ts(event.get("timestamp"))
            if ts is None or ts < window_start or ts >= window_end:
                continue

            host = event.get("hostname") or "unknown"
            proc = extract_proc_name(event)
            user = event.get("user") or "unknown"
            ts_str = str(event.get("timestamp"))

            host_map = proc_stats.setdefault(host, {})
            if proc not in host_map:
                host_map[proc] = {
                    "count": 0,
                    "first_seen": ts_str,
                    "last_seen": ts_str,
                    "users": set(),
                }
            stat = host_map[proc]
            stat["count"] += 1
            if ts_str < stat["first_seen"]:
                stat["first_seen"] = ts_str
            if ts_str > stat["last_seen"]:
                stat["last_seen"] = ts_str
            stat["users"].add(user)

            global_counts[proc] += 1
            proc_hosts[proc].add(host)

            parent = extract_parent(event)
            if parent:
                parent_child_pairs[host][(parent, proc)] += 1

    # Rare processes: seen on only one host OR fewer than five executions total
    rare_processes = sorted(
        p for p in global_counts
        if len(proc_hosts[p]) == 1 or global_counts[p] < 5
    )

    # Assemble output
    per_host_out = {}
    for host in sorted(proc_stats.keys()):
        host_map = proc_stats[host]
        per_host_out[host] = {
            proc: {
                "execution_count": stat["count"],
                "first_seen": stat["first_seen"],
                "last_seen": stat["last_seen"],
                "executing_users": sorted(stat["users"]),
            }
            for proc, stat in sorted(host_map.items())
        }

    global_top = [
        {"process": p, "count": c}
        for p, c in global_counts.most_common(50)
    ]

    parent_child_out = {
        host: [
            {"parent": parent, "child": child, "count": count}
            for (parent, child), count in sorted(pairs.items())
        ]
        for host, pairs in sorted(parent_child_pairs.items())
    }

    results = {
        "window": {"start": start_str, "end": end_str, "days": baseline_days},
        "per_host": per_host_out,
        "global_top": global_top,
        "rare_processes": rare_processes,
        "parent_child_pairs": parent_child_out,
    }

    output_file = os.path.join(baseline_pkg, "baseline_process.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    top_proc, top_count = (
        (global_top[0]["process"], global_top[0]["count"]) if global_top else ("none", 0)
    )
    total_pc_pairs = sum(len(v) for v in parent_child_out.values())

    print(f"baseline window : {start_str} -> {end_str}")
    print(f"processes indexed by host: {len(per_host_out)} hosts")
    print(f"global top process    : {top_proc} ({top_count} executions)")
    print(f"rare processes        : {len(rare_processes)}")
    print(f"parent->child pairs   : {total_pc_pairs}")
    print("baseline_process.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
