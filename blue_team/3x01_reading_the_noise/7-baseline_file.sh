#!/bin/bash
#
# Name: 7-baseline_file.sh
# Purpose: Compute file access baseline for sensitive directories across all hosts
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

FILE_LABELS = {
    "file_read_sensitive",
    "file_write_sensitive",
    "file_permission_change",
}

# Configurable sensitive path prefixes (matched case-insensitively)
SENSITIVE_PREFIXES = [
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/",
    "/var/log/audit/",
    "c:\\windows\\system32\\config\\",
    "c:\\program files\\meddefense\\",
    "c:\\meddefense\\",
    "/opt/meddefense/",
    "/etc/meddefense/",
]

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def is_sensitive(path):
    """Case-insensitive prefix match against the sensitive list."""
    if not path:
        return False
    norm = str(path).lower().strip()
    return any(norm.startswith(p) for p in SENSITIVE_PREFIXES)

def extract_file_path(event):
    """Extract a file path if the event carries one."""
    path = event.get("file_path") or event.get("target_filename")
    if path:
        return str(path)

    ed = event.get("event_data") or {}
    for key in ("TargetFilename", "ObjectName", "FileName", "FilePath"):
        if ed.get(key):
            return str(ed[key])

    raw = event.get("raw_message")
    if raw:
        raw_str = str(raw)
        low = raw_str.lower()
        for prefix in SENSITIVE_PREFIXES:
            idx = low.find(prefix)
            if idx != -1:
                end = idx + len(prefix)
                while end < len(raw_str) and raw_str[end] not in " \t\"'<>|":
                    end += 1
                return raw_str[idx:end]

        # Student telemetry pattern: "copy <src> <dst>"
        if raw_str.lower().startswith("module") and " copy " in low:
            parts = raw_str.split(" copy ")
            if len(parts) == 2:
                return parts[1].strip()

    return None

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

    # Accumulators
    path_access = defaultdict(Counter)   # path -> (proc, user) -> count
    host_paths = defaultdict(set)        # host -> set of sensitive paths
    path_counts = Counter()              # path -> total count
    # Pathless Sysmon/audit events: host -> event_id -> count
    unattributed = defaultdict(Counter)

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
            if label not in FILE_LABELS:
                continue

            ts = parse_ts(event.get("timestamp"))
            if ts is None or ts < window_start or ts >= window_end:
                continue

            host = event.get("hostname") or "unknown"
            file_path = extract_file_path(event)

            if not file_path:
                # No path recoverable: track under an event-type identifier
                eid = event.get("event_id") or "unknown"
                unattributed[host][f"event_{eid}"] += 1
                continue

            if is_sensitive(file_path):
                proc = event.get("process_name") or "unknown"
                user = event.get("user") or "unknown"
                path_access[file_path][(proc, user)] += 1
                host_paths[host].add(file_path)
                path_counts[file_path] += 1

    sensitive_paths = sorted(path_counts.keys())

    per_path_access = {}
    for path in sorted(path_access.keys()):
        per_path_access[path] = [
            {"process": proc, "user": user, "count": count}
            for (proc, user), count in sorted(
                path_access[path].items(), key=lambda x: (-x[1], x[0])
            )
        ]

    per_host_paths = {
        host: sorted(paths)
        for host, paths in sorted(host_paths.items())
    }

    rare_accesses = sorted(
        path for path, count in path_counts.items() if count < 3
    )

    results = {
        "window": {"start": start_str, "end": end_str, "days": baseline_days},
        "sensitive_prefixes": SENSITIVE_PREFIXES,
        "sensitive_paths": sensitive_paths,
        "per_path_access": per_path_access,
        "per_host_paths": per_host_paths,
        "rare_accesses": rare_accesses,
        "unattributed_events": {
            host: dict(sorted(counts.items()))
            for host, counts in sorted(
                {h: dict(c) for h, c in unattributed.items()}.items()
            )
        },
        "note": (
            "evidence_pack Sysmon file/registry events carry no file path fields; "
            "unattributed_events tracks their per-host volume so day-8 spikes remain detectable."
        ),
    }

    output_file = os.path.join(baseline_pkg, "baseline_file.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    total_accesses = sum(path_counts.values())

    print(f"baseline window   : {start_str} -> {end_str}")
    print(f"sensitive paths   : {len(sensitive_paths)}")
    print(f"total accesses     : {total_accesses}")
    print(f"per host coverage  : {len(per_host_paths)} hosts")
    print(f"rare accesses     : {len(rare_accesses)}")
    print("baseline_file.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
