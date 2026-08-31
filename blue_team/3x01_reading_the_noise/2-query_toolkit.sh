#!/bin/bash
#
# Name: 2-query_toolkit.sh
# Purpose: Reusable CLI query toolkit for filtering, projecting, and aggregating events
# Author: Steve - Cybersecurity Engineer
# Date: 31 August 2026
#

set -euo pipefail

# Resolve HANDOFF_DIR with default
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

ENRICHED_EVENTS="${HANDOFF_DIR}/data/enriched_events.json"

if [[ ! -f "${ENRICHED_EVENTS}" ]]; then
    echo "ERROR: Enriched events file not found at ${ENRICHED_EVENTS}" >&2
    exit 1
fi

export ENRICHED_EVENTS

python3 -W error - "$@" << 'PYEOF'
import json
import os
import sys
import argparse
from collections import Counter

USAGE = """query_toolkit.sh <verb> [options]
  filter   emit matching records as ndjson
  top      top N values of a field
  distinct distinct values of a field
  count    number of matching records
  window   bucketed counts by time window
  help     this message"""

def matches_filters(event, args):
    """Check if an event matches all provided filter arguments."""
    if hasattr(args, "source") and args.source is not None:
        if event.get("source_type") != args.source:
            return False
    if hasattr(args, "host") and args.host is not None:
        if event.get("hostname") != args.host:
            return False
    if hasattr(args, "category") and args.category is not None:
        if event.get("event_category") != args.category:
            return False
    ts = event.get("timestamp")
    if hasattr(args, "from_ts") and args.from_ts is not None:
        if ts is None or ts < args.from_ts:
            return False
    if hasattr(args, "to_ts") and args.to_ts is not None:
        if ts is None or ts >= args.to_ts:
            return False
    return True

def iter_events(path):
    """Stream NDJSON one line at a time, yielding parsed dicts."""
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue

def safe_write(s):
    """Write to stdout, suppressing BrokenPipeError gracefully."""
    try:
        sys.stdout.write(s)
    except BrokenPipeError:
        sys.stdout = None
        sys.exit(0)

def add_filter_args(subparser):
    """Add shared filter arguments to a subparser."""
    subparser.add_argument("--source", default=None, help="Filter by source_type")
    subparser.add_argument("--host", default=None, help="Filter by hostname")
    subparser.add_argument("--from", dest="from_ts", default=None,
                           help="ISO timestamp lower bound (inclusive)")
    subparser.add_argument("--to", dest="to_ts", default=None,
                           help="ISO timestamp upper bound (exclusive)")
    subparser.add_argument("--category", default=None, help="Filter by event_category")

def cmd_filter(args):
    enriched = os.environ["ENRICHED_EVENTS"]
    for event in iter_events(enriched):
        if matches_filters(event, args):
            safe_write(json.dumps(event, separators=(",", ":")) + "\n")

def cmd_top(args):
    enriched = os.environ["ENRICHED_EVENTS"]
    counter = Counter()
    for event in iter_events(enriched):
        if matches_filters(event, args):
            val = event.get(args.field)
            if val is not None:
                counter[str(val)] += 1
    for value, count in counter.most_common(args.limit):
        safe_write(f"{value}\t{count}\n")

def cmd_distinct(args):
    enriched = os.environ["ENRICHED_EVENTS"]
    seen = set()
    for event in iter_events(enriched):
        if matches_filters(event, args):
            val = event.get(args.field)
            if val is not None:
                val_str = str(val)
                if val_str not in seen:
                    seen.add(val_str)
                    safe_write(val_str + "\n")

def cmd_count(args):
    enriched = os.environ["ENRICHED_EVENTS"]
    count = 0
    for event in iter_events(enriched):
        if matches_filters(event, args):
            count += 1
    safe_write(str(count) + "\n")

def cmd_window(args):
    enriched = os.environ["ENRICHED_EVENTS"]
    counter = Counter()
    field = args.field
    for event in iter_events(enriched):
        if matches_filters(event, args):
            ts = event.get(field)
            if not ts:
                continue
            if args.bucket == "hour":
                bucket = ts[:13]
            elif args.bucket == "day":
                bucket = ts[:10]
            else:
                continue
            counter[bucket] += 1
    for bucket, count in sorted(counter.items()):
        safe_write(f"{bucket}\t{count}\n")

def main():
    parser = argparse.ArgumentParser(prog="2-query_toolkit.sh", add_help=False)
    subparsers = parser.add_subparsers(dest="verb")

    # filter
    sp = subparsers.add_parser("filter", add_help=False)
    add_filter_args(sp)
    sp.set_defaults(func=cmd_filter)

    # top
    sp = subparsers.add_parser("top", add_help=False)
    add_filter_args(sp)
    sp.add_argument("--field", required=True, help="Field to rank by occurrence")
    sp.add_argument("--limit", type=int, default=10, help="Max results (default 10)")
    sp.set_defaults(func=cmd_top)

    # distinct
    sp = subparsers.add_parser("distinct", add_help=False)
    add_filter_args(sp)
    sp.add_argument("--field", required=True, help="Field to list distinct values for")
    sp.set_defaults(func=cmd_distinct)

    # count
    sp = subparsers.add_parser("count", add_help=False)
    add_filter_args(sp)
    sp.set_defaults(func=cmd_count)

    # window
    sp = subparsers.add_parser("window", add_help=False)
    add_filter_args(sp)
    sp.add_argument("--field", required=True, help="Timestamp field to bucket on")
    sp.add_argument("--bucket", choices=["hour", "day"], required=True,
                    help="Bucket granularity")
    sp.set_defaults(func=cmd_window)

    # help
    sp = subparsers.add_parser("help", add_help=False)
    sp.set_defaults(func=None)

    args = parser.parse_args(sys.argv[1:])

    if args.verb is None or args.verb == "help":
        sys.stdout.write(USAGE + "\n")
        sys.exit(0)

    args.func(args)

if __name__ == "__main__":
    main()
PYEOF
exit 0
