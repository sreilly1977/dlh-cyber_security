#!/usr/bin/env python3
#
# Name: 8-correlation_primitives.py
# Purpose: Build credential-theft-chain correlation primitives from labeled events
#          (>=3 auth failures from IP A in 300s -> success for same user from
#          different IP B in 300s -> privilege_escalation on same host in 600s)
#          and write correlation_primitives.json for the sigma runner.
# Author: Steve - Cybersecurity Engineer
# Date: 05 September 2026
#
# Output: NDJSON, one chain record per line, sorted by timestamp.

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timedelta

BASELINE_PKG = os.environ.get(
    "BASELINE_PKG", os.path.expanduser("~/3x01_package/baseline_package"))
LABELED_EVENTS = os.environ.get(
    "LABELED_EVENTS", os.path.join(BASELINE_PKG, "labeled_events.json"))
OUTPUT_FILE = os.environ.get(
    "CORRELATION_PRIMITIVES",
    os.path.expanduser("~/3x02_package/correlation_primitives.json"))

FAILURE_MIN = 3
FAILURE_WINDOW = timedelta(seconds=300)
SUCCESS_WINDOW = timedelta(seconds=300)
PRIVESC_WINDOW = timedelta(seconds=600)


def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


def main():
    failures = defaultdict(lambda: defaultdict(list))   # (user,host) -> src_ip -> [(ts, rid)]
    successes = defaultdict(list)                       # (user,host) -> [(ts, src_ip, rid)]
    privesc = defaultdict(list)                         # host -> [(ts, rid)]

    with open(LABELED_EVENTS, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(ev.get("timestamp"))
            if ts is None:
                continue
            label = ev.get("canonical_label")
            host = ev.get("hostname")
            user = ev.get("user")
            rid = ev.get("record_id")
            if label == "login_failure":
                ip = ev.get("src_ip")
                if ip and user and host:
                    failures[(user, host)][ip].append((ts, rid))
            elif label == "login_success":
                ip = ev.get("src_ip")
                if ip and user and host:
                    successes[(user, host)].append((ts, ip, rid))
            elif label == "privilege_escalation":
                if host:
                    privesc[host].append((ts, rid))

    for d in (failures,):
        for sub in d.values():
            for lst in sub.values():
                lst.sort(key=lambda x: x[0])
    for lst in successes.values():
        lst.sort(key=lambda x: x[0])
    for lst in privesc.values():
        lst.sort(key=lambda x: x[0])

    # Best chain per success event (dedupe overlapping failure bursts)
    best = {}

    for (user, host), by_ip in failures.items():
        for ip_a, events in by_ip.items():
            times = [e[0] for e in events]
            n = len(events)
            # sliding anchors: window [times[i], times[i]+300s]
            for i in range(n):
                j = i
                while j < n and times[j] - times[i] <= FAILURE_WINDOW:
                    j += 1
                if j - i < FAILURE_MIN:
                    continue
                t_end = times[j - 1]
                fail_refs = [events[k][1] for k in range(i, j)]
                # stage 2: success from a different source IP within 300s of burst end
                for (s_ts, ip_b, s_rid) in successes.get((user, host), []):
                    if ip_b == ip_a:
                        continue
                    if not (t_end < s_ts <= t_end + SUCCESS_WINDOW):
                        continue
                    # stage 3: any privilege_escalation on same host within 600s
                    pe = [(p_ts, p_rid) for (p_ts, p_rid) in privesc.get(host, [])
                          if s_ts < p_ts <= s_ts + PRIVESC_WINDOW]
                    if not pe:
                        continue
                    key = s_rid
                    cand = {
                        "correlation_primitive": "credential_compromise_chain",
                        "timestamp": s_ts.isoformat().replace("+00:00", "Z"),
                        "hostname": host,
                        "user": user,
                        "failure_src_ip": ip_a,
                        "success_src_ip": ip_b,
                        "failure_count": j - i,
                        "failure_window_end": t_end.isoformat().replace("+00:00", "Z"),
                        "stage_refs": {
                            "failures": fail_refs,
                            "success": s_rid,
                            "privilege_escalations": [r for (_, r) in pe],
                        },
                        "record_id": s_rid,
                        "event_ref": s_rid,
                    }
                    prev = best.get(key)
                    if prev is None or cand["failure_count"] > prev["failure_count"]:
                        best[key] = cand

    chains = sorted(best.values(), key=lambda c: (c["timestamp"], c["hostname"] or ""))

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        for c in chains:
            out.write(json.dumps(c, separators=(",", ":")) + "\n")

    print(f"credential_compromise_chain primitives : {len(chains)}")
    print("correlation_primitives.json written")


if __name__ == "__main__":
    main()
