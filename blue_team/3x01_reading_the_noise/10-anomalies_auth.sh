#!/bin/bash
#
# Name: 10-anomalies_auth.sh
# Purpose: Detect authentication anomalies in the evaluation window using baseline thresholds
# Author: Steve - Cybersecurity Engineer
# Date: 31 August 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

BASELINE_SUMMARY="${BASELINE_PKG}/baseline_summary.json"
LABELED_EVENTS="${BASELINE_PKG}/labeled_events.json"

for f in "${BASELINE_SUMMARY}" "${LABELED_EVENTS}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: Required input not found: ${f}" >&2
        exit 1
    fi
done

export BASELINE_SUMMARY LABELED_EVENTS BASELINE_PKG

python3 -W error - << 'PYEOF'
import json
import os
from collections import defaultdict
from datetime import datetime

BUSINESS_HOURS = set(range(6, 18))
PE_SURGE_THRESHOLD = 3  # more than this many PE events on a zero-baseline host

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def main():
    with open(os.environ["BASELINE_SUMMARY"]) as f:
        summary = json.load(f)

    bw = summary["baseline_window"]
    ew = summary["evaluation_window"]

    base_end = datetime.fromisoformat(bw["end"].replace("Z", "+00:00"))
    eval_start = datetime.fromisoformat(ew["start"].replace("Z", "+00:00"))
    eval_end = datetime.fromisoformat(ew["end"].replace("Z", "+00:00"))

    auth = summary.get("auth", {})
    thresholds = summary.get("thresholds", {})

    # Known accounts: verified as an array
    ka = auth.get("known_accounts", [])
    if isinstance(ka, dict):
        known_accounts = set(ka.keys())
    elif isinstance(ka, list):
        known_accounts = set(ka)
    else:
        known_accounts = set()

    # Burst limit: baseline max 1h failures x multiplier, floored by summary threshold
    max_1h_observed = auth.get("max_failures_1h_window", 0)
    if not isinstance(max_1h_observed, (int, float)):
        max_1h_observed = 0
    frm = int(thresholds.get("failure_rate_multiplier", {}).get("value", 3))
    burst_limit = int(max_1h_observed) * frm
    fb_floor = thresholds.get("failure_burst_threshold", {}).get("value", 0)
    if isinstance(fb_floor, (int, float)):
        burst_limit = max(burst_limit, int(fb_floor))

    # --- Pass 1: baseline habits ---
    user_periods = defaultdict(set)      # user -> {"bh","oh"} seen in baseline
    host_pe_baseline = defaultdict(int)  # host -> PE count in baseline

    with open(os.environ["LABELED_EVENTS"]) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(ev.get("timestamp"))
            if ts is None or ts >= base_end:
                continue
            label = ev.get("canonical_label")
            if label == "login_success":
                u = ev.get("user")
                if u:
                    user_periods[u].add("bh" if ts.hour in BUSINESS_HOURS else "oh")
            elif label in ("privilege_escalation", "sudo"):
                host_pe_baseline[ev.get("hostname") or "unknown"] += 1

    # --- Pass 2: evaluation window scan ---
    counts = defaultdict(int)
    anomalies = []

    fail_data = defaultdict(list)  # src_ip -> list of (ts, ref, host, user)
    pe_eval = defaultdict(list)    # host -> list of (ts, ref, user)

    with open(os.environ["LABELED_EVENTS"]) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(ev.get("timestamp"))
            if ts is None or not (eval_start <= ts < eval_end):
                continue
            label = ev.get("canonical_label")
            if label not in ("login_success", "login_failure",
                             "privilege_escalation", "sudo"):
                continue

            host = ev.get("hostname") or "unknown"
            user = ev.get("user") or ""          # empty string, not "unknown"
            src_ip = ev.get("src_ip") or "unknown"
            ref = ev.get("record_id") or ""

            # unknown_account (requires an attributed user; null != novel)
            if label in ("login_success", "login_failure") and user \
                    and known_accounts and user not in known_accounts:
                counts["unknown_account"] += 1
                anomalies.append({
                    "timestamp": iso(ts), "host": host,
                    "user": user if user else "(unattributed)",
                    "src_ip": src_ip,
                    "anomaly_type": "unknown_account",
                    "baseline_value": "user absent from known_accounts",
                    "observed_value": label,
                    "severity": "high" if label == "login_success" else "medium",
                    "event_refs": [ref] if ref else [],
                })

            if label == "login_failure":
                fail_data[src_ip].append((ts, ref, host, user))

            # offhours_login: BH-only baseline users logging in off-hours
            if label == "login_success" and ts.hour not in BUSINESS_HOURS and user:
                prior = user_periods.get(user)
                if prior and "oh" not in prior and "bh" in prior:
                    counts["offhours_login"] += 1
                    anomalies.append({
                        "timestamp": iso(ts), "host": host, "user": user,
                        "src_ip": src_ip,
                        "anomaly_type": "offhours_login",
                        "baseline_value": "only business-hours logins in baseline",
                        "observed_value": f"login_success at {ts.hour:02d}:00",
                        "severity": "medium",
                        "event_refs": [ref] if ref else [],
                    })

            # PE events on zero-baseline hosts
            if label in ("privilege_escalation", "sudo") \
                    and host_pe_baseline.get(host, 0) == 0:
                pe_eval[host].append((ts, ref, user))

    # --- Failure bursts: best 1h window per src_ip ---
    for src_ip, entries in fail_data.items():
        entries.sort(key=lambda e: e[0])
        times = [e[0] for e in entries]
        n = len(times)
        best_count = 0
        best_i = 0
        i = 0
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() < 3600:
                j += 1
            if (j - i) > best_count:
                best_count = j - i
                best_i = i
            i += 1

        if best_count > burst_limit:
            win = entries[best_i:best_i + best_count]
            counts["failure_rate_burst"] += 1
            anomalies.append({
                "timestamp": iso(win[0][0]),
                "host": win[0][2],
                "user": win[0][3] if win[0][3] else "(unattributed)",
                "src_ip": src_ip,
                "anomaly_type": "failure_rate_burst",
                "baseline_value": f"{int(max_1h_observed)} max 1h failures x {frm} = {burst_limit}",
                "observed_value": f"{best_count} failures within 1h",
                "severity": "high" if best_count >= burst_limit * 2 else "medium",
                "event_refs": [e[1] for e in win if e[1]][:20],
            })

    # Privilege escalation surges: hosts with zero baseline PE
    for host, pe_entries in pe_eval.items():
        if len(pe_entries) > PE_SURGE_THRESHOLD:
            pe_entries.sort(key=lambda e: e[0])
            counts["privilege_escalation_surge"] += 1
            anomalies.append({
                "timestamp": iso(pe_entries[0][0]),
                "host": host,
                "user": pe_entries[0][2] if pe_entries[0][2] else "(unattributed)",
                "src_ip": "n/a",
                "anomaly_type": "privilege_escalation_surge",
                "baseline_value": 0,
                "observed_value": len(pe_entries),
                "severity": "critical" if len(pe_entries) >= 5 else "high",
                "event_refs": [e[1] for e in pe_entries if e[1]][:20],
            })

    anomalies.sort(key=lambda a: a["timestamp"])

    out_path = os.path.join(os.environ["BASELINE_PKG"], "anomalies_auth.json")
    with open(out_path, "w") as f:
        json.dump({
            "evaluation_window": {"start": iso(eval_start), "end": iso(eval_end)},
            "total_anomalies": len(anomalies),
            "anomalies": anomalies,
        }, f, indent=2)

    print(f"evaluation window  : {iso(eval_start)} -> {iso(eval_end)}")
    print(f"unknown_account           : {counts['unknown_account']}")
    print(f"failure_rate_burst        : {counts['failure_rate_burst']}")
    print(f"offhours_login            : {counts['offhours_login']}")
    print(f"privilege_escalation_surge: {counts['privilege_escalation_surge']}")
    print(f"total anomalies           : {len(anomalies)}")
    print("anomalies_auth.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
