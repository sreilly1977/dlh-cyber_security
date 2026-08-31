#!/bin/bash
#
# Name: 9-baseline_summary.sh
# Purpose: Combine all baselines into a single machine-readable summary for anomaly detection
# Author: Steve - Cybersecurity Engineer
# Date: 31 August 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

# Verify all required input files exist
for f in baseline_auth.json baseline_process.json baseline_network.json baseline_file.json temporal_profile.json; do
    if [[ ! -f "${BASELINE_PKG}/${f}" ]]; then
        echo "ERROR: ${f} not found in ${BASELINE_PKG}" >&2
        echo "Run the corresponding baseline script first." >&2
        exit 1
    fi
done

export BASELINE_PKG BASELINE_DAYS

python3 -W error - << 'PYEOF'
import json
import os
import sys
from datetime import datetime, timedelta, timezone

def load_json(path):
    """Load a JSON file, returning an empty dict on error."""
    with open(path, "r") as f:
        return json.load(f)

def main():
    baseline_pkg = os.environ["BASELINE_PKG"]

    # Load all baseline sub-documents
    auth = load_json(os.path.join(baseline_pkg, "baseline_auth.json"))
    process = load_json(os.path.join(baseline_pkg, "baseline_process.json"))
    network = load_json(os.path.join(baseline_pkg, "baseline_network.json"))
    file_base = load_json(os.path.join(baseline_pkg, "baseline_file.json"))
    temporal = load_json(os.path.join(baseline_pkg, "temporal_profile.json"))

    # Derive baseline window from the auth baseline (authoritative for the window)
    bw = auth.get("window", {})
    baseline_start = bw.get("start", "")
    baseline_end = bw.get("end", "")
    baseline_days = bw.get("days", 7)

    # Evaluation window: starts at baseline_end, runs for 24 hours
    eval_start = baseline_end
    try:
        end_dt = datetime.fromisoformat(baseline_end.replace("Z", "+00:00"))
        eval_start_dt = end_dt
        eval_end_dt = end_dt + timedelta(hours=24)
        eval_start = eval_start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        eval_end = eval_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        eval_end = ""

    # Build host inventory from all sources
    hosts = set()

    # From auth baseline (per_host keys)
    hosts.update(auth.get("per_host", {}).keys())

    # From process baseline (per_host keys)
    hosts.update(process.get("per_host", {}).keys())

    # From network baseline (per_host_destinations keys)
    hosts.update(network.get("per_host_destinations", {}).keys())

    # From file baseline (per_host_paths keys)
    hosts.update(file_base.get("per_host_paths", {}).keys())

    # From temporal profiles (parse source_type/canonical_label keys)
    for composite_key in temporal.get("profiles", {}).keys():
        parts = composite_key.split("/", 1)
        # Temporal profiles don't carry host info directly, but
        # the hosts are already covered by the other baselines

    host_inventory = sorted(hosts)

    # Derive thresholds with explanatory comments
    # Each threshold is derived from observations in the baseline data

    # Auth: max failures in 1h from a single src_ip during baseline
    max_1h_failures = auth.get("max_failures_1h_window", 0)
    # Anomaly threshold: 3x the observed max, or minimum 20 if baseline is very quiet
    failure_burst_threshold = max(max_1h_failures * 3, 20)

    # Auth: average failure rate per hour during business hours
    bh_failure_avg = auth.get("business_hours_avg", {}).get("failure_per_hour", 0)
    oh_failure_avg = auth.get("offhours_avg", {}).get("failure_per_hour", 0)
    # Anomaly: failure rate exceeds 3x the baseline average
    failure_rate_multiplier = 3

    # Process: rare processes are those seen on <1 host or <5 executions
    # Unknown process penalty: a process not in the baseline inventory for that host
    # gets a severity weight of 5 (arbitrary but consistent scoring for T10)
    unknown_process_penalty = 5

    # Network: unknown destination penalty
    # A dst_ip not in the baseline for that host
    unknown_destination_penalty = 4

    # Network: unknown port penalty
    # A dst_port not seen on that host during baseline
    unknown_port_penalty = 4

    # Network: external IP not in known_external_ips
    unknown_external_ip_penalty = 6

    # File: pathless Sysmon event volume anomaly
    # If unattributed event count for a host exceeds 2x the per-host average
    file_volume_multiplier = 2

    # Temporal: hour-of-day deviation factor
    # A day-8 hour count exceeding 3x the baseline mean for that hour
    temporal_deviation_multiplier = 3

    thresholds = {
        "failure_burst_threshold": {
            "value": failure_burst_threshold,
            "comment": f"3x the max 1h src_ip failures observed in baseline ({max_1h_failures}), floored at 20",
        },
        "failure_rate_multiplier": {
            "value": failure_rate_multiplier,
            "comment": "Day-8 failure rate must not exceed 3x the baseline hourly average for its time period",
        },
        "unknown_process_penalty": {
            "value": unknown_process_penalty,
            "comment": "Severity weight for a process not in the host's baseline inventory (rare processes had <5 executions or <2 hosts)",
        },
        "unknown_destination_penalty": {
            "value": unknown_destination_penalty,
            "comment": "Severity weight for a dst_ip not in the host's baseline destination set",
        },
        "unknown_port_penalty": {
            "value": unknown_port_penalty,
            "comment": "Severity weight for a dst_port not seen on that host during baseline",
        },
        "unknown_external_ip_penalty": {
            "value": unknown_external_ip_penalty,
            "comment": "Severity weight for an external IP not in known_external_ips from the baseline",
        },
        "file_volume_multiplier": {
            "value": file_volume_multiplier,
            "comment": "Unattributed file events per host must not exceed 2x the baseline per-host average",
        },
        "temporal_deviation_multiplier": {
            "value": temporal_deviation_multiplier,
            "comment": "Day-8 hourly count must not exceed 3x the baseline mean for that hour-of-day",
        },
    }

    # Build the summary
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    summary = {
        "version": "1.0",
        "generated_at": now_utc,
        "baseline_window": {
            "start": baseline_start,
            "end": baseline_end,
            "duration_days": baseline_days,
        },
        "evaluation_window": {
            "start": eval_start,
            "end": eval_end,
            "duration_hours": 24,
        },
        "host_inventory": host_inventory,
        "auth": auth,
        "process": process,
        "network": network,
        "file": file_base,
        "temporal": temporal,
        "thresholds": thresholds,
    }

    # Write output
    output_file = os.path.join(baseline_pkg, "baseline_summary.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Print summary
    sections = "auth, process, network, file, temporal, thresholds"
    print(f"version           : 1.0")
    print(f"baseline window   : {baseline_start} -> {baseline_end}  ({baseline_days} days)")
    print(f"evaluation window : {eval_start} -> {eval_end}  (24h)")
    print(f"hosts             : {len(host_inventory)}")
    print(f"sections included : {sections}")
    print("baseline_summary.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
