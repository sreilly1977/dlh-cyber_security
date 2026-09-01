#!/bin/bash
#
# Name: 11-anomalies_process.sh
# Purpose: Detect process execution anomalies in the evaluation window against per-host baseline
# Author: Steve - Cybersecurity Engineer
# Date: 1 September 2026
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

PROCESS_LABELS = ("process_start",)

# Watchlist: interpreters and tooling with a reputation for misuse
HIGH_RISK_WATCHLIST = {
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "nc", "ncat", "netcat", "nmap", "wget", "curl",
    "python", "python3", "bash",
}

# --- Severity rubric (declared at top per task instructions) ---
SEV_UNKNOWN_PROCESS = "low"     # novel process on a host, no misuse reputation
SEV_UNKNOWN_PAIR = "low"        # novel parent-child lineage only
SEV_RARE_SPIKE = "medium"       # rare baseline process, busy in eval window
SEV_RARE_SPIKE_SEVERE = "high"  # spike exceeds 50 eval-window runs
SEV_HIGH_RISK = "high"          # watchlisted tooling on a new host

SPIKE_SEVERE_AT = 50  # eval-window run count that escalates a rare spike
SPIKE_EVAL_MIN = 10   # eval-window runs needed for a rare-process spike

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def base_name(path):
    """Strip path components and lowercase: C:\\Windows\\cmd.exe -> cmd.exe"""
    if not path:
        return ""
    return str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()

def main():
    with open(os.environ["BASELINE_SUMMARY"]) as f:
        summary = json.load(f)

    base_end = datetime.fromisoformat(
        summary["baseline_window"]["end"].replace("Z", "+00:00"))
    eval_start = datetime.fromisoformat(
        summary["evaluation_window"]["start"].replace("Z", "+00:00"))
    eval_end = datetime.fromisoformat(
        summary["evaluation_window"]["end"].replace("Z", "+00:00"))

    # --- Pass 1: baseline per-host process facts ---
    host_procs = defaultdict(set)                # host -> {proc}
    host_pairs = defaultdict(set)                # host -> {(parent, proc)}
    host_proc_counts = defaultdict(lambda: defaultdict(int))

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
            if ev.get("canonical_label") not in PROCESS_LABELS:
                continue
            proc = base_name(ev.get("process_name"))
            if not proc:
                continue
            host = ev.get("hostname") or "unknown"
            host_procs[host].add(proc)
            host_proc_counts[host][proc] += 1
            parent = base_name(ev.get("parent_process_name"))
            if parent:
                host_pairs[host].add((parent, proc))

    # --- Evaluation window scan ---
    counts = defaultdict(int)
    anomalies = []

    unk = {}        # (host, proc) -> entry
    risk = {}       # (host, proc) -> entry (watchlist subset of unknown)
    unk_pair = {}   # (host, parent, proc) -> entry
    rare_eval = defaultdict(lambda: defaultdict(list))  # host -> proc -> runs

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
            if ev.get("canonical_label") not in PROCESS_LABELS:
                continue
            proc = base_name(ev.get("process_name"))
            if not proc:
                continue
            host = ev.get("hostname") or "unknown"
            user = ev.get("user") or ""
            parent = base_name(ev.get("parent_process_name"))
            ref = ev.get("record_id") or ""

            known_here = proc in host_procs.get(host, ())

            # 1 & 4: unknown process on host (+ watchlist subset)
            if not known_here:
                ent = unk.setdefault((host, proc),
                                     {"ts": ts, "user": user, "refs": [], "n": 0})
                ent["n"] += 1
                if not ent["user"] and user:
                    ent["user"] = user
                if ref and len(ent["refs"]) < 20:
                    ent["refs"].append(ref)

                if proc in HIGH_RISK_WATCHLIST:
                    rent = risk.setdefault((host, proc),
                                           {"ts": ts, "user": user, "refs": [], "n": 0})
                    rent["n"] += 1
                    if not rent["user"] and user:
                        rent["user"] = user
                    if ref and len(rent["refs"]) < 20:
                        rent["refs"].append(ref)

            # 2: unknown parent-child pair on host
            if parent and (parent, proc) not in host_pairs.get(host, ()):
                pent = unk_pair.setdefault((host, parent, proc),
                                           {"ts": ts, "user": user, "refs": [], "n": 0})
                pent["n"] += 1
                if not pent["user"] and user:
                    pent["user"] = user
                if ref and len(pent["refs"]) < 20:
                    pent["refs"].append(ref)

            # 3: rare process buffering (1-4 baseline runs on this host)
            bc = host_proc_counts.get(host, {}).get(proc, 0)
            if 0 < bc < 5:
                rare_eval[host][proc].append((ts, ref, user))

    # --- Emit: unknown_process_for_host ---
    for (host, proc), ent in sorted(unk.items()):
        counts["unknown_process_for_host"] += 1
        anomalies.append({
            "timestamp": iso(ent["ts"]), "host": host,
            "user": ent["user"] or "(unattributed)",
            "process_name": proc, "parent_process_name": "",
            "anomaly_type": "unknown_process_for_host",
            "severity": SEV_UNKNOWN_PROCESS,
            "observed_value": ent["n"], "baseline_value": 0,
            "event_refs": ent["refs"],
        })

    # --- Emit: high_risk_process ---
    for (host, proc), ent in sorted(risk.items()):
        counts["high_risk_process"] += 1
        anomalies.append({
            "timestamp": iso(ent["ts"]), "host": host,
            "user": ent["user"] or "(unattributed)",
            "process_name": proc, "parent_process_name": "",
            "anomaly_type": "high_risk_process",
            "severity": SEV_HIGH_RISK,
            "observed_value": ent["n"], "baseline_value": 0,
            "event_refs": ent["refs"],
        })

    # --- Emit: unknown_parent_child ---
    for (host, parent, proc), ent in sorted(unk_pair.items()):
        counts["unknown_parent_child"] += 1
        anomalies.append({
            "timestamp": iso(ent["ts"]), "host": host,
            "user": ent["user"] or "(unattributed)",
            "process_name": proc, "parent_process_name": parent,
            "anomaly_type": "unknown_parent_child",
            "severity": SEV_UNKNOWN_PAIR,
            "observed_value": ent["n"], "baseline_value": 0,
            "event_refs": ent["refs"],
        })

    # --- Emit: rare_process_spike ---
    for host, procs in sorted(rare_eval.items()):
        for proc, runs in sorted(procs.items()):
            n = len(runs)
            if n <= SPIKE_EVAL_MIN:
                continue
            runs.sort(key=lambda r: r[0])
            counts["rare_process_spike"] += 1
            anomalies.append({
                "timestamp": iso(runs[0][0]), "host": host,
                "user": next((u for _, _, u in runs if u), "(unattributed)"),
                "process_name": proc, "parent_process_name": "",
                "anomaly_type": "rare_process_spike",
                "severity": SEV_RARE_SPIKE_SEVERE if n > SPIKE_SEVERE_AT
                            else SEV_RARE_SPIKE,
                "observed_value": n,
                "observed_value_detail":
                    f"{n} eval-window runs; ran 1-4 times in baseline",
                "event_refs": [r[1] for r in runs if r[1]][:20],
            })

    anomalies.sort(key=lambda a: a["timestamp"])

    out_path = os.path.join(os.environ["BASELINE_PKG"], "anomalies_process.json")
    with open(out_path, "w") as f:
        json.dump({
            "evaluation_window": {"start": iso(eval_start), "end": iso(eval_end)},
            "total_anomalies": len(anomalies),
            "anomalies": anomalies,
        }, f, indent=2)

    print(f"evaluation window : {iso(eval_start)} -> {iso(eval_end)}")
    print(f"unknown_process_for_host : {counts['unknown_process_for_host']}")
    print(f"unknown_parent_child     : {counts['unknown_parent_child']}")
    print(f"rare_process_spike       : {counts['rare_process_spike']}")
    print(f"high_risk_process        : {counts['high_risk_process']}")
    print(f"total anomalies          : {len(anomalies)}")
    print("anomalies_process.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
