#!/bin/bash
#
# Name: 13-correlate_anomalies.sh
# Purpose: Correlate single-source anomalies (auth, process, network) sharing a
#          host and/or anomaly type within a time window into higher-confidence
#          multi-source findings for triage consumption (3x03)
# Author: Steve - Cybersecurity Engineer
# Date: 1 September 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CORRELATION_WINDOW_SECS="${CORRELATION_WINDOW_SECS:-300}"

AUTH_FILE="${BASELINE_PKG}/anomalies_auth.json"
PROCESS_FILE="${BASELINE_PKG}/anomalies_process.json"
NETWORK_FILE="${BASELINE_PKG}/anomalies_network.json"
ASSET_FILE="${HANDOFF_DIR}/context/asset_inventory.json"

for f in "${AUTH_FILE}" "${PROCESS_FILE}" "${NETWORK_FILE}" "${ASSET_FILE}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: Required input not found: ${f}" >&2
        exit 1
    fi
done

export AUTH_FILE PROCESS_FILE NETWORK_FILE ASSET_FILE CORRELATION_WINDOW_SECS BASELINE_PKG

python3 -W error - << 'PYEOF'
import hashlib
import json
import os
from datetime import datetime

# --- Scoring rubric (documented for auditability) ---
# score = (1 per involved source) + (2 per distinct anomaly type),
# multiplied by asset criticality multiplier:
#   CRITICAL/HIGH -> 2, MEDIUM/LOW/unknown -> 1
CRITICALITY_MULTIPLIER = {
    "CRITICAL": 2, "HIGH": 2, "MEDIUM": 1, "LOW": 1,
}
TYPE_BONUS = 2

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def load_asset_criticality(path):
    crit = {}
    if os.path.exists(path):
        with open(path) as f:
            inv = json.load(f)
        for asset in inv.get("assets", []):
            host = asset.get("hostname")
            if host:
                crit[host] = str(asset.get("criticality", "LOW")).upper()
    return crit

def main():
    window = int(os.environ["CORRELATION_WINDOW_SECS"])
    if window < 1:
        raise SystemExit("ERROR: CORRELATION_WINDOW_SECS must be >= 1")

    crit = load_asset_criticality(os.environ["ASSET_FILE"])

    # --- Load all single-source anomalies, tagged with their source ---
    items = []
    for source, path in (("auth", os.environ["AUTH_FILE"]),
                         ("process", os.environ["PROCESS_FILE"]),
                         ("network", os.environ["NETWORK_FILE"])):
        with open(path) as f:
            data = json.load(f)
        for idx, an in enumerate(data.get("anomalies", [])):
            ts = parse_ts(an.get("timestamp"))
            if ts is None:
                continue
            items.append({
                "source": source,
                "ref": f"{source}:{idx}",
                "ts": ts,
                "host": an.get("host") or "unknown",
                "anomaly_type": an.get("anomaly_type") or "unknown",
                "entry": an,
            })

    n_single = len(items)

    # --- Union-find ---
    parent = list(range(len(items)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # Rule A: same host, timestamps within window (chaining allowed)
    items.sort(key=lambda it: it["ts"])
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            delta = (items[j]["ts"] - items[i]["ts"]).total_seconds()
            if delta > window:
                break
            if items[i]["host"] == items[j]["host"]:
                union(i, j)

    # Rule B: same anomaly_type across different hosts, within window.
    # Pairwise within the sliding window; n is small (tens), so O(n*w) is fine.
    n = len(items)
    for i in range(n):
        for j in range(i + 1, n):
            if (items[j]["ts"] - items[i]["ts"]).total_seconds() > window:
                break
            if items[i]["anomaly_type"] == items[j]["anomaly_type"]:
                union(i, j)

    groups = {}
    for i, item in enumerate(items):
        groups.setdefault(find(i), []).append(item)

    # --- Emit findings for groups with 2+ members ---
    findings = []
    multi_host_count = 0
    max_score = 0
    for members in groups.values():
        if len(members) < 2:
            continue
        hosts = sorted({m["host"] for m in members})
        sources = sorted({m["source"] for m in members})
        types = sorted({m["anomaly_type"] for m in members})
        refs = sorted(m["ref"] for m in members)
        ts_min = min(m["ts"] for m in members)
        ts_max = max(m["ts"] for m in members)

        base = len(set(m["source"] for m in members))
        base += TYPE_BONUS * len({m["anomaly_type"] for m in members})
        mult = max(CRITICALITY_MULTIPLIER.get(crit.get(h, "LOW"), 1)
                   for h in hosts)

        corr_id = hashlib.sha256("|".join(refs).encode()).hexdigest()[:12]

        findings.append({
            "correlation_id": corr_id,
            "host": hosts[0] if len(hosts) == 1 else ",".join(hosts),
            "hosts": hosts,
            "window_start": ts_min.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_end": ts_max.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "sources_involved": sorted(set(m["source"] for m in members)),
            "anomaly_types": sorted(set(m["anomaly_type"] for m in members)),
            "member_refs": refs,
            "members": [m["entry"] for m in members],
            "score": base * mult,
        })

    findings.sort(key=lambda f: f["window_start"])
    multi_host_count = sum(1 for f in findings if len(f["hosts"]) > 1)
    max_score = max((f["score"] for f in findings), default=0)

    out_path = os.path.join(os.environ["BASELINE_PKG"],
                            "correlated_anomalies.json")
    with open(out_path, "w") as f:
        json.dump({
            "correlation_window_secs": window,
            "single_source_anomalies": n_single,
            "total_correlated_findings": len(findings),
            "findings": findings,
        }, f, indent=2)

    print(f"single-source anomalies  : {n_single}")
    print(f"correlated findings      : {len(findings)}")
    print(f"multi-host findings      : {multi_host_count}")
    print(f"max score                : {max_score}")
    print("correlated_anomalies.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
