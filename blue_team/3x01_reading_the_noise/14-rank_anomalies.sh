#!/bin/bash
#
# Name: 14-rank_anomalies.sh
# Purpose: Rank all single-source and correlated anomalies by a deterministic
#          composite priority score for the analyst queue
# Author: Steve - Cybersecurity Engineer
# Date: 1 September 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

AUTH_FILE="${BASELINE_PKG}/anomalies_auth.json"
PROCESS_FILE="${BASELINE_PKG}/anomalies_process.json"
NETWORK_FILE="${BASELINE_PKG}/anomalies_network.json"
CORR_FILE="${BASELINE_PKG}/correlated_anomalies.json"
ASSET_FILE="${HANDOFF_DIR}/context/asset_inventory.json"

for f in "${AUTH_FILE}" "${PROCESS_FILE}" "${NETWORK_FILE}" \
         "${CORR_FILE}" "${ASSET_FILE}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: Required input not found: ${f}" >&2
        exit 1
    fi
done

export AUTH_FILE PROCESS_FILE NETWORK_FILE CORR_FILE ASSET_FILE BASELINE_PKG

python3 -W error - << 'PYEOF'
import json
import os
from datetime import datetime

# --- Priority rubric (documented for auditability) ---
# priority_score =
#   severity base (low=1, medium=3, high=5, critical=8)
#   x asset criticality multiplier (low=1, medium=2, high=3, critical=4)
#   + correlation bonus (+2 per additional source beyond the first)
#   + off-hours bonus (+1 outside Mon-Fri 08:00-18:00 UTC)
#   + high-risk category bonus (+2 for high_risk_process,
#       privilege_escalation_surge, external_destination_new)

SEVERITY_VALUE = {"low": 1, "medium": 3, "high": 5, "critical": 8}
CRITICALITY_MULTIPLIER = {
    "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}
HIGH_RISK_TYPES = {"high_risk_process", "privilege_escalation_surge",
                   "external_destination_new"}

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def is_off_hours(dt):
    """Off-hours = before 08:00 or after 18:00, or Saturday/Sunday (UTC)."""
    if dt.weekday() >= 5:
        return True
    return dt.hour < 8 or dt.hour >= 18

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
    crit = load_asset_criticality(os.environ["ASSET_FILE"])
    ranked = []

    # --- Single-source anomalies ---
    for source in ("auth", "process", "network"):
        path = os.path.join(os.environ["BASELINE_PKG"],
                            f"anomalies_{source}.json")
        with open(path) as f:
            data = json.load(f)
        for an in data.get("anomalies", []):
            ts = parse_ts(an.get("timestamp"))
            if ts is None:
                continue
            host = an.get("host") or "unknown"
            severity = str(an.get("severity", "low")).lower()
            sev_val = SEVERITY_VALUE.get(severity, 1)
            crit_mult = CRITICALITY_MULTIPLIER.get(
                crit.get(host, "LOW"), 1)
            corr_bonus = 0  # single source: no additional sources
            off_hours_val = 1 if is_off_hours(ts) else 0
            risk_type = an.get("anomaly_type") or ""
            risk_val = 2 if risk_type in HIGH_RISK_TYPES else 0
            score = sev_val * crit_mult + corr_bonus + off_hours_val + risk_val

            breakdown = {
                "base_severity": sev_val,
                "asset_criticality": crit.get(host, "UNKNOWN"),
                "criticality_multiplier": crit_mult,
                "correlation_bonus": corr_bonus,
                "off_hours_bonus": off_hours_val,
                "high_risk_category_bonus": risk_val,
                "priority_score": score,
            }
            entry = dict(an)
            entry["item_kind"] = "single"
            entry["source"] = source
            entry["priority_score"] = score
            entry["score_breakdown"] = breakdown
            ranked.append(entry)

    # --- Correlated findings ---
    corr_path = os.path.join(os.environ["BASELINE_PKG"],
                             "correlated_anomalies.json")
    with open(corr_path) as f:
        corr = json.load(f)
    for cf in corr.get("findings", []):
        hosts = cf.get("hosts", []) or [cf.get("host", "unknown")]
        members = cf.get("members", [])
        sev_names = [str(m.get("severity", "low")).lower()
                     for m in members]
        severity = max(sev_names,
                       key=lambda s: SEVERITY_VALUE.get(s, 1)) \
            if sev_names else "low"
        sev_val = SEVERITY_VALUE.get(severity, 1)
        crit_mult = max({"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                        .get(crit.get(h, "LOW"), 1) for h in hosts)
        n_sources = len(cf.get("sources_involved", []))
        corr_bonus = 2 * max(0, n_sources - 1)
        ts = parse_ts(cf.get("window_start"))
        off_hours_val = 1 if (ts and is_off_hours(ts)) else 0
        types = cf.get("anomaly_types", [])
        risk_val = 2 if any(t in HIGH_RISK_TYPES for t in types) else 0
        score = sev_val * crit_mult + corr_bonus + off_hours_val + risk_val

        breakdown = {
            "base_severity": sev_val,
            "asset_criticality_multiplier": crit_mult,
            "correlation_bonus": corr_bonus,
            "off_hours_bonus": off_hours_val,
            "high_risk_category_bonus": risk_val,
            "priority_score": score,
        }
        entry = dict(cf)
        entry["item_kind"] = "correlated"
        entry["priority_score"] = score
        entry["score_breakdown"] = breakdown
        ranked.append(entry)

    ranked.sort(key=lambda r: (-r["priority_score"],
                               r.get("timestamp", ""),
                               str(r.get("host", ""))))

    out_path = os.path.join(os.environ["BASELINE_PKG"],
                            "ranked_anomalies.json")
    with open(out_path, "w") as f:
        json.dump({"total": len(ranked), "ranked_anomalies": ranked},
                  f, indent=2)

    print(f"ranked anomalies total : {len(ranked)}")
    print("top 5:")
    for i, r in enumerate(ranked[:5], 1):
        atype = r.get("anomaly_type") or ",".join(
            r.get("anomaly_types", [])) or "unknown"
        print(f" {i}  score {r['priority_score']}  "
              f"{r.get('host', 'unknown'):16s}  {atype}")
    print("ranked_anomalies.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
