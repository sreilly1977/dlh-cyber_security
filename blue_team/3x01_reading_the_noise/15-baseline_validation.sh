#!/bin/bash
#
# Name: 15-baseline_validation.sh
# Purpose: Backtest the baseline by running the anomaly scripts (T10-T12) over
#          the baseline window itself and over the evaluation window, then
#          compute signal-to-noise and a pass/fail verdict
# Author: Steve - Cybersecurity Engineer
# Date: 1 September 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SELF_CHECK_MAX="${SELF_CHECK_MAX:-5}"
SNR_MIN="${SNR_MIN:-3.0}"

SUMMARY_FILE="${BASELINE_PKG}/baseline_summary.json"
EVENTS_FILE="${BASELINE_PKG}/labeled_events.json"

for f in "${SUMMARY_FILE}" "${EVENTS_FILE}" \
         "${SCRIPTS_DIR}/10-anomalies_auth.sh" \
         "${SCRIPTS_DIR}/11-anomalies_process.sh" \
         "${SCRIPTS_DIR}/12-anomalies_network.sh"; do
    if [[ ! -e "${f}" ]]; then
        echo "ERROR: Required input not found: ${f}" >&2
        exit 1
    fi
done

TMP_SELF="$(mktemp -d)"
TMP_LIVE="$(mktemp -d)"
trap 'rm -rf "${TMP_SELF}" "${TMP_LIVE}"' EXIT

export BASELINE_PKG SCRIPTS_DIR TMP_SELF TMP_LIVE SELF_CHECK_MAX SNR_MIN

# --- Prepare a run directory: real summary, events symlink ---
prepare_run_dir() {
    local run_dir="$1"
    cp "${SUMMARY_FILE}" "${run_dir}/baseline_summary.json"
    ln -s "${EVENTS_FILE}" "${run_dir}/labeled_events.json"
}

# --- Rewrite evaluation window to equal baseline window (self-check) ---
make_self_summary() {
    python3 - "$1" << 'MODEOF'
import json
import sys

path = sys.argv[1]
with open(path) as f:
    summary = json.load(f)
summary["evaluation_window"] = json.loads(json.dumps(
    summary["baseline_window"]))
with open(path, "w") as f:
    json.dump(summary, f, indent=2)
MODEOF
}

# --- Run the three anomaly scripts against a prepared run dir ---
run_suite() {
    local run_dir="$1"
    (cd "${SCRIPTS_DIR}" \
        && BASELINE_PKG="${run_dir}" ./10-anomalies_auth.sh > /dev/null \
        && BASELINE_PKG="${run_dir}" ./11-anomalies_process.sh > /dev/null \
        && BASELINE_PKG="${run_dir}" ./12-anomalies_network.sh > /dev/null)
    for src in auth process network; do
        if [[ -f "${run_dir}/anomalies_${src}.json" ]]; then
            cp "${run_dir}/anomalies_${src}.json" \
               "${BASELINE_PKG}/self_check_${src}.json"
        fi
    done
}

# --- Run the full anomaly suite in both configurations ---

# Run 1 (self-check): evaluation window rewritten to the baseline window
prepare_run_dir "${TMP_SELF}"
make_self_summary "${TMP_SELF}/baseline_summary.json"

# Run 2 (live): unmodified summary, normal evaluation window
prepare_run_dir "${TMP_LIVE}"

for run_dir in "${TMP_SELF}" "${TMP_LIVE}"; do
    (
        cd "${SCRIPTS_DIR}"
        BASELINE_PKG="${run_dir}" ./10-anomalies_auth.sh > /dev/null
        BASELINE_PKG="${run_dir}" ./11-anomalies_process.sh > /dev/null
        BASELINE_PKG="${run_dir}" ./12-anomalies_network.sh > /dev/null
    )
done

# --- Capture outputs into the package ---
for src in auth process network; do
    cp "${TMP_SELF}/anomalies_${src}.json" \
       "${BASELINE_PKG}/self_check_${src}.json"
    cp "${TMP_LIVE}/anomalies_${src}.json" \
       "${BASELINE_PKG}/live_check_${src}.json"
done

python3 -W error - << 'PYEOF'
import json
import os

# Verdict rule:
#   pass if self_check_total <= SELF_CHECK_MAX (default 5, i.e. "at most 5")
#   AND signal_to_noise_ratio >= SNR_MIN (default 3.0)
SELF_CHECK_MAX = int(os.environ["SELF_CHECK_MAX"])
SNR_MIN = float(os.environ["SNR_MIN"])
PKG = os.environ["BASELINE_PKG"]

def load_run(prefix):
    total = 0
    by_type = {}
    for src in ("auth", "process", "network"):
        path = os.path.join(PKG, f"{prefix}_{src}.json")
        with open(path) as f:
            data = json.load(f)
        n = int(data.get("total_anomalies", 0))
        total += n
        for an in data.get("anomalies", []):
            t = an.get("anomaly_type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1
    return total, by_type

self_total, self_by_type = load_run("self_check")
live_total, live_by_type = load_run("live_check")

snr = live_total / max(self_total, 1)
passed = (self_total <= SELF_CHECK_MAX) and (snr >= SNR_MIN)
verdict = "pass" if passed else "fail"

out = {
    "self_check_total": self_total,
    "live_check_total": live_total,
    "signal_to_noise_ratio": round(snr, 3),
    "per_type": {
        "self_check": self_by_type,
        "live_check": live_by_type,
    },
    "thresholds": {
        "self_check_max": SELF_CHECK_MAX,
        "snr_min": SNR_MIN,
    },
    "verdict": verdict,
}

out_path = os.path.join(PKG, "baseline_validation.json")
with open(out_path, "w") as f:
    json.dump(out, f, indent=2)

print(f"self-check anomalies (baseline window): {self_total}")
print(f"live-check anomalies (evaluation win ): {live_total}")
print(f"signal-to-noise ratio                : {snr:.2f}")
print(f"verdict                              : {verdict}")
print("baseline_validation.json written")

raise SystemExit(0 if passed else 1)
PYEOF

exit 0
