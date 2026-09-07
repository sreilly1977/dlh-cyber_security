#!/bin/bash
#
# Name: 16-detection_catalog.sh
# Purpose: Assemble the locked-layout detection_catalog/ deliverable: rules,
#          metrics, coverage, alerts, runtime scripts, and spec, plus a
#          sha256 MANIFEST.json with existence/non-empty verification.
# Author: Steve - Cybersecurity Engineer
# Date: 2026/09/07
#
# Inputs (all overridable via env):
#   $CATALOG_DIR     - output directory (default ~/3x02_package/detection_catalog)
#   $SIGMA_DIR       - base Sigma rules (default ~/3x02_scripts/rules/sigma)
#   $TUNED_SRC       - tuned variants (default $SIGMA_DIR/tuned)
#   $PKG_DIR         - metrics/coverage/alerts package dir (default ~/3x02_package)
#   $SCRIPTS_DIR     - runtime scripts (default ~/3x02_scripts)
#   $DETECTION_MATRIX- detection_matrix.json path (default $PKG_DIR/detection_matrix.json)
#   $SPEC_MD         - detection_spec.md from T17 (default $SCRIPTS_DIR/detection_spec.md)
# Output:
#   $CATALOG_DIR with locked layout + MANIFEST.json
#
# Deviations (documented):
#   1. spec/detection_spec.md is produced by T17; until it exists the script
#      warns (graceful), creates an empty spec/ directory, and excludes it
#      from the manifest. Rerun after T17 to include it.
#   2. Required files that are missing or empty cause immediate loud failure.
#   3. MANIFEST.json contains no timestamps (deterministic; reruns are
#      byte-identical, suitable for diff-based verification).

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
SIGMA_DIR="${SIGMA_DIR:-$HOME/3x02_scripts/rules/sigma}"
TUNED_SRC="${TUNED_SRC:-$SIGMA_DIR/tuned}"
PKG_DIR="${PKG_DIR:-$HOME/3x02_package}"
SCRIPTS_DIR="${SCRIPTS_DIR:-$HOME/3x02_scripts}"
DETECTION_MATRIX="${DETECTION_MATRIX:-$PKG_DIR/detection_matrix.json}"
SPEC_MD="${SPEC_MD:-$SCRIPTS_DIR/detection_spec.md}"
export CATALOG_DIR

# --- Required file check (loud failure) ------------------------------------
require_file() {
    local f="$1"
    if [[ ! -s "$f" ]]; then
        echo "error: required file missing or empty: $f" >&2
        echo "       (set the corresponding env var if it lives elsewhere)" >&2
        exit 1
    fi
}

declare -a RULE_FILES=(
    001_ssh_brute_force.yml
    002_windows_offhours_privileged_logon.yml
    003_interpreter_abuse.yml
    004_recon_tool_execution.yml
    005_scheduled_task_creation.yml
    006_registry_autorun_modify.yml
    007_unknown_outbound_destination.yml
    008_uncommon_port_outbound.yml
    009_lateral_movement_smb.yml
    010_credential_theft_chain.yml
    011_patient_data_access.yml
    012_medical_segment_egress.yml
    013_privileged_account_shift_violation.yml
)
for f in "${RULE_FILES[@]}"; do
    require_file "$SIGMA_DIR/$f"
done

declare -a METRIC_FILES=(
    detection_matrix.json
    fp_baseline.json
    tuning_report.json
    rule_quality.json
)
for f in "${METRIC_FILES[@]}"; do
    case "$f" in
        detection_matrix.json) require_file "$DETECTION_MATRIX" ;;
        *)                      require_file "$PKG_DIR/$f" ;;
    esac
done

declare -a COVERAGE_FILES=(attack_coverage.json rule_prioritization.json)
for f in "${COVERAGE_FILES[@]}"; do
    require_file "$PKG_DIR/$f"
done

declare -a ALERT_FILES=(alert_queue.json alert_queue_schema.json)
for f in "${ALERT_FILES[@]}"; do
    require_file "$PKG_DIR/$f"
done

declare -a RUNTIME_FILES=(
    3-sigma_runner.sh
    8-correlation_primitives.py
    10-fp_baseline.sh
    11-tune_rules.sh
    12-attack_coverage.sh
    13-rule_quality.sh
    14-rule_prioritization.sh
    15-generate_alerts.sh
)
for f in "${RUNTIME_FILES[@]}"; do
    require_file "$SCRIPTS_DIR/$f"
done

# Tuned variants: at least the directory must exist; zero variants allowed.
if [[ ! -d "$TUNED_SRC" ]]; then
    echo "error: tuned rules directory not found: $TUNED_SRC" >&2
    exit 1
fi

# --- Clean rebuild (idempotent) ---------------------------------------------
rm -rf "$CATALOG_DIR"
mkdir -p "$CATALOG_DIR"/{rules/sigma,rules/tuned,metrics,coverage,alerts,runtime,spec}

cp -- "$SIGMA_DIR"/*.yml "$CATALOG_DIR/rules/sigma/"
n_sigma=$(find "$CATALOG_DIR/rules/sigma" -maxdepth 1 -name '*.yml' | wc -l)
echo "copying rules/sigma   ... $n_sigma files"

cp -- "$TUNED_SRC"/*.yml "$CATALOG_DIR/rules/tuned/"
n_tuned=$(find "$CATALOG_DIR/rules/tuned" -maxdepth 1 -name '*.yml' | wc -l)
echo "copying rules/tuned   ... $n_tuned files"

cp -- "$DETECTION_MATRIX" "$PKG_DIR/fp_baseline.json" \
   "$PKG_DIR/tuning_report.json" "$PKG_DIR/rule_quality.json" \
   "$CATALOG_DIR/metrics/"
n_metrics=$(find "$CATALOG_DIR/metrics" -type f | wc -l)
echo "copying metrics       ... $n_metrics files"

cp -- "$PKG_DIR/attack_coverage.json" "$PKG_DIR/rule_prioritization.json" \
   "$CATALOG_DIR/coverage/"
n_cov=$(find "$CATALOG_DIR/coverage" -type f | wc -l)
echo "copying coverage      ... $n_cov files"

cp -- "$PKG_DIR/alert_queue.json" "$PKG_DIR/alert_queue_schema.json" \
   "$CATALOG_DIR/alerts/"
n_alerts=$(find "$CATALOG_DIR/alerts" -type f | wc -l)
echo "copying alerts        ... $n_alerts files"

for f in "${RUNTIME_FILES[@]}"; do
    cp -- "$SCRIPTS_DIR/$f" "$CATALOG_DIR/runtime/$f"
done
n_runtime=$(find "$CATALOG_DIR/runtime" -type f | wc -l)
echo "copying runtime       ... $n_runtime files"

if [[ -s "$SPEC_MD" ]]; then
    cp -- "$SPEC_MD" "$CATALOG_DIR/spec/detection_spec.md"
    n_spec=1
else
    echo "warning: T17 spec not found at $SPEC_MD; spec/ left empty (rerun after T17)" >&2
    n_spec=0
fi
echo "copying spec          ... $n_spec files"

# --- MANIFEST generation + sanity check --------------------------------------
python3 -W error - <<'PYEOF'
import hashlib
import json
import os
import sys

catalog = os.environ["CATALOG_DIR"]
manifest_path = os.path.join(catalog, "MANIFEST.json")

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

entries = []
for root, dirs, files in os.walk(catalog):
    dirs.sort()
    for fname in sorted(files):
        full = os.path.join(root, fname)
        rel = os.path.relpath(full, catalog)
        if rel == "MANIFEST.json":
            continue
        size = os.path.getsize(full)
        if size == 0:
            sys.stderr.write("error: empty file in catalog: %s\n" % rel)
            sys.exit(1)
        entries.append({
            "path": rel,
            "size": size,
            "sha256": sha256_file(full),
        })

manifest = {
    "generator": "16-detection_catalog.sh",
    "entry_count": len(entries),
    "entries": entries,
}
with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")

# Sanity check: every manifest entry exists, matches size and hash.
with open(manifest_path, encoding="utf-8") as fh:
    check = json.load(fh)
for e in check["entries"]:
    full = os.path.join(catalog, e["path"])
    if not os.path.isfile(full):
        sys.stderr.write("error: manifest entry missing on disk: %s\n" % e["path"])
        sys.exit(1)
    if os.path.getsize(full) != e["size"]:
        sys.stderr.write("error: size mismatch: %s\n" % e["path"])
        sys.exit(1)
    if sha256_file(full) != e["sha256"]:
        sys.stderr.write("error: sha256 mismatch: %s\n" % e["path"])
        sys.exit(1)

print("MANIFEST.json         : %d entries" % len(entries))
print("sanity check          : ok")
print("detection_catalog/ ready")
PYEOF
