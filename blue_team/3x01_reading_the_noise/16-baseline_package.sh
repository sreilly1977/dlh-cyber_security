#!/bin/bash
#
# Name: 16-baseline_package.sh
# Purpose: Assemble the self-contained baseline_package/ directory with the
#          canonical subdirectory layout, MANIFEST.json (path, size, sha256),
#          and a final sanity check
# Author: Steve - Cybersecurity Engineer
# Date: 1 September 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export BASELINE_PKG

# Copy files of one category from src_dir into BASELINE_PKG/<category>/
copy_category() {
    local src_dir="$1"
    local category="$2"
    shift 2
    local dest_dir="${BASELINE_PKG}/${category}"
    mkdir -p "${dest_dir}"
    local count=0
    local fname
    for fname in "$@"; do
        if [[ ! -f "${src_dir}/${fname}" ]]; then
            echo "ERROR: missing source file: ${src_dir}/${fname}" >&2
            exit 1
        fi
        cp "${src_dir}/${fname}" "${dest_dir}/${fname}"
        count=$((count + 1))
    done
    printf 'copying %-11s ... %d files\n' "${category}" "${count}"
}

copy_category "${BASELINE_PKG}" baselines \
    baseline_auth.json baseline_process.json baseline_network.json \
    baseline_file.json temporal_profile.json baseline_summary.json

copy_category "${BASELINE_PKG}" anomalies \
    anomalies_auth.json anomalies_process.json anomalies_network.json \
    correlated_anomalies.json ranked_anomalies.json

copy_category "${BASELINE_PKG}" taxonomy \
    event_taxonomy.json labeled_events.json

copy_category "${BASELINE_PKG}" reports \
    format_analysis.json field_index.json baseline_validation.json

copy_category "${SCRIPTS_DIR}" toolkit \
    2-query_toolkit.sh 4-baseline_auth.sh 5-baseline_process.sh \
    6-baseline_network.sh 7-baseline_file.sh 8-temporal_profile.sh \
    9-baseline_summary.sh 10-anomalies_auth.sh 11-anomalies_process.sh \
    12-anomalies_network.sh 13-correlate_anomalies.sh 14-rank_anomalies.sh \
    15-baseline_validation.sh

python3 -W error - << 'PYEOF'
import hashlib
import json
import os

root = os.environ["BASELINE_PKG"]
CATEGORIES = ("baselines", "anomalies", "taxonomy", "reports", "toolkit")
EXPECTED_TOTAL = 29

entries = []
for cat in CATEGORIES:
    cat_dir = os.path.join(root, cat)
    for name in sorted(os.listdir(cat_dir)):
        full = os.path.join(cat_dir, name)
        if not os.path.isfile(full):
            continue
        h = hashlib.sha256()
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        entries.append({
            "path": f"{cat}/{name}",
            "size": os.path.getsize(full),
            "sha256": h.hexdigest(),
        })

manifest = {
    "generated_by": "16-baseline_package.sh",
    "file_count": len(entries),
    "files": entries,
}

manifest_path = os.path.join(root, "MANIFEST.json")
with open(manifest_path, "w") as mf:
    json.dump(manifest, mf, indent=2)

errors = []
if len(entries) != EXPECTED_TOTAL:
    errors.append(f"expected {EXPECTED_TOTAL} files, found {len(entries)}")
for ent in entries:
    full = os.path.join(root, ent["path"])
    if not os.path.isfile(full) or os.path.getsize(full) == 0:
        errors.append(f"missing or empty: {ent['path']}")

if errors:
    for err in errors:
        print("SANITY FAIL:", err)
    print(f"MANIFEST.json       : {len(entries)} entries")
    print("sanity check        : failed")
    raise SystemExit(1)

print(f"MANIFEST.json       : {len(entries)} entries")
print("sanity check        : ok")
print("baseline_package/ ready")
PYEOF

exit 0
