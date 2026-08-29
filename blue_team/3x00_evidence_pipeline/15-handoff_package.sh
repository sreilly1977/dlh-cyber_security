#!/bin/bash
#
# Name: 15-handoff_package.sh
# Purpose: Assemble complete evidence handoff directory for downstream Module 3 projects
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -uo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-${HOME}/3x00_handoff/evidence_handoff}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Locate context files ----------------------------------------------------
# Check working dir first, then evidence pack context directories

ASSET_INVENTORY=""
NETWORK_ZONES=""

for search_dir in "$SCRIPT_DIR" "$HOME/evidence_pack_primary/context" "$HOME/evidence_pack_secondary/context"; do
    if [[ -z "$ASSET_INVENTORY" ]] && [[ -f "${search_dir}/asset_inventory.json" ]]; then
        ASSET_INVENTORY="${search_dir}/asset_inventory.json"
    fi
    if [[ -z "$NETWORK_ZONES" ]] && [[ -f "${search_dir}/network_zones.json" ]]; then
        NETWORK_ZONES="${search_dir}/network_zones.json"
    fi
done

MISSING=()

[[ -z "$ASSET_INVENTORY" ]] && MISSING+=("asset_inventory.json")
[[ -z "$NETWORK_ZONES" ]] && MISSING+=("network_zones.json")

# Check all other required files exist in SCRIPT_DIR
REQUIRED_DATA=("normalized_events.json" "enriched_events.json" "timeline_index.json" "network_events.json" "quarantine.json")
REQUIRED_REPORTS=("source_inventory.json" "validation_report.json" "cleaning_log.json" "source_stats.json" "pipeline_test_report.json")
REQUIRED_SCHEMA=("event_schema.json")
REQUIRED_PIPELINE=("evidence_pipeline.sh" "0-source_inventory.sh" "1-telemetry_import.sh" "2-windows_parse.sh" "3-linux_parse.sh" "5-normalize.sh" "6-network_normalize.sh" "7-schema_validate.sh" "8-data_quality.sh" "9-enrich.sh" "10-timeline.sh" "11-source_stats.sh")

for f in "${REQUIRED_DATA[@]}"; do
    [[ -f "${SCRIPT_DIR}/${f}" ]] || MISSING+=("data/${f}")
done
for f in "${REQUIRED_REPORTS[@]}"; do
    [[ -f "${SCRIPT_DIR}/${f}" ]] || MISSING+=("reports/${f}")
done
for f in "${REQUIRED_SCHEMA[@]}"; do
    [[ -f "${SCRIPT_DIR}/${f}" ]] || MISSING+=("schema/${f}")
done
for f in "${REQUIRED_PIPELINE[@]}"; do
    [[ -f "${SCRIPT_DIR}/${f}" ]] || MISSING+=("pipeline/${f}")
done
[[ -f "${SCRIPT_DIR}/pipeline_spec.md" ]] || MISSING+=("pipeline_spec.md")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "[ERROR] Missing required files:" >&2
    for m in "${MISSING[@]}"; do
        echo "  ${m}" >&2
    done
    exit 1
fi

# --- Create handoff directory structure --------------------------------------

rm -rf "$HANDOFF_DIR"
mkdir -p "${HANDOFF_DIR}/data" "${HANDOFF_DIR}/context" "${HANDOFF_DIR}/reports" "${HANDOFF_DIR}/schema" "${HANDOFF_DIR}/pipeline"

# --- Copy files --------------------------------------------------------------

cp "${SCRIPT_DIR}/normalized_events.json" "${HANDOFF_DIR}/data/"
cp "${SCRIPT_DIR}/enriched_events.json" "${HANDOFF_DIR}/data/"
cp "${SCRIPT_DIR}/timeline_index.json" "${HANDOFF_DIR}/data/"
cp "${SCRIPT_DIR}/network_events.json" "${HANDOFF_DIR}/data/"
cp "${SCRIPT_DIR}/quarantine.json" "${HANDOFF_DIR}/data/"
echo "copying data/       ... 5 files"

cp "$ASSET_INVENTORY" "${HANDOFF_DIR}/context/asset_inventory.json"
cp "$NETWORK_ZONES" "${HANDOFF_DIR}/context/network_zones.json"
echo "copying context/    ... 2 files"

cp "${SCRIPT_DIR}/source_inventory.json" "${HANDOFF_DIR}/reports/"
cp "${SCRIPT_DIR}/validation_report.json" "${HANDOFF_DIR}/reports/"
cp "${SCRIPT_DIR}/cleaning_log.json" "${HANDOFF_DIR}/reports/"
cp "${SCRIPT_DIR}/source_stats.json" "${HANDOFF_DIR}/reports/"
cp "${SCRIPT_DIR}/pipeline_test_report.json" "${HANDOFF_DIR}/reports/"
echo "copying reports/    ... 5 files"

cp "${SCRIPT_DIR}/event_schema.json" "${HANDOFF_DIR}/schema/"
echo "copying schema/     ... 1 file"

for f in "${REQUIRED_PIPELINE[@]}"; do
    cp "${SCRIPT_DIR}/${f}" "${HANDOFF_DIR}/pipeline/"
done
echo "copying pipeline/   ... 12 files"

cp "${SCRIPT_DIR}/pipeline_spec.md" "${HANDOFF_DIR}/"
echo "copying spec        ... 1 file"

# --- Generate MANIFEST.json --------------------------------------------------

python3 - "$HANDOFF_DIR" <<'PYEOF'
import hashlib
import json
import os
import sys

handoff_dir = sys.argv[1]
entries = []

for root, dirs, files in os.walk(handoff_dir):
    dirs.sort()
    for filename in sorted(files):
        filepath = os.path.join(root, filename)
        relpath = os.path.relpath(filepath, handoff_dir)
        size = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        entries.append({"path": relpath, "size": size, "sha256": sha256})

entries.sort(key=lambda e: e["path"])

manifest = {"total_entries": len(entries), "files": entries}

manifest_path = os.path.join(handoff_dir, "MANIFEST.json")
with open(manifest_path, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

print(len(entries))
PYEOF

MANIFEST_COUNT=$(python3 -c "import json; print(len(json.load(open('${HANDOFF_DIR}/MANIFEST.json'))['files']))")
echo "MANIFEST.json       : ${MANIFEST_COUNT} entries"

# --- Sanity check: all files present and non-empty ---------------------------

SANITY_OK=true

ALL_PATHS=(
    "data/normalized_events.json"
    "data/enriched_events.json"
    "data/timeline_index.json"
    "data/network_events.json"
    "data/quarantine.json"
    "context/asset_inventory.json"
    "context/network_zones.json"
    "reports/source_inventory.json"
    "reports/validation_report.json"
    "reports/cleaning_log.json"
    "reports/source_stats.json"
    "reports/pipeline_test_report.json"
    "schema/event_schema.json"
    "pipeline/evidence_pipeline.sh"
    "pipeline/0-source_inventory.sh"
    "pipeline/1-telemetry_import.sh"
    "pipeline/2-windows_parse.sh"
    "pipeline/3-linux_parse.sh"
    "pipeline/5-normalize.sh"
    "pipeline/6-network_normalize.sh"
    "pipeline/7-schema_validate.sh"
    "pipeline/8-data_quality.sh"
    "pipeline/9-enrich.sh"
    "pipeline/10-timeline.sh"
    "pipeline/11-source_stats.sh"
    "pipeline_spec.md"
    "MANIFEST.json"
)

for relpath in "${ALL_PATHS[@]}"; do
    fullpath="${HANDOFF_DIR}/${relpath}"
    if [[ ! -f "$fullpath" ]] || [[ ! -s "$fullpath" ]]; then
        echo "[SANITY] Problem with: ${relpath}" >&2
        SANITY_OK=false
    fi
done

if [[ "$SANITY_OK" == "true" ]]; then
    echo "handoff sanity check: ok"
    echo "evidence_handoff/ ready"
    exit 0
else
    echo "handoff sanity check: FAILED" >&2
    exit 1
fi
