#!/bin/bash
# Name: 0-shift_intake.sh
# Purpose: Acknowledge the shift, verify the full toolchain (binaries, prior-project
#          components, evidence pack, assets, Wazuh exports), create the locked shift
#          workspace layout, and write the machine-readable shift start record that
#          serves as the clock reference for all downstream shift metrics.
# Author: Steve - Cybersecurity Engineer
# Date: 14 September 2026

set -u

log() { printf '[intake] %s\n' "$*"; }
die() { printf '[intake][ERROR] %s\n' "$*" >&2; exit 1; }

# Extract the first dotted version number from a command's version output
first_version() {
    grep -oE '[0-9]+([.][0-9]+)+' <<<"$1" | head -n 1
}

# ---------------------------------------------------------------------------
# 0. Environment contract must be exported before running
# ---------------------------------------------------------------------------
for var in CAPSTONE_PACK ASSETS_DIR WAZUH_EXPORTS SHIFT_WORKSPACE PIPELINE_BIN \
           BASELINE_BIN CATALOG_DIR TRIAGE_BIN; do
    if [[ -z "${!var:-}" ]]; then
        die "environment variable $var is not set - source the environment contract first"
    fi
done

# ---------------------------------------------------------------------------
# 1. Required binaries on PATH
# ---------------------------------------------------------------------------
for bin in jq python3 yq sigma sha256sum; do
    command -v "$bin" >/dev/null 2>&1 || die "required binary not on PATH: $bin"
done

JQ_V=$(first_version "$(jq --version 2>/dev/null)")
PY_V=$(first_version "$(python3 --version 2>&1)")
YQ_V=$(first_version "$(yq --version 2>/dev/null)")
SIGMA_V=$(first_version "$(sigma version 2>/dev/null)")

[[ -n "$JQ_V" ]]    || die "could not determine jq version"
[[ -n "$PY_V" ]]    || die "could not determine python3 version"
[[ -n "$YQ_V" ]]    || die "could not determine yq version"
[[ -n "$SIGMA_V" ]] || die "could not determine sigma version"

log "jq $JQ_V OK"
log "python3 $PY_V OK"
log "yq $YQ_V OK"
log "sigma-cli $SIGMA_V OK"
log "sha256sum OK"

# ---------------------------------------------------------------------------
# 2. Prior-project binaries and directories
# ---------------------------------------------------------------------------
[[ -f "$PIPELINE_BIN" && -x "$PIPELINE_BIN" ]] || die "PIPELINE_BIN is not an executable file: $PIPELINE_BIN"
log "PIPELINE_BIN OK"

[[ -f "$BASELINE_BIN" && -x "$BASELINE_BIN" ]] || die "BASELINE_BIN is not an executable file: $BASELINE_BIN"
log "BASELINE_BIN OK"

[[ -d "$CATALOG_DIR" && -r "$CATALOG_DIR" ]] || die "CATALOG_DIR is not a readable directory: $CATALOG_DIR"
catalog_rules=$(find "$CATALOG_DIR" -maxdepth 1 -type f -name '*.yml' | wc -l)
if (( catalog_rules < 1 )); then
    die "CATALOG_DIR contains no .yml rule files: $CATALOG_DIR"
fi
log "CATALOG_DIR OK ($catalog_rules rules)"

[[ -f "$TRIAGE_BIN" && -x "$TRIAGE_BIN" ]] || die "TRIAGE_BIN is not an executable file: $TRIAGE_BIN"
log "TRIAGE_BIN OK"

# ---------------------------------------------------------------------------
# 3. Evidence pack
# ---------------------------------------------------------------------------
[[ -d "$CAPSTONE_PACK" ]] || die "CAPSTONE_PACK is not a directory: $CAPSTONE_PACK"
[[ -r "$CAPSTONE_PACK" ]] || die "CAPSTONE_PACK is not accessible to $(id -un): $CAPSTONE_PACK"
PACK_SUBDIRS=$(find "$CAPSTONE_PACK" -mindepth 1 -maxdepth 1 -type d | wc -l)
if (( PACK_SUBDIRS < 1 )); then
    die "CAPSTONE_PACK is empty: $CAPSTONE_PACK"
fi
log "CAPSTONE_PACK OK"
while IFS= read -r subdir; do
    log "  pack/ $subdir"
done < <(find "$CAPSTONE_PACK" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)

# ---------------------------------------------------------------------------
# 4. Asset and context files
# ---------------------------------------------------------------------------
ASSET_FILES=(assets.json ioc_feed.json hc_red7_advisory.md change_tickets.json prior_shift_notes.md)
for f in "${ASSET_FILES[@]}"; do
    [[ -f "$ASSETS_DIR/$f" ]] || die "missing required asset file: $ASSETS_DIR/$f"
done
log "ASSETS_DIR: ${#ASSET_FILES[@]} meta files OK"

# ---------------------------------------------------------------------------
# 5. Wazuh exports
# ---------------------------------------------------------------------------
WAZUH_FILES=(incident_A_search_results.json incident_B_search_results.json \
             incident_C_search_results.json campaign_dashboard_summary.md)
for f in "${WAZUH_FILES[@]}"; do
    [[ -f "$WAZUH_EXPORTS/$f" ]] || die "missing required Wazuh export: $WAZUH_EXPORTS/$f"
done
log "WAZUH_EXPORTS: ${#WAZUH_FILES[@]} export files OK"

# ---------------------------------------------------------------------------
# 6. IOC feed count and advisory cluster ID
# ---------------------------------------------------------------------------
ioc_count=$(jq -r '.iocs | length' "$ASSETS_DIR/ioc_feed.json") \
    || die "failed to parse ioc_feed.json"
log "ioc_feed.json OK ($ioc_count entries)"

cluster_id=$(grep -m1 -oE 'HC-RED7' "$ASSETS_DIR/hc_red7_advisory.md")
[[ -n "$cluster_id" ]] || die "could not find HC-RED7 cluster ID in hc_red7_advisory.md"
log "advisory $cluster_id loaded"

# ---------------------------------------------------------------------------
# 7. Workspace layout (locked) and stub files
# ---------------------------------------------------------------------------
WS="$SHIFT_WORKSPACE"
mkdir -p "$WS"/{runtime,enriched,alerts,investigations,campaign,reports,response,handoff} \
    || die "failed to create workspace directories at $WS"

STUB_FILES=(
    "$WS/MANIFEST.json"
    "$WS/runtime/shift_start.json"
    "$WS/runtime/pipeline_run.json"
    "$WS/runtime/baseline_run.json"
    "$WS/runtime/catalog_run.json"
    "$WS/enriched/enriched_events.jsonl"
    "$WS/enriched/timeline.jsonl"
    "$WS/enriched/baseline.json"
    "$WS/enriched/source_stats.json"
    "$WS/alerts/alert_queue.json"
    "$WS/alerts/shift_briefing.json"
    "$WS/alerts/triage_log.jsonl"
    "$WS/alerts/incidents.json"
    "$WS/investigations/incident_A.json"
    "$WS/investigations/incident_B.json"
    "$WS/investigations/incident_C_cli.json"
    "$WS/investigations/incident_C_export.json"
    "$WS/campaign/campaign_assessment.json"
    "$WS/reports/incident_A.md"
    "$WS/reports/incident_B.md"
    "$WS/reports/incident_C.md"
    "$WS/response/tuning_recommendations.json"
    "$WS/response/containment.json"
    "$WS/response/ioc_package.json"
    "$WS/handoff/shift_handoff.md"
)
touch "${STUB_FILES[@]}" || die "failed to create stub files in $WS"
log "workspace layout created at $WS"

# ---------------------------------------------------------------------------
# 8. Shift start record
# ---------------------------------------------------------------------------
shift_id="SHIFT-$(date -u +%Y%m%d-%H%M)"
started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
analyst_host=$(hostname)
pack_resolved=$(cd "$CAPSTONE_PACK" && pwd)

jq -n \
    --arg shift_id "$shift_id" \
    --arg analyst_host "$analyst_host" \
    --arg started_at "$started_at" \
    --arg jq_v "$JQ_V" \
    --arg py_v "$PY_V" \
    --arg yq_v "$YQ_V" \
    --arg sigma_v "$SIGMA_V" \
    --arg pack_resolved "$pack_resolved" \
    --argjson ioc_count "$ioc_count" \
    --arg cluster_id "$cluster_id" \
    '{
        shift_id: $shift_id,
        analyst_host: $analyst_host,
        started_at: $started_at,
        tools: {
            jq: $jq_v,
            python3: $py_v,
            yq: $yq_v,
            "sigma-cli": $sigma_v,
            sha256sum: "present"
        },
        prior_project_bins: {
            pipeline: true,
            baseline: true,
            catalog: true,
            triage: true
        },
        capstone_pack: $pack_resolved,
        ioc_feed_count: $ioc_count,
        advisory_cluster_id: $cluster_id,
        wazuh_exports_verified: true
    }' > "$WS/runtime/shift_start.json" \
    || die "failed to write shift_start.json"

log "shift_start.json written"

exit 0
