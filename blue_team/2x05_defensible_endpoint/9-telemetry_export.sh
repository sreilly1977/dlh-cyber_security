#!/bin/bash
# Name: 9-telemetry_export.sh
# Purpose: Assemble structured telemetry export package with manifest and verification
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
# Exit Codes: 0=Success (verification passed), 1=Control Failure, 2=Environment Error

set -euo pipefail

# --- Configuration ---
CAPSTONE_DIR="capstone"
TELEMETRY_SRC="${CAPSTONE_DIR}/telemetry"
NETWORK_SRC="${CAPSTONE_DIR}/network"
EXPORT_DIR="${CAPSTONE_DIR}/telemetry_handoff"
LINUX_DEST="${EXPORT_DIR}/linux"
WINDOWS_DEST="${EXPORT_DIR}/windows"
NETWORK_DEST="${EXPORT_DIR}/network"
MANIFEST_DEST="${EXPORT_DIR}/manifest"
MANIFEST_FILE="${MANIFEST_DEST}/manifest.json"
TARBALL="${CAPSTONE_DIR}/telemetry_handoff.tar.gz"

# Schema version matching 2x02 and 2x04 schemas
SCHEMA_VERSION="1.0"
FIELD_SCHEMA_VERSION="1.0"
SOURCE_SITE="hawthorne"

# --- Helper Functions ---

log() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

fail_exit() {
    log "FAILURE: $1"
    exit 1
}

env_error() {
    log "ENVIRONMENT ERROR: $1"
    exit 2
}

compute_sha256() {
    sha256sum "$1" | awk '{print $1}'
}

compute_size() {
    stat -c %s "$1"
}

# --- Pre-flight Checks ---

log "Checking environment dependencies..."

if [[ $EUID -ne 0 ]]; then
    env_error "This script must be run as root."
fi

if ! command -v jq &>/dev/null; then
    env_error "jq is required but not installed"
fi

if ! command -v sha256sum &>/dev/null; then
    env_error "sha256sum is required but not installed"
fi

# --- Define Source Files ---

# Array of: source_path|dest_subdir|dest_filename|produced_by
declare -a FILES_TO_COPY=(
    "${TELEMETRY_SRC}/linux_events.json|linux|linux_events.json|2x02_eyes_on_endpoint"
    "${TELEMETRY_SRC}/windows_events.json|windows|windows_events.json|2x02_eyes_on_endpoint"
    "/etc/audit/rules.d/hawthorne.rules|linux|audit_rules.txt|2x02_eyes_on_endpoint"
    "${TELEMETRY_SRC}/sysmon_config.xml|windows|sysmon_config.xml|2x02_eyes_on_endpoint"
    "${TELEMETRY_SRC}/psl_registry.reg|windows|psl_registry.reg|2x02_eyes_on_endpoint"
    "${NETWORK_SRC}/suricata_alerts.json|network|suricata_alerts.json|7-network_deploy.sh"
    "${NETWORK_SRC}/nftables_ruleset.nft|network|nftables.conf|7-network_deploy.sh"
)

# --- Step 1: Create Directory Structure ---

log "Creating telemetry handoff directory structure..."

rm -rf "$EXPORT_DIR"
mkdir -p "$LINUX_DEST" "$WINDOWS_DEST" "$NETWORK_DEST" "$MANIFEST_DEST"

# --- Step 2: Copy Source Files ---
# Copy (not move) each source artifact into the telemetry handoff package
# copy source files into the export package directory structure

log "Copying source files into export package..."

MISSING_FILES=()

for entry in "${FILES_TO_COPY[@]}"; do
    IFS='|' read -r src_path dest_subdir dest_filename produced_by <<< "$entry"
    dest_path="${EXPORT_DIR}/${dest_subdir}/${dest_filename}"

    if [[ ! -f "$src_path" ]]; then
        log "Warning: Source file not found: $src_path"
        MISSING_FILES+=("${src_path}")
        continue
    fi

    # copy artifact from source to destination
    cp "$src_path" "$dest_path"
    log "  Copied: ${src_path} -> ${dest_path}"
done

if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
    log "Missing ${#MISSING_FILES[@]} source file(s):"
    for f in "${MISSING_FILES[@]}"; do
        log "  - $f"
    done
    fail_exit "Cannot assemble package with missing source files"
fi

# --- Step 3: Build Manifest ---

log "Building manifest.json..."

GENERATED_AT=$(date -Iseconds)

# Build files array
FILES_JSON="[]"

for entry in "${FILES_TO_COPY[@]}"; do
    IFS='|' read -r src_path dest_subdir dest_filename produced_by <<< "$entry"
    dest_rel="capstone/telemetry_handoff/${dest_subdir}/${dest_filename}"
    dest_abs="${EXPORT_DIR}/${dest_subdir}/${dest_filename}"

    file_size=$(compute_size "$dest_abs")
    file_hash=$(compute_sha256 "$dest_abs")

    FILES_JSON=$(echo "$FILES_JSON" | jq \
        --arg path "$dest_rel" \
        --argjson size "$file_size" \
        --arg sha256 "$file_hash" \
        --arg produced_by "$produced_by" \
        '. + [{
            path: $path,
            size_bytes: $size,
            sha256: $sha256,
            produced_by: $produced_by
        }]')
done

jq -n \
    --arg schema_version "$SCHEMA_VERSION" \
    --arg source_site "$SOURCE_SITE" \
    --arg generated_at "$GENERATED_AT" \
    --arg field_schema_version "$FIELD_SCHEMA_VERSION" \
    --argjson files "$FILES_JSON" \
    '{
        schema_version: $schema_version,
        source_site: $source_site,
        generated_at: $generated_at,
        field_schema_version: $field_schema_version,
        files: $files
    }' > "$MANIFEST_FILE"

log "Manifest written to $MANIFEST_FILE"

# --- Step 4: Tar the Package ---

log "Creating tarball..."

TARBALL_SIZE=0
TARBALL_HASH=""

if tar -czf "$TARBALL" -C "$(dirname "$CAPSTONE_DIR")" "$(basename "$CAPSTONE_DIR")/$(basename "$EXPORT_DIR")" 2>/dev/null; then
    TARBALL_SIZE=$(compute_size "$TARBALL")
    TARBALL_HASH=$(compute_sha256 "$TARBALL")
    log "Tarball created: $TARBALL (${TARBALL_SIZE} bytes)"
elif tar -czf "$TARBALL" "$EXPORT_DIR" 2>/dev/null; then
    TARBALL_SIZE=$(compute_size "$TARBALL")
    TARBALL_HASH=$(compute_sha256 "$TARBALL")
    log "Tarball created: $TARBALL (${TARBALL_SIZE} bytes)"
else
    fail_exit "Failed to create tarball"
fi

# --- Step 5: Update Manifest with Tarball Info ---

log "Updating manifest with tarball metadata..."

jq \
    --arg tarball_path "capstone/telemetry_handoff.tar.gz" \
    --argjson tarball_size "$TARBALL_SIZE" \
    --arg tarball_sha256 "$TARBALL_HASH" \
    '. + {
        tarball: {
            path: $tarball_path,
            size_bytes: $tarball_size,
            sha256: $tarball_sha256
        }
    }' "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp" && mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"

log "Manifest updated with tarball metadata"

# --- Step 6: Verify Hashes ---

log "Verifying manifest hashes against files on disk..."

VERIFICATION_PASS=true
VERIFIED_COUNT=0
FAILED_COUNT=0

FILE_COUNT=$(jq '.files | length' "$MANIFEST_FILE")

for i in $(seq 0 $((FILE_COUNT - 1))); do
    manifest_path=$(jq -r ".files[$i].path" "$MANIFEST_FILE")
    manifest_size=$(jq -r ".files[$i].size_bytes" "$MANIFEST_FILE")
    manifest_hash=$(jq -r ".files[$i].sha256" "$MANIFEST_FILE")

    # Resolve relative path (strip leading capstone/ since we run from project root)
    disk_path=".$manifest_path"

    if [[ ! -f "$disk_path" ]]; then
        disk_path="$manifest_path"
    fi

    if [[ ! -f "$disk_path" ]]; then
        log "  [FAIL] File not found on disk: $manifest_path"
        VERIFICATION_PASS=false
        FAILED_COUNT=$((FAILED_COUNT + 1))
        continue
    fi

    actual_size=$(compute_size "$disk_path")
    actual_hash=$(compute_sha256 "$disk_path")

    if [[ "$actual_hash" == "$manifest_hash" && "$actual_size" == "$manifest_size" ]]; then
        log "  [PASS] $manifest_path (sha256: ${actual_hash:0:16}...)"
        VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
    else
        log "  [FAIL] $manifest_path - hash mismatch"
        log "    Manifest: $manifest_hash ($manifest_size bytes)"
        log "    Disk:     $actual_hash ($actual_size bytes)"
        VERIFICATION_PASS=false
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
done

# Verify tarball hash
TARBALL_MANIFEST_HASH=$(jq -r '.tarball.sha256' "$MANIFEST_FILE")
TARBALL_DISK_HASH=$(compute_sha256 "$TARBALL")

if [[ "$TARBALL_DISK_HASH" == "$TARBALL_MANIFEST_HASH" ]]; then
    log "  [PASS] Tarball hash verified (${TARBALL_DISK_HASH:0:16}...)"
    VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
else
    log "  [FAIL] Tarball hash mismatch"
    log "    Manifest: $TARBALL_MANIFEST_HASH"
    log "    Disk:     $TARBALL_DISK_HASH"
    VERIFICATION_PASS=false
    FAILED_COUNT=$((FAILED_COUNT + 1))
fi

# --- Verification Summary ---

echo ""
echo "=== Telemetry Export Verification ==="
echo "Files verified: ${VERIFIED_COUNT}/${FILE_COUNT}"
echo "Failures: ${FAILED_COUNT}"
echo "Tarball: ${TARBALL} (${TARBALL_SIZE} bytes)"
echo "Tarball SHA-256: ${TARBALL_HASH}"
echo ""

if $VERIFICATION_PASS; then
    log "SUCCESS: All hashes verified. Telemetry export package is ready."
    exit 0
else
    log "FAILURE: ${FAILED_COUNT} hash(es) did not match."
    exit 1
fi
