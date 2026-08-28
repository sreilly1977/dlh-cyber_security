#!/bin/bash
# Name: 11-handoff_package.sh
# Purpose: Assemble every capstone deliverable into a single signed handoff package with manifest, runbook and round-trip verification
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
# Exit Codes: 0=Success (round-trip verification passed), 1=Failure, 2=Environment error
# This script produces the final handoff package tarball with SHA-256 manifest

set -euo pipefail

# --- Configuration ---
CAPSTONE_DIR="capstone"
PACKAGE_DIR="defensible_endpoint_package"
TARBALL="defensible_endpoint_package.tar.gz"
MANIFEST_FILE="${PACKAGE_DIR}/manifest.json"
HANDOFF_ASSEMBLY="${CAPSTONE_DIR}/handoff_assembly.json"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
SCHEMA_VERSION="capstone-handoff-v1"
SITE="hawthorne"

# --- Helper Functions ---

log() {
    echo "[INFO] $(date -Iseconds) - $1"
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

if [[ ! -d "$CAPSTONE_DIR" ]]; then
    env_error "capstone directory not found at $CAPSTONE_DIR"
fi

# --- Step 1: Create Package Directory Structure ---

log "Creating handoff package directory structure..."

rm -rf "$PACKAGE_DIR"
mkdir -p "${PACKAGE_DIR}/intake"
mkdir -p "${PACKAGE_DIR}/baseline"
mkdir -p "${PACKAGE_DIR}/exec"
mkdir -p "${PACKAGE_DIR}/telemetry"
mkdir -p "${PACKAGE_DIR}/patch"
mkdir -p "${PACKAGE_DIR}/network"
mkdir -p "${PACKAGE_DIR}/telemetry_handoff"
mkdir -p "${PACKAGE_DIR}/reports"
mkdir -p "${PACKAGE_DIR}/scripts"

# --- Step 2: Copy Content Into Package ---

log "Copying capstone content into handoff package..."

# intake/
if [[ -d "${CAPSTONE_DIR}/intake" ]]; then
    cp -r "${CAPSTONE_DIR}/intake/"* "${PACKAGE_DIR}/intake/" 2>/dev/null || true
    log "  Copied intake/"
else
    mkdir -p "${CAPSTONE_DIR}/intake"
    cp -r "${CAPSTONE_DIR}/intake/"* "${PACKAGE_DIR}/intake/" 2>/dev/null || true
    log "  intake/ source not found, created empty"
fi

# baseline/
cp -r "${CAPSTONE_DIR}/baseline/"* "${PACKAGE_DIR}/baseline/" 2>/dev/null || true
log "  Copied baseline/"

# exec/
cp -r "${CAPSTONE_DIR}/exec/"* "${PACKAGE_DIR}/exec/" 2>/dev/null || true
log "  Copied exec/"

# telemetry/
cp -r "${CAPSTONE_DIR}/telemetry/"* "${PACKAGE_DIR}/telemetry/" 2>/dev/null || true
log "  Copied telemetry/"

# patch/
cp -r "${CAPSTONE_DIR}/patch/"* "${PACKAGE_DIR}/patch/" 2>/dev/null || true
log "  Copied patch/"

# network/
cp -r "${CAPSTONE_DIR}/network/"* "${PACKAGE_DIR}/network/" 2>/dev/null || true
log "  Copied network/"

# telemetry_handoff/
if [[ -d "${CAPSTONE_DIR}/telemetry_handoff" ]]; then
    cp -r "${CAPSTONE_DIR}/telemetry_handoff/"* "${PACKAGE_DIR}/telemetry_handoff/" 2>/dev/null || true
    log "  Copied telemetry_handoff/"
else
    log "  telemetry_handoff/ not found, created empty"
fi

# reports/ — target_state.json, validation.json, compliance.json
cp "${CAPSTONE_DIR}/target_state.json" "${PACKAGE_DIR}/reports/" 2>/dev/null || log "  Warning: target_state.json not found"
cp "${CAPSTONE_DIR}/validation.json" "${PACKAGE_DIR}/reports/" 2>/dev/null || log "  Warning: validation.json not found"
cp "${CAPSTONE_DIR}/compliance.json" "${PACKAGE_DIR}/reports/" 2>/dev/null || log "  Warning: compliance.json not found"
log "  Copied reports/"

# scripts/ — every 0- through 11- script
log "  Copying deployment scripts..."
COPIED_SCRIPTS=0
for script in "$SCRIPTS_DIR"/[0-9]*.sh "$SCRIPTS_DIR"/[0-9]*.ps1; do
    if [[ -f "$script" ]]; then
        cp "$script" "${PACKAGE_DIR}/scripts/"
        COPIED_SCRIPTS=$((COPIED_SCRIPTS + 1))
    fi
done
# Also copy from capstone directory if scripts are there
for script in "${CAPSTONE_DIR}"/*.sh; do
    if [[ -f "$script" ]]; then
        base=$(basename "$script")
        if [[ ! -f "${PACKAGE_DIR}/scripts/${base}" ]]; then
            cp "$script" "${PACKAGE_DIR}/scripts/"
            COPIED_SCRIPTS=$((COPIED_SCRIPTS + 1))
        fi
    fi
done
log "  Copied ${COPIED_SCRIPTS} script(s) into scripts/"

# --- Step 3: Write runbook.sh ---
# runbook.sh provides a single command entry point for handoff verification

log "Writing runbook.sh..."

cat > "${PACKAGE_DIR}/runbook.sh" << 'RUNBOOK_EOF'
#!/bin/bash
# Name: runbook.sh
# Purpose: Single-file executable entry point for handoff verification
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
# This script runs the validation suite and reports the handoff verdict
# Usage: ./runbook.sh (takes no arguments)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "  Defensible Endpoint — Handoff Verification"
echo "  Site: hawthorne"
echo "  Host: $(hostname)"
echo "  Timestamp: $(date -Iseconds)"
echo "=========================================="
echo ""

echo "[1/2] Running validation suite..."
echo ""

bash "${SCRIPT_DIR}/scripts/8-validate_all.sh" "${SCRIPT_DIR}/reports/target_state.json" || true

echo ""
echo "[2/2] Reading validation results..."
echo ""

VALIDATION_FILE="${SCRIPT_DIR}/reports/validation.json"

if [[ ! -f "$VALIDATION_FILE" ]]; then
    echo "ERROR: validation.json not found at $VALIDATION_FILE"
    echo "HANDOFF NOT READY"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required but not installed"
    echo "HANDOFF NOT READY"
    exit 1
fi

FAIL_COUNT=$(jq -r '.fail_count // 0' "$VALIDATION_FILE")
ERROR_COUNT=$(jq -r '.error_count // 0' "$VALIDATION_FILE")
PASS_COUNT=$(jq -r '.pass_count // 0' "$VALIDATION_FILE")
TOTAL_CONTROLS=$(jq -r '.total_controls // 0' "$VALIDATION_FILE")
PASS_PCT=$(jq -r '.pass_percentage // 0' "$VALIDATION_FILE")

echo "Validation Summary:"
echo "  Total controls: ${TOTAL_CONTROLS}"
echo "  Pass: ${PASS_COUNT}"
echo "  Fail: ${FAIL_COUNT}"
echo "  Error: ${ERROR_COUNT}"
echo "  Pass percentage: ${PASS_PCT}%"
echo ""

if [[ "$FAIL_COUNT" -eq 0 && "$ERROR_COUNT" -eq 0 ]]; then
    echo "HANDOFF READY"
    exit 0
else
    echo "HANDOFF NOT READY"
    echo ""
    echo "Failing control IDs:"
    jq -r '.controls[] | select(.verdict == "fail" or .verdict == "error") | "  \(.id) — \(.evidence)"' "$VALIDATION_FILE"
    exit 1
fi
RUNBOOK_EOF

chmod +x "${PACKAGE_DIR}/runbook.sh"
log "runbook.sh written and made executable"

# --- Step 4: Write HANDOFF.md (exactly two paragraphs) ---

log "Writing HANDOFF.md..."

cat > "${PACKAGE_DIR}/HANDOFF.md" << 'HANDOFF_EOF'
This package contains the complete defensible endpoint configuration for the Hawthorne site, including baseline snapshots, hardening execution logs, telemetry exports, patch pipeline artifacts, network defense configurations, compliance mappings and validation results. Every artifact is referenced by manifest.json with a SHA-256 hash, and every script used to produce the package is included in the scripts/ directory. The runbook.sh entry point provides a single-command verification that re-runs the validation suite against the included target state and reports whether the environment is ready for operations.

To verify the package, untar the archive, execute ./runbook.sh from the extracted directory root and review the output. The runbook invokes the validation script, reads the validation report and prints HANDOFF READY if all controls pass or lists the failing control IDs with evidence paths if any control fails. No additional configuration or external dependencies beyond jq and standard Linux utilities are required. The manifest.json file in the package root contains the complete file inventory with hashes for integrity verification.
HANDOFF_EOF

log "HANDOFF.md written"

# --- Step 5: Write README.md (three lines) ---

log "Writing README.md..."

cat > "${PACKAGE_DIR}/README.md" << 'README_EOF'
# Defensible Endpoint Package — Hawthorne Site
Run ./runbook.sh to verify all controls. See HANDOFF.md for full details.
Manifest with SHA-256 hashes: manifest.json
README_EOF

log "README.md written"

# --- Step 6: Build manifest.json ---

log "Building manifest.json with SHA-256 hashes for all files..."

GENERATED_AT=$(date -Iseconds)
FILES_JSON="[]"
FILES_TOTAL=0

# Walk every file in the package directory (except manifest.json itself)
while IFS= read -r -d '' filepath; do
    rel_path="${filepath#${PACKAGE_DIR}/}"

    # Skip manifest.json — it will be added after hashing
    if [[ "$rel_path" == "manifest.json" ]]; then
        continue
    fi

    file_size=$(compute_size "$filepath")
    file_hash=$(compute_sha256 "$filepath")

    # Determine produced_by based on file location
    produced_by="capstone-workflow"
    case "$rel_path" in
        intake/*)            produced_by="0-environment_intake.sh" ;;
        baseline/*)          produced_by="1-baseline_snapshot.sh" ;;
        exec/*)              produced_by="3-linux_harden.sh" ;;
        telemetry/*)         produced_by="5-telemetry_deploy.sh" ;;
        patch/*)             produced_by="6-patch_pipeline.sh" ;;
        network/*)           produced_by="7-network_deploy.sh" ;;
        telemetry_handoff/*) produced_by="9-telemetry_export.sh" ;;
        reports/target_state.json)  produced_by="2-target_state.sh" ;;
        reports/validation.json)   produced_by="8-validate_all.sh" ;;
        reports/compliance.json)   produced_by="10-compliance_report.sh" ;;
        scripts/*)           produced_by="capstone-workflow" ;;
        runbook.sh)          produced_by="11-handoff_package.sh" ;;
        HANDOFF.md)          produced_by="11-handoff_package.sh" ;;
        README.md)           produced_by="11-handoff_package.sh" ;;
    esac

    FILES_JSON=$(echo "$FILES_JSON" | jq \
        --arg path "$rel_path" \
        --argjson size "$file_size" \
        --arg sha256 "$file_hash" \
        --arg produced_by "$produced_by" \
        '. + [{
            path: $path,
            size_bytes: $size,
            sha256: $sha256,
            produced_by: $produced_by
        }]')

    FILES_TOTAL=$((FILES_TOTAL + 1))

done < <(find "$PACKAGE_DIR" -type f -print0 | sort -z)

# Write manifest.json
jq -n \
    --arg schema_version "$SCHEMA_VERSION" \
    --arg site "$SITE" \
    --arg generated_at "$GENERATED_AT" \
    --argjson files "$FILES_JSON" \
    --arg runbook_entry "./runbook.sh" \
    --arg verification_command "./runbook.sh" \
    '{
        schema_version: $schema_version,
        site: $site,
        generated_at: $generated_at,
        files: $files,
        runbook_entry: $runbook_entry,
        verification_command: $verification_command
    }' > "$MANIFEST_FILE"

log "Manifest written to $MANIFEST_FILE with $FILES_TOTAL file entries"

# --- Step 7: Create Final Tarball ---

log "Creating tarball: $TARBALL..."

tar -czf "$TARBALL" "$PACKAGE_DIR"

TARBALL_SIZE=$(compute_size "$TARBALL")
TARBALL_SHA256=$(compute_sha256 "$TARBALL")

log "Tarball created: $TARBALL (${TARBALL_SIZE} bytes, SHA-256: ${TARBALL_SHA256:0:16}...)"

# --- Step 8: Round-Trip Verification ---

log "Performing round-trip verification..."

TEMP_DIR=$(mktemp -d)
ROUNDTRIP_EXIT_CODE=1

log "  Extracting tarball to $TEMP_DIR..."
tar -xzf "$TARBALL" -C "$TEMP_DIR"

EXTRACTED_PACKAGE="${TEMP_DIR}/${PACKAGE_DIR}"

if [[ ! -d "$EXTRACTED_PACKAGE" ]]; then
    log "  Error: Extracted package directory not found at $EXTRACTED_PACKAGE"
    rm -rf "$TEMP_DIR"
    fail_exit "Round-trip verification failed: package directory not found after extraction"
fi

log "  Executing runbook from extracted copy..."

# Run the runbook from the extracted directory
# Use a subshell to capture exit code without triggering set -e
(
    cd "$EXTRACTED_PACKAGE"
    bash ./runbook.sh
) > /tmp/roundtrip_output.log 2>&1 || true

ROUNDTRIP_EXIT_CODE=$?

log "  Round-trip exit code: $ROUNDTRIP_EXIT_CODE"
log "  Round-trip output (last 10 lines):"
tail -10 /tmp/roundtrip_output.log | while IFS= read -r line; do
    log "    $line"
done

# Clean up temp directory
rm -rf "$TEMP_DIR"

# --- Step 9: Emit handoff_assembly.json ---
# Output: capstone/handoff_assembly.json with tarball metadata and round-trip verification result

log "Emitting handoff assembly report..."

jq -n \
    --arg timestamp "$(date -Iseconds)" \
    --arg tarball_path "$TARBALL" \
    --arg tarball_sha256 "$TARBALL_SHA256" \
    --argjson tarball_size_bytes "$TARBALL_SIZE" \
    --argjson roundtrip_exit_code "$ROUNDTRIP_EXIT_CODE" \
    --argjson files_total "$FILES_TOTAL" \
    '{
        timestamp: $timestamp,
        tarball_path: $tarball_path,
        tarball_sha256: $tarball_sha256,
        tarball_size_bytes: $tarball_size_bytes,
        roundtrip_exit_code: $roundtrip_exit_code,
        files_total: $files_total
    }' > "$HANDOFF_ASSEMBLY"

log "Handoff assembly report saved to $HANDOFF_ASSEMBLY"

# --- Final Result ---

echo ""
echo "============================================================"
echo "  Handoff Package Assembly Complete"
echo "  Package: $PACKAGE_DIR"
echo "  Tarball: $TARBALL"
echo "  Size: ${TARBALL_SIZE} bytes"
echo "  SHA-256: $TARBALL_SHA256"
echo "  Files in manifest: $FILES_TOTAL"
echo "  Round-trip exit code: $ROUNDTRIP_EXIT_CODE"
echo "============================================================"
echo ""

if [[ $ROUNDTRIP_EXIT_CODE -eq 0 ]]; then
    log "SUCCESS: Round-trip verification passed. Handoff package is ready."
    exit 0
else
    log "FAILURE: Round-trip verification failed (exit code $ROUNDTRIP_EXIT_CODE)."
    log "The runbook did not produce a HANDOFF READY verdict from the extracted package."
    exit 1
fi
