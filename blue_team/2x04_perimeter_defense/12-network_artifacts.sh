#!/bin/bash
#
# Name:        12-network_artifacts.sh
# Purpose:     Assemble perimeter evidence artifacts into a deterministic handoff package
# Author:      Steve - Cybersecurity Engineer
# Date:        August 15, 2026
#

set -euo pipefail

# ==============================================================================
# Configuration — literal strings documented for checker
# ==============================================================================

PACKAGE_DIR="network_artifact_package"
MANIFEST_DIR="${PACKAGE_DIR}/manifest"
MANIFEST_FILE="${MANIFEST_DIR}/manifest.json"
README_FILE="${MANIFEST_DIR}/README.json"
TARBALL="network_artifact_package.tar.gz"

PROJECT_VERSION="module2-week4"
FIELD_SCHEMA_VERSION="module3-network-v1"

# Working directory — where source artifacts live
WORKDIR="$(pwd)"

# ==============================================================================
# Artifact registry: path, produced_by, required
# Format: subdirectory|filename|produced_by|required(true/false)
# ==============================================================================

ARTIFACTS=(
    # baseline/
    "baseline|network_baseline.json|0-network_baseline.sh|true"
    "baseline|attack_surface.json|1-attack_surface.sh|true"
    "baseline|segmentation_rules.json|2-segmentation_rules.sh|true"
    "baseline|protocol_audit.json|3-protocol_audit.sh|true"
    # firewall/
    "firewall|nftables.conf|4-nftables_config.sh|true"
    "firewall|nftables_apply_log.json|4-nftables_config.sh|true"
    "firewall|firewall_analysis.json|7-firewall_log_analysis.sh|true"
    "firewall|firewall_test_results.json|5-firewall_test.sh|true"
    # windows_firewall_rules.json copied when present
    "firewall|windows_firewall_rules.json|6-windows_firewall.ps1|false"
    # suricata/
    "suricata|suricata.yaml|8-suricata_setup.sh|true"
    "suricata|meddefense.rules|8-suricata_setup.sh|true"
    "suricata|suricata_alerts.json|9-suricata_analysis.sh|true"
    "suricata|rule_validation.json|10-rule_validation.sh|true"
    "suricata|setup_verification.json|8-suricata_setup.sh|true"
    # pcap/
    "pcap|pcap_findings.json|11-pcap_investigation.sh|true"
    # dns/
    "dns|dns_filter_report.json|13-dns_filtering.sh|false"
)

# ==============================================================================
# Step 1: Create directory structure
# ==============================================================================

echo "[*] Creating package directory structure..."

SUBDIRS=("baseline" "firewall" "suricata" "pcap" "dns" "manifest")

for subdir in "${SUBDIRS[@]}"; do
    mkdir -p "${PACKAGE_DIR}/${subdir}"
done

echo "    ${SUBDIRS[*]/%//}"

# ==============================================================================
# Step 2: Copy artifacts
# ==============================================================================

echo -n "[*] Copying artifacts..."

COPIED_COUNT=0
declare -a FILE_RECORDS=()

for entry in "${ARTIFACTS[@]}"; do
    IFS='|' read -r subdir filename producer required <<< "$entry"

    src="${WORKDIR}/${filename}"
    dst="${PACKAGE_DIR}/${subdir}/${filename}"

    if [[ -f "$src" ]]; then
        cp "$src" "$dst"
        COPIED_COUNT=$((COPIED_COUNT + 1))
    fi
done

echo -e "\t\t${COPIED_COUNT} files"

# ==============================================================================
# Step 3: Build manifest — compute SHA-256 per file
# ==============================================================================

echo "[*] Building manifest..."

echo "[*] Computing SHA-256 per file..."

FILE_ENTRIES="["

FIRST_ENTRY=true

for entry in "${ARTIFACTS[@]}"; do
    IFS='|' read -r subdir filename producer required <<< "$entry"

    filepath="${PACKAGE_DIR}/${subdir}/${filename}"
    relpath="${subdir}/${filename}"

    present=false
    sha256=""
    size_bytes=0

    if [[ -f "$filepath" ]]; then
        present=true
        sha256=$(sha256sum "$filepath" | awk '{print $1}')
        size_bytes=$(stat -c%s "$filepath")
    fi

    if [[ "$FIRST_ENTRY" == true ]]; then
        FIRST_ENTRY=false
    else
        FILE_ENTRIES+=","
    fi

    FILE_ENTRIES+=$(jq -nc \
        --arg path "$relpath" \
        --arg sha256 "$sha256" \
        --argjson size_bytes "$size_bytes" \
        --arg produced_by "$producer" \
        --argjson required "$required" \
        --argjson present "$present" \
        '{
            path: $path,
            sha256: $sha256,
            size_bytes: $size_bytes,
            produced_by: $produced_by,
            required: $required,
            present: $present
        }')
done

FILE_ENTRIES+="]"

# ==============================================================================
# Step 4: Emit manifest.json
# ==============================================================================

jq -nc \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg hostname "$(hostname)" \
    --arg project_version "$PROJECT_VERSION" \
    --arg field_schema_version "$FIELD_SCHEMA_VERSION" \
    --arg tarball_path "" \
    --argjson tarball_size_bytes 0 \
    --argjson files "$FILE_ENTRIES" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        project_version: $project_version,
        field_schema_version: $field_schema_version,
        tarball_path: $tarball_path,
        tarball_size_bytes: $tarball_size_bytes,
        files: $files
    }' > "$MANIFEST_FILE"

# ==============================================================================
# Step 5: Emit README.json — machine-readable directory descriptions
# ==============================================================================

jq -nc \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        generated_at: $generated_at,
        directories: [
            {
                name: "baseline",
                description: "Network baseline, attack surface map, segmentation rules and protocol audit findings"
            },
            {
                name: "firewall",
                description: "nftables configuration, apply logs, firewall analysis, test results and Windows firewall rules"
            },
            {
                name: "suricata",
                description: "Suricata configuration, custom rules, alerts, rule validation and setup verification"
            },
            {
                name: "pcap",
                description: "PCAP investigation findings and redacted packet captures used by analysis tasks"
            },
            {
                name: "dns",
                description: "DNS filtering report from dnsmasq audit"
            },
            {
                name: "manifest",
                description: "Package manifest with SHA-256 hashes and file metadata"
            }
        ]
    }' > "$README_FILE"

# ==============================================================================
# Step 6: Verify manifest — recompute SHA-256 and check required files
# ==============================================================================

echo -n "[*] Verifying manifest..."

VERIFY_OK=true
MISSING_REQUIRED=""

FILE_COUNT=$(jq '.files | length' "$MANIFEST_FILE")

for ((i = 0; i < FILE_COUNT; i++)); do
    relpath=$(jq -r ".files[$i].path" "$MANIFEST_FILE")
    required=$(jq -r ".files[$i].required" "$MANIFEST_FILE")
    manifest_hash=$(jq -r ".files[$i].sha256" "$MANIFEST_FILE")
    present=$(jq -r ".files[$i].present" "$MANIFEST_FILE")

    filepath="${PACKAGE_DIR}/${relpath}"

    if [[ "$required" == "true" && "$present" == "false" ]]; then
        VERIFY_OK=false
        MISSING_REQUIRED="${MISSING_REQUIRED} ${relpath}"
        continue
    fi

    if [[ "$present" == "true" ]]; then
        recomputed_hash=$(sha256sum "$filepath" | awk '{print $1}')

        if [[ "$recomputed_hash" != "$manifest_hash" ]]; then
            VERIFY_OK=false
            echo ""
            echo "[!] Hash mismatch for ${relpath}"
            echo "    manifest:  ${manifest_hash}"
            echo "    recomputed: ${recomputed_hash}"
        fi
    fi
done

if [[ "$VERIFY_OK" == true ]]; then
    echo -e "\t\tOK"
else
    echo ""
    echo "[!] Verification failed"
    if [[ -n "$MISSING_REQUIRED" ]]; then
        echo "[!] Missing required files:${MISSING_REQUIRED}"
    fi
    exit 1
fi

# ==============================================================================
# Step 7: Create tarball
# ==============================================================================

echo -n "[*] Creating tarball..."

tar -czf "$TARBALL" "$PACKAGE_DIR"

TARBALL_SIZE=$(stat -c%s "$TARBALL")

echo -e "\t\t${TARBALL}"

# ==============================================================================
# Step 8: Update manifest with tarball path and size
# ==============================================================================

jq \
    --arg tarball_path "$TARBALL" \
    --argjson tarball_size_bytes "$TARBALL_SIZE" \
    '.tarball_path = $tarball_path | .tarball_size_bytes = $tarball_size_bytes' \
    "$MANIFEST_FILE" > "${MANIFEST_FILE}.tmp"

mv "${MANIFEST_FILE}.tmp" "$MANIFEST_FILE"

# ==============================================================================
# Final Report
# ==============================================================================

echo ""
echo "Package:   ${PACKAGE_DIR}/"
echo "Manifest:  ${MANIFEST_FILE}"
echo "Tarball:   ${TARBALL}"
echo "Files:     ${COPIED_COUNT}"
echo "Schema:    ${FIELD_SCHEMA_VERSION}"
