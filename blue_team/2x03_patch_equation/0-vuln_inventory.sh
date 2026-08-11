#!/bin/bash
#
# Name:        0-vuln_inventory.sh
# Purpose:     Enumerate installed packages and produce structured vulnerability inventory
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Input/Output files
readonly CVE_FEED="${BASE_DIR}/cve_feed.json"
readonly CISA_KEV="${BASE_DIR}/cisa_kev.json"
readonly OUTPUT_FILE="${BASE_DIR}/vulnerability_inventory.json"

# Network timeout (seconds)
readonly TIMEOUT_SECONDS=5
readonly APT_TIMEOUT=30

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

validate_prerequisites() {
    local missing=0

    for cmd in dpkg-query apt-cache apt-get jq bc; do
        if ! command -v "$cmd" &>/dev/null; then
            log "ERROR: Missing required tool: $cmd"
            missing=1
        fi
    done

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi

    if [[ ! -f "$CVE_FEED" ]]; then
        warn "CVE feed not found at $CVE_FEED. Local CVE matches will be unavailable."
    fi
}

refresh_package_lists() {
    log "Refreshing package lists..."

    if timeout "$APT_TIMEOUT" apt-get update -qq 2>/dev/null; then
        log "Package lists refreshed successfully"
    else
        warn "Package list refresh timed out or failed (may be offline)"
        log "Continuing with cached data..."
    fi
}

# Get all installed packages with Status field (as required by task)
enumerate_installed_packages() {
    dpkg-query -W -f='${binary:Package} ${Version} ${Status}\n' 2>/dev/null | \
        awk '$3 == "install" && $4 == "ok" && $5 == "installed" {print $1 "\t" $2}' | sort
}

# Get upgradable packages in ONE call instead of per-package apt-cache policy
get_upgradable_packages() {
    local upgradable_file
    upgradable_file=$(mktemp)

    # Single apt call to get all upgradable packages
    timeout "$APT_TIMEOUT" apt list --upgradable 2>/dev/null | \
        grep -v "^Listing" | \
        awk -F'/' '{print $1}' | sort -u > "$upgradable_file" || true

    echo "$upgradable_file"
}

# Combined apt-cache policy call (gets both candidate and pocket in one call)
get_candidate_and_pocket() {
    local package="$1"
    local result=""

    result=$(timeout "$TIMEOUT_SECONDS" bash -c "apt-cache policy \"$package\"" 2>/dev/null || echo "")

    local candidate=""
    local pocket="unknown"

    # Extract candidate version
    candidate=$(echo "$result" | awk '/Candidate:/{print $2}' | head -1)

    # Extract source pocket
    pocket=$(echo "$result" | \
        grep -E '(security|updates|backports)' | head -1 | \
        grep -oE '[a-z]+-(security|updates|backports)' | head -1 || echo "")

    echo "${candidate:-}|${pocket:-unknown}"
}

extract_cves_from_changelog() {
    local package="$1"
    local cves='[]'
    local changelog=""

    changelog=$(timeout "$TIMEOUT_SECONDS" bash -c "apt-get changelog \"$package\"" 2>/dev/null | head -200 || echo "")

    if [[ -n "$changelog" ]]; then
        local raw_cves
        raw_cves=$(echo "$changelog" | \
            grep -oE 'CVE-[0-9]{4}-[0-9]+' | sort -u || echo "")

        if [[ -n "$raw_cves" ]]; then
            cves=$(echo "$raw_cves" | jq -R . | jq -s '.' 2>/dev/null || echo '[]')
        fi
    fi

    # Fallback to USN mapping if no CVEs found
    if [[ "$cves" == "[]" ]] && [[ -d "/usr/share/ubuntu-advantage-tools" ]]; then
        local usn_file="/usr/share/ubuntu-advantage-tools/usns.json"
        if [[ -f "$usn_file" ]]; then
            local usn_cves
            usn_cves=$(timeout "$TIMEOUT_SECONDS" bash -c \
                "jq --arg pkg \"$package\" '[.[] | select(.package == \$pkg) | .cves // []] | add // []' \
                \"$usn_file\"" 2>/dev/null || echo '[]')
            if [[ "$usn_cves" != "[]" ]] && [[ -n "$usn_cves" ]]; then
                cves="$usn_cves"
            fi
        fi
    fi

    if ! echo "$cves" | jq -e . >/dev/null 2>&1; then
        cves='[]'
    fi

    echo "$cves"
}

get_cvss_for_cve() {
    local cve="$1"

    if [[ ! -f "$CVE_FEED" ]]; then
        echo "0.0"
        return
    fi

    local cvss
    cvss=$(jq -r --arg cve "$cve" '.cves[$cve].cvss // 0' "$CVE_FEED" 2>/dev/null || echo "0")

    if ! echo "$cvss" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
        cvss="0.0"
    fi

    echo "$cvss"
}

check_cisa_kev_for_cve() {
    local cve="$1"

    if [[ ! -f "$CISA_KEV" ]]; then
        echo "false"
        return
    fi

    local result
    result=$(jq -r --arg cve "$cve" '.[$cve].active // false' "$CISA_KEV" 2>/dev/null || echo "false")

    if [[ "$result" != "true" ]]; then
        result="false"
    fi

    echo "$result"
}

classify_severity() {
    local cvss="$1"

    if (( $(echo "$cvss >= 9.0" | bc -l) )); then
        echo "critical"
    elif (( $(echo "$cvss >= 7.0" | bc -l) )); then
        echo "high"
    elif (( $(echo "$cvss >= 4.0" | bc -l) )); then
        echo "medium"
    elif (( $(echo "$cvss > 0" | bc -l) )); then
        echo "low"
    else
        echo "none"
    fi
}

calculate_max_cvss() {
    local cves_json="$1"

    if ! echo "$cves_json" | jq -e . >/dev/null 2>&1; then
        echo "0.0"
        return
    fi

    local cve_count
    cve_count=$(echo "$cves_json" | jq 'length')

    if [[ "$cve_count" -eq 0 ]]; then
        echo "0.0"
        return
    fi

    local max_cvss="0.0"

    while IFS= read -r cve; do
        [[ -z "$cve" ]] && continue
        local cvss
        cvss=$(get_cvss_for_cve "$cve")
        if (( $(echo "$cvss > $max_cvss" | bc -l) )); then
            max_cvss="$cvss"
        fi
    done < <(echo "$cves_json" | jq -r '.[]')

    echo "$max_cvss"
}

check_any_cve_in_kev() {
    local cves_json="$1"

    if [[ ! -f "$CISA_KEV" ]]; then
        echo "false"
        return
    fi

    local cve_count
    cve_count=$(echo "$cves_json" | jq 'length' 2>/dev/null || echo 0)

    if [[ "$cve_count" -eq 0 ]]; then
        echo "false"
        return
    fi

    while IFS= read -r cve; do
        [[ -z "$cve" ]] && continue
        local kev_status
        kev_status=$(check_cisa_kev_for_cve "$cve")
        if [[ "$kev_status" == "true" ]]; then
            echo "true"
            return
        fi
    done < <(echo "$cves_json" | jq -r '.[]')

    echo "false"
}

build_vulnerability_inventory() {
    log "Building vulnerability inventory..."

    local total_packages=0
    local vuln_count=0
    local packages_json='[]'
    local mode="online"

    # Step 1: Get all installed packages
    local pkg_list
    pkg_list=$(mktemp)
    enumerate_installed_packages > "$pkg_list"
    total_packages=$(wc -l < "$pkg_list")
    log "Installed packages found: $total_packages"

    # Step 2: Get upgradable packages in ONE call (major speedup)
    local upgradable_file
    upgradable_file=$(get_upgradable_packages)
    local upgradable_count
    upgradable_count=$(wc -l < "$upgradable_file")
    log "Upgradable packages found: $upgradable_count"

    if [[ "$upgradable_count" -eq 0 ]]; then
        warn "No upgradable packages found (may be offline or fully patched)"
    fi

    # Step 3: Build a lookup of installed versions
    declare -A installed_versions
    while IFS=$'\t' read -r pkg ver; do
        [[ -z "$pkg" ]] && continue
        installed_versions["$pkg"]="$ver"
    done < "$pkg_list"

    # Step 4: Only process upgradable packages (skip the other 700+ packages)
    local processed=0
    while IFS= read -r package; do
        [[ -z "$package" ]] && continue

        # Skip if not actually installed
        local installed_version="${installed_versions[$package]:-}"
        if [[ -z "$installed_version" ]]; then
            continue
        fi

        processed=$((processed + 1))

        if (( processed % 10 == 0 )); then
            log "Processing upgradable $processed/$upgradable_count (vulnerable: $vuln_count)..."
        fi

        # Get candidate version AND pocket in ONE apt-cache call
        local policy_result
        policy_result=$(get_candidate_and_pocket "$package")
        local candidate_version
        local pocket
        IFS='|' read -r candidate_version pocket <<< "$policy_result"

        # Skip if no candidate or same version
        if [[ -z "$candidate_version" ]] || [[ "$candidate_version" == "$installed_version" ]]; then
            continue
        fi

        # Only process security or updates pocket
        if [[ "$pocket" != *"security"* ]] && [[ "$pocket" != *"updates"* ]] && [[ "$pocket" != "unknown" ]]; then
            continue
        fi

        # Extract CVEs
        local cves
        cves=$(extract_cves_from_changelog "$package")

        # Calculate max CVSS
        local max_cvss
        max_cvss=$(calculate_max_cvss "$cves")

        # Classify severity
        local severity
        severity=$(classify_severity "$max_cvss")

        # Check CISA KEV
        local in_kev
        in_kev=$(check_any_cve_in_kev "$cves")

        # Validate max_cvss
        if ! echo "$max_cvss" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
            max_cvss="0.0"
        fi

        # Build package entry
        local pkg_entry
        pkg_entry=$(jq -n \
            --arg pkg "$package" \
            --arg inst_ver "$installed_version" \
            --arg cand_ver "$candidate_version" \
            --arg pocket "$pocket" \
            --argjson cves "$cves" \
            --argjson cvss "$max_cvss" \
            --arg sev "$severity" \
            --argjson kev "$in_kev" \
            '{
                package: $pkg,
                installed_version: $inst_ver,
                candidate_version: $cand_ver,
                source_pocket: $pocket,
                cves: $cves,
                max_cvss: $cvss,
                severity: $sev,
                in_cisa_kev: $kev
            }')

        packages_json=$(echo "$packages_json" | jq ". + [$pkg_entry]")
        vuln_count=$((vuln_count + 1))

    done < "$upgradable_file"

    # Write final inventory
    jq -n \
        --argjson pkgs "$packages_json" \
        --argjson total "$total_packages" \
        --argjson vuln "$vuln_count" \
        --arg mode "$mode" \
        '{
            generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
            total_packages_scanned: $total,
            vulnerable_packages: $vuln,
            mode: $mode,
            note: "Full online scan with repository data",
            packages: $pkgs
        }' > "$OUTPUT_FILE"

    log "Total packages scanned: $total_packages"
    log "Vulnerable packages found: $vuln_count"
    log "Inventory saved to: $OUTPUT_FILE"

    rm -f "$pkg_list" "$upgradable_file"
}

main() {
    log "Starting vulnerability inventory scan..."

    validate_prerequisites

    refresh_package_lists

    build_vulnerability_inventory

    log "Vulnerability inventory complete."
}

main "$@"
