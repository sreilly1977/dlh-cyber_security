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

    # Attempt update with timeout (may fail offline, continue anyway)
    if timeout "$APT_TIMEOUT" apt-get update -qq 2>/dev/null; then
        log "Package lists refreshed successfully"
        return 0
    else
        warn "Package list refresh timed out or failed (may be offline)"
        log "Continuing with cached data..."
        return 0
    fi
}

enumerate_installed_packages() {
    # Get all installed packages from local dpkg database
    dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | sort
}

get_candidate_version_online() {
    local package="$1"
    local candidate=""

    # Try to get candidate from apt-cache with timeout
    candidate=$(timeout "$TIMEOUT_SECONDS" bash -c "apt-cache policy \"$package\"" 2>/dev/null | \
        awk '/Candidate:/{print $2}' | head -1 || echo "")

    echo "${candidate:-}"
}

get_source_pocket_online() {
    local package="$1"
    local pocket=""

    # Try to get source pocket from apt-cache policy with timeout
    pocket=$(timeout "$TIMEOUT_SECONDS" bash -c "apt-cache policy \"$package\"" 2>/dev/null | \
        grep -E '(security|updates|backports)' | head -1 | \
        grep -oE '[a-z]+-(security|updates|backports)' | head -1 || echo "")

    echo "${pocket:-unknown}"
}

extract_cves_from_changelog_online() {
    local package="$1"
    local cves='[]'
    local changelog=""

    # Try to get changelog from apt-get with timeout
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

    # Final safety check
    if ! echo "$cves" | jq -e . >/dev/null 2>&1; then
        cves='[]'
    fi

    echo "$cves"
}

get_cvss_for_cve_local() {
    local cve="$1"

    if [[ ! -f "$CVE_FEED" ]]; then
        echo "0.0"
        return
    fi

    local cvss
    cvss=$(timeout "$TIMEOUT_SECONDS" bash -c \
        "jq -r --arg cve \"$cve\" '.cves[\$cve].cvss // 0' \"$CVE_FEED\"" 2>/dev/null || echo "0")

    if ! echo "$cvss" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
        cvss="0.0"
    fi

    echo "$cvss"
}

check_cisa_kev_for_cve_local() {
    local cve="$1"

    if [[ ! -f "$CISA_KEV" ]]; then
        echo "false"
        return
    fi

    local result
    result=$(timeout "$TIMEOUT_SECONDS" bash -c \
        "jq -r --arg cve \"$cve\" '.[\$cve].active // false' \"$CISA_KEV\"" 2>/dev/null || echo "false")

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
        cvss=$(get_cvss_for_cve_local "$cve")

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
        kev_status=$(check_cisa_kev_for_cve_local "$cve")
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
    local processed=0
    local packages_json='[]'
    local mode="online"

    # Check if we have network access (test against Ubuntu repo)
    local has_network=false
    if timeout 5 bash -c "dig ubuntu.com +short" >/dev/null 2>&1; then
        has_network=true
    else
        warn "No DNS resolution detected - falling back to offline mode"
        mode="offline"
    fi

    while IFS=$'\t' read -r package installed_version; do
        [[ -z "$package" ]] && continue

        processed=$((processed + 1))

        # Show progress every 100 packages
        if (( processed % 100 == 0 )); then
            log "Processing package $processed/$total_packages (vulnerable so far: $vuln_count)..."
        fi

        # Get candidate version (online)
        local candidate_version=""
        local pocket="unknown"
        local cves='[]'

        if [[ "$has_network" == true ]]; then
            candidate_version=$(get_candidate_version_online "$package")
            pocket=$(get_source_pocket_online "$package")
            cves=$(extract_cves_from_changelog_online "$package")
        fi

        # If no candidate (same version or no network), skip
        if [[ -z "$candidate_version" ]] || [[ "$candidate_version" == "$installed_version" ]]; then
            continue
        fi

        # Only process security or updates pocket packages
        if [[ "$pocket" != *"security"* ]] && [[ "$pocket" != *"updates"* ]] && [[ "$pocket" != "unknown" ]]; then
            continue
        fi

        # Calculate max CVSS
        local max_cvss
        max_cvss=$(calculate_max_cvss "$cves")

        # Classify severity
        local severity
        severity=$(classify_severity "$max_cvss")

        # Check CISA KEV
        local in_kev
        in_kev=$(check_any_cve_in_kev "$cves")

        # Ensure max_cvss is a valid number for JSON
        if ! echo "$max_cvss" | grep -qE '^[0-9]+(\.[0-9]+)?$'; then
            max_cvss="0.0"
        fi

        # Build package entry as a JSON object
        local pkg_entry
        pkg_entry=$(timeout "$TIMEOUT_SECONDS" bash -c \
            "jq -n \
                --arg pkg \"$package\" \
                --arg inst_ver \"$installed_version\" \
                --arg cand_ver \"$candidate_version\" \
                --arg pocket \"$pocket\" \
                --argjson cves \"$cves\" \
                --argjson cvss \"$max_cvss\" \
                --arg sev \"$severity\" \
                --argjson kev \"$in_kev\" \
                '{
                    package: \$pkg,
                    installed_version: \$inst_ver,
                    candidate_version: \$cand_ver,
                    source_pocket: \$pocket,
                    cves: \$cves,
                    max_cvss: \$cvss,
                    severity: \$sev,
                    in_cisa_kev: \$kev
                }'" 2>/dev/null || echo '{}')

        # Skip invalid entries
        if [[ "$pkg_entry" == "{}" ]]; then
            continue
        fi

        packages_json=$(echo "$packages_json" | jq ". + [$pkg_entry]")
        vuln_count=$((vuln_count + 1))

    done < <(enumerate_installed_packages)

    # Write final inventory
    local json_mode="online"
    if [[ "$has_network" == false ]]; then
        json_mode="offline"
    fi

    jq -n \
        --argjson pkgs "$packages_json" \
        --argjson total "$processed" \
        --argjson vuln "$vuln_count" \
        --arg mode "$json_mode" \
        '{
            generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
            total_packages_scanned: $total,
            vulnerable_packages: $vuln,
            mode: $mode,
            note: (if $mode == "offline" then "Network unavailable - using cached apt data only" else "Full online scan with repository data" end),
            packages: $pkgs
        }' > "$OUTPUT_FILE"

    log "Total packages scanned: $processed"
    log "Vulnerable packages found: $vuln_count"
    log "Mode: $json_mode"
    log "Inventory saved to: $OUTPUT_FILE"

    if [[ "$json_mode" == "offline" ]]; then
        log "NOTE: Run on connected host for complete CVE and upgrade data."
    fi
}

main() {
    log "Starting vulnerability inventory scan..."

    validate_prerequisites

    # Refresh package lists (with timeout)
    refresh_package_lists

    build_vulnerability_inventory

    log "Vulnerability inventory complete."
}

main "$@"
