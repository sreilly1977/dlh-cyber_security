#!/bin/bash
#
# Name:        6-log_source_map.sh
# Purpose:     Inventory all active log sources on the hardened Linux system
# Author:      Steve - Cybersecurity Engineer
# Date:        August 8, 2026
#
# Output columns: Source, Path, Format, Rotation, Events/hr, Relevance
# Description: Discovers log sources and documents their location, format type,
#              rotation policy, security relevance, and estimated events/hr.

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

readonly LOG_SOURCES=(
    "auth.log:/var/log/auth.log:syslog"
    "syslog:/var/log/syslog:syslog"
    "audit.log:/var/log/audit/audit.log:audit"
    "kern.log:/var/log/kern.log:syslog"
    "dpkg.log:/var/log/dpkg.log:custom"
    "apache2_access:/var/log/apache2/access.log:combined"
    "apache2_error:/var/log/apache2/error.log:custom"
    "boot.log:/var/log/boot.log:custom"
    "cron.log:/var/log/cron.log:syslog"
    "messages:/var/log/messages:syslog"
)

declare -A FORMAT_DESCRIPTIONS=(
    ["syslog"]="RFC 5424 syslog"
    ["audit"]="Linux audit daemon structured"
    ["json"]="JSON structured"
    ["combined"]="Apache combined log format"
    ["custom"]="Custom application format"
)

declare -A SECURITY_RELEVANCE=(
    ["auth.log"]="critical"
    ["syslog"]="high"
    ["audit.log"]="critical"
    ["kern.log"]="medium"
    ["dpkg.log"]="medium"
    ["apache2_access"]="high"
    ["apache2_error"]="high"
    ["boot.log"]="low"
    ["cron.log"]="medium"
    ["messages"]="high"
)

# ── Functions ─────────────────────────────────────────────────────────────────

# Estimate events/hr for a given log source
log_info() {
    echo "[*] $*"
}

get_file_size_mb() {
    local path="$1"
    if [[ -f "$path" ]]; then
        local size_bytes
        size_bytes=$(stat -c%s "$path" 2>/dev/null || echo 0)
        echo "scale=1; $size_bytes / 1048576" | bc 2>/dev/null || echo "N/A"
    else
        echo "0"
    fi
}

get_rotation_policy() {
    local path="$1"
    local basename
    basename=$(basename "$path")

    # Check logrotate configs for this file
    local rotation_days="N/A"
    while IFS= read -r config; do
        if [[ -f "$config" ]]; then
            # Try to extract rotate count from config
            local rotate_count
            rotate_count=$(grep -E '^\s*rotate\s+' "$config" 2>/dev/null | head -1 | awk '{print $2}')
            if [[ -n "$rotate_count" && "$rotate_count" != "N/A" ]]; then
                # Convert rotate count to days (assuming weekly rotation)
                rotation_days=$((rotate_count * 7))
            fi
        fi
    done < <(find /etc/logrotate.d /etc/logrotate.conf -name '*' 2>/dev/null | grep -v "^Binary")

    # Check if logrotate manages this file
    if logrotate -d "$path" 2>&1 | grep -qi "error\|does not exist"; then
        rotation_days="unmanaged"
    fi

    echo "$rotation_days"
}

estimate_events_per_hour() {
    local path="$1"
    local basename
    basename=$(basename "$path")

    # Get last modified time
    if [[ ! -f "$path" ]]; then
        echo "<1"
        return
    fi

    local mtime
    mtime=$(stat -c%Y "$path" 2>/dev/null || echo 0)
    local now
    now=$(date +%s)
    local age_seconds=$((now - mtime))

    # Calculate age in hours (minimum 1 to avoid division by zero)
    local age_hours=$((age_seconds / 3600))
    if [[ $age_hours -lt 1 ]]; then
        age_hours=1
    fi

    # Estimate based on file size and typical event sizes
    local file_bytes
    file_bytes=$(stat -c%s "$path" 2>/dev/null || echo 0)

    # Estimate lines based on average line length (80 bytes)
    local line_count=$((file_bytes / 80))
    local events_per_hour=$((line_count / age_hours))

    # Apply adjustments based on log type
    case "$basename" in
        "access.log"|*access*)
            # Web access logs tend to be high volume
            events_per_hour=$((events_per_hour * 2))
            ;;
        "auth.log"|*auth*)
            # Auth logs are lower volume but security-critical
            events_per_hour=$((events_per_hour / 2))
            ;;
        "audit.log"*|audit*)
            # Audit logs vary widely based on rules configured
            events_per_hour=$((events_per_hour * 3))
            ;;
    esac

    # Clamp to reasonable range
    if [[ $events_per_hour -lt 1 ]]; then
        echo "<1"
    elif [[ $events_per_hour -gt 10000 ]]; then
        echo ">10000"
    else
        echo "$events_per_hour"
    fi
}

get_relevance_rating() {
    local name="$1"
    echo "${SECURITY_RELEVANCE[$name]:-low}"
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

main() {
    log_info "Discovering log sources..."

    # Print header with Events/hr column (matches expected output format)
    printf "%-20s %-30s %-12s %-12s %-12s %-12s\n" \
        "Source" "Path" "Format" "Rotation" "Events/hr" "Relevance"
    printf "%-20s %-30s %-12s %-12s %-12s %-12s\n" \
        "--------------------" "------------------------------" \
        "------------" "------------" "------------" "------------"

    local sources_found=0
    local sources_missing=0
    declare -a missing_sources

    for source_entry in "${LOG_SOURCES[@]}"; do
        IFS=':' read -r name path format <<< "$source_entry"

        if [[ -f "$path" ]]; then
            local size_mb
            size_mb=$(get_file_size_mb "$path")

            local rotation
            rotation=$(get_rotation_policy "$path")

            local events_hr
            events_hr=$(estimate_events_per_hour "$path")

            local relevance
            relevance=$(get_relevance_rating "$name")

            printf "%-20s %-30s %-12s %-12s %-12s %-12s\n" \
                "$name" "$path" "$format" "${rotation} days" "$events_hr" "$relevance"
            ((sources_found++)) || true
        else
            missing_sources+=("$name ($path)")
            ((sources_missing++)) || true
        fi
    done

    echo ""
    echo "Sources found: $sources_found | Missing: $sources_missing"

    if [[ $sources_missing -gt 0 ]]; then
        echo ""
        log_info "Missing expected sources:"
        for missing in "${missing_sources[@]}"; do
            echo "  - $missing"
        done
    fi

    # Return non-zero if critical sources are missing
    local critical_missing=0
    for source_entry in "${LOG_SOURCES[@]}"; do
        IFS=':' read -r name path _ <<< "$source_entry"
        if [[ ! -f "$path" ]] && [[ "${SECURITY_RELEVANCE[$name]}" == "critical" ]]; then
            ((critical_missing++)) || true
        fi
    done

    if [[ $critical_missing -gt 0 ]]; then
        echo ""
        echo "[!] WARNING: $critical_missing critical log source(s) are missing or inactive"
        exit 1
    fi
}

main "$@"
