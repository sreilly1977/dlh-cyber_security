#!/bin/bash
#
# Name:        2-pre_patch_snapshot.sh
# Purpose:     Capture full system state before patch operations for validation and rollback
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly OUTPUT_FILE="${BASE_DIR}/pre_patch_state.json"

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

capture_packages_to_file() {
    local output_file="$1"
    log "Capturing package versions..."

    dpkg-query -W -f='${binary:Package}\t${Version}\n' 2>/dev/null | \
        jq -R -s 'split("\n") | map(select(length > 0)) | map(split("\t")) |
            map({package: .[0], version: .[1]})' > "$output_file"

    if [[ ! -s "$output_file" ]]; then
        echo '[]' > "$output_file"
    fi
}

capture_services_to_file() {
    local output_file="$1"
    log "Capturing service states..."

    local services_json='['
    local first=true
    local active_services

    active_services=$(systemctl list-units --type=service --state=active \
        --no-pager --no-legend 2>/dev/null | awk '{print $1}')

    if [[ -z "$active_services" ]]; then
        echo '[]' > "$output_file"
        return
    fi

    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue

        local active_state
        local sub_state
        local main_pid

        active_state=$(systemctl show "$svc" --property=ActiveState --value 2>/dev/null || echo "unknown")
        sub_state=$(systemctl show "$svc" --property=SubState --value 2>/dev/null || echo "unknown")
        main_pid=$(systemctl show "$svc" --property=MainPID --value 2>/dev/null || echo "0")

        local entry
        entry=$(jq -n \
            --arg svc "$svc" \
            --arg active "$active_state" \
            --arg sub "$sub_state" \
            --arg pid "$main_pid" \
            '{service: $svc, active_state: $active, sub_state: $sub, main_pid: $pid}')

        if [[ "$first" == true ]]; then
            services_json="${services_json}${entry}"
            first=false
        else
            services_json="${services_json},${entry}"
        fi

    done <<< "$active_services"

    services_json="${services_json}]"
    echo "$services_json" > "$output_file"
}

capture_listening_to_file() {
    local output_file="$1"
    log "Capturing listening sockets..."

    local listening_json='['
    local first=true

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local proto
        local local_addr
        local port
        local process

        proto=$(echo "$line" | awk '{print $1}')
        local_addr=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f2- | rev)
        port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        process=$(echo "$line" | awk '{for(i=7;i<=NF;i++) printf "%s ", $i; print ""}' | sed 's/ *$//')

        local entry
        entry=$(jq -n \
            --arg proto "$proto" \
            --arg addr "$local_addr" \
            --arg port "$port" \
            --arg proc "$process" \
            '{protocol: $proto, local_address: $addr, port: $port, process: $proc}')

        if [[ "$first" == true ]]; then
            listening_json="${listening_json}${entry}"
            first=false
        else
            listening_json="${listening_json},${entry}"
        fi

    done < <(ss -tulnp 2>/dev/null | tail -n +2)

    listening_json="${listening_json}]"
    echo "$listening_json" > "$output_file"
}

capture_conffile_hashes_to_file() {
    local output_file="$1"
    log "Capturing configuration file hashes..."

    local conffiles_temp
    conffiles_temp=$(mktemp)
    local processed=0

    local packages
    packages=$(dpkg-query -W -f='${binary:Package}\n' 2>/dev/null)

    local total_packages
    total_packages=$(echo "$packages" | wc -l)
    log "Scanning conffiles for $total_packages packages..."

    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue

        processed=$((processed + 1))

        if (( processed % 200 == 0 )); then
            log "  Conffile scan: $processed/$total_packages packages..."
        fi

        # Get conffiles for this package (files under /etc only)
        local conffiles
        conffiles=$(dpkg-query -W -f='${Conffiles}\n' "$pkg" 2>/dev/null | \
            tr ' ' '\n' | grep '^/etc/' | awk '{print $1}' || echo "")

        if [[ -z "$conffiles" ]]; then
            continue
        fi

        while IFS= read -r conf; do
            [[ -z "$conf" ]] && continue
            [[ ! -f "$conf" ]] && continue

            local sha
            sha=$(sha256sum "$conf" 2>/dev/null | awk '{print $1}')

            if [[ -n "$sha" ]]; then
                printf '%s\t%s\t%s\n' "$pkg" "$conf" "$sha" >> "$conffiles_temp"
            fi

        done <<< "$conffiles"

    done <<< "$packages"

    if [[ -s "$conffiles_temp" ]]; then
        jq -R -s 'split("\n") | map(select(length > 0)) |
            map(split("\t")) | map({
                package: .[0],
                file: .[1],
                sha256: .[2]
            })' "$conffiles_temp" > "$output_file"
    else
        echo '[]' > "$output_file"
    fi

    rm -f "$conffiles_temp"
}

capture_kernel() {
    uname -r 2>/dev/null || echo "unknown"
}

capture_reboot_required() {
    if [[ -f /var/run/reboot-required ]]; then
        echo "true"
    else
        echo "false"
    fi
}

main() {
    log "Starting pre-patch snapshot..."

    # Create temp files for arrays
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local packages_file="${tmp_dir}/packages.json"
    local services_file="${tmp_dir}/services.json"
    local listening_file="${tmp_dir}/listening.json"
    local conffiles_file="${tmp_dir}/conffiles.json"

    # Capture all state to files
    capture_packages_to_file "$packages_file"
    capture_services_to_file "$services_file"
    capture_listening_to_file "$listening_file"
    capture_conffile_hashes_to_file "$conffiles_file"

    # Get counts
    local pkg_count
    local svc_count
    local listening_count
    local hash_count

    pkg_count=$(jq 'length' "$packages_file" 2>/dev/null || echo 0)
    svc_count=$(jq 'length' "$services_file" 2>/dev/null || echo 0)
    listening_count=$(jq 'length' "$listening_file" 2>/dev/null || echo 0)
    hash_count=$(jq 'length' "$conffiles_file" 2>/dev/null || echo 0)

    # Assemble final JSON using jq --slurpfile to read arrays from files
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    local kernel_val
    kernel_val=$(capture_kernel)

    local reboot_req
    reboot_req=$(capture_reboot_required)

    jq -n \
        --arg ts "$timestamp" \
        --arg host "$hostname_val" \
        --arg kernel "$kernel_val" \
        --arg reboot "$reboot_req" \
        --argjson pkg_count "$pkg_count" \
        --argjson svc_count "$svc_count" \
        --argjson listening_count "$listening_count" \
        --argjson hash_count "$hash_count" \
        --slurpfile packages "$packages_file" \
        --slurpfile services "$services_file" \
        --slurpfile listening "$listening_file" \
        --slurpfile conffiles "$conffiles_file" \
        '{
            timestamp: $ts,
            hostname: $host,
            kernel: $kernel,
            reboot_required: $reboot,
            packages: {
                count: $pkg_count,
                list: $packages[0]
            },
            services: {
                count: $svc_count,
                list: $services[0]
            },
            listening: $listening[0],
            conffile_hashes: {
                count: $hash_count,
                list: $conffiles[0]
            }
        }' > "$OUTPUT_FILE"

    # Cleanup temp files
    rm -rf "$tmp_dir"

    local size_kb
    size_kb=$(du -k "$OUTPUT_FILE" | cut -f1)

    log "Snapshot: $OUTPUT_FILE"
    log "Size: ${size_kb} KB"
    log "Kernel: $kernel_val"
    log "Reboot required: $reboot_req"
    log "Packages: $pkg_count"
    log "Services: $svc_count"
    log "Listening sockets: $listening_count"
    log "Conffile hashes: $hash_count"
}

main "$@"
