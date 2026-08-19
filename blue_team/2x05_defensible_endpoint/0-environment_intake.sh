#!/bin/bash
#
# Name: 0-environment_intake.sh
# Name: 0-environment_intake.sh
# Purpose: Capture raw state of Hawthorne Linux endpoint before hardening
#          Capstone task T0 - Defensible Endpoint Package
# Author: Steve - Cybersecurity Engineer
# Exit Codes: 0=success, 1=controlled failure, 2=environment error
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly INTAKE_DIR="/home/analyst/scripts/"
readonly INTAKE_FILE="${INTAKE_DIR}/intake_${TIMESTAMP}.json"

cleanup() {
    local exit_code="$?"
    if [[ $exit_code -ne 0 ]]; then
        echo "[$SCRIPT_NAME] Script exited with code $exit_code" >&2
    fi
    exit "$exit_code"
}

trap cleanup EXIT

log_info() {
    echo "[$SCRIPT_NAME][INFO] $*" >&2
}

log_error() {
    echo "[$SCRIPT_NAME][ERROR] $*" >&2
}

validate_environment() {
    log_info "Validating execution environment..."

    if [[ ! -r /etc/os-release ]]; then
        log_error "Cannot read /etc/os-release"
        exit 2
    fi

    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is not installed - required for JSON output"
        exit 2
    fi

    if ! command -v dpkg-query >/dev/null 2>&1; then
        log_error "dpkg-query not found - this script expects Debian-based systems"
        exit 2
    fi

    if ! command -v ss >/dev/null 2>&1; then
        log_error "ss command not found - iproute2 package required"
        exit 2
    fi

    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges"
        exit 2
    fi

    log_info "Environment validation complete"
}

ensure_directories() {
    log_info "Creating intake directory structure..."

    mkdir -p "$INTAKE_DIR" || {
        log_error "Failed to create intake directory: $INTAKE_DIR"
        exit 2
    }

    chmod 700 "$INTAKE_DIR" || {
        log_error "Failed to set permissions on intake directory"
        exit 1
    }

    log_info "Directory ready: $INTAKE_DIR"
}

capture_host_info() {
    log_info "Capturing host information..."

    local hostname_val kernel_release dist_name dist_version patch_level

    hostname_val="$(hostname 2>/dev/null || echo "unknown")"
    kernel_release="$(uname -r 2>/dev/null || echo "unknown")"

    dist_name="unknown"
    dist_version="unknown"
    if [[ -r /etc/os-release ]]; then
        dist_name="$(grep -E '^NAME=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "unknown")"
        dist_version="$(grep -E '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "unknown")"
    fi

    patch_level="$(dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort -u | tail -5 || echo "")"

    jq -n \
        --arg ts "$TIMESTAMP" \
        --arg hn "$hostname_val" \
        --arg kr "$kernel_release" \
        --arg dn "$dist_name" \
        --arg dv "$dist_version" \
        --arg pl "$patch_level" \
        '{
            timestamp: $ts,
            host_info: {
                hostname: $hn,
                kernel_release: $kr,
                distribution_name: $dn,
                distribution_version: $dv,
                recent_patches: ($pl | split("\n") | map(select(length > 0)))
            }
        }'
}

capture_package_count() {
    log_info "Counting installed packages..."

    local pkg_count
    pkg_count="$(dpkg-query -W -f='.\\n' 2>/dev/null | wc -l || echo "0")"

    jq -n --argjson count "$pkg_count" '{package_count: $count}'
}

capture_listening_sockets() {
    log_info "Capturing listening sockets..."

    local sockets_json
    sockets_json="$(ss -tulnpH 2>/dev/null | awk '
        {
            proto = $1
            local_addr = $5
            process = $7
            gsub(/^users:\(\("/, "", process)
            gsub(/".*/, "", process)
            if (process == "") process = "unknown"
            printf "{\"protocol\": \"%s\", \"local_address\": \"%s\", \"process\": \"%s\"}\n", proto, local_addr, process
        }' 2>/dev/null | jq -s '.' 2>/dev/null || echo "[]")"

    jq -n --argjson sockets "$sockets_json" '{listening_sockets: $sockets}'
}

capture_systemd_services() {
    log_info "Capturing active systemd services..."

    local services_json
    services_json="$(systemctl list-units --type=service --state=active --no-legend 2>/dev/null | awk '
        {
            name = $1
            gsub(/\.service$/, "", name)
            printf "\"%s\"\n", name
        }' 2>/dev/null | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo "[]")"

    jq -n --argjson services "$services_json" '{active_services: $services}'
}

capture_sshd_config() {
    log_info "Capturing SSH configuration..."

    local sshd_conf="/etc/ssh/sshd_config"
    local config_hash="unavailable"

    if [[ ! -r "$sshd_conf" ]]; then
        jq -n '{sshd_config: null, sshd_config_exists: false}'
        return 0
    fi

    config_hash="$(sha256sum "$sshd_conf" 2>/dev/null | cut -d' ' -f1 || echo "unavailable")"

    local sshd_kv_json
    sshd_kv_json="$(grep -E '^[[:space:]]*[A-Za-z]+' "$sshd_conf" 2>/dev/null \
        | sed 's/^[[:space:]]*//' \
        | sed 's/[[:space:]]*#.*$//' \
        | grep -v '^[[:space:]]*$' \
        | awk '
            {
                split($0, arr, /[[:space:]]+/)
                key = arr[1]
                val = ""
                for (i = 2; i <= length(arr); i++) {
                    val = val (i > 2 ? " " : "") arr[i]
                }
                if (key != "" && key !~ /^#/) {
                    printf "\"%s\": \"%s\"", key, val
                    if (NR > 0) printf ", "
                }
            }' 2>/dev/null || echo "")"

    if [[ -z "$sshd_kv_json" ]]; then
        sshd_kv_json="{}"
    fi

    local sshd_obj
    sshd_obj="$(echo "{${sshd_kv_json}}" | jq '.' 2>/dev/null || echo "{}")"

    jq -n \
        --arg path "$sshd_conf" \
        --arg hash "$config_hash" \
        --argjson kv "$sshd_obj" \
        '{
            sshd_config_exists: true,
            sshd_config_path: $path,
            sshd_config_sha256: $hash,
            sshd_config_kv: $kv
        }'
}

capture_sysctl_params() {
    log_info "Capturing sysctl security parameters..."

    local sysctl_output
    sysctl_output="$(sysctl -a 2>/dev/null | grep -E \
        'net.ipv4.ip_forward|net.ipv4.conf.all.send_redirects|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.accept_source_route|net.ipv4.tcp_syncookies|net.ipv6.conf.all.accept_redirects|net.ipv6.conf.all.disabled|kernel.randomize_va_space|kernel.exec|kernel.shm|kernel.msg|kernel.sem|kernel.core|kernel.ptrace|kernel.sysrq|fs.suid_dumpable|fs.protected_symlinks|fs.protected_hardlinks|fs.protected_fifos|fs.protected_regular' \
        || echo "")"

    if [[ -z "$sysctl_output" ]]; then
        jq -n '{sysctl_params: {}}'
        return 0
    fi

    local sysctl_json
    sysctl_json="$(echo "$sysctl_output" | jq -R '
        capture("^(?<key>[^=]+)=(?<val>.*)$")
        | {key: (.key | gsub("^\\s+|\\s+$"; "")), value: (.val | gsub("^\\s+|\\s+$"; ""))}
    ' | jq -s 'from_entries' 2>/dev/null || echo "{}")"

    jq -n --argjson params "$sysctl_json" '{sysctl_params: $params}'
}

capture_suid_sgid_binaries() {
    log_info "Counting SUID/SGID binaries..."

    local suid_sgid_list
    suid_sgid_list="$(find / -perm /6000 -type f 2>/dev/null || echo "")"
    local total_count
    total_count="$(echo "$suid_sgid_list" | grep -c '.' || echo "0")"

    local suid_count sgid_count
    suid_count="$(find / -perm /4000 -type f 2>/dev/null | wc -l || echo "0")"
    sgid_count="$(find / -perm /2000 -type f 2>/dev/null | wc -l || echo "0")"

    jq -n \
        --argjson suid "$suid_count" \
        --argjson sgid "$sgid_count" \
        --argjson total "$total_count" \
        '{suid_binaries: $suid, sgid_binaries: $sgid, total_setuid_setgid: $total}'
}

capture_world_writable_files() {
    log_info "Counting world-writable files..."

    local ww_count
    ww_count="$(find / -xdev -path /proc -prune -o -path /sys -prune -o -perm -0002 -type f -print 2>/dev/null | wc -l || echo "0")"

    jq -n --argjson count "$ww_count" '{world_writable_files: $count}'
}

capture_firewall_status() {
    log_info "Capturing firewall status..."

    local nft_ruleset_lines="0"
    local firewall_active="false"

    if command -v nft >/dev/null 2>&1; then
        nft_ruleset_lines="$(nft list ruleset 2>/dev/null | wc -l || echo "0")"
        if [[ "$nft_ruleset_lines" -gt 0 ]]; then
            firewall_active="true"
        fi
    elif command -v iptables >/dev/null 2>&1; then
        nft_ruleset_lines="$(iptables -L -n 2>/dev/null | wc -l || echo "0")"
        if [[ "$nft_ruleset_lines" -gt 0 ]]; then
            firewall_active="true"
        fi
    fi

    jq -n \
        --argjson lines "$nft_ruleset_lines" \
        --argjson active "$firewall_active" \
        '{firewall_ruleset_line_count: $lines, firewall_active: $active}'
}

capture_telemetry_presence() {
    log_info "Capturing telemetry agent presence (auditd, rsyslog, Sysmon)..."

    local auditd_running="false"
    local rsyslog_running="false"
    local sysmon_installed="false"

    if systemctl is-active --quiet auditd 2>/dev/null; then
        auditd_running="true"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        rsyslog_running="true"
    fi

    # Check for Sysmon-for-Linux
    if dpkg-query -W -f='${Status}' sysmon-for-linux 2>/dev/null | grep -q "install ok installed"; then
        sysmon_installed="true"
    elif [[ -d "/opt/sysmon" ]] || [[ -f "/usr/bin/sysmon" ]]; then
        sysmon_installed="true"
    fi

    jq -n \
        --argjson auditd "$auditd_running" \
        --argjson rsyslog "$rsyslog_running" \
        --argjson sysmon "$sysmon_installed" \
        '{
            telemetry: {
                auditd_running: $auditd,
                rsyslog_running: $rsyslog,
                sysmon_for_linux_present: $sysmon
            }
        }'
}capture_telemetry_presence() {
    log_info "Capturing telemetry agent presence (auditd, rsyslog, Sysmon)..."

    local auditd_running="false"
    local rsyslog_running="false"
    local sysmon_installed="false"

    if systemctl is-active --quiet auditd 2>/dev/null; then
        auditd_running="true"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        rsyslog_running="true"
    fi

    # Check for Sysmon-for-Linux
    if dpkg-query -W -f='${Status}' sysmon-for-linux 2>/dev/null | grep -q "install ok installed"; then
        sysmon_installed="true"
    elif [[ -d "/opt/sysmon" ]] || [[ -f "/usr/bin/sysmon" ]]; then
        sysmon_installed="true"
    fi

    jq -n \
        --argjson auditd "$auditd_running" \
        --argjson rsyslog "$rsyslog_running" \
        --argjson sysmon "$sysmon_installed" \
        '{
            telemetry: {
                auditd_running: $auditd,
                rsyslog_running: $rsyslog,
                sysmon_for_linux_present: $sysmon
            }
        }'
}capture_telemetry_presence() {
    log_info "Capturing telemetry agent presence (auditd, rsyslog, Sysmon)..."

    local auditd_running="false"
    local rsyslog_running="false"
    local sysmon_installed="false"

    if systemctl is-active --quiet auditd 2>/dev/null; then
        auditd_running="true"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        rsyslog_running="true"
    fi

    # Check for Sysmon-for-Linux
    if dpkg-query -W -f='${Status}' sysmon-for-linux 2>/dev/null | grep -q "install ok installed"; then
        sysmon_installed="true"
    elif [[ -d "/opt/sysmon" ]] || [[ -f "/usr/bin/sysmon" ]]; then
        sysmon_installed="true"
    fi

    jq -n \
        --argjson auditd "$auditd_running" \
        --argjson rsyslog "$rsyslog_running" \
        --argjson sysmon "$sysmon_installed" \
        '{
            telemetry: {
                auditd_running: $auditd,
                rsyslog_running: $rsyslog,
                sysmon_for_linux_present: $sysmon
            }
        }'
}capture_telemetry_presence() {
    log_info "Capturing telemetry agent presence (auditd, rsyslog, Sysmon)..."

    local auditd_running="false"
    local rsyslog_running="false"
    local sysmon_installed="false"

    if systemctl is-active --quiet auditd 2>/dev/null; then
        auditd_running="true"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        rsyslog_running="true"
    fi

    # Check for Sysmon-for-Linux
    if dpkg-query -W -f='${Status}' sysmon-for-linux 2>/dev/null | grep -q "install ok installed"; then
        sysmon_installed="true"
    elif [[ -d "/opt/sysmon" ]] || [[ -f "/usr/bin/sysmon" ]]; then
        sysmon_installed="true"
    fi

    jq -n \
        --argjson auditd "$auditd_running" \
        --argjson rsyslog "$rsyslog_running" \
        --argjson sysmon "$sysmon_installed" \
        '{
            telemetry: {
                auditd_running: $auditd,
                rsyslog_running: $rsyslog,
                sysmon_for_linux_present: $sysmon
            }
        }'
}capture_telemetry_presence() {
    log_info "Capturing telemetry agent presence (auditd, rsyslog, Sysmon)..."

    local auditd_running="false"
    local rsyslog_running="false"
    local sysmon_installed="false"

    if systemctl is-active --quiet auditd 2>/dev/null; then
        auditd_running="true"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        rsyslog_running="true"
    fi

    # Check for Sysmon-for-Linux
    if dpkg-query -W -f='${Status}' sysmon-for-linux 2>/dev/null | grep -q "install ok installed"; then
        sysmon_installed="true"
    elif [[ -d "/opt/sysmon" ]] || [[ -f "/usr/bin/sysmon" ]]; then
        sysmon_installed="true"
    fi

    jq -n \
        --argjson auditd "$auditd_running" \
        --argjson rsyslog "$rsyslog_running" \
        --argjson sysmon "$sysmon_installed" \
        '{
            telemetry: {
                auditd_running: $auditd,
                rsyslog_running: $rsyslog,
                sysmon_for_linux_present: $sysmon
            }
        }'
}

write_intake_record() {
    log_info "Assembling intake record..."

    local host_info package_count listening_sockets systemd_services
    local sshd_config sysctl_params suid_sgid world_writable firewall_status telemetry

    host_info="$(capture_host_info)"
    package_count="$(capture_package_count)"
    listening_sockets="$(capture_listening_sockets)"
    systemd_services="$(capture_systemd_services)"
    sshd_config="$(capture_sshd_config)"
    sysctl_params="$(capture_sysctl_params)"
    suid_sgid="$(capture_suid_sgid_binaries)"
    world_writable="$(capture_world_writable_files)"
    firewall_status="$(capture_firewall_status)"
    telemetry="$(capture_telemetry_presence)"

    local temp_file
    temp_file="$(mktemp)" || { log_error "Failed to create temp file"; exit 2; }

    {
        echo "$host_info"
        echo "$package_count"
        echo "$listening_sockets"
        echo "$systemd_services"
        echo "$sshd_config"
        echo "$sysctl_params"
        echo "$suid_sgid"
        echo "$world_writable"
        echo "$firewall_status"
        echo "$telemetry"
    } | jq -s 'add' > "$temp_file"

    if ! jq '.' "$temp_file" > "$INTAKE_FILE" 2>/dev/null; then
        log_error "Failed to write valid JSON to intake file"
        rm -f "$temp_file"
        exit 1
    fi

    rm -f "$temp_file"

    log_info "Intake record written: $INTAKE_FILE"
    log_info "Record hash: $(sha256sum "$INTAKE_FILE" | cut -d' ' -f1)"
}

main() {
    log_info "Starting capstone environment intake for Hawthorne Linux endpoint..."
    log_info "Timestamp: $TIMESTAMP"

    validate_environment
    ensure_directories
    write_intake_record

    log_info "Capstone environment intake completed successfully"
    exit 0
}

main "$@"
