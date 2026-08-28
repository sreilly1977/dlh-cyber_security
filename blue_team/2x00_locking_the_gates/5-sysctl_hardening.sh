#!/bin/bash
#
# Name: 5-sysctl_hardening.sh
# Purpose: Apply sysctl security hardening parameters
#          Capstone task T3 - Defensible Endpoint Package (extension)
# Author: Steve - Cybersecurity Engineer
# Date: 20 August 2026
# Exit Codes: 0=success, 1=controlled failure, 2=environment error
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly SYSCTL_CONF="/etc/sysctl.d/99-meddefense.conf"
readonly BACKUP_DIR="/var/backups/sysctl"

log_info() {
    echo "[$SCRIPT_NAME][INFO] $*" >&2
}

log_error() {
    echo "[$SCRIPT_NAME][ERROR] $*" >&2
}

ensure_backup() {
    log_info "Creating backup directory..."
    mkdir -p "$BACKUP_DIR"

    if [[ -f "$SYSCTL_CONF" ]]; then
        cp "$SYSCTL_CONF" "${BACKUP_DIR}/99-meddefense.conf.$(date +%Y%m%d%H%M%S)"
        log_info "Backup created in $BACKUP_DIR"
    fi
}

apply_sysctl_values() {
    log_info "Applying sysctl hardening parameters..."

    cat > "$SYSCTL_CONF" << 'EOF'
# ============================================
# MedDefense Sysctl Hardening Profile
# Capstone Task T3 - Defensible Endpoint Package
# ============================================

# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Redirect Settings
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Source Routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# ICMP Configuration
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Reverse Path Filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# TCP Hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# IPv6 Disabled
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Address Space Layout Randomization
kernel.randomize_va_space = 2

# Core Dumps
fs.suid_dumpable = 0

# Exec Shield
kernel.exec-shield = 1

# ptrace Scope Restriction
kernel.yama.ptrace_scope = 2

# KASLR Pointer Restriction
kernel.kptr_restrict = 2

# Perf Events Paranoid
kernel.perf_event_paranoid = 2

# Protected Symlinks and Hardlinks
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Magic Sysrq
kernel.sysrq = 0

# Core Dump Handler
kernel.core_pattern = /dev/null

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ARP filtering
net.ipv4.conf.all.arp_filter = 1
net.ipv4.conf.default.arp_filter = 1

# TCP Memory Management
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_rmem = 4096 87380 6291456
net.ipv4.tcp_wmem = 4096 65536 6291456
EOF

    log_info "Sysctl configuration written to $SYSCTL_CONF"
}

load_sysctl_rules() {
    log_info "Loading sysctl rules..."

    if ! sysctl --system >/dev/null 2>&1; then
        log_error "Failed to load sysctl rules"
        return 1
    fi

    log_info "Sysctl rules loaded successfully"
}

validate_sysctl_values() {
    log_info "Validating sysctl values..."

    local failed=0

    # Check key hardening parameters
    local ip_forward
    ip_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "-1")"
    if [[ "$ip_forward" != "0" ]]; then
        log_error "net.ipv4.ip_forward is $ip_forward (expected 0)"
        failed=1
    fi

    local va_space
    va_space="$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "-1")"
    if [[ "$va_space" != "2" ]]; then
        log_error "kernel.randomize_va_space is $va_space (expected 2)"
        failed=1
    fi

    local rp_filter
    rp_filter="$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo "-1")"
    if [[ "$rp_filter" != "1" ]]; then
        log_error "net.ipv4.conf.all.rp_filter is $rp_filter (expected 1)"
        failed=1
    fi

    if [[ $failed -eq 0 ]]; then
        log_info "All sysctl values validated successfully"
        return 0
    else
        log_error "Some sysctl values did not match expected state"
        return 1
    fi
}

main() {
    log_info "Starting sysctl hardening..."

    ensure_backup
    apply_sysctl_values
    load_sysctl_rules
    validate_sysctl_values

    log_info "Sysctl hardening completed successfully"
    exit 0
}

main "$@"
