#!/bin/bash

# 5-sysctl_hardening.sh — Harden Linux kernel network stack and memory protections
#                         to prevent the server from being used as a pivot point.
#
# Usage:  sudo ./5-sysctl_hardening.sh
# ============================================================================

set -euo pipefail

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_BAK="/etc/sysctl.conf.bak"
SETTINGS_APPLIED=0
VERIFIED_PASS=0
VERIFIED_FAIL=0

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

if [[ ! -f "$SYSCTL_CONF" ]]; then
    echo "ERROR: Sysctl config file not found at $SYSCTL_CONF" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Define sysctl settings (network stack + memory protection)
# ---------------------------------------------------------------------------

declare -a SETTINGS=(
    "net.ipv4.ip_forward = 0"
    "net.ipv4.conf.all.accept_redirects = 0"
    "net.ipv4.conf.default.accept_redirects = 0"
    "net.ipv4.conf.all.send_redirects = 0"
    "net.ipv4.conf.all.accept_source_route = 0"
    "net.ipv4.conf.all.log_martians = 1"
    "net.ipv4.tcp_syncookies = 1"
    "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    "net.ipv6.conf.all.disable_ipv6 = 1"
    "net.ipv6.conf.default.disable_ipv6 = 1"
    "kernel.randomize_va_space = 2"
    "fs.suid_dumpable = 0"
    "kernel.dmesg_restrict = 1"
    "kernel.kptr_restrict = 2"
)

# ---------------------------------------------------------------------------
# Helper: extract key and value from "key = value" string
# ---------------------------------------------------------------------------

parse_key() {
    local entry="$1"
    echo "$entry" | sed 's/[[:space:]]*=.*//' | tr -d ' '
}

parse_value() {
    local entry="$1"
    echo "$entry" | sed 's/^[^=]*=[[:space:]]*//' | tr -d ' '
}

# ---------------------------------------------------------------------------
# Helper: read current value from /proc/sys/
# ---------------------------------------------------------------------------

get_proc_value() {
    local key="$1"
    local proc_path="/proc/sys/${key//./\/}"
    if [[ -f "$proc_path" ]]; then
        cat "$proc_path" 2>/dev/null || echo "unreadable"
    else
        echo "not_found"
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Back up current sysctl.conf
# ---------------------------------------------------------------------------

echo "[*] Backing up $SYSCTL_CONF"
cp -p "$SYSCTL_CONF" "$SYSCTL_BAK"

# ---------------------------------------------------------------------------
# Step 2: Apply kernel hardening parameters
# ---------------------------------------------------------------------------

echo "[*] Applying kernel hardening parameters..."

for setting in "${SETTINGS[@]}"; do
    key=$(parse_key "$setting")
    value=$(parse_value "$setting")

    # Check if already set correctly
    current_value=$(get_proc_value "$key")

    if [[ "$current_value" == "$value" ]]; then
        printf '%-50s [SKIP]\n' "$key = $value"
        SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))
        VERIFIED_PASS=$((VERIFIED_PASS + 1))
    else
        # Add or replace in sysctl.conf
        if grep -qE "^[#[:space:]]*${key}[[:space:]]*=" "$SYSCTL_CONF" 2>/dev/null; then
            # Comment out existing line and append new one
            sed -i "/^[#[:space:]]*${key}[[:space:]]*=/c\\# Old: ${key} = ${current_value}\n${setting}" "$SYSCTL_CONF"
        else
            echo "# Hardened by 5-sysctl_hardening.sh" >> "$SYSCTL_CONF"
            echo "$setting" >> "$SYSCTL_CONF"
        fi

        # Apply immediately
        sysctl -w "$key=$value" >/dev/null 2>&1 || true

        # Verify it was applied
        actual_value=$(get_proc_value "$key")

        if [[ "$actual_value" == "$value" ]]; then
            printf '%-50s [PASS]\n' "$key = $value"
            VERIFIED_PASS=$((VERIFIED_PASS + 1))
        else
            printf '%-50s [FAIL]\n' "$key = $value (got: %s)" "$actual_value"
            VERIFIED_FAIL=$((VERIFIED_FAIL + 1))
        fi

        SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "Parameters applied: $SETTINGS_APPLIED"
echo "Verified PASS: $VERIFIED_PASS"
echo "Verified FAIL: $VERIFIED_FAIL"

exit 0
