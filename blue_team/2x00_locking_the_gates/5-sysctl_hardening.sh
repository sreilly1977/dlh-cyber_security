#!/bin/bash

# 5-sysctl_hardening.sh — Harden Linux kernel network stack and memory protections
#                         to prevent the server from being used as a pivot point.
#
# Usage:  sudo ./5-sysctl_hardening.sh
# ============================================================================

set -euo pipefail

SYSCTL_CONF="/etc/sysctl.conf"
SYSCTL_D_CONF="/etc/sysctl.d/99-meddefense.conf"
SYSCTL_BAK="/etc/sysctl.conf.bak"
SETTINGS_APPLIED=0
VERIFIED_PASS=0
VERIFIED_FAIL=0

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Define sysctl settings
# ---------------------------------------------------------------------------

declare -a SETTINGS=(
    "net.ipv4.ip_forward = 0"
    "net.ipv4.conf.all.accept_redirects = 0"
    "net.ipv4.conf.default.accept_redirects = 0"
    "net.ipv4.conf.all.send_redirects = 0"
    "net.ipv4.conf.all.accept_source_route = 0"
    "net.ipv4.conf.default.accept_source_route = 0"
    "net.ipv4.conf.all.log_martians = 1"
    "net.ipv4.conf.default.log_martians = 1"
    "net.ipv4.conf.all.rp_filter = 1"
    "net.ipv4.conf.default.rp_filter = 1"
    "net.ipv4.tcp_syncookies = 1"
    "net.ipv4.icmp_echo_ignore_broadcasts = 1"
    "net.ipv4.icmp_ignore_bogus_error_responses = 1"
    "net.ipv6.conf.all.disable_ipv6 = 1"
    "net.ipv6.conf.default.disable_ipv6 = 1"
    "kernel.randomize_va_space = 2"
    "fs.suid_dumpable = 0"
    "kernel.dmesg_restrict = 1"
    "kernel.kptr_restrict = 2"
)

parse_key() {
    local entry="$1"
    echo "$entry" | sed 's/[[:space:]]*=.*//' | tr -d ' '
}

parse_value() {
    local entry="$1"
    echo "$entry" | sed 's/^[^=]*=[[:space:]]*//' | tr -d ' '
}

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
# Step 1: Back up current configs
# ---------------------------------------------------------------------------

echo "[*] Backing up sysctl configurations..."
cp -p "$SYSCTL_CONF" "$SYSCTL_BAK" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 2: Write all settings to /etc/sysctl.d/99-meddefense.conf
# This file loads LAST in the sysctl.d processing order, ensuring our
# settings override anything set by other packages (including UFW).
# ---------------------------------------------------------------------------

echo "[*] Writing settings to $SYSCTL_D_CONF..."

cat > "$SYSCTL_D_CONF" << 'MEDDEFENSE_SYSCTL'
# MedDefense Kernel Hardening Parameters
# Deployed by 5-sysctl_hardening.sh
# This file is loaded last (99- prefix) to override any other sysctl settings.

MEDDEFENSE_SYSCTL

for setting in "${SETTINGS[@]}"; do
    echo "$setting" >> "$SYSCTL_D_CONF"
    SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))
done

chmod 644 "$SYSCTL_D_CONF"

# Also comment out any conflicting settings in /etc/sysctl.conf to avoid confusion
echo "[*] Cleaning conflicting entries from $SYSCTL_CONF..."

for setting in "${SETTINGS[@]}"; do
    key=$(parse_key "$setting")
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=" "$SYSCTL_CONF" 2>/dev/null; then
        sed -i "/^[[:space:]]*#*[[:space:]]*${key}[[:space:]]*=/c\\# Managed by /etc/sysctl.d/99-meddefense.conf" "$SYSCTL_CONF"
    fi
done

# ---------------------------------------------------------------------------
# Step 3: Apply all settings via sysctl --system
# ---------------------------------------------------------------------------

echo ""
echo "[*] Applying settings via sysctl --system..."
sysctl --system 2>&1 || echo "WARNING: Some settings may have failed to load"

# ---------------------------------------------------------------------------
# Step 4: Force immediate application via sysctl -w for any that didn't stick
# ---------------------------------------------------------------------------

echo ""
echo "[*] Forcing immediate application of settings..."

for setting in "${SETTINGS[@]}"; do
    key=$(parse_key "$setting")
    value=$(parse_value "$setting")

    current_value=$(get_proc_value "$key")
    if [[ "$current_value" != "$value" ]]; then
        sysctl -w "${key}=${value}" 2>/dev/null || true
        echo "    Forced: $key ($current_value -> $value)"
    fi
done

# ---------------------------------------------------------------------------
# Step 5: Apply per-interface overrides for critical network settings
# These are reset by network interface initialization (e.g., UFW enable)
# ---------------------------------------------------------------------------

echo ""
echo "[*] Applying per-interface overrides..."

for iface in $(ls /proc/sys/net/ipv4/conf/ 2>/dev/null); do
    sysctl -w "net.ipv4.conf.${iface}.log_martians=1" 2>/dev/null || true
    sysctl -w "net.ipv4.conf.${iface}.accept_redirects=0" 2>/dev/null || true
    sysctl -w "net.ipv4.conf.${iface}.rp_filter=1" 2>/dev/null || true
    sysctl -w "net.ipv4.conf.${iface}.send_redirects=0" 2>/dev/null || true
    sysctl -w "net.ipv4.conf.${iface}.accept_source_route=0" 2>/dev/null || true
done
echo "    Per-interface overrides applied"

# ---------------------------------------------------------------------------
# Step 6: Verify each setting
# ---------------------------------------------------------------------------

echo ""
echo "[*] Verifying settings..."

for setting in "${SETTINGS[@]}"; do
    key=$(parse_key "$setting")
    value=$(parse_value "$setting")

    actual_value=$(get_proc_value "$key")

    if [[ "$actual_value" == "$value" ]]; then
        printf '%-50s [PASS]\n' "$key = $value"
        VERIFIED_PASS=$((VERIFIED_PASS + 1))
    else
        printf '%-50s [FAIL] (got: %s)\n' "$key = $value" "$actual_value"
        VERIFIED_FAIL=$((VERIFIED_FAIL + 1))
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Summary ==="
echo "Parameters processed: $SETTINGS_APPLIED"
echo "Verified PASS: $VERIFIED_PASS"
echo "Verified FAIL: $VERIFIED_FAIL"
echo "Config file: $SYSCTL_D_CONF (loads last to override UFW and other services)"

if [[ "$VERIFIED_FAIL" -gt 0 ]]; then
    echo ""
    echo "NOTE: If log_martians still shows 0, the firewall script may have"
    echo "reset it. Run this script AFTER the firewall script, or re-run it."
    echo "The 99-meddefense.conf file ensures settings survive a reboot."
fi

exit 0
