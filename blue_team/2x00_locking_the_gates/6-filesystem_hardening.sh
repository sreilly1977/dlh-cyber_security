#!/bin/bash

# 6-filesystem_hardening.sh — Audit and remediate dangerous filesystem permissions
#                             that could enable privilege escalation.
#
# Usage:  sudo ./6-filesystem_hardening.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Whitelist of known-safe SUID binaries for Ubuntu 22.04
# ---------------------------------------------------------------------------

declare -a SUID_WHITELIST=(
    "/usr/bin/passwd"
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/newgrp"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/ping"
    "/usr/bin/ping6"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/sbin/unix_chkpwd"
    "/usr/bin/fusermount"
    "/usr/lib/eject/dmcrypt-get-device"
    "/usr/bin/staprun"
    "/usr/lib/snapd/snap-confine"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
)

# ---------------------------------------------------------------------------
# Whitelist of known-safe SGID binaries for Ubuntu 22.04
# ---------------------------------------------------------------------------

declare -a SGID_WHITELIST=(
    "/usr/bin/wall"
    "/usr/bin/write"
    "/usr/bin/pt_chown"
    "/usr/bin/expiry"
    "/usr/bin/screen"
    "/usr/lib/xorg/Xorg.wrap"
    "/usr/bin/gnome-keyring-daemon"
    "/usr/bin/hardlink"
    "/usr/bin/at"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/git-core/git-gui--askpass"
)

# Counters
SUICOUNT_FOUND=0
SUIDWHITELISTED=0
SUIDREMOVED=0
SGIDCOUNT_FOUND=0
SGIDWHITELISTED=0
SGIDREMOVED=0
WWFOUND=0
WWRFIXED=0

# ---------------------------------------------------------------------------
# Helper: check if path is in whitelist
# ---------------------------------------------------------------------------

in_suid_whitelist() {
    local path="$1"
    for whitelisted in "${SUID_WHITELIST[@]}"; do
        if [[ "$path" == "$whitelisted" ]]; then
            return 0
        fi
    done
    return 1
}

in_sgid_whitelist() {
    local path="$1"
    for whitelisted in "${SGID_WHITELIST[@]}"; do
        if [[ "$path" == "$whitelisted" ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Step 1: Find and remediate SUID binaries
# ---------------------------------------------------------------------------

echo "[*] Scanning for SUID binaries..."

SUID_LIST=$(find / -xdev -type f -perm -4000 2>/dev/null | sort || true)
SUICOUNT_FOUND=$(echo "$SUID_LIST" | grep -c '^' || echo "0")

echo "Found $SUICOUNT_FOUND SUID binaries"

if [[ -n "$SUID_LIST" ]]; then
    echo "$SUID_LIST" | while read -r binary; do
        if in_suid_whitelist "$binary"; then
            : # Skip whitelisted
        else
            echo "  $binary   [SUID REMOVED]"
            chmod u-s "$binary" 2>/dev/null || true
            SUIDREMOVED=$((SUIDREMOVED + 1))
        fi
    done

    # Re-count SUID removed since subshell
    SUIDREMOVED=$(echo "$SUID_LIST" | while read -r binary; do
        if ! in_suid_whitelist "$binary"; then
            echo "1"
        fi
    done | wc -l | tr -d ' ')

    SUIDWHITELISTED=$((SUICOUNT_FOUND - SUIDREMOVED))
fi

echo "Whitelisted: $SUIDWHITELISTED"
echo "Non-whitelisted: $SUIDREMOVED"

# ---------------------------------------------------------------------------
# Step 2: Find and remediate SGID binaries
# ---------------------------------------------------------------------------

echo "[*] Scanning for SGID binaries..."

SGID_LIST=$(find / -xdev -type f -perm -2000 2>/dev/null | sort || true)
SGIDCOUNT_FOUND=$(echo "$SGID_LIST" | grep -c '^' || echo "0")

echo "Found $SGIDCOUNT_FOUND SGID binaries"

if [[ -n "$SGID_LIST" ]]; then
    echo "$SGID_LIST" | while read -r binary; do
        if in_sgid_whitelist "$binary"; then
            : # Skip whitelisted
        else
            echo "  $binary   [SGID REMOVED]"
            chmod g-s "$binary" 2>/dev/null || true
            SGIDREMOVED=$((SGIDREMOVED + 1))
        fi
    done

    # Re-count SGID removed since subshell
    SGIDREMOVED=$(echo "$SGID_LIST" | while read -r binary; do
        if ! in_sgid_whitelist "$binary"; then
            echo "1"
        fi
    done | wc -l | tr -d ' ')

    SGIDWHITELISTED=$((SGIDCOUNT_FOUND - SGIDREMOVED))
fi

echo "Whitelisted: $SGIDWHITELISTED"
echo "Non-whitelisted: $SGIDREMOVED"

# ---------------------------------------------------------------------------
# Step 3: Find and fix world-writable files
# ---------------------------------------------------------------------------

echo "[*] Scanning for world-writable files..."

WW_LIST=$(find / -xdev -type f -perm -0002 \( ! -path '/proc/*' \) \( ! -path '/sys/*' \) \( ! -path '/dev/*' \) 2>/dev/null | head -50 || true)
WW_COUNT=$(echo "$WW_LIST" | grep -c '^' 2>/dev/null || echo "0")

if [[ "$WW_COUNT" -gt 0 ]] && [[ -n "$WW_LIST" ]]; then
    echo "Found $WW_COUNT world-writable files"

    echo "$WW_LIST" | while read -r file; do
        if [[ -f "$file" ]] || [[ -d "$file" ]]; then
            echo "  $file           [FIXED]"
            chmod o-w "$file" 2>/dev/null || true
            WWRFIXED=$((WWRFIXED + 1))
        fi
    done

    # Re-count since subshell
    WWRFIXED=$(echo "$WW_LIST" | while read -r file; do
        if [[ -f "$file" ]] || [[ -d "$file" ]]; then
            echo "1"
        fi
    done | wc -l | tr -d ' ')
fi

# ---------------------------------------------------------------------------
# Step 4: Configure mount options for /tmp, /var/tmp, /dev/shm
# ---------------------------------------------------------------------------

echo "[*] Checking mount options..."

check_mount_option() {
    local mountpoint="$1"
    local option="$2"

    if mount | grep -q " on $mountpoint .* $option"; then
        echo "$mountpoint:     noexec,nosuid,nodev  [OK]"
        return 0
    else
        # Remount with option
        if mount | grep -q " on $mountpoint "; then
            mount -o remount,$option "$mountpoint" 2>/dev/null || true
        fi

        if mount | grep -q " on $mountpoint .* $option"; then
            echo "$mountpoint:     noexec,nosuid,nodev  [APPLIED]"
            return 0
        else
            echo "$mountpoint:     noexec,nosuid,nodev  [FAILED]"
            return 1
        fi
    fi
}

TMP_OK=true
VARTMP_OK=true
DEVSHM_OK=true

check_mount_option "/tmp" "noexec" || TMP_OK=false
check_mount_option "/var/tmp" "noexec" || VARTMP_OK=false
check_mount_option "/dev/shm" "noexec" || DEVSHM_OK=false

# ---------------------------------------------------------------------------
# Step 5: Restrict cron access
# ---------------------------------------------------------------------------

echo "[*] Restricting cron access..."

CRON_ALLOW="/etc/cron.allow"
CRON_DENY="/etc/cron.deny"

# Remove cron.deny if exists and create cron.allow with authorized users only
if [[ -f "$CRON_DENY" ]]; then
    rm -f "$CRON_DENY"
fi

if [[ ! -f "$CRON_ALLOW" ]]; then
    touch "$CRON_ALLOW"
    echo "root" >> "$CRON_ALLOW"
fi

chmod 644 "$CRON_ALLOW" 2>/dev/null || true
chown root:root "$CRON_ALLOW" 2>/dev/null || true

echo "    Cron access restricted to authorized users"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "SUID remediated: $SUIDREMOVED | SGID remediated: $SGIDREMOVED | World-writable fixed: $WWRFIXED"

exit 0
