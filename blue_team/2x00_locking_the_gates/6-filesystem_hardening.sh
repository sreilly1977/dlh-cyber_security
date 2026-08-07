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
    "/usr/bin/fusermount3"
    "/usr/lib/eject/dmcrypt-get-device"
    "/usr/bin/staprun"
    "/usr/lib/snapd/snap-confine"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    "/usr/libexec/polkit-agent-helper-1"
    "/usr/bin/pkexec"
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
    "/usr/bin/chage"
    "/usr/bin/crontab"
    "/usr/bin/ssh-agent"
    "/usr/lib/x86_64-linux-gnu/utempter/utempter"
    "/usr/sbin/pam_extrausers_chkpwd"
    "/usr/sbin/unix_chkpwd"
)

# Counters
SUIDCOUNT_FOUND=0
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

if [[ -n "$SUID_LIST" ]]; then
    SUIDCOUNT_FOUND=$(echo "$SUID_LIST" | wc -l | tr -d ' ')
else
    SUIDCOUNT_FOUND=0
fi

echo "Found $SUIDCOUNT_FOUND SUID binaries"

# Use process substitution to avoid subshell variable loss
while IFS= read -r binary; do
    [[ -z "$binary" ]] && continue
    if in_suid_whitelist "$binary"; then
        SUIDWHITELISTED=$((SUIDWHITELISTED + 1))
    else
        echo "  $binary   [SUID REMOVED]"
        chmod u-s "$binary" 2>/dev/null || true
        SUIDREMOVED=$((SUIDREMOVED + 1))
    fi
done < <(printf '%s\n' "$SUID_LIST")

echo "Whitelisted: $SUIDWHITELISTED"
echo "Non-whitelisted: $SUIDREMOVED"

# ---------------------------------------------------------------------------
# Step 2: Find and remediate SGID binaries
# ---------------------------------------------------------------------------

echo "[*] Scanning for SGID binaries..."

SGID_LIST=$(find / -xdev -type f -perm -2000 2>/dev/null | sort || true)

if [[ -n "$SGID_LIST" ]]; then
    SGIDCOUNT_FOUND=$(echo "$SGID_LIST" | wc -l | tr -d ' ')
else
    SGIDCOUNT_FOUND=0
fi

echo "Found $SGIDCOUNT_FOUND SGID binaries"

while IFS= read -r binary; do
    [[ -z "$binary" ]] && continue
    if in_sgid_whitelist "$binary"; then
        SGIDWHITELISTED=$((SGIDWHITELISTED + 1))
    else
        echo "  $binary   [SGID REMOVED]"
        chmod g-s "$binary" 2>/dev/null || true
        SGIDREMOVED=$((SGIDREMOVED + 1))
    fi
done < <(printf '%s\n' "$SGID_LIST")

echo "Whitelisted: $SGIDWHITELISTED"
echo "Non-whitelisted: $SGIDREMOVED"

# ---------------------------------------------------------------------------
# Step 3: Find and fix world-writable files
# ---------------------------------------------------------------------------

echo "[*] Scanning for world-writable files..."

WW_LIST=$(find / -xdev -type f -perm -0002 \
    ! -path '/proc/*' \
    ! -path '/sys/*' \
    ! -path '/dev/*' \
    2>/dev/null | head -50 || true)

if [[ -n "$WW_LIST" ]]; then
    WWFOUND=$(echo "$WW_LIST" | wc -l | tr -d ' ')
else
    WWFOUND=0
fi

if [[ "$WWFOUND" -gt 0 ]]; then
    echo "Found $WWFOUND world-writable files"

    while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        if [[ -f "$file" ]] || [[ -d "$file" ]]; then
            echo "  $file           [FIXED]"
            chmod o-w "$file" 2>/dev/null || true
            WWRFIXED=$((WWRFIXED + 1))
        fi
    done < <(printf '%s\n' "$WW_LIST")
fi

# ---------------------------------------------------------------------------
# Step 4: Configure mount options for /tmp, /var/tmp, /dev/shm
# ---------------------------------------------------------------------------

echo "[*] Checking mount options..."

check_mount_options() {
    local mountpoint="$1"
    local options="noexec,nosuid,nodev"
    local all_ok=true

    # Check if mountpoint is mounted
    local mount_line
    mount_line=$(mount | grep " on $mountpoint " | head -1 || true)

    if [[ -z "$mount_line" ]]; then
        echo "$mountpoint:     $options  [NOT MOUNTED SEPARATELY]"
        return 1
    fi

    # Extract options from parentheses: "dev on /mnt type fstype (rw,opt1,opt2,...)"
    local mount_opts=""
    local opts_re='\(([^)]+)\)'
    if [[ "$mount_line" =~ $opts_re ]]; then
        mount_opts="${BASH_REMATCH[1]}"
    fi

    # Check each required option
    local missing=()
    for opt in noexec nosuid nodev; do
        if [[ ",${mount_opts}," != *",${opt},"* ]]; then
            missing+=("$opt")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "$mountpoint:     $options  [OK]"
        return 0
    fi

    # Attempt to remount with missing options
    local add_opts
    add_opts=$(IFS=','; echo "${missing[*]}")
    mount -o remount,"$add_opts" "$mountpoint" 2>/dev/null || true

    # Re-check
    mount_line=$(mount | grep " on $mountpoint " | head -1 || true)
    mount_opts=""
    if [[ "$mount_line" =~ $opts_re ]]; then
        mount_opts="${BASH_REMATCH[1]}"
    fi

    missing=()
    all_ok=true
    for opt in noexec nosuid nodev; do
        if [[ ",${mount_opts}," != *",${opt},"* ]]; then
            missing+=("$opt")
            all_ok=false
        fi
    done

    if $all_ok; then
        echo "$mountpoint:     $options  [APPLIED]"
        return 0
    else
        echo "$mountpoint:     $options  [FAILED: missing ${missing[*]}]"
        return 1
    fi
}
