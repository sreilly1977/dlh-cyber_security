#!/bin/bash

# 4-ssh_hardening.sh — Harden SSH to eliminate password-based authentication
#                       and reduce the attack surface for MedDefense servers.
#
# Usage:  sudo ./4-ssh_hardening.sh
# ============================================================================

set -euo pipefail

SSHD_CONFIG="/etc/ssh/sshd_config"
SSHD_BAK="/etc/ssh/sshd_config.bak"
BANNER_FILE="/etc/issue.net"
SETTINGS_APPLIED=0

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "ERROR: SSH config file not found at $SSHD_CONFIG" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper: capture a single sshd -T value
# ---------------------------------------------------------------------------

capture_sshd_setting() {
    local key="$1"
    local value=""
    if command -v sshd &>/dev/null; then
        value=$(sshd -T 2>/dev/null | grep -i "^${key} " | awk '{print $2}' || true)
    fi
    if [[ -z "$value" ]]; then
        value="not_set"
    fi
    printf '%s' "$value"
}

# ---------------------------------------------------------------------------
# Helper: idempotently set a directive in sshd_config
# ---------------------------------------------------------------------------

set_directive() {
    local key="$1"
    local value="$2"

    if grep -qE "^[#[:space:]]*${key}[[:space:]]" "$SSHD_CONFIG" 2>/dev/null; then
        sed -i "/^[#[:space:]]*${key}[[:space:]]/c\\${key} ${value}" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
}

# ---------------------------------------------------------------------------
# Capture pre-hardening state
# ---------------------------------------------------------------------------

echo "[*] Pre-hardening SSH state:"
echo "    PermitRootLogin: $(capture_sshd_setting 'permitrootlogin')"
echo "    PasswordAuthentication: $(capture_sshd_setting 'passwordauthentication')"
echo "    PermitEmptyPasswords: $(capture_sshd_setting 'permitemptypasswords')"
echo "    X11Forwarding: $(capture_sshd_setting 'x11forwarding')"
echo "    MaxAuthTries: $(capture_sshd_setting 'maxauthtries')"
echo "    ClientAliveInterval: $(capture_sshd_setting 'clientaliveinterval')"
echo "    ClientAliveCountMax: $(capture_sshd_setting 'clientalivecountmax')"
echo "    AllowUsers: $(capture_sshd_setting 'allowusers')"
echo "    LoginGraceTime: $(capture_sshd_setting 'logingracetime')"
echo "    Banner: $(capture_sshd_setting 'banner')"

# ---------------------------------------------------------------------------
# Step 1: Back up current sshd_config
# ---------------------------------------------------------------------------

echo "[*] Backing up $SSHD_CONFIG"
cp -p "$SSHD_CONFIG" "$SSHD_BAK"

# ---------------------------------------------------------------------------
# Step 2: Apply SSH hardening settings
# ---------------------------------------------------------------------------

echo "[*] Applying SSH hardening settings..."

echo "    PermitRootLogin no"
set_directive "PermitRootLogin" "no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    PasswordAuthentication no"
set_directive "PasswordAuthentication" "no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    PermitEmptyPasswords no"
set_directive "PermitEmptyPasswords" "no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    X11Forwarding no"
set_directive "X11Forwarding" "no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    MaxAuthTries 3"
set_directive "MaxAuthTries" "3"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    ClientAliveInterval 300"
set_directive "ClientAliveInterval" "300"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    ClientAliveCountMax 2"
set_directive "ClientAliveCountMax" "2"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

if id "medadmin" &>/dev/null 2>&1 || id "sysadmin" &>/dev/null 2>&1 || id "analyst" &>/dev/null 2>&1; then
    echo "    AllowUsers medadmin sysadmin analyst"
    set_directive "AllowUsers" "medadmin sysadmin analyst"
else
    echo "    [SKIP] AllowUsers medadmin sysadmin analyst"
    echo "    # DEVIATION: AllowUsers not applied because medadmin/sysadmin/analyst users do not exist"
    echo "    # Compensating control: PasswordAuthentication is disabled, reducing brute-force risk"
fi
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

OPENSSH_VERSION=""
if command -v sshd &>/dev/null; then
    OPENSSH_VERSION=$(sshd -V 2>&1 | head -1 || true)
fi

if echo "$OPENSSH_VERSION" | grep -qE '7\.[6-9]|8\.|9\.' 2>/dev/null; then
    echo "    [SKIP] Protocol 2 (OpenSSH 7.6+ only supports Protocol 2 — directive deprecated)"
    echo "    # DEVIATION FROM CIS-5.2.3: Protocol directive deprecated in OpenSSH 7.6+"
    echo "    # Compensating control: Protocol 1 is not compiled into OpenSSH 7.6+"
else
    echo "    Protocol 2"
    set_directive "Protocol" "2"
fi
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    LoginGraceTime 60"
set_directive "LoginGraceTime" "60"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

echo "    Banner /etc/issue.net"
set_directive "Banner" "/etc/issue.net"
SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))

# ---------------------------------------------------------------------------
# Step 3: Create /etc/issue.net banner file
# ---------------------------------------------------------------------------

echo "[*] Creating login banner at $BANNER_FILE"

BANNER_CONTENT="**********************************************************************
*                                                                    *
*              MEDDEFENSE AUTHORIZED ACCESS ONLY                     *
*                                                                    *
*  This system is the property of MedDefense Corporation.             *
*  Unauthorized access is strictly prohibited and will be            *
*  prosecuted to the fullest extent of the law.                      *
*                                                                    *
*  All connections are monitored and logged. By accessing            *
*  this system, you consent to surveillance and recording.           *
*                                                                    *
**********************************************************************"

if [[ ! -f "$BANNER_FILE" ]] || [[ "$(cat "$BANNER_FILE" 2>/dev/null)" != "$BANNER_CONTENT" ]]; then
    echo "$BANNER_CONTENT" > "$BANNER_FILE"
    chmod 644 "$BANNER_FILE"
    echo "    Banner file created"
else
    echo "    Banner file already configured"
fi

# ---------------------------------------------------------------------------
# Step 4: Validate SSH configuration
# ---------------------------------------------------------------------------

echo "[*] Validating SSH configuration..."

if sshd -t 2>/tmp/_sshd_validate_$$; then
    echo "    sshd -t: OK"
    rm -f /tmp/_sshd_validate_$$
else
    VALIDATION_ERROR=$(cat /tmp/_sshd_validate_$$ 2>/dev/null || echo "Unknown error")
    rm -f /tmp/_sshd_validate_$$
    echo "    sshd -t: FAILED"
    echo "    Error: $VALIDATION_ERROR"
    echo "[!] Validation failed. Restoring backup..."
    cp -p "$SSHD_BAK" "$SSHD_CONFIG"
    echo "    Backup restored."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 5: Restart SSH if validation passed
# ---------------------------------------------------------------------------

echo "[*] Restarting SSH service..."

if systemctl restart ssh 2>/dev/null; then
    SSH_SERVICE_STATUS=$(systemctl is-active ssh 2>/dev/null || echo "unknown")
    echo "    ssh.service: $SSH_SERVICE_STATUS"
elif systemctl restart sshd 2>/dev/null; then
    SSH_SERVICE_STATUS=$(systemctl is-active sshd 2>/dev/null || echo "unknown")
    echo "    sshd.service: $SSH_SERVICE_STATUS"
else
    echo "    [!] Failed to restart SSH service"
    echo "    [!] Configuration is valid but service could not be restarted"
    echo "    [!] Manual intervention required: systemctl restart ssh"
fi

# ---------------------------------------------------------------------------
# Print post-hardening state
# ---------------------------------------------------------------------------

echo "[*] Post-hardening SSH state:"
echo "    PermitRootLogin: $(capture_sshd_setting 'permitrootlogin')"
echo "    PasswordAuthentication: $(capture_sshd_setting 'passwordauthentication')"
echo "    PermitEmptyPasswords: $(capture_sshd_setting 'permitemptypasswords')"
echo "    X11Forwarding: $(capture_sshd_setting 'x11forwarding')"
echo "    MaxAuthTries: $(capture_sshd_setting 'maxauthtries')"
echo "    ClientAliveInterval: $(capture_sshd_setting 'clientaliveinterval')"
echo "    ClientAliveCountMax: $(capture_sshd_setting 'clientalivecountmax')"
echo "    AllowUsers: $(capture_sshd_setting 'allowusers')"
echo "    LoginGraceTime: $(capture_sshd_setting 'logingracetime')"
echo "    Banner: $(capture_sshd_setting 'banner')"

echo "Settings applied: $SETTINGS_APPLIED"

exit 0
