#!/bin/bash

# 8-pam_hardening.sh — Configure PAM to enforce password quality requirements
#                       and lock accounts after failed authentication attempts.
#
# Usage:  sudo ./8-pam_hardening.sh
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
# Configuration values
# ---------------------------------------------------------------------------

PWQUALITY_CONF="/etc/security/pwquality.conf"
COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_PASSWORD="/etc/pam.d/common-password"
AUTH_ACCOUNT_LOCKOUT=5
LOCKOUT_TIME=900
FAIL_INTERVAL=900
PASSWORD_HISTORY=12
MIN_PASSWORD_LENGTH=14

# ---------------------------------------------------------------------------
# Step 1: Install libpam-pwquality if not present
# ---------------------------------------------------------------------------

echo "[*] Checking libpam-pwquality..."

if dpkg -l libpam-pwquality &>/dev/null 2>&1; then
    VERSION=$(dpkg -s libpam-pwquality 2>/dev/null | grep 'Version:' | awk '{print $2}')
    echo "    Already installed: libpam-pwquality $VERSION"
    PWQUALITY_INSTALLED=true
else
    echo "    Installing libpam-pwquality..."
    apt-get update -qq && apt-get install -y libpam-pwquality -qq
    echo "    Installation complete"
    PWQUALITY_INSTALLED=true
fi

# ---------------------------------------------------------------------------
# Step 2: Configure password quality
# ---------------------------------------------------------------------------

echo "[*] Configuring password quality ($PWQUALITY_CONF)..."

configure_pwquality() {
    local setting="$1"
    local value="$2"

    # Check if setting exists
    if grep -qE "^${setting}[[:space:]]*=" "$PWQUALITY_CONF" 2>/dev/null; then
        # Update existing setting
        sed -i "s/^${setting}[[:space:]]*=.*/${setting} = ${value}/" "$PWQUALITY_CONF"
        echo "    $setting = $value     [UPDATED]"
    else
        # Add new setting
        echo "# Hardened by 8-pam_hardening.sh" >> "$PWQUALITY_CONF"
        echo "${setting} = ${value}" >> "$PWQUALITY_CONF"
        echo "    $setting = $value     [SET]"
    fi
}

# Minimum password length
configure_pwquality "minlen" "$MIN_PASSWORD_LENGTH"

# Complexity requirements (-1 means required, not optional credits)
configure_pwquality "dcredit" "-1"      # At least 1 digit required
configure_pwquality "ucredit" "-1"      # At least 1 uppercase required
configure_pwquality "lcredit" "-1"      # At least 1 lowercase required
configure_pwquality "ocredit" "-1"      # At least 1 special character required

# Additional quality controls
configure_pwquality "maxrepeat" "3"     # Reject 3+ consecutive identical characters
configure_pwquality "reject_username" ""  # Reject passwords containing username

# ---------------------------------------------------------------------------
# Step 3: Configure account lockout with pam_faillock
# ---------------------------------------------------------------------------

echo "[*] Configuring account lockout (pam_faillock)..."

# Configure faillock settings in /etc/security/faillock.conf
FAILLOCK_CONF="/etc/security/faillock.conf"

if [[ -f "$FAILLOCK_CONF" ]]; then
    # Backup original
    cp -p "$FAILLOCK_CONF" "${FAILLOCK_CONF}.bak"

    configure_pam_setting() {
        local setting="$1"
        local value="$2"
        local file="$3"

        if grep -qE "^[[:space:]]*${setting}[[:space:]]*=" "$file" 2>/dev/null; then
            sed -i "s/^[[:space:]]*${setting}[[:space:]]*=.*/${setting} = ${value}/" "$file"
            echo "    $setting = $value     [UPDATED]"
        else
            echo "${setting} = ${value}" >> "$file"
            echo "    $setting = $value     [SET]"
        fi
    }

    configure_pam_setting "deny" "$AUTH_ACCOUNT_LOCKOUT" "$FAILLOCK_CONF"
    configure_pam_setting "unlock_time" "$LOCKOUT_TIME" "$FAILLOCK_CONF"
    configure_pam_setting "fail_interval" "$FAIL_INTERVAL" "$FAILLOCK_CONF"
else
    # Create faillock.conf if it doesn't exist
    touch "$FAILLOCK_CONF"
    echo "# Faillock configuration hardened by 8-pam_hardening.sh" > "$FAILLOCK_CONF"
    echo "deny = $AUTH_ACCOUNT_LOCKOUT" >> "$FAILLOCK_CONF"
    echo "unlock_time = $LOCKOUT_TIME" >> "$FAILLOCK_CONF"
    echo "fail_interval = $FAIL_INTERVAL" >> "$FAILLOCK_CONF"
    echo "    deny = $AUTH_ACCOUNT_LOCKOUT     [CREATED]"
    echo "    unlock_time = $LOCKOUT_TIME     [CREATED]"
    echo "    fail_interval = $FAIL_INTERVAL     [CREATED]"
fi

# Ensure pam_faillock is in common-auth (preauth and authfail sections)
if ! grep -q 'pam_faillock.so' "$COMMON_AUTH" 2>/dev/null; then
    echo "# Adding pam_faillock to common-auth" >> "$COMMON_AUTH"
    echo "auth required pam_faillock.so preauth silent deny=$AUTH_ACCOUNT_LOCKOUT unlock_time=$LOCKOUT_TIME fail_interval=$FAIL_INTERVAL" >> "$COMMON_AUTH"
    echo "auth [default=die] pam_faillock.so authfail deny=$AUTH_ACCOUNT_LOCKOUT" >> "$COMMON_AUTH"
else
    echo "    pam_faillock already configured in common-auth"
fi

# ---------------------------------------------------------------------------
# Step 4: Configure password history
# ---------------------------------------------------------------------------

echo "[*] Configuring password history..."

# Add pam_pwhistory to common-password (remember parameter)
if grep -q 'pam_pwhistory.so' "$COMMON_PASSWORD" 2>/dev/null; then
    # Update existing pam_pwhistory line
    if grep -qE 'remember[[:space:]]*=' "$COMMON_PASSWORD" 2>/dev/null; then
        sed -i "s/remember[[:space:]]*[0-9]*/remember=$PASSWORD_HISTORY/" "$COMMON_PASSWORD"
        echo "    remember = $PASSWORD_HISTORY     [UPDATED]"
    else
        # Add remember to existing pam_pwhistory line
        sed -i "s/pam_pwhistory.so/pam_pwhistory.so remember=$PASSWORD_HISTORY/" "$COMMON_PASSWORD"
        echo "    remember = $PASSWORD_HISTORY     [ADDED TO LINE]"
    fi
else
    # Add pam_pwhistory to common-password (after pam_unix)
    sed -i '/pam_unix.so.*password/a remember = '"$PASSWORD_HISTORY"'  # Password history' "$COMMON_PASSWORD"
    echo "    remember = $PASSWORD_HISTORY     [ADDED NEW ENTRY]"
fi

# Ensure pam_pwquality is also in common-password for enforcement
if ! grep -q 'pam_pwquality.so' "$COMMON_PASSWORD" 2>/dev/null; then
    # Insert after pam_unix.so
    sed -i '/pam_unix.so.*password/a pam_pwquality.so retry=3' "$COMMON_PASSWORD"
    echo "    pam_pwquality.so added to common-password"
fi

# ---------------------------------------------------------------------------
# Step 5: Validate configuration
# ---------------------------------------------------------------------------

echo "[*] Validating PAM configuration..."

validate_file() {
    local file="$1"
    if [[ -f "$file" ]] && [[ -r "$file" ]]; then
        echo "    $file: readable [OK]"
        return 0
    else
        echo "    $file: unreadable [WARN]"
        return 1
    fi
}

validate_file "$PWQUALITY_CONF"
validate_file "$COMMON_AUTH"
validate_file "$COMMON_PASSWORD"

# Verify key settings were applied
echo ""
echo "[*] Verifying applied settings..."

PW_MINLEN=$(grep -E '^minlen[[:space:]]*=' "$PWQUALITY_CONF" 2>/dev/null | grep -oE '[0-9]+' || echo "unknown")
DENY_VALUE=$(grep -E '^deny[[:space:]]*=' "$FAILLOCK_CONF" 2>/dev/null | grep -oE '[0-9]+' || echo "unknown")
UNLOCK_TIME=$(grep -E '^unlock_time[[:space:]]*=' "$FAILLOCK_CONF" 2>/dev/null | grep -oE '[0-9]+' || echo "unknown")
REMEMBER=$(grep -oE 'remember[[:space:]]*=[[:space:]]*[0-9]+' "$COMMON_PASSWORD" 2>/dev/null | grep -oE '[0-9]+' || echo "unknown")

echo "Password minimum length: $PW_MINLEN | Lockout: $DENY_VALUE attempts / $UNLOCK_TIME sec | History: $REMEMBER"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "Configuration complete: minlen=$PW_MINLEN | Lockout=$DENY_VALUE/$(( UNLOCK_TIME / 60 )) min | History=$REMEMBER"

exit 0
