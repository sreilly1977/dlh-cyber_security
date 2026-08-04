#!/bin/bash

# 8-pam_hardening.sh — Configure PAM to enforce password quality requirements
#                       and lock accounts after failed authentication attempts.
#
# Usage:  sudo ./8-pam_hardening.sh
# ============================================================================

set -euo pipefail

MINLEN=14
DENY=5
UNLOCK_TIME=900
FAIL_INTERVAL=900
REMEMBER=12

PWQUALITY_CONF="/etc/security/pwquality.conf"
COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_PASSWORD="/etc/pam.d/common-password"
FAILLOCK_CONF="/etc/security/faillock.conf"
PAM_FAILLOCK_PROFILE="/usr/share/pam-configs/faillock"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

set_config_value() {
    local file="$1" key="$2" value="$3"
    touch "$file" 2>/dev/null || true
    if grep -qE "^[#[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null; then
        sed -i "s|^[#[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
}

set_config_flag() {
    local file="$1" flag="$2"
    touch "$file" 2>/dev/null || true
    if ! grep -qE "^${flag}[[:space:]]*$" "$file" 2>/dev/null; then
        echo "$flag" >> "$file"
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Install libpam-pwquality
# ---------------------------------------------------------------------------

echo "[*] Checking libpam-pwquality..."

if dpkg -l libpam-pwquality &>/dev/null 2>&1; then
    VERSION=$(dpkg -s libpam-pwquality 2>/dev/null | grep 'Version:' | awk '{print $2}')
    echo "    Already installed: libpam-pwquality $VERSION"
else
    echo "    Installing libpam-pwquality..."
    apt-get update -qq 2>/dev/null
    apt-get install -y libpam-pwquality 2>/dev/null
    echo "    Installation complete"
fi

# ---------------------------------------------------------------------------
# Step 2: Backup PAM files (restore point before any changes)
# ---------------------------------------------------------------------------

echo "[*] Backing up PAM files..."
BACKUP_DIR="/root/pam_backups_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
for f in "$PWQUALITY_CONF" "$COMMON_AUTH" "$COMMON_PASSWORD" "$FAILLOCK_CONF"; do
    [[ -f "$f" ]] && cp -p "$f" "$BACKUP_DIR/" || true
done
echo "    Backup saved to: $BACKUP_DIR"

# ---------------------------------------------------------------------------
# Step 3: Configure password quality (pwquality.conf)
# ---------------------------------------------------------------------------

echo "[*] Configuring password quality ($PWQUALITY_CONF)..."

set_config_value "$PWQUALITY_CONF" "minlen" "$MINLEN"
echo "    minlen = $MINLEN                      [SET]"

set_config_value "$PWQUALITY_CONF" "dcredit" "-1"
echo "    dcredit = -1                     [SET]"

set_config_value "$PWQUALITY_CONF" "ucredit" "-1"
echo "    ucredit = -1                     [SET]"

set_config_value "$PWQUALITY_CONF" "lcredit" "-1"
echo "    lcredit = -1                     [SET]"

set_config_value "$PWQUALITY_CONF" "ocredit" "-1"
echo "    ocredit = -1                     [SET]"

set_config_value "$PWQUALITY_CONF" "maxrepeat" "3"
echo "    maxrepeat = 3                    [SET]"

# reject_username is a FLAG (no = value) — the original bug was writing
# "reject_username = " which is invalid syntax and caused pwquality to
# reject all password changes
set_config_flag "$PWQUALITY_CONF" "reject_username"
echo "    reject_username                  [SET]"

# ---------------------------------------------------------------------------
# Step 4: Configure account lockout (faillock.conf)
# ---------------------------------------------------------------------------

echo "[*] Configuring account lockout (pam_faillock)..."

set_config_value "$FAILLOCK_CONF" "deny" "$DENY"
set_config_value "$FAILLOCK_CONF" "unlock_time" "$UNLOCK_TIME"
set_config_value "$FAILLOCK_CONF" "fail_interval" "$FAIL_INTERVAL"

echo "    deny = $DENY                         [SET]"
echo "    unlock_time = $UNLOCK_TIME                [SET]"
echo "    fail_interval = $FAIL_INTERVAL              [SET]"

# ---------------------------------------------------------------------------
# Step 5: Enable pam_faillock in common-auth
# Uses pam-auth-update (Debian/Ubuntu native) with Python3 fallback
# for safe PAM stack modification
# ---------------------------------------------------------------------------

if [[ ! -f "$PAM_FAILLOCK_PROFILE" ]]; then
    mkdir -p "$(dirname "$PAM_FAILLOCK_PROFILE")"
    cat > "$PAM_FAILLOCK_PROFILE" << 'PAM_PROFILE'
Name: Authenticate using faillock
Default: no
Conf-Type: auth
Conf:
     auth required pam_faillock.so preauth silent
     auth [default=die] pam_faillock.so authfail
     auth sufficient pam_faillock.so authsucc
PAM_PROFILE
fi

if command -v pam-auth-update &>/dev/null; then
    pam-auth-update --enable faillock 2>/dev/null || true
fi

if ! grep -q 'pam_faillock.so' "$COMMON_AUTH" 2>/dev/null; then
    echo "    Manually adding pam_faillock to common-auth..."

    python3 << 'PYEOF'
import re

auth_file = '/etc/pam.d/common-auth'

with open(auth_file, 'r') as f:
    content = f.read()

if 'pam_faillock' not in content:
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        if 'pam_unix.so' in line and line.strip().startswith('auth'):
            new_lines.append(
                'auth    required                        pam_faillock.so preauth silent'
            )
            match = re.search(r'success=(\d+)', line)
            if match:
                old_val = int(match.group(1))
                line = line.replace(f'success={old_val}', f'success={old_val + 1}')
            new_lines.append(line)
            new_lines.append(
                'auth    [default=die]                    pam_faillock.so authfail'
            )
        else:
            new_lines.append(line)

    with open(auth_file, 'w') as f:
        f.write('\n'.join(new_lines))
else:
    print('    pam_faillock already in common-auth')
PYEOF
fi

# ---------------------------------------------------------------------------
# Step 6: Configure password history
# Uses pam_unix.so's built-in remember parameter
# ---------------------------------------------------------------------------

echo "[*] Configuring password history..."

if grep -q 'pam_unix\.so' "$COMMON_PASSWORD" 2>/dev/null; then
    if ! grep -q 'remember=' "$COMMON_PASSWORD" 2>/dev/null; then
        sed -i '/pam_unix\.so/ s/$/ remember='"$REMEMBER"'/' "$COMMON_PASSWORD"
        echo "    remember = $REMEMBER                    [SET]"
    else
        sed -i "s/remember=[0-9]*/remember=$REMEMBER/" "$COMMON_PASSWORD"
        echo "    remember = $REMEMBER                    [UPDATED]"
    fi
else
    echo "    WARNING: pam_unix.so not found in common-password"
fi

if ! grep -q 'pam_pwquality\.so' "$COMMON_PASSWORD" 2>/dev/null; then
    sed -i '/pam_unix\.so.*password/a pam_pwquality.so retry=3' "$COMMON_PASSWORD"
    echo "    pam_pwquality.so added to common-password"
fi

# ---------------------------------------------------------------------------
# Step 7: Validate configuration
# ---------------------------------------------------------------------------

echo "[*] Validating PAM configuration..."

VALIDATE_OK=true

[[ -r "$PWQUALITY_CONF" ]] && echo "    $PWQUALITY_CONF: readable [OK]" || { echo "    $PWQUALITY_CONF: unreadable [FAIL]"; VALIDATE_OK=false; }
[[ -r "$COMMON_AUTH" ]] && echo "    $COMMON_AUTH: readable [OK]" || { echo "    $COMMON_AUTH: unreadable [FAIL]"; VALIDATE_OK=false; }
[[ -r "$COMMON_PASSWORD" ]] && echo "    $COMMON_PASSWORD: readable [OK]" || { echo "    $COMMON_PASSWORD: unreadable [FAIL]"; VALIDATE_OK=false; }

if ! $VALIDATE_OK; then
    echo "ERROR: Validation failed. Restore from $BACKUP_DIR if needed."
    exit 1
fi

echo ""
echo "Password minimum length: $MINLEN | Lockout: $DENY attempts / $(( UNLOCK_TIME / 60 )) min | History: $REMEMBER"
echo ""
echo "Configuration complete. To test, run: passwd <username>"
echo "To restore from backup: cp $BACKUP_DIR/* <pam_file>"

exit 0
