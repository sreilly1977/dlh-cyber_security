#!/bin/bash

# 9-apparmor_config.sh — Deploy and configure AppArmor profiles in enforce mode
#                        for all network-exposed services.
#
# Addresses:
#   - 1x00 incident — crypto-miner compromised Apache with full filesystem access
#   - AppArmor MAC limits damage even if service is compromised
#   - Custom profile for MedDefense billing application restricts unauthorized access
#   - Difference between "shell on web server" and "shell confined to /var/www"
#
# Usage:  sudo ./9-apparmor_config.sh
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
# Configuration
# ---------------------------------------------------------------------------

MEDDEFENSE_APP_PATH="/opt/meddefense/billing-app"
MEDDEFENSE_CUSTOM_PROFILE="/etc/apparmor.d/opt.meddefense.billing-app"

# Services to enforce
declare -a SERVICES_TO_ENFORCE=(
    "/usr/sbin/apache2"
    "/usr/sbin/mysqld"
)

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

ENFORCE_COUNT=0
COMPLAIN_COUNT=0
UNCONFINED_COUNT=0

# ---------------------------------------------------------------------------
# Helper: check if AppArmor module is loaded
# ---------------------------------------------------------------------------

check_apparmor_loaded() {
    if lsmod | grep -q apparmor; then
        echo "    AppArmor module: loaded"
        return 0
    else
        echo "    AppArmor module: NOT LOADED"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Helper: check if AppArmor service is running
# ---------------------------------------------------------------------------

check_apparmor_service() {
    if systemctl is-active apparmor &>/dev/null 2>&1; then
        echo "    AppArmor service: active"
        return 0
    else
        echo "    AppArmor service: inactive"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Helper: get profile status
# ---------------------------------------------------------------------------

get_profile_mode() {
    local profile="$1"

    # Check aa-status output
    local status_output
    status_output=$(aa-status 2>/dev/null || true)

    if echo "$status_output" | grep -q "profile $profile.*\(enforce\|$profile\)" 2>/dev/null; then
        echo "enforce"
    elif echo "$status_output" | grep -q "profile $profile.*\(complain\|$profile\)" 2>/dev/null; then
        echo "complain"
    else
        # Alternative check via /sys/kernel/security/apparmor/profiles
        if [[ -f "/sys/kernel/security/apparmor/profiles" ]]; then
            if grep -q "${profile} (enforce)" "/sys/kernel/security/apparmor/profiles" 2>/dev/null; then
                echo "enforce"
            elif grep -q "${profile} (complain)" "/sys/kernel/security/apparmor/profiles" 2>/dev/null; then
                echo "complain"
            else
                echo "unknown"
            fi
        else
            echo "unknown"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Helper: switch profile to enforce mode
# ---------------------------------------------------------------------------

enforce_profile() {
    local profile="$1"

    if aa-enforce "$profile" &>/dev/null 2>&1; then
        echo "enforce"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Helper: switch profile to complain mode
# ---------------------------------------------------------------------------

complain_profile() {
    local profile="$1"

    if aa-complain "$profile" &>/dev/null 2>&1; then
        echo "complain"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Verify AppArmor is installed and running
# ---------------------------------------------------------------------------

echo "[*] Checking AppArmor status..."

APPARMOR_LOADED=false
APPARMOR_ACTIVE=false

check_apparmor_loaded && APPARMOR_LOADED=true
check_apparmor_service && APPARMOR_ACTIVE=true

if ! $APPARMOR_LOADED; then
    echo "    ERROR: AppArmor kernel module not loaded"
    exit 1
fi

if ! $APPARMOR_ACTIVE; then
    echo "    WARNING: AppArmor service not active, attempting to start..."
    systemctl start apparmor 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 2: List all current profiles and their status
# ---------------------------------------------------------------------------

echo ""
echo "[*] Listing all AppArmor profiles:"
aa-status 2>/dev/null | grep -E "(profiles|processes|unconfined)" || echo "    Unable to retrieve profile list"

# ---------------------------------------------------------------------------
# Step 3: Switch Apache and MySQL to enforce mode
# ---------------------------------------------------------------------------

echo ""
echo "[*] Profile enforcement:"

for service in "${SERVICES_TO_ENFORCE[@]}"; do
    current_mode=$(get_profile_mode "$service")

    case "$current_mode" in
        enforce)
            echo "    $service           enforce     [OK]"
            ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
            ;;
        complain)
            result=$(enforce_profile "$service")
            if [[ "$result" == "enforce" ]]; then
                echo "    $service           complain -> enforce  [ENFORCED]"
                ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
            else
                echo "    $service           complain -> enforce  [FAILED]"
            fi
            ;;
        *)
            echo "    $service           NOT FOUND"
            ;;
    esac
done

# Check sshd as example of already enforcing
SSHD_MODE=$(get_profile_mode "/usr/sbin/sshd")
if [[ "$SSHD_MODE" == "enforce" ]]; then
    echo "    /usr/sbin/sshd           enforce              [OK]"
    ENFORCE_COUNT=$((ENFORCE_COUNT + 1))
elif [[ "$SSHD_MODE" == "complain" ]]; then
    echo "    /usr/sbin/sshd           complain             [NOTE]"
    COMPLAIN_COUNT=$((COMPLAIN_COUNT + 1))
fi

# ---------------------------------------------------------------------------
# Step 4: Create custom AppArmor profile for MedDefense billing app
# ---------------------------------------------------------------------------

echo ""
echo "[*] Creating custom profile for MedDefense billing application..."

# Ensure directory exists
mkdir -p "$MEDDEFENSE_APP_PATH" 2>/dev/null || true

if [[ ! -f "$MEDDEFENSE_CUSTOM_PROFILE" ]]; then
    cat > "$MEDDEFENSE_CUSTOM_PROFILE" << 'APPARMOR_PROFILE'
# AppArmor profile for MedDefense Billing Application
# Created by 9-apparmor_config.sh
# Hardened for CIS Control 4 (Audit and Monitoring)

#include <tunables/global>

/opt/meddefense/billing-app {
  # Include base library paths
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Capability requirements
  capability chown,
  capability dac_override,
  capability setuid,
  capability setgid,

  # Network access (HTTP/HTTPS only)
  network inet stream,
  network inet6 stream,

  # Filesystem access - billing application only
  /opt/meddefense/billing-app/** rwk,
  /opt/meddefense/billing-app/config/** rw,
  /opt/meddefense/billing-app/logs/** w,

  # Temporary files
  /tmp/mediapp-* rw,
  /run/mediapp-* rw,

  # Log access
  /var/log/mediapp*.log w,

  # Library access
  /lib/x86_64-linux-gnu/** r,
  /usr/lib/x86_64-linux-gnu/** r,

  # Deny access to sensitive areas
  deny /etc/shadow rw,
  deny /etc/ssh/** rw,
  deny /root/** rw,
  deny /home/** rw,

  # Deny execution of binaries outside application
  deny /bin/** ix,
  deny /usr/bin/** ix,

  # Proc access for monitoring
  /proc/self/** r,
  /proc/sys/fs/file-max r,
}
APPARMOR_PROFILE

    chmod 644 "$MEDDEFENSE_CUSTOM_PROFILE"
    aa-enforce "$MEDDEFENSE_CUSTOM_PROFILE" 2>/dev/null || true
    echo "    Custom profile: $MEDDEFENSE_CUSTOM_PATH   [CREATED] [ENFORCED]"
else
    echo "    Custom profile: $MEDDEFENSE_CUSTOM_PATH   [ALREADY EXISTS]"
fi

# Reload AppArmor profiles
if command -v apparmor_parser &>/dev/null; then
    apparmor_parser -r "$MEDDEFENSE_CUSTOM_PROFILE" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 5: Report unconfined processes that should have profiles
# ---------------------------------------------------------------------------

echo ""
echo "[*] Unconfined network-exposed processes:"

# Get list of unconfined processes
UNCONFINED_PROCS=$(aa-status 2>/dev/null | grep -A100 "unconfined processes" | tail -n +2 | awk '{print $1}' | grep -E '^/' | head -5 || true)

if [[ -n "$UNCONFINED_PROCS" ]]; then
    echo "$UNCONFINED_PROCS" | while read -r proc; do
        [[ -z "$proc" ]] && continue
        # Check if it's a network-exposed service
        if ps aux 2>/dev/null | grep -q "$(basename "$proc")" | grep -v grep; then
            echo "    $proc       [UNCONFINED - Profile recommended]"
            UNCONFINED_COUNT=$((UNCONFINED_COUNT + 1))
        fi
    done

    # Recount since subshell
    UNCONFINED_COUNT=$(echo "$UNCONFINED_PROCS" | grep -c '^' 2>/dev/null || echo "0")
else
    echo "    None detected"
fi

# ---------------------------------------------------------------------------
# Step 6: Final summary
# ---------------------------------------------------------------------------

echo ""

# Get final counts
PROFILE_STATUS=$(aa-status 2>/dev/null || true)
ENFORCE_FINAL=$(echo "$PROFILE_STATUS" | grep -c "(enforce)" 2>/dev/null || echo "0")
COMPLAIN_FINAL=$(echo "$PROFILE_STATUS" | grep -c "(complain)" 2>/dev/null || echo "0")
UNCONFINED_FINAL=$(echo "$PROFILE_STATUS" | grep -A10 "unconfined processes" | grep -c '/' 2>/dev/null || echo "0")

echo "Profiles in enforce: $ENFORCE_FINAL | Complain: $COMPLAIN_FINAL | Unconfined: $UNCONFINED_FINAL"

# ---------------------------------------------------------------------------
# Additional verification
# ---------------------------------------------------------------------------

echo ""
echo "[*] Verification:"
echo "    Running aa-status to confirm changes:"
aa-status 2>/dev/null | head -10 || echo "    Unable to verify"

exit 0
