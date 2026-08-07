#!/bin/bash

# 9-apparmor_config.sh — Deploy and configure AppArmor profiles in enforce mode
#                        for all network-exposed services.
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
# Uses /sys/module instead of lsmod to handle built-in kernels
# ---------------------------------------------------------------------------

check_apparmor_loaded() {
    if [[ -d /sys/module/apparmor ]]; then
        echo "    AppArmor module: loaded"
        return 0
    elif lsmod 2>/dev/null | grep -q apparmor; then
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
    if systemctl is-active --quiet apparmor 2>/dev/null; then
        echo "    AppArmor service: active"
        return 0
    else
        echo "    AppArmor service: inactive"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Helper: get profile status
# Returns: enforce, complain, or unknown
# Always returns 0 to avoid set -e killing the script
# ---------------------------------------------------------------------------

get_profile_mode() {
    local profile="$1"
    local profiles_file="/sys/kernel/security/apparmor/profiles"

    if [[ -f "$profiles_file" ]]; then
        if grep -q "^${profile} (enforce)" "$profiles_file" 2>/dev/null; then
            echo "enforce"
            return 0
        elif grep -q "^${profile} (complain)" "$profiles_file" 2>/dev/null; then
            echo "complain"
            return 0
        fi
    fi

    # Fallback: try aa-status
    if command -v aa-status &>/dev/null; then
        local status_output
        status_output=$(aa-status 2>/dev/null || true)

        if echo "$status_output" | grep -qE "${profile}.*enforce"; then
            echo "enforce"
            return 0
        elif echo "$status_output" | grep -qE "${profile}.*complain"; then
            echo "complain"
            return 0
        fi
    fi

    echo "unknown"
    return 0
}

# ---------------------------------------------------------------------------
# Helper: switch profile to enforce mode
# ---------------------------------------------------------------------------

enforce_profile() {
    local profile="$1"

    if aa-enforce "$profile" 2>/dev/null; then
        echo "enforce"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Step 1: Verify AppArmor is installed and running
# ---------------------------------------------------------------------------

echo "[*] Checking AppArmor status..."

check_apparmor_loaded

if ! check_apparmor_service; then
    echo "    WARNING: AppArmor service not active, attempting to start..."
    systemctl start apparmor 2>/dev/null || true
fi

# Re-check service after attempt to start
if ! systemctl is-active --quiet apparmor 2>/dev/null; then
    echo "    WARNING: AppArmor service could not be activated"
    echo "    Continuing anyway — profiles may still be loadable"
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
    current_mode=$(get_profile_mode "$service") || current_mode="unknown"

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
            echo "    $service           NOT FOUND (no existing profile)"
            ;;
    esac
done

# Check sshd as example of already enforcing
SSHD_MODE=$(get_profile_mode "/usr/sbin/sshd") || SSHD_MODE="unknown"
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
  deny /bin/** x,
  deny /usr/bin/** x,

  # Proc access for monitoring
  /proc/self/** r,
  /proc/sys/fs/file-max r,
}
APPARMOR_PROFILE

    chmod 644 "$MEDDEFENSE_CUSTOM_PROFILE"
    echo "    Custom profile: $MEDDEFENSE_CUSTOM_PROFILE   [CREATED]"
else
    echo "    Custom profile: $MEDDEFENSE_CUSTOM_PROFILE   [ALREADY EXISTS]"
fi

# Load/reload the custom profile with apparmor_parser — show errors for debugging
if command -v apparmor_parser &>/dev/null; then
    # Remove old profile from kernel if loaded
    apparmor_parser -R "$MEDDEFENSE_CUSTOM_PROFILE" 2>/dev/null || true

    # Load fresh
    if apparmor_parser -r "$MEDDEFENSE_CUSTOM_PROFILE" 2>&1; then
        echo "    Profile loaded via apparmor_parser: [OK]"
        # Now switch to enforce mode using the app path
        aa-enforce "$MEDDEFENSE_APP_PATH" 2>/dev/null && \
            echo "    Enforce mode: [ACTIVATED]" || \
            echo "    Enforce mode: [FAILED - profile may not be attached to a running process]"
    else
        echo "    Profile load: [FAILED - see errors above]"
    fi
else
    echo "    apparmor_parser not found, skipping profile load"
fi

# ---------------------------------------------------------------------------
# Step 5: Report unconfined processes that should have profiles
# ---------------------------------------------------------------------------

echo ""
echo "[*] Unconfined network-exposed processes:"

# Get list of unconfined processes from aa-status
UNCONFINED_PROCS=$(aa-status 2>/dev/null | sed -n '/unconfined/,/^$/p' | grep -E '^\s*/' | head -5 || true)

if [[ -n "$UNCONFINED_PROCS" ]]; then
    while IFS= read -r proc; do
        [[ -z "$proc" ]] && continue
        echo "    $proc       [UNCONFINED - Profile recommended]"
        UNCONFINED_COUNT=$((UNCONFINED_COUNT + 1))
    done < <(printf '%s\n' "$UNCONFINED_PROCS")
else
    echo "    None detected"
fi

# ---------------------------------------------------------------------------
# Step 6: Final summary
# ---------------------------------------------------------------------------

echo ""

# Get final counts from aa-status (fixed: assign outside $())
ENFORCE_FINAL=$(aa-status 2>/dev/null | grep -c "(enforce)" 2>/dev/null) || ENFORCE_FINAL=0
COMPLAIN_FINAL=$(aa-status 2>/dev/null | grep -c "(complain)" 2>/dev/null) || COMPLAIN_FINAL=0
UNCONFINED_FINAL=$(aa-status 2>/dev/null | sed -n '/unconfined/,/^$/p' | grep -c '/' 2>/dev/null) || UNCONFINED_FINAL=0

echo "Profiles in enforce: $ENFORCE_FINAL | Complain: $COMPLAIN_FINAL | Unconfined: $UNCONFINED_FINAL"

# ---------------------------------------------------------------------------
# Additional verification
# ---------------------------------------------------------------------------

echo ""
echo "[*] Verification:"
echo "    Running aa-status to confirm changes:"
aa-status 2>/dev/null | head -10 || echo "    Unable to verify"

exit 0
