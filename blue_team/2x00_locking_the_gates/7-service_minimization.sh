#!/bin/bash

# 7-service_minimization.sh — Identify and disable unnecessary services
#                              to reduce the attack surface for MedDefense servers.
#
# Usage:  sudo ./7-service_minimization.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

if ! command -v systemctl &>/dev/null; then
    echo "ERROR: systemctl not found. This script requires systemd." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# MedDefense required services whitelist
# Each service includes a comment explaining why it's needed
# ---------------------------------------------------------------------------

declare -a WHITELIST=(
    # Core security and logging
    "ssh.service: Remote administration access"
    "ufw.service: Firewall enforcement (packet filtering)"
    "auditd.service: Security event auditing (CIS Control 4)"
    "apparmor.service: Mandatory access control"
    "cron.service: Scheduled task execution (backup jobs, log rotation)"
    "rsyslog.service: Centralized logging aggregation"

    # Network time synchronization
    "systemd-timesyncd.service: NTP time sync (log correlation requires consistent timestamps)"

    # Application-specific (billing server)
    "apache2.service: Web application host (MedDefense billing portal)"
    "mysql.service: Database backend (billing data storage)"
)

# Counters
ENABLED_BEFORE=0
DISABLED_COUNT=0
REQUIRED_ACTIVE=0

# ---------------------------------------------------------------------------
# Helper: extract service name from "name:description" format
# ---------------------------------------------------------------------------

get_service_name() {
    local entry="$1"
    echo "$entry" | sed 's/:.*//'
}

# ---------------------------------------------------------------------------
# Helper: check if service is enabled
# ---------------------------------------------------------------------------

is_enabled() {
    local service="$1"
    systemctl is-enabled "$service" 2>/dev/null | grep -qE '^(enabled|static)$'
}

# ---------------------------------------------------------------------------
# Helper: check if service is active (running)
# ---------------------------------------------------------------------------

is_active() {
    local service="$1"
    systemctl is-active "$service" 2>/dev/null | grep -q 'active'
}

# ---------------------------------------------------------------------------
# Helper: stop and disable a service
# ---------------------------------------------------------------------------

disable_service() {
    local service="$1"

    if is_active "$service"; then
        systemctl stop "$service" 2>/dev/null || true
        echo "  $service     [STOPPED]"
    else
        echo "  $service     [ALREADY STOPPED]"
    fi

    systemctl disable "$service" 2>/dev/null || true
    echo "               [DISABLED]"
}

# ---------------------------------------------------------------------------
# Step 1: Scan enabled services using systemctl list-unit-files
# ---------------------------------------------------------------------------

echo "[*] Scanning enabled services..."

# Use systemctl list-unit-files to get enabled services
ENABLED_SERVICES=$(systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | \
                   grep 'enabled' | awk '{print $1}' || true)

ENABLED_BEFORE=$(echo "$ENABLED_SERVICES" | grep -c '.' 2>/dev/null || echo "0")
[[ -z "$ENABLED_SERVICES" ]] && ENABLED_BEFORE=0

echo "    Enabled services found: $ENABLED_BEFORE"

# Also check list-units for additional context
ALL_UNITS=$(systemctl list-units --type=service --all --no-pager 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Step 2: Compare against whitelist and disable non-essential services
# ---------------------------------------------------------------------------

echo "[*] Comparing against MedDefense whitelist ($(( ${#WHITELIST[@]} )) required services)..."

declare -a REQUIRED_SERVICES=()
for entry in "${WHITELIST[@]}"; do
    service_name=$(get_service_name "$entry")
    REQUIRED_SERVICES+=("$service_name")
done

declare -a DISABLED_LIST=()
declare -a ACTIVE_REQUIRED=()

# Process each enabled service
while read -r service; do
    [[ -z "$service" ]] && continue

    service_base=$(basename "$service")
    found_in_whitelist=false

    for req_service in "${REQUIRED_SERVICES[@]}"; do
        if [[ "$service_base" == "$req_service" ]]; then
            found_in_whitelist=true
            break
        fi
    done

    if $found_in_whitelist; then
        if is_active "$service_base"; then
            echo "  $service_base     [ACTIVE]"
            ACTIVE_REQUIRED+=("$service_base")
        else
            echo "  $service_base     [STARTING...]"
            systemctl start "$service_base" 2>/dev/null || true
            ACTIVE_REQUIRED+=("$service_base")
        fi
    else
        disable_service "$service_base"
        DISABLED_LIST+=("$service_base")
    fi
done <<< "$ENABLED_SERVICES"

DISABLED_COUNT=${#DISABLED_LIST[@]}

# Count remaining enabled services
ENABLED_AFTER=0
for service in "${REQUIRED_SERVICES[@]}"; do
    if is_enabled "$service"; then
        ENABLED_AFTER=$((ENABLED_AFTER + 1))
    fi
done

# ---------------------------------------------------------------------------
# Step 3: Verify required services are running
# ---------------------------------------------------------------------------

echo ""
echo "[*] Verifying required services..."

for service in "${REQUIRED_SERVICES[@]}"; do
    if is_active "$service"; then
        echo "  $service     [RUNNING]"
        REQUIRED_ACTIVE=$((REQUIRED_ACTIVE + 1))
    else
        echo "  $service     [NOT RUNNING]"
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "Before: $ENABLED_BEFORE | After: $ENABLED_AFTER | Disabled: $DISABLED_COUNT"
echo "Required services verified running: $REQUIRED_ACTIVE/${#WHITELIST[@]}"

exit 0
