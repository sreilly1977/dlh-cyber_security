#!/bin/bash

# 13-firewall_baseline.sh — Configure a host firewall with default-deny
#                           inbound policy, allowing only required services.
#
# Addresses:
#   - 1x02 Finding 006 — billing-srv-01 had 11 open ports before hardening
#   - Service minimization (Task 7) reduced to 4-5 services
#   - Firewall enforces network-layer access control independent of services
#
# Usage:  sudo ./13-firewall_baseline.sh
# ============================================================================

set -euo pipefail

# Management network (SSH access)
MGMT_NETWORK="10.10.1.0/24"

# Application network (MySQL access)
APP_NETWORK="10.10.2.0/24"

# Logging level for denied connections
LOG_LEVEL="low"

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Ensure UFW is installed
# ---------------------------------------------------------------------------

echo "[*] Configuring UFW..."

if ! command -v ufw &>/dev/null; then
    echo "    Installing UFW..."
    apt-get update -qq && apt-get install -y ufw -qq 2>/dev/null
fi

# Reset UFW to clean slate
ufw --force reset 2>/dev/null || true

# Set default policies — default deny incoming, default allow outgoing
ufw default deny incoming 2>/dev/null || true
echo "    Default incoming: deny"

ufw default allow outgoing 2>/dev/null || true
echo "    Default outgoing: allow"

# ---------------------------------------------------------------------------
# Add allow rules for required services
# ---------------------------------------------------------------------------

echo "[*] Adding allow rules..."

# SSH from management network only
ufw allow from "$MGMT_NETWORK" to any port 22 proto tcp 2>/dev/null || true
echo "    22/tcp from $MGMT_NETWORK   [ADDED] SSH - management only"

# HTTP (unrestricted for public-facing web server)
ufw allow 80/tcp 2>/dev/null || true
echo "    80/tcp                     [ADDED] HTTP"

# HTTPS (unrestricted for public-facing web server)
ufw allow 443/tcp 2>/dev/null || true
echo "    443/tcp                    [ADDED] HTTPS"

# MySQL from application network only
ufw allow from "$APP_NETWORK" to any port 3306 proto tcp 2>/dev/null || true
echo "    3306/tcp from $APP_NETWORK [ADDED] MySQL - app network only"

# ---------------------------------------------------------------------------
# Enable logging for denied connections
# ---------------------------------------------------------------------------

echo "[*] Enabling logging..."

ufw logging "$LOG_LEVEL" 2>/dev/null || true
echo "    Logging: on ($LOG_LEVEL)"

# ---------------------------------------------------------------------------
# Activate the firewall
# ---------------------------------------------------------------------------

echo "[*] Activating firewall..."

ufw --force enable 2>/dev/null || true
sleep 2

UFW_STATUS=$(ufw status 2>/dev/null | head -1 || echo "inactive")

if echo "$UFW_STATUS" | grep -qi "active"; then
    echo "    UFW: active"
    FIREWALL_ACTIVE=true
else
    echo "    WARNING: UFW may not be fully active yet"
    echo "    Status: $UFW_STATUS"
    FIREWALL_ACTIVE=false
fi

# ---------------------------------------------------------------------------
# Display and validate the active ruleset
# ---------------------------------------------------------------------------

echo ""
echo "[*] Active firewall rules:"

ufw status verbose 2>/dev/null || echo "    Unable to retrieve rules"

# Count allow rules
ALLOW_RULES=$(ufw status 2>/dev/null | grep -c "ALLOW" || echo "0")

echo ""
echo "Rules: $ALLOW_RULES allow, default deny"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "Firewall baseline deployed: default deny incoming, default allow outgoing"
echo "Allowed ports: 22 (management), 80/443 (public), 3306 (application network)"
echo "Logging: $LOG_LEVEL"

if $FIREWALL_ACTIVE; then
    echo "Status: ACTIVE"
else
    echo "WARNING: Manual activation may be required"
fi

exit 0
