#!/bin/bash
#
# Name:        13-dns_filtering.sh
# Purpose:     Configure local DNS filtering with dnsmasq and validate blocklist/allowlist
# Author:      Steve - Cybersecurity Engineer
# Date:        August 14, 2026
#

set -euo pipefail

# Configuration
BLOCKLIST_FILE="/home/analyst/MedDefense_Lab/dns/blocklist.txt"
ALLOWLIST_FILE="/home/analyst/MedDefense_Lab/dns/allowlist.txt"
UPSTREAM_SOURCE="/home/analyst/MedDefense_Lab/dns/meddefense-upstream.conf"
UPSTREAM_TARGET="/etc/dnsmasq.d/meddefense-upstream.conf"
BLOCKLIST_CONF="/etc/dnsmasq.d/meddefense-blocklist.conf"
LOG_FILE="/var/log/dnsmasq.log"

# Verify required files exist
if [[ ! -f "$BLOCKLIST_FILE" ]]; then
    echo "Error: Blocklist file not found: $BLOCKLIST_FILE" >&2
    exit 1
fi

if [[ ! -f "$ALLOWLIST_FILE" ]]; then
    echo "Error: Allowlist file not found: $ALLOWLIST_FILE" >&2
    exit 1
fi

if [[ ! -f "$UPSTREAM_SOURCE" ]]; then
    echo "Error: Upstream config not found: $UPSTREAM_SOURCE" >&2
    exit 1
fi

# ---------------------------------------------------------------
# 1. Ensure dnsmasq is installed (idempotent)
# ---------------------------------------------------------------
echo -n "[*] Ensuring dnsmasq is installed...     "

# Check if installed and get version
if command -v dnsmasq >/dev/null 2>&1; then
    DNMASQ_VERSION=$(dnsmasq --version 2>&1 | head -n 1 | grep -E -o '[0-9]+\.[0-9]+' || echo "unknown")
else
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq dnsmasq >/dev/null 2>&1
    DNMASQ_VERSION=$(dnsmasq --version 2>&1 | head -n 1 | grep -E -o '[0-9]+\.[0-9]+' || echo "installed")
fi

echo "${DNMASQ_VERSION:-unknown}"

# ---------------------------------------------------------------
# 2. Copy upstream config if not already present
# ---------------------------------------------------------------
if [[ ! -f "$UPSTREAM_TARGET" ]]; then
    cp "$UPSTREAM_SOURCE" "$UPSTREAM_TARGET"
    chown root:root "$UPSTREAM_TARGET"
    chmod 644 "$UPSTREAM_TARGET"
fi

# ---------------------------------------------------------------
# 3. Render blocklist configuration
#    Convert each domain to: address=/domain/0.0.0.0
#    Skip comment lines (starting with #) and empty lines
# ---------------------------------------------------------------
echo -n "[*] Rendering blocklist...               "

# Count actual domains (non-comment, non-empty lines)
DOMAIN_COUNT=$(grep -v '^#' "$BLOCKLIST_FILE" | grep -cv '^[[:space:]]*$' || echo 0)

# Generate the config file
cat > "$BLOCKLIST_CONF" <<EOF
# MedDefense DNS blocklist - generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Domains returning sinkhole 0.0.0.0
EOF

grep -v '^#' "$BLOCKLIST_FILE" | grep -v '^[[:space:]]*$' | while read -r domain; do
    domain=$(echo "$domain" | tr -d '[:space:]')
    [[ -n "$domain" ]] && echo "address=/$domain/0.0.0.0"
done >> "$BLOCKLIST_CONF"

chown root:root "$BLOCKLIST_CONF"
chmod 644 "$BLOCKLIST_CONF"

# Add logging config to upstream target
if ! grep -q "log-queries" "$UPSTREAM_TARGET"; then
    cat >> "$UPSTREAM_TARGET" <<EOF

# Logging configuration
log-queries
log-facility=$LOG_FILE
EOF
fi

echo "($DOMAIN_COUNT domains)"

# ---------------------------------------------------------------
# 4. Restart dnsmasq and verify service is running
# ---------------------------------------------------------------
echo -n "[*] Restarting dnsmasq.service...        "

systemctl restart dnsmasq.service 2>/dev/null || true
sleep 1

if systemctl is-active --quiet dnsmasq.service 2>/dev/null; then
    echo "active"
elif pgrep -x "dnsmasq" >/dev/null 2>&1; then
    echo "active"
else
    echo "failed" >&2
    exit 1
fi

# ---------------------------------------------------------------
# 5. Validation queries using dig @127.0.0.1
# ---------------------------------------------------------------
echo "[*] Validation queries..."

# Get first allowed domain from allowlist (skip comments)
ALLOW_DOMAIN=$(awk '!/^#/ && !/^[[:space:]]*$/ {print; exit}' "$ALLOWLIST_FILE" | tr -d '[:space:]' || true)
ALLOW_DOMAIN=${ALLOW_DOMAIN:-billing.meddefense.local}

# Get first blocked domain from blocklist (skip comments)
BLOCK_DOMAIN=$(awk '!/^#/ && !/^[[:space:]]*$/ {print; exit}' "$BLOCKLIST_FILE" | tr -d '[:space:]' || true)
BLOCK_DOMAIN=${BLOCK_DOMAIN:-c2.crimson-tide-ops.xyz}

# Use a domain not in either list for upstream validation (pick one clearly outside both)
UPSTREAM_DOMAIN="example.net"

# Verify it's not in the blocklist or allowlist
if grep -q "$UPSTREAM_DOMAIN" "$BLOCKLIST_FILE" 2>/dev/null || grep -q "$UPSTREAM_DOMAIN" "$ALLOWLIST_FILE" 2>/dev/null; then
    UPSTREAM_DOMAIN="mozilla.org"
fi

# Query 1: Known allowed domain
echo -n "  dig @127.0.0.1 $ALLOW_DOMAIN"
ALLOW_RESULT=$(dig @127.0.0.1 "$ALLOW_DOMAIN" +short 2>/dev/null || echo "")
if [[ -z "$ALLOW_RESULT" || "$ALLOW_RESULT" == "0.0.0.0" ]]; then
    echo ""
    echo "      -> $ALLOW_RESULT               expected allow   FAIL"
else
    echo ""
    echo "      -> $ALLOW_RESULT               expected allow      PASS"
fi

# Query 2: Known blocked domain
echo -n "  dig @127.0.0.1 $BLOCK_DOMAIN"
BLOCK_RESULT=$(dig @127.0.0.1 "$BLOCK_DOMAIN" +short 2>/dev/null || echo "")
if [[ "$BLOCK_RESULT" == "0.0.0.0" ]]; then
    echo ""
    echo "      -> $BLOCK_RESULT               expected sinkhole   PASS"
else
    echo ""
    echo "      -> $BLOCK_RESULT               expected sinkhole   FAIL"
fi

# Query 3: Domain not in either list (should resolve via upstream)
echo -n "  dig @127.0.0.1 $UPSTREAM_DOMAIN"
UPSTREAM_RESULT=$(dig @127.0.0.1 "$UPSTREAM_DOMAIN" +short 2>/dev/null || echo "")
if [[ -n "$UPSTREAM_RESULT" && "$UPSTREAM_RESULT" != "0.0.0.0" ]]; then
    echo ""
    echo "      -> $UPSTREAM_RESULT        expected allow      PASS"
else
    echo ""
    echo "      -> $UPSTREAM_RESULT            expected allow      FAIL"
fi

# ---------------------------------------------------------------
# 6. Output summary as JSON for audit trail
# ---------------------------------------------------------------
echo ""
echo "[*] Generating audit summary..."

jq -n \
    --arg version "$DNMASQ_VERSION" \
    --arg domains "$DOMAIN_COUNT" \
    --arg blocklist "$BLOCKLIST_CONF" \
    --arg upstream "$UPSTREAM_TARGET" \
    --arg service_status "$(systemctl is-active dnsmasq.service 2>/dev/null || echo 'inactive')" \
    --arg timestamp "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{
        dnsmasq_version: $version,
        blocked_domains: ($domains | tonumber),
        config_files: {
            blocklist: $blocklist,
            upstream: $upstream
        },
        service_status: $service_status,
        generated_at: $timestamp
    }' > dnsmasq-audit-summary.json 2>/dev/null || true

echo "  Audit summary written to dnsmasq-audit-summary.json"
echo ""
echo "Configuration files:"
echo "  Blocklist:  $BLOCKLIST_CONF"
echo "  Upstream:   $UPSTREAM_TARGET"
echo "  Log file:   $LOG_FILE"
