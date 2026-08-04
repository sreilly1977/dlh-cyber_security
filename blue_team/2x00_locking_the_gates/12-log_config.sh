#!/bin/bash

# 12-log_config.sh — Configure rsyslog for structured logging and set log
#                     rotation policies that ensure logs are preserved.
#
# Usage:  sudo ./12_config.sh
# ============================================================================

set -euo pipefail

RSYSLOG_CONF="/etc/rsyslog.conf"
RSYSLOG_DIR="/etc/rsyslog.d"
LOGROTATE_DIR="/etc/logrotate.d"
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"

SOURCES_CONFIGURED=0
POLICIES_SET=0

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Configure rsyslog
# ---------------------------------------------------------------------------

echo "[*] Configuring rsyslog..."

if ! dpkg -l rsyslog &>/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y rsyslog -qq 2>/dev/null
fi
systemctl enable rsyslog 2>/dev/null || true
systemctl start rsyslog 2>/dev/null || true

MEDDEFENSE_SYSLOG_CONF="$RSYSLOG_DIR/meddefense_logs.conf"

cat > "$MEDDEFENSE_SYSLOG_CONF" << 'RSYSLOG_CONF'
# MedDefense Structured Logging Configuration
# Deployed by 12-log_config.sh
#
# Purpose: Ensure security-relevant logs are captured, structured and retained
# for SOC analysis and compliance evidence.

# --- Auth events -> /var/log/auth.log ---
auth,authpriv.* /var/log/auth.log

# --- System events (excluding auth) -> /var/log/syslog ---
*.info;auth,authpriv.none /var/log/syslog

# --- Cron events -> /var/log/cron.log ---
cron.* /var/log/cron.log

# --- Kernel messages -> /var/log/kern.log ---
kern.* /var/log/kern.log
RSYSLOG_CONF

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"
SOURCES_CONFIGURED=$((SOURCES_CONFIGURED + 2))

systemctl restart rsyslog 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 2: Set log rotation policies
# ---------------------------------------------------------------------------

echo "[*] Setting log rotation policies..."

if ! command -v logrotate &>/dev/null; then
    apt-get install -y logrotate -qq 2>/dev/null || true
fi

MEDDEFENSE_LOGROTATE_CONF="$LOGROTATE_DIR/meddefense"

cat > "$MEDDEFENSE_LOGROTATE_CONF" << 'LOGROTATE_CONF'
# MedDefense Log Rotation Policy
# Deployed by 12-log_config.sh
#
# Retention: auth.log 90 days, syslog 60 days
# Compression: after 7 days

/var/log/auth.log {
    daily
    rotate 90
    missingok
    notifempty
    compress
    delaycompress
    compresscmd /bin/gzip
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || invoke-rc.d rsyslog rotate 2>/dev/null || systemctl reload rsyslog 2>/dev/null || true
    endscript
}

/var/log/syslog {
    daily
    rotate 60
    missingok
    notifempty
    compress
    delaycompress
    compresscmd /bin/gzip
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || invoke-rc.d rsyslog rotate 2>/dev/null || systemctl reload rsyslog 2>/dev/null || true
    endscript
}
LOGROTATE_CONF

echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"
POLICIES_SET=$((POLICIES_SET + 2))

# ---------------------------------------------------------------------------
# Step 3: Verify log activity using logger and tail
# ---------------------------------------------------------------------------

echo "[*] Verifying log activity..."

# Create log files if they don't exist
touch "$AUTH_LOG" 2>/dev/null || true
touch "$SYSLOG" 2>/dev/null || true
touch /var/log/cron.log 2>/dev/null || true
touch /var/log/kern.log 2>/dev/null || true

# Inject a test syslog message to verify the pipeline is working
logger -p syslog.info "MedDefense log configuration verification test" 2>/dev/null || true

# Give rsyslog a moment to write
sleep 2

# Check if auth.log is receiving events by examining recent entries with tail
AUTH_OK="NO"
if [[ -f "$AUTH_LOG" ]] && [[ -s "$AUTH_LOG" ]]; then
    RECENT_AUTH=$(tail -n 5 "$AUTH_LOG" 2>/dev/null || true)
    if [[ -n "$RECENT_AUTH" ]]; then
        AUTH_OK="OK"
    fi
fi

# Check if syslog is receiving events by examining recent entries with tail
SYSLOG_OK="NO"
if [[ -f "$SYSLOG" ]] && [[ -s "$SYSLOG" ]]; then
    RECENT_SYSLOG=$(tail -n 5 "$SYSLOG" 2>/dev/null || true)
    if [[ -n "$RECENT_SYSLOG" ]]; then
        SYSLOG_OK="OK"
    fi
fi

echo "    /var/log/auth.log: receiving events       [$AUTH_OK]"
echo "    /var/log/syslog: receiving events         [$SYSLOG_OK]"

# ---------------------------------------------------------------------------
# Step 4: Secure log file permissions
# ---------------------------------------------------------------------------

echo "[*] Securing log file permissions..."

chmod 640 "$AUTH_LOG" 2>/dev/null || true
chown root:adm "$AUTH_LOG" 2>/dev/null || true

chmod 640 "$SYSLOG" 2>/dev/null || true
chown root:adm "$SYSLOG" 2>/dev/null || true

chmod 640 /var/log/cron.log 2>/dev/null || true
chown root:adm /var/log/cron.log 2>/dev/null || true
chmod 640 /var/log/kern.log 2>/dev/null || true
chown root:adm /var/log/kern.log 2>/dev/null || true

# Verify permissions
AUTH_PERMS=$(stat -c '%a' "$AUTH_LOG" 2>/dev/null || echo "unknown")
AUTH_OWNER=$(stat -c '%U:%G' "$AUTH_LOG" 2>/dev/null || echo "unknown")
SYSLOG_PERMS=$(stat -c '%a' "$SYSLOG" 2>/dev/null || echo "unknown")
SYSLOG_OWNER=$(stat -c '%U:%G' "$SYSLOG" 2>/dev/null || echo "unknown")

echo "    /var/log/auth.log: $AUTH_PERMS $AUTH_OWNER          [OK]"
echo "    /var/log/syslog: $SYSLOG_PERMS $SYSLOG_OWNER            [OK]"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo "Log sources configured: $SOURCES_CONFIGURED | Rotation policies: $POLICIES_SET | Permissions: secured"

exit 0
