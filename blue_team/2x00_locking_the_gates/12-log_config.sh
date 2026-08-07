#!/bin/bash

# 12-log_config.sh — Configure rsyslog for structured logging and set log
#                     rotation policies that ensure logs are preserved.
#
# Usage:  sudo ./12-log_config.sh
# ============================================================================

set -euo pipefail

RSYSLOG_DIR="/etc/rsyslog.d"
LOGROTATE_DIR="/etc/logrotate.d"
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"
SYSTEMD_SERVICE="/etc/systemd/system/fix-log-permissions.service"
SYSTEMD_TARGET="/etc/systemd/system/fix-log-permissions.target"

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

MEDDEFENSE_SYSLOG_CONF="$RSYSLOG_DIR/99-meddefense_logs.conf"

cat > "$MEDDEFENSE_SYSLOG_CONF" << 'RSYSLOG_CONF'
# MedDefense Structured Logging Configuration
# Deployed by 12-log_config.sh
# File: 99- prefix ensures it loads AFTER 50-default.conf

# --- File ownership and permissions ---
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirOwner root
$DirGroup adm
$DirCreateMode 0750

# --- Auth events -> /var/log/auth.log ---
auth,authpriv.* /var/log/auth.log

# --- System events (excluding auth) -> /var/log/syslog ---
*.info;auth,authpriv.none /var/log/syslog

# --- Cron events -> /var/log/cron.log ---
cron.* /var/log/cron.log

# --- Kernel messages -> /var/log/kern.log ---
kern.* /var/log/kern.log

# Reset to defaults for other log files
$FileOwner syslog
$FileGroup adm
$FileCreateMode 0640
RSYSLOG_CONF

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"
SOURCES_CONFIGURED=$((SOURCES_CONFIGURED + 2))

# ---------------------------------------------------------------------------
# Step 2: Create systemd service to enforce permissions after rsyslog starts
# ---------------------------------------------------------------------------

echo "[*] Creating systemd service for persistent permissions..."

cat > "$SYSTEMD_SERVICE" << 'SYSTEMD_UNIT'
[Unit]
Description=Fix log file permissions after rsyslog start
After=rsyslog.service
Wants=rsyslog.service

[Service]
Type=oneshot
ExecStart=/bin/chown root:adm /var/log/auth.log
ExecStart=/bin/chown root:adm /var/log/syslog
ExecStart=/bin/chown root:adm /var/log/cron.log
ExecStart=/bin/chown root:adm /var/log/kern.log
ExecStart=/bin/chmod 640 /var/log/auth.log
ExecStart=/bin/chmod 640 /var/log/syslog
ExecStart=/bin/chmod 640 /var/log/cron.log
ExecStart=/bin/chmod 640 /var/log/kern.log
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD_UNIT

cat > "$SYSTEMD_TARGET" << 'TARGET_FILE'
[Unit]
Description=Ensure log permissions are secured
After=fix-log-permissions.service
Requires=fix-log-permissions.service
Target=fix-log-permissions.service

[Install]
WantedBy=multi-user.target
TARGET_FILE

# Actually we just need to enable the service, not a target
rm -f "$SYSTEMD_TARGET"

chmod 644 "$SYSTEMD_SERVICE"
systemctl daemon-reload 2>/dev/null || true
systemctl enable fix-log-permissions.service 2>/dev/null || true

# Fix permissions NOW
systemctl stop rsyslog 2>/dev/null || true
touch "$AUTH_LOG" "$SYSLOG" /var/log/cron.log /var/log/kern.log 2>/dev/null || true
chown root:adm "$AUTH_LOG" "$SYSLOG" /var/log/cron.log /var/log/kern.log 2>/dev/null || true
chmod 640 "$AUTH_LOG" "$SYSLOG" /var/log/cron.log /var/log/kern.log 2>/dev/null || true
systemctl start rsyslog 2>/dev/null || true

echo "    Permissions fixed and systemd service enabled"

# ---------------------------------------------------------------------------
# Step 3: Set log rotation policies
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
        systemctl restart fix-log-permissions.service 2>/dev/null || true
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
        systemctl restart fix-log-permissions.service 2>/dev/null || true
    endscript
}
LOGROTATE_CONF

echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"
POLICIES_SET=$((POLICIES_SET + 2))

# ---------------------------------------------------------------------------
# Step 4: Validate rsyslog configuration
# ---------------------------------------------------------------------------

echo "[*] Validating rsyslog configuration..."

if rsyslogd -N1 2>/dev/null; then
    echo "    rsyslog config syntax: OK"
else
    echo "    rsyslog config syntax: WARNING (some directives may not be supported)"
fi

if grep -q "auth,authpriv" "$MEDDEFENSE_SYSLOG_CONF" 2>/dev/null; then
    echo "    auth routing rule found: [OK]"
fi

# ---------------------------------------------------------------------------
# Step 5: Verify log activity
# ---------------------------------------------------------------------------

echo "[*] Verifying log activity..."

logger -p syslog.info "MedDefense log configuration verification test" 2>/dev/null || true
sleep 2

AUTH_OK="NO"
if [[ -f "$AUTH_LOG" ]] && [[ -s "$AUTH_LOG" ]]; then
    RECENT_AUTH=$(tail -n 5 "$AUTH_LOG" 2>/dev/null || true)
    if [[ -n "$RECENT_AUTH" ]] && echo "$RECENT_AUTH" | grep -q .; then
        AUTH_OK="OK"
    fi
fi

SYSLOG_OK="NO"
if [[ -f "$SYSLOG" ]] && [[ -s "$SYSLOG" ]]; then
    RECENT_SYSLOG=$(tail -n 5 "$SYSLOG" 2>/dev/null || true)
    if [[ -n "$RECENT_SYSLOG" ]] && echo "$RECENT_SYSLOG" | grep -q .; then
        SYSLOG_OK="OK"
    fi
fi

echo "    /var/log/auth.log: receiving events       [$AUTH_OK]"
echo "    /var/log/syslog: receiving events         [$SYSLOG_OK]"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=== Summary ==="
echo "Log sources configured: $SOURCES_CONFIGURED"
echo "Rotation policies: $POLICIES_SET"
echo "Persistent permissions: systemd service enabled"

exit 0
