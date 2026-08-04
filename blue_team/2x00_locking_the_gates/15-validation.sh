#!/bin/bash

# 15-validation.sh — Post-Hardening Validator
#                     Reads system state and compares against expected hardening values.
#                     Makes NO changes — read-only verification only.
#
# Context:
#   - Configuration drift happens over time (debug changes, updates, etc.)
#   - This is a continuous validation tool run periodically (e.g., every Monday)
#   - Exits 0 if all checks pass, exits 1 if any fail
#
# Usage:  sudo ./15-validation.sh
# ============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Track failures for exit code
EXIT_CODE=0

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

check_pass() {
    local description="$1"
    echo "[PASS] $description"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
}

check_fail() {
    local description="$1"
    local actual="${2:-N/A}"
    local expected="${3:-N/A}"

    if [[ -n "$actual" ]] && [[ -n "$expected" ]]; then
        echo "[FAIL] $description (actual: $actual, expected: $expected)"
    else
        echo "[FAIL] $description"
    fi

    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    EXIT_CODE=1
}

# ---------------------------------------------------------------------------
# SSH Hardening Validation (Task 4: ssh_hardening.sh)
# ---------------------------------------------------------------------------

echo "=== SSH Hardening Checks ==="

SSH_CONFIG="/etc/ssh/sshd_config"

if [[ -f "$SSH_CONFIG" ]]; then
    # PermitRootLogin = no
    ROOT_LOGIN=$(grep -E "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ "$ROOT_LOGIN" == "no" ]]; then
        check_pass "PermitRootLogin = no"
    else
        check_fail "PermitRootLogin" "$ROOT_LOGIN" "no"
    fi

    # PasswordAuthentication = no
    PASSWORD_AUTH=$(grep -E "^PasswordAuthentication" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ "$PASSWORD_AUTH" == "no" ]]; then
        check_pass "PasswordAuthentication = no"
    else
        check_fail "PasswordAuthentication" "$PASSWORD_AUTH" "no"
    fi

    # MaxAuthTries = 3
    MAX_AUTH=$(grep -E "^MaxAuthTries" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ "$MAX_AUTH" == "3" ]]; then
        check_pass "MaxAuthTries = 3"
    else
        check_fail "MaxAuthTries" "$MAX_AUTH" "3"
    fi

    # X11Forwarding = no
    X11_FWD=$(grep -E "^X11Forwarding" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ "$X11_FWD" == "no" ]]; then
        check_pass "X11Forwarding = no"
    else
        check_fail "X11Forwarding" "$X11_FWD" "no"
    fi

    # ClientAliveInterval = 300
    CLIENT_ALIVE=$(grep -E "^ClientAliveInterval" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
    if [[ "$CLIENT_ALIVE" == "300" ]]; then
        check_pass "ClientAliveInterval = 300"
    else
        check_fail "ClientAliveInterval" "$CLIENT_ALIVE" "300"
    fi

    # Protocol = 2 (deprecated in newer OpenSSH, skip if not applicable)
    if grep -q "^Protocol" "$SSH_CONFIG" 2>/dev/null; then
        PROTOCOL=$(grep -E "^Protocol" "$SSH_CONFIG" 2>/dev/null | awk '{print $2}' || echo "")
        if [[ "$PROTOCOL" == "2" ]]; then
            check_pass "Protocol = 2"
        else
            check_fail "Protocol" "$PROTOCOL" "2"
        fi
    fi
else
    check_fail "sshd_config file not found"
fi

# ---------------------------------------------------------------------------
# Sysctl Hardening Validation (Task 5: sysctl_hardening.sh)
# ---------------------------------------------------------------------------

echo ""
echo "=== Sysctl Hardening Checks ==="

# Helper to read sysctl value
read_sysctl() {
    local key="$1"
    sysctl -n "$key" 2>/dev/null || echo ""
}

# net.ipv4.ip_forward = 0
IP_FORWARD=$(read_sysctl "net.ipv4.ip_forward")
if [[ "$IP_FORWARD" == "0" ]]; then
    check_pass "net.ipv4.ip_forward = 0"
else
    check_fail "net.ipv4.ip_forward" "$IP_FORWARD" "0"
fi

# net.ipv4.tcp_syncookies = 1
TCP_SYNCOOKIES=$(read_sysctl "net.ipv4.tcp_syncookies")
if [[ "$TCP_SYNCOOKIES" == "1" ]]; then
    check_pass "net.ipv4.tcp_syncookies = 1"
else
    check_fail "net.ipv4.tcp_syncookies" "$TCP_SYNCOOKIES" "1"
fi

# kernel.randomize_va_space = 2
ASLR=$(read_sysctl "kernel.randomize_va_space")
if [[ "$ASLR" == "2" ]]; then
    check_pass "kernel.randomize_va_space = 2"
else
    check_fail "kernel.randomize_va_space" "$ASLR" "2"
fi

# net.ipv4.conf.all.log_martians = 1
MARTIANS_ALL=$(read_sysctl "net.ipv4.conf.all.log_martians")
if [[ "$MARTIANS_ALL" == "1" ]]; then
    check_pass "net.ipv4.conf.all.log_martians = 1"
else
    check_fail "net.ipv4.conf.all.log_martians" "$MARTIANS_ALL" "1"
fi

# net.ipv4.conf.default.log_martians = 1
MARTIANS_DEFAULT=$(read_sysctl "net.ipv4.conf.default.log_martians")
if [[ "$MARTIANS_DEFAULT" == "1" ]]; then
    check_pass "net.ipv4.conf.default.log_martians = 1"
else
    check_fail "net.ipv4.conf.default.log_martians" "$MARTIANS_DEFAULT" "1"
fi

# net.ipv4.icmp_echo_ignore_broadcasts = 1
ICMP_BROADCAST=$(read_sysctl "net.ipv4.icmp_echo_ignore_broadcasts")
if [[ "$ICMP_BROADCAST" == "1" ]]; then
    check_pass "net.ipv4.icmp_echo_ignore_broadcasts = 1"
else
    check_fail "net.ipv4.icmp_echo_ignore_broadcasts" "$ICMP_BROADCAST" "1"
fi

# net.ipv4.icmp_ignore_bogus_error_responses = 1
ICMP_BOGUS=$(read_sysctl "net.ipv4.icmp_ignore_bogus_error_responses")
if [[ "$ICMP_BOGUS" == "1" ]]; then
    check_pass "net.ipv4.icmp_ignore_bogus_error_responses = 1"
else
    check_fail "net.ipv4.icmp_ignore_bogus_error_responses" "$ICMP_BOGUS" "1"
fi

# net.ipv4.conf.all.accept_redirects = 0
ACCEPT_REDIRECTS=$(read_sysctl "net.ipv4.conf.all.accept_redirects")
if [[ "$ACCEPT_REDIRECTS" == "0" ]]; then
    check_pass "net.ipv4.conf.all.accept_redirects = 0"
else
    check_fail "net.ipv4.conf.all.accept_redirects" "$ACCEPT_REDIRECTS" "0"
fi

# net.ipv4.conf.all.send_redirects = 0
SEND_REDIRECTS=$(read_sysctl "net.ipv4.conf.all.send_redirects")
if [[ "$SEND_REDIRECTS" == "0" ]]; then
    check_pass "net.ipv4.conf.all.send_redirects = 0"
else
    check_fail "net.ipv4.conf.all.send_redirects" "$SEND_REDIRECTS" "0"
fi

# net.ipv4.conf.all.rp_filter = 1
RP_FILTER=$(read_sysctl "net.ipv4.conf.all.rp_filter")
if [[ "$RP_FILTER" == "1" ]]; then
    check_pass "net.ipv4.conf.all.rp_filter = 1"
else
    check_fail "net.ipv4.conf.all.rp_filter" "$RP_FILTER" "1"
fi

# ---------------------------------------------------------------------------
# Auditd Validation (Task 10: auditd_config.sh)
# ---------------------------------------------------------------------------

echo ""
echo "=== Auditd Validation Checks ==="

# Check auditd.service is active
if systemctl is-active --quiet auditd 2>/dev/null; then
    check_pass "auditd.service = active"
else
    check_fail "auditd.service" "$(systemctl is-active auditd 2>/dev/null || echo 'inactive')" "active"
fi

# Check audit rules are loaded
RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l || echo "0")
if [[ "$RULE_COUNT" -gt 5 ]]; then
    check_pass "Audit rules loaded ($RULE_COUNT rules)"
else
    check_fail "Audit rules loaded" "$RULE_COUNT" "> 5"
fi

# Check /etc/audit/auditd.conf exists
if [[ -f "/etc/audit/auditd.conf" ]]; then
    check_pass "auditd.conf exists"
else
    check_fail "auditd.conf exists"
fi

# ---------------------------------------------------------------------------
# AppArmor Validation (Task 9: apparmor_config.sh)
# ---------------------------------------------------------------------------

echo ""
echo "=== AppArmor Validation Checks ==="

# Check apparmor.service is active
if systemctl is-active --quiet apparmor 2>/dev/null; then
    check_pass "apparmor.service = active"
else
    check_fail "apparmor.service" "$(systemctl is-active apparmor 2>/dev/null || echo 'inactive')" "active"
fi

# Check aa-enforce or aa-status exists
if command -v aa-status &>/dev/null || command -v aa-enforce &>/dev/null; then
    check_pass "AppArmor tools installed"
else
    check_fail "AppArmor tools installed"
fi

# Check AppArmor is enabled
if [[ -d "/sys/kernel/security/apparmor" ]]; then
    check_pass "AppArmor kernel interface present"
else
    check_fail "AppArmor kernel interface present"
fi

# ---------------------------------------------------------------------------
# Log Configuration Validation (Task 12: log_config.sh)
# ---------------------------------------------------------------------------

echo ""
echo "=== Log Configuration Validation Checks ==="

# Check auth.log exists and has proper permissions
if [[ -f "/var/log/auth.log" ]]; then
    AUTH_PERMS=$(stat -c '%a' /var/log/auth.log 2>/dev/null || echo "")
    AUTH_OWNER=$(stat -c '%U:%G' /var/log/auth.log 2>/dev/null || echo "")
    if [[ "$AUTH_PERMS" == "640" ]] && [[ "$AUTH_OWNER" == "root:adm" ]]; then
        check_pass "/var/log/auth.log permissions (640 root:adm)"
    else
        check_fail "/var/log/auth.log permissions" "$AUTH_PERMS $AUTH_OWNER" "640 root:adm"
    fi
else
    check_fail "/var/log/auth.log exists"
fi

# Check syslog exists
if [[ -f "/var/log/syslog" ]]; then
    SYSLOG_PERMS=$(stat -c '%a' /var/log/syslog 2>/dev/null || echo "")
    SYSLOG_OWNER=$(stat -c '%U:%G' /var/log/syslog 2>/dev/null || echo "")
    if [[ "$SYSLOG_PERMS" == "640" ]] && [[ "$SYSLOG_OWNER" == "root:adm" ]]; then
        check_pass "/var/log/syslog permissions (640 root:adm)"
    else
        check_fail "/var/log/syslog permissions" "$SYSLOG_PERMS $SYSLOG_OWNER" "640 root:adm"
    fi
else
    check_fail "/var/log/syslog exists"
fi

# Check rsyslog is running
if systemctl is-active --quiet rsyslog 2>/dev/null; then
    check_pass "rsyslog.service = active"
else
    check_fail "rsyslog.service" "$(systemctl is-active rsyslog 2>/dev/null || echo 'inactive')" "active"
fi

# ---------------------------------------------------------------------------
# Firewall Validation (Task 13: firewall_baseline.sh)
# ---------------------------------------------------------------------------

echo ""
echo "=== Firewall Validation Checks ==="

# Check UFW is active
if ufw status 2>/dev/null | grep -qi "active"; then
    check_pass "UFW status = active"
else
    check_fail "UFW status" "inactive" "active"
    EXIT_CODE=1
fi

# Check default incoming policy
UFW_DEFAULT_IN=$(ufw status verbose 2>/dev/null | grep -i "Default:" | grep -oE "incoming [a-z]+" | awk '{print $2}' || echo "")
if [[ "$UFW_DEFAULT_IN" == "deny" ]]; then
    check_pass "Default incoming = deny"
else
    check_fail "Default incoming" "$UFW_DEFAULT_IN" "deny"
fi

# Check default outgoing policy
UFW_DEFAULT_OUT=$(ufw status verbose 2>/dev/null | grep -i "Default:" | grep -oE "outgoing [a-z]+" | awk '{print $2}' || echo "")
if [[ "$UFW_DEFAULT_OUT" == "allow" ]]; then
    check_pass "Default outgoing = allow"
else
    check_fail "Default outgoing" "$UFW_DEFAULT_OUT" "allow"
fi

# ---------------------------------------------------------------------------
# Filesystem Hardening Validation (Task 6: filesystem_hardening.sh)
# ---------------------------------------------------------------------------

echo ""
echo "=== Filesystem Hardening Checks ==="

# Check /tmp is mounted with nosuid,nodev (if it's a separate partition)
if mount | grep -q "/tmp "; then
    TMP_MOUNT=$(mount | grep "/tmp " | grep -oE "nosuid" || echo "")
    NODEV_MOUNT=$(mount | grep "/tmp " | grep -oE "nodev" || echo "")
    if [[ -n "$TMP_MOUNT" ]] && [[ -n "$NODEV_MOUNT" ]]; then
        check_pass "/tmp mounted with nosuid,nodev"
    else
        check_fail "/tmp nosuid,nodev" "nosuid:$TMP_MOUNT nodev:$NODEV_MOUNT" "both present"
    fi
else
    # If /tmp is not a separate mount, check /tmp directory permissions
    if [[ -d "/tmp" ]]; then
        TMP_PERMS=$(stat -c '%a' /tmp 2>/dev/null || echo "")
        if [[ "$TMP_PERMS" == "1777" ]]; then
            check_pass "/tmp directory mode 1777 (sticky bit)"
        else
            check_fail "/tmp directory mode" "$TMP_PERMS" "1777"
        fi
    fi
fi

# Check world-writable directories with sticky bit
for DIR in /tmp /var/tmp; do
    if [[ -d "$DIR" ]]; then
        STICKY=$(stat -c '%A' "$DIR" 2>/dev/null | grep -o "t" || echo "")
        if [[ -n "$STICKY" ]]; then
            check_pass "$DIR has sticky bit set"
        else
            check_fail "$DIR sticky bit" "missing" "present"
        fi
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo "Total Checks:  $TOTAL_CHECKS"
echo "Passed:        $PASSED_CHECKS"
echo "Failed:        $FAILED_CHECKS"
echo "=========================================="

if [[ $FAILED_CHECKS -eq 0 ]]; then
    echo "RESULT: ALL HARDENING CONTROLS VERIFIED"
    exit 0
else
    echo "RESULT: HARDENING DRIFT DETECTED - REVIEW ABOVE FAILURES"
    exit 1
fi
