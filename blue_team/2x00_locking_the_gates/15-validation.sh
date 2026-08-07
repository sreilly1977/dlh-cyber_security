#!/bin/bash

# 15-validation.sh — Post-Hardening Validator
#                     Reads system state and compares against expected hardening values.
#                     Makes NO changes — read-only verification only.
# Outputs:
#   - Console summary (text format)
#   - validation_results.json (machine-readable JSON)
#
# Context:
#   - Configuration drift happens over time (debug changes, updates, etc.)
#   - This is a continuous validation tool run periodically (e.g., every Monday)
#   - Exits 0 if all checks pass, exits 1 if any fail
#
# Usage:  sudo ./15-validation.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Output Configuration
# ---------------------------------------------------------------------------

JSON_OUTPUT="validation_results.json"

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Track failures for exit code
EXIT_CODE=0

# ---------------------------------------------------------------------------
# Array to hold all check results for JSON output
# ---------------------------------------------------------------------------

declare -a CHECK_RESULTS=()

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

check_pass() {
    local description="$1"
    echo "[PASS] $description"
    PASSED_CHECKS=$((PASSED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    CHECK_RESULTS+=("{\"check\": \"$description\", \"status\": \"pass\"}")
}

check_fail() {
    local description="$1"
    local actual="${2:-N/A}"
    local expected="${3:-N/A}"

    if [[ -n "$actual" ]] && [[ -n "$expected" ]]; then
        echo "[FAIL] $description (actual: $actual, expected: $expected)"
        CHECK_RESULTS+=("{\"check\": \"$description\", \"status\": \"fail\", \"actual\": \"$actual\", \"expected\": \"$expected\"}")
    else
        echo "[FAIL] $description"
        CHECK_RESULTS+=("{\"check\": \"$description\", \"status\": \"fail\", \"actual\": \"$actual\", \"expected\": \"$expected\"}")
    fi

    FAILED_CHECKS=$((FAILED_CHECKS + 1))
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    EXIT_CODE=1
}

generate_validation_json() {
    local timestamp
    timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    {
        printf '{\n'
        printf '  "timestamp": "%s",\n' "$timestamp"
        printf '  "total_checks": %d,\n' "$TOTAL_CHECKS"
        printf '  "passed_checks": %d,\n' "$PASSED_CHECKS"
        printf '  "failed_checks": %d,\n' "$FAILED_CHECKS"
        printf '  "overall_status": "'
        if [[ "$FAILED_CHECKS" -eq 0 ]]; then
            printf 'ALL_CONTROLS_VERIFIED'
        else
            printf 'HARDENING_DRIFT_DETECTED'
        fi
        printf '",\n'
        printf '  "checks": [\n'

        local first=true
        for result in "${CHECK_RESULTS[@]}"; do
            if $first; then
                first=false
            else
                printf ',\n'
            fi
            printf '    %s' "$result"
        done

        printf '\n  ]\n'
        printf '}\n'
    } > "$JSON_OUTPUT"

    # Ensure trailing newline
    if [[ "$(tail -c1 "$JSON_OUTPUT" | wc -l)" -eq 0 ]]; then
        echo "" >> "$JSON_OUTPUT"
    fi

    echo ""
    echo "Validation results saved to: $JSON_OUTPUT"
}

# ---------------------------------------------------------------------------
# SSH Hardening Validation (Task 4: ssh_hardening.sh)
# ---------------------------------------------------------------------------

echo "=== SSH Hardening Checks ==="

SSH_CONFIG="/etc/ssh/sshd_config"

if [[ -f "$SSH_CONFIG" ]]; then
    # PermitRootLogin = no
    ROOT_LOGIN=$(grep -E "^PermitRootLogin" "$SSH_CONFIG" 2>/dev/null | awk '{print $2; exit}') || ROOT_LOGIN=""
    if [[ "$ROOT_LOGIN" == "no" ]]; then
        check_pass "PermitRootLogin = no"
    else
        check_fail "PermitRootLogin" "$ROOT_LOGIN" "no"
    fi

    # PasswordAuthentication = no
    PASSWORD_AUTH=$(grep -E "^PasswordAuthentication" "$SSH_CONFIG" 2>/dev/null | awk '{print $2; exit}') || PASSWORD_AUTH=""
    if [[ "$PASSWORD_AUTH" == "no" ]]; then
        check_pass "PasswordAuthentication = no"
    else
        check_fail "PasswordAuthentication" "$PASSWORD_AUTH" "no"
    fi

    # MaxAuthTries = 3
    MAX_AUTH=$(grep -E "^MaxAuthTries" "$SSH_CONFIG" 2>/dev/null | awk '{print $2; exit}') || MAX_AUTH=""
    if [[ "$MAX_AUTH" == "3" ]]; then
        check_pass "MaxAuthTries = 3"
    else
        check_fail "MaxAuthTries" "$MAX_AUTH" "3"
    fi

    # X11Forwarding = no
    X11_FWD=$(grep -E "^X11Forwarding" "$SSH_CONFIG" 2>/dev/null | awk '{print $2; exit}') || X11_FWD=""
    if [[ "$X11_FWD" == "no" ]]; then
        check_pass "X11Forwarding = no"
    else
        check_fail "X11Forwarding" "$X11_FWD" "no"
    fi

    # ClientAliveInterval = 300
    CLIENT_ALIVE=$(grep -E "^ClientAliveInterval" "$SSH_CONFIG" 2>/dev/null | awk '{print $2; exit}') || CLIENT_ALIVE=""
    if [[ "$CLIENT_ALIVE" == "300" ]]; then
        check_pass "ClientAliveInterval = 300"
    else
        check_fail "ClientAliveInterval" "$CLIENT_ALIVE" "300"
    fi

    # Protocol = 2 (deprecated in newer OpenSSH, skip if not applicable)
    if grep -q "^Protocol" "$SSH_CONFIG" 2>/dev/null; then
        PROTOCOL=$(grep -E "^Protocol" "$SSH_CONFIG" 2>/dev/null | awk '{print $2; exit}') || PROTOCOL=""
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
    AUDITD_STATE=$(systemctl is-active auditd 2>/dev/null) || AUDITD_STATE="inactive"
    check_fail "auditd.service" "$AUDITD_STATE" "active"
fi

# Check audit rules are loaded
RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l)
RULE_COUNT=${RULE_COUNT//[^0-9]/}
[[ -z "$RULE_COUNT" ]] && RULE_COUNT=0

if [[ "$RULE_COUNT" -gt 5 ]]; then
    check_pass "Audit rules loaded ($RULE_COUNT rules)"
else
    check_fail "Audit rules loaded" "$RULE_COUNT" "> 5"
fi

# Check auditd.conf exists at common paths
AUDITD_CONF=""
for conf_path in /etc/audit/auditd.conf /etc/audit/rules.d/auditd.conf /etc/audit/audit.rules; do
    if [[ -f "$conf_path" ]]; then
        AUDITD_CONF="$conf_path"
        break
    fi
done

if [[ -n "$AUDITD_CONF" ]]; then
    check_pass "auditd.conf exists ($AUDITD_CONF)"
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
    # AppArmor may be loaded as kernel feature without a standard service unit
    # Check aa-status as fallback
    if aa-status 2>/dev/null | grep -q "profiles are loaded"; then
        AA_PROFILES=$(aa-status 2>/dev/null | grep "profiles are loaded" | grep -oE '^[0-9]+' || echo "0")
        check_pass "AppArmor active ($AA_PROFILES profiles loaded via aa-status)"
    else
        APPARMOR_STATE=$(systemctl is-active apparmor 2>/dev/null) || APPARMOR_STATE="inactive"
        check_fail "apparmor.service" "$APPARMOR_STATE" "active"
    fi
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
    AUTH_PERMS=$(stat -c '%a' /var/log/auth.log 2>/dev/null) || AUTH_PERMS="unknown"
    AUTH_OWNER=$(stat -c '%U:%G' /var/log/auth.log 2>/dev/null) || AUTH_OWNER="unknown"
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
    SYSLOG_PERMS=$(stat -c '%a' /var/log/syslog 2>/dev/null) || SYSLOG_PERMS="unknown"
    SYSLOG_OWNER=$(stat -c '%U:%G' /var/log/syslog 2>/dev/null) || SYSLOG_OWNER="unknown"
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
    RSYSLOG_STATE=$(systemctl is-active rsyslog 2>/dev/null) || RSYSLOG_STATE="inactive"
    check_fail "rsyslog.service" "$RSYSLOG_STATE" "active"
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
fi

# Check default incoming policy
# ufw status verbose output: "Default: deny (incoming), allow (outgoing), ..."
UFW_DEFAULT_LINE=$(ufw status verbose 2>/dev/null | grep -i "Default:") || UFW_DEFAULT_LINE=""

if echo "$UFW_DEFAULT_LINE" | grep -qi "deny.*incoming"; then
    check_pass "Default incoming = deny"
else
    UFW_IN_VAL=$(echo "$UFW_DEFAULT_LINE" | grep -oE "[a-z]+ \(incoming\)" | grep -oE "^[a-z]+") || UFW_IN_VAL="not found"
    [[ -z "$UFW_IN_VAL" ]] && UFW_IN_VAL="not found"
    check_fail "Default incoming" "$UFW_IN_VAL" "deny"
fi

# Check default outgoing policy
if echo "$UFW_DEFAULT_LINE" | grep -qi "allow.*outgoing"; then
    check_pass "Default outgoing = allow"
else
    UFW_OUT_VAL=$(echo "$UFW_DEFAULT_LINE" | grep -oE "[a-z]+ \(outgoing\)" | grep -oE "^[a-z]+") || UFW_OUT_VAL="not found"
    [[ -z "$UFW_OUT_VAL" ]] && UFW_OUT_VAL="not found"
    check_fail "Default outgoing" "$UFW_OUT_VAL" "allow"
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
        TMP_PERMS=$(stat -c '%a' /tmp 2>/dev/null) || TMP_PERMS="unknown"
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

# Generate JSON output
generate_validation_json

if [[ $FAILED_CHECKS -eq 0 ]]; then
    echo "RESULT: ALL HARDENING CONTROLS VERIFIED"
    exit 0
else
    echo "RESULT: HARDENING DRIFT DETECTED - REVIEW ABOVE FAILURES"
    exit 1
fi
