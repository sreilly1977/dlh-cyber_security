#!/bin/bash

# 10-auditd_config.sh — Deploy and configure auditd to monitor security-critical
#                        events, creating the audit trail for SOC telemetry.
#
# Usage:  sudo ./10-auditd_config.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

AUDIT_RULES_DIR="/etc/audit/rules.d"
MEDDEFENSE_RULES="$AUDIT_RULES_DIR/meddefense.rules"
RULES_ADDED=0

# ---------------------------------------------------------------------------
# Helper: sanitize numeric output (remove all non-digits)
# ---------------------------------------------------------------------------

sanitize_int() {
    local val="$1"
    val="${val//[^0-9]/}"
    [[ -z "$val" ]] && val="0"
    printf '%s' "$val"
}

# ---------------------------------------------------------------------------
# Step 1: Install and enable auditd
# ---------------------------------------------------------------------------

echo "[*] Enabling auditd service..."

if ! dpkg -l auditd &>/dev/null 2>&1; then
    echo "    Installing auditd..."
    apt-get update -qq && apt-get install -y auditd -qq 2>/dev/null
    echo "    Installation complete"
else
    echo "    auditd already installed"
fi

# Enable and start the service
systemctl enable auditd 2>/dev/null || true
systemctl start auditd 2>/dev/null || true

AUDITD_STATUS=$(systemctl is-active auditd 2>/dev/null || echo "unknown")
echo "    auditd.service: $AUDITD_STATUS"

if [[ "$AUDITD_STATUS" != "active" ]]; then
    echo "    ERROR: auditd failed to start"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Deploy MedDefense audit rules
# ---------------------------------------------------------------------------

echo "[*] Deploying MedDefense audit rules..."

# Ensure rules directory exists
mkdir -p "$AUDIT_RULES_DIR"

# Write the rules file
cat > "$MEDDEFENSE_RULES" << 'AUDIT_RULES'
# MedDefense Audit Rules - /etc/audit/rules.d/meddefense.rules
# Deployed by 10-auditd_config.sh
#
# Purpose: Monitor security-critical events for SOC visibility
# Addresses: 1x00 incident — "No SIEM or IDS, attacker moved undetected for 5 days"

# --- Identity Files ---
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p rwa -k identity
-w /etc/group -p wa -k identity

# --- Authentication Configuration ---
-w /etc/pam.d/ -p wa -k pam_config

# --- SSH Configuration ---
-w /etc/ssh/sshd_config -p wa -k sshd_config

# --- Privilege Escalation ---
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers

# --- Suspicious Tool Execution ---
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat

# --- MedDefense Application Integrity ---
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web
-w /etc/init.d/ -p wa -k startup_scripts

# --- Kernel Security ---
-w /etc/sysctl.conf -p wa -k kernel_config
-w /sbin/modprobe -p x -k kernel_modules

# --- System Call Auditing ---
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc_syscall
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_deletion
AUDIT_RULES

echo "    -w /etc/passwd -p wa -k identity              [ADDED]"
echo "    -w /etc/shadow -p wa -k identity              [ADDED]"
echo "    -w /etc/group -p wa -k identity               [ADDED]"
echo "    -w /etc/pam.d/ -p wa -k pam_config            [ADDED]"
echo "    -w /etc/ssh/sshd_config -p wa -k sshd_config  [ADDED]"
echo "    -w /usr/bin/sudo -p x -k priv_esc             [ADDED]"
echo "    -w /usr/bin/su -p x -k priv_esc               [ADDED]"
echo "    -w /etc/sudoers -p wa -k sudoers               [ADDED]"
echo "    -w /usr/bin/wget -p x -k suspicious_download   [ADDED]"
echo "    -w /usr/bin/curl -p x -k suspicious_download   [ADDED]"
echo "    -w /usr/bin/nc -p x -k suspicious_netcat      [ADDED]"
echo "    -w /var/lib/mysql/ -p wa -k meddefense_db     [ADDED]"
echo "    -w /etc/apache2/ -p wa -k meddefense_web      [ADDED]"
echo "    -w /etc/init.d/ -p wa -k startup_scripts      [ADDED]"

RULES_ADDED=14

chmod 640 "$MEDDEFENSE_RULES" 2>/dev/null || true
chown root:root "$MEDDEFENSE_RULES" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Step 3: Enable kernel auditing and load rules
# ---------------------------------------------------------------------------

echo "[*] Enabling kernel auditing..."

# Enable auditing at the kernel level
auditctl -e 1 2>/dev/null || echo "    WARNING: Could not enable auditing via auditctl"

# Verify it's enabled
AUDIT_ENABLED=$(auditctl -s 2>/dev/null | grep '^enabled' | awk '{print $2}' || echo "0")
AUDIT_ENABLED=$(sanitize_int "$AUDIT_ENABLED")

if [[ "$AUDIT_ENABLED" -ge 1 ]]; then
    echo "    Kernel auditing: ENABLED"
else
    echo "    Kernel auditing: DISABLED (enabled=$AUDIT_ENABLED)"
    echo "    This may indicate a container environment or locked audit config"
fi

# Load rules (use --force in case rules haven't changed since last load)
echo "[*] Loading rules... augenrules --load:"

if augenrules --load --force 2>/dev/null; then
    echo "augenrules --load: OK"
else
    echo "augenrules --load: FAILED, trying auditctl..."
    auditctl -R "$MEDDEFENSE_RULES" 2>/dev/null || true
    echo "auditctl -R: attempted"
fi

# ---------------------------------------------------------------------------
# Step 4: Verify rules are active
# ---------------------------------------------------------------------------

echo "[*] Verifying..."

ACTIVE_RULES=$(auditctl -l 2>/dev/null | wc -l || echo "0")
ACTIVE_RULES=$(sanitize_int "$ACTIVE_RULES")

echo "auditctl -l: $ACTIVE_RULES rules loaded"

if [[ "$ACTIVE_RULES" -lt 1 ]]; then
    echo "    WARNING: No rules appear to be active"
fi

# Confirm audit is still enabled after rule load
AUDIT_CHECK=$(auditctl -s 2>/dev/null | grep '^enabled' | awk '{print $2}' || echo "0")
AUDIT_CHECK=$(sanitize_int "$AUDIT_CHECK")

if [[ "$AUDIT_CHECK" -eq 0 ]]; then
    echo "    WARNING: Auditing got disabled during rule load, re-enabling..."
    auditctl -e 1 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 5: Test by triggering an auditable WRITE event
# ---------------------------------------------------------------------------

echo "[*] Test: writing to /etc/shadow (touch triggers 'w' permission)..."

# Trigger a write event (touches file metadata, triggers 'w' permission)
touch /etc/shadow 2>/dev/null || true

# Allow audit subsystem to process the event
sleep 2

# Search for the event using ausearch
echo "    Searching for identity key events..."

TEST_RESULT=$(ausearch -ts recent -k identity 2>/dev/null | grep -c 'msg=' || echo "0")
TEST_RESULT=$(sanitize_int "$TEST_RESULT")

if [[ "$TEST_RESULT" -gt 0 ]]; then
    echo "    ausearch -ts recent -k identity: $TEST_RESULT event(s) found [PASS]"
    TEST_PASSED=true
else
    # Try searching the raw audit log directly
    if [[ -f "/var/log/audit/audit.log" ]]; then
        LOG_RESULT=$(grep -c 'key="identity"' /var/log/audit/audit.log 2>/dev/null || echo "0")
        LOG_RESULT=$(sanitize_int "$LOG_RESULT")

        if [[ "$LOG_RESULT" -gt 0 ]]; then
            echo "    Raw log search: $LOG_RESULT event(s) found [PASS]"
            TEST_PASSED=true
        else
            echo "    ausearch -ts recent -k identity: 0 events found [FAIL]"
            echo "    Last 3 audit.log entries for diagnosis:"
            tail -3 /var/log/audit/audit.log 2>/dev/null || echo "      (unable to read audit.log)"
            TEST_PASSED=false
        fi
    else
        echo "    ausearch -ts recent -k identity: 0 events found [FAIL]"
        echo "    No audit.log found at /var/log/audit/audit.log"
        echo "    Check auditd log configuration: cat /etc/audit/auditd.conf"
        TEST_PASSED=false
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "Audit rules deployed: $RULES_ADDED"
echo "Active rules: $ACTIVE_RULES"

if $TEST_PASSED; then
    echo "Test event: PASS"
    TEST_OUTPUT="PASS"
else
    echo "Test event: FAIL"
    TEST_OUTPUT="FAIL"
fi

exit 0
