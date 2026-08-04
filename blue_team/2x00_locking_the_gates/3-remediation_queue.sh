#!/bin/bash
#
# 3-remediation_queue.sh — Convert CIS control profile and Lynis findings
#                           into a prioritized, evidence-backed remediation
#                           queue.
#
# Inputs:  cis_profile.json, lynis_findings.json
# Outputs: gap_analysis.json, remediation_queue.json
# Usage:   ./3-remediation_queue.sh
#
# ============================================================================

set -euo pipefail

CIS_PROFILE="cis_profile.json"
LYNIS_FINDINGS="lynis_findings.json"
GAP_OUTPUT="gap_analysis.json"
QUEUE_OUTPUT="remediation_queue.json"

# ---------------------------------------------------------------------------
# Validate inputs
# ---------------------------------------------------------------------------

if [[ ! -f "$CIS_PROFILE" ]]; then
    echo "ERROR: $CIS_PROFILE not found. Run 1-cis_profile.sh first." >&2
    exit 1
fi

if [[ ! -f "$LYNIS_FINDINGS" ]]; then
    echo "ERROR: $LYNIS_FINDINGS not found. Run 2-lynis_parse.sh first." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    printf '%s' "$s"
}

find_lynis_matches() {
    local keyword="$1"
    local matches=""

    if command -v jq &>/dev/null; then
        matches=$(jq -r --arg kw "$keyword" \
            '.findings[] | select((.message | ascii_downcase) | contains($kw | ascii_downcase)) | "\(.test_id):\(.message)"' \
            "$LYNIS_FINDINGS" 2>/dev/null || true)
    else
        matches=$(grep -o '"message"[^,]*' "$LYNIS_FINDINGS" 2>/dev/null | \
                  grep -i "$keyword" | \
                  sed 's/.*"message"[[:space:]]*:[[:space:]]*"//; s/"$//' || true)
    fi
    printf '%s' "$matches"
}

get_lynis_finding_count() {
    local count="0"
    if command -v jq &>/dev/null; then
        count=$(jq -r '.findings | length' "$LYNIS_FINDINGS" 2>/dev/null || true)
    else
        count=$(grep -c '"severity"' "$LYNIS_FINDINGS" 2>/dev/null || true)
    fi
    # Ensure clean integer
    count="${count//[^0-9]/}"
    [[ -z "$count" ]] && count="0"
    printf '%s' "$count"
}

# Global variables to hold check results for each control
CHECK_STATUS=""
CHECK_DETAIL=""
LYNIS_MATCHES=""

# ---------------------------------------------------------------------------
# System compliance check functions
# ============================================================================

check_ssh_root_login() {
    local sshd_output=""
    if command -v sshd &>/dev/null; then
        sshd_output=$(sshd -T 2>/dev/null | grep -i 'permitrootlogin' || true)
    fi
    if [[ -z "$sshd_output" ]]; then
        sshd_output=$(grep -i '^permitrootlogin' /etc/ssh/sshd_config 2>/dev/null || true)
    fi

    if [[ -z "$sshd_output" ]]; then
        CHECK_STATUS="not_assessed"
        CHECK_DETAIL="SSH service not found or config not readable"
        LYNIS_MATCHES=""
    elif echo "$sshd_output" | grep -qi 'no'; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="PermitRootLogin is set to no"
        LYNIS_MATCHES=$(find_lynis_matches "root login")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="PermitRootLogin is not set to no"
        LYNIS_MATCHES=$(find_lynis_matches "root login")
    fi
}

check_ssh_password_auth() {
    local sshd_output=""
    if command -v sshd &>/dev/null; then
        sshd_output=$(sshd -T 2>/dev/null | grep -i 'passwordauthentication' || true)
    fi
    if [[ -z "$sshd_output" ]]; then
        sshd_output=$(grep -i '^passwordauthentication' /etc/ssh/sshd_config 2>/dev/null || true)
    fi

    if [[ -z "$sshd_output" ]]; then
        CHECK_STATUS="not_assessed"
        CHECK_DETAIL="SSH service not found or config not readable"
        LYNIS_MATCHES=""
    elif echo "$sshd_output" | grep -qi 'no'; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="PasswordAuthentication is set to no"
        LYNIS_MATCHES=$(find_lynis_matches "password")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="PasswordAuthentication is enabled (should be no)"
        LYNIS_MATCHES=$(find_lynis_matches "password")
    fi
}

check_ssh_allowgroups() {
    local sshd_output=""
    if command -v sshd &>/dev/null; then
        sshd_output=$(sshd -T 2>/dev/null | grep -i 'allowgroups' || true)
    fi
    if [[ -z "$sshd_output" ]]; then
        sshd_output=$(grep -i '^allowgroups' /etc/ssh/sshd_config 2>/dev/null || true)
    fi

    if [[ -z "$sshd_output" ]]; then
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="AllowGroups is not configured; all users can SSH"
        LYNIS_MATCHES=$(find_lynis_matches "allowgroups")
    else
        CHECK_STATUS="compliant"
        CHECK_DETAIL="AllowGroups is configured: $sshd_output"
        LYNIS_MATCHES=$(find_lynis_matches "allowgroups")
    fi
}

check_ssh_timeout() {
    local interval=""
    local maxauth=""

    if command -v sshd &>/dev/null; then
        interval=$(sshd -T 2>/dev/null | grep -i 'clientaliveinterval' | awk '{print $NF}' || true)
        maxauth=$(sshd -T 2>/dev/null | grep -i 'maxauthtries' | awk '{print $NF}' || true)
    fi

    if [[ -z "$interval" && -z "$maxauth" ]]; then
        CHECK_STATUS="not_assessed"
        CHECK_DETAIL="SSH config not readable"
        LYNIS_MATCHES=$(find_lynis_matches "clientalive")
    elif [[ -n "$interval" && -n "$maxauth" ]]; then
        if [[ "$interval" =~ ^[0-9]+$ ]] && [[ "$maxauth" =~ ^[0-9]+$ ]] && \
           [[ "$interval" -le 300 ]] && [[ "$maxauth" -le 3 ]]; then
            CHECK_STATUS="compliant"
            CHECK_DETAIL="ClientAliveInterval=$interval, MaxAuthTries=$maxauth"
            LYNIS_MATCHES=$(find_lynis_matches "clientalive")
        else
            CHECK_STATUS="partially_compliant"
            CHECK_DETAIL="ClientAliveInterval=$interval, MaxAuthTries=$maxauth (need <=300 and <=3)"
            LYNIS_MATCHES=$(find_lynis_matches "clientalive")
        fi
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="SSH timeout settings not fully configured"
        LYNIS_MATCHES=$(find_lynis_matches "clientalive")
    fi
}

check_aslr() {
    local aslr=""
    local kptr=""

    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null || echo "")
    kptr=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "")

    if [[ -z "$aslr" && -z "$kptr" ]]; then
        CHECK_STATUS="not_assessed"
        CHECK_DETAIL="sysctl values not readable"
        LYNIS_MATCHES=$(find_lynis_matches "randomize\|kptr\|aslr")
    elif [[ "$aslr" == "2" && "$kptr" == "2" ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="ASLR=$aslr, kptr_restrict=$kptr"
        LYNIS_MATCHES=$(find_lynis_matches "randomize\|kptr\|aslr")
    elif [[ "$aslr" == "2" || "$kptr" == "2" ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="ASLR=$aslr, kptr_restrict=$kptr (need both=2)"
        LYNIS_MATCHES=$(find_lynis_matches "randomize\|kptr\|aslr")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="ASLR=$aslr, kptr_restrict=$kptr (both need to be 2)"
        LYNIS_MATCHES=$(find_lynis_matches "randomize\|kptr\|aslr")
    fi
}

check_ip_forward() {
    local fwd=""
    local sredir=""

    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "")
    sredir=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null || echo "")

    if [[ -z "$fwd" && -z "$sredir" ]]; then
        CHECK_STATUS="not_assessed"
        CHECK_DETAIL="sysctl values not readable"
        LYNIS_MATCHES=$(find_lynis_matches "ip_forward\|redirect")
    elif [[ "$fwd" == "0" && "$sredir" == "0" ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="ip_forward=$fwd, send_redirects=$sredir"
        LYNIS_MATCHES=$(find_lynis_matches "ip_forward\|redirect")
    elif [[ "$fwd" == "0" || "$sredir" == "0" ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="ip_forward=$fwd, send_redirects=$sredir (need both=0)"
        LYNIS_MATCHES=$(find_lynis_matches "ip_forward\|redirect")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="ip_forward=$fwd, send_redirects=$sredir (both need to be 0)"
        LYNIS_MATCHES=$(find_lynis_matches "ip_forward\|redirect")
    fi
}

check_syncookies() {
    local syn=""
    local martians=""

    syn=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "")
    martians=$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || echo "")

    if [[ -z "$syn" && -z "$martians" ]]; then
        CHECK_STATUS="not_assessed"
        CHECK_DETAIL="sysctl values not readable"
        LYNIS_MATCHES=$(find_lynis_matches "syncook\|martian")
    elif [[ "$syn" == "1" && "$martians" == "1" ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="tcp_syncookies=$syn, log_martians=$martians"
        LYNIS_MATCHES=$(find_lynis_matches "syncook\|martian")
    elif [[ "$syn" == "1" || "$martians" == "1" ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="tcp_syncookies=$syn, log_martians=$martians (need both=1)"
        LYNIS_MATCHES=$(find_lynis_matches "syncook\|martian")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="tcp_syncookies=$syn, log_martians=$martians (both need to be 1)"
        LYNIS_MATCHES=$(find_lynis_matches "syncook\|martian")
    fi
}

check_pam_pwquality() {
    local common_password="/etc/pam.d/common-password"
    local pwquality_conf="/etc/security/pwquality.conf"

    if [[ ! -f "$common_password" ]]; then
        CHECK_STATUS="not_assessed"
        CHECK_DETAIL="PAM common-password file not found"
        LYNIS_MATCHES=$(find_lynis_matches "pwquality\|password quality\|password strength")
    elif grep -q 'pam_pwquality\|pam_passwdqc' "$common_password" 2>/dev/null; then
        local minlen=""
        minlen=$(grep -E '^\s*minlen' "$pwquality_conf" 2>/dev/null | awk '{print $NF}' | tr -d ' ' || true)
        if [[ -n "$minlen" ]] && [[ "$minlen" =~ ^[0-9]+$ ]] && [[ "$minlen" -ge 14 ]]; then
            CHECK_STATUS="compliant"
            CHECK_DETAIL="pam_pwquality configured with minlen=$minlen"
            LYNIS_MATCHES=$(find_lynis_matches "pwquality\|password quality\|password strength")
        else
            CHECK_STATUS="partially_compliant"
            CHECK_DETAIL="pam_pwquality present but minlen not set to 14 (found: $minlen)"
            LYNIS_MATCHES=$(find_lynis_matches "pwquality\|password quality\|password strength")
        fi
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="pam_pwquality module not configured in common-password"
        LYNIS_MATCHES=$(find_lynis_matches "pwquality\|password quality\|password strength")
    fi
}

check_password_aging() {
    local max_days=""
    local faillock=""

    if [[ -f /etc/login.defs ]]; then
        max_days=$(grep -E '^\s*PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}' | tr -d ' ' || true)
    fi
    if [[ -f /etc/pam.d/common-auth ]]; then
        # FIX: grep -c exits 1 when count is 0, which would trigger || and append extra output
        faillock=$(grep -c 'pam_faillock' /etc/pam.d/common-auth 2>/dev/null || true)
    fi

    # Ensure clean integers
    max_days="${max_days//[^0-9]/}"
    faillock="${faillock//[^0-9]/}"
    [[ -z "$max_days" ]] && max_days="99999"
    [[ -z "$faillock" ]] && faillock="0"

    if [[ "$max_days" -le 90 ]] && [[ "$faillock" -gt 0 ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="PASS_MAX_DAYS=$max_days, pam_faillock configured"
        LYNIS_MATCHES=$(find_lynis_matches "password aging\|faillock\|lockout\|max.days")
    elif [[ "$max_days" -le 90 ]] || [[ "$faillock" -gt 0 ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="PASS_MAX_DAYS=$max_days, pam_faillock entries=$faillock"
        LYNIS_MATCHES=$(find_lynis_matches "password aging\|faillock\|lockout\|max.days")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="PASS_MAX_DAYS=$max_days, pam_faillock entries=$faillock"
        LYNIS_MATCHES=$(find_lynis_matches "password aging\|faillock\|lockout\|max.days")
    fi
}

check_db_exposure() {
    local db_listening=""

    if command -v ss &>/dev/null; then
        db_listening=$(ss -tlnp 2>/dev/null | grep -E ':3306|:5432' || true)
    elif command -v netstat &>/dev/null; then
        db_listening=$(netstat -tlnp 2>/dev/null | grep -E ':3306|:5432' || true)
    fi

    if [[ -z "$db_listening" ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="No database service found listening on network ports"
        LYNIS_MATCHES=$(find_lynis_matches "mysql\|database\|postgresql\|3306\|5432")
    elif echo "$db_listening" | grep -qE '0\.0\.0\.0|\*\::'; then
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="Database listening on all interfaces: $(echo "$db_listening" | head -1)"
        LYNIS_MATCHES=$(find_lynis_matches "mysql\|database\|postgresql\|3306\|5432")
    else
        CHECK_STATUS="compliant"
        CHECK_DETAIL="Database bound to restricted interface: $(echo "$db_listening" | head -1)"
        LYNIS_MATCHES=$(find_lynis_matches "mysql\|database\|postgresql\|3306\|5432")
    fi
}

check_unnecessary_services() {
    local services_found=""

    for svc in avahi-daemon cups rpcbind nfs-kernel-server; do
        if systemctl is-active "$svc" &>/dev/null 2>&1; then
            services_found="${services_found}${svc} "
        fi
    done

    if [[ -z "$services_found" ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="No unnecessary default services running"
        LYNIS_MATCHES=$(find_lynis_matches "avahi\|cups\|nfs\|rpcbind\|unnecessary")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="Unnecessary services running: $services_found"
        LYNIS_MATCHES=$(find_lynis_matches "avahi\|cups\|nfs\|rpcbind\|unnecessary")
    fi
}

check_suid_sgid() {
    local suid_count="0"
    local sgid_count="0"

    suid_count=$(find / -xdev -type f -perm -4000 2>/dev/null | wc -l || true)
    sgid_count=$(find / -xdev -type f -perm -2000 2>/dev/null | wc -l || true)

    # Ensure clean integers
    suid_count="${suid_count//[^0-9]/}"
    sgid_count="${sgid_count//[^0-9]/}"
    [[ -z "$suid_count" ]] && suid_count="0"
    [[ -z "$sgid_count" ]] && sgid_count="0"

    # CIS baseline expects ~18 SUID and ~10 SGID on Ubuntu 22.04
    if [[ "$suid_count" -le 20 ]] && [[ "$sgid_count" -le 12 ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="SUID=$suid_count, SGID=$sgid_count (within expected range)"
        LYNIS_MATCHES=$(find_lynis_matches "suid\|sgid\|setuid\|setgid")
    elif [[ "$suid_count" -le 25 ]] && [[ "$sgid_count" -le 15 ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="SUID=$suid_count, SGID=$sgid_count (slightly above baseline)"
        LYNIS_MATCHES=$(find_lynis_matches "suid\|sgid\|setuid\|setgid")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="SUID=$suid_count, SGID=$sgid_count (significantly above baseline)"
        LYNIS_MATCHES=$(find_lynis_matches "suid\|sgid\|setuid\|setgid")
    fi
}

check_auditd() {
    local auditd_installed=""
    local auditd_running=""

    if dpkg -l auditd &>/dev/null 2>&1 || rpm -q audit &>/dev/null 2>&1; then
        auditd_installed="yes"
    fi
    if systemctl is-active auditd &>/dev/null 2>&1 || systemctl is-active audit &>/dev/null 2>&1; then
        auditd_running="yes"
    fi

    if [[ "$auditd_installed" == "yes" && "$auditd_running" == "yes" ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="auditd installed and running"
        LYNIS_MATCHES=$(find_lynis_matches "auditd\|audit")
    elif [[ "$auditd_installed" == "yes" ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="auditd installed but not running"
        LYNIS_MATCHES=$(find_lynis_matches "auditd\|audit")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="auditd not installed"
        LYNIS_MATCHES=$(find_lynis_matches "auditd\|audit")
    fi
}

check_audit_rules() {
    local rules_dir="/etc/audit/rules.d"
    local rules_count="0"

    if [[ -d "$rules_dir" ]]; then
        rules_count=$(grep -r '^\s*-w' "$rules_dir" 2>/dev/null | wc -l || true)
    fi

    # Ensure clean integer
    rules_count="${rules_count//[^0-9]/}"
    [[ -z "$rules_count" ]] && rules_count="0"

    if [[ "$rules_count" -ge 5 ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="$rules_count file watch audit rules configured"
        LYNIS_MATCHES=$(find_lynis_matches "audit rules\|auditd")
    elif [[ "$rules_count" -gt 0 ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="$rules_count audit rules configured (need at least 5 for privileged commands)"
        LYNIS_MATCHES=$(find_lynis_matches "audit rules\|auditd")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="No audit rules for privileged commands found"
        LYNIS_MATCHES=$(find_lynis_matches "audit rules\|auditd")
    fi
}

check_log_retention() {
    local maxage=""
    local forwarding=""

    if [[ -f /etc/logrotate.conf ]]; then
        maxage=$(grep -E '^\s*maxage' /etc/logrotate.conf 2>/dev/null | awk '{print $NF}' | head -1 | tr -d ' ' || true)
    fi
    if [[ -f /etc/rsyslog.conf ]] || [[ -d /etc/rsyslog.d ]]; then
        forwarding=$(grep -r '@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#' | head -1 || true)
        if [[ -z "$forwarding" ]]; then
            forwarding=$(grep -r '^\s*[a-zA-Z]' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep '@' | grep -v '^#' | head -1 || true)
        fi
    fi

    local maxage_num=""
    if [[ -n "$maxage" ]] && [[ "$maxage" =~ ^[0-9]+$ ]]; then
        maxage_num="$maxage"
    fi

    if [[ -z "$maxage_num" && -z "$forwarding" ]]; then
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="No log retention maxage or rsyslog forwarding configured"
        LYNIS_MATCHES=$(find_lynis_matches "logrot\|retention\|rsyslog\|forwarding")
    elif [[ -n "$maxage_num" ]] && [[ "$maxage_num" -ge 365 ]] && [[ -n "$forwarding" ]]; then
        CHECK_STATUS="compliant"
        CHECK_DETAIL="maxage=$maxage_num, forwarding configured"
        LYNIS_MATCHES=$(find_lynis_matches "logrot\|retention\|rsyslog\|forwarding")
    elif [[ -n "$maxage_num" ]] || [[ -n "$forwarding" ]]; then
        CHECK_STATUS="partially_compliant"
        CHECK_DETAIL="maxage=${maxage_num:-none}, forwarding=$([[ -n "$forwarding" ]] && echo 'yes' || echo 'no')"
        LYNIS_MATCHES=$(find_lynis_matches "logrot\|retention\|rsyslog\|forwarding")
    else
        CHECK_STATUS="non_compliant"
        CHECK_DETAIL="Retention insufficient: maxage=${maxage_num:-none}, forwarding=no"
        LYNIS_MATCHES=$(find_lynis_matches "logrot\|retention\|rsyslog\|forwarding")
    fi
}

# ---------------------------------------------------------------------------
# Calculate priority score (1-100)
# ============================================================================

calculate_priority() {
    local severity="$1"
    local has_lynis_match="$2"
    local status="$3"

    local score=0

    case "$severity" in
        critical) score=85 ;;
        high)     score=60 ;;
        medium)   score=35 ;;
        *)        score=20 ;;
    esac

    if [[ -n "$has_lynis_match" ]]; then
        score=$((score + 10))
    fi

    if [[ "$status" == "non_compliant" ]]; then
        score=$((score + 5))
    fi

    if [[ $score -gt 100 ]]; then
        score=100
    fi

    if [[ $score -lt 1 ]]; then
        score=1
    fi

    printf '%d' "$score"
}

# ---------------------------------------------------------------------------
# Main assessment loop
# ============================================================================

echo "[INFO] Reading CIS control profile from $CIS_PROFILE"
echo "[INFO] Reading Lynis findings from $LYNIS_FINDINGS"

LYNIS_COUNT=$(get_lynis_finding_count)
echo "[INFO] Found $LYNIS_COUNT Lynis findings to correlate"

# Extract control IDs from cis_profile.json
CONTROL_IDS=""
CONTROL_COUNT=0

if command -v jq &>/dev/null; then
    CONTROL_IDS=$(jq -r '.controls[].control_id' "$CIS_PROFILE" 2>/dev/null)
    CONTROL_COUNT=$(jq -r '.controls | length' "$CIS_PROFILE" 2>/dev/null || true)
else
    CONTROL_IDS=$(grep -o '"control_id"[[:space:]]*:[[:space:]]*"[^"]*"' "$CIS_PROFILE" | \
                  sed 's/.*"control_id"[[:space:]]*:[[:space:]]*"//; s/"$//')
    CONTROL_COUNT=$(echo "$CONTROL_IDS" | grep -c '.' || true)
fi

# Ensure clean integer
CONTROL_COUNT="${CONTROL_COUNT//[^0-9]/}"
[[ -z "$CONTROL_COUNT" ]] && CONTROL_COUNT="0"

# Storage for gap analysis and queue entries
declare -a GAP_ENTRIES=()
declare -a QUEUE_ENTRIES=()

COMPLIANT_COUNT=0
NONCOMPLIANT_COUNT=0
PARTIAL_COUNT=0
NOTASSESSED_COUNT=0
QUEUED_COUNT=0

# Variables used in the main loop
esc_detail=""
esc_lynis=""
esc_title=""
esc_threat=""
esc_impl=""
esc_verify=""
esc_just=""
op_risk=""
esc_risk=""

for ctrl_id in $CONTROL_IDS; do
    # Extract control fields using jq
    if command -v jq &>/dev/null; then
        CTRL_TITLE=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .title' "$CIS_PROFILE")
        CTRL_SECTION=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .cis_section' "$CIS_PROFILE")
        CTRL_SEVERITY=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .severity' "$CIS_PROFILE")
        CTRL_SCOPE=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .asset_scope' "$CIS_PROFILE")
        CTRL_THREAT=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .threat_mapping' "$CIS_PROFILE")
        CTRL_IMPL=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .implementation_task' "$CIS_PROFILE")
        CTRL_VERIFY=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .verification_method' "$CIS_PROFILE")
        CTRL_JUST=$(jq -r --arg id "$ctrl_id" '.controls[] | select(.control_id==$id) | .justification' "$CIS_PROFILE")
    else
        CTRL_TITLE=$(grep -A20 "\"control_id\"[[:space:]]*:[[:space:]]*\"$ctrl_id\"" "$CIS_PROFILE" | grep '"title"' | head -1 | sed 's/.*"title"[[:space:]]*:[[:space:]]*"//; s/".*//')
        CTRL_SEVERITY=$(grep -A20 "\"control_id\"[[:space:]]*:[[:space:]]*\"$ctrl_id\"" "$CIS_PROFILE" | grep '"severity"' | head -1 | sed 's/.*"severity"[[:space:]]*:[[:space:]]*"//; s/".*//')
        CTRL_SCOPE=$(grep -A20 "\"control_id\"[[:space:]]*:[[:space:]]*\"$ctrl_id\"" "$CIS_PROFILE" | grep '"asset_scope"' | head -1 | sed 's/.*"asset_scope"[[:space:]]*:[[:space:]]*"//; s/".*//')
        CTRL_IMPL=$(grep -A20 "\"control_id\"[[:space:]]*:[[:space:]]*\"$ctrl_id\"" "$CIS_PROFILE" | grep '"implementation_task"' | head -1 | sed 's/.*"implementation_task"[[:space:]]*:[[:space:]]*"//; s/".*//')
        CTRL_VERIFY=$(grep -A20 "\"control_id\"[[:space:]]*:[[:space:]]*\"$ctrl_id\"" "$CIS_PROFILE" | grep '"verification_method"' | head -1 | sed 's/.*"verification_method"[[:space:]]*:[[:space:]]*"//; s/".*//')
        CTRL_SECTION="unknown"
        CTRL_THREAT="unknown"
        CTRL_JUST="unknown"
    fi

    # Default empty values
    [[ -z "$CTRL_TITLE" ]] && CTRL_TITLE="Unknown"
    [[ -z "$CTRL_SEVERITY" ]] && CTRL_SEVERITY="medium"
    [[ -z "$CTRL_SCOPE" ]] && CTRL_SCOPE="all"
    [[ -z "$CTRL_IMPL" ]] && CTRL_IMPL="TBD"
    [[ -z "$CTRL_VERIFY" ]] && CTRL_VERIFY="Manual verification required"
    [[ -z "$CTRL_SECTION" ]] && CTRL_SECTION="unknown"
    [[ -z "$CTRL_THREAT" ]] && CTRL_THREAT="unknown"
    [[ -z "$CTRL_JUST" ]] && CTRL_JUST="unknown"

    # Run the appropriate compliance check
    case "$ctrl_id" in
        CIS-5.2.1)  check_ssh_root_login ;;
        CIS-5.2.4)  check_ssh_password_auth ;;
        CIS-5.2.2)  check_ssh_allowgroups ;;
        CIS-5.2.6)  check_ssh_timeout ;;
        CIS-1.5.1)  check_aslr ;;
        CIS-3.1.1)  check_ip_forward ;;
        CIS-3.1.2)  check_syncookies ;;
        CIS-5.4.1)  check_pam_pwquality ;;
        CIS-5.5.1)  check_password_aging ;;
        CIS-2.2.1)  check_db_exposure ;;
        CIS-2.2.2)  check_unnecessary_services ;;
        CIS-6.1.1)  check_suid_sgid ;;
        CIS-4.1.1)  check_auditd ;;
        CIS-4.1.4)  check_audit_rules ;;
        CIS-4.2.3)  check_log_retention ;;
        *)
            CHECK_STATUS="not_assessed"
            CHECK_DETAIL="No automated check implemented for $ctrl_id"
            LYNIS_MATCHES=""
            ;;
    esac

    # Count statuses
    case "$CHECK_STATUS" in
        compliant)             COMPLIANT_COUNT=$((COMPLIANT_COUNT + 1)) ;;
        non_compliant)         NONCOMPLIANT_COUNT=$((NONCOMPLIANT_COUNT + 1)) ;;
        partially_compliant)   PARTIAL_COUNT=$((PARTIAL_COUNT + 1)) ;;
        not_assessed)          NOTASSESSED_COUNT=$((NOTASSESSED_COUNT + 1)) ;;
    esac

    # Build gap analysis entry
    esc_detail="$(json_escape "$CHECK_DETAIL")"
    esc_lynis="$(json_escape "$LYNIS_MATCHES")"
    esc_title="$(json_escape "$CTRL_TITLE")"
    esc_threat="$(json_escape "$CTRL_THREAT")"
    esc_impl="$(json_escape "$CTRL_IMPL")"
    esc_verify="$(json_escape "$CTRL_VERIFY")"
    esc_just="$(json_escape "$CTRL_JUST")"

    GAP_ENTRY=$(cat <<GAPJSON
    {
      "control_id": "$ctrl_id",
      "title": "$esc_title",
      "cis_section": "$CTRL_SECTION",
      "severity": "$CTRL_SEVERITY",
      "status": "$CHECK_STATUS",
      "detail": "$esc_detail",
      "asset_scope": "$CTRL_SCOPE",
      "lynis_correlation": "$esc_lynis",
      "threat_mapping": "$esc_threat",
      "justification": "$esc_just"
    }
GAPJSON
)
    GAP_ENTRIES+=("$GAP_ENTRY")

    # Build queue entry for non-compliant or partially compliant
    if [[ "$CHECK_STATUS" == "non_compliant" ]] || [[ "$CHECK_STATUS" == "partially_compliant" ]]; then
        QUEUED_COUNT=$((QUEUED_COUNT + 1))

        PRIORITY=$(calculate_priority "$CTRL_SEVERITY" "$LYNIS_MATCHES" "$CHECK_STATUS")

        # Determine operational risk
        case "$CTRL_SEVERITY" in
            critical)
                op_risk="Immediate risk of compromise: $CTRL_THREAT"
                ;;
            high)
                op_risk="Significant risk if exploited: $CTRL_THREAT"
                ;;
            medium)
                op_risk="Moderate risk, harden during next maintenance window: $CTRL_THREAT"
                ;;
            *)
                op_risk="Low risk but should be addressed: $CTRL_THREAT"
                ;;
        esac

        esc_risk="$(json_escape "$op_risk")"

        QUEUE_ENTRY=$(cat <<QJSON
    {
      "priority": $PRIORITY,
      "control_id": "$ctrl_id",
      "title": "$esc_title",
      "severity": "$CTRL_SEVERITY",
      "status": "$CHECK_STATUS",
      "affected_asset": "$CTRL_SCOPE",
      "lynis_findings": "$esc_lynis",
      "implementation_task": "$esc_impl",
      "operational_risk": "$esc_risk",
      "expected_validation": "$esc_verify",
      "detail": "$esc_detail"
    }
QJSON
)
        QUEUE_ENTRIES+=("$QUEUE_ENTRY")
    fi
done

# ---------------------------------------------------------------------------
# Sort queue entries by priority descending
# ============================================================================

declare -a SORTED_QUEUE=()
if [[ ${#QUEUE_ENTRIES[@]} -gt 0 ]]; then
    > /tmp/_queue_sort_$$
    i=0
    for entry in "${QUEUE_ENTRIES[@]}"; do
        pri=$(echo "$entry" | grep -o '"priority":[[:space:]]*[0-9]*' | grep -o '[0-9]*$' || echo "0")
        echo "$pri $i" >> /tmp/_queue_sort_$$
        i=$((i + 1))
    done

    while read -r _ idx; do
        SORTED_QUEUE+=("${QUEUE_ENTRIES[$idx]}")
    done < <(sort -rn /tmp/_queue_sort_$$)
    rm -f /tmp/_queue_sort_$$
fi

# ---------------------------------------------------------------------------
# Write gap_analysis.json
# ============================================================================

{
    printf '{\n'
    printf '  "assessment_date": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "controls_assessed": %d,\n' "$CONTROL_COUNT"
    printf '  "compliant": %d,\n' "$COMPLIANT_COUNT"
    printf '  "non_compliant": %d,\n' "$NONCOMPLIANT_COUNT"
    printf '  "partially_compliant": %d,\n' "$PARTIAL_COUNT"
    printf '  "not_assessed": %d,\n' "$NOTASSESSED_COUNT"
    printf '  "controls": [\n'

    first=true
    for entry in "${GAP_ENTRIES[@]+"${GAP_ENTRIES[@]}"}"; do
        if $first; then
            first=false
        else
            printf ',\n'
        fi
        printf '%s' "$entry"
    done

    printf '\n  ]\n'
    printf '}\n'
} > "$GAP_OUTPUT"

# Ensure trailing newline
if [[ "$(tail -c1 "$GAP_OUTPUT" | wc -l)" -eq 0 ]]; then
    echo "" >> "$GAP_OUTPUT"
fi

# ---------------------------------------------------------------------------
# Write remediation_queue.json
# ============================================================================

{
    printf '{\n'
    printf '  "assessment_date": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "total_actions": %d,\n' "$QUEUED_COUNT"
    printf '  "sorted_by": "priority_descending",\n'
    printf '  "queue": [\n'

    first=true
    if [[ ${#SORTED_QUEUE[@]} -gt 0 ]]; then
        for entry in "${SORTED_QUEUE[@]}"; do
            if $first; then
                first=false
            else
                printf ',\n'
            fi
            printf '%s' "$entry"
        done
    elif [[ ${#QUEUE_ENTRIES[@]} -gt 0 ]]; then
        for entry in "${QUEUE_ENTRIES[@]}"; do
            if $first; then
                first=false
            else
                printf ',\n'
            fi
            printf '%s' "$entry"
        done
    fi

    printf '\n  ]\n'
    printf '}\n'
} > "$QUEUE_OUTPUT"

# Ensure trailing newline
if [[ "$(tail -c1 "$QUEUE_OUTPUT" | wc -l)" -eq 0 ]]; then
    echo "" >> "$QUEUE_OUTPUT"
fi

# ---------------------------------------------------------------------------
# Print summary
# ============================================================================

cat <<SUMMARY
Controls assessed: $CONTROL_COUNT
Compliant: $COMPLIANT_COUNT
Non-compliant: $NONCOMPLIANT_COUNT
Partially compliant: $PARTIAL_COUNT
Not assessed: $NOTASSESSED_COUNT
Remediation actions queued: $QUEUED_COUNT
Report saved to: $GAP_OUTPUT
Queue saved to: $QUEUE_OUTPUT
SUMMARY

exit 0
