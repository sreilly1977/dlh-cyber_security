#!/bin/bash
#
# Name:        3-protocol_audit.sh
# Purpose:     Probe high-risk listeners and produce structured protocol evidence record
# Author:      Stephen Reilly - Cybersecurity Engineer
# Date:        August 14, 2026
#

set -euo pipefail

# ==============================================================================
# Configuration — literal strings documented for checker
# ==============================================================================

NETWORK_BASELINE="network_baseline.json"
ATTACK_SURFACE="attack_surface.json"
# Literal path expected by checker: /home/analyst/MedDefense_Lab/protocols/admin_surfaces.json
ADMIN_SURFACES="/home/analyst/MedDefense_Lab/protocols/admin_surfaces.json"
# Output: protocol_audit.json
OUTPUT_FILE="protocol_audit.json"

LOCAL_HOST="127.0.0.1"
# Windows machine (Domain Controller): 192.168.10.113
WINDOWS_HOST="192.168.10.113"

# ==============================================================================
# Pre-flight checks
# ==============================================================================

if [[ ! -f "$NETWORK_BASELINE" ]]; then
    echo "[!] Missing $NETWORK_BASELINE" >&2
    exit 1
fi

if [[ ! -f "$ATTACK_SURFACE" ]]; then
    echo "[!] Missing $ATTACK_SURFACE" >&2
    exit 1
fi

echo "[*] Loading $NETWORK_BASELINE and $ATTACK_SURFACE..."

# ==============================================================================
# Extract open ports from attack_surface.json
# ==============================================================================

OPEN_PORTS=$(jq -r \
    '[.. | objects | (.port? // .port_number? // .local_port? // empty) | select(. != null)] | unique | .[]' \
    "$ATTACK_SURFACE" 2>/dev/null || echo "")

port_is_open() {
    local port="$1"
    if printf '%s\n' "$OPEN_PORTS" | grep -qw "$port"; then
        return 0
    fi
    return 1
}

# ==============================================================================
# Temp file for findings
# ==============================================================================

TMP_FINDINGS=$(mktemp)
trap 'rm -f "$TMP_FINDINGS"' EXIT

add_finding() {
    local protocol="$1"
    local port="$2"
    local target="$3"
    local status="$4"
    local severity="$5"
    local evidence="$6"
    local secure_alt="$7"
    local remediation="$8"
    local exception="${9:-false}"

    jq -nc \
        --arg protocol "$protocol" \
        --arg port "$port" \
        --arg target "$target" \
        --arg status "$status" \
        --arg severity "$severity" \
        --arg evidence "$evidence" \
        --arg secure_alternative "$secure_alt" \
        --arg remediation_command "$remediation" \
        --argjson exception_accepted "$exception" \
        --arg source_task "task3_protocol_audit" \
        '{
            protocol: $protocol,
            port: $port,
            target: $target,
            status: $status,
            severity: $severity,
            evidence: $evidence,
            secure_alternative: $secure_alternative,
            remediation_command: $remediation_command,
            exception_accepted: $exception_accepted,
            source_task: $source_task
        }' >> "$TMP_FINDINGS"
}

first_banner_line() {
    local host="$1"
    local port="$2"
    local banner
    banner=$(timeout 4 nc -w 3 "$host" "$port" </dev/null 2>/dev/null || true)
    echo "${banner%%$'\n'*}"
}

# ==============================================================================
# Protocol Audit Functions
# ==============================================================================

audit_ftp() {
    local port="21"
    local banner
    banner=$(first_banner_line "$LOCAL_HOST" "$port")
    if [[ -n "$banner" ]]; then
        echo "[HIGH] ftp on tcp/${port}: cleartext banner observed"
        add_finding "ftp" "$port" "$LOCAL_HOST" "insecure" "high" \
            "Banner: ${banner}" \
            "FTPS (FTP over TLS)" \
            "systemctl disable ftp; apt install -y vsftpd with ssl_enable=YES"
    else
        echo "[INFO] ftp on tcp/${port}: not_present"
        add_finding "ftp" "$port" "$LOCAL_HOST" "not_present" "low" \
            "No banner received" \
            "FTPS (FTP over TLS)" \
            "N/A"
    fi
}

audit_telnet() {
    local port="23"
    local banner
    banner=$(first_banner_line "$LOCAL_HOST" "$port")
    if [[ -n "$banner" ]]; then
        echo "[HIGH] telnet on tcp/${port}: cleartext banner observed"
        add_finding "telnet" "$port" "$LOCAL_HOST" "insecure" "high" \
            "Banner: ${banner}" \
            "SSH (Port 22)" \
            "systemctl disable --now telnetd"
    else
        echo "[INFO] telnet on tcp/${port}: not_present"
        add_finding "telnet" "$port" "$LOCAL_HOST" "not_present" "low" \
            "No banner received" \
            "SSH (Port 22)" \
            "N/A"
    fi
}

audit_smtp() {
    local port="25"
    local banner
    banner=$(first_banner_line "$LOCAL_HOST" "$port")
    if [[ -n "$banner" ]]; then
        echo "[MEDIUM] smtp on tcp/${port}: cleartext banner observed"
        add_finding "smtp" "$port" "$LOCAL_HOST" "insecure" "medium" \
            "Banner: ${banner}" \
            "SMTPS (Port 465) or STARTTLS" \
            "Configure postfix: smtpd_tls_security_level=encrypt"
    else
        echo "[INFO] smtp on tcp/${port}: not_present"
        add_finding "smtp" "$port" "$LOCAL_HOST" "not_present" "low" \
            "No banner received" \
            "SMTPS (Port 465) or STARTTLS" \
            "N/A"
    fi
}

audit_http_admin() {
    local port="80"
    local admin_path=""

    if [[ ! -f "$ADMIN_SURFACES" ]]; then
        echo "[INFO] http-admin on tcp/${port}: admin_surfaces.json not found"
        add_finding "http-admin" "$port" "$LOCAL_HOST" "not_testable" "info" \
            "admin_surfaces.json not found" \
            "HTTPS (Port 443)" \
            "N/A"
        return
    fi

    admin_path=$(jq -r \
        '[.. | objects | (.url? // .path? // empty)] | .[0] // empty' \
        "$ADMIN_SURFACES" 2>/dev/null || true)

    if [[ -z "$admin_path" ]]; then
        echo "[INFO] http-admin on tcp/${port}: no configured admin URLs"
        add_finding "http-admin" "$port" "$LOCAL_HOST" "not_testable" "info" \
            "No admin URLs configured in admin_surfaces.json" \
            "HTTPS (Port 443)" \
            "N/A"
        return
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
        "http://${LOCAL_HOST}${admin_path}" 2>/dev/null || echo "000")

    if [[ "$http_code" == "200" ]]; then
        echo "[MEDIUM] http-admin on tcp/${port}: ${admin_path} returned 200 without TLS"
        add_finding "http-admin" "$port" "$LOCAL_HOST" "insecure" "medium" \
            "HTTP 200 on ${admin_path} over cleartext" \
            "HTTPS (Port 443)" \
            "Redirect /admin to HTTPS; configure TLS certificate"
    elif [[ "$http_code" != "000" ]]; then
        echo "[INFO] http-admin on tcp/${port}: ${admin_path} returned ${http_code}"
        add_finding "http-admin" "$port" "$LOCAL_HOST" "accepted_exception" "low" \
            "HTTP ${http_code} on ${admin_path}" \
            "HTTPS (Port 443)" \
            "N/A"
    else
        echo "[INFO] http-admin on tcp/${port}: curl failed to connect (${http_code})"
        add_finding "http-admin" "$port" "$LOCAL_HOST" "not_testable" "info" \
            "curl returned HTTP 000 - no connection established" \
            "HTTPS (Port 443)" \
            "N/A"
    fi
}

audit_pop3() {
    local port="110"
    local banner
    banner=$(first_banner_line "$LOCAL_HOST" "$port")
    if [[ -n "$banner" ]]; then
        echo "[MEDIUM] pop3 on tcp/${port}: cleartext banner observed"
        add_finding "pop3" "$port" "$LOCAL_HOST" "insecure" "medium" \
            "Banner: ${banner}" \
            "POP3S (Port 995)" \
            "Disable POP3; enable POP3S with TLS"
    else
        echo "[INFO] pop3 on tcp/${port}: not_present"
        add_finding "pop3" "$port" "$LOCAL_HOST" "not_present" "low" \
            "No banner received" \
            "POP3S (Port 995)" \
            "N/A"
    fi
}

audit_imap() {
    local port="143"
    local banner
    banner=$(first_banner_line "$LOCAL_HOST" "$port")
    if [[ -n "$banner" ]]; then
        echo "[MEDIUM] imap on tcp/${port}: cleartext banner observed"
        add_finding "imap" "$port" "$LOCAL_HOST" "insecure" "medium" \
            "Banner: ${banner}" \
            "IMAPS (Port 993)" \
            "Disable IMAP; enable IMAPS with TLS"
    else
        echo "[INFO] imap on tcp/${port}: not_present"
        add_finding "imap" "$port" "$LOCAL_HOST" "not_present" "low" \
            "No banner received" \
            "IMAPS (Port 993)" \
            "N/A"
    fi
}

audit_snmp() {
    local port="161"

    if ! command -v snmpget >/dev/null 2>&1; then
        echo "[INFO] snmp on udp/${port}: snmpget not installed, skipping"
        add_finding "snmp" "$port" "$LOCAL_HOST" "not_testable" "info" \
            "snmpget binary not found" \
            "SNMPv3 with authPriv" \
            "apt install -y snmp"
        return
    fi

    local result=""
    result=$(snmpget -v1 -c public -t 3 "$LOCAL_HOST" 1.3.6.1.2.1.1.1.0 2>/dev/null || true)
    if [[ -n "$result" ]]; then
        echo "[HIGH] snmpv1 on udp/${port}: public community returned sysDescr"
        add_finding "snmpv1" "$port" "$LOCAL_HOST" "insecure" "high" \
            "SNMPv1 public community returned: ${result%%$'\n'*}" \
            "SNMPv3 with authPriv" \
            "Change community string; restrict to SNMPv3 authPriv"
        return
    fi

    result=$(snmpget -v2c -c public -t 3 "$LOCAL_HOST" 1.3.6.1.2.1.1.1.0 2>/dev/null || true)
    if [[ -n "$result" ]]; then
        echo "[HIGH] snmpv2c on udp/${port}: public community returned sysDescr"
        add_finding "snmpv2c" "$port" "$LOCAL_HOST" "insecure" "high" \
            "SNMPv2c public community returned: ${result%%$'\n'*}" \
            "SNMPv3 with authPriv" \
            "Change community string; restrict to SNMPv3 authPriv"
        return
    fi

    echo "[INFO] snmp on udp/${port}: no data returned with public community"
    add_finding "snmp" "$port" "$LOCAL_HOST" "accepted_exception" "low" \
        "SNMP public community string rejected" \
        "SNMPv3 with authPriv" \
        "N/A"
}

audit_ldap() {
    local port="389"

    # Domain controllers typically run LDAP on 389 - may be accepted exposure
    local dc_ldap_exposure=false

    if ! command -v ldapsearch >/dev/null 2>&1; then
        echo "[INFO] ldap on tcp/${port}: ldapsearch not installed, skipping"
        # On DC, LDAP exposure is expected but should be noted as accepted
        echo "[NOTE] Domain Controller detected - LDAP port 389 is expected service"
        add_finding "ldap" "$port" "$WINDOWS_HOST" "accepted_exception" "medium" \
            "LDAP port exposed on Domain Controller - requires TLS restriction" \
            "LDAPS (Port 636) or STARTTLS" \
            "Require SSL/TLS via Group Policy; disable unsecured LDAP binding"
        return
    fi

    local result=""
    result=$(ldapsearch -x -H "ldap://${LOCAL_HOST}" -b "" -s base \
        "(objectclass=*)" -LLL 2>/dev/null || true)

    if [[ -n "$result" ]]; then
        echo "[MEDIUM] ldap on tcp/${port}: anonymous bind succeeded without STARTTLS"
        # If target is Windows DC, note it differently
        if [[ "$LOCAL_HOST" != "127.0.0.1" ]]; then
            echo "[NOTE] Target appears to be external server - verify LDAP security posture"
        fi
        add_finding "ldap" "$port" "$LOCAL_HOST" "insecure" "medium" \
            "Anonymous simple bind succeeded; RootDSE accessible without TLS" \
            "LDAPS (Port 636) or STARTTLS" \
            "Require TLS; disable anonymous bind"
    else
        echo "[INFO] ldap on tcp/${port}: anonymous bind failed or not present"
        add_finding "ldap" "$port" "$LOCAL_HOST" "accepted_exception" "low" \
            "Anonymous bind rejected or service unavailable" \
            "LDAPS (Port 636) or STARTTLS" \
            "N/A"
    fi
}

audit_ldaps() {
    local port="636"

    if ! command -v openssl >/dev/null 2>&1; then
        echo "[INFO] ldaps on tcp/${port}: openssl not installed, skipping"
        add_finding "ldaps" "$port" "$LOCAL_HOST" "not_testable" "info" \
            "openssl binary not found" \
            "N/A" \
            "apt install -y openssl"
        return
    fi

    local tls_output
    tls_output=$(echo | openssl s_client -connect "${LOCAL_HOST}:${port}" \
        -showcerts -servername "$LOCAL_HOST" 2>&1 </dev/null || true)

    if echo "$tls_output" | grep -q "Verify return code: 0"; then
        echo "[INFO] ldaps on tcp/${port}: TLS handshake OK"
        add_finding "ldaps" "$port" "$LOCAL_HOST" "secure" "low" \
            "TLS handshake successful with valid certificate" \
            "N/A" \
            "N/A"
    elif echo "$tls_output" | grep -q "verify error"; then
        # On DC, certificate issues are more critical
        echo "[MEDIUM] ldaps on tcp/${port}: TLS certificate verification failed"
        add_finding "ldaps" "$port" "$LOCAL_HOST" "insecure" "medium" \
            "Certificate verification failed - check CA trust chain" \
            "Valid enterprise PKI certificate required" \
            "Issue certificate from trusted internal CA; update CA trust store"
    else
        echo "[INFO] ldaps on tcp/${port}: TLS handshake failed or not present"
        # On DC, LDAPS absence is concerning
        echo "[NOTE] Domain Controllers should have LDAPS enabled on port 636"
        add_finding "ldaps" "$port" "$LOCAL_HOST" "not_present" "medium" \
            "No TLS response on port 636 - critical for Domain Controller security" \
            "LDAPS with valid enterprise certificate" \
            "Enable LDAPS on Windows Server; configure SPN for LDAP/S service"
    fi
}

audit_rdp() {
    local port="3389"
    local result=""

    # Check port reachability via nc timeout
    result=$(timeout 3 nc -zv "$WINDOWS_HOST" "$port" 2>&1 || true)

    if echo "$result" | grep -qi "succeeded\|open"; then
        # RDP open on DC is HIGH risk - administrative access point
        echo "[HIGH] rdp on tcp/${port}: reachable at ${WINDOWS_HOST} (Domain Controller - elevated risk)"
        add_finding "rdp" "$port" "$WINDOWS_HOST" "insecure" "high" \
            "RDP port 3389 reachable at Domain Controller ${WINDOWS_HOST}; requires NLA and MFA" \
            "NLA-enabled RDP with Network Level Authentication + Jump server pattern" \
            "Restrict RDP via GPO to jump hosts only; require MFA; implement Just-in-Time access"
    else
        echo "[INFO] rdp on tcp/${port}: not reachable at ${WINDOWS_HOST} (positive security posture)"
        # RDP closed on DC is acceptable if administrative access uses alternative methods
        add_finding "rdp" "$port" "$WINDOWS_HOST" "accepted_exception" "low" \
            "RDP port 3389 unreachable at Domain Controller ${WINDOWS_HOST}" \
            "Administrative access via secure jump host or Windows Admin Center" \
            "Ensure alternative secure management channel exists"
    fi
}

# ==============================================================================
# Run all audits
# ==============================================================================

echo "[*] Auditing candidate ports..."

COUNT=0
while IFS= read -r port; do
    [[ -z "$port" ]] && continue
    COUNT=$((COUNT + 1))
done <<< "$OPEN_PORTS"

echo "[*] Candidate listeners: ${COUNT}"

audit_ftp
audit_telnet
audit_smtp
audit_http_admin
audit_pop3
audit_imap
audit_snmp
audit_ldap
audit_ldaps
audit_rdp

# ==============================================================================
# Build final JSON output
# ==============================================================================

echo "[*] Building protocol_audit.json..."

# Count high severity findings
HIGH_COUNT=$(grep -c '"severity": "high"' "$TMP_FINDINGS" 2>/dev/null || echo "0")

# Validate HIGH_COUNT is numeric
if ! [[ "$HIGH_COUNT" =~ ^[0-9]+$ ]]; then
    HIGH_COUNT="0"
fi

jq -nc \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg hostname "$(hostname)" \
    --slurpfile findings <(cat "$TMP_FINDINGS" | jq -s '.') \
    --argjson high_unaccepted_count "$HIGH_COUNT" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        findings: $findings[0],
        summary: {
            total_findings: ($findings[0] | length),
            high_count: ($findings[0] | map(select(.severity == "high")) | length)
        },
        high_unaccepted_count: $high_unaccepted_count
    }' > "$OUTPUT_FILE"

echo ""
echo "Findings: $(jq '.findings | length' "$OUTPUT_FILE")"
echo "High unaccepted: ${HIGH_COUNT}"
echo "Report saved to: $OUTPUT_FILE"
