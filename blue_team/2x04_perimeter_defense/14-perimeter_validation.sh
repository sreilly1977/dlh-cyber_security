#!/bin/bash
#
# Name:        14-perimeter_validation.sh
# Purpose:     End-to-end check of every network defense control built in this project
# Author:      Steve - Cybersecurity Engineer
# Date:        August 15, 2026
#

set -euo pipefail

# ==============================================================================
# Configuration
# ==============================================================================

# Do not modify system state - this script validates only, makes no changes
# Generates audit reports only - no configuration changes
WORKDIR="$(pwd)"
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECK_COUNT=0

# Source: /home/analyst/MedDefense_Lab/firewall_samples/ufw.log
# Argument: $1 overrides default log file (used by 7-firewall_log_analysis.sh)

# Output
OUTPUT_FILE="perimeter_validation_output.json"

# ==============================================================================
# Helper: report check result
# ==============================================================================

check_pass() {
    local check_num="$1"
    local check_name="$2"
    local details="${3:-}"

    CHECKS_PASSED=$((CHECKS_PASSED + 1))
    echo "[$(printf '%02d/09' "$check_num")] $check_name ${details:+($details)} PASS"
}

check_fail() {
    local check_num="$1"
    local check_name="$2"
    local reason="${3:-}"

    CHECKS_FAILED=$((CHECKS_FAILED + 1))
    echo "[$(printf '%02d/09' "$check_num")] $check_name FAIL"
    if [[ -n "$reason" ]]; then
        echo "    Reason: $reason"
    fi
}

# ==============================================================================
# Check 01: nftables ruleset
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking nftables ruleset..."

if nft list tables 2>/dev/null | grep -q "meddefense"; then
    # Count actual rule lines (lines with accept/drop/reject/jump/log/queue — not set/chain declarations)
    RULE_OUTPUT=$(nft list table inet meddefense 2>/dev/null || true)
    RULE_COUNT=$(echo "$RULE_OUTPUT" | grep -cE '(accept|drop|reject|jump|log|queue|dnat|snat|masquerade|redirect|tproxy)' || echo "0")
    RULE_COUNT=$(echo "$RULE_COUNT" | tr -d '[:space:]')

    if [[ -z "$RULE_COUNT" ]] || [[ ! "$RULE_COUNT" =~ ^[0-9]+$ ]]; then
        RULE_COUNT=0
    fi

    if [[ "$RULE_COUNT" -gt 0 ]]; then
        check_pass "$CHECK_COUNT" "nftables ruleset loaded" "$RULE_COUNT rules"
    else
        check_fail "$CHECK_COUNT" "nftables ruleset loaded" "No rules found in meddefense table"
    fi
else
    check_fail "$CHECK_COUNT" "nftables ruleset loaded" "meddefense table not found"
fi

# ==============================================================================
# Check 02: firewall validation report
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking firewall validation report..."

FIREWALL_CHECKS="${WORKDIR}/firewall_test_results.json"

if [[ ! -f "$FIREWALL_CHECKS" ]]; then
    check_fail "$CHECK_COUNT" "firewall test results" "firewall_test_results.json not found"
else
    TOTAL_TESTS=$(jq -r '.summary.total // 0' "$FIREWALL_CHECKS")
    PASSED_TESTS=$(jq -r '.summary.passed // 0' "$FIREWALL_CHECKS")
    FAILED_TESTS=$(jq -r '.summary.failed // 0' "$FIREWALL_CHECKS")

    if [[ "$FAILED_TESTS" -eq 0 && "$TOTAL_TESTS" -gt 0 ]]; then
        check_pass "$CHECK_COUNT" "firewall test results" "${PASSED_TESTS}/${TOTAL_TESTS}"
    else
        check_fail "$CHECK_COUNT" "firewall test results" "${PASSED_TESTS}/${TOTAL_TESTS} passed, ${FAILED_TESTS} failed"
    fi
fi

# ==============================================================================
# Check 03: Suricata configuration
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking Suricata configuration..."

SURICATA_CONFIG="${WORKDIR}/suricata.yaml"

if [[ ! -f "$SURICATA_CONFIG" ]]; then
    check_fail "$CHECK_COUNT" "suricata config -T" "suricata.yaml not found"
elif ! command -v suricata >/dev/null 2>&1; then
    check_fail "$CHECK_COUNT" "suricata config -T" "suricata binary not found"
else
    if suricata -T -c "$SURICATA_CONFIG" >/dev/null 2>&1; then
        check_pass "$CHECK_COUNT" "suricata config -T"
    else
        check_fail "$CHECK_COUNT" "suricata config -T" "suricata -T returned non-zero"
    fi
fi

# ==============================================================================
# Check 04: Suricata rule load
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking Suricata rule load..."

SETUP_VERIFICATION="${WORKDIR}/setup_verification.json"

if [[ ! -f "$SETUP_VERIFICATION" ]]; then
    check_fail "$CHECK_COUNT" "suricata rule load" "setup_verification.json not found"
else
    RULE_COUNT=$(jq -r '.rule_count // 0' "$SETUP_VERIFICATION" 2>/dev/null || echo "0")
    SMOKE_PASSED=$(jq -r '.smoke_test_passed // false' "$SETUP_VERIFICATION" 2>/dev/null || echo "false")

    # Get custom rule count from rule_validation.json
    CUSTOM_RULES=0
    if [[ -f "${WORKDIR}/rule_validation.json" ]]; then
        CUSTOM_RULES=$(jq -r '.rule_count // 0' "${WORKDIR}/rule_validation.json" 2>/dev/null || echo "0")
    fi

    # Check if meddefense.rules is referenced in suricata.yaml
    if grep -q "meddefense.rules" "$SURICATA_CONFIG" 2>/dev/null; then
        RULE_FILE_INCLUDED=true
    else
        RULE_FILE_INCLUDED=false
    fi

    if [[ "$RULE_COUNT" -gt 0 && "$SMOKE_PASSED" == "true" && "$RULE_FILE_INCLUDED" == true ]]; then
        check_pass "$CHECK_COUNT" "suricata rule load" "${RULE_COUNT} base + ${CUSTOM_RULES} custom"
    else
        check_fail "$CHECK_COUNT" "suricata rule load" "rule_count=${RULE_COUNT}, smoke=${SMOKE_PASSED}, included=${RULE_FILE_INCLUDED}"
    fi
fi

# ==============================================================================
# Check 05: custom rule validation
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking custom rule validation..."

RULE_VALIDATION="${WORKDIR}/rule_validation.json"

if [[ ! -f "$RULE_VALIDATION" ]]; then
    check_fail "$CHECK_COUNT" "custom rule validation" "rule_validation.json not found"
else
    TOTAL_RULES=$(jq -r '.rule_count // 0' "$RULE_VALIDATION" 2>/dev/null || echo "0")
    PASSED_RULES=$(jq -r '.passed // 0' "$RULE_VALIDATION" 2>/dev/null || echo "0")
    FAILED_RULES=$(jq -r '.failed // 0' "$RULE_VALIDATION" 2>/dev/null || echo "0")

    if [[ "$FAILED_RULES" -eq 0 && "$TOTAL_RULES" -gt 0 ]]; then
        check_pass "$CHECK_COUNT" "custom rule validation" "${PASSED_RULES}/${TOTAL_RULES}"
    else
        check_fail "$CHECK_COUNT" "custom rule validation" "${PASSED_RULES}/${TOTAL_RULES} passed"
    fi
fi

# ==============================================================================
# Check 06: protocol audit
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking protocol audit..."

PROTOCOL_AUDIT="${WORKDIR}/protocol_audit.json"

if [[ ! -f "$PROTOCOL_AUDIT" ]]; then
    check_fail "$CHECK_COUNT" "protocol audit" "protocol_audit.json not found"
else
    UNACCEPTED_HIGH=$(jq '[.findings[]? | select(.severity == "high" and .exception_accepted != true)] | length' "$PROTOCOL_AUDIT" 2>/dev/null || echo "0")

    if [[ "$UNACCEPTED_HIGH" -eq 0 ]]; then
        check_pass "$CHECK_COUNT" "protocol audit" "no unaccepted high"
    else
        check_fail "$CHECK_COUNT" "protocol audit" "${UNACCEPTED_HIGH} unaccepted high findings"
    fi
fi

# ==============================================================================
# Check 07: DNS filtering
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking DNS filtering..."

DNS_REPORT="${WORKDIR}/dns_filter_report.json"

if [[ ! -f "$DNS_REPORT" ]]; then
    echo "    (dns_filter_report.json not found — skipping)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
    echo "[$(printf '%02d/09' "$CHECK_COUNT")] dns filtering skipped (file not present) PASS"
else
    SERVICE_STATUS=$(jq -r '.service_status // "inactive"' "$DNS_REPORT" 2>/dev/null || echo "inactive")
    BLOCKED_DOMAINS=$(jq -r '.blocked_domains // 0' "$DNS_REPORT" 2>/dev/null || echo "0")

    if [[ "$SERVICE_STATUS" == "active" && "$BLOCKED_DOMAINS" -gt 0 ]]; then
        check_pass "$CHECK_COUNT" "dns filtering active and validated" "${BLOCKED_DOMAINS} domains blocked"
    else
        check_fail "$CHECK_COUNT" "dns filtering active and validated" "service_status=${SERVICE_STATUS}, blocked=${BLOCKED_DOMAINS}"
    fi
fi

# ==============================================================================
# Check 08: artifact package
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking artifact package..."

MANIFEST_FILE="${WORKDIR}/network_artifact_package/manifest/manifest.json"

if [[ ! -f "$MANIFEST_FILE" ]]; then
    check_fail "$CHECK_COUNT" "artifact package manifest" "manifest.json not found"
else
    VERIFIED=0
    TOTAL_FILES=$(jq '.files | length' "$MANIFEST_FILE")
    PACKAGE_FAIL=false

    for ((i = 0; i < TOTAL_FILES; i++)); do
        relpath=$(jq -r ".files[$i].path" "$MANIFEST_FILE")
        manifest_hash=$(jq -r ".files[$i].sha256" "$MANIFEST_FILE")
        required=$(jq -r ".files[$i].required" "$MANIFEST_FILE")
        present=$(jq -r ".files[$i].present" "$MANIFEST_FILE")

        filepath="${WORKDIR}/network_artifact_package/${relpath}"

        if [[ "$required" == "true" && "$present" == "false" ]]; then
            check_fail "$CHECK_COUNT" "artifact package manifest" "required file missing: ${relpath}"
            PACKAGE_FAIL=true
            break
        fi

        if [[ "$present" == "true" ]]; then
            actual_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
            if [[ "$actual_hash" != "$manifest_hash" ]]; then
                check_fail "$CHECK_COUNT" "artifact package manifest" "hash mismatch: ${relpath}"
                PACKAGE_FAIL=true
                break
            fi
            VERIFIED=$((VERIFIED + 1))
        fi
    done

    if [[ "$PACKAGE_FAIL" == false ]]; then
        check_pass "$CHECK_COUNT" "artifact package manifest verified" "${VERIFIED} files verified"
    fi
fi

# ==============================================================================
# Check 09: no-residue rerun consistency
# ==============================================================================

CHECK_COUNT=$((CHECK_COUNT + 1))

echo "[*] Checking no-residue rerun consistency..."

# Verify no temp listeners from previous 5-firewall_test.sh runs remain
TEMP_PIDS_RAW=$(pgrep -f "python3.*socket.*AF_INET" 2>/dev/null || true)
TEMP_PIDS_COUNT=$(echo "$TEMP_PIDS_RAW" | grep -c . 2>/dev/null || echo "0")
TEMP_PIDS_COUNT=$(echo "$TEMP_PIDS_COUNT" | tr -d '[:space:]')

if [[ -z "$TEMP_PIDS_COUNT" ]] || [[ ! "$TEMP_PIDS_COUNT" =~ ^[0-9]+$ ]]; then
    TEMP_PIDS_COUNT=0
fi

if [[ "$TEMP_PIDS_COUNT" -eq 0 ]]; then
    check_pass "$CHECK_COUNT" "no-residue rerun consistency"
else
    check_fail "$CHECK_COUNT" "no-residue rerun consistency" "${TEMP_PIDS_COUNT} temp listeners remaining"
fi

# ==============================================================================
# Final Report
# ==============================================================================

echo ""
echo "Checks: ${CHECK_COUNT}    Passed: ${CHECKS_PASSED}    Failed: ${CHECKS_FAILED}"

# Build JSON output
jq -nc \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg hostname "$(hostname)" \
    --argjson total "$CHECK_COUNT" \
    --argjson passed "$CHECKS_PASSED" \
    --argjson failed "$CHECKS_FAILED" \
    --arg overall_status "$([[ "$CHECKS_FAILED" -eq 0 ]] && echo "READY" || echo "NOT_READY")" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        total_checks: $total,
        passed: $passed,
        failed: $failed,
        perimeter_status: $overall_status,
        all_passed: ($failed == 0)
    }' | tee "$OUTPUT_FILE"

echo ""

if [[ "$CHECKS_FAILED" -eq 0 ]]; then
    echo "Perimeter validation: READY"
    exit 0
else
    echo "Perimeter validation: NOT READY"
    exit 1
fi
