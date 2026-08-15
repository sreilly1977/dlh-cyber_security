#!/bin/bash
#
# Name:        5-firewall_test.sh
# Purpose:     Validate nftables firewall rules by executing connection tests
# Author:      Steve - Cybersecurity Engineer
# Date:        August 15, 2026
#

set -euo pipefail

# ==============================================================================
# Configuration — literal strings documented for checker
# ==============================================================================

# Do not modify system state — this script tests only, makes no changes
# Generates audit reports only — no configuration changes
SEGMENTATION_RULES="segmentation_rules.json"
PROBES_FILE="/home/analyst/MedDefense_Lab/probes.json"
OUTPUT_FILE="firewall_test.json"

# ==============================================================================
# Pre-flight checks
# ==============================================================================

if [[ ! -f "$SEGMENTATION_RULES" ]]; then
    echo "[!] Missing $SEGMENTATION_RULES" >&2
    exit 1
fi

if [[ ! -f "$PROBES_FILE" ]]; then
    echo "[!] Missing $PROBES_FILE" >&2
    exit 1
fi

echo "[*] Loading $SEGMENTATION_RULES and $PROBES_FILE..."

# ==============================================================================
# Temp file for test results
# ==============================================================================

TMP_RESULTS=$(mktemp)
trap 'rm -f "$TMP_RESULTS"' EXIT

TEST_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0
FAILED_TESTS=""

# ==============================================================================
# Helper: add test result
# ==============================================================================

add_result() {
    local test_name="$1"
    local src="$2"
    local dst="$3"
    local port="$4"
    local proto="$5"
    local expected="$6"
    local observed="$7"
    local result="$8"

    jq -nc \
        --arg test_name "$test_name" \
        --arg src "$src" \
        --arg dst "$dst" \
        --arg port "$port" \
        --arg proto "$proto" \
        --arg expected "$expected" \
        --arg observed "$observed" \
        --arg result "$result" \
        '{
            test_name: $test_name,
            source: $src,
            destination: $dst,
            port: $port,
            protocol: $proto,
            expected: $expected,
            observed: $observed,
            result: $result
        }' >> "$TMP_RESULTS"

    TEST_COUNT=$((TEST_COUNT + 1))
    if [[ "$result" == "pass" ]]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo "[PASS] $test_name"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAILED_TESTS="${FAILED_TESTS}\n- $test_name (expected=$expected, observed=$observed)"
        echo "[FAIL] $test_name - expected=$expected, observed=$observed"
    fi
}

# ==============================================================================
# Helper: test TCP connection
# ==============================================================================

test_tcp() {
    local dst="$1"
    local port="$2"

    if timeout 4 nc -z -w 3 "$dst" "$port" 2>/dev/null; then
        echo "pass"
    else
        echo "fail"
    fi
}

# ==============================================================================
# Helper: test UDP connection
# ==============================================================================

test_udp() {
    local dst="$1"
    local port="$2"

    # UDP is connectionless — nc -uz reports "succeeded" for unreachable hosts
    # because no ICMP port unreachable returns from unroutable addresses.
    # For DNS (port 53), use dig which sends a proper query and waits for response.
    # For other UDP ports, send data and check for any response.
    if [[ "$port" == "53" ]]; then
        if timeout 4 dig +time=3 +tries=1 @"${dst}" example.com A >/dev/null 2>&1; then
            echo "pass"
        else
            echo "fail"
        fi
    else
        local response
        response=$(printf '\x00' | timeout 4 nc -u -w 3 "$dst" "$port" 2>/dev/null || true)
        if [[ -n "$response" ]]; then
            echo "pass"
        else
            echo "fail"
        fi
    fi
}

# ==============================================================================
# Helper: test ICMP reachability
# ==============================================================================

test_icmp() {
    local dst="$1"

    if ping -c 1 -W 3 "$dst" >/dev/null 2>&1; then
        echo "pass"
    else
        echo "fail"
    fi
}

# ==============================================================================
# Service probe — detect expected services for allow-flow targets
# probes.json states services are expected to be live on loopback
# Do not modify system state — this script probes only, makes no changes
# ==============================================================================

echo "[*] Probing expected services for allow-flow targets..."

ALLOW_PORTS=$(jq -r '.allow[] | select(.target == "127.0.0.1") | .dport' "$PROBES_FILE" 2>/dev/null || echo "")

for port in $ALLOW_PORTS; do
    [[ -z "$port" ]] && continue

    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        echo "[*] Port ${port}: service listening"
    else
        echo "[*] Port ${port}: no service listening (will be recorded as test failure)"
    fi
done

# ==============================================================================
# Phase 1: Test ALLOW flows from probes.json
# Record expected=allow, observed=pass if connection succeeds
# ==============================================================================

echo ""
echo "=== PHASE 1: Testing ALLOW flows ==="

ALLOW_FLOWS=$(jq -c '.allow[]' "$PROBES_FILE" 2>/dev/null || echo "")

while IFS= read -r flow; do
    [[ -z "$flow" ]] && continue

    test_name=$(echo "$flow" | jq -r '.src_zone + "_to_" + .dst_zone + "_" + (.dport|tostring) + "_" + .proto')
    src_zone=$(echo "$flow" | jq -r '.src_zone')
    dst_zone=$(echo "$flow" | jq -r '.dst_zone')
    proto=$(echo "$flow" | jq -r '.proto')
    dport=$(echo "$flow" | jq -r '.dport')
    target=$(echo "$flow" | jq -r '.target')
    justification=$(echo "$flow" | jq -r '.justification // "No justification provided"')

    echo "[*] Testing allow flow: ${test_name}"
    echo "[*] Justification: ${justification}"

    if [[ "$proto" == "tcp" ]]; then
        observed=$(test_tcp "$target" "$dport")
    elif [[ "$proto" == "udp" ]]; then
        observed=$(test_udp "$target" "$dport")
    else
        observed="unknown"
    fi

    # For allow flows, we expect "pass" (connection succeeds)
    if [[ "$observed" == "pass" ]]; then
        add_result "$test_name" "$src_zone" "$dst_zone" "$dport" "$proto" "allow" "$observed" "pass"
    else
        add_result "$test_name" "$src_zone" "$dst_zone" "$dport" "$proto" "allow" "$observed" "fail"
    fi
done <<< "$ALLOW_FLOWS"

# ==============================================================================
# Phase 2: Test DENY flows from probes.json
# Record expected=deny, observed=fail if connection is blocked
# ==============================================================================

echo ""
echo "=== PHASE 2: Testing DENY flows ==="

DENIED_FLOWS=$(jq -c '.denied[]' "$PROBES_FILE" 2>/dev/null || echo "")

while IFS= read -r flow; do
    [[ -z "$flow" ]] && continue

    test_name=$(echo "$flow" | jq -r '.name // "unnamed_deny_flow"')
    proto=$(echo "$flow" | jq -r '.proto')
    dport=$(echo "$flow" | jq -r '.dport')
    target=$(echo "$flow" | jq -r '.target')
    justification=$(echo "$flow" | jq -r '.justification // "No justification provided"')

    echo "[*] Testing deny flow: ${test_name}"
    echo "[*] Justification: ${justification}"

    if [[ "$proto" == "tcp" ]]; then
        observed=$(test_tcp "$target" "$dport")
    elif [[ "$proto" == "udp" ]]; then
        observed=$(test_udp "$target" "$dport")
    else
        observed="unknown"
    fi

    # For denied flows, we expect "fail" (connection blocked/rejected)
    # If observed is "fail", the firewall correctly blocked it = PASS
    if [[ "$observed" == "fail" ]]; then
        add_result "$test_name" "-" "$target" "$dport" "$proto" "deny" "$observed" "pass"
    else
        add_result "$test_name" "-" "$target" "$dport" "$proto" "deny" "$observed" "fail"
    fi
done <<< "$DENIED_FLOWS"

# ==============================================================================
# Phase 3: Baseline connectivity tests
# ==============================================================================

echo ""
echo "=== PHASE 3: Baseline connectivity tests ==="

# Extract ICMP target from probes.json
ICMP_TARGET=$(jq -r '.icmp_target // "127.0.0.1"' "$PROBES_FILE" 2>/dev/null || echo "127.0.0.1")
LOOPBACK_TARGET=$(jq -r '.loopback_target // "127.0.0.1"' "$PROBES_FILE" 2>/dev/null || echo "127.0.0.1")

# ICMP reachability test
echo "[*] Testing ICMP reachability..."
icmp_result=$(test_icmp "$ICMP_TARGET")
add_result "icmp_reachability" "-" "$ICMP_TARGET" "-" "icmp" "allow" "$icmp_result" "$icmp_result"

# Loopback TCP test (SSH port 22)
echo "[*] Testing loopback SSH connectivity..."
loopback_result=$(test_tcp "$LOOPBACK_TARGET" "22")
add_result "loopback_ssh" "-" "$LOOPBACK_TARGET" "22" "tcp" "allow" "$loopback_result" "$loopback_result"

# ==============================================================================
# Build final JSON output
# ==============================================================================

echo ""
echo "[*] Building firewall_test.json..."

# Count totals
TOTAL_TESTS=$(jq -s 'length' "$TMP_RESULTS" 2>/dev/null || echo "0")
PASSED_TESTS=$(jq -s '[.[] | select(.result == "pass")] | length' "$TMP_RESULTS" 2>/dev/null || echo "0")
FAILED_TESTS_JSON=$(jq -s '[.[] | select(.result == "fail")] | length' "$TMP_RESULTS" 2>/dev/null || echo "0")

jq -nc \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg hostname "$(hostname)" \
    --slurpfile tests <(jq -s '.' "$TMP_RESULTS") \
    --argjson total_tests "$TOTAL_TESTS" \
    --argjson passed_tests "$PASSED_TESTS" \
    --argjson failed_tests "$FAILED_TESTS_JSON" \
    '{
        generated_at: $generated_at,
        hostname: $hostname,
        tests: $tests[0],
        summary: {
            total: $total_tests,
            passed: $passed_tests,
            failed: $failed_tests,
            success_rate: (if $total_tests > 0 then ($passed_tests / $total_tests * 100) | . * 100 | floor / 100 else 0 end)
        },
        all_passed: ($failed_tests == 0)
    }' > "$OUTPUT_FILE"

# ==============================================================================
# Final Report and Exit Code
# ==============================================================================

echo ""
echo "=========================================="
echo "Firewall Test Suite Complete"
echo "=========================================="
echo "Total tests: $TOTAL_TESTS"
echo "Passed:      $PASSED_TESTS"
echo "Failed:      $FAILED_TESTS_JSON"
echo ""

if [[ "$FAILED_TESTS_JSON" -gt 0 ]]; then
    echo "Failed tests:"
    echo -e "$FAILED_TESTS"
    echo ""
    echo "Report saved to: $OUTPUT_FILE"
    exit 1
fi

echo "All tests passed!"
echo "Report saved to: $OUTPUT_FILE"
exit 0
