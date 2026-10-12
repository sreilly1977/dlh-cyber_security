#!/bin/bash
# Name: recovery_validation.sh
# Purpose: Validate incident recovery by querying mock endpoint, SIEM, and netflow APIs
# Author: Steve - Cybersecurity Engineer
# Date: 14 April 2026

set -uo pipefail

BASE_URL="http://127.0.0.1:8080"
INCIDENT_ID="IR-2026-0414-01"
EVIDENCE_STORE="/evidence/${INCIDENT_ID}"
HASH_MANIFEST="${EVIDENCE_STORE}/hashes.txt"

declare -a FAILURES=()

log_pass() { echo "[PASS] $1"; }
log_fail() { echo "[FAIL] $1"; FAILURES+=("$1"); }

# Verify server is running before proceeding
check_server() {
    if ! curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/" 2>/dev/null | grep -q '^2'; then
        log_fail "mock API server not reachable at ${BASE_URL}"
        return 1
    fi
    return 0
}

check_process_trees() {
    local hosts=("WST-WS-031" "WST-WS-017" "LIS-WSIDE-01")
    local total_match=0

    for host in "${hosts[@]}"; do
        resp=$(curl -s "${BASE_URL}/endpoint/processtree/${host}")
        if [[ -z "$resp" ]]; then
            log_fail "process tree: empty response from /endpoint/processtree/${host}"
            return
        fi
        count=$(echo "$resp" | jq -r '.data.process_trees_matching["powershell_parent_msbuild_child"] // 0' 2>/dev/null) || count=0
        total_match=$((total_match + count))
    done

    if [[ "$total_match" -eq 0 ]]; then
        log_pass "process tree: no powershell->msbuild in last 24h across WST-WS-031, WST-WS-017, LIS-WSIDE-01"
    else
        log_fail "process tree: found ${total_match} powershell->msbuild lineage instances across hosts"
    fi
}

check_netflow() {
    local ip1="185.220.101.47"
    local ip2="91.234.99.107"

    resp=$(curl -s "${BASE_URL}/siem/netflow")
    if [[ -z "$resp" ]]; then
        log_fail "netflow: empty response from /siem/netflow"
        return
    fi

    pack1=$(echo "$resp" | jq -r '.data.connections_to_185_220_101_47.packets // 0' 2>/dev/null) || pack1=0
    bytes1=$(echo "$resp" | jq -r '.data.connections_to_185_220_101_47.bytes // 0' 2>/dev/null) || bytes1=0
    pack2=$(echo "$resp" | jq -r '.data.connections_to_91_234_99_107.packets // 0' 2>/dev/null) || pack2=0
    bytes2=$(echo "$resp" | jq -r '.data.connections_to_91_234_99_107.bytes // 0' 2>/dev/null) || bytes2=0

    if [[ "$pack1" -eq 0 && "$bytes1" -eq 0 && "$pack2" -eq 0 && "$bytes2" -eq 0 ]]; then
        log_pass "netflow: no outbound to 185.220.101.47 or 91.234.99.107 in last 24h"
    else
        log_fail "netflow: ${pack1} packets (${bytes1} bytes) to ${ip1}; ${pack2} packets (${bytes2} bytes) to ${ip2}"
    fi
}

check_persistence() {
    local hosts=("WST-WS-031" "WST-WS-017" "LIS-WSIDE-01")
    local found_artifacts=0

    for host in "${hosts[@]}"; do
        resp=$(curl -s "${BASE_URL}/endpoint/persistence/${host}")
        if [[ -z "$resp" ]]; then
            log_fail "persistence: empty response from /endpoint/persistence/${host}"
            return
        fi

        sched_count=$(echo "$resp" | jq -r '.data.scheduled_tasks_with_guid_names | length' 2>/dev/null) || sched_count=0
        if [[ "$sched_count" -gt 0 ]]; then
            found_artifacts=$((found_artifacts + sched_count))
        fi

        hkcu_count=$(echo "$resp" | jq -r '.data.run_keys["HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"] | length' 2>/dev/null) || hkcu_count=0
        hklm_count=$(echo "$resp" | jq -r '.data.run_keys["HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"] | length' 2>/dev/null) || hklm_count=0
        found_artifacts=$((found_artifacts + hkcu_count + hklm_count))

        temp_payloads=$(echo "$resp" | jq -r '.data.temp_dropped_payloads | to_entries[] | select(.value != "absent") | .key' 2>/dev/null | wc -l) || temp_payloads=0
        found_artifacts=$((found_artifacts + temp_payloads))
    done

    if [[ "$found_artifacts" -eq 0 ]]; then
        log_pass "persistence: no scheduled tasks, Run keys, or dropped payloads found"
    else
        log_fail "persistence: found ${found_artifacts} artifacts across affected hosts"
    fi
}

check_service_health() {
    local epic_http lis_http

    epic_http=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/service/epic-api/health")
    lis_http=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/service/lis-api/health")

    if [[ "$epic_http" -eq 200 && "$lis_http" -eq 200 ]]; then
        log_pass "service health: epic-api returns 200; lis-api returns 200"
    elif [[ "$epic_http" -ne 200 ]]; then
        log_fail "service health: epic-api returned ${epic_http} (expected 200)"
    else
        log_fail "service health: lis-api returned ${lis_http} (expected 200)"
    fi
}

check_detection_rule() {
    resp=$(curl -s "${BASE_URL}/siem/detection/wz-edr-100041")
    if [[ -z "$resp" ]]; then
        log_fail "detection: empty response from /siem/detection/wz-edr-100041"
        return
    fi

    rule_enabled=$(echo "$resp" | jq -r '.data.enabled' 2>/dev/null) || rule_enabled=false

    resp=$(curl -s "${BASE_URL}/siem/detection/wz-edr-100041/synthetic")
    if [[ -z "$resp" ]]; then
        log_fail "detection: empty response from /siem/detection/wz-edr-100041/synthetic"
        return
    fi

    synth_matched=$(echo "$resp" | jq -r '.data.synthetic_matched' 2>/dev/null) || synth_matched=false
    synth_time=$(echo "$resp" | jq -r '.data.synthetic_hit_at // "null"' 2>/dev/null) || synth_time="unknown"

    if [[ "$rule_enabled" == "true" && "$synth_matched" == "true" ]]; then
        log_pass "detection: wz-edr-100041 returned expected synthetic hit at ${synth_time}"
    elif [[ "$rule_enabled" != "true" ]]; then
        log_fail "detection: wz-edr-100041 rule disabled"
    else
        log_fail "detection: synthetic test did not match (synthetic_matched=${synth_matched})"
    fi
}

check_evidence_hashes() {
    local total=0 match=0 mismatch=0

    if [[ ! -f "${HASH_MANIFEST}" ]]; then
        log_fail "evidence hashes: manifest not found at ${HASH_MANIFEST}"
        return
    fi

    while IFS=' ' read -r expected relpath _ || [[ -n "$expected" ]]; do
        [[ "$expected" =~ ^# ]] && continue
        [[ -z "$relpath" || -z "$expected" ]] && continue

        total=$((total + 1))
        artifact_path="${EVIDENCE_STORE}/${relpath}"

        if [[ ! -f "$artifact_path" ]]; then
            mismatch=$((mismatch + 1))
            continue
        fi

        actual=$(sha256sum "$artifact_path" 2>/dev/null | awk '{print $1}') || actual=""
        if [[ "$actual" == "$expected" ]]; then
            match=$((match + 1))
        else
            mismatch=$((mismatch + 1))
        fi
    done < "${HASH_MANIFEST}"

    if [[ "$match" -eq "$total" && "$total" -gt 0 ]]; then
        log_pass "evidence hashes: ${total}/${total} artifacts match original SHA-256"
    else
        log_fail "evidence hashes: ${match}/${total} artifacts match; ${mismatch} mismatches"
    fi
}

main() {
    echo "=== Recovery Validation for ${INCIDENT_ID} ==="
    echo ""

    if ! check_server; then
        echo ""
        echo "--- FAILED CHECKS ---"
        for f in "${FAILURES[@]}"; do echo "- $f"; done
        echo ""
        echo "TOTAL: ${#FAILURES[@]} failure(s)"
        exit 1
    fi

    check_process_trees
    check_netflow
    check_persistence
    check_service_health
    check_detection_rule
    check_evidence_hashes

    echo ""

    if [[ ${#FAILURES[@]} -eq 0 ]]; then
        echo "ALL CHECKS PASSED"
        exit 0
    else
        echo "--- FAILED CHECKS ---"
        for f in "${FAILURES[@]}"; do echo "- $f"; done
        echo ""
        echo "TOTAL: ${#FAILURES[@]} failure(s)"
        exit 1
    fi
}

main
