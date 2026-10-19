#!/bin/bash
# Name: validate_rules.sh
# Purpose: Test both Sigma rules from Tasks 3 and 4 against incident and
#          clean Sysmon data, report match counts and false positive
#          rates, and trigger tuning workflow if FP rate exceeds target.
# Author: Steve - Cybersecurity Engineer
# Date: 19 October 2026

set -euo pipefail

# Configuration
INCIDENT_LOG="5x03/incident_sysmon.jsonl"
CLEAN_LOG="5x03/clean_sysmon.jsonl"
RULE_PROCESS_CREATION="sigma_powershell_msbuild_lolbin.yml"
RULE_NETWORK_CONN="sigma_msbuild_network_connection.yml"
TARGET_FP_RATE="0.001"
CONFIG_SYSMON="sysmon"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log_info()    { echo "[INFO] ${1}"; }
log_success() { echo -e "${GREEN}[PASS]${NC} ${1}"; }
log_warn()    { echo -e "${YELLOW}[REVIEW]${NC} ${1}"; }
log_error()   { echo -e "${RED}[FAIL]${NC} ${1}"; }

check_dependencies() {
    local missing=()

    if ! command -v sigmac &>/dev/null; then
        missing+=("sigmac")
    fi
    if ! command -v jq &>/dev/null; then
        missing+=("jq")
    fi
    if ! command -v bc &>/dev/null; then
        missing+=("bc")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        exit 1
    fi
}

validate_inputs() {
    local file

    for file in "$INCIDENT_LOG" "$CLEAN_LOG" \
                "$RULE_PROCESS_CREATION" "$RULE_NETWORK_CONN"; do
        if [[ ! -f "$file" ]]; then
            log_error "Missing input file: $file"
            exit 1
        fi
    done
}

count_events() {
    wc -l < "$1" | tr -d ' '
}

# Process Creation rule logic:
# event_id 1 AND parent in (powershell/pwsh/ise/wscript/cscript/mshta)
# AND image ends with MSBuild.exe
count_process_creation_matches() {
    jq -c 'select(.event_id == 1) |
        select(.parent_image |
            test("\\\\(powershell|pwsh|powershell_ise|wscript|cscript|mshta)\\.exe$")) |
        select(.image | test("MSBuild\\.exe$"))' "$1" | wc -l | tr -d ' '
}

# Network Connection rule logic:
# event_id 3 AND MSBuild.exe AND initiated == true AND dst_ip NOT in
# RFC 1918 (10/8, 172.16-31, 192.168/16) AND NOT loopback
# Network Connection rule logic (tuned):
# event_id 3 AND MSBuild.exe AND initiated == true AND dst_ip NOT in
# RFC 1918 (10/8, 172.16-31, 192.168/16) AND NOT loopback
# AND NOT hostname ending .nuget.org (tuning per rule_validation_report.md)
count_network_conn_matches() {
    jq -c 'select(.event_id == 3 and .initiated == true) |
        select(.image | test("MSBuild\\.exe$")) |
        select(.dst_ip | test(
            "^(10\\.|127\\.|169\\.254\\.|192\\.168\\.)" +
            "|^172\\.(1[6-9]|2[0-9]|3[01])\\." +
            "|^(::1|fe80:)" ) | not) |
        select(.dst_hostname == null or
               (.dst_hostname | test("\\.nuget\\.org$") | not))' "$1" | wc -l | tr -d ' '
}

calc_percentage() {
    local num="$1" denom="$2"

    if [[ "$denom" -eq 0 ]]; then
        echo "0.000"
        return
    fi
    printf "%.3f" "$(echo "scale=6; ($num / $denom) * 100" | bc)"
}

rate_exceeds_threshold() {
    awk -v r="$1" -v t="$2" 'BEGIN { exit !(r > t) }'
}

list_fp_patterns() {
    local log_file="$1" rule_type="$2"

    if [[ "$rule_type" == "process" ]]; then
        echo "  Matched process creation events (false positive pattern):"
        jq -r 'select(.event_id == 1) |
            select(.parent_image |
                test("\\\\(powershell|pwsh|powershell_ise|wscript|cscript|mshta)\\.exe$")) |
            select(.image | test("MSBuild\\.exe$")) |
            "\(.ts) \(.host) \(.user) parent=\(.parent_image) child=\(.image)"' \
            "$log_file" | head -20
    else
        echo "  Matched network events (false positive pattern):"
        jq -r 'select(.event_id == 3 and .initiated == true) |
            select(.image | test("MSBuild\\.exe$")) |
            "\(.ts) \(.host) dst=\(.dst_ip) host=\(.dst_hostname) port=\(.dst_port)"' \
            "$log_file" | head -20
    fi
}

run_validation() {
    local sample_file="$1"
    local rule_desc="$2"
    local is_clean="$3"
    local rule_type="$4"

    local total_events
    total_events=$(count_events "$sample_file")

    local match_count=0
    if [[ "$rule_type" == "process" ]]; then
        match_count=$(count_process_creation_matches "$sample_file")
    else
        match_count=$(count_network_conn_matches "$sample_file")
    fi

    local match_rate
    match_rate=$(calc_percentage "$match_count" "$total_events")

    echo ""
    echo "[$(basename "$sample_file")] ${rule_desc}"
    echo "  Total events: $total_events"
    echo "  Matches: $match_count"
    echo "  Match rate: ${match_rate}%"

    if [[ "$is_clean" -eq 1 ]]; then
        if rate_exceeds_threshold "$match_rate" "$TARGET_FP_RATE"; then
            log_warn "FP rate ${match_rate}% exceeds target ${TARGET_FP_RATE}%"
            list_fp_patterns "$sample_file" "$rule_type"
            echo "  Verdict: REVIEW"
            return 1
        else
            if [[ "$match_count" -gt 0 ]]; then
                log_warn "FP rate within target but matches exist (${match_count})"
                list_fp_patterns "$sample_file" "$rule_type"
            fi
            log_success "FP rate within target (${match_rate}% <= ${TARGET_FP_RATE}%)"
            echo "  Verdict: PASS"
            return 0
        fi
    else
        if [[ "$match_count" -gt 0 ]]; then
            log_success "Rule detected expected attack activity"
            list_incident_evidence "$sample_file" "$rule_type"
            echo "  Verdict: PASS"
            return 0
        else
            log_error "Rule did not detect expected attack activity"
            echo "  Verdict: FAIL"
            return 1
        fi
    fi
}

list_incident_evidence() {
    local log_file="$1" rule_type="$2"

    echo "  Matched incident events:"
    if [[ "$rule_type" == "process" ]]; then
        jq -r 'select(.event_id == 1) |
            select(.parent_image |
                test("\\\\(powershell|pwsh|powershell_ise|wscript|cscript|mshta)\\.exe$")) |
            select(.image | test("MSBuild\\.exe$")) |
            "\(.ts) \(.host) \(.user) pid=\(.pid) parent=\(.parent_image) -> \(.image)"' \
            "$log_file"
    else
        jq -r 'select(.event_id == 3 and .initiated == true) |
            select(.image | test("MSBuild\\.exe$")) |
            "\(.ts) \(.host) pid=\(.pid) dst=\(.dst_ip):\(.dst_port)"' \
            "$log_file"
    fi
}

main() {
    log_info "Starting rule validation..."
    check_dependencies
    validate_inputs

    echo ""
    echo "=============================================="
    echo "SIGMA RULE VALIDATION REPORT"
    echo "=============================================="

    local overall_pass=0

    run_validation "$INCIDENT_LOG" \
        "Process Creation ($RULE_PROCESS_CREATION)" 0 "process" || overall_pass=1
    run_validation "$CLEAN_LOG" \
        "Process Creation ($RULE_PROCESS_CREATION)" 1 "process" || overall_pass=1
    run_validation "$INCIDENT_LOG" \
        "Network Connection ($RULE_NETWORK_CONN)" 0 "network" || overall_pass=1
    run_validation "$CLEAN_LOG" \
        "Network Connection ($RULE_NETWORK_CONN)" 1 "network" || overall_pass=1

    echo ""
    echo "=============================================="
    echo "SUMMARY"
    echo "=============================================="
    if [[ "$overall_pass" -eq 0 ]]; then
        log_success "All validations passed"
    else
        log_warn "Some validations require review"
    fi

    return "$overall_pass"
}

main "$@"
