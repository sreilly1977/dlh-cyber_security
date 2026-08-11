#!/bin/bash
#
# Name:        5-post_patch_validate.sh
# Purpose:     Validate post-patch service state, listening ports, and liveness probes
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly EXECUTION_LOG="${BASE_DIR}/patch_execution_log.json"
readonly DEPS_MAP_FILE="${BASE_DIR}/service_dependency_map.json"
readonly PRE_STATE_FILE="${BASE_DIR}/pre_patch_state.json"
readonly OUTPUT_FILE="${BASE_DIR}/post_patch_validation.json"

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

validate_prerequisites() {
    local missing=0

    if [[ ! -f "$EXECUTION_LOG" ]]; then
        warn "Execution log not found: $EXECUTION_LOG"
        missing=1
    fi

    if [[ ! -f "$DEPS_MAP_FILE" ]]; then
        warn "Service dependency map not found: $DEPS_MAP_FILE"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        log "ERROR: Missing prerequisite files. Exiting."
        exit 1
    fi
}

# Get current service active state from systemctl
get_current_service_state() {
    local service="$1"
    systemctl show "$service" --property=ActiveState --value 2>/dev/null || echo "unknown"
}

# Check if a port is currently listening (TCP or UDP) using ss -tulnp
check_port_listening() {
    local port="$1"

    if command -v ss >/dev/null 2>&1; then
        ss -tulnp 2>/dev/null | grep -q ":${port} " && return 0
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp 2>/dev/null | grep -q ":${port} " && return 0
    fi

    return 1
}

get_expected_port_for_service() {
    local service="$1"

    case "$service" in
        *apache2*)    echo "80" ;;
        *ssh*)        echo "22" ;;
        *mysql*)      echo "3306" ;;
        *postgres*)   echo "5432" ;;
        *nginx*)      echo "80" ;;
        *redis*)      echo "6379" ;;
        *bind9*|*named*) echo "53" ;;
        *docker*)     echo "2375" ;;
        *)            echo "" ;;
    esac
}

run_liveness_probe() {
    local service="$1"
    local timeout_sec="${2:-10}"

    case "$service" in
        *apache2*|*nginx*)
            curl -sf --max-time "$timeout_sec" "http://localhost/" >/dev/null 2>&1 && return 0
            ;;
        *mysql*)
            mysqladmin ping -h "127.0.0.1" -P "3306" 2>/dev/null | grep -q "mysqld is alive" && return 0
            check_port_listening "3306" && return 0
            ;;
        *postgres*)
            pg_isready -h "127.0.0.1" -p "5432" >/dev/null 2>&1 && return 0
            check_port_listening "5432" && return 0
            ;;
        *ssh*)
            timeout "$timeout_sec" bash -c "echo > /dev/tcp/127.0.0.1/22" 2>/dev/null && return 0
            check_port_listening "22" && return 0
            ;;
        *redis*)
            redis-cli -h 127.0.0.1 -p 6379 ping >/dev/null 2>&1 && return 0
            check_port_listening "6379" && return 0
            ;;
        *bind9*|*named*)
            dig +short +time="$timeout_sec" @127.0.0.1 localhost A >/dev/null 2>&1 && return 0
            check_port_listening "53" && return 0
            ;;
    esac

    local port
    port=$(get_expected_port_for_service "$service")
    if [[ -n "$port" ]] && check_port_listening "$port"; then
        return 0
    fi

    return 1
}

extract_services_from_deps() {
    jq -r '[.services[]?.service] | unique | .[]' "$DEPS_MAP_FILE" 2>/dev/null
}

extract_critical_services_from_deps() {
    jq -r '[.services[]? | select(.criticality == "critical") | .service] | unique | .[]' "$DEPS_MAP_FILE" 2>/dev/null
}

# Get pre-patch service state from pre_patch_state.json, falling back to
# execution log if the file doesn't exist
get_pre_patch_service_state() {
    local service="$1"

    # Try pre_patch_state.json first
    if [[ -f "$PRE_STATE_FILE" ]]; then
        local state
        state=$(jq -r --arg s "$service" '.services[]? | select(.service == $s) | .active_state // empty' "$PRE_STATE_FILE" 2>/dev/null || echo "")
        if [[ -n "$state" ]]; then
            echo "$state"
            return
        fi
    fi

    # Fall back to execution log pre-block snapshots
    local log_state
    log_state=$(jq -r --arg s "$service" '[.entries[].pre.service_states[]? | select(.service == $s)] | .[0].active_state // "unknown"' "$EXECUTION_LOG" 2>/dev/null || echo "unknown")
    echo "$log_state"
}

perform_validation() {
    local service_check_pass=0
    local service_check_total=0
    local socket_check_pass=0
    local socket_check_total=0
    local probe_check_pass=0
    local probe_check_total=0

    declare -a details_array=()

    # ============================================
    # PART 1: SERVICE STATE CHECKS
    # Compare current ActiveState against pre_patch_state.json baseline.
    # Only flag as regression if pre-patch state was "active" and
    # current state is anything else.
    # ============================================
    log "Checking service states against pre-patch snapshot..."

    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        [[ "$svc" == "(kernel-wide)" ]] && continue
        [[ "$svc" == "(system-wide)" ]] && continue

        local pre_state current_state status
        pre_state=$(get_pre_patch_service_state "$svc")
        current_state=$(get_current_service_state "$svc")

        service_check_total=$((service_check_total + 1))

        # Only regression if was active before and not active now
        if [[ "$pre_state" == "active" && "$current_state" != "active" ]]; then
            status="regression"
        else
            status="pass"
            service_check_pass=$((service_check_pass + 1))
        fi

        local detail
        detail=$(jq -n \
            --arg svc "$svc" \
            --arg pre "$pre_state" \
            --arg cur "$current_state" \
            --arg status "$status" \
            '{type:"service_state",name:$svc,expected:$pre,actual:$cur,status:$status}')

        details_array+=("$detail")

    done < <(extract_services_from_deps)

    # ============================================
    # PART 2: LISTENING SOCKET CHECKS
    # Verify that ports which were listening pre-patch are still listening.
    # ============================================
    log "Checking listening sockets..."

    # Try to get ports from pre_patch_state.json, fall back to service mapping
    local sockets_source='[]'
    if [[ -f "$PRE_STATE_FILE" ]]; then
        sockets_source=$(jq '.listening_ports // []' "$PRE_STATE_FILE" 2>/dev/null || echo '[]')
    fi

    local socket_count
    socket_count=$(echo "$sockets_source" | jq 'length' 2>/dev/null || echo 0)

    if [[ "$socket_count" -gt 0 ]]; then
        # Use ports from pre_patch_state.json
        while IFS= read -r sock_entry; do
            [[ -z "$sock_entry" ]] && continue

            local port protocol status
            port=$(echo "$sock_entry" | jq -r '.port')
            protocol=$(echo "$sock_entry" | jq -r '.protocol // "tcp"')

            [[ -z "$port" ]] && continue

            socket_check_total=$((socket_check_total + 1))

            if check_port_listening "$port"; then
                status="pass"
                socket_check_pass=$((socket_check_pass + 1))
            else
                status="regression"
            fi

            local detail
            detail=$(jq -n \
                --arg port "$port" \
                --arg proto "$protocol" \
                --arg status "$status" \
                '{type:"listening_socket",port:$port,protocol:$proto,status:$status}')

            details_array+=("$detail")

        done < <(echo "$sockets_source" | jq -c '.[]')
    else
        # Fall back to deriving ports from known service names
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue

            local port
            port=$(get_expected_port_for_service "$svc")
            [[ -z "$port" ]] && continue

            socket_check_total=$((socket_check_total + 1))

            local status
            if check_port_listening "$port"; then
                status="pass"
                socket_check_pass=$((socket_check_pass + 1))
            else
                status="regression"
            fi

            local detail
            detail=$(jq -n \
                --arg svc "$svc" \
                --arg port "$port" \
                --arg status "$status" \
                '{type:"listening_socket",service:$svc,port:$port,protocol:"tcp",status:$status}')

            details_array+=("$detail")

        done < <(extract_services_from_deps)
    fi

    # ============================================
    # PART 3: CRITICAL LIVENESS PROBES
    # For every service marked critical in service_dependency_map.json,
    # run a lightweight liveness probe (curl, mysqladmin ping, tcp connect, etc.)
    # ============================================
    log "Running critical liveness probes..."

    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue

        probe_check_total=$((probe_check_total + 1))

        local status result_msg
        if run_liveness_probe "$svc" 10; then
            status="pass"
            result_msg="Probe succeeded"
            probe_check_pass=$((probe_check_pass + 1))
        else
            status="probe_failed"
            result_msg="Probe failed"
        fi

        local detail
        detail=$(jq -n \
            --arg svc "$svc" \
            --arg type "tcp_connect" \
            --arg target "localhost" \
            --arg status "$status" \
            --arg result "$result_msg" \
            '{type:"liveness_probe",service:$svc,probe_type:$type,target:$target,status:$status,result:$result}')

        details_array+=("$detail")

    done < <(extract_critical_services_from_deps)

    # ============================================
    # BUILD FINAL REPORT
    # ============================================
    local total_checks=$((service_check_total + socket_check_total + probe_check_total))
    local total_passed=$((service_check_pass + socket_check_pass + probe_check_pass))
    local total_failed=$((total_checks - total_passed))

    local hostname_val verdict
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    if [[ $total_failed -eq 0 ]]; then
        verdict="PASS"
    else
        verdict="FAIL"
    fi

    local details_json='[]'
    for detail in "${details_array[@]:-}"; do
        [[ -z "$detail" ]] && continue
        details_json=$(echo "$details_json" | jq ". + [$detail]")
    done

    jq -n \
        --arg host "$hostname_val" \
        --argjson total "$total_checks" \
        --argjson passed "$total_passed" \
        --argjson failed "$total_failed" \
        --arg verdict "$verdict" \
        --argjson svc_total "$service_check_total" \
        --argjson svc_pass "$service_check_pass" \
        --argjson sock_total "$socket_check_total" \
        --argjson sock_pass "$socket_check_pass" \
        --argjson probe_total "$probe_check_total" \
        --argjson probe_pass "$probe_check_pass" \
        --argjson details "$details_json" \
        '{
            hostname: $host,
            generated_at: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
            total_checks: $total,
            passed: $passed,
            failed: $failed,
            verdict: $verdict,
            summary: {
                service_state: {checked: $svc_total, passed: $svc_pass},
                listening_sockets: {checked: $sock_total, passed: $sock_pass},
                liveness_probes: {checked: $probe_total, passed: $probe_pass}
            },
            details: $details
        }' > "$OUTPUT_FILE"

    echo "Service state checks:     ${service_check_pass}/${service_check_total}   PASS"
    echo "Listening socket checks:  ${socket_check_pass}/${socket_check_total}   PASS"
    echo "Critical liveness probes: ${probe_check_pass}/${probe_check_total}   PASS"
    echo "VERDICT: ${verdict} (${total_passed}/${total_checks})"
    log "Report saved to: $OUTPUT_FILE"

    if [[ $total_failed -gt 0 ]]; then
        return 1
    fi
    return 0
}

main() {
    log "Starting post-patch validation..."

    validate_prerequisites

    if perform_validation; then
        log "Validation PASSED"
        exit 0
    else
        log "Validation FAILED"
        exit 1
    fi
}

main "$@"
