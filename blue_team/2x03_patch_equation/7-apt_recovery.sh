#!/bin/bash
#
# Name:        7-apt_recovery.sh
# Purpose:     Diagnose and repair a broken apt/dpkg state from an interrupted upgrade
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly DEPS_MAP_FILE="${BASE_DIR}/service_dependency_map.json"
readonly OUTPUT_FILE="${BASE_DIR}/apt_recovery.json"
readonly APT_ENV="DEBIAN_FRONTEND=noninteractive"

log() {
    echo "[*] $*"
}

info() {
    echo "    $*"
}

warn() {
    echo "[!] $*" >&2
}

readonly LOCK_FILES=(
    "/var/lib/dpkg/lock-frontend"
    "/var/lib/dpkg/lock"
    "/var/cache/apt/archives/lock"
)

# ============================================
# DIAGNOSIS FUNCTIONS
# ============================================

check_live_processes() {
    local procs
    procs=$(pgrep -fa 'dpkg|apt-get|aptitude|unattended' 2>/dev/null | grep -v "$SCRIPT_NAME" || true)

    if [[ -n "$procs" ]]; then
        echo "$procs"
        return 1
    fi
    return 0
}

check_lock_files() {
    local stale_locks=''
    for lf in "${LOCK_FILES[@]}"; do
        if [[ -f "$lf" ]]; then
            if ! fuser "$lf" >/dev/null 2>&1; then
                if [[ -n "$stale_locks" ]]; then
                    stale_locks="${stale_locks}, ${lf}"
                else
                    stale_locks="${lf}"
                fi
            fi
        fi
    done
    echo "$stale_locks"
}

run_dpkg_audit() {
    dpkg --audit 2>/dev/null || true
}

get_broken_packages() {
    local broken=''

    # Method 1: dpkg --audit output
    local audit_output
    audit_output=$(dpkg --audit 2>/dev/null || true)

    if [[ -n "$audit_output" ]]; then
        broken=$(echo "$audit_output" | grep -oE '^[a-zA-Z0-9][a-zA-Z0-9.+~-]*' | sort -u | tr '\n' ',' | sed 's/,$//')
    fi

    # Method 2: Query dpkg database for broken states
    # Check for half-configured, half-installed, unpacked, and triggers-pending states
    local state_broken
    state_broken=$(dpkg-query -W -f='${binary:Package}\t${db:Status-Abbrev}\n' 2>/dev/null | \
        awk -F'\t' '{
            # First char = desired, Second char = status, Third char = error
            # F = half-configured, H = half-installed, U = unpacked, T = triggers-pending
            if ($2 ~ /F/) state="half-configured";
            else if ($2 ~ /H/) state="half-installed";
            else if ($2 ~ /U/) state="unpacked";
            else if ($2 ~ /T/) state="triggers-pending";
            else next;
            print $1
        }' | sort -u | tr '\n' ',' | sed 's/,$//' || true)

    # Merge both lists
    if [[ -n "$broken" ]] && [[ -n "$state_broken" ]]; then
        broken=$(echo "${broken},${state_broken}" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
    elif [[ -n "$state_broken" ]]; then
        broken="$state_broken"
    fi

    echo "$broken"
}

check_free_space() {
    local result='[]'

    for mountpoint in "/" "/var"; do
        local avail_kb
        avail_kb=$(df -P "$mountpoint" 2>/dev/null | awk 'NR==2 {print $4}')
        if [[ -n "$avail_kb" ]]; then
            local avail_mb=$((avail_kb / 1024))
            local entry
            entry=$(jq -n --arg mp "$mountpoint" --argjson mb "$avail_mb" \
                '{mountpoint:$mp, available_mb:$mb}')
            result=$(echo "$result" | jq ". + [$entry]")
        fi
    done

    echo "$result"
}

perform_diagnosis() {
    local diagnosis_temp
    diagnosis_temp=$(mktemp)

    # Check live processes
    local live_procs
    live_procs=$(check_live_processes || true)

    # Check lock files
    local stale_locks
    stale_locks=$(check_lock_files)

    # Run dpkg --audit
    local audit_output
    audit_output=$(run_dpkg_audit)

    # Get broken packages
    local broken_pkgs
    broken_pkgs=$(get_broken_packages)

    # Check free space
    local free_space
    free_space=$(check_free_space)

    # Build diagnosis JSON
    jq -n \
        --arg live_procs "${live_procs:-none}" \
        --arg stale_locks "${stale_locks:-none}" \
        --arg audit "${audit_output:-clean}" \
        --arg broken "${broken_pkgs:-none}" \
        --argjson free_space "$free_space" \
        '{live_processes:$live_procs, stale_locks:$stale_locks, dpkg_audit:$audit, broken_packages:$broken, free_space:$free_space}' \
        > "$diagnosis_temp"

    cat "$diagnosis_temp"
    rm -f "$diagnosis_temp"
}

# ============================================
# REPAIR FUNCTIONS
# ============================================

remove_stale_locks() {
    local removed='[]'

    for lf in "${LOCK_FILES[@]}"; do
        if [[ -f "$lf" ]]; then
            if ! fuser "$lf" >/dev/null 2>&1; then
                rm -f "$lf" 2>/dev/null && true || true
                local entry
                entry=$(jq -n --arg f "$lf" '{file:$f, action:"removed"}')
                removed=$(echo "$removed" | jq ". + [$entry]")
            fi
        fi
    done

    echo "$removed"
}

run_dpkg_configure() {
    local result
    local rc

    set +e
    env $APT_ENV dpkg --configure -a 2>&1
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        echo "OK"
    else
        echo "FAILED (exit code $rc)"
    fi
}

run_fix_broken() {
    local rc

    set +e
    env $APT_ENV apt-get --fix-broken install -y 2>&1
    rc=$?
    set -e

    if [[ $rc -eq 0 ]]; then
        echo "OK"
    else
        echo "FAILED (exit code $rc)"
    fi
}

rerun_dpkg_audit() {
    local audit
    audit=$(dpkg --audit 2>/dev/null || true)

    if [[ -z "$audit" ]]; then
        echo "clean"
    else
        echo "$audit"
    fi
}

# ============================================
# SERVICE RESTART FUNCTIONS
# ============================================

get_owning_package_for_service() {
    local service_name="$1"
    local pkg=""

    # Check service_dependency_map.json for linked_packages
    if [[ -f "$DEPS_MAP_FILE" ]]; then
        pkg=$(jq -r --arg svc "$service_name" \
            '.services[]? | select(.service == $svc) | .owning_package // empty' \
            "$DEPS_MAP_FILE" 2>/dev/null || echo "")

        if [[ -z "$pkg" ]]; then
            pkg=$(jq -r --arg svc "$service_name" \
                '.services[]? | select(.service == $svc) | .linked_packages[]? // empty' \
                "$DEPS_MAP_FILE" 2>/dev/null | head -1 || echo "")
        fi
    fi

    echo "$pkg"
}

restart_affected_services() {
    local broken_pkgs_str="$1"
    local results='[]'

    if [[ -z "$broken_pkgs_str" ]]; then
        echo "$results"
        return
    fi

    # Convert comma-separated list to newline-separated
    local broken_list
    broken_list=$(echo "$broken_pkgs_str" | tr ',' '\n')

    # Get services from dependency map that are linked to broken packages
    if [[ ! -f "$DEPS_MAP_FILE" ]]; then
        echo "$results"
        return
    fi

    local services_to_restart
    services_to_restart=$(jq -r '.services[]?.service' "$DEPS_MAP_FILE" 2>/dev/null | sort -u || echo '')

    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        [[ "$svc" == "(kernel-wide)" ]] && continue
        [[ "$svc" == "(system-wide)" ]] && continue

        # Check if this service's owning package or linked packages are in the broken set
        local owning_pkg
        owning_pkg=$(get_owning_package_for_service "$svc")

        local should_restart=false

        if [[ -n "$owning_pkg" ]] && echo "$broken_list" | grep -qx "$owning_pkg"; then
            should_restart=true
        fi

        if [[ "$should_restart" == "false" ]] && [[ -f "$DEPS_MAP_FILE" ]]; then
            local linked_pkgs
            linked_pkgs=$(jq -r --arg svc "$svc" \
                '.services[]? | select(.service == $svc) | .linked_packages[]?' \
                "$DEPS_MAP_FILE" 2>/dev/null || echo '')

            while IFS= read -r lpkg; do
                [[ -z "$lpkg" ]] && continue
                if echo "$broken_list" | grep -qx "$lpkg"; then
                    should_restart=true
                    break
                fi
            done <<< "$linked_pkgs"
        fi

        if [[ "$should_restart" == "true" ]]; then
            info "$(printf '%-40s' "${svc}")"

            set +e
            systemctl try-restart "$svc" >/dev/null 2>&1
            local r_rc=$?
            set -e

            local active_state
            active_state=$(systemctl show "$svc" --property=ActiveState --value 2>/dev/null || echo "unknown")

            info "$active_state"

            local entry
            entry=$(jq -n --arg svc "$svc" --arg state "$active_state" --argjson rc "$r_rc" \
                '{service:$svc, active_state:$state, exit_code:$rc}')
            results=$(echo "$results" | jq ". + [$entry]")
        fi

    done <<< "$services_to_restart"

    echo "$results"
}

# ============================================
# MAIN
# ============================================

main() {
    trap 'true' ERR

    log "Diagnosing..."

    local start_time
    start_time=$(date +%s)

    # ============================================
    # STEP 1: DIAGNOSE
    # ============================================
    local live_procs
    live_procs=$(check_live_processes || true)

    local stale_locks
    stale_locks=$(check_lock_files)

    local audit_output
    audit_output=$(run_dpkg_audit)

    local broken_pkgs
    broken_pkgs=$(get_broken_packages)

    local free_space
    free_space=$(check_free_space)

    # Print diagnosis to console
    info "live dpkg/apt processes: ${live_procs:-none}"
    info "stale locks: ${stale_locks:-none}"

    # Format audit output for display
    local audit_display
    if [[ -n "$audit_output" ]]; then
        audit_display=$(echo "$audit_output" | grep -oE '^[a-zA-Z0-9][a-zA-Z0-9.+~-]*' | sort -u | tr '\n' ', ' | sed 's/,$//')
    else
        audit_display="clean"
    fi
    info "dpkg --audit: ${audit_display}"

    local broken_count
    if [[ -n "$broken_pkgs" ]]; then
        broken_count=$(echo "$broken_pkgs" | tr ',' '\n' | wc -l)
    else
        broken_count=0
        broken_pkgs=""
    fi
    info "broken packages: ${broken_count}"

    # Build initial diagnosis JSON
    local initial_diagnosis
    initial_diagnosis=$(jq -n \
        --arg live_procs "${live_procs:-none}" \
        --arg stale_locks "${stale_locks:-none}" \
        --arg audit "${audit_output:-clean}" \
        --arg broken "${broken_pkgs:-none}" \
        --argjson broken_count "$broken_count" \
        --argjson free_space "$free_space" \
        '{
            live_processes: $live_procs,
            stale_locks: $stale_locks,
            dpkg_audit: $audit,
            broken_packages: $broken,
            broken_count: $broken_count,
            free_space: $free_space
        }')

    # ============================================
    # STEP 2: REFUSE IF LIVE PROCESSES DETECTED
    # ============================================
    if [[ -n "$live_procs" ]]; then
        warn "Live dpkg/apt processes detected. Refusing to proceed."
        local end_time_refuse
        end_time_refuse=$(date +%s)
        local duration_refuse=$((end_time_refuse - start_time))

        jq -n \
            --argjson diagnosis "$initial_diagnosis" \
            --argjson duration "$duration_refuse" \
            '{
                initial_diagnosis: $diagnosis,
                actions_taken: [],
                final_state: "refused_live_processes",
                recovered: false,
                duration_seconds: $duration
            }' > "$OUTPUT_FILE"

        log "Report saved to: $OUTPUT_FILE"
        exit 2
    fi

    # ============================================
    # STEP 3: REPAIR IN STRICT ORDER
    # ============================================
    log "Repairing..."

    local actions_taken='[]'

    # Action 1: Remove stale lock files
    info "$(printf '%-40s' 'remove stale locks')"
    local lock_action_result
    lock_action_result=$(remove_stale_locks)
    echo "OK"

    local action1
    action1=$(jq -n --arg desc "remove stale locks" --arg result "OK" --argjson locks "$lock_action_result" \
        '{step:1, action:$desc, result:$result, locks:$locks}')
    actions_taken=$(echo "$actions_taken" | jq ". + [$action1]")

    # Action 2: dpkg --configure -a
    info "$(printf '%-40s' 'dpkg --configure -a')"
    local configure_result
    configure_result=$(run_dpkg_configure)
    echo "$configure_result"

    local action2
    action2=$(jq -n --arg desc "dpkg --configure -a" --arg result "$configure_result" \
        '{step:2, action:$desc, result:$result}')
    actions_taken=$(echo "$actions_taken" | jq ". + [$action2]")

    # Action 3: apt-get --fix-broken install
    info "$(printf '%-40s' 'apt-get --fix-broken install')"
    local fix_result
    fix_result=$(run_fix_broken)
    echo "$fix_result"

    local action3
    action3=$(jq -n --arg desc "apt-get --fix-broken install" --arg result "$fix_result" \
        '{step:3, action:$desc, result:$result}')
    actions_taken=$(echo "$actions_taken" | jq ". + [$action3]")

    # Action 4: Re-run dpkg --audit
    info "$(printf '%-40s' 'dpkg --audit (re-run)')"
    local final_audit
    final_audit=$(rerun_dpkg_audit)
    echo "$final_audit"

    local action4
    action4=$(jq -n --arg desc "dpkg --audit (re-run)" --arg result "$final_audit" \
        '{step:4, action:$desc, result:$result}')
    actions_taken=$(echo "$actions_taken" | jq ". + [$action4]")

    # ============================================
    # STEP 4: RESTART AFFECTED SERVICES
    # ============================================
    log "Restarting affected services..."

    local service_results
    service_results=$(restart_affected_services "$broken_pkgs")

    # ============================================
    # STEP 5: DETERMINE FINAL STATE
    # ============================================
    local recovered=false
    local final_state=""

    if [[ "$final_audit" == "clean" ]]; then
        recovered=true
        final_state="clean"
    else
        recovered=false
        final_state="residual_breakage"
    fi

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # ============================================
    # STEP 6: EMIT apt_recovery.json
    # ============================================
    # Build final JSON using temp file for actions to avoid ARG_MAX
    local actions_temp
    actions_temp=$(mktemp)
    echo "$actions_taken" > "$actions_temp"

    cat "$actions_temp" | jq \
        --argjson diagnosis "$initial_diagnosis" \
        --arg final_state "$final_state" \
        --argjson recovered "$recovered" \
        --argjson duration "$duration" \
        --argjson services "$service_results" \
        '{
            initial_diagnosis: $diagnosis,
            actions_taken: .,
            final_state: $final_state,
            recovered: $recovered,
            duration_seconds: $duration,
            service_restarts: $services
        }' > "$OUTPUT_FILE"

    rm -f "$actions_temp"

    # Print summary
    if [[ "$recovered" == "true" ]]; then
        echo "RECOVERED: yes"
    else
        echo "RECOVERED: no"
    fi
    echo "Duration: ${duration}s"
    log "Report saved to: $OUTPUT_FILE"

    if [[ "$recovered" == "true" ]]; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
