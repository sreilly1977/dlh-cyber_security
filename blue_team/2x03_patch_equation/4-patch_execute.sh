#!/bin/bash
#
# Name:        4-patch_execute.sh
# Purpose:     Execute patch plan safely with pre/post checks and structured logging
#              Captures installed version and service states before and after each patch
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly PLAN_FILE="${BASE_DIR}/patch_plan.json"
readonly LOCK_FILE="/var/lock/meddefense-patch.lock"
readonly OUTPUT_FILE="${BASE_DIR}/patch_execution_log.json"
readonly DPKG_LOCK_WAIT=120
readonly APT_ENV="DEBIAN_FRONTEND=noninteractive"

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

LOCK_FD=200

cleanup_lock() {
    exec {LOCK_FD}>&- 2>/dev/null || true
    flock -u "$LOCK_FD" 2>/dev/null || true
    rm -f "$LOCK_FILE" 2>/dev/null || true
}

acquire_lock() {
    log "Acquiring lock ${LOCK_FILE}..."

    eval "exec ${LOCK_FD}>\"$LOCK_FILE\"" || {
        log "ERROR: Cannot create lock file"
        exit 2
    }

    if flock -n "$LOCK_FD"; then
        echo "  OK"
    else
        local waited=0
        while true; do
            if flock -w 5 "$LOCK_FD" 2>/dev/null; then
                echo "  OK (after ${waited}s wait)"
                return 0
            fi
            waited=$((waited + 5))
            if [[ $waited -ge 120 ]]; then
                log "ERROR: Could not acquire lock after 120 seconds"
                exit 2
            fi
            warn "Waiting for lock... (${waited}s elapsed)"
        done
    fi
}

# Handle busy dpkg lock: on "E: Could not get lock", wait with exponential backoff
wait_for_dpkg_lock() {
    local waited=0
    local backoff=1

    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [[ $waited -ge $DPKG_LOCK_WAIT ]]; then
            warn "E: Could not get lock /var/lib/dpkg/lock-frontend after ${DPKG_LOCK_WAIT}s"
            return 1
        fi
        sleep "$backoff"
        waited=$((waited + backoff))
        backoff=$((backoff * 2))
        [[ $backoff -gt 30 ]] && backoff=30
    done
    return 0
}

get_package_version() {
    local package="$1"
    dpkg-query -W -f='${Version}' "$package" 2>/dev/null || echo "not-installed"
}

# Get current state for a single service (active_state, sub_state, main_pid)
get_service_state() {
    local service="$1"
    local active sub pid

    active=$(systemctl show "$service" --property=ActiveState --value 2>/dev/null || echo "unknown")
    sub=$(systemctl show "$service" --property=SubState --value 2>/dev/null || echo "unknown")
    pid=$(systemctl show "$service" --property=MainPID --value 2>/dev/null || echo "0")

    jq -n --arg s "$service" --arg a "$active" --arg b "$sub" --arg p "$pid" \
        '{service:$s,active_state:$a,sub_state:$b,main_pid:$p}'
}

# Capture service states array for all linked services (pre or post snapshot)
capture_service_states() {
    local services_json="$1"
    local states='[]'
    local count

    count=$(echo "$services_json" | jq 'length' 2>/dev/null || echo 0)
    [[ "$count" -eq 0 ]] && { echo '[]'; return; }

    while IFS= read -r svc; do
        [[ -z "$svc" || "$svc" == "(kernel-wide)" || "$svc" == "(system-wide)" ]] && continue
        local st
        st=$(get_service_state "$svc")
        states=$(echo "$states" | jq ". + [$st]")
    done < <(echo "$services_json" | jq -r '.[]')

    echo "$states"
}

write_tail_file() {
    local src="$1"
    local dst="$2"
    if [[ -f "$src" ]]; then
        tail -20 "$src" > "$dst" 2>/dev/null || printf '' > "$dst"
    else
        printf '' > "$dst"
    fi
}

execute_patch_entry() {
    local entry_json="$1"
    local rank="$2"
    local total="$3"
    local result_file="$4"

    local package bucket score affected_services requires_restart requires_reboot rollback_version
    package=$(echo "$entry_json" | jq -r '.package')
    bucket=$(echo "$entry_json" | jq -r '.bucket')
    score=$(echo "$entry_json" | jq -r '.score')
    affected_services=$(echo "$entry_json" | jq -c '.affected_services // []')
    requires_restart=$(echo "$entry_json" | jq -r '.requires_restart // false')
    requires_reboot=$(echo "$entry_json" | jq -r '.requires_reboot // false')
    rollback_version=$(echo "$entry_json" | jq -r '.rollback_target_version // ""')

    printf '[%d/%d] %-30s %-12s' "$rank" "$total" "$package" "$bucket"

    # Record PRE state: installed version and service states for linked services
    local pre_version pre_service_states pre_block
    pre_version=$(get_package_version "$package")
    pre_service_states=$(capture_service_states "$affected_services")
    pre_block=$(jq -n --arg v "$pre_version" --argjson s "$pre_service_states" \
        '{installed_version:$v,service_states:$s}')

    # Wait for dpkg lock (handles "E: Could not get lock" with exponential backoff)
    if ! wait_for_dpkg_lock; then
        echo " FAILED (dpkg lock busy)"
        jq -n --arg p "$package" --arg b "$bucket" --argjson sc "$score" \
            --argjson pr "$pre_block" --arg r "dpkg lock busy after 120s" \
            '{package:$p,bucket:$b,score:$sc,status:"failed",reason:$r,pre:$pr,post:null,duration_seconds:0,stdout_tail:"",stderr_tail:$r,service_restarts:[],rollback_target_version:""}' \
            > "$result_file" || echo '{"status":"failed"}' > "$result_file"
        return 1
    fi

    # Execute patch
    local start_time end_time duration apt_rc
    start_time=$(date +%s)

    local apt_stdout_file apt_stderr_file
    apt_stdout_file=$(mktemp)
    apt_stderr_file=$(mktemp)

    set +e
    env $APT_ENV apt-get install --only-upgrade -y "$package" >"$apt_stdout_file" 2>"$apt_stderr_file"
    apt_rc=$?
    set -e

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    # Record POST state: installed version and service states for linked services
    local post_version post_service_states post_block
    post_version=$(get_package_version "$package")
    post_service_states=$(capture_service_states "$affected_services")
    post_block=$(jq -n --arg v "$post_version" --argjson s "$post_service_states" \
        '{installed_version:$v,service_states:$s}')

    # Create tail files (last 20 lines) for jq --rawfile
    local stdout_tail_file stderr_tail_file
    stdout_tail_file=$(mktemp)
    stderr_tail_file=$(mktemp)
    write_tail_file "$apt_stdout_file" "$stdout_tail_file"
    write_tail_file "$apt_stderr_file" "$stderr_tail_file"

    rm -f "$apt_stdout_file" "$apt_stderr_file"

    local status="success"
    [[ $apt_rc -ne 0 ]] && status="failed"

    if [[ "$status" == "success" ]]; then
        printf ' apt-get ... OK (%ds)\n' "$duration"
    else
        printf ' apt-get ... FAILED (%ds)\n' "$duration"
    fi

    # Service restarts when required and no reboot needed
    local restart_results='[]'
    if [[ "$status" == "success" && "$requires_restart" == "true" && "$requires_reboot" == "false" ]]; then
        local svc_count
        svc_count=$(echo "$affected_services" | jq 'length' 2>/dev/null || echo 0)

        if [[ "$svc_count" -gt 0 ]]; then
            while IFS= read -r svc; do
                [[ -z "$svc" || "$svc" == "(kernel-wide)" || "$svc" == "(system-wide)" ]] && continue

                printf '      try-restart %-30s' "$svc"

                set +e
                systemctl try-restart "$svc" >/dev/null 2>&1
                local r_rc=$?
                set -e

                local r_state
                r_state=$(systemctl show "$svc" --property=ActiveState --value 2>/dev/null || echo "unknown")

                if [[ $r_rc -eq 0 ]]; then
                    echo " OK"
                else
                    echo " FAILED"
                fi

                local rs_entry
                rs_entry=$(jq -n --arg s "$svc" --argjson rc "$r_rc" --arg st "$r_state" \
                    '{service:$s,result:(if $rc==0 then "OK" else "FAILED" end),active_state_after:$st}')
                restart_results=$(echo "$restart_results" | jq ". + [$rs_entry]")
            done < <(echo "$affected_services" | jq -r '.[]')
        fi
    fi

    # Write result using --rawfile for stdout/stderr tails (avoids arg list too long)
    jq -n --arg pkg "$package" --arg bkt "$bucket" --argjson sc "$score" \
        --arg stat "$status" --argjson pr "$pre_block" --argjson po "$post_block" \
        --argjson dur "$duration" \
        --rawfile out "$stdout_tail_file" \
        --rawfile err "$stderr_tail_file" \
        --argjson rst "$restart_results" --arg rb "$rollback_version" --argjson rc "$apt_rc" \
        '{package:$pkg,bucket:$bkt,score:$sc,status:$stat,apt_exit_code:$rc,pre:$pr,post:$po,duration_seconds:$dur,stdout_tail:$out,stderr_tail:$err,service_restarts:$rst,rollback_target_version:$rb}' \
        > "$result_file" || echo '{"status":"failed"}' > "$result_file"

    rm -f "$stdout_tail_file" "$stderr_tail_file"

    return $apt_rc
}

main() {
    trap cleanup_lock EXIT INT TERM

    log "Starting patch execution..."

    [[ ! -f "$PLAN_FILE" ]] && { log "ERROR: Patch plan not found: $PLAN_FILE"; exit 1; }

    acquire_lock

    local plan_count
    plan_count=$(jq '.plan | length' "$PLAN_FILE" 2>/dev/null || echo 0)
    log "Loading plan: $PLAN_FILE (${plan_count} entries)"

    if [[ "$plan_count" -eq 0 ]]; then
        local ts_start ts_end hostname_val plan_hash
        ts_start=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        ts_end=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        hostname_val=$(hostname 2>/dev/null || echo "unknown")
        plan_hash=$(sha256sum "$PLAN_FILE" | awk '{print $1}')

        jq -n --arg st "$ts_start" --arg en "$ts_end" --arg h "$hostname_val" --arg ph "$plan_hash" \
            '{started_at:$st,finished_at:$en,hostname:$h,plan_source_hash:$ph,entries:[]}' \
            > "$OUTPUT_FILE"

        log "No patches applied. Log saved to: $OUTPUT_FILE"
        exit 0
    fi

    local started_at hostname_val plan_hash
    started_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    hostname_val=$(hostname 2>/dev/null || echo "unknown")
    plan_hash=$(sha256sum "$PLAN_FILE" | awk '{print $1}')

    declare -a result_files=()
    local succeeded=0 failed=0

    while IFS= read -r entry_json; do
        [[ -z "$entry_json" ]] && continue

        local rank result_file
        rank=$(echo "$entry_json" | jq -r '.rank')
        result_file=$(mktemp)

        execute_patch_entry "$entry_json" "$rank" "$plan_count" "$result_file" || true

        local entry_status
        entry_status=$(jq -r '.status // "unknown"' "$result_file" 2>/dev/null || echo "unknown")

        if [[ "$entry_status" == "success" ]]; then
            succeeded=$((succeeded + 1))
        else
            failed=$((failed + 1))
            warn "Patch failed for $(jq -r '.package // "unknown"' "$result_file" 2>/dev/null || echo 'unknown'). Stopping execution."
        fi

        result_files+=("$result_file")
        [[ "$entry_status" != "success" ]] && break

    done < <(jq -c '.plan[]' "$PLAN_FILE" 2>/dev/null)

    # Build entries array - validate each file, use --slurpfile to avoid arg limits
    local entries_json='[]'
    if [[ ${#result_files[@]} -gt 0 ]]; then
        local valid_files=()
        for rf in "${result_files[@]}"; do
            if [[ -f "$rf" ]] && jq -e . "$rf" >/dev/null 2>&1; then
                valid_files+=("$rf")
            else
                echo '{"status":"failed"}' > "$rf"
                valid_files+=("$rf")
            fi
        done
        entries_json=$(jq -s '.' "${valid_files[@]}" 2>/dev/null || echo '[]')
    fi

    local finished_at
    finished_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Use a temp file for the final output to handle large entries_json
    local final_temp
    final_temp=$(mktemp)

    echo "$entries_json" | jq \
        --arg st "$started_at" --arg fn "$finished_at" --arg h "$hostname_val" \
        --arg ph "$plan_hash" --argjson s "$succeeded" --argjson f "$failed" \
        '{started_at:$st,finished_at:$fn,hostname:$h,plan_source_hash:$ph,entries:.,summary:{total_attempted:(.|length),succeeded:$s,failed:$f}}' \
        > "$final_temp" || echo '{"started_at":"","finished_at":"","hostname":"error","plan_source_hash":"","entries":[],"summary":{"total_attempted":0,"succeeded":0,"failed":0}}' > "$final_temp"

    mv "$final_temp" "$OUTPUT_FILE"

    for rf in "${result_files[@]}"; do
        rm -f "$rf"
    done

    echo "Succeeded: ${succeeded}  Failed: ${failed}"
    log "Log saved to: $OUTPUT_FILE"

    [[ $failed -gt 0 ]] && exit 1
    exit 0
}

main "$@"
