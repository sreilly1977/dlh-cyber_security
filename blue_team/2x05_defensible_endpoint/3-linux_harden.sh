#!/bin/bash
#
# Name: 3-linux_harden.sh
# Purpose: Orchestrate full Linux hardening pass and persist execution evidence
#          Capstone task T3 - Defensible Endpoint Package
# Author: Steve - Cybersecurity Engineer
# Date: 20 August 2026
# Exit Codes: 0=success, 1=controlled failure, 2=environment error
#
# Outputs (relative to script directory):
#   capstone/exec/linux_harden.log        - step-by-step execution log
#   capstone/exec/linux_harden.json       - structured execution evidence
#

set -uo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
readonly CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
readonly EXEC_DIR="${CAPSTONE_DIR}/exec"
readonly HARDENING_SCRIPTS_DIR="${SCRIPT_DIR}/2x00_locking_the_gates"
readonly LOG_FILE="${EXEC_DIR}/linux_harden.log"
readonly JSON_FILE="${EXEC_DIR}/linux_harden.json"
readonly BASELINE_FILE="${CAPSTONE_DIR}/baseline/baseline_linux.json"
readonly TARGET_STATE_FILE="${CAPSTONE_DIR}/target_state.json"

readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
declare -a STEPS_JSON=()
declare -a CONTROLS_TOUCHED=()

cleanup() {
    local exit_code="$?"
    if [[ $exit_code -ne 0 ]]; then
        echo "[$SCRIPT_NAME] Script exited with code $exit_code" >&2
    fi
    exit "$exit_code"
}

trap cleanup EXIT

log_info() {
    echo "[$SCRIPT_NAME][INFO] $*" >&2
}

log_error() {
    echo "[$SCRIPT_NAME][ERROR] $*" >&2
}

log_step() {
    echo "[STEPS][$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$LOG_FILE"
}

validate_environment() {
    log_info "Validating execution environment..."

    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is not installed - required for JSON processing"
        exit 2
    fi

    if ! command -v lynis >/dev/null 2>&1; then
        log_error "lynis is not installed - required for hardening assessment"
        exit 2
    fi

    if [[ ! -f "$BASELINE_FILE" ]]; then
        log_error "Baseline file not found: $BASELINE_FILE - run T1 first"
        exit 2
    fi

    if [[ ! -f "$TARGET_STATE_FILE" ]]; then
        log_error "Target state not found: $TARGET_STATE_FILE - run T2 first"
        exit 2
    fi

    if [[ ! -d "$HARDENING_SCRIPTS_DIR" ]]; then
        log_error "Hardening scripts directory not found: $HARDENING_SCRIPTS_DIR"
        exit 2
    fi

    log_info "Environment validation complete"
}

ensure_directories() {
    log_info "Ensuring exec directory exists..."

    mkdir -p "$EXEC_DIR" || {
        log_error "Failed to create exec directory: $EXEC_DIR"
        exit 2
    }

    log_info "Directory ready: $EXEC_DIR"
}

run_harden_step() {
    local step_name="$1"
    local script_path="$2"
    local control_ids="$3"

    if [[ ! -f "$script_path" ]]; then
        log_error "Hardening script not found: $script_path"
        return 1
    fi

    log_step "Starting: $step_name - $script_path"
    local start_time
    start_time="$(date +%s.%N)"

    local output_file
    output_file="${EXEC_DIR}/${step_name}_output.txt"

    # Capture stdout and stderr of each sub-step
    local exit_code=0
    bash "$script_path" > "$output_file" 2>&1 || exit_code=$?

    local end_time
    end_time="$(date +%s.%N)"
    local duration
    duration="$(echo "$end_time - $start_time" | bc)"

    local changed="false"
    if [[ $exit_code -eq 0 && -s "$output_file" ]]; then
        changed="true"
    fi

    log_step "Completed: $step_name - exit_code=$exit_code duration=${duration}s"

    local step_json
    step_json="$(jq -n \
        --arg name "$step_name" \
        --arg path "$script_path" \
        --argjson exit_code "$exit_code" \
        --arg duration "$duration" \
        --argjson changed "$changed" \
        '{name: $name, script_path: $path, exit_code: $exit_code, duration_seconds: ($duration | tonumber), changed: $changed}')"

    STEPS_JSON+=("$step_json")
    CONTROLS_TOUCHED+=("$control_ids")

    if [[ $exit_code -ne 0 ]]; then
        log_error "Step failed: $step_name exit code $exit_code - see $output_file"
        return 1
    fi

    return 0
}

orchestrate_hardening() {
    log_info "Starting Linux hardening orchestration..."

    local all_success=true

    # SSH hardening - 4-ssh_hardening.sh
    if ! run_harden_step "ssh_hardening" \
        "$HARDENING_SCRIPTS_DIR/4-ssh_hardening.sh" \
        "LNX-SSH-01,LNX-SSH-02"; then
        all_success=false
    fi

    # Sysctl hardening - 5-sysctl_hardening.sh
    if ! run_harden_step "sysctl_hardening" \
        "$HARDENING_SCRIPTS_DIR/5-sysctl_hardening.sh" \
        "LNX-SYS-01,LNX-SYS-02"; then
        all_success=false
    fi

    # Filesystem permission hardening - 6-filesystem_hardening.sh
    if ! run_harden_step "filesystem_permission_hardening" \
        "$HARDENING_SCRIPTS_DIR/6-filesystem_hardening.sh" \
        "LNX-PER-01,LNX-PER-02"; then
        all_success=false
    fi

    # service minimization - 7-service_minimization.sh
    if ! run_harden_step "service_minimization" \
        "$HARDENING_SCRIPTS_DIR/7-service_minimization.sh" \
        "LNX-SVC-01"; then
        all_success=false
    fi

    # PAM hardening - 8-pam_hardening.sh
    if ! run_harden_step "pam_hardening" \
        "$HARDENING_SCRIPTS_DIR/8-pam_hardening.sh" \
        "LNX-PAM-01"; then
        all_success=false
    fi

    # AppArmor config - 9-apparmor_config.sh
    if ! run_harden_step "apparmor_config" \
        "$HARDENING_SCRIPTS_DIR/9-apparmor_config.sh" \
        "LNX-MAC-01"; then
        all_success=false
    fi

    # auditd config - 10-auditd_config.sh
    if ! run_harden_step "auditd_config" \
        "$HARDENING_SCRIPTS_DIR/10-auditd_config.sh" \
        "LNX-AUD-01,LNX-AUD-02"; then
        all_success=false
    fi

    if [[ "$all_success" != "true" ]]; then
        log_error "One or more hardening steps failed"
        return 1
    fi

    log_info "All hardening steps completed successfully"
    return 0
}

run_post_hardening_assessment() {
    local temp_log
    temp_log="$(mktemp)"

    if ! lynis audit system --quick --no-colors > "$temp_log" 2>&1; then
        rm -f "$temp_log"
        return 1
    fi

    local lynis_after
    lynis_after="$(grep -E 'Hardening index' "$temp_log" | grep -Eo '[0-9]+' | head -n 1 || echo "0")"

    rm -f "$temp_log"

    if ! [[ "$lynis_after" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    echo "$lynis_after"
}

read_baseline_index() {
    local lynis_before
    lynis_before="$(jq -r '.hardening_index' "$BASELINE_FILE" 2>/dev/null || echo "0")"

    if ! [[ "$lynis_before" =~ ^[0-9]+$ ]]; then
        lynis_before=0
    fi

    echo "$lynis_before"
}

read_target_index() {
    local target_index
    target_index="$(jq -r '.controls[] | select(.id == "LNX-LYN-01") | .expected_value' "$TARGET_STATE_FILE" 2>/dev/null || echo "80")"

    if ! [[ "$target_index" =~ ^[0-9]+$ ]]; then
        target_index=80
    fi

    echo "$target_index"
}

emit_execution_record() {
    log_info "Writing execution evidence to linux_harden.json..."

    local lynis_before
    lynis_before="$(read_baseline_index)"

    local lynis_after
    if ! lynis_after="$(run_post_hardening_assessment)"; then
        log_error "Failed to run post-hardening assessment"
        exit 1
    fi

    local target_index
    target_index="$(read_target_index)"

    local index_delta
    index_delta=$((lynis_after - lynis_before))

    local steps_array
    steps_array="$(printf '%s\n' "${STEPS_JSON[@]}" | jq -s '.')"

    local controls_string
    controls_string="$(printf '%s\n' "${CONTROLS_TOUCHED[@]}" | tr ',' '\n' | sort -u | grep -v '^$' || true)"
    local controls_array
    controls_array="$(echo "$controls_string" | jq -R . | jq -s '.' 2>/dev/null || echo "[]")"

    local hostname_val
    hostname_val="$(hostname 2>/dev/null || echo "unknown")"

    local record_json
    record_json="$(jq -n \
        --arg ts "$TIMESTAMP" \
        --arg hn "$hostname_val" \
        --argjson steps "$steps_array" \
        --argjson before "$lynis_before" \
        --argjson after "$lynis_after" \
        --argjson delta "$index_delta" \
        --argjson target "$target_index" \
        --argjson touched "$controls_array" \
        '{
            timestamp: $ts,
            hostname: $hn,
            steps: $steps,
            lynis_before: $before,
            lynis_after: $after,
            index_delta: $delta,
            target_hardening_index: $target,
            controls_touched: $touched,
            passed: ($after >= $target)
        }')"

    if ! echo "$record_json" | jq '.' > "$JSON_FILE" 2>/dev/null; then
        log_error "Failed to write valid JSON to $JSON_FILE"
        exit 1
    fi

    log_info "Execution evidence written: $JSON_FILE"
    log_info "Lynis delta: $lynis_before -> $lynis_after delta=$index_delta"
    log_info "Target: $target_index Passed: $([ "$lynis_after" -ge "$target_index" ] && echo "yes" || echo "no")"
    log_info "Controls touched: $(echo "$controls_array" | jq -r '. | length')"
    log_info "Record hash: $(sha256sum "$JSON_FILE" | cut -d' ' -f1)"
}

main() {
    log_info "Starting Linux hardening execution..."
    log_info "Timestamp: $TIMESTAMP"

    validate_environment
    ensure_directories

    local orchestration_failed=false
    orchestrate_hardening || orchestration_failed=true

    emit_execution_record

    if [[ "$orchestration_failed" == "true" ]]; then
        log_error "Hardening completed with failures - see $LOG_FILE and per-step output files"
        exit 1
    fi

    log_info "Linux hardening execution completed"
    exit 0
}

main "$@"
