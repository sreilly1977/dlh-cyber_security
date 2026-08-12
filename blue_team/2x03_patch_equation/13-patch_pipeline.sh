#!/bin/bash
#
# Name:        13-patch_pipeline.sh
# Purpose:     Orchestrate the full end-to-end patch workflow, chaining all
#              preceding tasks into a single idempotent pipeline
# Author:      Steve - Cybersecurity Engineer
# Date:        August 12, 2026
#
# In emergency mode (override window check):
# sudo MEDDEFENSE_EMERGENCY=1 ./13-patch_pipeline.sh
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly OUTPUT_FILE="${BASE_DIR}/pipeline_run.json"

log() {
    echo "[*] $*"
}

info() {
    echo "    $*"
}

warn() {
    echo "[!] $*" >&2
}

# ============================================
# PIPELINE STAGE DEFINITIONS
# ============================================
# Each stage: script|description|artifact_path|artifact_optional
readonly STAGES=(
    "0-vuln_inventory.sh|Vulnerability Inventory|vulnerability_inventory.json"
    "1-service_deps.sh|Service Dependencies|service_dependency_map.json"
    "2-pre_patch_snapshot.sh|Pre-Patch Snapshot|pre_patch_state.json"
    "3-patch_plan.sh|Patch Plan|patch_plan.json"
    "11-maintenance_window.sh|Maintenance Window Check|maintenance_window.json"
    "4-patch_execute.sh|Patch Execution|patch_execution_log.json"
    "5-post_patch_validate.sh|Post-Patch Validation|post_patch_validation.json"
    "6-config_drift.sh|Config Drift Detection|config_drift.json"
    "12-change_log.sh|Change Tracking Log|patch_change_log.json"
)

# Stages to skip when deferred (indices 6, 7, 8 = patch_execute, validate, drift)
readonly DEFER_SKIP_START=6
readonly DEFER_SKIP_END=8

# ============================================
# RUN A SINGLE STAGE
# ============================================
run_stage() {
    local script="$1"
    local description="$2"
    local artifact="$3"
    local stage_num="$4"
    local total_stages="$5"
    local extra_args="${6:-}"

    local script_path="${BASE_DIR}/${script}"
    local stage_label="$(printf '[%d/%d] %s' "$stage_num" "$total_stages" "$script")"

    # Check script exists
    if [[ ! -f "$script_path" ]]; then
        printf "%-40s MISSING\n" "$stage_label" >&2
        warn "Stage script not found: $script_path"
        echo "1|0|"
        return 0
    fi

    # Make sure it's executable
    chmod +x "$script_path" 2>/dev/null || true

    local stage_start
    stage_start=$(date +%s)

    # Capture stdout, stderr, and exit code separately
    local stdout_file stderr_file
    stdout_file=$(mktemp)
    stderr_file=$(mktemp)

    local exit_code=0

    set +e
    if [[ -n "$extra_args" ]]; then
        sudo -n bash -c "'$script_path' $extra_args" >"$stdout_file" 2>"$stderr_file"
        exit_code=$?
    else
        "$script_path" >"$stdout_file" 2>"$stderr_file"
        exit_code=$?
    fi
    set -e

    local stage_end
    stage_end=$(date +%s)
    local duration=$((stage_end - stage_start))

    local stdout_content stderr_content
    stdout_content=$(cat "$stdout_file" 2>/dev/null || echo "")
    stderr_content=$(cat "$stderr_file" 2>/dev/null || echo "")

    rm -f "$stdout_file" "$stderr_file"

    # Output the stage result to stderr (visible on screen, not captured by caller)
    local status_label
    if [[ $exit_code -eq 0 ]]; then
        status_label="OK"
    else
        status_label="FAIL"
    fi

    printf "%-40s %s  (%ds)\n" "$stage_label" "$status_label" "$duration" >&2

    # Return result via stdout (captured by caller)
    echo "${exit_code}|${duration}"
    return 0
}

# ============================================
# BUILD STAGE JSON ENTRY
# ============================================
build_stage_json() {
    local script="$1"
    local description="$2"
    local artifact="$3"
    local exit_code="$4"
    local duration="$5"
    local stdout_trunc="${6:-}"
    local stderr_trunc="${7:-}"
    local skipped="${8:-false}"

    local artifact_path="${BASE_DIR}/${artifact}"
    local artifact_exists=false

    if [[ -f "$artifact_path" ]]; then
        artifact_exists=true
    fi

    # Truncate stdout/stderr to first 500 chars for JSON
    stdout_trunc="${stdout_trunc:0:500}"
    stderr_trunc="${stderr_trunc:0:500}"

    jq -nc \
        --arg script "$script" \
        --arg description "$description" \
        --arg artifact "$artifact" \
        --argjson exit_code "$exit_code" \
        --argjson duration "$duration" \
        --arg stdout "$stdout_trunc" \
        --arg stderr "$stderr_trunc" \
        --argjson skipped "$skipped" \
        --argjson artifact_exists "$artifact_exists" \
        '{
            script: $script,
            description: $description,
            artifact: $artifact,
            exit_code: $exit_code,
            duration_seconds: $duration,
            skipped: $skipped,
            artifact_exists: $artifact_exists,
            stdout_tail: $stdout,
            stderr_tail: $stderr
        }'
}

# ============================================
# MAIN
# ============================================
main() {
    local pipeline_start
    pipeline_start=$(date +%s)
    local started_at
    started_at=$(date -u -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    local total_stages=${#STAGES[@]}
    log "Starting patch pipeline (${total_stages} stages)..."

    local stages_json_temp
    stages_json_temp=$(mktemp)

    local artifacts_temp
    artifacts_temp=$(mktemp)

    local pipeline_status="ok"
    local stage_num=0
    local deferred=false

    for stage_def in "${STAGES[@]}"; do
        stage_num=$((stage_num + 1))

        IFS='|' read -r script description artifact <<< "$stage_def"

        local extra_args=""

        # Special handling for maintenance window stage
        if [[ "$script" == "11-maintenance_window.sh" ]]; then
            extra_args="--check"
        fi

        # Check if we should skip this stage due to deferral
        if [[ "$deferred" == "true" ]]; then
            if [[ $stage_num -ge $DEFER_SKIP_START ]] && [[ $stage_num -le $DEFER_SKIP_END ]]; then
                info "$(printf '[%d/%d] %-40s SKIPPED (deferred)' "$stage_num" "$total_stages" "$script")"

                build_stage_json "$script" "$description" "$artifact" 0 0 "" "" true >> "$stages_json_temp"
                continue
            fi
        fi

                # Run the stage
        local stage_stdout stage_stderr
        local stdout_file stderr_file
        stdout_file=$(mktemp)
        stderr_file=$(mktemp)

        local stage_result
        stage_result=$(run_stage "$script" "$description" "$artifact" "$stage_num" "$total_stages" "$extra_args")
        local exit_code duration
        exit_code=$(echo "$stage_result" | cut -d'|' -f1)
        duration=$(echo "$stage_result" | cut -d'|' -f2)

        # Record artifact path
        jq -nc --arg stage "$script" --arg path "${BASE_DIR}/${artifact}" \
            '{stage:$stage, path:$path}' >> "$artifacts_temp"

        build_stage_json "$script" "$description" "$artifact" "$exit_code" "$duration" "" "" false >> "$stages_json_temp"

        # Handle maintenance window exit codes
        if [[ "$script" == "11-maintenance_window.sh" ]]; then
            if [[ $exit_code -eq 20 ]]; then
                # Out of window — check for emergency override
                if [[ -z "${MEDDEFENSE_EMERGENCY:-}" ]]; then
                    log "Outside maintenance window. Deferring patch execution stages."
                    deferred=true
                    pipeline_status="deferred"
                else
                    log "Outside maintenance window but MEDDEFENSE_EMERGENCY is set. Proceeding."
                fi
            elif [[ $exit_code -eq 10 ]]; then
                # Emergency only — requires override
                if [[ -z "${MEDDEFENSE_EMERGENCY:-}" ]]; then
                    log "Emergency window only. MEDDEFENSE_EMERGENCY not set. Deferring."
                    deferred=true
                    pipeline_status="deferred"
                else
                    log "Emergency window active with override. Proceeding."
                fi
            elif [[ $exit_code -ne 0 ]]; then
                warn "Maintenance window check failed (exit ${exit_code}). Aborting pipeline."
                pipeline_status="failed"
                break
            fi
        elif [[ $exit_code -ne 0 ]]; then
            warn "Stage '${script}' failed (exit ${exit_code}). Aborting pipeline."
            pipeline_status="failed"
            break
        fi

    done

    local pipeline_end
    pipeline_end=$(date +%s)
    local total_duration=$((pipeline_end - pipeline_start))
    local finished_at
    finished_at=$(date -u -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')

    # ============================================
    # BUILD FINAL JSON REPORT
    # ============================================
    local stages_json
    if [[ -s "$stages_json_temp" ]]; then
        stages_json=$(jq -s '.' "$stages_json_temp" 2>/dev/null || echo '[]')
    else
        stages_json='[]'
    fi

    local artifacts_json
    if [[ -s "$artifacts_temp" ]]; then
        artifacts_json=$(jq -s '.' "$artifacts_temp" 2>/dev/null || echo '[]')
    else
        artifacts_json='[]'
    fi

    # Transform artifacts array into a map (stage -> path)
    local artifacts_map
    artifacts_map=$(echo "$artifacts_json" | jq 'map({(.stage): .path}) | add // {}' 2>/dev/null || echo '{}')

    jq -n \
        --arg started_at "$started_at" \
        --arg finished_at "$finished_at" \
        --arg hostname "$hostname_val" \
        --arg status "$pipeline_status" \
        --argjson duration "$total_duration" \
        --argjson stages "$stages_json" \
        --argjson artifacts "$artifacts_map" \
        '{
            started_at: $started_at,
            finished_at: $finished_at,
            hostname: $hostname,
            pipeline_status: $status,
            duration_seconds: $duration,
            stages: $stages,
            artifacts: $artifacts
        }' > "$OUTPUT_FILE"

    rm -f "$stages_json_temp" "$artifacts_temp"

    # ============================================
    # PRINT SUMMARY
    # ============================================
    echo "PIPELINE: ${pipeline_status}"
    echo "Duration: ${total_duration}s"
    log "Report saved to: $OUTPUT_FILE"

    # Exit codes: 0 for ok or deferred, 1 for failed
    if [[ "$pipeline_status" == "failed" ]]; then
        exit 1
    else
        exit 0
    fi
}

main "$@"
