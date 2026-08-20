#!/bin/bash
#
# Name: 1-baseline_snapshot.sh
# Purpose: Run lynis baseline audit and persist raw output + hardening score
#          Capstone task T1 - Defensible Endpoint Package
# Author: Steve - Cybersecurity Engineer
# Date: 20 August 2026
# Exit Codes: 0=success, 1=controlled failure, 2=environment error
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
readonly BASELINE_DIR="${SCRIPT_DIR}/capstone/baseline"
readonly LOG_FILE="${BASELINE_DIR}/lynis_baseline.log"
readonly JSON_FILE="${BASELINE_DIR}/baseline_linux.json"

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

validate_environment() {
    log_info "Validating execution environment..."

    if ! command -v lynis >/dev/null 2>&1; then
        log_error "lynis is not installed - required for the baseline audit"
        exit 2
    fi

    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is not installed - required for JSON output"
        exit 2
    fi

    log_info "Environment validation complete"
}

ensure_directories() {
    log_info "Creating baseline directory structure..."

    mkdir -p "$BASELINE_DIR" || {
        log_error "Failed to create baseline directory: $BASELINE_DIR"
        exit 2
    }

    chmod 755 "$BASELINE_DIR" || {
        log_error "Failed to set permissions on baseline directory"
        exit 1
    }

    log_info "Directory ready: $BASELINE_DIR"
}

run_baseline_audit() {
    log_info "Running lynis audit system --quick --no-colors..."

    if ! lynis audit system --quick --no-colors > "$LOG_FILE" 2>&1; then
        log_error "Lynis audit returned a non-zero exit code"
        exit 1
    fi

    if [[ ! -s "$LOG_FILE" ]]; then
        log_error "Lynis log is empty - audit did not produce output"
        exit 1
    fi

    log_info "Raw log persisted: $LOG_FILE"
}

write_baseline_record() {
    log_info "Parsing lynis output and writing baseline_linux.json..."

    local hostname_val lynis_version hardening_index warnings_count suggestions_count

    hostname_val="$(hostname 2>/dev/null || echo "unknown")"

    lynis_version="$(grep -E 'Program version' "$LOG_FILE" | awk '{print $NF}' | head -n 1 || true)"
    if [[ -z "$lynis_version" ]]; then
        lynis_version="$(grep -oE 'Lynis [0-9]+\.[0-9]+(\.[0-9]+)?' "$LOG_FILE" | head -n 1 | awk '{print $2}' || true)"
    fi
    if [[ -z "$lynis_version" ]]; then
        lynis_version="unknown"
    fi

    hardening_index="$(grep -E 'Hardening index' "$LOG_FILE" | grep -Eo '[0-9]+' | head -n 1 || true)"
    if ! [[ "$hardening_index" =~ ^[0-9]+$ ]]; then
        log_error "Could not parse Hardening index from lynis output"
        exit 1
    fi

    warnings_count="$(grep -cE '^\s*!.*\[[A-Z]' "$LOG_FILE" || true)"
    if ! [[ "$warnings_count" =~ ^[0-9]+$ ]]; then
        warnings_count=0
    fi

    suggestions_count="$(grep -cE '^\s*\*.*\[[A-Z]' "$LOG_FILE" || true)"
    if ! [[ "$suggestions_count" =~ ^[0-9]+$ ]]; then
        suggestions_count=0
    fi

    if ! jq -n \
        --arg ts "$TIMESTAMP" \
        --arg hn "$hostname_val" \
        --arg lv "$lynis_version" \
        --argjson hi "$hardening_index" \
        --argjson wc "$warnings_count" \
        --argjson sc "$suggestions_count" \
        --arg lp "$LOG_FILE" \
        '{
            timestamp: $ts,
            hostname: $hn,
            lynis_version: $lv,
            hardening_index: $hi,
            warnings_count: $wc,
            suggestions_count: $sc,
            log_path: $lp
        }' > "$JSON_FILE"; then
        log_error "Failed to write valid JSON to $JSON_FILE"
        exit 1
    fi

    log_info "Baseline record written: $JSON_FILE"
    log_info "Hardening index: $hardening_index (warnings: $warnings_count, suggestions: $suggestions_count)"
}

main() {
    log_info "Starting capstone baseline snapshot for Hawthorne Linux endpoint..."
    log_info "Timestamp: $TIMESTAMP"

    validate_environment
    ensure_directories
    run_baseline_audit
    write_baseline_record

    log_info "Baseline snapshot completed successfully"
    exit 0
}

main "$@"
