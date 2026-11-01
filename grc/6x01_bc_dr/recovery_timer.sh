#!/bin/bash
# Name: recovery_timer.sh
# Purpose: Timestamp each LIS recovery test step, record per-step durations and
#          PASS/FAIL outcomes to recovery_test_log.txt as steps complete, keep
#          run state in /tmp/rtest_state, and report total elapsed time against
#          the declared 30-minute RTO when called with SUMMARY.
# Author: Steve - Cybersecurity Engineer
# Date: 2026-11-01

set -u

STATE_DIR="/tmp/rtest_state"
LOG_FILE="recovery_test_log.txt"
RTO_SECONDS=1800

usage() {
    echo "Usage: $0 \"Step name\" START|PASS|FAIL"
    echo "       $0 SUMMARY"
    exit 1
}

init_state() {
    mkdir -p "$STATE_DIR"
    [ -f "$STATE_DIR/test_start_epoch" ] || date +%s > "$STATE_DIR/test_start_epoch"
    [ -f "$STATE_DIR/step_counter" ] || echo 0 > "$STATE_DIR/step_counter"
}

now_epoch() {
    date +%s
}

start_step() {
    local step_name="$1"
    local counter
    counter=$(( $(cat "$STATE_DIR/step_counter") + 1 ))
    echo "$counter" > "$STATE_DIR/step_counter"
    printf '%s\n' "$step_name" > "$STATE_DIR/current_step"
    printf '%s\n' "$(now_epoch)" > "$STATE_DIR/current_start_epoch"
    date '+%H:%M:%S' > "$STATE_DIR/current_start_fmt"
    printf 'Started [STEP %02d] %s at %s\n' "$counter" "$step_name" "$(cat "$STATE_DIR/current_start_fmt")"
}

end_step() {
    local step_name="$1"
    local status="$2"
    if [ ! -f "$STATE_DIR/current_step" ]; then
        echo "Error: no step currently in progress." >&2
        exit 1
    fi
    local open_step
    open_step=$(cat "$STATE_DIR/current_step")
    if [ "$open_step" != "$step_name" ]; then
        echo "Warning: closing step '$step_name' but open step is '$open_step'." >&2
    fi
    local step_number start_epoch end_epoch elapsed mins secs start_fmt end_fmt
    step_number=$(cat "$STATE_DIR/step_counter")
    start_epoch=$(cat "$STATE_DIR/current_start_epoch")
    start_fmt=$(cat "$STATE_DIR/current_start_fmt")
    end_epoch=$(now_epoch)
    end_fmt=$(date '+%H:%M:%S')
    elapsed=$(( end_epoch - start_epoch ))
    mins=$(( elapsed / 60 ))
    secs=$(( elapsed % 60 ))
    printf '[STEP %02d] %-36s | Start: %s | End: %s | Duration: %dm %ds | %s\n' \
        "$step_number" "$step_name" "$start_fmt" "$end_fmt" "$mins" "$secs" "$status" >> "$LOG_FILE"
    printf '[STEP %02d] %-36s | Start: %s | End: %s | Duration: %dm %ds | %s\n' \
        "$step_number" "$step_name" "$start_fmt" "$end_fmt" "$mins" "$secs" "$status"
    rm -f "$STATE_DIR/current_step" "$STATE_DIR/current_start_epoch" "$STATE_DIR/current_start_fmt"
}

run_summary() {
    local start_epoch total mins secs pass_count fail_count verdict
    start_epoch=$(cat "$STATE_DIR/test_start_epoch")
    total=$(( $(now_epoch) - start_epoch ))
    mins=$(( total / 60 ))
    secs=$(( total % 60 ))
    pass_count=$(grep -c '| PASS$' "$LOG_FILE" 2>/dev/null || true)
    fail_count=$(grep -c '| FAIL$' "$LOG_FILE" 2>/dev/null || true)
    if [ "$total" -le "$RTO_SECONDS" ]; then
        verdict="PASS (within 30-minute RTO)"
    else
        verdict="FAIL (exceeded 30-minute RTO)"
    fi
    printf 'SUMMARY | Total elapsed: %dm %ds | Steps passed: %s | Steps failed: %s | RTO verdict: %s\n' \
        "$mins" "$secs" "${pass_count:-0}" "${fail_count:-0}" "$verdict"
    if [ ! -f "$STATE_DIR/summary_written" ]; then
        printf 'SUMMARY | Total elapsed: %dm %ds | Steps passed: %s | Steps failed: %s | RTO verdict: %s\n' \
            "$mins" "$secs" "${pass_count:-0}" "${fail_count:-0}" "$verdict" >> "$LOG_FILE"
        touch "$STATE_DIR/summary_written"
    fi
}

if [ $# -eq 0 ]; then
    usage
fi

init_state

if [ "$1" = "SUMMARY" ]; then
    run_summary
    exit 0
fi

if [ $# -ne 2 ]; then
    usage
fi

case "$2" in
    START)
        start_step "$1"
        ;;
    PASS|FAIL)
        end_step "$1" "$2"
        ;;
    *)
        usage
        ;;
esac
