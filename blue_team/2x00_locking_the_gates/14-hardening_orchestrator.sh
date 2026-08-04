#!/bin/bash

# 14-hardening_orchestrator.sh — Production Hardening Workflow Orchestrator
#                                  Executes hardening scripts in dependency order,
#                                  records timing/exit codes, captures Lynis delta.
#
# Addresses:
#   - Task dependencies and ordered execution
#   - Failure detection and rollback readiness
#   - Evidence collection for compliance audits
#
# Usage:  sudo ./14-hardening_orchestrator.sh
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_LOG_FILE="hardening_run.json"
IMPROVEMENT_FILE="hardening_improvement.json"
TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
WORKFLOW_START=$(date +%s)
WORKFLOW_END=""

# Find Lynis binary dynamically
LYNIS_BIN=$(which lynis 2>/dev/null || echo "/usr/sbin/lynis")

# Hardening scripts to execute (in dependency order) — including 15
STEPS=(
    "0-baseline_snapshot.sh"
    "2-lynis_parse.sh"
    "4-ssh_hardening.sh"
    "5-sysctl_hardening.sh"
    "6-filesystem_hardening.sh"
    "7-service_minimization.sh"
    "8-pam_hardening.sh"
    "9-apparmor_config.sh"
    "10-auditd_config.sh"
    "11-audit_coverage_test.sh"
    "12-log_config.sh"
    "13-firewall_baseline.sh"
    "15-validation.sh"
)

# Track results
declare -a STEP_RESULTS=()
STEPS_SCHEDULED=${#STEPS[@]}
STEPS_COMPLETED=0
STEPS_FAILED=0
PRE_LYNIS_SCORE="N/A"
POST_LYNIS_SCORE="N/A"
IDEMPOTENT_MODE=false

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "$s"
}

# Get Lynis score from output (parses various Lynis output formats)
get_lynis_score() {
    if [[ ! -f "$LYNIS_BIN" ]]; then
        printf '%s' "N/A"
        return
    fi

    local score_output

    # Run Lynis in audit system mode and extract the score
    score_output=$("$LYNIS_BIN" audit system 2>&1 | grep -iE "scores?|rating" | grep -oE '[0-9]+' | head -1) || true

    if [[ -n "$score_output" ]]; then
        printf '%s' "$score_output"
        return
    fi

    # Fallback: look in the Lynis report file if it exists
    local report_file="/var/log/lynis-report.dat"
    if [[ -f "$report_file" ]]; then
        score_output=$(grep "PHASE_END" "$report_file" 2>/dev/null | grep -oE 'score=[0-9]+' | cut -d= -f2) || true
        if [[ -n "$score_output" ]]; then
            printf '%s' "$score_output"
            return
        fi
    fi

    # Another fallback: check lynis.log
    if [[ -f "/var/log/lynis.log" ]]; then
        score_output=$(grep -i "scores" "/var/log/lynis.log" 2>/dev/null | grep -oE '[0-9]+' | head -1) || true
        if [[ -n "$score_output" ]]; then
            printf '%s' "$score_output"
            return
        fi
    fi

    printf '%s' "N/A"
}

# Run a single step and track timing/result
run_step() {
    local step_name="$1"
    local step_path="$SCRIPT_DIR/$step_name"
    local step_num

    # Extract step number from filename
    step_num=$(printf '%s' "$step_name" | grep -oE '^[0-9]+' || echo "0")

    local start_time end_time duration exit_code status skip_hint=""

    start_time=$(date +%s.%N)

    # Check if script exists
    if [[ ! -f "$step_path" ]]; then
        echo "    [$step_name] SKIP (not found)"
        exit_code=1
        status="SKIPPED"
        duration=0
    else
        # Make executable if needed
        chmod +x "$step_path" 2>/dev/null || true

        # Check if already hardened (idempotency check)
        if [[ -f "$step_path.hardened" ]] && $IDEMPOTENT_MODE; then
            echo "    [$step_name] SKIP (already hardened)"
            skip_hint="ALREADY_HARDENED"
            exit_code=0
            status="SKIPPED"
        else
            echo "    [$step_name] RUNNING..."

            # Execute the step
            set +e
            "$step_path" > /dev/null 2>&1
            exit_code=$?
            set -e

            if [[ $exit_code -eq 0 ]]; then
                status="PASS"
                STEPS_COMPLETED=$((STEPS_COMPLETED + 1))
                # Mark as hardened for idempotency
                touch "$step_path.hardened"
            else
                status="FAIL"
                STEPS_FAILED=$((STEPS_FAILED + 1))
            fi
        fi
    fi

    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc 2>/dev/null || echo "0")

    # Store result for JSON output
    STEP_RESULTS+=("{\"step\": \"$step_name\", \"step_number\": $step_num, \"status\": \"$status\", \"exit_code\": $exit_code, \"duration_seconds\": $duration, \"skip_reason\": ${skip_hint:-null}}")

    if [[ $exit_code -ne 0 ]] && [[ "$status" != "SKIPPED" ]]; then
        echo "    ERROR: $step_name failed with exit code $exit_code"
        echo "Stopping hardening workflow due to failure."
        generate_run_log
        exit 1
    fi
}

# Generate the hardening run log JSON
generate_run_log() {
    local total_duration delta

    WORKFLOW_END=$(date +%s)
    total_duration=$((WORKFLOW_END - WORKFLOW_START))

    # Calculate Lynis delta
    if [[ "$PRE_LYNIS_SCORE" =~ ^[0-9]+$ ]] && [[ "$POST_LYNIS_SCORE" =~ ^[0-9]+$ ]]; then
        delta=$((POST_LYNIS_SCORE - PRE_LYNIS_SCORE))
    else
        delta="N/A"
    fi

    {
        printf '{\n'
        printf '  "timestamp": "%s",\n' "$TIMESTAMP"
        printf '  "run_start_epoch": %d,\n' "$WORKFLOW_START"
        printf '  "run_end_epoch": %d,\n' "$WORKFLOW_END"
        printf '  "total_duration_seconds": %d,\n' "$total_duration"
        printf '  "steps_scheduled": %d,\n' "$STEPS_SCHEDULED"
        printf '  "steps_completed": %d,\n' "$STEPS_COMPLETED"
        printf '  "steps_failed": %d,\n' "$STEPS_FAILED"
        printf '  "pre_lynis_score": "%s",\n' "$PRE_LYNIS_SCORE"
        printf '  "post_lynis_score": "%s",\n' "$POST_LYNIS_SCORE"
        printf '  "lynis_delta": "%s",\n' "$delta"
        printf '  "idempotent_mode": %s,\n' "$IDEMPOTENT_MODE"
        printf '  "results": [\n'

        local first=true
        for result in "${STEP_RESULTS[@]}"; do
            if $first; then
                first=false
            else
                printf ',\n'
            fi
            printf '    %s' "$result"
        done

        printf '\n  ]\n'
        printf '}\n'
    } > "$RUN_LOG_FILE"

    # Ensure trailing newline
    if [[ "$(tail -c1 "$RUN_LOG_FILE" | wc -l)" -eq 0 ]]; then
        echo "" >> "$RUN_LOG_FILE"
    fi
}

# Generate improvement JSON
generate_improvement_json() {
    local delta

    if [[ "$PRE_LYNIS_SCORE" =~ ^[0-9]+$ ]] && [[ "$POST_LYNIS_SCORE" =~ ^[0-9]+$ ]]; then
        delta=$((POST_LYNIS_SCORE - PRE_LYNIS_SCORE))
    else
        delta="N/A"
    fi

    {
        printf '{\n'
        printf '  "timestamp": "%s",\n' "$TIMESTAMP"
        printf '  "pre_hardening_score": "%s",\n' "$PRE_LYNIS_SCORE"
        printf '  "post_hardening_score": "%s",\n' "$POST_LYNIS_SCORE"
        printf '  "score_delta": "%s",\n' "$delta"
        printf '  "improvement_percentage": '

        if [[ "$PRE_LYNIS_SCORE" =~ ^[0-9]+$ ]] && [[ "$PRE_LYNIS_SCORE" -gt 0 ]]; then
            local pct
            pct=$(echo "scale=1; ($delta * 100) / $PRE_LYNIS_SCORE" | bc 2>/dev/null || echo "N/A")
            printf '"%s"', "$pct"
        else
            printf '"N/A"'
        fi

        printf ',\n'
        printf '  "hardening_steps_applied": %d,\n' "$STEPS_COMPLETED"
        printf '  "overall_status": "'

        if [[ $STEPS_FAILED -eq 0 ]]; then
            printf 'SUCCESS'
        else
            printf 'PARTIAL_FAILURE'
        fi

        printf '"\n'
        printf '}\n'
    } > "$IMPROVEMENT_FILE"

    # Ensure trailing newline
    if [[ "$(tail -c1 "$IMPROVEMENT_FILE" | wc -l)" -eq 0 ]]; then
        echo "" >> "$IMPROVEMENT_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Pre-checks
# ---------------------------------------------------------------------------

echo "[*] Pre-checks..."

PRE_CHECKS_PASS=true

# Verify Lynis is available (check both paths)
if [[ -f "$LYNIS_BIN" ]]; then
    echo "    Lynis binary found: $LYNIS_BIN [OK]"
else
    # Try alternate path
    ALTERNATE_LYNIS="/usr/sbin/lynis"
    if [[ -f "$ALTERNATE_LYNIS" ]]; then
        LYNIS_BIN="$ALTERNATE_LYNIS"
        echo "    Lynis binary found: $LYNIS_BIN [OK]"
    else
        echo "    WARNING: Lynis not found — scores will show N/A"
    fi
fi

# Verify all required scripts exist
echo "    Verifying hardening scripts..."
for step in "${STEPS[@]}"; do
    step_path="$SCRIPT_DIR/$step"
    if [[ ! -f "$step_path" ]]; then
        echo "    MISSING: $step"
        PRE_CHECKS_PASS=false
    fi
done

if $PRE_CHECKS_PASS; then
    echo "    All scripts present: PASS"
else
    echo "    ERROR: Missing scripts — aborting hardening"
    exit 1
fi

echo "Pre-checks: PASS"
echo "Steps scheduled: $STEPS_SCHEDULED"

# ---------------------------------------------------------------------------
# Capture Lynis baseline score before hardening starts
# ---------------------------------------------------------------------------

echo "[*] Capturing security baseline before hardening begins..."

PRE_LYNIS_SCORE=$(get_lynis_score)
echo "Before Lynis score: $PRE_LYNIS_SCORE"

# ---------------------------------------------------------------------------
# Execute hardening workflow
# ---------------------------------------------------------------------------

echo "[*] Executing hardening workflow..."

for step in "${STEPS[@]}"; do
    run_step "$step"
done

# ---------------------------------------------------------------------------
# Capture Lynis score after hardening ends
# ---------------------------------------------------------------------------

echo "[*] Capturing security baseline after hardening completes..."

POST_LYNIS_SCORE=$(get_lynis_score)
echo "After Lynis score: $POST_LYNIS_SCORE"

# ---------------------------------------------------------------------------
# Calculate delta
# ---------------------------------------------------------------------------

DELTA="N/A"
if [[ "$PRE_LYNIS_SCORE" =~ ^[0-9]+$ ]] && [[ "$POST_LYNIS_SCORE" =~ ^[0-9]+$ ]]; then
    DELTA=$((POST_LYNIS_SCORE - PRE_LYNIS_SCORE))
    if [[ $DELTA -ge 0 ]]; then
        echo "Delta: +$DELTA"
    else
        echo "Delta: $DELTA"
    fi
else
    echo "Delta: N/A (could not calculate)"
fi

# ---------------------------------------------------------------------------
# Generate output files
# ---------------------------------------------------------------------------

echo "[*] Generating output files..."

generate_run_log
generate_improvement_json

echo "Run log saved to: $RUN_LOG_FILE"
echo "Improvement saved to: $IMPROVEMENT_FILE"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "Steps completed: $STEPS_COMPLETED"
echo "Steps failed: $STEPS_FAILED"

if [[ $STEPS_FAILED -eq 0 ]]; then
    echo "Overall status: SUCCESS"
    exit 0
else
    echo "Overall status: PARTIAL_FAILURE"
    echo "Review hardening_run.json for failure details"
    exit 1
fi
