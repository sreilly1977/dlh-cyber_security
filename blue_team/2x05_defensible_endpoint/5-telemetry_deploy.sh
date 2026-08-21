#!/bin/bash
# Name: 5-telemetry_deploy.sh
# Purpose: Deploy auditd telemetry, run controlled test sequences, verify coverage, and export evidence.
# Author: Stephen Reilly
# Exit Codes: 0=Success, 1=Control Failure (verification failed), 2=Environment Error (missing deps/files)

set -euo pipefail

# --- Configuration ---
RULES_FILE="/etc/audit/rules.d/meddefense.rules"
LOG_DIR="capstone/telemetry"
JSON_OUTPUT="${LOG_DIR}/linux_events.json"
COVERAGE_OUTPUT="${LOG_DIR}/linux_coverage.json"
TEST_USER="test_audit_user"
CRON_JOB_NAME="meddefense_test_cron"
SERVICE_ACTION="cron"
KEY_USER_MGMT="meddefense-user-mgmt"
KEY_SERVICE="meddefense-service"
KEY_SCHEDULER="meddefense-scheduler"
KEY_FILE_ACCESS="meddefense-file-access"

# Marker block for the test-specific rules the script manages
TELEMETRY_MARKER="# --- Telemetry Test Rules (managed by 5-telemetry_deploy.sh) ---"

# Ensure we are running as root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root." >&2
    exit 2
fi

# --- Initialize Coverage Tracking Array ---
declare -A COVERAGE_STATUS
COVERAGE_STATUS=(
    ["create_user"]="pending"
    ["remove_user"]="pending"
    ["service_restart"]="pending"
    ["cron_create"]="pending"
    ["cron_remove"]="pending"
    ["file_access"]="pending"
)

log_step() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

fail_exit() {
    log_step "FAILURE: $1"
    exit 1
}

env_error() {
    log_step "ENVIRONMENT ERROR: $1"
    exit 2
}

# Helper to safely run crontab commands (handles "no crontab" gracefully)
safe_crontab_list() {
    crontab -l 2>/dev/null || true
}

# --- Pre-flight Checks ---

log_step "Checking environment dependencies..."

if ! command -v auditctl &> /dev/null; then
    env_error "auditctl not found. Is auditd installed?"
fi

if ! command -v ausearch &> /dev/null; then
    env_error "ausearch not found. Is auditd installed?"
fi

if [[ ! -f "$RULES_FILE" ]]; then
    env_error "Rules file not found at $RULES_FILE"
fi

mkdir -p "$LOG_DIR"

# --- Ensure Test-Specific Rules Exist (Idempotent Append) ---

log_step "Ensuring telemetry test rules are present in $RULES_FILE..."

# Define the test-specific rules we need
read -r -d '' TEST_RULES << 'TELEMETRY_RULES' || true
-w /usr/sbin/useradd -p x -k meddefense-user-mgmt
-w /usr/sbin/userdel -p x -k meddefense-user-mgmt
-w /etc/passwd -p wa -k meddefense-user-mgmt
-w /etc/shadow -p wa -k meddefense-user-mgmt
-w /usr/bin/systemctl -p x -k meddefense-service
-w /var/spool/cron/crontabs/ -p wa -k meddefense-scheduler
-w /usr/bin/find -p x -k meddefense-file-access
TELEMETRY_RULES

# Check if our marker is already in the rules file
if ! grep -q "$TELEMETRY_MARKER" "$RULES_FILE" 2>/dev/null; then
    log_step "Appending telemetry test rules to $RULES_FILE..."
    {
        echo ""
        echo "$TELEMETRY_MARKER"
        echo "$TEST_RULES"
        echo "# --- End Telemetry Test Rules ---"
        echo ""
    } >> "$RULES_FILE"
else
    log_step "Telemetry test rules already present in $RULES_FILE."
fi

# --- Reload Auditd Rules ---

log_step "Reloading auditd rules..."

if command -v augenrules &> /dev/null; then
    augenrules --load 2>&1 | tail -n 1
else
    auditctl -R "$RULES_FILE" 2>/dev/null || true
fi

# Verify auditd is running
if ! systemctl is-active --quiet auditd; then
    fail_exit "auditd service is not active."
fi

log_step "Auditd rules loaded and service verified."

# Small delay to let audit subsystem settle after rule load
sleep 2

# Record the timestamp after rules are loaded; we only search forward from here
VERIFY_START_TS=$(date +%s)

# --- Controlled Test Sequence ---

log_step "Starting controlled test sequence..."

# 1. create a user (Expected: KEY_USER_MGMT)
log_step "Test 1: create a user ('$TEST_USER')..."
if id "$TEST_USER" &> /dev/null; then
    log_step "User '$TEST_USER' already exists, skipping creation (idempotent)."
else
    useradd -m "$TEST_USER"
fi
sleep 2

# 2. remove the user (Expected: KEY_USER_MGMT)
log_step "Test 2: remove the user ('$TEST_USER')..."
if id "$TEST_USER" &> /dev/null; then
    userdel -r "$TEST_USER" 2>/dev/null || userdel "$TEST_USER" 2>/dev/null || true
fi
sleep 2

# 3. run a service management action (Expected: KEY_SERVICE)
log_step "Test 3: run a service management action ('$SERVICE_ACTION')..."
systemctl restart "$SERVICE_ACTION" 2>/dev/null || true
sleep 2

# 4. schedule a cron job (Expected: KEY_SCHEDULER)
log_step "Test 4: schedule a cron job..."
# Safe pipeline: suppress "no crontab" error, grep -v won't fail on empty input
existing_cron=$(safe_crontab_list)
if echo "$existing_cron" | grep -q "$CRON_JOB_NAME"; then
    log_step "Cron job '$CRON_JOB_NAME' already exists, skipping (idempotent)."
else
    echo "$existing_cron" | { cat; echo "* * * * * /bin/true # $CRON_JOB_NAME"; } | crontab -
fi
sleep 2

# 5. remove it (Expected: KEY_SCHEDULER)
log_step "Test 5: remove it (cron job)..."
existing_cron=$(safe_crontab_list)
echo "$existing_cron" | grep -v "$CRON_JOB_NAME" | crontab - 2>/dev/null || true
sleep 2

# 6. run a short authorized find as root (Expected: KEY_FILE_ACCESS)
log_step "Test 6: run a short authorized find as root..."
find /etc -maxdepth 2 -name "*.conf" 2>/dev/null | head -n 5 > /dev/null
sleep 2

# --- Verification Phase ---

log_step "Verifying telemetry coverage..."

verify_trace() {
    local key=$1
    local action_name=$2
    local count

    # Search for the key in audit records since our verification start time
    # ausearch -ts recent covers the last 10 minutes
    count=$(ausearch -k "$key" -ts recent 2>/dev/null | grep -c "type=" || echo "0")

    if [[ "$count" -gt 0 ]]; then
        log_step "PASS: Found $count records for key '$key' ($action_name)."
        COVERAGE_STATUS["$action_name"]="verified"
        return 0
    else
        log_step "FAIL: No records found for key '$key' ($action_name)."
        COVERAGE_STATUS["$action_name"]="failed"
        return 1
    fi
}

FAILED=0

verify_trace "$KEY_USER_MGMT" "create_user" || FAILED=1
verify_trace "$KEY_USER_MGMT" "remove_user" || FAILED=1
verify_trace "$KEY_SERVICE" "service_restart" || FAILED=1
verify_trace "$KEY_SCHEDULER" "cron_create" || FAILED=1
verify_trace "$KEY_SCHEDULER" "cron_remove" || FAILED=1
verify_trace "$KEY_FILE_ACCESS" "file_access" || FAILED=1

# --- Evidence Export ---

log_step "Exporting structured JSON evidence..."

# Build linux_events.json: structured JSON from ausearch output for all test keys
build_events_json() {
    local output_file=$1
    local ts_iso
    ts_iso=$(date -Iseconds)

    echo "[" > "$output_file"
    local first=true

    for key in "$KEY_USER_MGMT" "$KEY_SERVICE" "$KEY_SCHEDULER" "$KEY_FILE_ACCESS"; do
        local raw_output
        raw_output=$(ausearch -k "$key" -ts recent -i 2>/dev/null || true)

        if [[ -n "$raw_output" ]]; then
            while IFS= read -r line; do
                if [[ "$line" =~ type=([A-Z_]+) ]]; then
                    local evt_type="${BASH_REMATCH[1]}"
                    # Extract timestamp from the line if possible
                    local evt_ts="$ts_iso"
                    # Escape the line for JSON
                    local escaped_line
                    escaped_line=$(echo "$line" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g')

                    if [[ "$first" == "true" ]]; then
                        first=false
                    else
                        echo "," >> "$output_file"
                    fi

                    printf '  {"timestamp": "%s", "audit_key": "%s", "event_type": "%s", "raw_message": "%s"}' \
                        "$evt_ts" "$key" "$evt_type" "$escaped_line" >> "$output_file"
                fi
            done <<< "$raw_output"
        fi
    done

    echo "" >> "$output_file"
    echo "]" >> "$output_file"
}

build_events_json "$JSON_OUTPUT"

# Build linux_coverage.json
{
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"host\": \"$(hostname)\","
    echo "  \"source\": \"auditd\","
    echo "  \"test_actions\": ["

    first_cov=true
    for action in "create_user" "remove_user" "service_restart" "cron_create" "cron_remove" "file_access"; do
        if [[ "$first_cov" == "true" ]]; then
            first_cov=false
        else
            echo ","
        fi
        printf '    {"action": "%s", "status": "%s"}' "$action" "${COVERAGE_STATUS[$action]}"
    done

    echo ""
    echo "  ],"
    echo "  \"overall_result\": \"$([[ $FAILED -eq 0 ]] && echo 'PASS' || echo 'FAIL')\""
    echo "}"
} > "$COVERAGE_OUTPUT"

# --- Cleanup Test Artifacts ---

log_step "Cleaning up test artifacts..."

# Remove the test user if it still exists
if id "$TEST_USER" &> /dev/null; then
    userdel -r "$TEST_USER" 2>/dev/null || true
fi

# Ensure the cron job is removed
existing_cron=$(safe_crontab_list)
if echo "$existing_cron" | grep -q "$CRON_JOB_NAME"; then
    echo "$existing_cron" | grep -v "$CRON_JOB_NAME" | crontab - 2>/dev/null || true
fi

# --- Final Result ---

if [[ $FAILED -eq 0 ]]; then
    log_step "Telemetry deployment and verification successful."
    log_step "Evidence exported to: $JSON_OUTPUT"
    log_step "Coverage report exported to: $COVERAGE_OUTPUT"
    exit 0
else
    log_step "Verification failed. Some test actions did not produce expected traces."
    log_step "Coverage report exported to: $COVERAGE_OUTPUT"
    exit 1
fi
