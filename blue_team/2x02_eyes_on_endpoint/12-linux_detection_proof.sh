#!/bin/bash
#
# name:        12-linux_detection_proof.sh
# purpose:     Correlate Linux attack simulation log against captured telemetry
# author:      Steve - Cybersecurity Engineer
# date:        August 10, 2026
#
# .Purpose
#     This script correlates the Linux attack simulation log (ground truth from Task 11)
#     against captured telemetry (auditd, auth.log, syslog) to produce a detection matrix.
#
#     For each simulated action, it searches telemetry within a 30-second window
#     around the recorded timestamp and determines:
#
#         - Which source captured it (auditd, auth.log, syslog)
#         - The audit key (if auditd)
#         - Detail level (Full/Partial/Missed)
#         - Key fields present in the event
#
#     Output: linux_detection_matrix.json
#

# Root check (needed for ausearch and reading system logs)
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script requires root privileges. Please run with sudo." >&2
    exit 1
fi

# Check for jq
if ! command -v jq &> /dev/null; then
    echo "[ERROR] jq is required. Install with: sudo apt install jq" >&2
    exit 1
fi

# Configuration
GROUND_TRUTH_FILE="linux_attack_log.json"
OUTPUT_FILE="linux_detection_matrix.json"
TIME_WINDOW_SECONDS=30

# Check if ground truth file exists
if [[ ! -f "$GROUND_TRUTH_FILE" ]]; then
    echo "[ERROR] Ground truth file '$GROUND_TRUTH_FILE' not found." >&2
    echo "Please run 11-linux_attack_sim.sh first to generate the attack log." >&2
    exit 1
fi

# Extract total actions
TOTAL_ACTIONS=$(jq '.actions | length' "$GROUND_TRUTH_FILE")

echo "[*] Loading ground truth ($TOTAL_ACTIONS actions)..."
echo "[*] Searching telemetry..."
echo ""

# Print header
printf "%-26s %-15s %-16s %-10s %s\n" "Action" "Source" "Key" "Detail" "Status"
printf "%-26s %-15s %-16s %-10s %s\n" "------" "------" "---" "------" "------"

# Initialize counters
CAPTURED_COUNT=0
MULTI_SOURCE_COUNT=0

# Initialize JSON matrix
MATRIX_JSON="["

# Function to get short action name
get_short_action() {
    local desc="$1"
    case "$desc" in
        *user*account*) echo "Create user" ;;
        *sudoers*)      echo "Modify sudoers" ;;
        *binary*/tmp*|*tmp*suspicious*|*suspicious*execution*) echo "Execute from /tmp" ;;
        *reverse*shell*) echo "Reverse shell" ;;
        *cron*)         echo "Cron persistence" ;;
        *shadow*)       echo "Access /etc/shadow" ;;
        *)              echo "Unknown" ;;
    esac
}

# Function to get detection mapping for an action
# Returns: audit_key|auth_keyword|syslog_keyword
get_detection_mapping() {
    local desc="$1"
    case "$desc" in
        *user*account*)
            echo "identity|useradd|useradd"
            ;;
        *sudoers*)
            echo "sudoers||"
            ;;
        *binary*/tmp*|*tmp*suspicious*|*suspicious*execution*)
            echo "process_exec||"
            ;;
        *reverse*shell*)
            echo "network_connect||"
            ;;
        *cron*)
            echo "cron_persist|cron|cron"
            ;;
        *shadow*)
            echo "identity||"
            ;;
        *)
            echo "||"
            ;;
    esac
}

# Function to search auditd within time window
search_auditd() {
    local start_epoch="$1"
    local end_epoch="$2"
    local audit_key="$3"

    local start_date start_time end_date end_time
    start_date=$(date -d "@$start_epoch" +"%m/%d/%Y")
    start_time=$(date -d "@$start_epoch" +"%H:%M:%S")
    end_date=$(date -d "@$end_epoch" +"%m/%d/%Y")
    end_time=$(date -d "@$end_epoch" +"%H:%M:%S")

    ausearch -ts "$start_date" "$start_time" -te "$end_date" "$end_time" -k "$audit_key" 2>/dev/null || true
}

# Function to search auth.log within time window
search_authlog() {
    local start_epoch="$1"
    local end_epoch="$2"
    local keyword="$3"

    # Try journalctl first (supports epoch-based filtering)
    if command -v journalctl &> /dev/null; then
        local result
        result=$(journalctl --since "@$start_epoch" --until "@$end_epoch" --no-pager 2>/dev/null | grep -i "$keyword" || true)
        if [[ -n "$result" ]]; then
            echo "$result"
            return
        fi
    fi

    # Fall back to grepping auth.log directly
    if [[ -f /var/log/auth.log ]]; then
        grep -i "$keyword" /var/log/auth.log 2>/dev/null | tail -50 || true
    fi
}

# Function to search syslog within time window
search_syslog() {
    local start_epoch="$1"
    local end_epoch="$2"
    local keyword="$3"

    # Try journalctl first
    if command -v journalctl &> /dev/null; then
        local result
        result=$(journalctl --since "@$start_epoch" --until "@$end_epoch" --no-pager 2>/dev/null | grep -i "$keyword" || true)
        if [[ -n "$result" ]]; then
            echo "$result"
            return
        fi
    fi

    # Fall back to grepping syslog directly
    if [[ -f /var/log/syslog ]]; then
        grep -i "$keyword" /var/log/syslog 2>/dev/null | tail -50 || true
    fi
}

# Function to evaluate detail level from search results
evaluate_detail() {
    local result="$1"
    local keywords="$2"

    if [[ -z "$result" ]]; then
        echo "Missed"
        return
    fi

    local match_count=0
    IFS='|' read -ra kw_array <<< "$keywords"
    for kw in "${kw_array[@]}"; do
        if [[ -n "$kw" ]] && echo "$result" | grep -qi "$kw" 2>/dev/null; then
            match_count=$((match_count + 1))
        fi
    done

    if [[ $match_count -ge 2 ]]; then
        echo "Full"
    elif [[ $match_count -ge 1 ]]; then
        echo "Partial"
    else
        echo "Partial"
    fi
}

# Function to extract key fields from auditd output
extract_key_fields() {
    local result="$1"
    local source="$2"
    local audit_key="$3"

    local has_data="false"
    local data_length=0
    local first_line=""

    if [[ -n "$result" ]]; then
        has_data="true"
        data_length=${#result}
        first_line=$(echo "$result" | head -1 | tr -d '"' | head -c 200)
    fi

    # Build key fields JSON
    local fields
    fields=$(jq -n \
        --arg source "$source" \
        --arg audit_key "$audit_key" \
        --arg has_data "$has_data" \
        --argjson data_length "$data_length" \
        --arg first_line "$first_line" \
        '{source: $source, audit_key: $audit_key, has_data: ($has_data == "true"), data_length: $data_length, sample_line: $first_line}')
    echo "$fields"
}

# Function to append entry to matrix JSON
append_to_matrix() {
    local action_num="$1"
    local action="$2"
    local source="$3"
    local audit_key="$4"
    local detail="$5"
    local status="$6"
    local timestamp="$7"
    local mitre="$8"
    local key_fields="$9"

    local event_id="$audit_key"
    if [[ -z "$event_id" ]]; then
        event_id="-"
    fi

    local entry
    entry=$(jq -n \
        --argjson action_num "$action_num" \
        --arg action "$action" \
        --arg source "$source" \
        --arg audit_key "$audit_key" \
        --arg event_id "$event_id" \
        --arg detail_level "$detail" \
        --arg status "$status" \
        --arg timestamp "$timestamp" \
        --arg mitre_attack "$mitre" \
        --argjson key_fields "$key_fields" \
        '{action_number: $action_num, action: $action, source: $source, audit_key: $audit_key, event_id: $event_id, detail_level: $detail_level, status: $status, timestamp: $timestamp, mitre_attack: $mitre_attack, key_fields: $key_fields}')

    if [[ "$MATRIX_JSON" != "[" ]]; then
        MATRIX_JSON+=","
    fi
    MATRIX_JSON+="$entry"
}

# Process each action
for i in $(seq 0 $((TOTAL_ACTIONS - 1))); do
    ACTION_NUM=$(jq -r ".actions[$i].action_number" "$GROUND_TRUTH_FILE")
    DESCRIPTION=$(jq -r ".actions[$i].description" "$GROUND_TRUTH_FILE")
    TIMESTAMP=$(jq -r ".actions[$i].timestamp" "$GROUND_TRUTH_FILE")
    MITRE=$(jq -r ".actions[$i].mitre_attack_technique" "$GROUND_TRUTH_FILE")

    # Strip Z from timestamp and convert to epoch
    TS_CLEAN="${TIMESTAMP%Z}"
    EPOCH=$(date -u -d "$TS_CLEAN" +%s 2>/dev/null)

    if [[ -z "$EPOCH" ]]; then
        echo "  [ERROR] Could not parse timestamp: $TIMESTAMP" >&2
        continue
    fi

    # Calculate time window (30 seconds before and after)
    START_EPOCH=$((EPOCH - TIME_WINDOW_SECONDS))
    END_EPOCH=$((EPOCH + TIME_WINDOW_SECONDS))

    # Get detection mapping
    MAPPING=$(get_detection_mapping "$DESCRIPTION")
    IFS='|' read -r AUDIT_KEY AUTH_KEYWORD SYSLOG_KEYWORD <<< "$MAPPING"

    # Get short action name for display
    SHORT_ACTION=$(get_short_action "$DESCRIPTION")

    SOURCES_CAPTURED=0
    FIRST_ROW=true

    # Search auditd
    if [[ -n "$AUDIT_KEY" ]]; then
        AUDIT_RESULT=$(search_auditd "$START_EPOCH" "$END_EPOCH" "$AUDIT_KEY")
        DETAIL=$(evaluate_detail "$AUDIT_RESULT" "$AUDIT_KEY|$AUTH_KEYWORD")
        STATUS="MISSING"
        if [[ "$DETAIL" != "Missed" ]]; then
            STATUS="CAPTURED"
            SOURCES_CAPTURED=$((SOURCES_CAPTURED + 1))
        fi

        # Display row
        DISPLAY_ACTION="$SHORT_ACTION"
        if [[ "$FIRST_ROW" != "true" ]]; then
            DISPLAY_ACTION=""
        fi
        printf "%-26s %-15s %-16s %-10s [%s]\n" "$DISPLAY_ACTION" "auditd" "$AUDIT_KEY" "$DETAIL" "$STATUS"
        FIRST_ROW=false

        # Extract key fields and add to matrix
        KEY_FIELDS=$(extract_key_fields "$AUDIT_RESULT" "auditd" "$AUDIT_KEY")
        append_to_matrix "$ACTION_NUM" "$DESCRIPTION" "auditd" "$AUDIT_KEY" "$DETAIL" "$STATUS" "$TIMESTAMP" "$MITRE" "$KEY_FIELDS"
    fi

    # Search auth.log
    if [[ -n "$AUTH_KEYWORD" ]]; then
        AUTH_RESULT=$(search_authlog "$START_EPOCH" "$END_EPOCH" "$AUTH_KEYWORD")
        DETAIL=$(evaluate_detail "$AUTH_RESULT" "$AUTH_KEYWORD")
        STATUS="MISSING"
        if [[ "$DETAIL" != "Missed" ]]; then
            STATUS="CAPTURED"
            SOURCES_CAPTURED=$((SOURCES_CAPTURED + 1))
        fi

        # Display row
        DISPLAY_ACTION=""
        if [[ "$FIRST_ROW" == "true" ]]; then
            DISPLAY_ACTION="$SHORT_ACTION"
            FIRST_ROW=false
        fi
        printf "%-26s %-15s %-16s %-10s [%s]\n" "$DISPLAY_ACTION" "auth.log" "$AUTH_KEYWORD" "$DETAIL" "$STATUS"

        # Extract key fields and add to matrix
        KEY_FIELDS=$(extract_key_fields "$AUTH_RESULT" "auth.log" "$AUTH_KEYWORD")
        append_to_matrix "$ACTION_NUM" "$DESCRIPTION" "auth.log" "$AUTH_KEYWORD" "$DETAIL" "$STATUS" "$TIMESTAMP" "$MITRE" "$KEY_FIELDS"
    fi

    # Search syslog
    if [[ -n "$SYSLOG_KEYWORD" ]]; then
        SYSLOG_RESULT=$(search_syslog "$START_EPOCH" "$END_EPOCH" "$SYSLOG_KEYWORD")
        DETAIL=$(evaluate_detail "$SYSLOG_RESULT" "$SYSLOG_KEYWORD")
        STATUS="MISSING"
        if [[ "$DETAIL" != "Missed" ]]; then
            STATUS="CAPTURED"
            SOURCES_CAPTURED=$((SOURCES_CAPTURED + 1))
        fi

        # Display row
        DISPLAY_ACTION=""
        if [[ "$FIRST_ROW" == "true" ]]; then
            DISPLAY_ACTION="$SHORT_ACTION"
            FIRST_ROW=false
        fi
        printf "%-26s %-15s %-16s %-10s [%s]\n" "$DISPLAY_ACTION" "syslog" "$SYSLOG_KEYWORD" "$DETAIL" "$STATUS"

        # Extract key fields and add to matrix
        KEY_FIELDS=$(extract_key_fields "$SYSLOG_RESULT" "syslog" "$SYSLOG_KEYWORD")
        append_to_matrix "$ACTION_NUM" "$DESCRIPTION" "syslog" "$SYSLOG_KEYWORD" "$DETAIL" "$STATUS" "$TIMESTAMP" "$MITRE" "$KEY_FIELDS"
    fi

    # Update counters
    if [[ $SOURCES_CAPTURED -gt 0 ]]; then
        CAPTURED_COUNT=$((CAPTURED_COUNT + 1))
    fi
    if [[ $SOURCES_CAPTURED -gt 1 ]]; then
        MULTI_SOURCE_COUNT=$((MULTI_SOURCE_COUNT + 1))
    fi
done

MATRIX_JSON+="]"

echo ""
CAPTURE_PCT=0
if [[ $TOTAL_ACTIONS -gt 0 ]]; then
    CAPTURE_PCT=$((CAPTURED_COUNT * 100 / TOTAL_ACTIONS))
fi
echo "Actions: $TOTAL_ACTIONS | Captured: $CAPTURED_COUNT/$TOTAL_ACTIONS ($CAPTURE_PCT%) | Multi-source: $MULTI_SOURCE_COUNT"

# Generate JSON report
CAPTURE_RATE=$(awk "BEGIN {printf \"%.1f\", $CAPTURED_COUNT * 100 / $TOTAL_ACTIONS}" 2>/dev/null || echo "$CAPTURE_PCT")
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build final report using jq for proper JSON validation
jq -n \
    --arg gt_file "$GROUND_TRUTH_FILE" \
    --arg analysis_ts "$NOW" \
    --argjson total "$TOTAL_ACTIONS" \
    --argjson captured "$CAPTURED_COUNT" \
    --argjson rate "$CAPTURE_RATE" \
    --argjson multi "$MULTI_SOURCE_COUNT" \
    --argjson window "$TIME_WINDOW_SECONDS" \
    --argjson matrix "$MATRIX_JSON" \
    '{
        summary: {
            ground_truth_file: $gt_file,
            analysis_timestamp: $analysis_ts,
            total_actions: $total,
            actions_captured: $captured,
            capture_rate_percent: $rate,
            multi_source_detections: $multi,
            time_window_seconds: $window
        },
        detection_matrix: $matrix
    }' > "$OUTPUT_FILE"

echo "Report saved to: $OUTPUT_FILE"
echo ""

# Display detection summary by action
echo "Detection Summary by Action:" | tee /dev/stderr
echo "----------------------------" | tee /dev/stderr

# Read back from the generated JSON for the summary
for i in $(seq 0 $((TOTAL_ACTIONS - 1))); do
    ACTION_NUM=$(jq -r ".actions[$i].action_number" "$GROUND_TRUTH_FILE")
    DESCRIPTION=$(jq -r ".actions[$i].description" "$GROUND_TRUTH_FILE")
    SHORT_ACTION=$(get_short_action "$DESCRIPTION")

    # Check if any source captured this action
    ACTION_STATUS=$(jq -r --arg desc "$DESCRIPTION" \
        '.detection_matrix[] | select(.action == $desc) | .status' \
        "$OUTPUT_FILE" 2>/dev/null | head -1)

    if [[ "$ACTION_STATUS" == "CAPTURED" ]]; then
        CAPTURE_STATUS="[CAPTURED]"
    else
        CAPTURE_STATUS="[MISSING]"
    fi

    echo "  $ACTION_NUM. $SHORT_ACTION $CAPTURE_STATUS" >&2

    # Show captured sources
    jq -r --arg desc "$DESCRIPTION" \
        '.detection_matrix[] | select(.action == $desc and .status == "CAPTURED") | "      Source: \(.source) | Key: \(.audit_key) | Detail: \(.detail_level)"' \
        "$OUTPUT_FILE" 2>/dev/null >&2
done

echo "" >&2
echo "Telemetry Source Statistics:" >&2
echo "----------------------------" >&2

# Calculate per-source statistics
for source in "auditd" "auth.log" "syslog"; do
    TOTAL_FOR_SOURCE=$(jq -r --arg src "$source" \
        '[.detection_matrix[] | select(.source == $src)] | length' \
        "$OUTPUT_FILE" 2>/dev/null)
    CAPTURED_FOR_SOURCE=$(jq -r --arg src "$source" \
        '[.detection_matrix[] | select(.source == $src and .status == "CAPTURED")] | length' \
        "$OUTPUT_FILE" 2>/dev/null)

    if [[ "$TOTAL_FOR_SOURCE" -gt 0 ]] 2>/dev/null; then
        echo "  $source : $CAPTURED_FOR_SOURCE/$TOTAL_FOR_SOURCE captured" >&2
    fi
done

echo ""
echo "[*] Detection proof complete."
