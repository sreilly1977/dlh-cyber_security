#!/bin/bash
#
# name:        13-consolidated_export.sh
# purpose:     Combine Windows and Linux telemetry exports into unified handoff package
# author:      Steve - Cybersecurity Engineer
# date:        August 10, 2026
#
# .Purpose
#     This script creates a consolidated telemetry handoff package for SOC intake.
#     It combines normalized telemetry from both Windows and Linux platforms along with
#     attacker simulation ground truth data for detection validation.
#
#     Input files:
#         - windows_events_export.json (Task 3 output)
#         - linux_events_export.json (Task 7 output)
#         - windows_attack_log.json (Task 9/11 output)
#         - linux_attack_log.json (Task 11 output)
#
#     Output structure:
#         telemetry_handoff/
#             windows_events.json          (normalized Windows telemetry)
#             linux_events.json            (normalized Linux telemetry)
#             attack_ground_truth.json     (combined attacker ground truth)
#
#     All timestamps normalized to UTC ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ)
#

set -euo pipefail

# Check for jq
if ! command -v jq &> /dev/null; then
    echo "[ERROR] jq is required. Install with: sudo apt install jq" >&2
    exit 1
fi

# Configuration
WINDOWS_EVENTS_FILE="windows_events_export.json"
LINUX_EVENTS_FILE="linux_events_export.json"
WINDOWS_GROUND_TRUTH="windows_attack_log.json"
LINUX_GROUND_TRUTH="linux_attack_log.json"
HANDOFF_DIR="telemetry_handoff"

# Check for required input files
MISSING_FILES=()
if [[ ! -f "$WINDOWS_EVENTS_FILE" ]]; then
    MISSING_FILES+=("$WINDOWS_EVENTS_FILE")
fi
if [[ ! -f "$LINUX_EVENTS_FILE" ]]; then
    MISSING_FILES+=("$LINUX_EVENTS_FILE")
fi
if [[ ! -f "$WINDOWS_GROUND_TRUTH" ]]; then
    MISSING_FILES+=("$WINDOWS_GROUND_TRUTH")
fi
if [[ ! -f "$LINUX_GROUND_TRUTH" ]]; then
    MISSING_FILES+=("$LINUX_GROUND_TRUTH")
fi

if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
    echo "[ERROR] Missing required input files:" >&2
    for file in "${MISSING_FILES[@]}"; do
        echo "  - $file" >&2
    done
    echo >&2
    exit 1
fi

# Detect JSON format: "array", "ndjson", or "object"
# Uses jq itself to determine the type, which handles BOM and whitespace
detect_format() {
    local file="$1"

    # Try parsing as a single JSON value first
    local root_type
    root_type=$(jq -r 'type' "$file" 2>/dev/null || echo "")

    if [[ "$root_type" == "array" ]]; then
        echo "array"
        return
    fi

    if [[ "$root_type" == "object" ]]; then
        # Check if it has a known events array property
        if jq -e 'has("events") and (.events | type == "array")' "$file" >/dev/null 2>&1; then
            echo "object"
            return
        fi
        if jq -e 'has("records") and (.records | type == "array")' "$file" >/dev/null 2>&1; then
            echo "object"
            return
        fi
        if jq -e 'has("data") and (.data | type == "array")' "$file" >/dev/null 2>&1; then
            echo "object"
            return
        fi
        if jq -e 'has("log_entries") and (.log_entries | type == "array")' "$file" >/dev/null 2>&1; then
            echo "object"
            return
        fi
        # Object without a known events array, treat as ndjson (could be first line of NDJSON)
        echo "ndjson"
        return
    fi

    # If jq can't parse it as a single value, it's likely NDJSON
    echo "ndjson"
}

# Count events based on detected format
count_events() {
    local file="$1"
    local format="$2"

    case "$format" in
        "array")
            jq 'length' "$file"
            ;;
        "object")
            jq '(.events // .records // .data // .log_entries) | length' "$file"
            ;;
        "ndjson")
            # Try slurping and counting
            jq -s 'length' "$file"
            ;;
        *)
            echo "0"
            ;;
    esac
}

# Get the events as a JSON array, regardless of input format
get_events_array() {
    local file="$1"
    local format="$2"

    case "$format" in
        "array")
            jq '.' "$file"
            ;;
        "object")
            jq '.events // .records // .data // .log_entries' "$file"
            ;;
        "ndjson")
            # Slurp all lines into a single JSON array
            jq -s '.' "$file"
            ;;
        *)
            echo '[]'
            ;;
    esac
}

# Normalize timestamps in a JSON array (stdin -> stdout)
NORM_FILTER='
    def normalize_ts:
        if type != "string" then .
        elif test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") then .
        elif test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}$") then
            sub("[+-][0-9]{2}:[0-9]{2}$"; "") + "Z"
        elif test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}") then
            . + "Z"
        else
            .
        end;

    if type == "array" then
        [.[] | if type == "object" and .timestamp then .timestamp |= normalize_ts else . end]
    else
        .
    end
'

# ==========================================
# Main script
# ==========================================

echo "[*] Loading Windows events..."

WINDOWS_FORMAT=$(detect_format "$WINDOWS_EVENTS_FILE")
WINDOWS_EVENT_COUNT=$(count_events "$WINDOWS_EVENTS_FILE" "$WINDOWS_FORMAT")
if [[ "$WINDOWS_EVENT_COUNT" == "null" ]] || [[ -z "$WINDOWS_EVENT_COUNT" ]]; then
    WINDOWS_EVENT_COUNT=0
fi

echo "[*] Loading Linux events..."

LINUX_FORMAT=$(detect_format "$LINUX_EVENTS_FILE")
LINUX_EVENT_COUNT=$(count_events "$LINUX_EVENTS_FILE" "$LINUX_FORMAT")
if [[ "$LINUX_EVENT_COUNT" == "null" ]] || [[ -z "$LINUX_EVENT_COUNT" ]]; then
    LINUX_EVENT_COUNT=0
fi

echo ""
echo "[*] Normalizing timestamps to UTC..."

# Create handoff directory
mkdir -p "$HANDOFF_DIR"

# Extract, normalize, and write Windows events
get_events_array "$WINDOWS_EVENTS_FILE" "$WINDOWS_FORMAT" | jq "$NORM_FILTER" > "$HANDOFF_DIR/windows_events.json"
echo "    Windows: $WINDOWS_EVENT_COUNT events normalized"

# Extract, normalize, and write Linux events
get_events_array "$LINUX_EVENTS_FILE" "$LINUX_FORMAT" | jq "$NORM_FILTER" > "$HANDOFF_DIR/linux_events.json"
echo "    Linux: $LINUX_EVENT_COUNT events normalized"

echo ""
echo "[*] Verifying field consistency..."

# Required fields
REQUIRED_FIELDS=("timestamp" "hostname" "source_type" "event_category")

# Check Windows events structure
WINDOWS_VALID=true
if [[ $WINDOWS_EVENT_COUNT -gt 0 ]]; then
    WINDOWS_FIRST_KEYS=$(jq '[.[] | select(type == "object")] | if length > 0 then .[0] | keys else [] end' "$HANDOFF_DIR/windows_events.json" 2>/dev/null || echo '[]')
    for field in "${REQUIRED_FIELDS[@]}"; do
        if ! echo "$WINDOWS_FIRST_KEYS" | grep -q "\"$field\""; then
            echo "    Warning: Missing required field '$field' in Windows events" >&2
            WINDOWS_VALID=false
        fi
    done
fi

# Check Linux events structure
LINUX_VALID=true
if [[ $LINUX_EVENT_COUNT -gt 0 ]]; then
    LINUX_FIRST_KEYS=$(jq '[.[] | select(type == "object")] | if length > 0 then .[0] | keys else [] end' "$HANDOFF_DIR/linux_events.json" 2>/dev/null || echo '[]')
    for field in "${REQUIRED_FIELDS[@]}"; do
        if ! echo "$LINUX_FIRST_KEYS" | grep -q "\"$field\""; then
            echo "    Warning: Missing required field '$field' in Linux events" >&2
            LINUX_VALID=false
        fi
    done
fi

# Determine final status
if [[ "$WINDOWS_VALID" == "true" ]] && [[ "$LINUX_VALID" == "true" ]]; then
    echo "    Required fields present in all events    [OK]"
else
    echo "    Field consistency check had warnings     [WARN]"
fi

echo ""
echo "[*] Combining ground truth..."

# Handle both root arrays and objects with .actions
WINDOWS_GROUND_ACTIONS=$(jq 'if type == "array" then length else (.actions // [] | length) end' "$WINDOWS_GROUND_TRUTH" 2>/dev/null || echo "0")
if [[ "$WINDOWS_GROUND_ACTIONS" == "null" ]] || [[ -z "$WINDOWS_GROUND_ACTIONS" ]]; then
    WINDOWS_GROUND_ACTIONS=0
fi

LINUX_GROUND_ACTIONS=$(jq 'if type == "array" then length else (.actions // [] | length) end' "$LINUX_GROUND_TRUTH" 2>/dev/null || echo "0")
if [[ "$LINUX_GROUND_ACTIONS" == "null" ]] || [[ -z "$LINUX_GROUND_ACTIONS" ]]; then
    LINUX_GROUND_ACTIONS=0
fi

TOTAL_GROUND_ACTIONS=$((WINDOWS_GROUND_ACTIONS + LINUX_GROUND_ACTIONS))

# Extract actions from both files
WINDOWS_ACTIONS=$(jq 'if type == "array" then . else (.actions // []) end' "$WINDOWS_GROUND_TRUTH" 2>/dev/null || echo '[]')
LINUX_ACTIONS=$(jq 'if type == "array" then . else (.actions // []) end' "$LINUX_GROUND_TRUTH" 2>/dev/null || echo '[]')

# Create combined ground truth file
NOW_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg ws "$WINDOWS_GROUND_TRUTH" \
    --arg ls "$LINUX_GROUND_TRUTH" \
    --arg ts "$NOW_TS" \
    --argjson wa "$WINDOWS_ACTIONS" \
    --argjson la "$LINUX_ACTIONS" \
    '{
        combined_metadata: {
            platform: "cross-platform",
            export_timestamp: $ts,
            windows_source: $ws,
            linux_source: $ls
        },
        windows_actions: $wa,
        linux_actions: $la,
        total_actions: ($wa | length) + ($la | length)
    }' > "$HANDOFF_DIR/attack_ground_truth.json"

echo "    Windows actions: $WINDOWS_GROUND_ACTIONS | Linux actions: $LINUX_GROUND_ACTIONS | Total: $TOTAL_GROUND_ACTIONS"

echo ""
echo "[*] Building handoff directory..."

# Calculate file sizes
WINDOWS_BYTES=$(stat -c%s "$HANDOFF_DIR/windows_events.json" 2>/dev/null || stat -f%z "$HANDOFF_DIR/windows_events.json" 2>/dev/null || echo "0")
LINUX_BYTES=$(stat -c%s "$HANDOFF_DIR/linux_events.json" 2>/dev/null || stat -f%z "$HANDOFF_DIR/linux_events.json" 2>/dev/null || echo "0")

# Calculate MB using awk
WINDOWS_MB=$(awk "BEGIN {printf \"%.1f\", $WINDOWS_BYTES / 1048576}")
LINUX_MB=$(awk "BEGIN {printf \"%.1f\", $LINUX_BYTES / 1048576}")

echo ""
echo "telemetry_handoff/"
echo "  windows_events.json           (${WINDOWS_EVENT_COUNT} events, ${WINDOWS_MB} MB)"
echo "  linux_events.json             (${LINUX_EVENT_COUNT} events, ${LINUX_MB} MB)"
echo "  attack_ground_truth.json      ($TOTAL_GROUND_ACTIONS actions)"

# Calculate totals
TOTAL_EVENTS=$((WINDOWS_EVENT_COUNT + LINUX_EVENT_COUNT))

echo ""
echo "Total: $TOTAL_EVENTS events across 2 platforms"
echo ""
echo "[*] Handoff package complete."
