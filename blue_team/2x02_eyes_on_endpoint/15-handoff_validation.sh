#!/bin/bash
#
# name:        15-handoff_validation.sh
# purpose:     Validate the telemetry handoff package against quality gates for SOC consumption
# author:      Steve - Cybersecurity Engineer
# date:        August 10, 2026
#
# .Purpose
#     This script validates the telemetry_handoff/ directory to ensure it is ready
#     for analyst consumption in Module 3. It performs the following checks:
#
#         1. File existence: all 3 expected files present
#         2. JSON validity: each file parses without errors
#         3. Required fields: every event has timestamp, hostname, source_type, event_category
#         4. Minimum event counts: Windows >= 1000, Linux >= 500, ground truth >= 10
#         5. Timestamp consistency: valid ISO 8601, no future timestamps
#         6. Cross-platform alignment: timestamp ranges overlap
#         7. Ground truth completeness: every action has a detection matrix entry
#
#     Output: handoff_validation.json with PASS/FAIL per check and final verdict
#

set -euo pipefail

# Check for jq
if ! command -v jq &> /dev/null; then
    echo "[ERROR] jq is required. Install with: sudo apt install jq" >&2
    exit 1
fi

# Configuration
HANDOFF_DIR="telemetry_handoff"
WINDOWS_FILE="$HANDOFF_DIR/windows_events.json"
LINUX_FILE="$HANDOFF_DIR/linux_events.json"
GROUND_TRUTH_FILE="$HANDOFF_DIR/attack_ground_truth.json"
WINDOWS_MATRIX="windows_detection_matrix.json"
LINUX_MATRIX="linux_detection_matrix.json"
OUTPUT_FILE="handoff_validation.json"

MIN_WINDOWS_EVENTS=1000
MIN_LINUX_EVENTS=500
MIN_GROUND_TRUTH=10

PASS_COUNT=0
FAIL_COUNT=0
CHECKS_JSON='[]'

# Helper functions
pass_check() {
    local name="$1"
    local detail="$2"
    echo "[PASS] $detail"
    PASS_COUNT=$((PASS_COUNT + 1))
    CHECKS_JSON=$(jq -n --argjson arr "$CHECKS_JSON" --arg n "$name" --arg s "PASS" --arg d "$detail" \
        '$arr + [{check: $n, status: $s, detail: $d}]')
}

fail_check() {
    local name="$1"
    local detail="$2"
    echo "[FAIL] $detail"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    CHECKS_JSON=$(jq -n --argjson arr "$CHECKS_JSON" --arg n "$name" --arg s "FAIL" --arg d "$detail" \
        '$arr + [{check: $n, status: $s, detail: $d}]')
}

get_size_kb() {
    local file="$1"
    local bytes
    bytes=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo "0")
    echo $((bytes / 1024))
}

# Helper: extract events array from file (handles array or object with .events)
get_events_count() {
    local file="$1"
    jq 'if type == "array" then length else (.events // []) | length end' "$file" 2>/dev/null || echo "0"
}

echo "[*] Validating $HANDOFF_DIR/ ..."

# ==========================================
# 1. File Existence
# ==========================================
echo "=== File Existence ==="

if [[ -f "$WINDOWS_FILE" ]]; then
    SIZE_KB=$(get_size_kb "$WINDOWS_FILE")
    SIZE_MB_INT=$((SIZE_KB / 1024))
    SIZE_MB_FRAC=$(( (SIZE_KB % 1024 * 100) / 1024 ))
    pass_check "file_existence_windows" "windows_events.json exists (${SIZE_MB_INT}.${SIZE_MB_FRAC} MB)"
else
    fail_check "file_existence_windows" "windows_events.json missing"
fi

if [[ -f "$LINUX_FILE" ]]; then
    SIZE_KB=$(get_size_kb "$LINUX_FILE")
    SIZE_MB_INT=$((SIZE_KB / 1024))
    SIZE_MB_FRAC=$(( (SIZE_KB % 1024 * 100) / 1024 ))
    pass_check "file_existence_linux" "linux_events.json exists (${SIZE_MB_INT}.${SIZE_MB_FRAC} MB)"
else
    fail_check "file_existence_linux" "linux_events.json missing"
fi

if [[ -f "$GROUND_TRUTH_FILE" ]]; then
    SIZE_KB=$(get_size_kb "$GROUND_TRUTH_FILE")
    pass_check "file_existence_ground_truth" "attack_ground_truth.json exists ($SIZE_KB KB)"
else
    fail_check "file_existence_ground_truth" "attack_ground_truth.json missing"
fi

# If any file missing, can't continue meaningfully
if [[ ! -f "$WINDOWS_FILE" ]] || [[ ! -f "$LINUX_FILE" ]] || [[ ! -f "$GROUND_TRUTH_FILE" ]]; then
    echo ""
    TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT))
    echo "VERDICT: FAIL ($PASS_COUNT/$TOTAL_CHECKS checks)"
    echo "Cannot continue validation with missing files."
    exit 1
fi

# ==========================================
# 2. JSON Validity
# ==========================================
echo "=== JSON Validity ==="

WINDOWS_OBJ_COUNT=$(get_events_count "$WINDOWS_FILE")
if jq -e '.' "$WINDOWS_FILE" >/dev/null 2>&1 && [[ "$WINDOWS_OBJ_COUNT" != "0" ]]; then
    pass_check "json_validity_windows" "windows_events.json: valid JSON, $WINDOWS_OBJ_COUNT objects"
else
    fail_check "json_validity_windows" "windows_events.json: invalid JSON or 0 objects"
    WINDOWS_OBJ_COUNT=0
fi

LINUX_OBJ_COUNT=$(get_events_count "$LINUX_FILE")
if jq -e '.' "$LINUX_FILE" >/dev/null 2>&1 && [[ "$LINUX_OBJ_COUNT" != "0" ]]; then
    pass_check "json_validity_linux" "linux_events.json: valid JSON, $LINUX_OBJ_COUNT objects"
else
    fail_check "json_validity_linux" "linux_events.json: invalid JSON or 0 objects"
    LINUX_OBJ_COUNT=0
fi

# Ground truth count
GT_TOTAL_ACTIONS=$(jq '
    if .total_actions then .total_actions
    elif (.windows_actions // []) + (.linux_actions // []) then ((.windows_actions // []) | length) + ((.linux_actions // []) | length)
    else 0 end
' "$GROUND_TRUTH_FILE" 2>/dev/null || echo "0")

if [[ "$GT_TOTAL_ACTIONS" == "null" ]] || [[ -z "$GT_TOTAL_ACTIONS" ]]; then
    GT_TOTAL_ACTIONS=0
fi

if jq -e '.' "$GROUND_TRUTH_FILE" >/dev/null 2>&1 && [[ "$GT_TOTAL_ACTIONS" -gt 0 ]]; then
    pass_check "json_validity_ground_truth" "attack_ground_truth.json: valid JSON, $GT_TOTAL_ACTIONS objects"
else
    fail_check "json_validity_ground_truth" "attack_ground_truth.json: invalid JSON or 0 objects"
fi

# ==========================================
# 3. Required Fields
# ==========================================
echo "=== Required Fields ==="

REQUIRED_FIELDS="timestamp hostname source_type event_category"

# Check Windows required fields
WIN_FIELDS_OK=true
for field in $REQUIRED_FIELDS; do
    WIN_MISSING=$(jq --arg f "$field" '[if type == "array" then .[] else (.events // [])[] end | select(has($f) | not)] | length' "$WINDOWS_FILE" 2>/dev/null || echo "999")
    if [[ "$WIN_MISSING" != "0" ]]; then
        WIN_FIELDS_OK=false
        FIELD_NAME="$field"
        break
    fi
done

# Check Linux required fields
LIN_FIELDS_OK=true
for field in $REQUIRED_FIELDS; do
    LIN_MISSING=$(jq --arg f "$field" '[if type == "array" then .[] else (.events // [])[] end | select(has($f) | not)] | length' "$LINUX_FILE" 2>/dev/null || echo "999")
    if [[ "$LIN_MISSING" != "0" ]]; then
        LIN_FIELDS_OK=false
        FIELD_NAME="$field"
        break
    fi
done

if [[ "$WIN_FIELDS_OK" == "true" && "$LIN_FIELDS_OK" == "true" ]]; then
    pass_check "required_fields" "All events have timestamp, hostname, source_type, event_category"
else
    if [[ "$WIN_FIELDS_OK" != "true" ]]; then
        fail_check "required_fields" "Windows events missing required field: $FIELD_NAME"
    elif [[ "$LIN_FIELDS_OK" != "true" ]]; then
        fail_check "required_fields" "Linux events missing required field: $FIELD_NAME"
    fi
fi

# ==========================================
# 4. Minimum Event Counts
# ==========================================
echo "=== Minimum Event Counts ==="

if [[ $WINDOWS_OBJ_COUNT -ge $MIN_WINDOWS_EVENTS ]]; then
    pass_check "min_events_windows" "Windows: $WINDOWS_OBJ_COUNT >= $MIN_WINDOWS_EVENTS"
else
    fail_check "min_events_windows" "Windows: $WINDOWS_OBJ_COUNT < $MIN_WINDOWS_EVENTS (need $MIN_WINDOWS_EVENTS)"
fi

if [[ $LINUX_OBJ_COUNT -ge $MIN_LINUX_EVENTS ]]; then
    pass_check "min_events_linux" "Linux: $LINUX_OBJ_COUNT >= $MIN_LINUX_EVENTS"
else
    fail_check "min_events_linux" "Linux: $LINUX_OBJ_COUNT < $MIN_LINUX_EVENTS (need $MIN_LINUX_EVENTS)"
fi

if [[ $GT_TOTAL_ACTIONS -ge $MIN_GROUND_TRUTH ]]; then
    pass_check "min_events_ground_truth" "Ground truth: $GT_TOTAL_ACTIONS >= $MIN_GROUND_TRUTH"
else
    fail_check "min_events_ground_truth" "Ground truth: $GT_TOTAL_ACTIONS < $MIN_GROUND_TRUTH (need $MIN_GROUND_TRUTH)"
fi

# ==========================================
# 5. Timestamp Consistency
# ==========================================
echo "=== Timestamp Consistency ==="

# Check all timestamps are valid ISO 8601 in Windows using jq
WIN_TS_INVALID=$(jq '
    def is_valid_ts:
        type == "string" and (test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") or
                              test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}$"));
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(. != null and (is_valid_ts | not))] | length
' "$WINDOWS_FILE" 2>/dev/null || echo "0")

# Check all timestamps are valid ISO 8601 in Linux using jq
LIN_TS_INVALID=$(jq '
    def is_valid_ts:
        type == "string" and (test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$") or
                              test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}$"));
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(. != null and (is_valid_ts | not))] | length
' "$LINUX_FILE" 2>/dev/null || echo "0")

if [[ "$WIN_TS_INVALID" == "null" ]] || [[ -z "$WIN_TS_INVALID" ]]; then
    WIN_TS_INVALID=0
fi
if [[ "$LIN_TS_INVALID" == "null" ]] || [[ -z "$LIN_TS_INVALID" ]]; then
    LIN_TS_INVALID=0
fi

TOTAL_TS_INVALID=$((WIN_TS_INVALID + LIN_TS_INVALID))

if [[ $TOTAL_TS_INVALID -eq 0 ]]; then
    pass_check "timestamp_format" "All timestamps valid ISO 8601"
else
    fail_check "timestamp_format" "Found $TOTAL_TS_INVALID invalid timestamps"
fi

# Check for future timestamps
NOW_EPOCH=$(date -u +%s)

# Count future timestamps in Windows
WIN_FUTURE=$(jq --argjson now "$NOW_EPOCH" '
    def is_future:
        if type != "string" then false
        else
            (.[:-1] // .) | gsub("Z$"; "") | gsub("[+-][0-9]{2}:[0-9]{2}$"; "") |
            try (fromdateiso8601) catch 0 > $now
        end;
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(is_future)] | length
' "$WINDOWS_FILE" 2>/dev/null || echo "0")

# Count future timestamps in Linux
LIN_FUTURE=$(jq --argjson now "$NOW_EPOCH" '
    def is_future:
        if type != "string" then false
        else
            (.[:-1] // .) | gsub("Z$"; "") | gsub("[+-][0-9]{2}:[0-9]{2}$"; "") |
            try (fromdateiso8601) catch 0 > $now
        end;
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(is_future)] | length
' "$LINUX_FILE" 2>/dev/null || echo "0")

if [[ "$WIN_FUTURE" == "null" ]] || [[ -z "$WIN_FUTURE" ]]; then
    WIN_FUTURE=0
fi
if [[ "$LIN_FUTURE" == "null" ]] || [[ -z "$LIN_FUTURE" ]]; then
    LIN_FUTURE=0
fi

TOTAL_FUTURE=$((WIN_FUTURE + LIN_FUTURE))

if [[ $TOTAL_FUTURE -eq 0 ]]; then
    pass_check "no_future_timestamps" "No future timestamps"
else
    fail_check "no_future_timestamps" "Found $TOTAL_FUTURE future timestamps"
fi

# Get timestamp ranges for Windows
WINDOWS_MIN_TS=$(jq -r '
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(type == "string")] | sort | .[0] // "N/A"
' "$WINDOWS_FILE" 2>/dev/null || echo "N/A")

WINDOWS_MAX_TS=$(jq -r '
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(type == "string")] | sort | .[-1] // "N/A"
' "$WINDOWS_FILE" 2>/dev/null || echo "N/A")

# Get timestamp ranges for Linux
LINUX_MIN_TS=$(jq -r '
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(type == "string")] | sort | .[0] // "N/A"
' "$LINUX_FILE" 2>/dev/null || echo "N/A")

LINUX_MAX_TS=$(jq -r '
    [if type == "array" then .[] else (.events // [])[] end | .timestamp | select(type == "string")] | sort | .[-1] // "N/A"
' "$LINUX_FILE" 2>/dev/null || echo "N/A")

# Report range
if [[ "$WINDOWS_MIN_TS" != "N/A" ]] && [[ "$WINDOWS_MAX_TS" != "N/A" ]]; then
    pass_check "timestamp_range" "Range: $WINDOWS_MIN_TS to $WINDOWS_MAX_TS"
else
    fail_check "timestamp_range" "Could not determine timestamp range"
fi

# ==========================================
# 6. Cross-Platform Alignment
# ==========================================
echo "=== Cross-Platform Alignment ==="

if [[ "$WINDOWS_MIN_TS" != "N/A" && "$WINDOWS_MAX_TS" != "N/A" && "$LINUX_MIN_TS" != "N/A" && "$LINUX_MAX_TS" != "N/A" ]]; then
    # Convert to epochs for comparison
    WIN_MIN_EPOCH=$(date -u -d "${WINDOWS_MIN_TS%Z}" +%s 2>/dev/null || echo "0")
    WIN_MAX_EPOCH=$(date -u -d "${WINDOWS_MAX_TS%Z}" +%s 2>/dev/null || echo "0")
    LIN_MIN_EPOCH=$(date -u -d "${LINUX_MIN_TS%Z}" +%s 2>/dev/null || echo "0")
    LIN_MAX_EPOCH=$(date -u -d "${LINUX_MAX_TS%Z}" +%s 2>/dev/null || echo "0")

    # Check for overlap: max(start1, start2) < min(end1, end2)
    if [[ $WIN_MIN_EPOCH -gt $LIN_MIN_EPOCH ]]; then
        OVERLAP_START=$WIN_MIN_EPOCH
    else
        OVERLAP_START=$LIN_MIN_EPOCH
    fi

    if [[ $WIN_MAX_EPOCH -lt $LIN_MAX_EPOCH ]]; then
        OVERLAP_END=$WIN_MAX_EPOCH
    else
        OVERLAP_END=$LIN_MAX_EPOCH
    fi

    if [[ $OVERLAP_START -lt $OVERLAP_END ]]; then
        OVERLAP_HOURS=$(( (OVERLAP_END - OVERLAP_START) / 3600 ))
        pass_check "cross_platform_alignment" "Windows and Linux time ranges overlap ($OVERLAP_HOURS hours shared)"
    else
        fail_check "cross_platform_alignment" "Windows and Linux time ranges do not overlap"
    fi
else
    fail_check "cross_platform_alignment" "Insufficient data to determine time ranges"
fi

# ==========================================
# 7. Ground Truth Completeness
# ==========================================
echo "=== Ground Truth Completeness ==="

GT_MATCHED=0
GT_TOTAL=0

# Get all ground truth action descriptions
ALL_GT_ACTIONS=$(jq -r '
    ([.windows_actions[], .linux_actions[]] | .[] | .description // empty)
' "$GROUND_TRUTH_FILE" 2>/dev/null || echo "")

if [[ -z "$ALL_GT_ACTIONS" ]]; then
    # Try alternate structure
    ALL_GT_ACTIONS=$(jq -r '.actions[] | .description // empty' "$GROUND_TRUTH_FILE" 2>/dev/null || echo "")
fi

if [[ -n "$ALL_GT_ACTIONS" ]]; then
    GT_TOTAL=$(echo "$ALL_GT_ACTIONS" | grep -c . || echo "0")
    GT_MATCHED=0

    # Check each ground truth action against detection matrices
    while IFS= read -r action_desc; do
        [[ -z "$action_desc" ]] && continue
        # Check if this action appears in either detection matrix
        WIN_MATCH=$(jq --arg a "$action_desc" '[.detection_matrix[] | select(.action == $a)] | length' "$WINDOWS_MATRIX" 2>/dev/null || echo "0")
        LIN_MATCH=$(jq --arg a "$action_desc" '[.detection_matrix[] | select(.action == $a)] | length' "$LINUX_MATRIX" 2>/dev/null || echo "0")

        if [[ "$WIN_MATCH" -gt 0 ]] || [[ "$LIN_MATCH" -gt 0 ]]; then
            GT_MATCHED=$((GT_MATCHED + 1))
        fi
    done <<< "$ALL_GT_ACTIONS"
fi

if [[ $GT_TOTAL -gt 0 ]] && [[ $GT_MATCHED -eq $GT_TOTAL ]]; then
    pass_check "ground_truth_completeness" "$GT_MATCHED/$GT_TOTAL actions have detection matrix entries"
else
    fail_check "ground_truth_completeness" "$GT_MATCHED/$GT_TOTAL actions have detection matrix entries"
fi

# ==========================================
# Final Verdict
# ==========================================
TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT))

echo ""
if [[ $FAIL_COUNT -eq 0 ]]; then
    echo "VERDICT: PASS ($PASS_COUNT/$TOTAL_CHECKS checks)"
    echo "Handoff package is ready for Module 3."
    FINAL_VERDICT="PASS"
else
    echo "VERDICT: FAIL ($PASS_COUNT/$TOTAL_CHECKS checks)"
    echo "Handoff package requires attention before proceeding."
    FINAL_VERDICT="FAIL"
fi

# Save validation report
NOW_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg ts "$NOW_TS" \
    --arg verdict "$FINAL_VERDICT" \
    --argjson pass "$PASS_COUNT" \
    --argjson fail "$FAIL_COUNT" \
    --argjson total "$TOTAL_CHECKS" \
    --argjson checks "$CHECKS_JSON" \
    '{
        validation_timestamp: $ts,
        verdict: $verdict,
        checks_passed: $pass,
        checks_failed: $fail,
        total_checks: $total,
        checks: $checks
    }' > "$OUTPUT_FILE"

echo "Report saved to: $OUTPUT_FILE"
