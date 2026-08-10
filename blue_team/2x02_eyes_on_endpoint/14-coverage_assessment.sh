#!/bin/bash
#
# name:        14-coverage_assessment.sh
# purpose:     Produce final telemetry coverage assessment combining handoff data and detection matrices
# author:      Steve - Cybersecurity Engineer
# date:        August 10, 2026
#
# .Purpose
#     This script generates a comprehensive telemetry coverage assessment that the SOC
#     can use to understand detection strengths, weaknesses, and blind spots across
#     Windows and Linux platforms.
#
#     Input files:
#         - telemetry_handoff/windows_events.json
#         - telemetry_handoff/linux_events.json
#         - telemetry_handoff/attack_ground_truth.json
#         - windows_detection_matrix.json
#         - linux_detection_matrix.json
#         - windows_telemetry_quality.json
#         - linux_telemetry_quality.json
#         - sysmon_coverage_matrix.json
#
#     Output:
#         - telemetry_coverage_assessment.json
#
#     The assessment includes event counts by platform/source/category, detection
#     summary, ATT&CK technique coverage, known gaps, and quality scores.
#

set -euo pipefail

# Check for jq
if ! command -v jq &> /dev/null; then
    echo "[ERROR] jq is required. Install with: sudo apt install jq" >&2
    exit 1
fi

# Configuration
HANDOFF_DIR="telemetry_handoff"
WINDOWS_EVENTS="$HANDOFF_DIR/windows_events.json"
LINUX_EVENTS="$HANDOFF_DIR/linux_events.json"
ATTACK_GROUND_TRUTH="$HANDOFF_DIR/attack_ground_truth.json"
WINDOWS_MATRIX="windows_detection_matrix.json"
LINUX_MATRIX="linux_detection_matrix.json"
WINDOWS_QUALITY="windows_telemetry_quality.json"
LINUX_QUALITY="linux_telemetry_quality.json"
SYMON_COVERAGE="sysmon_coverage_matrix.json"
OUTPUT_FILE="telemetry_coverage_assessment.json"

# Verify all required input files exist
MISSING_FILES=()
[[ ! -f "$WINDOWS_EVENTS" ]] && MISSING_FILES+=("$WINDOWS_EVENTS")
[[ ! -f "$LINUX_EVENTS" ]] && MISSING_FILES+=("$LINUX_EVENTS")
[[ ! -f "$ATTACK_GROUND_TRUTH" ]] && MISSING_FILES+=("$ATTACK_GROUND_TRUTH")
[[ ! -f "$WINDOWS_MATRIX" ]] && MISSING_FILES+=("$WINDOWS_MATRIX")
[[ ! -f "$LINUX_MATRIX" ]] && MISSING_FILES+=("$LINUX_MATRIX")
[[ ! -f "$WINDOWS_QUALITY" ]] && MISSING_FILES+=("$WINDOWS_QUALITY")
[[ ! -f "$LINUX_QUALITY" ]] && MISSING_FILES+=("$LINUX_QUALITY")

if [[ ${#MISSING_FILES[@]} -gt 0 ]]; then
    echo "[ERROR] Missing required input files:" >&2
    for file in "${MISSING_FILES[@]}"; do
        echo "  - $file" >&2
    done
    echo >&2
    exit 1
fi

echo "[*] Loading telemetry handoff package..."

# Count events from handoff package
WINDOWS_EVENT_COUNT=$(jq 'if type == "array" then length else (.events // []) | length end' "$WINDOWS_EVENTS" 2>/dev/null || echo "0")
LINUX_EVENT_COUNT=$(jq 'if type == "array" then length else (.events // []) | length end' "$LINUX_EVENTS" 2>/dev/null || echo "0")
TOTAL_EVENTS=$((WINDOWS_EVENT_COUNT + LINUX_EVENT_COUNT))

echo "[*] Analyzing detection matrices..."

# Get detection matrix stats
WINDOWS_CAPTURED=$(jq '[.detection_matrix[] | select(.status == "CAPTURED")] | length' "$WINDOWS_MATRIX" 2>/dev/null || echo "0")
WINDOWS_TOTAL=$(jq '.detection_matrix | length' "$WINDOWS_MATRIX" 2>/dev/null || echo "0")

LINUX_CAPTURED=$(jq '[.detection_matrix[] | select(.status == "CAPTURED")] | length' "$LINUX_MATRIX" 2>/dev/null || echo "0")
LINUX_TOTAL=$(jq '.detection_matrix | length' "$LINUX_MATRIX" 2>/dev/null || echo "0")

TOTAL_CAPTURED=$((WINDOWS_CAPTURED + LINUX_CAPTURED))
TOTAL_DETECTIONS=$((WINDOWS_TOTAL + LINUX_TOTAL))
TOTAL_MISSED=$((TOTAL_DETECTIONS - TOTAL_CAPTURED))

# Count multi-source detections (same action captured by multiple sources)
WINDOWS_MULTI=$(jq '[.detection_matrix | group_by(.action)[] | select(length > 1 and any(.[]; .status == "CAPTURED"))] | length' "$WINDOWS_MATRIX" 2>/dev/null || echo "0")
LINUX_MULTI=$(jq '[.detection_matrix | group_by(.action)[] | select(length > 1 and any(.[]; .status == "CAPTURED"))] | length' "$LINUX_MATRIX" 2>/dev/null || echo "0")
MULTI_SOURCE=$((WINDOWS_MULTI + LINUX_MULTI))

echo "[*] Aggregating ATT&CK coverage..."

# Create temporary files for ATT&CK data
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Extract Windows ATT&CK techniques
jq -r '[.detection_matrix[] | select(.mitre_attack != null and .mitre_attack != "" and .mitre_attack != "-")] |
    group_by(.mitre_attack) |
    map({technique: .[0].mitre_attack, status: (if any(.[]; .status == "CAPTURED") then "covered" else "blind" end)}) |
    if length > 0 then . else [] end' "$WINDOWS_MATRIX" > "$TEMP_DIR/windows_attack.json" 2>/dev/null || echo "[]" > "$TEMP_DIR/windows_attack.json"

# Extract Linux ATT&CK techniques
jq -r '[.detection_matrix[] | select(.mitre_attack != null and .mitre_attack != "" and .mitre_attack != "-")] |
    group_by(.mitre_attack) |
    map({technique: .[0].mitre_attack, status: (if any(.[]; .status == "CAPTURED") then "covered" else "blind" end)}) |
    if length > 0 then . else [] end' "$LINUX_MATRIX" > "$TEMP_DIR/linux_attack.json" 2>/dev/null || echo "[]" > "$TEMP_DIR/linux_attack.json"

# Validate and merge
VALID_WIN=$(jq '.' "$TEMP_DIR/windows_attack.json" 2>/dev/null || echo "[]")
VALID_LIN=$(jq '.' "$TEMP_DIR/linux_attack.json" 2>/dev/null || echo "[]")

ATTACK_COVERAGE=$(jq -n --argjson w "$VALID_WIN" --argjson l "$VALID_LIN" '($w + $l) |
    group_by(.technique) |
    map({
        technique: .[0].technique,
        status: (if any(.[]; .status == "covered") then "covered" else "partial" end),
        sources: [.[].source?] | flatten | unique
    })')

COVERED_COUNT=$(echo "$ATTACK_COVERAGE" | jq '[.[] | select(.status == "covered")] | length')
PARTIAL_COUNT=$(echo "$ATTACK_COVERAGE" | jq '[.[] | select(.status == "partial")] | length')
BLIND_COUNT=$(echo "$ATTACK_COVERAGE" | jq '[.[] | select(.status == "blind")] | length')

echo "[*] Evaluating quality scores..."

# Extract quality scores - check all known nested locations
WINDOWS_SCORE=$(jq -r '
    if .quality_score.score then .quality_score.score
    elif .summary.quality_score then .summary.quality_score
    elif .score then .score
    elif .quality_score | type == "number" then .quality_score
    else 0 end
' "$WINDOWS_QUALITY" 2>/dev/null || echo "0")

LINUX_SCORE=$(jq -r '
    if .quality_score.score then .quality_score.score
    elif .summary.quality_score then .summary.quality_score
    elif .score then .score
    elif .quality_score | type == "number" then .quality_score
    else 0 end
' "$LINUX_QUALITY" 2>/dev/null || echo "0")

# Handle both numeric and percentage formats
WINDOWS_SCORE=$(echo "$WINDOWS_SCORE" | sed 's/%//' | tr -d ' ')
LINUX_SCORE=$(echo "$LINUX_SCORE" | sed 's/%//' | tr -d ' ')

# Ensure they are valid numbers
if ! [[ "$WINDOWS_SCORE" =~ ^[0-9]+\.?[0-9]*$ ]]; then
    WINDOWS_SCORE="0"
fi
if ! [[ "$LINUX_SCORE" =~ ^[0-9]+\.?[0-9]*$ ]]; then
    LINUX_SCORE="0"
fi

# Calculate overall confidence
AVG_SCORE=$(awk "BEGIN {printf \"%.1f\", ($WINDOWS_SCORE + $LINUX_SCORE) / 2}")

if (( $(echo "$AVG_SCORE >= 90" | bc -l 2>/dev/null || echo 0) )); then
    CONFIDENCE="high"
elif (( $(echo "$AVG_SCORE >= 80" | bc -l 2>/dev/null || echo 0) )); then
    CONFIDENCE="acceptable"
elif (( $(echo "$AVG_SCORE >= 70" | bc -l 2>/dev/null || echo 0) )); then
    CONFIDENCE="moderate"
else
    CONFIDENCE="low"
fi

echo "[*] Identifying known gaps..."

# Identify gaps from detection matrices
WINDOW_GAPS=$(jq '[.detection_matrix[] | select(.status == "MISSING") | {
    description: ("Missing detection for: " + .action),
    platform: "Windows",
    technique: (.mitre_attack // "Unknown"),
    source: (.source // "Unknown"),
    reason: "Event not captured within time window",
    recommendation: ("Enable or tune logging for " + .source)
}] // []' "$WINDOWS_MATRIX" 2>/dev/null || echo "[]")

LINUX_GAPS=$(jq '[.detection_matrix[] | select(.status == "MISSING") | {
    description: ("Missing detection for: " + .action),
    platform: "Linux",
    technique: (.mitre_attack // "Unknown"),
    source: (.source // "Unknown"),
    reason: "Event not captured within time window",
    recommendation: ("Enable or tune audit rules for " + .audit_key)
}] // []' "$LINUX_MATRIX" 2>/dev/null || echo "[]")

# Combine gaps
GAPS_JSON=$(jq -n --argjson wg "$WINDOW_GAPS" --argjson lg "$LINUX_GAPS" '$wg + $lg')
GAP_COUNT=$(echo "$GAPS_JSON" | jq 'length')

echo "[*] Calculating event breakdown by platform and source..."

# Count Windows events by source type and category
WINDOWS_BY_SOURCE=$(jq '[if type == "array" then .[] else .events[] end] | group_by(.source_type) | map({source: .[0].source_type, count: length})' "$WINDOWS_EVENTS" 2>/dev/null || echo '[]')
WINDOWS_BY_CATEGORY=$(jq '[if type == "array" then .[] else .events[] end] | group_by(.event_category) | map({category: .[0].event_category, count: length})' "$WINDOWS_EVENTS" 2>/dev/null || echo '[]')

# Count Linux events by source type and category
LINUX_BY_SOURCE=$(jq '[if type == "array" then .[] else .events[] end] | group_by(.source_type) | map({source: .[0].source_type, count: length})' "$LINUX_EVENTS" 2>/dev/null || echo '[]')
LINUX_BY_CATEGORY=$(jq '[if type == "array" then .[] else .events[] end] | group_by(.event_category) | map({category: .[0].event_category, count: length})' "$LINUX_EVENTS" 2>/dev/null || echo '[]')

echo "[*] Generating coverage assessment report..."

# Generate the final assessment JSON
NOW_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

jq -n \
    --arg ts "$NOW_TS" \
    --argjson win_events "$WINDOWS_EVENT_COUNT" \
    --argjson lin_events "$LINUX_EVENT_COUNT" \
    --argjson total_events "$TOTAL_EVENTS" \
    --argjson win_by_source "$WINDOWS_BY_SOURCE" \
    --argjson win_by_category "$WINDOWS_BY_CATEGORY" \
    --argjson lin_by_source "$LINUX_BY_SOURCE" \
    --argjson lin_by_category "$LINUX_BY_CATEGORY" \
    --argjson total_actions "$TOTAL_DETECTIONS" \
    --argjson captured "$TOTAL_CAPTURED" \
    --argjson missed "$TOTAL_MISSED" \
    --argjson multi "$MULTI_SOURCE" \
    --argjson attack_coverage "$ATTACK_COVERAGE" \
    --argjson covered "$COVERED_COUNT" \
    --argjson partial "$PARTIAL_COUNT" \
    --argjson blind "$BLIND_COUNT" \
    --argjson gaps "$GAPS_JSON" \
    --argjson win_score "$WINDOWS_SCORE" \
    --argjson lin_score "$LINUX_SCORE" \
    --arg avg_score "$AVG_SCORE" \
    --arg confidence "$CONFIDENCE" \
    '{
        assessment_metadata: {
            generated_at: $ts,
            version: "1.0",
            assessor: "Blue Team Automation"
        },
        event_counts: {
            total_events: $total_events,
            by_platform: {
                windows: $win_events,
                linux: $lin_events
            },
            by_source_type: {
                windows: $win_by_source,
                linux: $lin_by_source
            },
            by_event_category: {
                windows: $win_by_category,
                linux: $lin_by_category
            }
        },
        detection_summary: {
            total_simulated_actions: $total_actions,
            captured_actions: $captured,
            missed_actions: $missed,
            multi_source_detections: $multi,
            capture_rate_percent: (if $total_actions > 0 then (($captured / $total_actions) * 100 | floor) else 0 end)
        },
        attack_technique_coverage: {
            covered_techniques: $covered,
            partially_covered_techniques: $partial,
            blind_techniques: $blind,
            techniques: $attack_coverage
        },
        known_gaps: {
            total_gaps: ($gaps | length),
            gaps: $gaps
        },
        quality_summary: {
            windows_score: $win_score,
            linux_score: $lin_score,
            average_score: ($avg_score | tonumber),
            handoff_confidence: $confidence,
            scoring_criteria: {
                high: "Score >= 90%",
                acceptable: "Score >= 80%",
                moderate: "Score >= 70%",
                low: "Score < 70%"
            }
        },
        recommendations: {
            immediate: "Review missed detections and tune alerting rules",
            short_term: "Implement additional logging for blind ATT&CK techniques",
            long_term: "Deploy EDR/XDR agents for enhanced visibility across platforms"
        }
    }' > "$OUTPUT_FILE"

# Display summary
echo ""
echo "=== TELEMETRY COVERAGE ASSESSMENT SUMMARY ==="
echo ""
echo "Total Events:"
echo "  Windows: $WINDOWS_EVENT_COUNT"
echo "  Linux:   $LINUX_EVENT_COUNT"
echo "  Combined: $TOTAL_EVENTS"
echo ""
echo "Detection Matrix:"
echo "  Simulated Actions: $TOTAL_DETECTIONS"
echo "  Captured:          $TOTAL_CAPTURED"
echo "  Missed:            $TOTAL_MISSED"
echo "  Multi-Source:      $MULTI_SOURCE"
echo ""
echo "ATT&CK Coverage:"
echo "  Covered:  $COVERED_COUNT"
echo "  Partial:  $PARTIAL_COUNT"
echo "  Blind:    $BLIND_COUNT"
echo ""
echo "Quality Scores:"
echo "  Windows: $WINDOWS_SCORE"
echo "  Linux:   $LINUX_SCORE"
echo "  Average: $AVG_SCORE"
echo ""
echo "Confidence Level: $CONFIDENCE"
echo ""
echo "Report saved to: $OUTPUT_FILE"
echo "[*] Coverage assessment complete."
