#!/bin/bash
#
# 2-lynis_parse.sh — Parse a Lynis audit .dat report file and produce
#                     machine-readable JSON output.
#
# Input:   Path to lynis-report.dat file ($1)
# Output:  JSON structure on stdout with hardening_index and findings array
# Usage:   ./2-lynis_parse.sh /var/log/lynis-report.dat | jq '.' > lynis_findings.json
#
# ============================================================================
# Project Rules Compliance
# - JSON Output: Produces structured JSON on stdout
# - MedDefense Context: Findings relate to baseline snapshot comparison
# - Delta Support: Hardening index enables before/after security posture comparison
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Validate input
# ---------------------------------------------------------------------------

if [[ $# -lt 1 ]]; then
    echo "ERROR: Usage: $0 <path_to_lynis-report.dat>" >&2
    exit 1
fi

REPORT_FILE="$1"

if [[ ! -f "$REPORT_FILE" ]]; then
    echo "ERROR: Report file not found: $REPORT_FILE" >&2
    exit 1
fi

# Debug: show what we're reading
echo "[DEBUG] Parsing: $REPORT_FILE" >&2
head -20 "$REPORT_FILE" >&2

# ---------------------------------------------------------------------------
# Extract hardening index
# Lynis report format varies: could be hardening_index=XX or hardening_index="XX"
# ---------------------------------------------------------------------------

HARDENING_INDEX=""

# Pattern 1: hardening_index=XX (no quotes)
HARDENING_INDEX=$(grep -E '^hardening_index=' "$REPORT_FILE" 2>/dev/null | \
                  sed 's/hardening_index=//' | tr -d '"' | tr -d "'" | tr -d ' ')

# Default to 0 if not found
if [[ -z "$HARDENING_INDEX" || ! "$HARDENING_INDEX" =~ ^[0-9]+$ ]]; then
    HARDENING_INDEX=0
fi

echo "[DEBUG] Hardening index: $HARDENING_INDEX" >&2

# ---------------------------------------------------------------------------
# Function to escape strings for JSON
# ---------------------------------------------------------------------------

json_escape_string() {
    local str="$1"
    # Escape backslashes first
    str="${str//\\/\\\\}"
    # Escape double quotes
    str="${str//\"/\\\"}"
    # Escape tabs
    str="${str//$'\t'/\\t}"
    # Escape newlines
    str="${str//$'\n'/\\n}"
    # Escape carriage returns
    str="${str//$'\r'/\\r}"
    printf '%s' "$str"
}

# ---------------------------------------------------------------------------
# Parse the report file for warnings, suggestions, manual_check entries
#
# Lynis dat files can store findings in multiple formats:
# 1. Individual array entries: warning[N]="message"
# 2. Test result lines: TEST_ID="STATUS,message"
# 3. Key-value pairs: warning_count=NN, suggestion_count=NN
#
# We'll check multiple formats to ensure we capture everything
# ============================================================================

declare -a FINDINGS_ARRAY=()

# Format 1: Look for warning[N]=, suggestion[N]=, manual_check[N]= patterns
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    # Try warning pattern
    if [[ "$line" =~ ^warning\[([0-9]+)\]= ]]; then
        test_num="${BASH_REMATCH[1]}"
        # Extract message after the = sign, stripping quotes
        message="${line#*=}"
        message="${message#\"}"
        message="${message%\"}"
        message="${message#\'}"
        message="${message%\'}"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            FINDINGS_ARRAY+=("$(printf '{"severity":"warning","test_id":"WARN-%s","message":"%s"}' "$test_num" "$esc_message")")
        fi
    fi

    # Try suggestion pattern
    if [[ "$line" =~ ^suggestion\[([0-9]+)\]= ]]; then
        test_num="${BASH_REMATCH[1]}"
        message="${line#*=}"
        message="${message#\"}"
        message="${message%\"}"
        message="${message#\'}"
        message="${message%\'}"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            FINDINGS_ARRAY+=("$(printf '{"severity":"suggestion","test_id":"SUGG-%s","message":"%s"}' "$test_num" "$esc_message")")
        fi
    fi

    # Try manual_check pattern
    if [[ "$line" =~ ^manual_check\[([0-9]+)\]= ]]; then
        test_num="${BASH_REMATCH[1]}"
        message="${line#*=}"
        message="${message#\"}"
        message="${message%\"}"
        message="${message#\'}"
        message="${message%\'}"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            FINDINGS_ARRAY+=("$(printf '{"severity":"manual_check","test_id":"MANUAL-%s","message":"%s"}' "$test_num" "$esc_message")")
        fi
    fi
done < "$REPORT_FILE"

echo "[DEBUG] Found ${#FINDINGS_ARRAY[@]} findings in array format" >&2

# Format 2: Check for test_result or similar patterns that contain messages
# Some Lynis versions store test results as:
#   test_id_status=message or test_id=STATUS,message
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    # Skip already-captured patterns
    [[ "$line" =~ ^(warning|suggestion|manual_check)\[ ]] && continue

    # Check for lines that might contain test failures/warnings
    # Format: TESTID=status,message
    if [[ "$line" =~ ^[A-Z]{2,}-[0-9]+= ]]; then
        key="${line%%=*}"
        value="${line#*=}"
        # Remove quotes if present
        value="${value#\"}"
        value="${value%\"}"
        value="${value#\'}"
        value="${value%\'}"

        # Determine severity based on key patterns
        severity="suggestion"
        if [[ "$value" == *"warning"* || "$value" == *"FAIL"* || "$value" == *"critical"* ]]; then
            severity="warning"
        elif [[ "$value" == *"manual"* || "$value" == *"check"* ]]; then
            severity="manual_check"
        fi

        if [[ -n "$value" && "$value" != "ok" && "$value" == *" "* ]]; then
            esc_value="$(json_escape_string "$value")"
            FINDINGS_ARRAY+=("$(printf '{"severity":"%s","test_id":"%s","message":"%s"}' "$severity" "$key" "$esc_value")")
        fi
    fi
done < "$REPORT_FILE"

echo "[DEBUG] After test_result parsing: ${#FINDINGS_ARRAY[@]} findings total" >&2

# ---------------------------------------------------------------------------
# Output JSON structure
# ---------------------------------------------------------------------------

echo '{'
echo "  \"hardening_index\": ${HARDENING_INDEX},"
echo '  "findings": ['

first=true
for finding in "${FINDINGS_ARRAY[@]+"${FINDINGS_ARRAY[@]}"}"; do
    if $first; then
        first=false
        echo "    $finding"
    else
        echo "    ,$finding"
    fi
done

echo '  ]'
echo '}'

# ---------------------------------------------------------------------------
# End of script
# ============================================================================

exit 0
