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

# ---------------------------------------------------------------------------
# Extract hardening index
# ============================================================================

HARDENING_INDEX=""

while IFS='=' read -r key value; do
    if [[ "$key" =~ ^hardening_index$ ]]; then
        HARDENING_INDEX="${value//\"/}"
        HARDENING_INDEX="${HARDENING_INDEX//\'/}"
        HARDENING_INDEX="${HARDENING_INDEX// /}"
        break
    fi
done < <(grep -E '^hardening_index' "$REPORT_FILE" 2>/dev/null || true)

if [[ -z "$HARDENING_INDEX" || ! "$HARDENING_INDEX" =~ ^[0-9]+$ ]]; then
    HARDENING_INDEX=0
fi

# ---------------------------------------------------------------------------
# Function to escape strings for JSON
# ============================================================================

json_escape_string() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\t'/\\t}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    printf '%s' "$str"
}

# ---------------------------------------------------------------------------
# Collect all findings
# ============================================================================

declare -a FINDINGS_ARRAY=()

# ============================================================================
# Lynis Format: suggestion[]=TEST_ID|MESSAGE|extra_fields|extra_fields
# ============================================================================

# Parse suggestions
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    # Extract content after suggestion[]=
    if [[ "$line" =~ ^suggestion\[]=[^\|]+\|(.+) ]]; then
        full_content="${BASH_REMATCH[1]}"

        # Split by pipe - first field is test_id, second field is message
        IFS='|' read -r test_id message _ _ <<< "$full_content"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            FINDINGS_ARRAY+=("{\"severity\":\"suggestion\",\"test_id\":\"${test_id}\",\"message\":\"${esc_message}\"}")
        fi
    fi
done < <(grep -E '^suggestion\[\]=' "$REPORT_FILE" 2>/dev/null || true)

# Parse warnings
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" =~ ^warning\[]=[^\|]+\|(.+) ]]; then
        full_content="${BASH_REMATCH[1]}"

        IFS='|' read -r test_id message _ _ <<< "$full_content"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            FINDINGS_ARRAY+=("{\"severity\":\"warning\",\"test_id\":\"${test_id}\",\"message\":\"${esc_message}\"}")
        fi
    fi
done < <(grep -E '^warning\[\]=' "$REPORT_FILE" 2>/dev/null || true)

# Parse manual_check
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" =~ ^manual_check\[]=[^\|]+\|(.+) ]]; then
        full_content="${BASH_REMATCH[1]}"

        IFS='|' read -r test_id message _ _ <<< "$full_content"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            FINDINGS_ARRAY+=("{\"severity\":\"manual_check\",\"test_id\":\"${test_id}\",\"message\":\"${esc_message}\"}")
        fi
    fi
done < <(grep -E '^manual_check\[\]=' "$REPORT_FILE" 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Output JSON structure
# ============================================================================

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

exit 0
