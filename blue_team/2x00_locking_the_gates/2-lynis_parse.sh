#!/bin/bash
#
# 2-lynis_parse.sh — Run Lynis audit, parse the .dat report file, and produce
#                     machine-readable JSON output.
#
# Usage:   ./2-lynis_parse.sh [--debug]
# Output:  lynis_findings.json (automatically saved via jq)
# ============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEBUG="${1:-false}"
DEBUG_MODE=false
[[ "$DEBUG" == "--debug" ]] && DEBUG_MODE=true

LYNIS_PATH="/usr/sbin/lynis"
LYNIS_LOG_DEFAULT="/var/log/lynis.log"
LYNIS_DAT_DEFAULT="/var/log/lynis-report.dat"

# If not root, warn about potential issues
if [[ $EUID -ne 0 ]]; then
    echo "WARNING: Running without root may limit Lynis coverage." >&2
    echo "         Consider running with: sudo $0" >&2
fi

# ---------------------------------------------------------------------------
# Helper: sanitize numeric output
# ---------------------------------------------------------------------------

sanitize_int() {
    local val="$1"
    val="${val//[^0-9]/}"
    [[ -z "$val" ]] && val="0"
    printf '%s' "$val"
}

# ---------------------------------------------------------------------------
# Step 1: Locate Lynis binary
# ---------------------------------------------------------------------------

echo "[*] Locating Lynis..."

if [[ -x "$LYNIS_PATH" ]]; then
    echo "    Lynis found at: $LYNIS_PATH"
elif command -v lynis &>/dev/null; then
    LYNIS_PATH=$(command -v lynis)
    echo "    Lynis found at: $LYNIS_PATH"
else
    echo "    ERROR: Lynis not found. Install with: apt-get install lynis" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1b: Ensure report file exists before proceeding
# ---------------------------------------------------------------------------

if [[ ! -f "$LYNIS_DAT_DEFAULT" ]]; then
    echo "    Report file not found, running Lynis to generate..."
    "$LYNIS_PATH" audit system >/dev/null 2>&1 || true
    sleep 2
fi

# ---------------------------------------------------------------------------
# Step 2: Run Lynis audit
# ---------------------------------------------------------------------------

echo ""
echo "[*] Running Lynis audit system scan..."

# Lynis typically outputs to /var/log/lynis.log and /var/log/lynis-report.dat
# The report path may vary depending on version/configuration
"$LYNIS_PATH" audit system --quiet 2>&1 | tail -20 || true

# Wait a moment for files to be flushed
sleep 2

# ---------------------------------------------------------------------------
# Step 3: Locate the .dat file
# ---------------------------------------------------------------------------

echo ""
echo "[*] Locating Lynis .dat report file..."

DAT_FILE=""

# Try common locations first
for candidate in "$LYNIS_DAT_DEFAULT" "/var/log/lynis-report.dat"; do
    if [[ -f "$candidate" ]]; then
        DAT_FILE="$candidate"
        echo "    Found: $DAT_FILE"
        break
    fi
done

# Search more broadly if not found
if [[ -z "$DAT_FILE" ]]; then
    DAT_FILE=$(find /var/log -name "*lynis*report*.dat" -type f 2>/dev/null | head -1 || true)
fi

if [[ -z "$DAT_FILE" ]]; then
    echo "    ERROR: Could not find lynis-report.dat file" >&2

    if $DEBUG_MODE; then
        echo "    DEBUG: Checking if log file exists instead..."
        if [[ -f "$LYNIS_LOG_DEFAULT" ]]; then
            echo "    Log file exists: $LYNIS_LOG_DEFAULT"
            echo "    Note: This appears to be a log file, not the .dat report." >&2
            echo "    You may need to check Lynis configuration for report output path." >&2
        fi
    fi

    exit 1
fi

# ---------------------------------------------------------------------------
# Step 4: Validate .dat file format
# ---------------------------------------------------------------------------

if $DEBUG_MODE; then
    echo ""
    echo "--- DEBUG: File inspection ---"
    echo "File type: $(file "$DAT_FILE" 2>/dev/null || echo 'unknown')"
    echo "Line count: $(wc -l < "$DAT_FILE" 2>/dev/null || echo '0')"
    echo "First 5 lines:"
    head -5 "$DAT_FILE" 2>/dev/null || true
    echo "--- END DEBUG ---"
fi

# ---------------------------------------------------------------------------
# Step 5: Extract hardening index
# ============================================================================

HARDENING_INDEX=""

# Primary extraction: grep the key=value pair directly
RAW_INDEX=$(grep -oE 'hardening_index=[0-9]+' "$DAT_FILE" 2>/dev/null | cut -d= -f2 | head -1) || RAW_INDEX=""

if [[ -n "$RAW_INDEX" ]]; then
    HARDENING_INDEX=$(sanitize_int "$RAW_INDEX")
else
    # Fallback: iterate line by line in case format differs
    while IFS='=' read -r key value; do
        if [[ "$key" =~ ^hardening_index$ ]]; then
            HARDENING_INDEX="${value//\"/}"
            HARDENING_INDEX="${HARDENING_INDEX//\'/}"
            HARDENING_INDEX="${HARDENING_INDEX// /}"
            HARDENING_INDEX=$(sanitize_int "$HARDENING_INDEX")
            break
        fi
    done < <(grep -E '^hardening_index=' "$DAT_FILE" 2>/dev/null || true)
fi

if [[ -z "$HARDENING_INDEX" ]]; then
    HARDENING_INDEX=0
fi

echo "    Hardening index: $HARDENING_INDEX"

# ---------------------------------------------------------------------------
# Step 6: Function to escape strings for JSON
# ============================================================================

json_escape_string() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\t'/\\t}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    printf '%s' "$str"
}

# ---------------------------------------------------------------------------
# Step 7: Collect all findings
# ============================================================================

declare -a FINDINGS_ARRAY=()

# Parse suggestions
# Lynis .dat Format: suggestion[]=TEST_ID|MESSAGE|extra_fields|extra_fields
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" =~ ^suggestion\[]=([^\|]+)\|(.+) ]]; then
        test_id="${BASH_REMATCH[1]}"
        full_content="${BASH_REMATCH[2]}"

        IFS='|' read -r message _ _ <<< "$full_content"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            esc_test_id="$(json_escape_string "$test_id")"
            FINDINGS_ARRAY+=("{\"severity\":\"suggestion\",\"test_id\":\"${esc_test_id}\",\"message\":\"${esc_message}\"}")
        fi
    fi
done < <(grep -E '^suggestion\[\]=' "$DAT_FILE" 2>/dev/null || true)

# Parse warnings
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" =~ ^warning\[]=([^\|]+)\|(.+) ]]; then
        test_id="${BASH_REMATCH[1]}"
        full_content="${BASH_REMATCH[2]}"

        IFS='|' read -r message _ _ <<< "$full_content"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            esc_test_id="$(json_escape_string "$test_id")"
            FINDINGS_ARRAY+=("{\"severity\":\"warning\",\"test_id\":\"${esc_test_id}\",\"message\":\"${esc_message}\"}")
        fi
    fi
done < <(grep -E '^warning\[\]=' "$DAT_FILE" 2>/dev/null || true)

# Parse manual_check
while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    if [[ "$line" =~ ^manual_check\[]=([^\|]+)\|(.+) ]]; then
        test_id="${BASH_REMATCH[1]}"
        full_content="${BASH_REMATCH[2]}"

        IFS='|' read -r message _ _ <<< "$full_content"

        if [[ -n "$message" ]]; then
            esc_message="$(json_escape_string "$message")"
            esc_test_id="$(json_escape_string "$test_id")"
            FINDINGS_ARRAY+=("{\"severity\":\"manual_check\",\"test_id\":\"${esc_test_id}\",\"message\":\"${esc_message}\"}")
        fi
    fi
done < <(grep -E '^manual_check\[\]=' "$DAT_FILE" 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Step 8: Output JSON structure and validate with jq
# ============================================================================

echo ""
echo "[*] Generating JSON output..."

OUTPUT_FILE="lynis_findings.json"

# Build JSON to temp file first, then validate with jq
{
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
} > "${OUTPUT_FILE}.tmp"

# Validate JSON with jq; if valid, pretty-print to final file
if jq '.' < "${OUTPUT_FILE}.tmp" > "$OUTPUT_FILE" 2>/dev/null; then
    rm -f "${OUTPUT_FILE}.tmp"
    echo "    JSON validation: OK"
else
    echo "    ERROR: JSON validation failed" >&2
    echo "    Raw output for debugging:" >&2
    cat "${OUTPUT_FILE}.tmp" >&2
    cp "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
    rm -f "${OUTPUT_FILE}.tmp"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 9: Summary
# ---------------------------------------------------------------------------

echo "    Output saved to: $OUTPUT_FILE"
echo ""
echo "=== Summary ==="
echo "Hardening Index: $HARDENING_INDEX"
echo "Total Findings: ${#FINDINGS_ARRAY[@]}"

# Count by severity (safe iteration avoiding pipe capture issues)
SUGGESTIONS=0
WARNINGS=0
MANUAL_CHECKS=0

for finding in "${FINDINGS_ARRAY[@]+"${FINDINGS_ARRAY[@]}"}"; do
    if echo "$finding" | grep -q '"severity":"suggestion"'; then
        SUGGESTIONS=$((SUGGESTIONS + 1))
    elif echo "$finding" | grep -q '"severity":"warning"'; then
        WARNINGS=$((WARNINGS + 1))
    elif echo "$finding" | grep -q '"severity":"manual_check"'; then
        MANUAL_CHECKS=$((MANUAL_CHECKS + 1))
    fi
done

echo "Suggestions: $SUGGESTIONS"
echo "Warnings: $WARNINGS"
echo "Manual Checks: $MANUAL_CHECKS"
echo ""

# Show preview of first few findings if any exist
if [[ ${#FINDINGS_ARRAY[@]} -gt 0 ]]; then
    echo "Preview of findings:"
    jq '.findings[:3]' "$OUTPUT_FILE" 2>/dev/null || true
fi

exit 0
