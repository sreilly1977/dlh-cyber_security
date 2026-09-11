#!/bin/bash
# Name: 1-wazuh_workspace.sh
# Purpose: Initialize the 3x04 Wazuh export workspace. Reads index metadata
#          (index name, document count, time range), loads the field mapping
#          document, prints the dashboard username (never the password),
#          verifies all required export files under wazuh_exports/ and
#          query_results/, and writes workspace/workspace_init.json so
#          downstream tasks know which export set they run against.
# Author: Steve - Cybersecurity Engineer
# Date: 11 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"
QUERY_RESULTS="$ASSETS_DIR/query_results"
WORKSPACE_DIR="${WORKSPACE_DIR:-$SCRIPT_DIR/workspace}"

failures=0

fail() {
    printf '%-15s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

comma_fmt() {
    # 339882 -> 339,882 (portable, locale-independent)
    printf '%s' "$1" | sed -E ':a; s/^([0-9]+)([0-9]{3})/\1,\2/; ta'
}

# ---------------------------------------------------------------------------
# Prerequisite: jq must be available to read the JSON exports.
# ---------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
    printf '%-15s : FAIL (jq not found on PATH)\n' "mode"
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Index metadata.
# ---------------------------------------------------------------------------
META_FILE="$WAZUH_EXPORTS/index_metadata.json"
FIELD_MAP_FILE="$WAZUH_EXPORTS/field_mapping.json"
CRED_FILE="$ASSETS_DIR/dashboard_credentials.json"

index_name=""
doc_count=""
tr_earliest=""
tr_latest=""
if [ -s "$META_FILE" ]; then
    index_name=$(jq -r '.source_index // empty' "$META_FILE" 2>/dev/null)
    doc_count=$(jq -r '.total_documents // empty' "$META_FILE" 2>/dev/null)
    tr_earliest=$(jq -r '.time_range.earliest // empty' "$META_FILE" 2>/dev/null)
    tr_latest=$(jq -r '.time_range.latest // empty' "$META_FILE" 2>/dev/null)
fi
if [ -z "$index_name" ] || [ -z "$doc_count" ] || [ -z "$tr_earliest" ] || [ -z "$tr_latest" ]; then
    fail "index" "could not read source_index/total_documents/time_range from $META_FILE"
fi

printf '%-15s : %s\n' "mode" "wazuh_export (no live dashboard required)"
if [ -n "$index_name" ]; then
    printf '%-15s : %s\n' "index" "$index_name"
fi
if [ -n "$doc_count" ]; then
    printf '%-15s : %s\n' "documents" "$(comma_fmt "$doc_count")"
fi
if [ -n "$tr_earliest" ]; then
    printf '%-15s : %s to %s\n' "time range" "$tr_earliest" "$tr_latest"
fi

# ---------------------------------------------------------------------------
# 2. Dashboard credentials — username only, password is never printed.
# ---------------------------------------------------------------------------
cred_user=""
if [ -s "$CRED_FILE" ]; then
    cred_user=$(jq -r '.username // empty' "$CRED_FILE" 2>/dev/null)
fi
if [ -z "$cred_user" ]; then
    fail "credentials" "could not read username from $CRED_FILE"
else
    printf '%-15s : %s (from dashboard_credentials.json)\n' "credentials" "$cred_user"
fi

# ---------------------------------------------------------------------------
# 3. Field mapping: total count, then the 10 most-used mappings as a table.
#    Identity mappings (@timestamp -> @timestamp) and the technical
#    event_ref -> _id pair are skipped; the next ten in document order cover
#    every mapping the workflow actually pivots on.
# ---------------------------------------------------------------------------
mapping_count=""
if [ -s "$FIELD_MAP_FILE" ]; then
    mapping_count=$(jq '.mappings | length' "$FIELD_MAP_FILE" 2>/dev/null)
fi
if [ -z "$mapping_count" ] || [ "$mapping_count" = "null" ]; then
    fail "field mapping" "could not read mappings from $FIELD_MAP_FILE"
else
    printf '%-15s : loaded (%s mappings)\n' "field mapping" "$mapping_count"
    jq -r '.mappings[]
            | select(.normalized != .wazuh and .normalized != "event_ref" and .normalized != "timestamp")
            | "\(.normalized)|\(.wazuh)"' \
        "$FIELD_MAP_FILE" 2>/dev/null | head -n 10 |
    while IFS='|' read -r norm waz; do
        printf '  %-12s -> %s\n' "$norm" "$waz"
    done
fi

# ---------------------------------------------------------------------------
# 4. Required export files. Counted set (11): six core wazuh_exports files +
#    five query_results files. Dashboard traces are verified silently and
#    only reported on failure, per the Task 0 convention.
# ---------------------------------------------------------------------------
core_wazuh=(
    field_mapping.json
    index_metadata.json
    anchor_search_results.json
    scenario_a_search_results.json
    scenario_b_search_results.json
    scenario_c_search_results.json
)
query_files=(
    kql_anchor_query.json
    lucene_anchor_query.json
    kql_scenario_a.json
    kql_scenario_b.json
    kql_scenario_c.json
)
trace_files=(
    anchor_dashboard_trace.json
    scenario_a_dashboard_trace.json
    scenario_b_dashboard_trace.json
    scenario_c_dashboard_trace.json
)

verify_files() {
    # $1 = directory, $2.. = filenames; echoes count verified OK.
    local dir="$1"
    shift
    local f ok=0
    for f in "$@"; do
        if [ -s "$dir/$f" ]; then
            ok=$((ok + 1))
        else
            fail "export files" "missing or empty: $dir/$f"
        fi
    done
    echo "$ok"
}

core_ok=$(verify_files "$WAZUH_EXPORTS" "${core_wazuh[@]}")
query_ok=$(verify_files "$QUERY_RESULTS" "${query_files[@]}")
trace_ok=$(verify_files "$WAZUH_EXPORTS" "${trace_files[@]}")

files_verified=$((core_ok + query_ok))
if [ "$files_verified" -eq 11 ]; then
    printf '%-15s : all present (%d files verified)\n' "export files" "$files_verified"
else
    fail "export files" "expected 11 required files, $files_verified present"
fi
# Traces verified above; silence on success, already reported per-file on failure.

# ---------------------------------------------------------------------------
# 5. Write workspace_init.json (idempotent — safe to rerun).
# ---------------------------------------------------------------------------
mkdir -p "$WORKSPACE_DIR"
INIT_FILE="$WORKSPACE_DIR/workspace_init.json"
if jq -n \
        --arg mode "wazuh_export" \
        --arg idx "$index_name" \
        --argjson docs "$doc_count" \
        --arg earliest "$tr_earliest" \
        --arg latest "$tr_latest" \
        --argjson fv "$([ "$failures" -eq 0 ] && echo true || echo false)" \
        --argjson fml "$([ -n "$mapping_count" ] && echo true || echo false)" \
        --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        '{
            mode: $mode,
            source_index: $idx,
            total_documents: $docs,
            time_range: {earliest: $earliest, latest: $latest},
            export_files_verified: $fv,
            field_mapping_loaded: $fml,
            initialized_at: $ts
        }' > "$INIT_FILE"; then
    printf 'workspace_init.json written\n'
else
    fail "workspace" "could not write $INIT_FILE"
fi

# ---------------------------------------------------------------------------
# 6. Exit status.
# ---------------------------------------------------------------------------
if [ "$failures" -eq 0 ]; then
    exit 0
fi
printf '%-15s : FAILED (%d check%s failed)\n' "all checks" "$failures" \
    $([ "$failures" -eq 1 ] || printf 's')
exit 1
