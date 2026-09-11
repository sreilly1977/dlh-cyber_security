#!/bin/bash
# Name: 0-tool_check.sh
# Purpose: Verify the complete 3x04 toolkit (jq, yq, python3, sigma-cli, xmllint,
#          curl), upstream handoff directories (3x00/3x01/3x02/3x03), the Wazuh
#          export artifacts, and the presence of the anchor scenario in the
#          enriched NDJSON evidence stream. Exits non-zero if any check fails.
# Author: Steve - Cybersecurity Engineer
# Date: 11 September 2026

set -u -o pipefail

failures=0
jq_available=1

# Resolved defaults per project requirements (environment may override).
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"

report_fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

# ---------------------------------------------------------------------------
# 1. Tools on PATH, with version banners normalised to bare version strings.
# ---------------------------------------------------------------------------
get_version() {
    # $1 = tool name, $2.. = fallback version flags to try.
    local tool="$1"
    local v=""
    case "$tool" in
        jq)       v=$(jq --version 2>&1) && v=${v#jq-} ;;
        yq)       v=$(yq --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1) ;;
        python3)  v=$(python3 --version 2>&1) && v=${v#Python } ;;
        sigma-cli)
            v=$(sigma version 2>&1 | head -n 1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
            ;;
        xmllint)  v=$(xmllint --version 2>&1 | grep -oE 'libxml version [0-9]+' | grep -oE '[0-9]+') ;;
        curl)     v=$(curl --version 2>&1 | head -n 1 | awk '{print $2}') ;;
    esac
    printf '%s' "$v"
}

check_tool() {
    local tool="$1"
    local cmd="$tool"
    [ "$tool" = "sigma-cli" ] && cmd="sigma"   # pip package sigma-cli installs 'sigma'
    local ver
    if ! command -v "$cmd" >/dev/null 2>&1; then
        report_fail "$tool" "not found on PATH"
        if [ "$tool" = "jq" ]; then jq_available=0; fi
        return
    fi
    ver=$(get_version "$tool")
    if [ -z "$ver" ]; then
        report_fail "$tool" "on PATH but version could not be determined"
        return
    fi
    printf '%-12s : %s\n' "$tool" "$ver"
}

check_tool jq
check_tool yq
check_tool python3
check_tool sigma-cli
check_tool xmllint
check_tool curl

# ---------------------------------------------------------------------------
# 2. Upstream directory existence. handoff/catalog print ok-lines; the others
#    stay silent on success so output matches the expected transcript.
# ---------------------------------------------------------------------------
for dir_pair in "HANDOFF_DIR:$HANDOFF_DIR" "BASELINE_PKG:$BASELINE_PKG" \
                "CATALOG_DIR:$CATALOG_DIR" "TRIAGE_PKG:$TRIAGE_PKG" \
                "ASSETS_DIR:$ASSETS_DIR"; do
    var_name=${dir_pair%%:*}
    dir_path=${dir_pair#*:}
    if [ ! -d "$dir_path" ]; then
        report_fail "$var_name" "directory not found: $dir_path"
    fi
done
if [ -d "$HANDOFF_DIR" ]; then
    printf '%-12s : ok (%s)\n' "handoff-dir" "$HANDOFF_DIR"
fi
if [ -d "$BASELINE_PKG" ]; then
    printf '%-12s : ok (%s)\n' "baseline" "$BASELINE_PKG"
fi
if [ -d "$TRIAGE_PKG" ]; then
    printf '%-12s : ok (%s)\n' "triage" "$TRIAGE_PKG"
fi

# ---------------------------------------------------------------------------
# 3. Handoff data: enriched_events.json present and non-empty.
# ---------------------------------------------------------------------------
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
if [ ! -s "$EVENTS_FILE" ]; then
    report_fail "handoff" "missing or empty: $EVENTS_FILE"
else
    printf '%-12s : ok (enriched_events.json present)\n' "handoff"
fi

# ---------------------------------------------------------------------------
# 4. Detection catalog: Sigma rule directory and rule count.
# ---------------------------------------------------------------------------
SIGMA_DIR="$CATALOG_DIR/rules/sigma"
if [ -d "$SIGMA_DIR" ]; then
    rule_count=$(find "$SIGMA_DIR" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) | wc -l)
    if [ "$rule_count" -gt 0 ]; then
        printf '%-12s : ok (%d sigma rules)\n' "catalog" "$rule_count"
    else
        report_fail "catalog" "no sigma rules found in $SIGMA_DIR"
    fi
else
    report_fail "catalog" "rules/sigma directory not found: $SIGMA_DIR"
fi

# ---------------------------------------------------------------------------
# 5. Wazuh export artifacts (field_mapping, index_metadata, 4 search_results,
#    4 dashboard_traces).
# ---------------------------------------------------------------------------
wazuh_ok=1
for wf in field_mapping.json index_metadata.json \
          anchor_search_results.json \
          scenario_a_search_results.json \
          scenario_b_search_results.json \
          scenario_c_search_results.json \
          anchor_dashboard_trace.json \
          scenario_a_dashboard_trace.json \
          scenario_b_dashboard_trace.json \
          scenario_c_dashboard_trace.json; do
    if [ ! -s "$WAZUH_EXPORTS/$wf" ]; then
        report_fail "wazuh_exports" "missing or empty: $WAZUH_EXPORTS/$wf"
        wazuh_ok=0
    fi
done
if [ "$wazuh_ok" -eq 1 ]; then
    printf '%s : ok (field_mapping, index_metadata, 4 search_results, 4 dashboard_traces)\n' "wazuh_exports"
fi

# ---------------------------------------------------------------------------
# 6. Anchor scenario: extract target_host + time_window from anchor_event.json
#    and stream enriched_events.json (NDJSON, ~264 MB — never slurp) looking
#    for matching events.
# ---------------------------------------------------------------------------
ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
if [ "$jq_available" -ne 1 ] || [ ! -s "$ANCHOR_FILE" ]; then
    report_fail "anchor" "cannot verify (jq unavailable or anchor_event.json missing)"
else
    anchor_host=$(jq -r '.target_host // empty' "$ANCHOR_FILE" 2>/dev/null)
    tw_start=$(jq -r '.time_window.start // empty' "$ANCHOR_FILE" 2>/dev/null)
    tw_end=$(jq -r '.time_window.end // empty' "$ANCHOR_FILE" 2>/dev/null)
    attacker_ips=$(jq -c '.attacker_ips // []' "$ANCHOR_FILE" 2>/dev/null)

    if [ -z "$anchor_host" ] || [ -z "$tw_start" ] || [ -z "$tw_end" ] || [ ! -s "$EVENTS_FILE" ]; then
        report_fail "anchor" "could not extract target_host/time_window or events file unusable"
    else
        # Primary match: host inside the anchor time window (ISO 8601 UTC
        # strings compare correctly lexicographically).
        match_line=$(jq -c --arg h "$anchor_host" --arg s "$tw_start" --arg e "$tw_end" \
            'select(.hostname == $h and .timestamp != null and .timestamp >= $s and .timestamp <= $e)' \
            "$EVENTS_FILE" 2>/dev/null | head -n 1) || true

        if [ -n "$match_line" ]; then
            printf '%-12s : ok (%s matched in enriched_events.json)\n' "anchor" "$anchor_host"
        else
            # Fallback: any event sourced from an anchor attacker IP inside
            # the window, in case the host field differs between log sources.
            ip_match=$(jq -c --arg s "$tw_start" --arg e "$tw_end" --argjson ips "$attacker_ips" \
                'select((([.src_ip] - $ips) | length) == 0 and .timestamp != null and .timestamp >= $s and .timestamp <= $e)' \
                "$EVENTS_FILE" 2>/dev/null | head -n 1) || true

            if [ -n "$ip_match" ]; then
                printf '%-12s : ok (%s matched via attacker IP in enriched_events.json)\n' "anchor" "$anchor_host"
            else
                report_fail "anchor" "no events for $anchor_host within $tw_start .. $tw_end"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# 7. Summary.
# ---------------------------------------------------------------------------
if [ "$failures" -eq 0 ]; then
    printf '%-12s : passed\n' "all checks"
    exit 0
else
    printf '%-12s : FAILED (%d check%s failed)\n' "all checks" "$failures" \
        $([ "$failures" -eq 1 ] || printf 's')
    exit 1
fi
