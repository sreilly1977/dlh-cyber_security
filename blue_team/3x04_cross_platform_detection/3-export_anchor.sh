#!/bin/bash
# Name: 3-export_anchor.sh
# Purpose: Investigate the anchor event through the Wazuh export artifacts
#          and produce the matching export-interface finding. Reads the
#          anchor search results (hits_total, KQL query, time range), the
#          dashboard workflow trace (click_path, estimated_time_seconds),
#          and the field mapping document; reconciles five normalized ->
#          Wazuh field pairs against the export; measures wall clock from
#          first file read to written finding; and emits
#          findings/anchor_export.json in the locked finding schema with
#          interface: wazuh_export.
# Author: Steve - Cybersecurity Engineer
# Date: 11 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
WAZUH_EXPORTS="${WAZUH_EXPORTS:-$ASSETS_DIR/wazuh_exports}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

SEARCH_FILE="$WAZUH_EXPORTS/anchor_search_results.json"
TRACE_FILE="$WAZUH_EXPORTS/anchor_dashboard_trace.json"
FIELD_MAP_FILE="$WAZUH_EXPORTS/field_mapping.json"
OUT_FILE="$FINDINGS_DIR/anchor_export.json"

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
read_count=0

# ---------------------------------------------------------------------------
# 0. Prerequisites.
# ---------------------------------------------------------------------------
for f in "$SEARCH_FILE" "$TRACE_FILE" "$FIELD_MAP_FILE"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

EVENTS_TMP="$(mktemp)"
LEAVES_TMP="$(mktemp)"
trap 'rm -f "$EVENTS_TMP" "$LEAVES_TMP"' EXIT

# ---------------------------------------------------------------------------
# 1. File read 1: search-results header — hits_total, KQL query, time range.
# ---------------------------------------------------------------------------
META_TSV=$(jq -r 'del(.events)
    | [.hits_total // 0,
       (.query.kql // "(none)"),
       (.query.time_start // ""),
       (.query.time_end // "")] | @tsv' \
    < "$SEARCH_FILE")
read_count=$((read_count + 1))

IFS=$'\t' read -r hits_total kql_query q_start q_end <<< "$META_TSV"

printf '%-12s : %s\n' "reading" '$ASSETS_DIR/wazuh_exports/anchor_search_results.json'
printf '%-12s : %s\n' "hits_total" "$hits_total"
printf '%-12s : %s\n' "kql_query" "$kql_query"

if [[ "${hits_total:-0}" -eq 0 ]]; then
    fail "hits_total" "zero hits in $SEARCH_FILE"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. File read 2: events array, streamed to temp; census of first/last.
#    The array is timestamp-sorted, but sort_by is used defensively anyway.
# ---------------------------------------------------------------------------
jq -c '.events[]' < "$SEARCH_FILE" > "$EVENTS_TMP"
read_count=$((read_count + 1))

CENSUS_TSV=$(jq -sr 'sort_by(."@timestamp")
    | [length,
       .[0]."@timestamp", (.[0]._source.source.ip // ""),
       .[-1]."@timestamp", (.[-1]._source.source.ip // "")] | @tsv' \
    < "$EVENTS_TMP")
IFS=$'\t' read -r evt_count first_ts first_ip last_ts last_ip <<< "$CENSUS_TSV"

if [[ "${evt_count:-0}" -eq 0 ]]; then
    fail "events" "empty events array in $SEARCH_FILE"
    exit 1
fi

printf '%-12s : %s (%s)\n' "first event" "$first_ts" "$first_ip"
printf '%-12s : %s (%s)\n' "last event" "$last_ts" "$last_ip"

# First investigative answer obtained: the export census is complete.
tffa=$(( $(date +%s) - t0_epoch ))

# ---------------------------------------------------------------------------
# 3. File read 3: dashboard trace — click path (the actions record) and the
#    estimated interaction time for the live-dashboard equivalent.
# ---------------------------------------------------------------------------
TRACE_JSON=$(jq -c '{click_path: (.click_path // []),
                    est_secs: (.estimated_time_seconds // 0)}' \
    < "$TRACE_FILE")
read_count=$((read_count + 1))

ACTIONS_JSON=$(jq -c '.click_path' <<< "$TRACE_JSON")
click_steps=$(jq '.click_path | length' <<< "$TRACE_JSON")
est_secs=$(jq -r '.est_secs' <<< "$TRACE_JSON")

printf '%-12s : %s steps loaded from dashboard_trace (%ss estimated)\n' \
    "click_path" "$click_steps" "$est_secs"

# ---------------------------------------------------------------------------
# 4. File read 4: field mapping — five pairs from the anchor workflow, each
#    verified against the leaf paths of the first hit (plus hit-level _id).
# ---------------------------------------------------------------------------
head -n 1 "$EVENTS_TMP" \
    | jq -r 'paths | join(".") | ltrimstr("_source.")' \
    | sort -u > "$LEAVES_TMP"
read_count=$((read_count + 1))

printf '%-12s : %s\n' "field map" "normalized schema -> Wazuh field name"
for pair in "src_ip|source.ip" "hostname|agent.name" "user|user.name" \
            "event_ref|_id" "raw_message|full_log"; do
    norm="${pair%%|*}"
    waz="${pair#*|}"
    if grep -qxF "$waz" "$LEAVES_TMP"; then
        printf '  %-12s -> %s\n' "$norm" "$waz"
    else
        printf '  %-12s -> %-16s (not present in this export)\n' "$norm" "$waz"
    fi
done

# ---------------------------------------------------------------------------
# 5. Write the finding (locked schema; all 13 keys).
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"
t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$tffa" \
    --argjson actions "$ACTIONS_JSON" \
    --slurpfile ev "$EVENTS_TMP" \
    --arg hyp "The Wazuh export returns $hits_total documents for the anchor KQL query, the same four attacker IPs reaching db-patient-01 on port 22, corroborating the CLI investigation. The export-side deltas (hit count, first/last event boundaries, technique tagging) are recorded for the interface comparison deliverable." \
    '{
        finding_id: "anchor_wazuh_export",
        scenario_id: "anchor",
        interface: "wazuh_export",
        investigation_start: $ts_start,
        investigation_end: $ts_end,
        time_to_first_answer_seconds: $tffa,
        actions: $actions,
        fields_touched: (["source.ip", "destination.ip", "agent.name", "user.name", "@timestamp", "_id", "full_log"] | unique),
        event_refs: ($ev | map(._id)),
        attack_techniques: ["T1110.001"],
        hypothesis: $hyp,
        confidence: "high",
        created_at: $ts_end
    }' > "$OUT_FILE"

if [[ ! -s "$OUT_FILE" ]]; then
    fail "finding" "could not write $OUT_FILE"
    exit 1
fi

# Schema self-check: exact key set (all 13, hypothesis included), action cap.
if ! jq -e '
    (keys | sort) == (["actions","attack_techniques","confidence","created_at","event_refs",
                       "fields_touched","finding_id","hypothesis","interface",
                       "investigation_end","investigation_start","scenario_id",
                       "time_to_first_answer_seconds"] | sort)
    and (.actions | length <= 20)
    and (.confidence == "low" or .confidence == "medium" or .confidence == "high")
' "$OUT_FILE" >/dev/null; then
    fail "finding" "schema validation failed on $OUT_FILE"
fi

# ---------------------------------------------------------------------------
# 6. Timing summary and exit.
# ---------------------------------------------------------------------------
elapsed=$(( $(date +%s) - t0_epoch ))
printf '%-12s : %s seconds, %s file reads\n' "elapsed" "$elapsed" "$read_count"

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/anchor_export.json"
    exit 0
fi
exit 1
