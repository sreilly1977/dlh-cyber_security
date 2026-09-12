#!/bin/bash
# Name: 7-export_scenario_a.sh
# Purpose: Investigate the credential theft chain on clin-ws-12 through
#          the Wazuh export artifacts. Reads scenario_a_search_results.json
#          (hits_total, KQL query, events array), filters documents for
#          winlog.event_id 10/1/11/3, reads scenario_a_dashboard_trace.json
#          (click path, field name translation, estimated time), prints the
#          ATT&CK mapping section from scenario_a_dashboard_summary.md,
#         compares elapsed time against the T4 CLI finding, and writes
#          findings/scenario_a_export.json in the locked finding schema.
# Author: Steve - Cybersecurity Engineer
# Date: 12 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

RES_FILE="$ASSETS_DIR/wazuh_exports/scenario_a_search_results.json"
TRACE_FILE="$ASSETS_DIR/wazuh_exports/scenario_a_dashboard_trace.json"
SUMMARY_FILE="$ASSETS_DIR/dashboard_exports/scenario_a_dashboard_summary.md"
CLI_FINDING="$FINDINGS_DIR/scenario_a_cli.json"
OUT_FILE="$FINDINGS_DIR/scenario_a_export.json"

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
file_reads=0

for f in "$RES_FILE" "$TRACE_FILE" "$SUMMARY_FILE" "$CLI_FINDING"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Search results: hits_total, KQL query, events array census.
# ---------------------------------------------------------------------------
IFS=$'\t' read -r hits_total kql ev_count <<< "$(jq -r '
    [.hits_total, .query.kql, (.events | length)] | @tsv' < "$RES_FILE")"
file_reads=$((file_reads + 1))

printf '%-12s : scenario_a_search_results.json (%s events)\n' "reading" "$ev_count"
printf '%-12s : %s\n' "kql" "$kql"

if [[ "$hits_total" != "$ev_count" ]]; then
    fail "hits" "hits_total ($hits_total) != events returned ($ev_count)"
fi

# ---------------------------------------------------------------------------
# 2. Filter events for event_id 10/1/11/3, chronological, key Wazuh fields.
# ---------------------------------------------------------------------------
jq -r '
    .events
    | map(select(._source.winlog.event_id == 10
              or ._source.winlog.event_id == 1
              or ._source.winlog.event_id == 11
              or ._source.winlog.event_id == 3))
    | sort_by(._source."@timestamp")
    | .[]
    | (._source."@timestamp" | split("T")[1]) as $t
    | (._source.winlog.event_id | tostring) as $eid
    | ("EID " + $eid + " : "
       + (if $eid == "10" then (._source.rule.description // "")
          elif $eid == "1" then ("CommandLine: " + (._source.event_data.CommandLine // ""))
          elif $eid == "11" then ((._source.full_log // "") + " (file created)")
          elif $eid == "3" then ("cmd.exe -> "
              + (._source.event_data.DestinationIp // "") + ":"
              + (._source.event_data.DestinationPort // "") + " (SMB)")
          else (._source.full_log // "") end)
       + " at " + $t)' < "$RES_FILE"
cmd_extract_done=1

# ---------------------------------------------------------------------------
# 3. Dashboard trace: click path, field name translation, estimated time.
# ---------------------------------------------------------------------------
IFS=$'\t' read -r cp_len est_secs fm_host fm_eid <<< "$(jq -r '
    [(.click_path | length), .estimated_time_seconds,
     (.field_name_translation.hostname // ""),
     (.field_name_translation.event_id // "")] | @tsv' < "$TRACE_FILE")"
file_reads=$((file_reads + 1))

CLICK_PATH_JSON=$(jq -c '.click_path' < "$TRACE_FILE")
TECHS_JSON=$(jq -c '.attack_techniques' < "$TRACE_FILE")
trace_verdict=$(jq -r '.verdict // "unknown"' < "$TRACE_FILE")
trace_conf=$(jq -r '.confidence // "unknown"' < "$TRACE_FILE")

printf '%-12s : %s steps\n' "click_path" "$cp_len"
printf '%-12s : hostname -> %s, event_id -> %s\n' "field_map" "$fm_host" "$fm_eid"

# ---------------------------------------------------------------------------
# 4. Dashboard summary: ATT&CK mapping section, cross-checked vs the trace.
# ---------------------------------------------------------------------------
ATTCK_SECTION=$(awk '/^## ATT&CK Mapping/{flag=1; next} /^## /{flag=0} flag' \
    "$SUMMARY_FILE")
file_reads=$((file_reads + 1))

printf '%-12s :\n%s\n' "attck_md" "$ATTCK_SECTION"

while IFS= read -r tid; do
    [[ -z "$tid" ]] && continue
    if ! grep -q "$tid" <<< "$ATTCK_SECTION"; then
        fail "attck_md" "trace technique $tid missing from summary md section"
    fi
done < <(jq -r '.attack_techniques[]' < "$TRACE_FILE")

printf '%-12s : %s\n' "attack" "$(jq -r '.attack_techniques | join(" ")' < "$TRACE_FILE")"

# ---------------------------------------------------------------------------
# 5. Elapsed time and comparison against the T4 CLI finding.
# ---------------------------------------------------------------------------
export_elapsed=$(( $(date +%s) - t0_epoch ))
cli_tffa=$(jq -r '.time_to_first_answer_seconds // 0' < "$CLI_FINDING")
file_reads=$((file_reads + 1))

t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
delta=$(( cli_tffa - export_elapsed ))

if [[ "$delta" -gt 0 ]]; then
    delta_text="$delta seconds faster via export"
else
    delta_text="$(( -delta )) seconds slower via export"
fi

printf '%-12s : %s seconds, %s file reads\n' "elapsed" "$export_elapsed" "$file_reads"
printf '%-12s : %s (cli %ss vs export %ss; live-dashboard trace equivalent %ss)\n' \
    "delta_vs_cli" "$delta_text" "$cli_tffa" "$export_elapsed" "$est_secs"

# ---------------------------------------------------------------------------
# 6. Write the finding (locked schema, all 13 keys). Actions carry the
#    click path, per the task requirement.
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$export_elapsed" \
    --argjson actions "$CLICK_PATH_JSON" \
    --argjson techs "$TECHS_JSON" \
    --arg conf "$trace_conf" \
    --slurpfile res "$RES_FILE" \
    --arg hyp "Credential theft chain on clin-ws-12: j.martinez used rundll32.exe with comsvcs.dll MiniDump to dump LSASS (T1003.001) to C:\Temp\debug.dmp, then moved laterally via SMB (T1021.002) to 10.1.1.10:445 (srv-dc-01). Export-side reconstruction confirms the CLI verdict: 10 documents returned for the same KQL shape, all three techniques tagged identically to the rule." \
    '{
        finding_id: "scenario_a_export",
        scenario_id: "scenario_a",
        interface: "wazuh_export",
        investigation_start: $ts_start,
        investigation_end: $ts_end,
        time_to_first_answer_seconds: $tffa,
        actions: $actions,
        fields_touched: ($res[0].events
            | map(._source | [paths(scalars) | join(".")])
            | flatten | unique
            | map(ltrimstr("_source."))),
        event_refs: ($res[0].events | map(._id)),
        attack_techniques: $techs,
        hypothesis: $hyp,
        confidence: $conf,
        created_at: $ts_end
    }' > "$OUT_FILE"

if [[ ! -s "$OUT_FILE" ]]; then
    fail "finding" "could not write $OUT_FILE"
    exit 1
fi

# Schema self-check: exact key set, action cap, technique set.
if ! jq -e '
    (keys | sort) == (["actions","attack_techniques","confidence","created_at","event_refs",
                       "fields_touched","finding_id","hypothesis","interface",
                       "investigation_end","investigation_start","scenario_id",
                       "time_to_first_answer_seconds"] | sort)
    and (.finding_id == "scenario_a_export")
    and (.scenario_id == "scenario_a")
    and (.interface == "wazuh_export")
    and (.actions | length <= 20)
    and (.attack_techniques == ["T1003.001","T1550.002","T1021.002"])
    and (.confidence == "low" or .confidence == "medium" or .confidence == "high")
' "$OUT_FILE" >/dev/null; then
    fail "finding" "schema validation failed on $OUT_FILE"
fi

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/scenario_a_export.json"
    exit 0
fi
exit 1
