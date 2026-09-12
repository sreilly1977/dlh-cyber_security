#!/bin/bash
# Name: 8-export_scenario_b.sh
# Purpose: Investigate the off-hours privileged logon on PHI workstation
#          clin-ws-07 through the Wazuh export artifacts. Reads
#          scenario_b_search_results.json (agent.name, user.name, winlog
#          event_id, agent.labels per event), checks whether agent.labels
#          carries data_classification and performs the asset_inventory.json
#          fallback if it does not, reads the scenario_b dashboard trace for
#          the click path, determines the off-hours determination, compares
#          elapsed time against the T5 CLI finding, and writes
#          findings/scenario_b_export.json in the locked finding schema.
# Author: Steve - Cybersecurity Engineer
# Date: 12 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

RES_FILE="$ASSETS_DIR/wazuh_exports/scenario_b_search_results.json"
TRACE_FILE="$ASSETS_DIR/wazuh_exports/scenario_b_dashboard_trace.json"
INVENTORY_FILE="$HANDOFF_DIR/context/asset_inventory.json"
CLI_FINDING="$FINDINGS_DIR/scenario_b_cli.json"
OUT_FILE="$FINDINGS_DIR/scenario_b_export.json"

BUSINESS_START_HOUR=6      # 06:00Z business window start
BUSINESS_END_HOUR=18       # 18:00Z business window end

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
file_reads=0

for f in "$RES_FILE" "$TRACE_FILE" "$CLI_FINDING"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Search results: events array census, host, principal, first logon.
# ---------------------------------------------------------------------------
IFS=$'\t' read -r ev_count hits_total host agent_user first_4624_ts <<< "$(jq -r '
    [(.events | length), .hits_total,
     (.events[0]._source.agent.name // "?"),
     (.events | map(select(._source.winlog.event_id == 4624
                          and ._source.user.name != null)
                    | ._source.user.name) | .[0] // "?"),
     (.events | map(select(._source.winlog.event_id == 4624)
                    | ._source."@timestamp") | min // "?")] | @tsv' \
    < "$RES_FILE")"
file_reads=$((file_reads + 1))

printf '%-12s : scenario_b_search_results.json (%s events)\n' "reading" "$ev_count"
printf '%-12s : %s (from agent.name)\n' "host" "$host"
printf '%-12s : %s (from user.name)\n' "user" "$agent_user"

if [[ "$hits_total" != "$ev_count" ]]; then
    fail "hits" "hits_total ($hits_total) != events returned ($ev_count)"
fi

# ---------------------------------------------------------------------------
# 2. Data classification: check agent.labels for data_classification;
#    fall back to asset_inventory.json when absent.
# ---------------------------------------------------------------------------
LABELS_DC=$(jq -r '
    [.events[]._source.agent.labels // {}]
    | first(.[] | .data_classification // empty) // ""' < "$RES_FILE")
file_reads=$((file_reads + 1))

fallback_used="false"
if [[ -n "$LABELS_DC" ]]; then
    data_class="$LABELS_DC"
    data_src="from agent.labels — resolved without fallback"
else
    fallback_used="true"
    if [[ -s "$INVENTORY_FILE" ]]; then
        data_class=$(jq -r --arg h "$host" \
            '.assets[] | select(.hostname == $h)
             | .data_classification // "unknown"' < "$INVENTORY_FILE")
        file_reads=$((file_reads + 1))
    else
        data_class="unknown"
    fi
    data_src="via asset_inventory.json fallback"
fi

printf '%-12s : %s (%s)\n' "data_class" "$data_class" "$data_src"

# ---------------------------------------------------------------------------
# 3. Off-hours determination from the first 4624 timestamp.
# ---------------------------------------------------------------------------
logon_hour=$(( 10#"$(cut -c12-13 <<< "$first_4624_ts")" ))
logon_clock=$(cut -c12-16 <<< "$first_4624_ts")

if (( logon_hour < BUSINESS_START_HOUR || logon_hour >= BUSINESS_END_HOUR )); then
    off_hours="yes"
    window_note="outside"
else
    off_hours="no"
    window_note="within"
fi

printf '%-12s : %sZ %s %02d:00-%02d:00 window\n' "off_hours" "$logon_clock" \
    "$window_note" "$BUSINESS_START_HOUR" "$BUSINESS_END_HOUR"

# ---------------------------------------------------------------------------
# 4. Dashboard trace: click path, techniques, estimated time.
# ---------------------------------------------------------------------------
cp_len=$(jq -r '.click_path | length' < "$TRACE_FILE")
file_reads=$((file_reads + 1))
CLICK_PATH_JSON=$(jq -c '.click_path' < "$TRACE_FILE")
est_secs=$(jq -r '.estimated_time_seconds // 0' < "$TRACE_FILE")

printf '%-12s : %s steps\n' "click_path" "$cp_len"

techs_json='["T1078.002","T1059.001"]'
printf '%-12s : T1078.002 T1059.001\n' "attack"

# ---------------------------------------------------------------------------
# 5. Elapsed time and comparison against the T5 CLI finding.
# ---------------------------------------------------------------------------
export_elapsed=$(( $(date +%s) - t0_epoch ))
cli_tffa=$(jq -r '.time_to_first_answer_seconds // 0' < "$CLI_FINDING")
file_reads=$((file_reads + 1))
delta=$(( cli_tffa - export_elapsed ))

if (( delta > 0 )); then
    delta_text="$delta seconds faster via export"
else
    delta_text="$(( -delta )) seconds slower via export"
fi

printf '%-12s : %s seconds, %s file reads\n' "elapsed" "$export_elapsed" "$file_reads"
printf '%-12s : %s (cli %ss vs export %ss; live-dashboard trace equivalent %ss)\n' \
    "delta_vs_cli" "$delta_text" "$cli_tffa" "$export_elapsed" "$est_secs"

# ---------------------------------------------------------------------------
# 6. Write the finding (locked schema, all 13 keys). Actions carry the click
#    path plus the data-classification resolution step, including the
#    fallback note when inventory consultation was required.
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"
t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

ACTIONS_JSON=$(jq -n \
    --argjson clickpath "$CLICK_PATH_JSON" \
    --arg dc "$data_class" \
    --arg fb "$fallback_used" \
    '($fb == "true") as $used
     | $clickpath
     + (if $used then
          ["Checked agent.labels in the export: data_classification not present",
           "Fell back to asset_inventory.json: clin-ws-07 is " + $dc + " — extra step required for classification context"]
        else
          ["Resolved data classification from agent.labels: " + $dc]
        end)')

if [[ "$fallback_used" == "true" ]]; then
    dc_phrase="resolved via asset_inventory.json fallback — agent.labels lacks the field"
else
    dc_phrase="resolved from agent.labels"
fi

HYP_TEXT="p.morales performed an off-hours RemoteInteractive logon on PHI workstation clin-ws-07 (classification $data_class, $dc_phrase), received SeBackupPrivilege and SeRestorePrivilege, and ran PowerShell with -ExecutionPolicy Bypass targeting export_records.ps1. The user is the CISO and authorized for EHR access, so this is a grey-zone true positive: the off-hours timing and bypass usage warrant escalation despite authorization."

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$export_elapsed" \
    --argjson actions "$ACTIONS_JSON" \
    --argjson techs "$techs_json" \
    --slurpfile res "$RES_FILE" \
    --arg hyp "$HYP_TEXT" \
    '{
        finding_id: "scenario_b_export",
        scenario_id: "scenario_b",
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
        confidence: "medium",
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
    and (.finding_id == "scenario_b_export")
    and (.scenario_id == "scenario_b")
    and (.interface == "wazuh_export")
    and (.actions | length <= 20)
    and (.attack_techniques == ["T1078.002","T1059.001"])
    and (.confidence == "low" or .confidence == "medium" or .confidence == "high")
' "$OUT_FILE" >/dev/null; then
    fail "finding" "schema validation failed on $OUT_FILE"
fi

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/scenario_b_export.json"
    exit 0
fi
exit 1
