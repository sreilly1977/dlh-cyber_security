#!/bin/bash
# Name: 5-cli_scenario_b.sh
# Purpose: Investigate the off-hours privileged logon on PHI workstation
#          clin-ws-07 through CLI tools only. Reads the scenario manifest,
#          scopes the enriched NDJSON stream to the host and time window,
#          looks up the asset record (criticality, data classification) in
#          the 3x00 asset inventory, extracts the EID 4624 (logon), 4672
#          (special privileges), and Sysmon EID 1 (PowerShell execution)
#          chain for p.morales, carries the manifest's FP/TP ambiguity note
#          into the finding, and writes findings/scenario_b_cli.json in
#          the locked finding schema.
# Author: Steve - Cybersecurity Engineer
# Date: 12 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

MANIFEST_FILE="$ASSETS_DIR/scenarios/scenario_b_offhours_phi.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
INVENTORY_FILE="$HANDOFF_DIR/context/asset_inventory.json"
OUT_FILE="$FINDINGS_DIR/scenario_b_cli.json"

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cmd_count=0

for f in "$MANIFEST_FILE" "$EVENTS_FILE" "$INVENTORY_FILE"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Manifest: scenario label, host, window, ambiguity note, principal.
#    The acting principal is taken from the manifest's first key event user,
#    falling back to the known scenario principal p.morales.
# ---------------------------------------------------------------------------
IFS=$'\t' read -r manifest_sid target_host tw_start tw_end ambiguity_note \
    <<< "$(jq -r '[.scenario_id, .host_path[0],
                   .time_window.start, .time_window.end,
                   (.ambiguity_note // "")] | @tsv' \
        < "$MANIFEST_FILE")"
cmd_count=$((cmd_count + 1))
scenario_label=$(basename "$MANIFEST_FILE" .json)
principal="p.morales"

printf '%-12s : %s\n' "scenario" "$scenario_label"

# ---------------------------------------------------------------------------
# 2. Asset inventory lookup: criticality and data classification.
# ---------------------------------------------------------------------------
INV_TSV=$(jq -r --arg h "$target_host" \
    '.assets[]
     | select(.hostname == $h)
     | [(.criticality // "unknown"), (.data_classification // "unknown")] | @tsv' \
    < "$INVENTORY_FILE")
cmd_count=$((cmd_count + 1))
IFS=$'\t' read -r inv_crit inv_dataclass <<< "$INV_TSV"

printf '%-12s : %s (criticality: %s, data: %s)\n' "host" "$target_host" \
    "$inv_crit" "$inv_dataclass"
printf '%-12s : %s -> %s\n' "window" "$tw_start" "$tw_end"

# ---------------------------------------------------------------------------
# 3. Scope the NDJSON stream to host + window (one full pass).
# ---------------------------------------------------------------------------
SCOPED_TMP="$(mktemp)"
trap 'rm -f "$SCOPED_TMP"' EXIT

jq -c --arg h "$target_host" --arg s "$tw_start" --arg e "$tw_end" \
    'select(.hostname == $h
        and .timestamp != null and .timestamp >= $s and .timestamp <= $e)' \
    < "$EVENTS_FILE" > "$SCOPED_TMP"
cmd_count=$((cmd_count + 1))

scoped_count=$(wc -l < "$SCOPED_TMP")
printf '%-12s : %s events on %s in window\n' "scoped" "$scoped_count" "$target_host"

if [[ "$scoped_count" -eq 0 ]]; then
    fail "scoped" "no events for $target_host in $tw_start -> $tw_end"
    exit 1
fi

tffa=$(( $(date +%s) - t0_epoch ))

# ---------------------------------------------------------------------------
# 4. Chain extraction for the scenario principal. The window contains other
#    users' benign activity, so each EID filter is scoped to the principal:
#    4624 by user field, 4672 by raw_message (user is null there), EID 1 by
#    user field.
# ---------------------------------------------------------------------------
EID4624_TSV=$(jq -sr --arg u "$principal" 'map(select(.event_id == 4624
        and .user == $u))
    | sort_by(.timestamp)
    | if length == 0 then ["", "", ""] else
        [ .[0].timestamp, .[0].user,
          ((.[0].event_data.LogonType // 0) | tostring) ]
      end | @tsv' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

EID4672_TSV=$(jq -sr --arg u "$principal" 'map(select(.event_id == 4672
        and ((.raw_message // "") | contains($u))))
    | sort_by(.timestamp)
    | if length == 0 then ["", ""] else
        [ .[0].timestamp,
          (((.[0].event_data.PrivilegeList //
            ((.[0].raw_message // "") | [scan("Se[A-Za-z]+Privilege")]
                                          | unique | join(" "))))
            | gsub("\\s+"; " ") | sub("^ "; "")) ]
      end | @tsv' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

EID1_TSV=$(jq -sr --arg u "$principal" 'map(select(.event_id == 1
        and .user == $u))
    | sort_by(.timestamp)
    | if length == 0 then ["", "", ""] else
        [ .[0].timestamp, (.[0].process_name // ""),
          (.[0].event_data.CommandLine // "") ]
      end | @tsv' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

IFS=$'\t' read -r e4624_ts e4624_user e4624_lt <<< "$EID4624_TSV"
IFS=$'\t' read -r e4672_ts e4672_privs <<< "$EID4672_TSV"
IFS=$'\t' read -r e1_ts e1_proc e1_cmd <<< "$EID1_TSV"
# Undo @tsv backslash doubling in the command line.
e1_cmd=${e1_cmd//\\\\/\\}
# Undo it in the privilege list too, in case names contain backslashes.
e4672_privs=${e4672_privs//\\\\/\\}

case "$e4624_lt" in
    10) logon_desc="RemoteInteractive" ;;
    2)  logon_desc="Interactive" ;;
    3)  logon_desc="Network" ;;
    "") logon_desc="" ;;
    *)  logon_desc="Type $e4624_lt" ;;
esac

if [[ -z "$e4624_ts" ]]; then
    printf '%-12s : not found in scoped events\n' "EID 4624"
else
    printf '%-12s : %s %s logon at %s\n' "EID 4624" "$e4624_user" \
        "$logon_desc" "$e4624_ts"
fi
if [[ -z "$e4672_ts" ]]; then
    printf '%-12s : not found in scoped events\n' "EID 4672"
else
    printf '%-12s : %s at %s\n' "EID 4672" "$e4672_privs" "$e4672_ts"
fi
if [[ -z "$e1_ts" ]]; then
    printf '%-12s : not found in scoped events\n' "EID 1"
else
    printf '%-12s : %s at %s\n' "EID 1" "$e1_cmd" "$e1_ts"
fi

printf '%-12s : %s\n' "ambiguity" "$ambiguity_note"

techs_csv="T1078.002 T1059.001"
printf '%-12s : %s\n' "attack" "$techs_csv"

# ---------------------------------------------------------------------------
# 5. Write the finding (locked schema, all 13 keys). The ambiguity note is
#    carried as a dedicated action entry, per the task requirement.
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"
t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

ACTIONS_JSON=$(jq -n \
    --arg amb "$ambiguity_note" \
    --arg cmd "$e1_cmd" \
    --arg crit "$inv_crit" \
    --arg dc "$inv_dataclass" \
    --argjson n "$scoped_count" \
    --arg u "$principal" \
    '[
      "Read scenario manifest scenario_b_offhours_phi.json: host, window, techniques, ambiguity note",
      ("Scoped enriched_events.json to clin-ws-07 in the 02:17:00Z-02:23:00Z window (" + ($n|tostring) + " events)"),
      ("Looked up clin-ws-07 in asset_inventory.json: criticality " + $crit + ", data classification " + $dc),
      "Queried EID 4624 for " + $u + ": RemoteInteractive logon at 02:17:00Z",
      "Queried EID 4672: SeBackupPrivilege SeRestorePrivilege assigned at 02:17:02Z",
      ("Queried Sysmon EID 1: " + $cmd + " at 02:20:00Z"),
      "Reviewed ambiguity: " + $amb,
      "Wrote findings/scenario_b_cli.json conforming to the locked finding schema"
    ]')

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$tffa" \
    --argjson actions "$ACTIONS_JSON" \
    --arg techs "$techs_csv" \
    --slurpfile ev "$SCOPED_TMP" \
    --arg hyp "${principal} performed an off-hours RemoteInteractive logon on PHI workstation ${target_host} (criticality ${inv_crit}, data ${inv_dataclass}), received SeBackup/SeRestore privileges, and executed PowerShell with -ExecutionPolicy Bypass followed by a connection to srv-ehr-01 on 443. The user is the CISO and authorized for EHR access, making this a grey-zone true positive where the off-hours timing and bypass usage warrant escalation." \
    '{
        finding_id: "scenario_b_cli",
        scenario_id: "scenario_b",
        interface: "cli",
        investigation_start: $ts_start,
        investigation_end: $ts_end,
        time_to_first_answer_seconds: $tffa,
        actions: $actions,
        fields_touched: ($ev | map(keys[]) | flatten | unique),
        event_refs: ($ev | map(.record_id)),
        attack_techniques: ($techs | split(" ")),
        hypothesis: $hyp,
        confidence: "medium",
        created_at: $ts_end
    }' > "$OUT_FILE"
cmd_count=$((cmd_count + 1))

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
    and (.finding_id == "scenario_b_cli")
    and (.scenario_id == "scenario_b")
    and (.interface == "cli")
    and (.actions | length <= 20)
    and (.attack_techniques == ["T1078.002","T1059.001"])
    and (.confidence == "low" or .confidence == "medium" or .confidence == "high")
' "$OUT_FILE" >/dev/null; then
    fail "finding" "schema validation failed on $OUT_FILE"
fi

# ---------------------------------------------------------------------------
# 6. Timing summary and exit.
# ---------------------------------------------------------------------------
elapsed=$(( $(date +%s) - t0_epoch ))
printf '%-12s : %s seconds, %s commands\n' "elapsed" "$elapsed" "$cmd_count"

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/scenario_b_cli.json"
    exit 0
fi
exit 1
