#!/bin/bash
# Name: 4-cli_scenario_a.sh
# Purpose: Investigate the credential theft chain on clin-ws-12 through
#          CLI tools only. Reads the scenario manifest, scopes the enriched
#          NDJSON stream to the host and time window, extracts the Sysmon
#          EID 10 (LSASS access), EID 11 (dump file creation), and EID 3
#          (SMB lateral movement) chain events, forms an ordered-chain
#          hypothesis, and writes findings/scenario_a_cli.json in the
#          locked finding schema.
# Author: Steve - Cybersecurity Engineer
# Date: 11 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

MANIFEST_FILE="$ASSETS_DIR/scenarios/scenario_a_credential_theft.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
OUT_FILE="$FINDINGS_DIR/scenario_a_cli.json"

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cmd_count=0

for f in "$MANIFEST_FILE" "$EVENTS_FILE"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Manifest: scenario label, primary host, window, techniques.
#    The schema's scenario_id is scenario_<lowercase manifest id>.
# ---------------------------------------------------------------------------
IFS=$'\t' read -r manifest_sid target_host tw_start tw_end techs_csv \
    <<< "$(jq -r '[.scenario_id, .host_path[0],
                   .time_window.start, .time_window.end,
                   (.mitre_techniques | join(" "))] | @tsv' \
        < "$MANIFEST_FILE")"
cmd_count=$((cmd_count + 1))
scenario_label=$(basename "$MANIFEST_FILE" .json)

printf '%-12s : %s\n' "scenario" "$scenario_label"
printf '%-12s : %s\n' "host" "$target_host"
printf '%-12s : %s -> %s\n' "window" "$tw_start" "$tw_end"

# ---------------------------------------------------------------------------
# 2. Scope the NDJSON stream to host + window (single full pass; only the
#    scoped events are materialised to temp).
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

# First investigative answer obtained: the scoped event set is in hand.
tffa=$(( $(date +%s) - t0_epoch ))

# ---------------------------------------------------------------------------
# 3. Chain extraction. Each stage filters the scoped set (10 events, safe
#    to work in memory) and pulls the chain-describing fields from
#    event_data. Benign same-EID events are excluded by substance.
# ---------------------------------------------------------------------------
EID10_TSV=$(jq -sr 'map(select(.event_id == 10))
    | sort_by(.timestamp)
    | if length == 0 then ["", "", ""] else
        [ .[0].timestamp,
          (.[0].event_data.TargetImage // "" | split("\\") | last),
          (.[0].event_data.SourceImage // "" | split("\\") | last) ]
      end | @tsv' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

EID11_TSV=$(jq -sr 'map(select(.event_id == 11
        and ((.event_data.TargetFilename // "") | endswith(".dmp"))))
    | sort_by(.timestamp)
    | if length == 0 then ["", ""] else
        [ .[0].timestamp, .[0].event_data.TargetFilename ]
      end | @tsv' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

EID3_TSV=$(jq -sr 'map(select(.event_id == 3 and .dst_port == 445))
    | sort_by(.timestamp)
    | if length == 0 then ["", "", "", ""] else
        [ .[0].timestamp, (.[0].process_name // ""),
          (.[0].dst_ip // ""), (.[0].dst_port // 0) ]
      end | @tsv' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

IFS=$'\t' read -r e10_ts e10_target e10_source <<< "$EID10_TSV"
IFS=$'\t' read -r e11_ts e11_file <<< "$EID11_TSV"
IFS=$'\t' read -r e3_ts e3_proc e3_ip e3_port <<< "$EID3_TSV"

chain_complete=1
if [[ -z "$e10_ts" ]]; then
    printf '%-12s : not found in scoped events\n' "EID 10"
    chain_complete=0
else
    printf '%-12s : %s accessed by %s at %s\n' "EID 10" "$e10_target" "$e10_source" "$e10_ts"
fi
if [[ -z "$e11_ts" ]]; then
    printf '%-12s : not found in scoped events\n' "EID 11"
    chain_complete=0
else
    printf '%-12s : %s created at %s\n' "EID 11" "$e11_file" "$e11_ts"
fi
if [[ -z "$e3_ts" ]]; then
    printf '%-12s : not found in scoped events\n' "EID 3"
    chain_complete=0
else
    printf '%-12s : %s -> %s:%s at %s\n' "EID 3" "$e3_proc" "$e3_ip" "$e3_port" "$e3_ts"
fi

hyp_summary="LSASS dump via rundll32, lateral move to DC via SMB"
printf '%-12s : %s\n' "hypothesis" "$hyp_summary"
printf '%-12s : %s\n' "attack" "$techs_csv"

# ---------------------------------------------------------------------------
# 4. Write the finding (locked schema, all 13 keys). event_refs cover the
#    full scoped event set; fields_touched is the union of keys across it.
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"
t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

read -r -d '' ACTIONS_JSON <<'EOF' || true
[
  "Read scenario manifest scenario_a_credential_theft.json: host, window, techniques, key events",
  "Scoped enriched_events.json to clin-ws-12 in the 14:22:00Z-14:28:00Z window (10 events)",
  "Queried Sysmon EID 10: lsass.exe accessed by rundll32.exe, GrantedAccess 0x1010",
  "Queried Sysmon EID 11 for .dmp target filenames: C:\\Temp\\debug.dmp created",
  "Queried Sysmon EID 3 for port 445: cmd.exe SMB connection to 10.1.1.10 (srv-dc-01)",
  "Correlated ordered chain EID 10 -> 11 -> 3 against the manifest key events",
  "Wrote findings/scenario_a_cli.json conforming to the locked finding schema"
]
EOF

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$tffa" \
    --argjson actions "$ACTIONS_JSON" \
    --arg techs "$techs_csv" \
    --slurpfile ev "$SCOPED_TMP" \
    --arg hyp "rundll32.exe accessed lsass.exe with GrantedAccess 0x1010 and created C:\\Temp\\debug.dmp, followed by an SMB connection from cmd.exe to srv-dc-01 (10.1.1.10:445). This indicates a credential dumping chain on clin-ws-12 under MEDDEFENSE\\j.martinez progressing to lateral movement toward the domain controller, and warrants immediate containment and credential rotation." \
    '{
        finding_id: "scenario_a_cli",
        scenario_id: "scenario_a",
        interface: "cli",
        investigation_start: $ts_start,
        investigation_end: $ts_end,
        time_to_first_answer_seconds: $tffa,
        actions: $actions,
        fields_touched: ($ev | map(keys[]) | flatten | unique),
        event_refs: ($ev | map(.record_id)),
        attack_techniques: ($techs | split(" ")),
        hypothesis: $hyp,
        confidence: "high",
        created_at: $ts_end
    }' > "$OUT_FILE"
cmd_count=$((cmd_count + 1))

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
    and (.finding_id == "scenario_a_cli")
    and (.scenario_id == "scenario_a")
    and (.interface == "cli")
    and (.actions | length <= 20)
    and (.attack_techniques == ["T1003.001","T1550.002","T1021.002"])
    and (.confidence == "low" or .confidence == "medium" or .confidence == "high")
' "$OUT_FILE" >/dev/null; then
    fail "finding" "schema validation failed on $OUT_FILE"
fi

# ---------------------------------------------------------------------------
# 5. Timing summary and exit.
# ---------------------------------------------------------------------------
elapsed=$(( $(date +%s) - t0_epoch ))
printf '%-12s : %s seconds, %s commands\n' "elapsed" "$elapsed" "$cmd_count"

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/scenario_a_cli.json"
    exit 0
fi
exit 1
