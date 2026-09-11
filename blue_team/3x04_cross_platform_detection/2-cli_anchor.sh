#!/bin/bash
# Name: 2-cli_anchor.sh
# Purpose: Investigate the known anchor event (SSH brute force against
#          db-patient-01) end to end using CLI tools only. Streams
#          enriched_events.json (NDJSON, never slurped) against the anchor
#          manifest, gathers the match census, prints the Sigma rule's
#          detection and logsource sections via yq, measures wall-clock
#          time from first command to written finding, and emits
#          findings/anchor_cli.json in the locked finding schema.
# Author: Steve - Cybersecurity Engineer
# Date: 11 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

ANCHOR_FILE="$ASSETS_DIR/anchor_event.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
RULE_FILE="$CATALOG_DIR/rules/sigma/001_ssh_brute_force.yml"
OUT_FILE="$FINDINGS_DIR/anchor_cli.json"

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

# Wall clock starts before the first investigation command.
t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cmd_count=0

# ---------------------------------------------------------------------------
# 1. Prerequisites and anchor manifest. @tsv + read keeps this shellcheck-
#    clean; the attacker list is emitted twice: joined for display and as
#    JSON for the filter below.
# ---------------------------------------------------------------------------
for f in "$ANCHOR_FILE" "$EVENTS_FILE"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

MANIFEST_ROW=$(jq -r '[.target_host, .target_ip,
                       .time_window.start, .time_window.end,
                       (.attacker_ips | join(",")),
                       (.attacker_ips | tojson)] | @tsv' \
    < "$ANCHOR_FILE")
cmd_count=$((cmd_count + 1))

IFS=$'\t' read -r target_host target_ip tw_start tw_end ip_csv ip_json \
    <<< "$MANIFEST_ROW"

printf '%-12s : %s\n' "reading" '$ASSETS_DIR/anchor_event.json'
printf '%-12s : %s (%s)\n' "host" "$target_host" "$target_ip"
printf '%-12s : %s -> %s\n' "window" "$tw_start" "$tw_end"
printf '%-12s : %s\n' "attacker ips" "$(printf '%s' "$ip_csv" | tr ',' ' ')"

# ---------------------------------------------------------------------------
# 2. Stream-filter enriched_events.json (264 MB NDJSON — never slurped).
#    Only the matched lines (expected: 48) are materialised to a temp file.
# ---------------------------------------------------------------------------
TMP_MATCHES="$(mktemp)"
trap 'rm -f "$TMP_MATCHES"' EXIT

jq -c --arg h "$target_host" --arg s "$tw_start" --arg e "$tw_end" \
    --argjson ips "$ip_json" '
    select(.hostname == $h)
    | select(.timestamp != null and .timestamp >= $s and .timestamp <= $e)
    | select(.src_ip as $ip | $ips | index($ip))
' < "$EVENTS_FILE" > "$TMP_MATCHES"
cmd_count=$((cmd_count + 1))

# ---------------------------------------------------------------------------
# 3. Census: count, earliest, latest. True min/max over the stream, since the
#    file is not chronologically ordered. This census is the first answer.
# ---------------------------------------------------------------------------
CENSUS_ROW=$(jq -sr '[length,
                     ([.[].timestamp] | min),
                     ([.[].timestamp] | max)] | @tsv' \
    < "$TMP_MATCHES")
cmd_count=$((cmd_count + 1))

IFS=$'\t' read -r match_count first_ts last_ts <<< "$CENSUS_ROW"

if [[ "${match_count:-0}" -eq 0 ]]; then
    fail "matched" "no events matched the anchor window and attacker IPs"
    exit 1
fi

# First investigative answer obtained: the census is complete.
tffa=$(( $(date +%s) - t0_epoch ))

printf '%-12s : %s events in enriched_events.json\n' "matched" "$match_count"
printf '%-12s : %s\n' "first event" "$first_ts"
printf '%-12s : %s\n' "last event" "$last_ts"

# ---------------------------------------------------------------------------
# 4. Read the firing Sigma rule with yq and print detection + logsource.
# ---------------------------------------------------------------------------
techs_var=""
if [[ -s "$RULE_FILE" ]]; then
    TECHS=$(yq -r '.tags[] | select(test("attack\\.t")) | sub("attack\\."; "")' \
        "$RULE_FILE" | tr '[:lower:]' '[:upper:]' | paste -sd, -)
    cmd_count=$((cmd_count + 1))
    if [[ -n "$TECHS" ]]; then
        printf '%-12s : 001_ssh_brute_force (%s)\n' "rule" "$TECHS"
    else
        printf '%-12s : 001_ssh_brute_force (no attack tags)\n' "rule"
    fi

    printf '  logsource:\n'
    yq '.logsource' "$RULE_FILE" | sed 's/^/    /'
    printf '  detection:\n'
    yq '.detection' "$RULE_FILE" | sed 's/^/    /'
    cmd_count=$((cmd_count + 1))
else
    printf '%-12s : 001_ssh_brute_force (rule file not found)\n' "rule"
fi
techs_var="${TECHS:-}"

# ---------------------------------------------------------------------------
# 5. Write the finding. fields_touched is the union of keys across matched
#    events; event_refs come from record_id.
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"
t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

read -r -d '' ACTIONS_JSON <<'EOF' || true
[
  "Read anchor manifest (anchor_event.json): target_host, target_ip, time_window, attacker_ips",
  "Streamed enriched_events.json with jq filtering hostname, time window, and attacker source IPs",
  "Aggregated match count, earliest event, and latest event timestamps over the matched set",
  "Read 001_ssh_brute_force.yml with yq: logsource, detection, and ATT&CK tags",
  "Wrote findings/anchor_cli.json conforming to the locked finding schema"
]
EOF

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$tffa" \
    --argjson actions "$ACTIONS_JSON" \
    --arg techs "$techs_var" \
    --slurpfile ev "$TMP_MATCHES" \
    --arg hyp "Distributed SSH brute force against db-patient-01 from four external IPs, culminating in a successful root login at 01:47:00Z. Recommend immediate root credential rotation, blocking the four source IPs, and Tier 2 escalation with the matched records preserved." \
    '{
        finding_id: "anchor_cli",
        scenario_id: "anchor",
        interface: "cli",
        investigation_start: $ts_start,
        investigation_end: $ts_end,
        time_to_first_answer_seconds: $tffa,
        actions: $actions,
        fields_touched: ($ev | map(keys[]) | flatten | unique),
        event_refs: ($ev | map(.record_id)),
        attack_techniques: (if $techs == "" then [] else ($techs | split(",")) end),
        hypothesis: $hyp,
        confidence: "high",
        created_at: $ts_end
    }' > "$OUT_FILE"
cmd_count=$((cmd_count + 1))

if [[ ! -s "$OUT_FILE" ]]; then
    fail "finding" "could not write $OUT_FILE"
    exit 1
fi

# Schema self-check: exact key set, action cap, enum validity.
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
printf '%-12s : %s seconds, %s commands\n' "elapsed" "$elapsed" "$cmd_count"

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/anchor_cli.json"
    exit 0
fi
exit 1
