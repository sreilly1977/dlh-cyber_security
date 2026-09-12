#!/bin/bash
# Name: 13-workflow_comparison.sh
# Purpose: Compute the aggregate workflow metrics across every finding in
#          findings/ and produce the final cross-platform workflow
#          comparison dataset. Per interface: totals, averages, and
#          medians for time_to_first_answer_seconds, action_count,
#          fields_touched_count, and event_refs_count. Per scenario:
#          deltas between the cli and wazuh_export findings (sign
#          convention: wazuh_export - cli, so negative means the export
#          was faster/smaller). Aggregate confidence distribution per
#          interface. Emits comparison/workflow_comparison.json as a
#          single object with keys per_interface, per_scenario,
#          confidence_distribution, and generated_at, and prints a
#          summary table safe to paste into the vendor brief.
# Author: Steve - Cybersecurity Engineer
# Date: 12 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"
COMPARE_DIR="${COMPARE_DIR:-$SCRIPT_DIR/comparison}"
OUT_FILE="$COMPARE_DIR/workflow_comparison.json"

failures=0
fail() {
    printf '%-20s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

shopt -s nullglob
findings=( "$FINDINGS_DIR"/*.json )
shopt -u nullglob

if (( ${#findings[@]} == 0 )); then
    fail "findings" "no findings in $FINDINGS_DIR"
    exit 1
fi

mkdir -p "$COMPARE_DIR"

# ---------------------------------------------------------------------------
# Normalize each finding to flat metric fields, guarding for metrics that
# may be stored as arrays (actions, fields_touched, event_refs) or counts.
# Findings are SLURPED (-s): each file is a single JSON object, so the
# eight inputs are concatenated into one array before map/group_by.
# ---------------------------------------------------------------------------
BASE_JQ='map(select(.scenario_id != null and .interface != null)
    | {scenario_id, interface,
       tffa: .time_to_first_answer_seconds,
       actions: (if (.actions | type) == "array" then (.actions | length) else .actions end),
       fields: (if (.fields_touched | type) == "array" then (.fields_touched | length) else .fields_touched end),
       refs: (if (.event_refs | type) == "array" then (.event_refs | length) else .event_refs end),
       confidence: .confidence})'

AGG_JQ="$BASE_JQ"'
| def median(x): (x | sort) as $s | ($s | length) as $n
    | if $n == 0 then null
      elif $n % 2 == 1 then $s[($n - 1) / 2]
      else (($s[$n / 2 - 1] + $s[$n / 2]) / 2)
      end;
  def mstats(f): {total: (map(f) | add),
                  avg: (((map(f) | add) / length) * 100 | round / 100),
                  median: median(map(f))};
  {
    per_interface: (group_by(.interface) | map({
        interface: .[0].interface,
        findings: length,
        time_to_first_answer_seconds: mstats(.tffa),
        action_count: mstats(.actions),
        fields_touched_count: mstats(.fields),
        event_refs_count: mstats(.refs)})),
    per_scenario: (group_by(.scenario_id) | map({
        scenario_id: .[0].scenario_id,
        cli: (map(select(.interface == "cli")) | .[0]),
        wazuh_export: (map(select(.interface == "wazuh_export")) | .[0]),
        delta_tffa_seconds: ((map(select(.interface == "wazuh_export")) | .[0].tffa)
                             - (map(select(.interface == "cli")) | .[0].tffa)),
        delta_actions: ((map(select(.interface == "wazuh_export")) | .[0].actions)
                        - (map(select(.interface == "cli")) | .[0].actions))})),
    confidence_distribution: (group_by(.interface) | map({
        interface: .[0].interface,
        low:    (map(select(.confidence == "low"))    | length),
        medium: (map(select(.confidence == "medium")) | length),
        high:   (map(select(.confidence == "high"))   | length)})),
    generated_at: (now | todateiso8601)
  }'

if ! jq -s "$AGG_JQ" "${findings[@]}" > "$OUT_FILE"; then
    fail "aggregate" "jq aggregation failed"
    exit 1
fi

if [[ ! -s "$OUT_FILE" ]]; then
    fail "output" "could not write $OUT_FILE"
    exit 1
fi

# ---------------------------------------------------------------------------
# Summary table (paste-safe for the vendor brief).
# ---------------------------------------------------------------------------
printf '%-20s : %s (%s cli + %s wazuh_export)\n' "findings loaded" \
    "$(jq '[.per_interface[].findings] | add' "$OUT_FILE")" \
    "$(jq -r '.per_interface[] | select(.interface == "cli") | .findings' "$OUT_FILE")" \
    "$(jq -r '.per_interface[] | select(.interface == "wazuh_export") | .findings' "$OUT_FILE")"

printf 'per interface totals:\n'
while IFS=$'\t' read -r iface t tot tot_median act act_tot ref ref_tot; do
    printf '  %-13s : %ss total, avg %ss, median %ss, %s actions, %s fields_touched, %s event_refs\n' \
        "$iface" "$tot" "$t" "$tot_median" "$act" "$act_tot" "$ref"
done < <(jq -r '.per_interface[]
    | [.interface,
       (.time_to_first_answer_seconds.avg   | tostring),
       (.time_to_first_answer_seconds.total | tostring),
       (.time_to_first_answer_seconds.median| tostring),
       (.action_count.total                 | tostring),
       (.fields_touched_count.total         | tostring),
       (.event_refs_count.total             | tostring)]
    | @tsv' "$OUT_FILE")

printf 'per interface confidence:\n'
while IFS=$'\t' read -r iface lo mid hi; do
    printf '  %-13s : high=%s medium=%s low=%s\n' "$iface" "$hi" "$mid" "$lo"
done < <(jq -r '.confidence_distribution[]
    | [.interface, (.low|tostring), (.medium|tostring), (.high|tostring)]
    | @tsv' "$OUT_FILE")

printf 'per scenario deltas (wazuh_export - cli):\n'
while IFS=$'\t' read -r sid dt da; do
    verdict="tie"
    if (( dt < 0 )); then verdict="wazuh_export faster"
    elif (( dt > 0 )); then verdict="cli faster"; fi
    printf '  %-13s : %ss (%s)\n' "$sid" "$dt" "$verdict"
done < <(jq -r '.per_scenario[]
    | [.scenario_id, (.delta_tffa_seconds|tostring), (.delta_actions|tostring)]
    | @tsv' "$OUT_FILE")

printf '%s\n' "comparison/workflow_comparison.json written"

exit 0
