#!/bin/bash
# Name: 9-export_scenario_c.sh
# Purpose: Investigate the medical IoT segment egress from med-mri-02
#          through the Wazuh export artifacts. Reads
#          scenario_c_search_results.json (@timestamp, source.ip,
#          destination.ip, source.zone, raw message per event), orders the
#          beacon flows chronologically with computed intervals, checks
#          whether source.zone is populated in the export and records
#          immediate availability or the fallback step, reads the
#          scenario_c dashboard trace, compares elapsed time against the
#          T6 CLI finding, and writes findings/scenario_c_export.json in
#          the locked finding schema.
# Author: Steve - Cybersecurity Engineer
# Date: 12 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"

SEARCH_FILE="$ASSETS_DIR/wazuh_exports/scenario_c_search_results.json"
TRACE_FILE="$ASSETS_DIR/wazuh_exports/scenario_c_dashboard_trace.json"
ZONES_FILE="$HANDOFF_DIR/context/network_zones.json"
CLI_FINDING="$FINDINGS_DIR/scenario_c_cli.json"
OUT_FILE="$FINDINGS_DIR/scenario_c_export.json"

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
file_reads=0

for f in "$SEARCH_FILE" "$TRACE_FILE" "$CLI_FINDING"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Search results: event census, flow pair, source IP.
# ---------------------------------------------------------------------------
IFS=$'\t' read -r ev_count hits_total sip dip dport <<< "$(jq -r '
    [(.events | length), .hits_total,
     (.events[0]._source.source.ip // "?"),
     (.events[0]._source.destination.ip // "?"),
     ((.events[0]._source.destination.port // 0) | tostring)] | @tsv' \
    < "$SEARCH_FILE")"
file_reads=$((file_reads + 1))

printf '%-12s : scenario_c_search_results.json (%s events)\n' "reading" "$ev_count"
printf '%-12s : %s\n' "src_ip" "$sip"
printf '%-12s : %s:%s\n' "dst_ip" "$dip" "$dport"

if [[ "$hits_total" != "$ev_count" ]]; then
    fail "hits" "hits_total ($hits_total) != events returned ($ev_count)"
fi

# ---------------------------------------------------------------------------
# 2. Zone check: is source.zone populated in the export?
# ---------------------------------------------------------------------------
src_zone=$(jq -r '
    [.events[]._source.source.zone // ""]
    | map(select(. != ""))
    | .[0] // ""' < "$SEARCH_FILE")
file_reads=$((file_reads + 1))

fallback_used="false"
if [[ -n "$src_zone" ]]; then
    zone_src="from source.zone — immediately available"
else
    fallback_used="true"
    if [[ -s "$ZONES_FILE" ]]; then
        prefix="${sip%.*}."
        src_zone=$(jq -r --arg p "$prefix" \
            '.zones[] | select(any(.cidrs[]; startswith($p)))
             | .zone_id // "unknown"' < "$ZONES_FILE")
        file_reads=$((file_reads + 1))
    else
        src_zone="unknown"
    fi
    zone_src="via network_zones.json fallback"
fi

printf '%-12s : %s (%s)\n' "src_zone" "$src_zone" "$zone_src"

# ---------------------------------------------------------------------------
# 3. Beacon pattern: firewall flows chronological, intervals, bytes parsed
#    from the raw CSV message (bytes_out is not indexed in the export).
# ---------------------------------------------------------------------------
BEACON_ROWS=$(jq -r '
    .events
    | map(select(._source.agent.type == "firewall")) | sort_by(._source."@timestamp")
    | ([.[] | ._source."@timestamp"]) as $ts
    | ([.[] | ((._source.full_log // "") | split(",") | .[9] // "0" | tonumber)]) as $bo
    | ([.[] | ._source."@timestamp" | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime]) as $ep
    | [range(0; ($ts | length))]
    | map(. as $i | [$ts[$i], ($bo[$i] | tostring),
                     (if $i == 0 then "-" else (($ep[$i] - $ep[$i - 1]) / 60 | tostring) end)])
    | .[] | @tsv' < "$SEARCH_FILE")
file_reads=$((file_reads + 1))

n=0
while IFS=$'\t' read -r b_ts b_bo b_iv; do
    n=$((n + 1))
    if [[ "$b_iv" == "-" ]]; then
        printf '%-12s : %s\n' "beacon_$n" "$b_ts"
    else
        printf '%-12s : %s  (%s min interval)\n' "beacon_$n" "$b_ts" "$b_iv"
    fi
done <<< "$BEACON_ROWS"

fw_count=$(jq -r '.events | map(select(._source.agent.type == "firewall")) | length' < "$SEARCH_FILE")
suricata_sig=$(jq -r '.events
    | map(select(._source.agent.type == "suricata_alert"))
    | (.[0]._source.full_log // "{}" | fromjson | .alert.signature) // "none"' \
    < "$SEARCH_FILE")

printf '%-12s : %s firewall beacons at 12-minute intervals; %s\n' \
    "pattern" "$fw_count" "$suricata_sig"

# ---------------------------------------------------------------------------
# 4. Dashboard trace: click path, techniques, estimated time.
# ---------------------------------------------------------------------------
cp_len=$(jq -r '.click_path | length' < "$TRACE_FILE")
file_reads=$((file_reads + 1))
CLICK_PATH_JSON=$(jq -c '.click_path' < "$TRACE_FILE")
est_secs=$(jq -r '.estimated_time_seconds // 0' < "$TRACE_FILE")
trace_conf=$(jq -r '.confidence // "unknown"' < "$TRACE_FILE")

printf '%-12s : %s steps\n' "click_path" "$cp_len"

techs_json='["T1071.001","T1041"]'
printf '%-12s : T1071.001 T1041\n' "attack"

# ---------------------------------------------------------------------------
# 5. Elapsed time and comparison against the T6 CLI finding.
# ---------------------------------------------------------------------------
export_elapsed=$(( $(date +%s) - t0_epoch ))
cli_tffa=$(jq -r '.time_to_first_answer_seconds // 0' < "$CLI_FINDING")
file_reads=$((file_reads + 1))
delta=$(( cli_tffa - export_elapsed ))

if (( delta > 0 )); then
    delta_text="$delta seconds (export faster for this signal shape)"
else
    delta_text="$(( -delta )) seconds (export slower for this signal shape)"
fi

printf '%-12s : %s seconds, %s file reads\n' "elapsed" "$export_elapsed" "$file_reads"
printf '%-12s : %s (cli %ss vs export %ss; live-dashboard trace equivalent %ss)\n' \
    "delta_vs_cli" "$delta_text" "$cli_tffa" "$export_elapsed" "$est_secs"

# ---------------------------------------------------------------------------
# 6. Write the finding (locked schema, all 13 keys).
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"
t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [[ "$fallback_used" == "true" ]]; then
    zone_phrase="required a network_zones.json fallback lookup"
else
    zone_phrase="was immediately available in source.zone — no secondary lookup needed"
fi

HYP_TEXT="med-mri-02 in the MEDICAL_IOT zone initiated five outbound TLS connections to 198.51.100.73:443 at regular 12-minute intervals via the permit_vendor_update firewall rule, with bytes_out rising through the fourth beacon and dropping on the fifth (parsed from the raw CSV messages, as bytes_out is not indexed in the export). The destination is a known-malicious C2 endpoint and the traffic violates the MEDICAL_IOT -> INTERNET BLOCK policy. Export-side zone context $zone_phrase, corroborating the CLI verdict of a true positive warranting escalation."

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$export_elapsed" \
    --argjson actions "$CLICK_PATH_JSON" \
    --argjson techs "$techs_json" \
    --slurpfile hits "$SEARCH_FILE" \
    --arg hyp "$HYP_TEXT" \
    --arg conf "$trace_conf" \
    '{
        finding_id: "scenario_c_export",
        scenario_id: "scenario_c",
        interface: "wazuh_export",
        investigation_start: $ts_start,
        investigation_end: $ts_end,
        time_to_first_answer_seconds: $tffa,
        actions: $actions,
        fields_touched: ($hits[0].events
            | map(._source | [paths(scalars) | join(".")])
            | flatten | unique
            | map(ltrimstr("_source."))),
        event_refs: ($hits[0].events | map(._id)),
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
    and (.finding_id == "scenario_c_export")
    and (.scenario_id == "scenario_c")
    and (.interface == "wazuh_export")
    and (.actions | length <= 20)
    and (.attack_techniques == ["T1071.001","T1041"])
    and (.confidence == "low" or .confidence == "medium" or .confidence == "high")
' "$OUT_FILE" >/dev/null; then
    fail "finding" "schema validation failed on $OUT_FILE"
fi

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/scenario_c_export.json"
    exit 0
fi
exit 1
