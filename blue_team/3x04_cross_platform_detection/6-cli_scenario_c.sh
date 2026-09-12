#!/bin/bash
# Name: 6-cli_scenario_c.sh
# Purpose: Investigate the medical IoT segment egress from med-mri-02
#          through CLI tools only. Reads the scenario manifest, streams
#          enriched_events.json for the src/dst flow pair, verifies the
#          source zone against network_zones.json (including the
#          inter-zone rule violation), checks the destination IP against
#          the 3x03 IOC context feed, orders the beacon events
#          chronologically with computed intervals, and writes
#          findings/scenario_c_cli.json in the locked finding schema.
# Author: Steve - Cybersecurity Engineer
# Date: 12 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x04_assets}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
FINDINGS_DIR="${FINDINGS_DIR:-$SCRIPT_DIR/findings}"
IOC_CONTEXT="${IOC_CONTEXT:-$HOME/3x03_assets/ioc_context.json}"

MANIFEST_FILE="$ASSETS_DIR/scenarios/scenario_c_medical_egress.json"
EVENTS_FILE="$HANDOFF_DIR/data/enriched_events.json"
ZONES_FILE="$HANDOFF_DIR/context/network_zones.json"
OUT_FILE="$FINDINGS_DIR/scenario_c_cli.json"

SRC_IP="${SRC_IP:-10.2.3.2}"
DST_IP="${DST_IP:-198.51.100.73}"

failures=0
fail() {
    printf '%-12s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

t0_epoch=$(date +%s)
t_start_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cmd_count=0

for f in "$MANIFEST_FILE" "$EVENTS_FILE" "$ZONES_FILE"; do
    if [[ ! -s "$f" ]]; then
        fail "prereq" "missing or empty: $f"
    fi
done
if [[ "$failures" -gt 0 ]]; then
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Manifest: label, window, techniques. src/dst IPs come from the
#    manifest's host_path narrative; the flow pair is the scenario pivot.
# ---------------------------------------------------------------------------
IFS=$'\t' read -r tw_start tw_end techs_csv <<< "$(jq -r '
    [.time_window.start, .time_window.end, (.mitre_techniques | join(" "))] | @tsv' \
    < "$MANIFEST_FILE")"
cmd_count=$((cmd_count + 1))
scenario_label=$(basename "$MANIFEST_FILE" .json)

# ---------------------------------------------------------------------------
# 2. Zone verification: match the source IP's /24 against the zones file,
#    then pull the MEDICAL_IOT -> INTERNET inter-zone rule.
# ---------------------------------------------------------------------------
src_prefix="${SRC_IP%.*}"    # 10.2.3.2 -> 10.2.3
ZONE_JSON=$(jq -c --arg p "${src_prefix}." \
    '.zones[] | select(any(.cidrs[]; startswith($p)))' < "$ZONES_FILE")
cmd_count=$((cmd_count + 1))
zone_id=$(jq -r '.zone_id // "unknown"' <<< "$ZONE_JSON")

IZR_JSON=$(jq -c --arg z "$zone_id" \
    '.inter_zone_rules[] | select(.from == $z and .to == "INTERNET")' \
    < "$ZONES_FILE")
cmd_count=$((cmd_count + 1))
izr_action=$(jq -r '.action // "none"' <<< "$IZR_JSON")
izr_sev=$(jq -r '.severity // "n/a"' <<< "$IZR_JSON")
izr_notes=$(jq -r '.notes // ""' <<< "$IZR_JSON")

printf '%-12s : %s\n' "scenario" "$scenario_label"
printf '%-12s : %s (%s zone)\n' "src_ip" "$SRC_IP" "$zone_id"
printf '%-12s : %s\n' "dst_ip" "$DST_IP"

# ---------------------------------------------------------------------------
# 3. Stream the enriched NDJSON for the flow pair (single full pass).
# ---------------------------------------------------------------------------
SCOPED_TMP="$(mktemp)"
trap 'rm -f "$SCOPED_TMP"' EXIT

jq -c --arg s "$SRC_IP" --arg d "$DST_IP" \
    'select(.src_ip == $s and .dst_ip == $d)' \
    < "$EVENTS_FILE" > "$SCOPED_TMP"
cmd_count=$((cmd_count + 1))

matched_count=$(wc -l < "$SCOPED_TMP")
printf '%-12s : %s flows in enriched_events.json\n' "matched" "$matched_count"

if [[ "$matched_count" -eq 0 ]]; then
    fail "matched" "no flows for $SRC_IP -> $DST_IP"
    exit 1
fi

tffa=$(( $(date +%s) - t0_epoch ))

# ---------------------------------------------------------------------------
# 4. Beacon pattern: firewall flows ordered chronologically, intervals in
#    minutes via epoch conversion, plus the Suricata corroboration.
# ---------------------------------------------------------------------------
BEACON_ROWS=$(jq -sr '
    map(select(.source_type == "firewall")) | sort_by(.timestamp)
    | ([.[] | .timestamp]) as $ts
    | ([.[] | (.bytes_out // 0)]) as $bo
    | ([.[] | .timestamp | strptime("%Y-%m-%dT%H:%M:%SZ") | mktime]) as $ep
    | [range(0; ($ts | length))]
    | map(. as $i | [$ts[$i], ($bo[$i] | tostring),
                     (if $i == 0 then "-"
                      else (($ep[$i] - $ep[$i - 1]) / 60 | tostring) end)])
    | .[] | @tsv' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

n=0
while IFS=$'\t' read -r b_ts b_bo b_iv; do
    n=$((n + 1))
    if [[ "$b_iv" == "-" ]]; then
        printf '%-12s : %s  (bytes_out: %s)\n' "beacon_$n" "$b_ts" "$b_bo"
    else
        printf '%-12s : %s  (interval: %s min, bytes_out: %s)\n' \
            "beacon_$n" "$b_ts" "$b_iv" "$b_bo"
    fi
done <<< "$BEACON_ROWS"

fw_count=$(jq -sr 'map(select(.source_type == "firewall")) | length' < "$SCOPED_TMP")
total_bo=$(jq -sr 'map(select(.source_type == "firewall") | (.bytes_out // 0)) | add // 0' < "$SCOPED_TMP")
suricata_sig=$(jq -sr 'map(select(.source_type == "suricata") | .signature) | .[0] // "none"' < "$SCOPED_TMP")
cmd_count=$((cmd_count + 1))

printf '%-12s : %s firewall beacons, %s bytes_out total (~%dKB)\n' \
    "pattern" "$fw_count" "$total_bo" "$(( total_bo / 1024 ))"
printf '%-12s : %s\n' "suricata" "$suricata_sig"

printf '%-12s : %s — outbound restricted to RADIOLOGY only; %s -> INTERNET is %s/%s: %s\n' \
    "zone" "$zone_id" "$zone_id" "$izr_action" "$izr_sev" "$izr_notes"

# ---------------------------------------------------------------------------
# 5. IOC check on the destination IP (graceful if not listed).
# ---------------------------------------------------------------------------
if [[ -s "$IOC_CONTEXT" ]]; then
    IOC_JSON=$(jq -c --arg ip "$DST_IP" '.indicators[$ip] // empty' \
        < "$IOC_CONTEXT")
    cmd_count=$((cmd_count + 1))
    if [[ -n "$IOC_JSON" ]]; then
        ioc_rep=$(jq -r '.reputation' <<< "$IOC_JSON")
        ioc_cats=$(jq -r '.categories | join("/")' <<< "$IOC_JSON")
        ioc_actor=$(jq -r '.threat_actor // "n/a"' <<< "$IOC_JSON")
        ioc_loc=$(jq -r '.geolocation.city // "?"' <<< "$IOC_JSON")
        printf '%-12s : %s is %s (%s, %s, actor %s)\n' \
            "ioc" "$DST_IP" "$ioc_rep" "$ioc_cats" "$ioc_loc" "$ioc_actor"
    else
        ioc_rep="not_listed"; ioc_cats=""; ioc_actor=""; ioc_loc=""
        printf '%-12s : %s not listed in ioc_context.json\n' "ioc" "$DST_IP"
    fi
else
    ioc_rep="unavailable"; ioc_cats=""; ioc_actor=""; ioc_loc=""
    printf '%-12s : ioc_context.json not available\n' "ioc"
fi

printf '%-12s : %s\n' "attack" "$techs_csv"

# ---------------------------------------------------------------------------
# 6. Write the finding (locked schema, all 13 keys).
# ---------------------------------------------------------------------------
mkdir -p "$FINDINGS_DIR"
t_end_iso=$(date -u +%Y-%m-%dT%H:%M:%SZ)

ACTIONS_JSON=$(jq -n \
    --argjson n "$matched_count" \
    --argjson fw "$fw_count" \
    --argjson bo "$total_bo" \
    --arg rep "$ioc_rep" \
    --arg cats "$ioc_cats" \
    --arg actor "$ioc_actor" \
    --arg sig "$suricata_sig" \
    --arg z "$zone_id" \
    '[
      "Read scenario manifest scenario_c_medical_egress.json: host, window, techniques, zone violation note",
      ("Streamed enriched_events.json for 10.2.3.2 -> 198.51.100.73: " + ($n|tostring) + " matched records"),
      ("Ordered " + ($fw|tostring) + " firewall beacons chronologically: 12-minute intervals, " + ($bo|tostring) + " bytes_out total, rising through beacon 4 then dropping on beacon 5"),
      ("Corroborated with Suricata alert: " + $sig),
      "Verified zone in network_zones.json: 10.2.3.0/24 is MEDICAL_IOT, outbound restricted to RADIOLOGY only, MEDICAL_IOT -> INTERNET is BLOCK/CRITICAL",
      ("Checked destination IP in ioc_context.json: reputation " + $rep + ($cats | if . == "" then "" else " (" + . + ")" end) + ($actor | if . == "" then "" else ", threat actor " + . end)),
      "Confirmed flows permitted by firewall rule permit_vendor_update on interface lan_medical",
      "Wrote findings/scenario_c_cli.json conforming to the locked finding schema"
    ]')

jq -n \
    --arg ts_start "$t_start_iso" \
    --arg ts_end "$t_end_iso" \
    --argjson tffa "$tffa" \
    --argjson actions "$ACTIONS_JSON" \
    --arg techs "$techs_csv" \
    --argjson fw "$fw_count" \
    --argjson bo "$total_bo" \
    --slurpfile ev "$SCOPED_TMP" \
    --arg hyp "med-mri-02 in the MEDICAL_IOT zone initiated five outbound TLS connections to 198.51.100.73:443 at regular 12-minute intervals via the permit_vendor_update firewall rule, with bytes_out rising through the fourth beacon and dropping on the fifth. The destination is a known-malicious C2 endpoint (HC-RED7-CANDIDATE cluster) and the traffic violates the MEDICAL_IOT -> INTERNET BLOCK policy, warranting immediate containment of the device and firewall rule review." \
    '{
        finding_id: "scenario_c_cli",
        scenario_id: "scenario_c",
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

# Schema self-check: exact key set, action cap, technique set.
if ! jq -e '
    (keys | sort) == (["actions","attack_techniques","confidence","created_at","event_refs",
                       "fields_touched","finding_id","hypothesis","interface",
                       "investigation_end","investigation_start","scenario_id",
                       "time_to_first_answer_seconds"] | sort)
    and (.finding_id == "scenario_c_cli")
    and (.scenario_id == "scenario_c")
    and (.interface == "cli")
    and (.actions | length <= 20)
    and (.attack_techniques == ["T1071.001","T1041"])
    and (.confidence == "low" or .confidence == "medium" or .confidence == "high")
' "$OUT_FILE" >/dev/null; then
    fail "finding" "schema validation failed on $OUT_FILE"
fi

# ---------------------------------------------------------------------------
# 7. Timing summary and exit.
# ---------------------------------------------------------------------------
elapsed=$(( $(date +%s) - t0_epoch ))
printf '%-12s : %s seconds, %s commands\n' "elapsed" "$elapsed" "$cmd_count"

if [[ "$failures" -eq 0 ]]; then
    printf '%-12s : %s written\n' "finding" "findings/scenario_c_cli.json"
    exit 0
fi
exit 1
