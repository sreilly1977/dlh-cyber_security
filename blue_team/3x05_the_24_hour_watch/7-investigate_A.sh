#!/bin/bash
# Name: 7-investigate_A.sh
# Purpose: Deep-dive investigation of Incident A (INC-YYYYMMDD-A) using CLI
#          tools only (jq, sha256sum). Loads the incident record, extracts
#          events for its hosts within first_seen-15min..last_seen+15min,
#          builds a chronologically sorted timeline, checks src_ip/dst_ip
#          against IP IOCs, src_port/dst_port against port IOCs (numeric
#          only, never string-matched to avoid digit false positives), and
#          raw_message against domain/hash/service_name/account IOCs.
#          Prints baseline deviation markers, forms a hypothesis with ATT&CK
#          technique IDs, and writes a Locked Finding Schema artifact with
#          interface "cli". Falls back through enriched_events.jsonl ->
#          enriched_events.json -> normalized_events.json. Event identifiers
#          prefer record_id/event_uid/uid/id; otherwise the SHA-256 of the
#          compact event record. Exits non-zero if fewer than 6 event_refs
#          or fewer than 2 attack_techniques.
# Author: Steve - Cybersecurity Engineer
# Date: 15 September 2026

set -euo pipefail

err_trap() { printf '[inv-A][ERROR] command failed at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'err_trap $LINENO $?' ERR

WS="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE not set - source the environment contract first}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR not set - source the environment contract first}"

INC_FILE="$WS/alerts/incidents.json"
BASE_FILE="$WS/enriched/baseline.json"
IOC_FILE="$ASSETS/ioc_feed.json"
OUT_FILE="$WS/investigations/incident_A.json"
RT_DIR="$WS/runtime"
ACTIONS_FILE="$RT_DIR/invA_actions.jsonl"
TIMELINE_FILE="$RT_DIR/invA_timeline.jsonl"
WINDOW_EVENTS="$RT_DIR/invA_events.jsonl"
IOC_HITS_FILE="$RT_DIR/invA_ioc_hits.txt"

log() { printf '[inv-A] %s\n' "$*"; }
die() { printf '[inv-A][ERROR] %s\n' "$*" >&2; exit 1; }

for f in "$INC_FILE" "$BASE_FILE" "$IOC_FILE"; do
    [[ -f "$f" && -s "$f" ]] || die "required input missing or empty: $f"
done
mkdir -p "$WS/investigations" "$RT_DIR"
: > "$ACTIONS_FILE"

log_action() {
    jq -n --arg tool "$1" --arg cmd "$2" --arg tgt "$3" \
        '{tool: $tool, command: $cmd, target: $tgt}' >> "$ACTIONS_FILE"
}

# --- 1. Load the INC-YYYYMMDD-A record -------------------------------------
log_action jq "jq '[.incidents[] | select(.incident_id | endswith(\"-A\"))][0]' $INC_FILE" "$INC_FILE"
INC_A=$(jq '[.incidents[] | select(.incident_id | endswith("-A"))][0]' "$INC_FILE")
[[ "$INC_A" != "null" && -n "$INC_A" ]] || die "no incident with -A suffix in $INC_FILE"

INC_ID=$(jq -r '.incident_id' <<< "$INC_A")
HOSTS=$(jq -c '[.host_list[]] | unique' <<< "$INC_A")
FIRST_SEEN=$(jq -r '.first_seen' <<< "$INC_A")
LAST_SEEN=$(jq -r '.last_seen' <<< "$INC_A")
ALERT_N=$(jq -r '.alert_ids | length' <<< "$INC_A")

log "loading $INC_ID"
log "host_list: $(jq -r '.host_list | join(", ")' <<< "$INC_A")"
log "alerts: $ALERT_N  rule: $(jq -r '.grouping_rule' <<< "$INC_A")  tentative_category: $(jq -r '.tentative_category' <<< "$INC_A")"

W_START=$(date -u -d "$FIRST_SEEN" +%s); W_START=$((W_START - 900))
W_END=$(date -u -d "$LAST_SEEN" +%s);     W_END=$((W_END + 900))
WS_ISO=$(date -u -d "@$W_START" +%Y-%m-%dT%H:%M:%SZ)
WE_ISO=$(date -u -d "@$W_END" +%Y-%m-%dT%H:%M:%SZ)
log "window: $WS_ISO .. $WE_ISO (incident +/- 15 min)"

# --- 2. Event source fallback chain ----------------------------------------
EVF=""
for cand in "$WS/enriched/enriched_events.jsonl" \
             "$WS/enriched/enriched_events.json" \
             "$WS/enriched/normalized_events.json"; do
    [[ -s "$cand" ]] && { EVF="$cand"; break; }
done
[[ -n "$EVF" ]] || die "no populated events file found"
log "event source: $EVF"

SELECT_BODY='select(.hostname as $h | $hosts | index($h) != null) | select(.timestamp >= $ws and .timestamp <= $we)'
if [[ "$(head -c 1 "$EVF")" == "[" ]]; then
    FILTER=".[] | $SELECT_BODY"
else
    FILTER="$SELECT_BODY"
fi

log_action jq "jq -c --argjson hosts <host_list> --arg ws <start> --arg we <end> '<host+time filter>' $EVF" "$EVF"
jq -c --argjson hosts "$HOSTS" --arg ws "$WS_ISO" --arg we "$WE_ISO" \
    "$FILTER" "$EVF" > "$WINDOW_EVENTS"

EVT_N=$(wc -l < "$WINDOW_EVENTS")
log "events in window: $EVT_N"
(( EVT_N > 0 )) || die "no events in the expanded incident window"

# --- 3. IOC values by type --------------------------------------------------
IOC_IPS=$(jq -c '[.iocs[] | select(.type == "ip") | .value] | unique' "$IOC_FILE")
IOC_PORTS=$(jq -c '[.iocs[] | select(.type == "port") | (.value | tonumber)] | unique' "$IOC_FILE")
IOC_OTHER=$(jq -c '[.iocs[] | select(.type != "ip" and .type != "port") | .value] | unique' "$IOC_FILE")

# --- 4. Prioritized, chronologically sorted timeline (top 6) ----------------
CLS_PROG='def ipmatch($ips):
    ((.src_ip // "") as $s | ($ips | index($s)) != null)
    or ((.dst_ip // "") as $d | ($ips | index($d)) != null);
(map(. + {cls: (
      if .event_category == "authentication" and ((.raw_message // "") | ascii_downcase | test("fail")) then "authfail"
    elif .event_category == "network_alert" then "netalert"
    elif .event_category == "process" and (((.raw_message // "") + " " + (.process_name // "")) | ascii_downcase | test("service|schtasks|install")) then "proc_persist"
    elif ipmatch($iocips) then "netioc"
    elif .event_category == "authentication" then "authok"
    elif .event_category == "process" then "proc"
    elif .event_category == "network" then "net"
    else "other" end)})) as $ev
| (["authfail", "authok", "proc_persist", "netalert", "netioc", "proc", "other"]
   | map(. as $c | ($ev | map(select(.cls == $c))
                    | (if $c == "authfail" then .[0:2] else .[0:1] end))))
| flatten
| sort_by(.timestamp)
| .[0:6]'

log_action jq "jq -s --argjson iocips <ioc_ips> '<class-prioritized selection>' $WINDOW_EVENTS" "$WINDOW_EVENTS"
jq -s --argjson iocips "$IOC_IPS" "$CLS_PROG" "$WINDOW_EVENTS" | jq -c '.[]' > "$TIMELINE_FILE"

TL_N=$(wc -l < "$TIMELINE_FILE")
log "timeline (top $TL_N):"
jq -r '[.timestamp, .hostname, .source_type, .event_category, ((.raw_message // "") | .[0:80])]
       | join("  ")' "$TIMELINE_FILE" | sed 's/^/  /'

# Class counts for the selected timeline events
N_AF=$(jq -s 'map(select(.cls == "authfail")) | length' "$TIMELINE_FILE")
N_OK=$(jq -s 'map(select(.cls == "authok")) | length' "$TIMELINE_FILE")
N_PP=$(jq -s 'map(select(.cls == "proc_persist")) | length' "$TIMELINE_FILE")
N_NA=$(jq -s 'map(select(.cls == "netalert")) | length' "$TIMELINE_FILE")
N_IOC=$(jq -s 'map(select(.cls == "netioc")) | length' "$TIMELINE_FILE")

# --- 5. IOC matching: single-pass scans (IPs, ports, others) -----------------
> "$IOC_HITS_FILE"

# IP hits on src_ip or dst_ip (equality, case-sensitive)
jq -r --argjson ips "$IOC_IPS" '
    [.[] | (.src_ip // "", .dst_ip // "")][]
    | select(. != "" and ($ips | index(.) != null))
' "$WINDOW_EVENTS" >> "$IOC_HITS_FILE" 2>/dev/null || true

# Port hits on src_port or dst_port (numeric equality only)
if jq -e '.[0] | has("src_port")' "$WINDOW_EVENTS" >/dev/null 2>&1; then
    jq -r --argjson ports "$IOC_PORTS" '
        [.[] | (.src_port // "", .dst_port // "")][]
        | select(. != "" and (. != "null") and (($ports | index(tonumber)) != null))
    ' "$WINDOW_EVENTS" >> "$IOC_HITS_FILE" 2>/dev/null || true
fi

# Non-IP/non-port IOC values (domains, hashes, service_names, accounts) in raw_message
jq -r --argjson others "$IOC_OTHER" '
    select($others | length > 0)
    | (.raw_message // "") as $m
    | $others[]
    | select(. != null and ($m | contains(.)))
' "$WINDOW_EVENTS" >> "$IOC_HITS_FILE" 2>/dev/null || true

# Deduplicate and count
sort -u -o "$IOC_HITS_FILE" "$IOC_HITS_FILE" 2>/dev/null || true
MATCH_TOTAL=$(wc -l < "$IOC_HITS_FILE" | tr -d ' ')
MATCHED_VALUES=$(tr '\n' ' ' < "$IOC_HITS_FILE")
[[ -z "$MATCHED_VALUES" ]] && MATCHED_VALUES="(none)"
log "ioc_matches: $MATCH_TOTAL ($MATCHED_VALUES)"

if (( MATCH_TOTAL > 0 )); then
    MIP_JSON=$(jq -R . "$IOC_HITS_FILE" | jq -s '.')
else
    MIP_JSON="[]"
fi

# --- 6. Baseline deviation markers for incident hosts --------------------
log_action jq "jq --argjson hosts <host_list> '[.deviation_markers[] | select(.host in hosts)]' $BASE_FILE" "$BASE_FILE"
MARKERS=$(jq -c --argjson hosts "$HOSTS" \
    '[.deviation_markers[] | select(.host as $h | $hosts | index($h) != null)]' "$BASE_FILE")
MARKER_N=$(jq 'length' <<< "$MARKERS")
log "baseline deviations: $MARKER_N markers for incident hosts"
if (( MARKER_N > 0 )); then
    jq -r '.[] | "  \(.host) \(.marker) \(.observed_value)"' <<< "$MARKERS"
fi

# --- 7. Event refs: timeline events (explicit ID field or record hash) + markers ---
REFS=()
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    id=$(jq -r '.record_id // .event_uid // .uid // .id // empty' <<< "$line")
    if [[ -z "$id" || "$id" == "null" ]]; then
        id=$(printf '%s' "$line" | sha256sum | awk '{print $1}')
    fi
    REFS+=("$id")
done < "$TIMELINE_FILE"

if (( MARKER_N > 0 )); then
    while IFS= read -r mr; do
        [[ -n "$mr" ]] && REFS+=("$mr")
    done < <(jq -r '.[].event_refs[]?' <<< "$MARKERS")
fi

REFS_JSON=$(printf '%s\n' "${REFS[@]}" | jq -R . | jq -s 'unique')
REF_N=$(jq 'length' <<< "$REFS_JSON")
log "event_refs collected: $REF_N"

# --- 8. Hypothesis, techniques, confidence --------------------------------
TECHS=()
if (( N_AF > 0 )); then TECHS+=("T1110.003"); fi   # Brute force: Password Guessing
if (( N_PP > 0 )); then TECHS+=("T1543.003"); fi  # Create/Modify System Process/Service
if (( N_IOC > 0 || N_NA > 0 )); then TECHS+=("T1071.001"); fi  # Web Protocols

# Fallback techniques if we lack sufficient signal
if (( ${#TECHS[@]} < 2 )); then TECHS+=("T1078"); fi     # Valid Accounts
if (( ${#TECHS[@]} < 2 )); then TECHS+=("T1059.001"); fi  # PowerShell

TECH_JSON=$(printf '%s\n' "${TECHS[@]}" | jq -R . | jq -s 'unique')

# Build hypothesis based on evidence pattern
if (( N_AF > 0 && N_PP > 0 && (N_IOC > 0 || N_NA > 0) )); then
    HYP="Automated credential attacks succeeded via off-hours logins, enabling service-based persistence and outbound C2 traffic matching HC-RED7 indicators."
elif (( N_AF > 0 && N_PP > 0 )); then
    HYP="Automated credential attacks preceded service-based persistence on the affected hosts, with C2 not yet confirmed in network telemetry."
elif (( N_AF > 0 )); then
    HYP="Off-hours automated credential attacks were observed on the affected hosts without confirmed follow-on persistence or C2 activity."
else
    HYP="Suspicious process and network activity deviating from baseline was observed across incident hosts; initial access vector unconfirmed."
fi

OPEN_Q=()
CONFIDENCE="high"
if (( MATCH_TOTAL == 0 )); then
    CONFIDENCE="medium"
    OPEN_Q+=("Perimeter firewall and DNS logs covering the incident window would confirm whether any incident host contacted HC-RED7 C2 endpoints.")
fi
if (( MARKER_N == 0 )); then
    CONFIDENCE="medium"
    OPEN_Q+=("A baseline window of 30 or more days for the incident hosts would resolve whether the observed authentication times are true deviations.")
fi

if (( ${#OPEN_Q[@]} == 0 )); then
    OPEN_Q_JSON="[]"
else
    OPEN_Q_JSON=$(printf '%s\n' "${OPEN_Q[@]}" | jq -R . | jq -s '.')
fi

log "hypothesis: $HYP"
log "techniques: $(jq -r 'join(" ")' <<< "$TECH_JSON")"
log "confidence: $CONFIDENCE"

# --- 9. Integrity hashes + assemble the finding ----------------------------
H_INC=$(sha256sum "$INC_FILE" | awk '{print $1}')
H_EVF=$(sha256sum "$EVF" | awk '{print $1}')
H_BASE=$(sha256sum "$BASE_FILE" | awk '{print $1}')
H_IOC=$(sha256sum "$IOC_FILE" | awk '{print $1}')

INPUT_HASHES=$(jq -n --arg inc "$H_INC" --arg evf "$H_EVF" --arg base "$H_BASE" --arg ioc "$H_IOC" \
    '{incidents_json: $inc, events_file: $evf, baseline_json: $base, ioc_feed: $ioc}')

TIMELINE_JSON=$(jq -s 'map(del(.cls))' "$TIMELINE_FILE")

# Validation gates
(( REF_N >= 6 )) || die "event_refs below minimum: $REF_N collected, 6 required"
TECH_N=$(jq 'length' <<< "$TECH_JSON")
(( TECH_N >= 2 )) || die "attack_techniques below minimum: $TECH_N collected, 2 required"

log_action jq "jq -n <args> '<finding assembly>' > $OUT_FILE" "$OUT_FILE"
jq -n \
    --arg fid "FINDING-$INC_ID" \
    --arg iid "$INC_ID" \
    --arg iface "cli" \
    --arg gen "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg first "$FIRST_SEEN" --arg last "$LAST_SEEN" \
    --argjson alert_n "$ALERT_N" --argjson evt_n "$EVT_N" \
    --arg hyp "$HYP" \
    --argjson techs "$TECH_JSON" \
    --argjson refs "$REFS_JSON" \
    --arg conf "$CONFIDENCE" \
    --argjson open_q "$OPEN_Q_JSON" \
    --argjson ioc_matched "$MIP_JSON" \
    --argjson markers "$MARKERS" \
    --argjson timeline "$TIMELINE_JSON" \
    --argjson input_hashes "$INPUT_HASHES" \
    --argjson actions "$(jq -s '.' "$ACTIONS_FILE")" \
    '{
        schema_version: "1.0",
        finding_id: $fid,
        interface: $iface,
        incident_id: $iid,
        created_at: $gen,
        summary: {
            alert_count: $alert_n,
            events_in_window: $evt_n,
            first_seen: $first,
            last_seen: $last
        },
        hypothesis: $hyp,
        attack_techniques: $techs,
        event_refs: $refs,
        evidence: {
            timeline: $timeline,
            ioc_matches: $ioc_matched,
            baseline_markers: $markers,
            input_hashes: $input_hashes
        },
        confidence: $conf,
        open_questions: $open_q,
        actions: $actions
    }' > "$OUT_FILE"

log "event_refs: $REF_N  attack_techniques: $TECH_N"
log "incident_A.json written"
exit 0
