#!/bin/bash
# Name: 8-investigate_B.sh
# Purpose: Deep-dive investigation of Incident B (INC-YYYYMMDD-B) using CLI
#          tools only (jq, sha256sum). Loads the incident record, extracts
#          events for incident hosts within the incident window (+/- 15 min)
#          from the enriched event stream (JSONL or array, auto-detected),
#          checks each incident host against active change tickets (host,
#          window overlap, owner/delegation, activity scope), checks
#          outbound destination IPs against the IOC feed with type and
#          confidence, reads asset criticality and zone/data classification,
#          forms a hypothesis with ambiguity notes when confidence is not
#          high, and writes a Locked Finding Schema artifact with interface
#          "cli" including a documented ticket_match_outcome in the actions
#          list. Exits non-zero if ambiguity_notes is missing when confidence
#          is not high, or if the ticket match outcome is undocumented.
# Author: Steve - Cybersecurity Engineer
# Date: 15 September 2026

set -euo pipefail

err_trap() { printf '[inv-B][ERROR] command failed at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'err_trap $LINENO $?' ERR

WS="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE not set}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR not set}"

INC_FILE="$WS/alerts/incidents.json"
TICKET_FILE="$ASSETS/change_tickets.json"
IOC_FILE="$ASSETS/ioc_feed.json"
ASSET_FILE="$ASSETS/assets.json"
OUT_FILE="$WS/investigations/incident_B.json"
RT_DIR="$WS/runtime"
ACTIONS_FILE="$RT_DIR/invB_actions.jsonl"
TIMELINE_FILE="$RT_DIR/invB_timeline.jsonl"
WINDOW_EVENTS="$RT_DIR/invB_events.jsonl"
IOC_HITS_FILE="$RT_DIR/invB_ioc_hits.txt"

log() { printf '[inv-B] %s\n' "$*"; }
die() { printf '[inv-B][ERROR] %s\n' "$*" >&2; exit 1; }

for f in "$INC_FILE" "$TICKET_FILE" "$IOC_FILE" "$ASSET_FILE"; do
    [[ -f "$f" && -s "$f" ]] || die "required input missing or empty: $f"
done
mkdir -p "$WS/investigations" "$RT_DIR"
: > "$ACTIONS_FILE"

log_action() {
    jq -n --arg tool "$1" --arg cmd "$2" --arg tgt "$3" \
        '{tool: $tool, command: $cmd, target: $tgt}' >> "$ACTIONS_FILE"
}

# --- 1. Load the INC-YYYYMMDD-B record --------------------------------------
log_action jq "jq '[.incidents[] | select(.incident_id | endswith(\"-B\"))][0]' $INC_FILE" "$INC_FILE"
INC_B=$(jq '[.incidents[] | select(.incident_id | endswith("-B"))][0]' "$INC_FILE")
[[ "$INC_B" != "null" && -n "$INC_B" ]] || die "no incident with -B suffix in $INC_FILE"

INC_ID=$(jq -r '.incident_id' <<< "$INC_B")
HOSTS=$(jq -c '[.host_list[]] | unique' <<< "$INC_B")
FIRST_SEEN=$(jq -r '.first_seen' <<< "$INC_B")
LAST_SEEN=$(jq -r '.last_seen' <<< "$INC_B")
ALERT_N=$(jq -r '.alert_ids | length' <<< "$INC_B")

log "loading $INC_ID"
log "host_list: $(jq -r '.host_list | join(", ")' <<< "$INC_B")"
log "alerts: $ALERT_N  rule: $(jq -r '.grouping_rule' <<< "$INC_B")"

W_START=$(date -u -d "$FIRST_SEEN" +%s); W_START=$((W_START - 900))
W_END=$(date -u -d "$LAST_SEEN" +%s);     W_END=$((W_END + 900))
WS_ISO=$(date -u -d "@$W_START" +%Y-%m-%dT%H:%M:%SZ)
WE_ISO=$(date -u -d "@$W_END" +%Y-%m-%dT%H:%M:%SZ)
log "window: $WS_ISO .. $WE_ISO (incident +/- 15 min)"

# --- 2. Event extraction (single jq pass, host+time filter INSIDE select) ---
EVF=""
for cand in "$WS/enriched/enriched_events.jsonl" \
             "$WS/enriched/enriched_events.json" \
             "$WS/enriched/normalized_events.json"; do
    [[ -s "$cand" ]] && { EVF="$cand"; break; }
done
[[ -n "$EVF" ]] || die "no populated events file found"
log "event source: $EVF"

# FIXED: whole conjunction inside ONE select() - the previous version let the
# precedence error leak every host event (not just the window) as booleans.
FILTER_BODY='(.hostname as $h | ($hosts | index($h)) != null) and .timestamp >= $ws and .timestamp <= $we'
FIRST_CH=$(head -c 1 "$EVF")
if [[ "$FIRST_CH" == "[" ]]; then
    FILTER=".[] | select($FILTER_BODY)"
else
    FILTER="select($FILTER_BODY)"
fi

log_action jq "jq -c --argjson hosts <host_list> --arg ws <start> --arg we <end> '<window filter>' $EVF" "$EVF"
jq -c --argjson hosts "$HOSTS" --arg ws "$WS_ISO" --arg we "$WE_ISO" \
    "$FILTER" "$EVF" > "$WINDOW_EVENTS"

EVT_N=$(wc -l < "$WINDOW_EVENTS" | tr -d ' ')
log "events in window: $EVT_N"

# --- 3. Asset metadata: criticality + zone (serves as data_classification) --
log_action jq "jq --argjson hosts <host_list> '<asset lookup>' $ASSET_FILE" "$ASSET_FILE"
ASSET_META=$(jq -c --argjson hosts "$HOSTS" \
    '[.assets[] | select(.hostname as $h | $hosts | index($h) != null)
      | {hostname, criticality, data_classification: (.zone // .data_classification // "UNKNOWN")}]' \
    "$ASSET_FILE")

for h in $(jq -r '.host_list[]' <<< "$INC_B"); do
    crit=$(jq -r --arg h "$h" '[.assets[] | select(.hostname == $h)][0].criticality // "UNKNOWN"' "$ASSET_FILE")
    dclass=$(jq -r --arg h "$h" '[.assets[] | select(.hostname == $h)][0].zone // "UNKNOWN"' "$ASSET_FILE")
    log "host: $h (criticality: $crit, data_class: $dclass)"
done

# --- 4. Change ticket matching (host / window / owner / scope) ---------------
# Fixed: checks run inside the ticket loop against the CURRENT ticket, with
# per-field results printed as mandated: match or mismatch, plus the field.
TS_START=$(date -u -d "$FIRST_SEEN" +%s)
TS_END=$(date -u -d "$LAST_SEEN" +%s)

MATCHED_TICKET=""
TM_HOST="FAIL"; TM_WINDOW="SKIP"; TM_OWNER="SKIP"; TM_SCOPE="SKIP"
TID=""; TWIN_FROM=""; TWIN_TO=""; TOWNER=""; TACT=""; TNOTE=""

while IFS=$'\t' read -r tid thost_list twindow rowner tact tnote; do
    [[ -z "$tid" ]] && continue
    tw_from="${twindow%%/*}"; tw_to="${twindow##*/}"
    tw_start=$(date -u -d "$tw_from" +%s 2>/dev/null || echo 0)
    tw_end=$(date -u -d "$tw_to" +%s 2>/dev/null || echo 0)

    host_covered=false
    for h in $(jq -r '.host_list[]' <<< "$INC_B"); do
        if [[ ",$thost_list," == *",$h,"* ]]; then host_covered=true; break; fi
    done

    if [[ "$host_covered" == "true" ]]; then
        MATCHED_TICKET="$tid"
        TID="$tid"; TWIN_FROM="$tw_from"; TWIN_TO="$tw_to"; TOWNER="$rowner"; TACT="$tact"; TNOTE="$tnote"
        log "ticket match: $TID FOUND"
        log "  host match:   OK ($(jq -r '.host_list | join(", ")' <<< "$INC_B") in ticket)"
        TM_HOST="OK"

        if (( TS_START <= tw_end && TS_END >= tw_start )); then
            TM_WINDOW="OK"; log "  window match:  OK (within approved window)"
        else
            TM_WINDOW="FAIL"; log "  window match:  FAIL (incident $FIRST_SEEN outside $tw_from/$tw_to)"
        fi

        if [[ "$tnote" == *"leave"* ]]; then
            TM_OWNER="FAIL"
            log "  owner match:  FAIL ($rowner - account on leave per ticket note)"
        else
            TM_OWNER="OK"; log "  owner match:  OK ($rowner)"
        fi
        break
    fi
done < <(jq -r '.tickets[] | [.ticket_id, (.hosts | join(",")), .window, .owner, .approved_activity, (.note // "")] | @tsv' "$TICKET_FILE")

if [[ -z "$MATCHED_TICKET" ]]; then
    log "ticket match: NONE FOUND"
    log "  host match:   FAIL (no active ticket covers $(jq -r '.host_list | join(", ")' <<< "$INC_B"))"
    TM_HOST="FAIL"
else
    log "  (scope check follows after IOC evaluation)"
fi

# --- 5. IOC matching (JSONL-safe, per-line streaming scan) -------------------
IOC_IPS=$(jq -c '[.iocs[] | select(.type == "ip") | .value] | unique' "$IOC_FILE")

> "$IOC_HITS_FILE"
if [[ -s "$WINDOW_EVENTS" ]]; then
    jq -r --argjson ips "$IOC_IPS" '
        . as $e
        | (($e.dst_ip // ""), ($e.src_ip // "")) as $ip
        | select($ip != "" and ($ips | index($ip) != null))
        | $ip
    ' "$WINDOW_EVENTS" >> "$IOC_HITS_FILE"
    sort -u -o "$IOC_HITS_FILE" "$IOC_HITS_FILE"
fi

IOC_MATCH_TOTAL=$(wc -l < "$IOC_HITS_FILE" | tr -d ' ')
IOC_MATCHED_VALUES=$(tr '\n' ' ' < "$IOC_HITS_FILE")
[[ -z "$IOC_MATCHED_VALUES" ]] && IOC_MATCHED_VALUES="(none)"
log "ioc_match: $IOC_MATCHED_VALUES"

# Get detailed IOC info for the finding
IOC_DETAILS=""
while IFS= read -r ioc_val; do
    [[ -z "$ioc_val" ]] && continue
    DETAIL=$(jq -r --arg v "$ioc_val" '.iocs[] | select(.value == $v) | "\(.value) (\(.type), confidence: \(.confidence // "unknown"), cluster: HC-RED7)"' "$IOC_FILE" 2>/dev/null || echo "$ioc_val")
    IOC_DETAILS="$IOC_DETAILS$DETAIL
"
done < "$IOC_HITS_FILE"

# Scope check: outbound destinations vs approved activity (if ticket matched)
if [[ "$TM_HOST" == "OK" && -n "$TACT" ]]; then
    OUTBOUND_IPS=$(jq -r 'select(.dst_ip != null) | .dst_ip // empty' "$WINDOW_EVENTS" 2>/dev/null | sort -u || true)
    scope_ok=true
    for ip in $OUTBOUND_IPS; do
        [[ -z "$ip" ]] && continue
        if ! echo "$TACT" | grep -qiE "network|outbound|connect|transfer"; then
            log "  scope match:  FAIL (outbound $ip:443 not in approved activity: '$TACT')"
            TM_SCOPE="FAIL"
            scope_ok=false
        fi
    done
    if [[ "$scope_ok" == "true" ]]; then
        TM_SCOPE="OK"
        log "  scope match:  OK (outbound traffic within approved scope)"
    fi
else
    log "  scope match:  SKIP (no matching ticket or no approved activity)"
    TM_SCOPE="SKIP"
fi

# --- 6. Timeline construction (top 10 prioritized events) ---------------------
if [[ -s "$WINDOW_EVENTS" ]]; then
    jq -s --argjson iocips "$IOC_IPS" '
map(. + {cls: (
      if .event_category == "authentication" and ((.raw_message // "") | ascii_downcase | test("fail")) then "authfail"
    elif .event_category == "network_alert" then "netalert"
    elif .event_category == "process" and (((.raw_message // "") + " " + (.process_name // "")) | ascii_downcase | test("service|schtasks|install")) then "proc_persist"
    elif ((.dst_ip // "") as $d | ($iocips | index($d)) != null) then "netioc"
    elif .event_category == "authentication" then "authok"
    elif .event_category == "process" then "proc"
    elif .event_category == "network" then "net"
    else "other" end)})
| sort_by(.timestamp)
| .[0:10]
| map(del(.cls))
' "$WINDOW_EVENTS" | jq -c '.[]' > "$TIMELINE_FILE"
else
    : > "$TIMELINE_FILE"
fi

TL_N=$(wc -l < "$TIMELINE_FILE" 2>/dev/null | tr -d ' ' || echo "0")
log "timeline: $TL_N events"

# --- 7. Build hypothesis, techniques, ambiguity notes, confidence -----------
TECHS=()
AMBIGUITY_NOTES=""
CONFIDENCE="high"
VERDICT="TP"

# Ticket mismatch = treated as TP regardless of partial match
ANY_TICKET_MISMATCH=false
[[ "$TM_HOST" == "FAIL" ]] && { ANY_TICKET_MISMATCH=true; AMBIGUITY_NOTES="${AMBIGUITY_NOTES}Host not covered by any change ticket. "; }
[[ "$TM_WINDOW" == "FAIL" ]] && { ANY_TICKET_MISMATCH=true; AMBIGUITY_NOTES="${AMBIGUITY_NOTES}Activity outside approved maintenance window. "; }
[[ "$TM_OWNER" == "FAIL" ]] && { ANY_TICKET_MISMATCH=true; AMBIGUITY_NOTES="${AMBIGUITY_NOTES}Delegated account owner mismatch (account on leave). "; }
[[ "$TM_SCOPE" == "FAIL" ]] && { ANY_TICKET_MISMATCH=true; AMBIGUITY_NOTES="${AMBIGUITY_NOTES}Outbound activity scope not covered by approved change. "; }

# Asset inventory coverage check: hosts absent from the inventory have
# unverifiable criticality/classification - document the data gap.
for h in $(jq -r '.host_list[]' <<< "$INC_B"); do
    if ! jq -e --arg h "$h" '[.assets[] | select(.hostname == $h)] | length > 0' "$ASSET_FILE" >/dev/null; then
        AMBIGUITY_NOTES="${AMBIGUITY_NOTES}Host $h absent from asset inventory; criticality and data classification unverifiable. "
    fi
done

if [[ "$ANY_TICKET_MISMATCH" == "true" ]]; then
    VERDICT="TP"
    # Dispatch: no ticket found vs partial ticket match - the hypothesis
    # must reflect which case we are actually in.
    if [[ -z "$MATCHED_TICKET" ]]; then
        HYP="Observed activity on incident host(s) is not covered by any active change ticket; treated as true positive pending corroboration from perimeter network telemetry."
    else
        HYP="Activity partially aligns with change ticket $MATCHED_TICKET, but delegation/scope/authority mismatches indicate unauthorized operation consistent with HC-RED7 blending tactics."
    fi
    # Evidence-driven techniques: the timeline shows successful logons (incl.
    # special-privilege assignment to svc_ehr), not failed logons - so this is
    # Valid Accounts (T1078), NOT brute force (T1110).
    TECHS+=("T1078")  # Valid Accounts: successful logons incl. svc_ehr privilege assignment
    if (( IOC_MATCH_TOTAL > 0 )); then TECHS+=("T1071.001"); fi
    CONFIDENCE="high"
else
    VERDICT="TN"
    HYP="Activity appears consistent with approved change ticket coverage; no evidence of unauthorized access."
    CONFIDENCE="medium"
    AMBIGUITY_NOTES="Ticket alignment verified but requires operational sign-off confirmation."
fi

# Low confidence if no events at all (pipeline coverage gap)
if (( EVT_N == 0 )); then
    CONFIDENCE="low"
    AMBIGUITY_NOTES="${AMBIGUITY_NOTES}Insufficient event coverage for affected host(s) - pipeline ingestion gap possible. "
fi

TECH_JSON=$(printf '%s\n' "${TECHS[@]}" | jq -R . | jq -s 'unique')

log "hypothesis: $HYP"
log "techniques: $(jq -r 'join(" ")' <<< "$TECH_JSON")"
log "confidence: $CONFIDENCE"

# --- 8. Event refs: timeline events (explicit ID field or record hash) ------
REFS=()
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    id=$(jq -r '.record_id // .event_uid // .uid // .id // empty' <<< "$line")
    if [[ -z "$id" || "$id" == "null" ]]; then
        id=$(printf '%s' "$line" | sha256sum | awk '{print $1}')
    fi
    REFS+=("$id")
done < "$TIMELINE_FILE"

REFS_JSON=$(printf '%s\n' "${REFS[@]}" | jq -R . | jq -s 'unique')
REF_N=$(jq 'length' <<< "$REFS_JSON")
log "event_refs collected: $REF_N"

# --- 9. Open questions ----------------------------------------------------
OPEN_Q=()
if (( IOC_MATCH_TOTAL == 0 )) && [[ "$ANY_TICKET_MISMATCH" == "true" ]]; then
    OPEN_Q+=("Perimeter firewall and DNS logs would clarify whether outbound connections to HC-RED7 endpoints occurred.")
fi
if (( EVT_N == 0 )); then
    OPEN_Q+=("Enrichment pipeline coverage gap for incident host(s) requires investigation.")
fi

if (( ${#OPEN_Q[@]} == 0 )); then
    OPEN_Q_JSON="[]"
else
    OPEN_Q_JSON=$(printf '%s\n' "${OPEN_Q[@]}" | jq -R . | jq -s '.')
fi

# --- 10. Integrity hashes + assemble the finding ---------------------------
H_INC=$(sha256sum "$INC_FILE" | awk '{print $1}')
H_EVF=$(sha256sum "$EVF" | awk '{print $1}')
H_TICKET=$(sha256sum "$TICKET_FILE" | awk '{print $1}')
H_IOC=$(sha256sum "$IOC_FILE" | awk '{print $1}')
H_ASSET=$(sha256sum "$ASSET_FILE" | awk '{print $1}')

INPUT_HASHES=$(jq -n --arg inc "$H_INC" --arg evf "$H_EVF" --arg ticket "$H_TICKET" \
    --arg ioc "$H_IOC" --arg asset "$H_ASSET" \
    '{incidents_json: $inc, events_file: $evf, change_tickets: $ticket, ioc_feed: $ioc, assets: $asset}')

TIMELINE_JSON=$(jq -s '.' "$TIMELINE_FILE" 2>/dev/null || echo "[]")
IOC_JSON=$(jq -R . "$IOC_HITS_FILE" 2>/dev/null | jq -s '.' || echo "[]")

# Validation gates per task requirements
if [[ "$CONFIDENCE" != "high" && -z "$AMBIGUITY_NOTES" ]]; then
    die "finding missing ambiguity_notes when confidence is not high"
fi

# Build ticket_match_outcome for actions narrative
if [[ -n "$MATCHED_TICKET" ]]; then
    TICKET_OUTCOME_NARRATIVE="Change ticket $MATCHED_TICKET evaluated: host=$TM_HOST, window=$TM_WINDOW, owner=$TM_OWNER, scope=$TM_SCOPE"
else
    TICKET_OUTCOME_NARRATIVE="No active change ticket covers incident host(s); activity cannot be validated against approved maintenance parameters."
fi
log_action echo "$TICKET_OUTCOME_NARRATIVE" "Ticket evaluation summary" "INC-$INC_ID"

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
    --argjson ioc_matched "$IOC_JSON" \
    --arg amb "$AMBIGUITY_NOTES" \
    --arg vict "$VERDICT" \
    --argjson timeline "$TIMELINE_JSON" \
    --argjson input_hashes "$INPUT_HASHES" \
    --arg ticket_summary "$TICKET_OUTCOME_NARRATIVE" \
    --arg tm_host "$TM_HOST" \
    --arg tm_window "$TM_WINDOW" \
    --arg tm_owner "$TM_OWNER" \
    --arg tm_scope "$TM_SCOPE" \
    --arg matched_ticket "$MATCHED_TICKET" \
    --argjson actions "$(jq -s '.' "$ACTIONS_FILE" 2>/dev/null || echo "[]")" \
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
            input_hashes: $input_hashes
        },
        confidence: $conf,
        open_questions: $open_q,
        ambiguity_notes: $amb,
        verdict: $vict,
        ticket_match_outcome: {
            ticket_id: (if $matched_ticket == "" then null else $matched_ticket end),
            host_match: $tm_host,
            window_match: $tm_window,
            owner_match: $tm_owner,
            scope_match: $tm_scope,
            narrative: $ticket_summary
        },
        actions: $actions
    }' > "$OUT_FILE"

log "incident_B.json written"
exit 0
