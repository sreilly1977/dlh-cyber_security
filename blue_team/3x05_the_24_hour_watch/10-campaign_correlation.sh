#!/bin/bash
# Name: 10-campaign_correlation.sh
# Purpose: Determine whether the three shift incidents form a single campaign
#          linked to HC-RED7 using mechanical counting rules: per-incident IOC
#          feed match counts over event_refs (IP addresses and user accounts
#          only), a pairwise overlap matrix (IOC values from incidents.json
#          ioc_list, shared ATT&CK techniques from the three CLI findings,
#          temporal distance between incident windows), and fixed linkage
#          rules: (1) shared IOC count >= 1 AND at least one incident in the
#          pair has a direct feed match; (2) shared tactics >= 2 AND temporal
#          distance <= 360 minutes; (3) shared host or shared user. Reads the
#          Wazuh campaign export view (campaign_dashboard_summary.md and
#          exported_dashboard_workflow.json) as a second evidence view, prints
#          it alongside the mechanical result, and writes
#          campaign/campaign_assessment.json. Confidence rule (documented):
#          high if >= 2 linked pairs and at least one linked incident has a
#          feed match; medium if >= 1 linked pair and a linked feed match;
#          low otherwise. Cluster is HC-RED7 only if a linked incident has a
#          feed match, else unknown.
# Author: Steve - Cybersecurity Engineer
# Date: 15 September 2026

set -euo pipefail

err_trap() { printf '[campaign][ERROR] command failed at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'err_trap $LINENO $?' ERR

WS="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE not set}"
ASSETS="${ASSETS_DIR:?ASSETS_DIR not set}"
WAZUH="${WAZUH_EXPORTS:?WAZUH_EXPORTS not set}"

F_A="$WS/investigations/incident_A.json"
F_B="$WS/investigations/incident_B.json"
F_C="$WS/investigations/incident_C_cli.json"
INC_FILE="$WS/alerts/incidents.json"
IOC_FILE="$ASSETS/ioc_feed.json"
CAMPAIGN_MD="$WAZUH/campaign_dashboard_summary.md"
WORKFLOW_EXPORT="$WAZUH/exported_dashboard_workflow.json"
ENRICHED_JSON="$WS/enriched/enriched_events.json"
ENRICHED_JSONL="$WS/enriched/enriched_events.jsonl"
OUT_DIR="$WS/campaign"
OUT_FILE="$OUT_DIR/campaign_assessment.json"
RT="$WS/runtime"
REF_EVENTS="$RT/campaign_ref_events.jsonl"

log() { printf '[campaign] %s\n' "$*"; }
die() { printf '[campaign][ERROR] %s\n' "$*" >&2; exit 1; }

for f in "$F_A" "$F_B" "$F_C" "$INC_FILE" "$IOC_FILE" "$CAMPAIGN_MD" "$WORKFLOW_EXPORT"; do
    [[ -f "$f" && -s "$f" ]] || die "required input missing or empty: $f"
done

if [[ -s "$ENRICHED_JSONL" ]]; then
    ENRICHED_FILE="$ENRICHED_JSONL"
else
    ENRICHED_FILE="$ENRICHED_JSON"
fi
[[ -s "$ENRICHED_FILE" ]] || die "enriched events file not found (tried .jsonl and .json)"
mkdir -p "$OUT_DIR" "$RT"

# --- 1. Load the three findings and incident records -------------------------
log "loading 3 incident findings"

IOC_IPS=$(jq -c '[.iocs[] | select(.type == "ip") | .value]' "$IOC_FILE")
IOC_ACCTS=$(jq -c '[.iocs[] | select(.type == "account") | .value]' "$IOC_FILE")
IOC_N=$(jq '.iocs | length' "$IOC_FILE")
log "ioc feed: $IOC_N IOCs loaded"

declare -A INCID IOCL TECHL HOSTL USERL FIRSTL LASTL REFS

load_incident() {
    local letter="$1" finding="$2" rec
    rec=$(jq -c --arg l "-$letter" '[.incidents[] | select(.incident_id | endswith($l))][0]' "$INC_FILE")
    [[ "$rec" != "null" && -n "$rec" ]] || die "incident -$letter not found in $INC_FILE"
    INCID[$letter]=$(jq -r '.incident_id' <<< "$rec")
    IOCL[$letter]=$(jq -c '.ioc_list // []' <<< "$rec")
    HOSTL[$letter]=$(jq -c '.host_list // []' <<< "$rec")
    USERL[$letter]=$(jq -c '.user_list // []' <<< "$rec")
    FIRSTL[$letter]=$(jq -r '.first_seen' <<< "$rec")
    LASTL[$letter]=$(jq -r '.last_seen' <<< "$rec")
    TECHL[$letter]=$(jq -c '.attack_techniques' "$finding")
    REFS[$letter]=$(jq -c '.event_refs | unique' "$finding")
}
load_incident A "$F_A"
load_incident B "$F_B"
load_incident C "$F_C"

# --- 2. Per-incident IOC feed match count over event_refs ---------------------
# Ref membership via fixed-string grep prefilter + jq from_entries hash map for
# O(1) per-record lookup; index() on the refs array over the 265 MB stream is
# O(N*M) and is documented in the repo bug-pattern ledger.
REFS_ALL=$(jq -n --argjson a "${REFS[A]}" --argjson b "${REFS[B]}" --argjson c "${REFS[C]}" \
    '$a + $b + $c | unique')

log "scanning enriched stream for referenced events (single grep pass, then jq)"
jq -r '.[]' <<< "$REFS_ALL" > "$RT/campaign_refs.txt"

grep -F -f "$RT/campaign_refs.txt" "$ENRICHED_FILE" \
    | jq -c --argjson refs "$REFS_ALL" '
        (($refs | map({key: ., value: true}) | from_entries)) as $refmap |
        select(.record_id as $id | $refmap[$id] == true) |
        {record_id, src_ip, dst_ip, user}' \
    > "$REF_EVENTS"

log "referenced events extracted: $(wc -l < "$REF_EVENTS")"

MATCHED_REFS=$(jq -s -c --argjson ips "$IOC_IPS" --argjson accts "$IOC_ACCTS" '
    [.[] | select(. as $e |
        (($ips | index($e.src_ip)) != null) or
        (($ips | index($e.dst_ip)) != null) or
        (($accts | index($e.user)) != null)
      ) | .record_id] | unique' "$REF_EVENTS")

declare -A FEEDL
for L in A B C; do
    FEEDL[$L]=$(jq -n --argjson m "$MATCHED_REFS" --argjson r "${REFS[$L]}" \
        '[$r[] | select(. as $ref | $m | index($ref) != null)] | length')
done
log "feed matches: A=${FEEDL[A]} B=${FEEDL[B]} C=${FEEDL[C]}"

# --- 3. Pairwise matrices ------------------------------------------------------
pair_key() { echo "$1-$2"; }

IOC_OVERLAP='{}'
TACTIC_OVERLAP='{}'
TEMPORAL_DIST='{}'
LINKED_PAIRS='[]'
PAIR_REASONS='{}'

for PAIR in "A B" "A C" "B C"; do
    set -- $PAIR
    X="$1"; Y="$2"; K="$(pair_key "$X" "$Y")"

    # IOC overlap: values in both incidents' ioc_list (from incidents.json)
    OV=$(jq -n --argjson a "${IOCL[$X]}" --argjson b "${IOCL[$Y]}" \
        '[$a[] | select(. as $v | $b | index($v) != null)] | length')

    # Tactic overlap: ATT&CK techniques shared between the two findings
    TV=$(jq -n --argjson a "${TECHL[$X]}" --argjson b "${TECHL[$Y]}" \
        '[$a[] | select((. | ascii_upcase) as $t | ($b | map(ascii_upcase) | index($t)) != null)] | length')

    # Temporal distance: minutes between earlier.last_seen and later.first_seen
    XF_FIRST=$(date -u -d "${FIRSTL[$X]}" +%s); XF_LAST=$(date -u -d "${LASTL[$X]}" +%s)
    YF_FIRST=$(date -u -d "${FIRSTL[$Y]}" +%s); YF_LAST=$(date -u -d "${LASTL[$Y]}" +%s)
    if (( XF_LAST <= YF_FIRST )); then
        TD=$(( (YF_FIRST - XF_LAST) / 60 ))
    elif (( YF_LAST <= XF_FIRST )); then
        TD=$(( (XF_FIRST - YF_LAST) / 60 ))
    else
        TD=0   # overlapping windows: distance is zero by convention
    fi

    # Shared host or shared user (linkage rule 3)
    SH_HOST=$(jq -n --argjson a "${HOSTL[$X]}" --argjson b "${HOSTL[$Y]}" \
        '[$a[] | select(. as $h | $b | index($h) != null)] | length')
    SH_USER=$(jq -n --argjson a "${USERL[$X]}" --argjson b "${USERL[$Y]}" \
        '[$a[] | select(. as $u | $b | index($u) != null)] | length')

    log "$K: ioc_overlap=$OV tactic_overlap=$TV temporal_dist=${TD}min"

    IOC_OVERLAP=$(jq -n --argjson o "$IOC_OVERLAP" --arg k "$K" --argjson v "$OV" \
        '$o + {($k): $v}')
    TACTIC_OVERLAP=$(jq -n --argjson o "$TACTIC_OVERLAP" --arg k "$K" --argjson v "$TV" \
        '$o + {($k): $v}')
    TEMPORAL_DIST=$(jq -n --argjson o "$TEMPORAL_DIST" --arg k "$K" --argjson v "$TD" \
        '$o + {($k): $v}')

    # --- Mechanical linkage rules (fixed, applied in order) ------------------
    REASON=""
    if (( OV >= 1 )) && (( FEEDL[$X] >= 1 || FEEDL[$Y] >= 1 )); then
        REASON="shared_ioc+feed_match"
    elif (( TV >= 2 )) && (( TD <= 360 )); then
        REASON="shared_tactics+temporal"
    elif (( SH_HOST >= 1 || SH_USER >= 1 )); then
        REASON="shared_host_or_user"
    fi

    if [[ -n "$REASON" ]]; then
        LINKED_PAIRS=$(jq -n --argjson lp "$LINKED_PAIRS" --arg k "$K" --arg r "$REASON" \
            '$lp + [$k]')
        PAIR_REASONS=$(jq -n --argjson pr "$PAIR_REASONS" --arg k "$K" --arg r "$REASON" \
            '$pr + {($k): $r}')
        log "linked pair: $K ($REASON)"
    fi
done

LINKED_N=$(jq 'length' <<< "$LINKED_PAIRS")

# --- 4. Export view (second evidence view) --------------------------------------
# Verdict line extraction from the campaign dashboard summary markdown:
# hyphen placed first in the bracket expression so it is a literal character,
# not a descending range operator (sed error: "Invalid range end").
EXPORT_VERDICT=$(grep -i -m1 'verdict\|campaign' "$CAMPAIGN_MD" | sed 's/^[-#* ]*//' || true)
WORKFLOW_VERDICT=$(jq -r '[.verdict // empty, .cluster // empty] | join(" ")' "$WORKFLOW_EXPORT")
if [[ -z "$EXPORT_VERDICT" ]]; then
    EXPORT_VERDICT="(no explicit verdict line in campaign_dashboard_summary.md)"
fi
if [[ -z "$WORKFLOW_VERDICT" ]]; then
    WORKFLOW_VERDICT="(no verdict/cluster fields in exported_dashboard_workflow.json)"
fi
EXPORT_VIEW_STR="export view: $WORKFLOW_VERDICT — $EXPORT_VERDICT"
log "export view: $EXPORT_VIEW_STR"

# --- 5. Verdict: campaign linkage + cluster attribution --------------------------
LINKED_FEED_MATCH=0
for L in A B C; do
    if (( ${FEEDL[$L]} >= 1 )); then
        LINKED_FEED_MATCH=1
        break
    fi
done

if (( LINKED_N >= 1 )); then
    CAMPAIGN_LINKED=true
else
    CAMPAIGN_LINKED=false
fi

if [[ "$CAMPAIGN_LINKED" == "true" && "$LINKED_FEED_MATCH" -eq 1 ]]; then
    CLUSTER_ID="HC-RED7"
else
    CLUSTER_ID="unknown"
fi

if (( LINKED_N >= 2 )) && (( LINKED_FEED_MATCH == 1 )); then
    CONFIDENCE="high"
elif (( LINKED_N >= 1 )) && (( LINKED_FEED_MATCH == 1 )); then
    CONFIDENCE="medium"
else
    CONFIDENCE="low"
fi

SUPPORT_IOC_TOTAL=$(jq -nc --argjson o "$IOC_OVERLAP" '[$o[]] | add // 0')
SUPPORT_TACTIC_TOTAL=$(jq -nc --argjson o "$TACTIC_OVERLAP" '[$o[]] | add // 0')

# --- 6. Write campaign_assessment.json -------------------------------------------
log "verdict: campaign_linked=$CAMPAIGN_LINKED cluster=$CLUSTER_ID confidence=$CONFIDENCE"

jq -n \
    --argjson incidents "$(jq -nc --arg a "${INCID[A]}" --arg b "${INCID[B]}" --arg c "${INCID[C]}" '[$a, $b, $c]')" \
    --argjson ioc_ov "$IOC_OVERLAP" \
    --argjson tac_ov "$TACTIC_OVERLAP" \
    --argjson tmp_d "$TEMPORAL_DIST" \
    --argjson feeds "$(jq -nc --argjson a "${FEEDL[A]}" --argjson b "${FEEDL[B]}" --argjson c "${FEEDL[C]}" '{A: $a, B: $b, C: $c}')" \
    --argjson linked "$LINKED_PAIRS" \
    --argjson linked_bool "$CAMPAIGN_LINKED" \
    --arg cluster "$CLUSTER_ID" \
    --arg confidence "$CONFIDENCE" \
    --arg export_view "$EXPORT_VIEW_STR" \
    --argjson sup "$(jq -nc --argjson i "$SUPPORT_IOC_TOTAL" --argjson t "$SUPPORT_TACTIC_TOTAL" '{shared_iocs_total: $i, shared_tactics_total: $t}')" \
    --argjson reasons "$PAIR_REASONS" \
    '{
        incidents: $incidents,
        ioc_overlap_matrix: $ioc_ov,
        tactic_overlap_matrix: $tac_ov,
        temporal_distance_minutes: $tmp_d,
        ioc_feed_matches: $feeds,
        linked_pairs: $linked,
        campaign_linked: $linked_bool,
        cluster_id: $cluster,
        confidence: $confidence,
        export_view_verdict: $export_view,
        supporting_counts: $sup,
        linkage_reasons: $reasons
    }' > "$OUT_FILE"

log "campaign_assessment.json written"
