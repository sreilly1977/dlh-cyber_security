#!/bin/bash
#
# Name: 11-attack_mapping_v3.sh
# Purpose: Produce version 3 of the HEALTHBANE ATT&CK mapping. Loads the
#          4x03 attack mapping (reference/4x03_attack_mapping.json, a
#          Navigator-format layer with 29 techniques whose status is
#          encoded in the color legend: #c40000 OBSERVED, #ffcf00
#          INFERRED, #8a8a8a NOT COVERED), incorporates the Stage 4
#          techniques confirmed by the 4x04 hunt (PsExec/SMB T1021.002,
#          WMI T1047, LSASS memory T1003.001, WinRM T1021.006, Domain
#          Accounts T1078.002, Pass the Hash T1550.002), reclassifies
#          techniques previously inferred or not covered as OBSERVED
#          Stage 4 where hunt evidence confirms them, and emits
#          healthbane_layer_v3.json in MITRE ATT&CK Navigator layer
#          format (v4.4) with a four-tier scheme:
#            OBSERVED Stages 1-3   score 100  #FF0000
#            OBSERVED Stage 4      score 100  #C00000
#            NEWLY OBSERVED (hunt) score 75   #FF8000
#            INFERRED              score 50   #FFBF00
#          Also prints console comparison statistics. Input file is
#          read-only; only healthbane_layer_v3.json is written.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Status decoding precedence:
#   1. explicit status/state/classification field, if present
#   2. color legend per the 4x03 layer (c40000/ffcf00/8a8a8a,
#      case-insensitive)
#   3. Navigator score (>=75 observed, else inferred)

set -euo pipefail

readonly MAPPING="reference/4x03_attack_mapping.json"
readonly OUTPUT="healthbane_layer_v3.json"

if [[ ! -r "$MAPPING" ]]; then
  echo "ERROR: required file not readable: $MAPPING" >&2
  exit 1
fi

# --- Parse the 4x03 mapping (Navigator layer, status from color) ----------------
# Emits TSV: 1 id  2 statusexpr (status field | color | score)  3 tactic
#            4 comment  5 score
old_tsv=$(jq -r '
  (if type == "array" then .
   elif (.techniques | type) == "array" then .techniques
   else empty end)[]
  | if ((.techniqueID // .technique_id // .id // .tech_id // null) == null)
    then empty
    else
      [ (.techniqueID // .technique_id // .id // .tech_id),
        ((.status // .state // .classification // "NOSTATUS")
         + "|" + ((.color // "") | tostring)
         + "|" + (((.score // 0) | tostring))),
        (.tactic // "-"),
        (.comment // .description // ""),
        ((.score // 0) | tostring) ]
      | map(tostring) | join("\t")
    end
' "$MAPPING" 2>/dev/null | grep -v '^[[:space:]]*$' || true)

if [[ -z "$old_tsv" ]]; then
  echo "ERROR: no technique entries extracted from $MAPPING" >&2
  echo "  Top-level keys detected:" >&2
  jq -r 'keys? // "n/a"' "$MAPPING" >&2 || true
  exit 1
fi

# Status decode: explicit field first, then 4x03 color legend, then score
norm_status() {
  local expr="$1"
  local status color score
  status="${expr%%|*}"
  color="${expr#*|}"; color="${color%%|*}"
  score="${expr##*|}"

  case "$(echo "$status" | tr '[:lower:]' '[:upper:]')" in
    *NOT*COVER*|*NOTCOVER*) echo "NOTCOVERED"; return ;;
    *OBSERV*)               echo "OBSERVED";   return ;;
    *INFER*)                echo "INFERRED";   return ;;
  esac

  case "$(echo "$color" | tr '[:lower:]' '[:upper:]')" in
    *C40000*) echo "OBSERVED";   return ;;   # 4x03 legend: red = OBSERVED
    *FFCF00*) echo "INFERRED";   return ;;   # amber = INFERRED
    *8A8A8A*) echo "NOTCOVERED"; return ;;   # gray = NOT COVERED
  esac

  if [[ "$score" =~ ^[0-9]+$ ]] && (( score >= 75 )); then echo "OBSERVED"
  else echo "INFERRED"; fi
}

declare -A old_status old_tactic old_comment
declare -a old_order=()
while IFS=$'\t' read -r oid oexpr otac ocomm oscore; do
  st=$(norm_status "$oexpr")
  if [[ -z "${old_status[$oid]+x}" ]]; then
    old_status["$oid"]="$st"; old_tactic["$oid"]="$otac"
    old_comment["$oid"]="$ocomm"; old_order+=("$oid")
  fi
done <<< "$old_tsv"

old_total=${#old_order[@]}
old_observed=0; old_inferred=0; old_notcovered=0
for oid in "${old_order[@]}"; do
  case "${old_status[$oid]}" in
    OBSERVED)   old_observed=$((old_observed + 1)) ;;
    INFERRED)   old_inferred=$((old_inferred + 1)) ;;
    NOTCOVERED) old_notcovered=$((old_notcovered + 1)) ;;
  esac
done

if (( old_observed < 16 )); then
  echo "WARNING: only ${old_observed} OBSERVED techniques parsed from" >&2
  echo "         $MAPPING (expected 16 per the 4x03 documentation)." >&2
  echo "         Colors seen: $(jq -r '.techniques[].color // "none"' "$MAPPING" | sort | uniq -c | tr '\n' ' ')" >&2
  echo "         Continuing - verify the legend mapping." >&2
fi

# --- Hunt-discovered Stage 4 technique set --------------------------------------
declare -a hunt_ids=(T1021.002 T1047 T1003.001 T1021.006 T1078.002 T1550.002)
declare -A hunt_name hunt_tactic hunt_evidence hunt_hybrid
hunt_name[T1021.002]="SMB/Admin Shares";     hunt_tactic[T1021.002]="lateral-movement"
hunt_name[T1047]="WMI";                      hunt_tactic[T1047]="execution"
hunt_name[T1003.001]="LSASS Memory";         hunt_tactic[T1003.001]="credential-access"
hunt_name[T1021.006]="Windows Remote Mgmt"; hunt_tactic[T1021.006]="lateral-movement"
hunt_name[T1078.002]="Domain Accounts";     hunt_tactic[T1078.002]="defense-evasion"
hunt_name[T1550.002]="Pass the Hash";       hunt_tactic[T1550.002]="defense-evasion"

hunt_evidence[T1021.002]="OBSERVED (Stage 4): PsExec C:\\Users\\Public\\Downloads\\PsExec64.exe from WS-RECV-03 to SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01 (4x04 Tasks 4, 10)"
hunt_evidence[T1047]="OBSERVED (Stage 4): wsmprovhost.exe follow-on on SRV-HEALTH-DB and SRV-INS-DB during off-hours sessions (4x04 Tasks 5, 10)"
hunt_evidence[T1003.001]="OBSERVED (Stage 4): C:\\Windows\\Temp\\debug_tool.exe accessed lsass.exe with 0x1010 memory-read mask on WS-RECV-03 (4x04 Tasks 6, 10)"
hunt_evidence[T1021.006]="OBSERVED (Stage 4): Enter-PSSession as svc_healthsync and Copy-Item of sync_healthdata.ps1 to C:\\Windows\\Temp on DB servers (4x04 Tasks 7, 10)"
hunt_evidence[T1078.002]="OBSERVED (Stage 4): svc_healthsync workstation-source NTLM logons violating authorization matrix RULES 1-3 (4x04 Task 9)"
hunt_evidence[T1550.002]="OBSERVED: NTLM authentication by service account from workstation, RULE 3 pass-the-hash indicator (4x04 Task 9); INFERRED: hash-level credential reuse mechanism"
hunt_hybrid[T1550.002]=1

# --- Merge into the v3 layer (temp file, one printf per entry) ------------------
merge_file=$(mktemp)
trap 'rm -f "$merge_file"' EXIT

tier1_n=0; tier4_n=0; hunt_new=0; hunt_reclassified=0; hunt_emitted=0
reclassified_list=""

# Tier 1: previously observed (Stages 1-3) carry over unchanged
for oid in "${old_order[@]}"; do
  if [[ "${old_status[$oid]}" == "OBSERVED" ]]; then
    comm="OBSERVED (Stages 1-3, 4x02/4x03 evidence)"
    [[ -n "${old_comment[$oid]}" ]] && comm="${comm}: ${old_comment[$oid]}"
    printf '%s\t%s\t100\t#FF0000\t%s\n' "$oid" "${old_tactic[$oid]}" "$comm" >> "$merge_file"
    tier1_n=$((tier1_n + 1))
  fi
done

# Tier 4: previously inferred/not covered, not confirmed by the hunt
for oid in "${old_order[@]}"; do
  in_hunt=false
  for hid in "${hunt_ids[@]}"; do [[ "$hid" == "$oid" ]] && in_hunt=true; done
  if [[ "$in_hunt" == "false" && ( "${old_status[$oid]}" == "INFERRED" || "${old_status[$oid]}" == "NOTCOVERED" ) ]]; then
    comm="INFERRED (retained from 4x03 mapping, not yet observed)"
    [[ -n "${old_comment[$oid]}" ]] && comm="${comm}: ${old_comment[$oid]}"
    printf '%s\t%s\t50\t#FFBF00\t%s\n' "$oid" "${old_tactic[$oid]}" "$comm" >> "$merge_file"
    tier4_n=$((tier4_n + 1))
  fi
done

# Hunt set: reclassified (present in old map) or newly observed (absent)
for hid in "${hunt_ids[@]}"; do
  if [[ -n "${old_status[$hid]+x}" && "${old_status[$hid]}" != "OBSERVED" ]]; then
    hunt_reclassified=$((hunt_reclassified + 1))
    prev="${old_status[$hid]}"
    comm=$(printf 'OBSERVED (Stage 4, hunt-confirmed; previously %s in 4x03 map): %s' "$prev" "${hunt_evidence[$hid]}")
    printf '%s\t%s\t100\t#C00000\t%s\n' "$hid" "${hunt_tactic[$hid]}" "$comm" >> "$merge_file"
    reclassified_list+="${hid} (was ${prev})
"
  elif [[ -z "${old_status[$hid]+x}" ]]; then
    hunt_new=$((hunt_new + 1))
    if [[ -n "${hunt_hybrid[$hid]+x}" ]]; then
      printf '%s\t%s\t75\t#FF8000\t%s\n' "$hid" "${hunt_tactic[$hid]}" "${hunt_evidence[$hid]}" >> "$merge_file"
    else
      printf '%s\t%s\t100\t#C00000\t%s\n' "$hid" "${hunt_tactic[$hid]}" "${hunt_evidence[$hid]}" >> "$merge_file"
    fi
  fi
  hunt_emitted=$((hunt_emitted + 1))
done

total_entries=$(( tier1_n + tier4_n + hunt_emitted ))

# --- Statistics -------------------------------------------------------------------
new_observed=$(( old_observed + hunt_reclassified + hunt_new ))
new_total=$(( old_total + hunt_new ))
old_pct=$(awk -v o="$old_observed" -v t="$old_total" 'BEGIN {printf "%.0f", 100*o/t}')
new_pct=$(awk -v o="$new_observed" -v t="$new_total" 'BEGIN {printf "%.0f", 100*o/t}')
hybrid_flag=1
fully_observed=$(( new_observed - hybrid_flag ))

# --- Console output -----------------------------------------------------------------
echo "================================================================"
echo "   ATT&CK MAPPING UPDATE - HEALTHBANE (Post-Hunt, v3)"
echo "================================================================"
echo
echo "PARSER CHECK:"
echo "  4x03 mapping parsed: ${old_total} techniques (${old_observed} observed,"
echo "  ${old_inferred} inferred, ${old_notcovered} not covered)"
echo "  Layer entries emitted: ${total_entries} (${tier1_n} tier-1, ${tier4_n}"
echo "  tier-4, ${hunt_emitted} hunt)"
echo
echo "NEW TECHNIQUES FROM HUNT:"
for hid in "${hunt_ids[@]}"; do
  tier="[OBSERVED]"
  [[ -n "${hunt_hybrid[$hid]+x}" ]] && tier="[OBSERVED/INFERRED]"
  printf "  %-10s  %-22s %s\n" "$hid" "${hunt_name[$hid]}" "$tier"
done
echo
if [[ -n "$reclassified_list" ]]; then
  echo "RECLASSIFIED (previously INFERRED/NOT COVERED, now OBSERVED):"
  printf '%s' "$reclassified_list"
  echo
fi
echo "MAPPING STATISTICS:"
echo "  4x03 Mapping: ${old_observed} observed / ${old_total} total (${old_pct}%)"
echo "  4x04 Update:  +${hunt_new} newly added, +${hunt_reclassified} reclassified"
echo "                as observed from hunt evidence"
echo "  Layer now:    ${new_observed} observed / ${new_total} total"
echo "                (${fully_observed} fully observed + 1 hybrid NTLM/PtH)"
echo "  Coverage:     ${old_pct}% -> ${new_pct}%"
echo
echo "  Tier legend (healthbane_layer_v3.json):"
echo "    OBSERVED Stages 1-3    score 100  #FF0000"
echo "    OBSERVED Stage 4       score 100  #C00000"
echo "    NEWLY OBSERVED (hunt)  score 75   #FF8000"
echo "    INFERRED              score 50   #FFBF00"
echo

# --- Emit the Navigator layer -----------------------------------------------------
tech_json=$(jq -R -s '
  split("\n") | map(select(length > 0)) | map(split("\t")) |
  map({techniqueID: .[0], tactic: .[1], score: (.[2] | tonumber),
       color: .[3], comment: .[4], enabled: true})
' "$merge_file")

jq -n --argjson techniques "$tech_json" '
{
  name: "HEALTHBANE Campaign v3",
  versions: { "attack": "15", "navigator": "4.8.2", "layer": "4.4" },
  domain: "enterprise-attack",
  description: "ATT&CK technique mapping for HEALTHBANE, update 3 (post-hunt). Tiers: OBSERVED Stages 1-3 scored 100 (#FF0000); OBSERVED Stage 4 hunt-confirmed scored 100 (#C00000); NEWLY OBSERVED from 4x04 hunt scored 75 (#FF8000); INFERRED scored 50 (#FFBF00). Baselines: 4x02 healthbane_layer.json, 4x03 healthbane_layer_v2.json. Source: Project 4x04 Threat Hunting, Tasks 4-10.",
  hideDisabled: false,
  techniques: $techniques,
  legendItems: [
    { "label": "OBSERVED Stages 1-3 (Direct Evidence)", "color": "#FF0000" },
    { "label": "OBSERVED Stage 4 (Hunt-Confirmed)", "color": "#C00000" },
    { "label": "NEWLY OBSERVED (4x04 Hunt)", "color": "#FF8000" },
    { "label": "INFERRED (Retained Hypothesis)", "color": "#FFBF00" }
  ],
  metadata: [
    { "name": "Campaign", "value": "HEALTHBANE" },
    { "name": "Analyst", "value": "Steve - Cybersecurity Engineer" },
    { "name": "Project", "value": "4x04 Threat Hunting" },
    { "name": "Source", "value": "Tasks 4-10 hunt findings vs 4x03_attack_mapping.json" }
  ]
}' > "$OUTPUT"

# --- Post-write validation gate ------------------------------------------------------
layer_len=$(jq '.techniques | length' "$OUTPUT")
if (( layer_len < 29 )); then
  echo "ERROR: layer written with only ${layer_len} techniques (expected >= 29);" >&2
  echo "       refusing to certify $OUTPUT - inspect the parse counts above." >&2
  exit 1
fi

echo "[*] Navigator layer saved: ${OUTPUT} (${layer_len} techniques)"
echo
echo "================================================================"
