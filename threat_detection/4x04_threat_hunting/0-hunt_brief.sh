#!/bin/bash
#
# Name: 0-hunt_brief.sh
# Purpose: Produce the HEALTHBANE Stage 4 hunt brief. Extracts the Stage 4
#          TTP profile from the HC3 advisory (verifying each TTP is actually
#          present in the source text), loads the 4x03 ATT&CK coverage layer
#          to list lateral-movement / credential-access techniques by state,
#          intersects advisory TTPs with the NOT COVERED set, ranks hunt
#          priorities, and records data sources, the 14-day time window and
#          false-positive control references. Read-only; output to stdout.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Priority ranking rationale (each entry validated against the gap before
# printing; all five are NOT COVERED and advisory-declared):
#   P1 PsExec   - advisory night narrative shows PsExec as the first lateral
#                 movement vector used against target servers
#   P2 LSASS    - credential dumping sustains the operation (refresh cycles)
#   P3 WMI      - used where PsExec was blocked or unstable, follows PsExec
#   P4 PSRemoting - shorter interactive sessions used for staging
#   P5 Domain service accounts - enabler for the lateral authentication above

set -euo pipefail

readonly ADVISORY="reference/hc3_advisory_004.txt"
readonly MAPPING="reference/4x03_attack_mapping.json"
readonly SCHEDULE="reference/admin_schedule.txt"
readonly SVC_ACCOUNTS="reference/service_accounts.txt"
readonly TOPOLOGY="reference/network_topology.txt"
readonly ALERTS="siem_export/wazuh_alerts_14d.json"
readonly SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
readonly BASELINE="baseline/robert_kim_activity.json"

# --- Pre-flight: required inputs must be readable -----------------------------
for f in "$ADVISORY" "$MAPPING" "$SCHEDULE" "$SVC_ACCOUNTS" "$TOPOLOGY"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

# --- Banner -------------------------------------------------------------------
echo "================================================================"
echo "   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)"
echo "   Classification: TLP:AMBER"
echo "================================================================"
echo
echo "SCOPE:"
echo "  Retrospective hunt for HEALTHBANE Stage 4 (living-off-the-land"
echo "  lateral movement) across MedDefense Health Systems, driven by"
echo "  HC3-2026-HEALTHBANE-004 and the 4x03 ATT&CK coverage gap."
echo

# --- Section 1: HC3 advisory TTP summary --------------------------------------
# Each summary bullet is printed only if its evidence keyword is confirmed
# in the advisory text; otherwise a warning goes to stderr.
echo "HC3 ADVISORY SUMMARY:"
echo "  Stage 4 TTPs:"

ttp_labels=(
  "PsExec for remote command execution on servers"
  "WMI for remote process creation and enumeration"
  "PowerShell Remoting for interactive access and staging"
  "Credential dumping via LSASS memory access"
  "Service account abuse for lateral authentication"
  "Off-hours operations to avoid detection"
)
ttp_patterns=(
  'psexec'
  'wmic|invoke-wmimethod|TTP 4\.3'
  'psremoting|powershell remoting|TTP 4\.4'
  'lsass'
  'service account'
  'off.?hours|night|overnight'
)
for i in "${!ttp_labels[@]}"; do
  if grep -qiE "${ttp_patterns[$i]}" "$ADVISORY"; then
    echo "    [*] ${ttp_labels[$i]}"
  else
    echo "    [!] not found in advisory: ${ttp_labels[$i]}" >&2
  fi
done

# --- Section 2: ATT&CK coverage gap analysis ----------------------------------
echo
echo "ATT&CK COVERAGE GAP ANALYSIS:"
observed=$(jq -r '.technique_count_summary.observed' "$MAPPING")
total=$(jq -r '.technique_count_summary.total_in_threat_model' "$MAPPING")
pct=$(jq -r '.technique_count_summary.percent_observed' "$MAPPING")
echo "  Current coverage: ${observed}/${total} techniques (${pct}%)"

# Lateral-movement / credential-access techniques, grouped by state.
# State is derived from the comment prefix; parenthetical qualifiers such
# as "OBSERVED (attacker-side)" are normalized to their base state. The
# display name is the first sentence of the comment.
echo "  Lateral movement / credential access techniques by state:"
for state in "OBSERVED" "INFERRED" "NOT COVERED"; do
  echo "    ${state}:"
  lines=$(jq -r --arg s "$state" '
    [.techniques[]
      | (.comment // "") as $c
      | ($c | split(" - ")[0] | sub("\\s*\\(.*\\)"; "")) as $st
      | select($st == $s)
      | select(.tactic == "lateral-movement" or .tactic == "credential-access")
      | "\(.techniqueID)  \($c | sub("^[^-]*- "; "") | sub("[.].*$"; ""))"]
    | sort[]
  ' "$MAPPING")
  if [[ -n "$lines" ]]; then
    while IFS= read -r line; do
      printf '      %s\n' "$line"
    done <<< "$lines"
  else
    echo "      (none)"
  fi
done

# Advisory-declared TTPs (parsed from the "MITRE ATT&CK:" declaration lines)
# intersected with the NOT COVERED set in the 4x03 mapping.
# NOTE: bind the technique object first ($t); inside `select($adv | index(...))`
# the argument expression is evaluated against $adv (an array), so a bare
# `.techniqueID` there would be indexed against the array, not the object.
adv_json=$(grep -E '^[[:space:]]*MITRE ATT&CK:' "$ADVISORY" \
  | grep -oE 'T[0-9]{4}(\.[0-9]{3})?' | sort -u | jq -R . | jq -s .)

gap_table=$(jq -r --argjson adv "$adv_json" '
  [.techniques[]
    | (.comment // "") as $c
    | ($c | split(" - ")[0]) as $st
    | select($st == "NOT COVERED")
    | . as $t
    | select($adv | index($t.techniqueID))
    | {id: $t.techniqueID,
       name: ($c | sub("^[^-]*- "; "") | sub("[.].*$"; "")),
       tactic: $t.tactic}]
  | sort_by(.id)[]
  | "\(.id)\t\(.name)\t\(.tactic)"
' "$MAPPING")

echo "  Stage 4 techniques in gap:"
if [[ -n "$gap_table" ]]; then
  while IFS=$'\t' read -r tid tname _ttac; do
    printf '    %-10s %-34s NOT COVERED\n' "$tid" "$tname"
  done <<< "$gap_table"
else
  echo "    (none)"
fi

gap_ids=$(cut -f1 <<< "$gap_table")

# --- Section 3: Hunt priority ranking ------------------------------------------
# Ordered per the documented rationale in the header comment; each entry is
# suppressed with a stderr warning if it is not in the confirmed gap.
echo
echo "HUNT PRIORITY RANKING:"
rank=0
priorities=(
  "T1021.002|PsExec"
  "T1003.001|LSASS"
  "T1047|WMI"
  "T1021.006|PSRemoting"
  "T1078.002|Domain Accounts"
)
for entry in "${priorities[@]}"; do
  pid="${entry%%|*}"
  plabel="${entry#*|}"
  if grep -qx "$pid" <<< "$gap_ids"; then
    rank=$((rank + 1))
    echo "  P${rank}: ${pid} ${plabel}"
  else
    echo "  [!] skipped ${pid} (${plabel}): not NOT COVERED or not advisory-declared" >&2
  fi
done
if [[ "$rank" -eq 0 ]]; then
  echo "  [!] no advisory-declared Stage 4 techniques found in the gap" >&2
fi

# --- Section 4: Data sources, controls, time window ---------------------------
echo
echo "DATA SOURCES:"
report_file() {
  local label="$1" path="$2"
  if [[ -r "$path" ]]; then
    echo "  ${label}: ${path}"
  else
    echo "  ${label}: ${path}  [NOT FOUND - required before hunting]"
  fi
}
report_file "Primary  " "$ALERTS"
report_file "Secondary" "$SYSMON"
report_file "Baseline " "$BASELINE"

echo
echo "FALSE-POSITIVE CONTROL REFERENCES:"
echo "  Robert Kim maintenance schedule:  ${SCHEDULE} ($(wc -l < "$SCHEDULE") lines)"
echo "  Service account authorization matrix: ${SVC_ACCOUNTS} ($(wc -l < "$SVC_ACCOUNTS") lines)"
echo "  Network topology / host roles:    ${TOPOLOGY} ($(wc -l < "$TOPOLOGY") lines)"

echo
echo "TIME WINDOW: 14 days"
echo
echo "================================================================"
