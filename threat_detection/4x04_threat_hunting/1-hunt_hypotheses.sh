#!/bin/bash
#
# Name: 1-hunt_hypotheses.sh
# Purpose: Emit five structured hunt hypotheses for HEALTHBANE Stage 4,
#          derived from the HC3 advisory TTP profile and the 4x03 ATT&CK
#          gap analysis. Each hypothesis validates its technique against
#          the 4x03 mapping (confirming NOT COVERED status) and its
#          observable keywords against the advisory text before printing.
#          Field names in the jq-style search filters use fallback
#          alternations pending SIEM schema reconnaissance. Read-only;
#          output to stdout.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026

set -euo pipefail

readonly ADVISORY="reference/hc3_advisory_004.txt"
readonly MAPPING="reference/4x03_attack_mapping.json"
readonly BASELINE="baseline/robert_kim_activity.json"
readonly ALERTS="siem_export/wazuh_alerts_14d.json"
readonly SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

# --- Pre-flight ---------------------------------------------------------------
for f in "$ADVISORY" "$MAPPING" "$BASELINE"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

# Mapping state for a technique ID (OBSERVED / INFERRED / NOT COVERED),
# derived from the comment prefix in the 4x03 layer.
tech_state() {
  jq -r --arg t "$1" '
    [.techniques[] | select(.techniqueID == $t)][0]
    | (.comment // "") | split(" - ")[0]
  ' "$MAPPING"
}

# Mapping display name for a technique ID (first sentence of the comment).
tech_name() {
  jq -r --arg t "$1" '
    [.techniques[] | select(.techniqueID == $t)][0]
    | (.comment // "") | sub("^[^-]*- "; "") | sub("[.].*$"; "")
  ' "$MAPPING"
}

# Emit one hypothesis block. Arguments:
#   1 ID, 2 title, 3 technique ID, 4 advisory keyword regex,
#   5 IF/THEN statement, 6 data source, 7 jq-style search,
#   8 positive criteria, 9 FP exclusion, 10 expected baseline rate
emit_hyp() {
  local id="$1" title="$2" tid="$3" kw="$4" stmt="$5" src="$6"
  local search="$7" positive="$8" fpx="$9" rate="${10}"

  local state name
  state=$(tech_state "$tid")
  name=$(tech_name "$tid")

  echo "HYPOTHESIS ${id}: ${title}"
  printf '  Technique: %s %s' "$tid" "$name"
  if [[ -n "$state" ]]; then
    echo "  [mapping: ${state}]"
  else
    echo "  [WARNING: not found in 4x03 mapping]" >&2
  fi
  if ! grep -qiE "$kw" "$ADVISORY"; then
    echo "  [WARNING: observable keyword not found in advisory]" >&2
  fi
  echo "  Statement: ${stmt}"
  echo "  Data Source: ${src}"
  echo "  Search: ${search}"
  echo "  Positive: ${positive}"
  echo "  FP Exclusion: ${fpx}"
  echo "  Baseline Rate: ${rate}"
  echo
}

echo "================================================================"
echo "   HUNT HYPOTHESES - HEALTHBANE Stage 4"
echo "================================================================"
echo

emit_hyp \
  "H1" "Lateral Movement via PsExec" "T1021.002" 'psexec' \
  "IF the attacker used PsExec for lateral movement, THEN
    process creation events will show PsExec execution from a
    non-admin workstation or outside maintenance windows." \
  "$ALERTS (primary), $SYSMON (secondary)" \
  "jq 'select(((.Image // .image // \"\") + \" \" +
       (.CommandLine // .command_line // \"\")) | test(\"(?i)psexec\"))'" \
  "PsExec execution from a source host other than WS-ADMIN-01, or
    from any host outside Robert Kim's documented maintenance
    windows, targeting server assets." \
  "Robert Kim legitimate deployments from WS-ADMIN-01 within
    scheduled maintenance windows (admin_schedule.txt)." \
  "Zero PsExec events outside Robert Kim's scheduled maintenance;
    nonzero only within documented deployment windows."

emit_hyp \
  "H2" "Credential Access via LSASS Memory" "T1003.001" 'lsass' \
  "IF the attacker dumped LSASS memory, THEN process access events
    will show a non-system process opening a handle to lsass.exe
    with memory-read permissions, originating from executables in
    writable temporary paths." \
  "$SYSMON (primary), $ALERTS (secondary)" \
  "jq 'select((.TargetImage // .target_image // \"\") | test(\"lsass\")) |
       select(.GrantedAccess // .granted_access | test(\"1010|1410|143a\"; \"i\"))'" \
  "Any non-authorized process opening lsass.exe with read-memory
    access, or an unknown executable in C:\\Windows\\Temp,
    C:\\Users\\Public or C:\\ProgramData accessing LSASS." \
  "Known-good system binaries accessing LSASS per HC3 advisory:
    antivirus engines (MsMpEng.exe), WmiPrvSE.exe, wininit.exe." \
  "Zero legitimate LSASS memory access outside the known-good
    process whitelist; any hit is anomalous by definition."

emit_hyp \
  "H3" "Remote Execution via WMI" "T1047" 'wmiprvse|wmic /node' \
  "IF the attacker used WMI for remote execution, THEN WMI provider
    host (wmiprvse.exe) process creation events on target hosts will
    show spawning of cmd.exe or powershell.exe initiated from wmic
    commands issued by non-admin sources." \
  "$SYSMON (primary), $ALERTS (secondary)" \
  "jq 'select((.ParentImage // .parent_image // \"\") | test(\"wmiprvse\")) |
       select((.Image // .image // \"\") | test(\"cmd|powershell\"))'" \
  "wmiprvse.exe spawning cmd.exe or powershell.exe on server
    assets, or wmic process-call-create issued from a workstation
    other than WS-ADMIN-01." \
  "Robert Kim scheduled WMI inventory runs per admin_schedule.txt;
    legitimate software-management agents on managed hosts." \
  "Only Robert Kim's documented inventory runs; zero unscheduled
    WMI remote process creation expected."

emit_hyp \
  "H4" "Interactive Access via PowerShell Remoting" "T1021.006" 'psremoting|winrm|wsmprovhost' \
  "IF the attacker used PowerShell Remoting for interactive access
    and staging, then WinRM host process (wsmprovhost.exe) on target
    servers will spawn PowerShell sessions initiated from non-admin
    workstations or outside maintenance windows, with shorter
    session durations than legitimate patch cycles." \
  "$SYSMON (primary), $ALERTS (secondary)" \
  "jq 'select((.ParentImage // .parent_image // \"\") | test(\"wsmprovhost\")) |
       select((.Image // .image // \"\") | test(\"powershell\"))'" \
  "PowerShell process whose parent is wsmprovhost.exe on a server
    asset, where the initiating source host is not WS-ADMIN-01 or
    the session falls outside the maintenance schedule." \
  "Robert Kim patch-management remoting sessions from WS-ADMIN-01
    during scheduled windows (admin_schedule.txt)." \
  "Robert Kim patch cycle only; expect zero PSRemoting sessions
    from non-admin sources or outside scheduled windows."

emit_hyp \
  "H5" "Service Account Abuse (Valid Accounts)" "T1078.002" 'service account' \
  "IF the attacker abused domain service account credentials, THEN
    authentication events will show a documented service account
    authenticating from a workstation host, from an unauthorized
    source, with a logon type inconsistent with the service
    account authorization matrix." \
  "$ALERTS (primary), $SYSMON (secondary)" \
  "jq 'select((.subjectUserName // .user // \"\") | test(\"^svc-\")) |
       select((.workstationName // .source_host // \"\") |
         test(\"ws-[0-9]|workstation\"; \"i\"))'" \
  "Any service account authenticating from a workstation host,
    outside its authorized source/destination pairs in
    service_accounts.txt, or with an unexpected logon type
    (interactive where network is authorized)." \
  "Authorized service-account usage pairs defined in the service
    account authorization matrix (service_accounts.txt): correct
    source host, authorized target, scheduled job times." \
  "Service accounts authenticate only from authorized source
    hosts during authorized job windows; zero workstation-origin
    or off-schedule authentications expected."

# --- Summary: gap confirmation for all five hunted techniques -----------------
echo "GAP CONFIRMATION:"
confirmed=0
for tid in T1021.002 T1003.001 T1047 T1021.006 T1078.002; do
  state=$(tech_state "$tid")
  if [[ "$state" == "NOT COVERED" ]]; then
    confirmed=$((confirmed + 1))
  else
    echo "  [!] $tid state is '${state}', expected NOT COVERED" >&2
  fi
done
echo "  ${confirmed}/5 hypothesis techniques confirmed NOT COVERED in 4x03 mapping"
echo "  Baseline reference: $BASELINE ($(wc -l < "$BASELINE") lines)"
echo
echo "================================================================"
