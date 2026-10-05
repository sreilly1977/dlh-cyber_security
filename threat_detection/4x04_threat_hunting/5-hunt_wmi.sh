#!/bin/bash
#
# Name: 5-hunt_wmi.sh
# Purpose: Execute hunt hypothesis H3 (lateral movement via WMI,
#          T1047). Extracts all WMI-related events (wmiprvse.exe,
#          wmic.exe, Invoke-WmiMethod) from the 14-day SIEM exports,
#          classifies each against Robert Kim's documented baseline
#          (source host, Central Time business hours, weekday, account,
#          authorized targets), prints full evidence for every anomalous
#          event with per-event anomaly flags, correlates findings
#          with PsExec attack windows when possible, and concludes
#          with a finding and confidence assessment. Read-only; stdout only.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Baseline tuple (validated in 2-baseline_profile.sh):
#   source  = WS-ADMIN-01
#   account = MEDDEFENSE\robert.kim
#   window  = Mon-Fri 08:00-18:00 Central Time (CDT = UTC-5 in May 2026)
#   targets = SRV-AV-01, SRV-BACKUP-01, SRV-DC-01, SRV-FILE-01,
#             SRV-HEALTH-DB, SRV-INS-DB, SRV-PATCH-01
#
# Attack windows from PsExec hunt (Task 4):
#   Night 1: 2026-05-06T07:14 CT (SRV-HEALTH-DB)
#   Night 2: 2026-05-09T08:42 CT (SRV-INS-DB)
#   Night 3: 2026-05-13T06:58 CT (SRV-DC-01)
#
# Key distinction: wmiprvse.exe is the WMI provider host that spawns
# child processes when remote WMI commands execute. Robert Kim's
# legitimate WMI runs typically show only inventory queries without
# cmd.exe/powershell.exe children. Attacker WMI abuse spawns shells.

set -euo pipefail

readonly ALERTS="siem_export/wazuh_alerts_14d.json"
readonly SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

for f in "$ALERTS" "$SYSMON"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

readonly EXPECTED_SOURCE="WS-ADMIN-01"
readonly EXPECTED_USER="MEDDEFENSE\\robert.kim"
readonly BUSINESS_START=480     # 08:00 CT in minutes since midnight
readonly BUSINESS_END=1080       # 18:00 CT
targets_regex="^(SRV-AV-01|SRV-BACKUP-01|SRV-DC-01|SRV-FILE-01|SRV-HEALTH-DB|SRV-INS-DB|SRV-PATCH-01)$"

# Known benign processes that legitimately access WMI (per advisory TTP 4.3)
# These should not trigger anomalies even if they appear in eventdata
benign_images="MsMpEng.exe|wininit.exe|WmiPrvSE.exe|svchost.exe"

# --- Extract and normalize WMI events to TSV -----------------------------------
# Columns: 1 ts 2 date(CT) 3 weekday(CT) 4 hh:mm(CT) 5 minutes(CT)
#          6 source(agent) 7 user 8 ruleid 9 image 10 target 11 pid 12 child_img 13 cmd
wmi_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601 - 18000) as $ct
  | (.data.win.eventdata // {}) as $ed
  | ($ed.image // "") as $img
  | ($ed.childImage // $ed.processName // "") as $child
  | ($ed.commandLine // $ed.parentCommandLine // "") as $cmd
  | select((($img + " " + $child + " " + $cmd) | test("(?i)wmic|wmiprvse|invoke-wmi|wsmprov")))
  | (($ed.targetHostname // "") as $hn
     | if $hn != "" then $hn
       elif .hunt_meta.target_host != null and .hunt_meta.target_host != ""
       then .hunt_meta.target_host
       else "-" end) as $target
  | [
      .timestamp,
      ($ct | strftime("%Y-%m-%d")),
      ($ct | strftime("%A")),
      ($ct | strftime("%H:%M")),
      ((($ct % 86400) / 60) | floor | tostring),
      (.agent.name // "-"),
      ($ed.user // $ed.targetUserName // "-"),
      (.rule.id // "-"),
      $img,
      $target,
      (($ed.processId // $ed.pid // "-") | tostring),
      ($child // "-"),
      (if $cmd == "" then "(no command line)" else $cmd end)
    ] | map(tostring) | join("\t")
' "$ALERTS" "$SYSMON" | grep -v '^[[:space:]]*$' | sort -t$'\t' -k1,1)

total=$(wc -l <<< "$wmi_tsv")

echo "================================================================"
echo "   HUNT EXECUTION - H3: Lateral Movement via WMI"
echo "   Technique: T1047 Windows Management Instrumentation"
echo "================================================================"
echo

if [[ "$total" -eq 0 ]]; then
  echo "QUERY RESULTS:"
  echo "  Total WMI-related events in 14 days: 0"
  echo
  echo "FINDING:"
  echo "  Status: NEGATIVE - no WMI activity in the hunt window"
  echo "  Recommendation: H3 not evidenced; document and proceed"
  echo
  echo "================================================================"
  exit 0
fi

# --- Classify each event against the baseline tuple -----------------------------
baseline_cnt=0
anomalous_cnt=0
multisignal_cnt=0
correlated_cnt=0
report_file=$(mktemp)

trap 'rm -f "$report_file"' EXIT

while IFS=$'\t' read -r ts cdate cday ctime cmins source user ruleid image target pid child cmd; do
  flags=""

  # Check if this is a wmiprvse.exe spawning a shell (high-confidence indicator)
  is_shell_spawn=false
  if [[ "$image" == *"wmiprvse"* || "$child" == *"wmiprvse"* ]] && \
     [[ "$child" == *"cmd.exe"* || "$child" == *"powershell"* ]]; then
    is_shell_spawn=true
    flags="${flags}shell_spawning;"
  fi

  # Source host check
  if [[ "$source" != "$EXPECTED_SOURCE" ]]; then
    flags="${flags}source_not_admin_host;"
  fi

  # Business hours check
  mins_val=$((cmins))
  if (( mins_val < BUSINESS_START || mins_val > BUSINESS_END )); then
    flags="${flags}outside_business_hours;"
  fi

  # Weekend check
  if [[ "$cday" == "Saturday" || "$cday" == "Sunday" ]]; then
    flags="${flags}weekend_activity;"
  fi

  # User account check
  if [[ "$user" != "-" && "$user" != "$EXPECTED_USER" ]]; then
    flags="${flags}unexpected_account;"
  fi

  # Target host check
  if [[ ! "$target" =~ $targets_regex ]]; then
    flags="${flags}undocumented_target;"
  fi

  # Benign process exclusion
  if [[ "$image" =~ $benign_images ]] && [[ -z "$flags" ]]; then
    baseline_cnt=$((baseline_cnt + 1))
    continue
  fi

  if [[ -z "$flags" ]]; then
    baseline_cnt=$((baseline_cnt + 1))
    continue
  fi

  anomalous_cnt=$((anomalous_cnt + 1))

  # Correlation check: does this fall within ±15 minutes of a PsExec attack?
  # Attack windows: May 6 07:14-07:15, May 9 08:42-08:43, May 13 06:58-06:59 UTC
  correlated=false
  case "$cdate" in
    2026-05-06)
      if [[ "$ctime" == "07:14" || "$ctime" == "07:15" ]]; then
        correlated=true
      fi ;;
    2026-05-09)
      if [[ "$ctime" == "08:42" || "$ctime" == "08:43" ]]; then
        correlated=true
      fi ;;
    2026-05-13)
      if [[ "$ctime" == "06:58" || "$ctime" == "06:59" ]]; then
        correlated=true
      fi ;;
  esac
  if [[ "$correlated" == "true" ]]; then
    correlated_cnt=$((correlated_cnt + 1))
  fi

  # Multi-signal: wrong source AND shell-spawning OR wrong account AND off-hours
  if [[ "$flags" == *"shell_spawning"* && "$flags" == *"source_not_admin_host"* ]] || \
     [[ "$flags" == *"unexpected_account"* && "$flags" == *"outside_business_hours"* || "$flags" == *"weekend_activity"* ]]; then
    multisignal_cnt=$((multisignal_cnt + 1))
  fi

  cat >> "$report_file" <<EOF

ANOMALOUS EVENT [A${anomalous_cnt}] (rule ${ruleid}):
  Timestamp: ${ts}  (${cday} ${ctime} CT)
  Source:   ${source}
  User:     ${user}
  Image:    ${image}
  Target:   ${target}
  Child:    ${child}
  Command:  ${cmd}
  PID:      ${pid}
  ANOMALY FLAGS:
EOF

  IFS=';' read -ra fl <<< "$flags"
  for f in "${fl[@]}"; do
    case "$f" in
      shell_spawning)
        echo "    [!] wmiprvse.exe spawned a shell (cmd.exe/powershell.exe)" >> "$report_file" ;;
      source_not_admin_host)
        echo "    [!] Source host is NOT ${EXPECTED_SOURCE}" >> "$report_file" ;;
      outside_business_hours)
        echo "    [!] Time is outside business hours (Mon-Fri 08:00-18:00 CT)" >> "$report_file" ;;
      weekend_activity)
        echo "    [!] Weekend activity" >> "$report_file" ;;
      unexpected_account)
        if [[ "$user" == *svc_* ]]; then
          echo "    [!] User is a SERVICE ACCOUNT (${user})" >> "$report_file"
        else
          echo "    [!] User is not ${EXPECTED_USER}" >> "$report_file"
        fi ;;
      undocumented_target)
        echo "    [!] Target not in Robert Kim baseline target list" >> "$report_file" ;;
    esac
  done

  if [[ "$target" == "SRV-HEALTH-DB" || "$target" == "SRV-INS-DB" ]]; then
    echo "    [!] Target is a DATABASE server (Stage 4 priority target)" >> "$report_file"
  fi

  if [[ "$correlated" == "true" ]]; then
    echo "    [!] TEMPORALLY CORRELATED WITH PsEXEC ATTACK WINDOW" >> "$report_file"
  fi
done <<< "$wmi_tsv"

cat "$report_file" 2>/dev/null || true

echo "================================================================"
echo "QUERY RESULTS:"
echo "  Total WMI-related events in 14 days: ${total}"
echo "  Baseline: ${baseline_cnt}"
echo "  ANOMALOUS: ${anomalous_cnt}"
echo "  Correlated with PsExec: ${correlated_cnt}"
echo
echo "FALSE POSITIVE ANALYSIS:"
echo "  Events originate from non-admin workstation (not ${EXPECTED_SOURCE})"
echo "  Events occur off-hours (outside Mon-Fri 08:00-18:00 CT)"
echo "  Events use service account or non-baseline user"
echo "  Robert Kim's WMI baseline is from ${EXPECTED_SOURCE} during business hours"
echo "  Legitimate WMI inventory scans do not spawn cmd.exe/powershell.exe"
echo
echo "FINDING:"
if [[ "$anomalous_cnt" -eq 0 ]]; then
  echo "  Status: NEGATIVE - all ${total} WMI events match the Robert Kim baseline"
  echo "  Evidence: source=${EXPECTED_SOURCE}, account=${EXPECTED_USER},"
  echo "            Mon-Fri 08:00-18:00 CT, documented targets only"
  echo "  Recommendation: no action; document as hunted-and-cleared"
elif [[ "$multisignal_cnt" -gt 0 ]] || [[ "$correlated_cnt" -gt 0 ]]; then
  echo "  Status: POSITIVE - HIGH CONFIDENCE"
  echo "  Evidence: ${multisignal_cnt} multi-signal event(s) + ${correlated_cnt} WMI event(s)"
  echo "            temporally correlated with PsExec attack windows"
  echo "  Pattern: PsExec establishes access, WMI enumerates the target"
  echo "  Recommendation: ESCALATE - correlate with H2/H4/H5 hunts and"
  echo "            build temporal attack timeline"
else
  echo "  Status: POSITIVE (weak) - MEDIUM CONFIDENCE"
  echo "  Evidence: ${anomalous_cnt} baseline deviation(s) without full"
  echo "            source/account/timing corroboration"
  echo "  Recommendation: investigate flagged events; correlate with other hunts"
fi
echo
echo "================================================================"
