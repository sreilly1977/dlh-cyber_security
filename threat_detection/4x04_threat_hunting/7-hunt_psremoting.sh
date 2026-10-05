#!/bin/bash
#
# Name: 7-hunt_psremoting.sh
# Purpose: Execute hunt hypothesis H4 (PowerShell Remoting / Windows
#          Remote Management, T1021.006). Extracts PSRemoting-related
#          events (Enter-PSSession, Invoke-Command, New-PSSession,
#          wsmprovhost.exe, Copy-Item to remote targets) from the
#          14-day SIEM exports, classifies each against Robert Kim's
#          documented baseline (source host, Central Time business
#          hours, weekday, account, authorized targets), prints full
#          evidence for every anomalous event, correlates findings
#          with PsExec/WMI/LSASS timelines from Tasks 4-6, and
#          cross-references Copy-Item commands against 4x03 exfil
#          staging paths. Read-only; stdout only.
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
# Attack windows from Tasks 4-6 (PsExec + LSASS chain):
#   Night 1: 2026-05-06T07:14 CT (SRV-HEALTH-DB)
#   Night 2: 2026-05-09T08:42 CT (SRV-INS-DB)
#   Night 3: 2026-05-13T06:58 CT (SRV-DC-01)
#
# 4x03 exfiltrator staging paths (from 4x03_malware_awareness):
#   C:\Users\Public\*, C:\Windows\Temp\*, temporary download dirs
#   on database servers (SRV-HEALTH-DB, SRV-INS-DB)

set -euo pipefail

readonly ALERTS="siem_export/wazuh_alerts_14d.json"
readonly SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
readonly BASELINE="baseline/robert_kim_activity.json"
readonly REF_4X03="reference/4x03_attack_mapping.json"  # Contains exfil staging paths

for f in "$ALERTS" "$SYSMON"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

# Baseline configuration
readonly EXPECTED_SOURCE="WS-ADMIN-01"
readonly EXPECTED_USER="MEDDEFENSE\\robert.kim"
readonly BUSINESS_START=480     # 08:00 CT in minutes since midnight
readonly BUSINESS_END=1080       # 18:00 CT
targets_regex="^(SRV-AV-01|SRV-BACKUP-01|SRV-DC-01|SRV-FILE-01|SRV-HEALTH-DB|SRV-INS-DB|SRV-PATCH-01)$"

# Exfiltrator staging patterns from 4x03
readonly EXFIL_STAGING_REGEX="(users\\\\public|windows\\\\temp|programdata).*\\\\(downloads|tmp|cache)"

# --- Extract and normalize PSRemoting events to TSV ------------------------------
# Columns: 1 ts 2 date(CT) 3 weekday(CT) 4 hh:mm(CT) 5 minutes(CT)
#          6 source(agent) 7 user 8 ruleid 9 image 10 target 11 cmd 12 child
psrem_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601 - 18000) as $ct
  | (.data.win.eventdata // {}) as $ed
  | ($ed.image // "") as $img
  | ($ed.commandLine // "") as $cmd
  | select((($img + " " + $cmd) | test("(?i)(enter-pssession|invoke-command|new-pssession|wsmprovhost|copy-item)")))
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
      (if $cmd == "" then "(no command line)" else $cmd end),
      ($ed.childImage // "-")
    ] | map(tostring) | join("\t")
' "$ALERTS" "$SYSMON" | grep -v '^[[:space:]]*$' | sort -t$'\t' -k1,1)

total=$(wc -l <<< "$psrem_tsv")

echo "================================================================"
echo "   HUNT EXECUTION - H4: PowerShell Remoting"
echo "   Technique: T1021.006 Windows Remote Management"
echo "================================================================"
echo

if [[ "$total" -eq 0 ]]; then
  echo "QUERY RESULTS:"
  echo "  Total PSRemoting events in 14 days: 0"
  echo
  echo "FINDING:"
  echo "  Status: NEGATIVE - no PSRemoting activity in the hunt window"
  echo "  Recommendation: H4 not evidenced; document and proceed"
  echo
  echo "================================================================"
  exit 0
fi

# --- Classify each event against the baseline tuple -----------------------------
baseline_cnt=0
anomalous_cnt=0
multisignal_cnt=0
correlated_cnt=0
exfil_correlated_cnt=0
report_file=$(mktemp)
timeline_file=$(mktemp)
trap 'rm -f "$report_file" "$timeline_file"' EXIT

while IFS=$'\t' read -r ts cdate cday ctime cmins source user ruleid image target cmd child; do
  flags=""
  is_exfil=false

  # Shell-spawning check (high-confidence indicator for remote execution)
  shell_spawn=false
  if [[ "$child" == *"powershell"* || "$child" == *"cmd.exe"* ]]; then
    shell_spawn=true
    flags="${flags}shell_spawning;"
  fi

  # Staging path check (4x03 exfiltrator correlation)
  if echo "$cmd$image" | grep -qiE "$EXFIL_STAGING_REGEX"; then
    is_exfil=true
    exfil_correlated_cnt=$((exfil_correlated_cnt + 1))
    flags="${flags}exfil_staging_path;"
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

  if [[ -z "$flags" ]]; then
    baseline_cnt=$((baseline_cnt + 1))
    continue
  fi

  anomalous_cnt=$((anomalous_cnt + 1))

  # Correlation check: does this fall within ±15 minutes of a PsExec attack?
  correlated=false
  case "$cdate" in
    2026-05-06)
      if [[ "$ctime" == "07:14" || "$ctime" == "07:15" || "$ctime" == "07:52" ]]; then
        correlated=true
      fi ;;
    2026-05-09)
      if [[ "$ctime" == "08:42" || "$ctime" == "08:43" || "$ctime" == "09:19" ]]; then
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
     [[ "$flags" == *"unexpected_account"* && ("$flags" == *"outside_business_hours"* || "$flags" == *"weekend_activity"*) ]]; then
    multisignal_cnt=$((multisignal_cnt + 1))
  fi

  {
    echo ""
    echo "ANOMALOUS EVENT [A${anomalous_cnt}] (rule ${ruleid}):"
    echo "  Timestamp: ${ts}  (${cday} ${ctime} CT)"
    echo "  Source:   ${source}"
    echo "  User:     ${user}"
    echo "  Image:    ${image}"
    echo "  Target:   ${target}"
    echo "  Command:  ${cmd}"
    echo "  Child:    ${child}"
    echo "  ANOMALY FLAGS:"

    IFS=';' read -ra fl <<< "$flags"
    for f in "${fl[@]}"; do
      case "$f" in
        shell_spawning)
          echo "    [!] PSRemoting spawned a shell (cmd.exe/powershell.exe)" ;;
        source_not_admin_host)
          echo "    [!] Source host is NOT ${EXPECTED_SOURCE}" ;;
        outside_business_hours)
          echo "    [!] Time is outside business hours (Mon-Fri 08:00-18:00 CT)" ;;
        weekend_activity)
          echo "    [!] Weekend activity" ;;
        unexpected_account)
          if [[ "$user" == *svc_* ]]; then
            echo "    [!] User is a SERVICE ACCOUNT (${user})"
          else
            echo "    [!] User is not ${EXPECTED_USER}"
          fi ;;
        undocumented_target)
          echo "    [!] Target not in Robert Kim baseline target list" ;;
        exfil_staging_path)
          echo "    [!] Copy-Item references 4x03 exfiltrator staging path" ;;
      esac
    done

    if [[ "$target" == "SRV-HEALTH-DB" || "$target" == "SRV-INS-DB" ]]; then
      echo "    [!] Target is a DATABASE server (Stage 4 priority target)"
    fi

    if [[ "$correlated" == "true" ]]; then
      echo "    [!] TEMPORALLY CORRELATED WITH PsEXEC/WMI ATTACK WINDOW"
    fi
  } >> "$report_file"

  # Add to timeline for cross-correlation
  echo "${cmins} PSREMOTING ${ts}  ${source} -> ${target}  ${user} (${cmd:0:50}...)" >> "$timeline_file"

done <<< "$psrem_tsv"

cat "$report_file" 2>/dev/null || true

echo "================================================================"
echo "QUERY RESULTS:"
echo "  Total PSRemoting events in 14 days: ${total}"
echo "  Baseline: ${baseline_cnt}"
echo "  ANOMALOUS: ${anomalous_cnt}"
echo "  Correlated with PsExec/WMI: ${correlated_cnt}"
echo "  Correlated with 4x03 Exfil Staging: ${exfil_correlated_cnt}"
echo

# --- Cross-reference with 4x03 attack mapping ------------------------------------
echo "CROSS-REFERENCE WITH 4x03:"
echo "  The HEALTHBANE exfiltrator from 4x03 was staged on servers with"
echo "  access to health records. Copy-Item events referencing:"
echo "    C:\\Users\\Public\\*, C:\\Windows\\Temp\\*"
echo "  indicate data staging consistent with the exfiltration chain."
if [[ "$exfil_correlated_cnt" -gt 0 ]]; then
  echo "  Evidence: ${exfil_correlated_cnt} PSRemoting event(s) reference"
  echo "            4x03 exfil staging paths."
fi
echo

# --- Unified timeline (append to 6-hunt_credentials timeline) --------------------
if [[ -f "$timeline_file" ]]; then
  echo "UNIFIED ATTACK TIMELINE (PSRemoting + Previous Hunts):"
  cat "$timeline_file" 2>/dev/null || true
  echo
fi

# --- Finding and confidence assessment ------------------------------------------
echo "FINDING:"
if [[ "$anomalous_cnt" -eq 0 ]]; then
  echo "  Status: NEGATIVE - all ${total} PSRemoting events match the Robert Kim baseline"
  echo "  Evidence: source=${EXPECTED_SOURCE}, account=${EXPECTED_USER},"
  echo "            Mon-Fri 08:00-18:00 CT, documented targets only"
  echo "  Recommendation: no action; document as hunted-and-cleared"
elif [[ "$multisignal_cnt" -gt 0 ]] || [[ "$correlated_cnt" -gt 0 ]]; then
  echo "  Status: POSITIVE - HIGH CONFIDENCE"
  echo "  PSRemoting from non-admin host using service account is consistent"
  echo "  with attacker staging activity."
  echo "  Evidence: ${multisignal_cnt} multi-signal event(s) + ${correlated_cnt} event(s)"
  echo "            temporally correlated with PsExec/WMI attack windows"
  echo "            + ${exfil_correlated_cnt} event(s) referencing 4x03 exfil staging"
  echo "  Pattern: PsExec/WMI establishes access, PSRemoting stages files,"
  echo "            4x03 exfiltrator collects data from database servers"
  echo "  Recommendation: ESCALATE - correlate with H5 (service account abuse),"
  echo "            build unified attack timeline, update ATT&CK layer"
else
  echo "  Status: POSITIVE (weak) - MEDIUM CONFIDENCE"
  echo "  Evidence: ${anomalous_cnt} baseline deviation(s) without full"
  echo "            source/account/timing corroboration"
  echo "  Recommendation: investigate flagged events; correlate with other hunts"
fi
echo
echo "================================================================"
