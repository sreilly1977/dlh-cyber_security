#!/bin/bash
#
# Name: 4-hunt_psexec.sh
# Purpose: Execute hunt hypothesis H1 (lateral movement via PsExec,
#          T1021.002). Extracts all PsExec-related events (image or
#          command line mentioning psexec) from the 14-day SIEM exports,
#          classifies each against Robert Kim's documented baseline tuple
#          (source host, Central Time business hours, weekday, account,
#          authorized target), prints full evidence for every anomalous
#          event with per-event anomaly flags, and concludes with a
#          finding and confidence assessment. Read-only; stdout only.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Baseline tuple (validated in 2-baseline_profile.sh):
#   source  = WS-ADMIN-01
#   account = MEDDEFENSE\robert.kim
#   window  = Mon-Fri 08:00-18:00 Central Time (CDT = UTC-5 in May 2026)
#   targets = SRV-AV-01, SRV-BACKUP-01, SRV-DC-01, SRV-FILE-01,
#             SRV-HEALTH-DB, SRV-INS-DB, SRV-PATCH-01
# Notes:
#   - hunt_meta.target_host populates on PsExec events in this dataset and
#     is the primary target source; destinationHostname and command-line
#     UNC tokens are fallbacks.
#   - Some matched events (e.g. Sysmon network/DNS events) carry an image
#     but no commandLine and often no user field; the account flag is only
#     raised when a user value is present, not when the field is absent.
#   - An additional advisory-derived flag: PsExec binary executed from a
#     writable staging path (C:\Users\Public, C:\Windows\Temp,
#     C:\ProgramData), per TTP 4.2 observed paths in HC3-ADV-004.

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

# --- Extract and normalize PsExec events to TSV --------------------------------
# Columns: 1 ts 2 date(CT) 3 weekday(CT) 4 hh:mm(CT) 5 minutes(CT)
#          6 source(agent) 7 user 8 ruleid 9 command/image 10 target
#          11 pid 12 image
psexec_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601 - 18000) as $ct
  | (.data.win.eventdata // {}) as $ed
  | ($ed.image // "") as $img
  | ($ed.commandLine // "") as $cmd
  | select((($img + " " + $cmd) | test("(?i)psexec")))
  | (first(
      [.hunt_meta.target_host, $ed.destinationHostname,
       ($cmd | split("\\\\")[1] // "" | split(" ")[0])]
      | .[] | select(. != null and . != "")
    ) // "-") as $target
  | [
      .timestamp,
      ($ct | strftime("%Y-%m-%d")),
      ($ct | strftime("%A")),
      ($ct | strftime("%H:%M")),
      ((($ct % 86400) / 60) | floor | tostring),
      (.agent.name // "-"),
      ($ed.user // $ed.targetUserName // "-"),
      (.rule.id // "-"),
      (if $cmd == "" then "(no command line; image: " + $img + ")" else $cmd end),
      $target,
      (($ed.processId // $ed.pid // "-") | tostring),
      $img
    ] | map(tostring) | join("\t")
' "$ALERTS" "$SYSMON" | grep -v '^[[:space:]]*$' | sort -t$'\t' -k1,1)

total=$(wc -l <<< "$psexec_tsv")

echo "================================================================"
echo "   HUNT EXECUTION - H1: Lateral Movement via PsExec"
echo "   Technique: T1021.002 SMB/Windows Admin Shares"
echo "================================================================"
echo

if [[ "$total" -eq 0 ]]; then
  echo "QUERY RESULTS:"
  echo "  Total PsExec events in 14 days: 0"
  echo
  echo "FINDING:"
  echo "  Status: NEGATIVE - no PsExec activity in the hunt window"
  echo "  Recommendation: H1 not evidenced; document and proceed"
  echo
  echo "================================================================"
  exit 0
fi

# --- Classify each event against the baseline tuple -----------------------------
baseline_cnt=0
anomalous_cnt=0
multisignal_cnt=0
anomalous_output=""

while IFS=$'\t' read -r ts cdate cday ctime cmins source user ruleid command target pid image; do
  flags=""

  [[ "$source" != "$EXPECTED_SOURCE" ]] && flags+="source_not_admin_host;"
  (( cmins < BUSINESS_START || cmins > BUSINESS_END )) && flags+="outside_business_hours;"
  [[ "$cday" == "Saturday" || "$cday" == "Sunday" ]] && flags+="weekend_activity;"
  if [[ "$user" != "-" && "$user" != "$EXPECTED_USER" ]]; then
    flags+="unexpected_account;"
  fi
  [[ ! "$target" =~ $targets_regex ]] && flags+="undocumented_target;"
  if [[ "$command$image" == *[Uu]sers\\[Pp]ublic* || \
        "$command$image" == *indows\\[Tt]emp* || \
        "$command[image" == *rogramData* ]]; then
    flags+="staging_path_binary;"
  fi

  if [[ -z "$flags" ]]; then
    baseline_cnt=$((baseline_cnt + 1))
    continue
  fi

  anomalous_cnt=$((anomalous_cnt + 1))

  # Multi-signal: wrong source AND wrong account AND wrong timing together
  if [[ "$flags" == *source_not_admin_host* && "$flags" == *unexpected_account* \
     && ( "$flags" == *outside_business_hours* || "$flags" == *weekend_activity* ) ]]; then
    multisignal_cnt=$((multisignal_cnt + 1))
  fi

  {
    echo ""
    echo "ANOMALOUS EVENT [A${anomalous_cnt}] (rule ${ruleid}):"
    echo "  Timestamp: ${ts}  (${cday} ${ctime} CT)"
    echo "  Source:   ${source}"
    echo "  User:     ${user}"
    echo "  Command:  ${command}"
    echo "  Target:   ${target}"
    echo "  PID:      ${pid}"
    echo "  Image:    ${image}"
    echo "  ANOMALY FLAGS:"
    IFS=';' read -ra fl <<< "$flags"
    for f in "${fl[@]}"; do
      case "$f" in
        source_not_admin_host)  echo "    [!] Source host is NOT ${EXPECTED_SOURCE}" ;;
        outside_business_hours) echo "    [!] Time is outside business hours (Mon-Fri 08:00-18:00 CT)" ;;
        weekend_activity)       echo "    [!] Weekend activity" ;;
        unexpected_account)
          if [[ "$user" == *svc_* ]]; then
            echo "    [!] User is a SERVICE ACCOUNT (${user})"
          else
            echo "    [!] User is not ${EXPECTED_USER}"
          fi ;;
        undocumented_target)    echo "    [!] Target not in Robert Kim baseline target list" ;;
        staging_path_binary)    echo "    [!] PsExec binary executed from a writable staging path (advisory TTP 4.2)" ;;
      esac
    done
    if [[ "$target" == "SRV-HEALTH-DB" || "$target" == "SRV-INS-DB" ]]; then
      echo "    [!] Target is a DATABASE server (Stage 4 priority target)"
    fi
  } >> /tmp/anomalous_report_$$
done <<< "$psexec_tsv"

cat /tmp/anomalous_report_$$ 2>/dev/null || true
rm -f /tmp/anomalous_report_$$ 2>/dev/null || true

# --- Finding and confidence assessment -------------------------------------------
echo "================================================================"
echo "QUERY RESULTS:"
echo "  Total PsExec events in 14 days: ${total}"
echo "  Baseline: ${baseline_cnt}"
echo "  ANOMALOUS: ${anomalous_cnt}"
echo
echo "FINDING:"
if [[ "$anomalous_cnt" -eq 0 ]]; then
  echo "  Status: NEGATIVE - all ${total} PsExec events match the Robert Kim baseline"
  echo "  Evidence: source=${EXPECTED_SOURCE}, account=${EXPECTED_USER},"
  echo "            Mon-Fri 08:00-18:00 CT, documented targets only"
  echo "  Recommendation: no action; document as hunted-and-cleared"
elif [[ "$multisignal_cnt" -gt 0 ]]; then
  echo "  Status: POSITIVE - HIGH CONFIDENCE"
  echo "  Evidence: ${multisignal_cnt} event(s) combine non-admin source host,"
  echo "            non-robert.kim account and off-hours timing;"
  echo "            ${anomalous_cnt} total baseline violations"
  echo "  Recommendation: ESCALATE - correlate with H2/H3/H4/H5 hunts and the"
  echo "            HEALTHBANE-phishing alert hosts before attributing"
else
  echo "  Status: POSITIVE (weak) - MEDIUM CONFIDENCE"
  echo "  Evidence: ${anomalous_cnt} baseline deviation(s) without full"
  echo "            source/account/timing corroboration"
  echo "  Recommendation: investigate flagged events; correlate with other hunts"
fi
echo
echo "================================================================"
