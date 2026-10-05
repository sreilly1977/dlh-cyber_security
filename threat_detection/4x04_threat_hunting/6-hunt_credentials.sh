#!/bin/bash
#
# Name: 6-hunt_credentials.sh
# Purpose: Execute hunt hypothesis H2 (credential access via LSASS memory,
#          T1003.001). Extracts Sysmon Event 10 process-access events with
#          TargetImage = lsass.exe from the 14-day SIEM exports, separates
#          legitimate system LSASS access (per the HC3 advisory whitelist:
#          MsMpEng.exe, WmiPrvSE.exe, wininit.exe) from anomalous access
#          (non-whitelisted source process, writable staging path, memory-
#          read access mask, off-hours/non-baseline context), then searches
#          for subsequent authentication events using svc_healthsync and
#          builds a unified credential-theft timeline correlating LSASS
#          access, service account use and PsExec lateral movement.
#          Read-only; stdout only.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Known-good LSASS accessors per HC3-2026-HEALTHBANE-004 TTP 4.1:
#   antivirus engine (MsMpEng.exe), WmiPrvSE.exe, wininit.exe.
# Advisory-observed dump tool paths: C:\Windows\Temp, C:\Users\Public
# (incl. Downloads), C:\ProgramData.
# Memory-read access masks associated with dumping: 0x1010, 0x1410, 0x143a.
# Baseline tuple for context flags (2-baseline_profile.sh):
#   WS-ADMIN-01 / MEDDEFENSE\robert.kim / Mon-Fri 08:00-18:00 CT.
# Service account authorization rule (service_accounts.txt): service
# accounts authenticate from designated SERVERS via network logon;
# interactive/workstation-source authentication is unauthorized abuse.

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
readonly BUSINESS_START=480     # 08:00 CT in minutes since midnight
readonly BUSINESS_END=1080       # 18:00 CT

# --- Extract LSASS access events (Sysmon E10: targetImage = lsass.exe) ----------
lsass_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601) as $utc
  | ($utc - 18000) as $ct
  | (.data.win.eventdata // {}) as $ed
  | ($ed.targetImage // "") as $timg
  | select($timg | test("(?i)lsass"))
  | [
      .timestamp,
      ($utc | tostring),
      ($ct | strftime("%A")),
      ($ct | strftime("%H:%M")),
      ((($ct % 86400) / 60) | floor | tostring),
      (.agent.name // "-"),
      ($ed.user // $ed.targetUserName // "-"),
      ($ed.image // $ed.sourceImage // "-"),
      $timg,
      ($ed.grantedAccess // $ed.grantMask // "-"),
      (($ed.processId // $ed.sourceProcessId // "-") | tostring),
      (.rule.id // "-")
    ] | map(tostring) | join("\t")
' "$ALERTS" "$SYSMON" | grep -v '^[[:space:]]*$' | sort -t$'\t' -k1,1)

lsass_total=$(wc -l <<< "$lsass_tsv")

# --- Extract svc_healthsync authentication events (4624-style logons) ----------
svc_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601) as $utc
  | ($utc - 18000) as $ct
  | (.data.win.eventdata // {}) as $ed
  | select(($ed.targetUserName // "") | test("svc_healthsync"))
  | select((.rule.id // "") == "60106" or ((.rule.description // "") | test("login"; "i")))
  | [
      .timestamp,
      ($utc | tostring),
      ($ct | strftime("%A")),
      ($ct | strftime("%H:%M")),
      ((($ct % 86400) / 60) | floor | tostring),
      ($ed.targetUserName // "-"),
      ($ed.workstationName // "-"),
      ($ed.logonType // "-"),
      (.hunt_meta.target_host // .agent.name // "-"),
      ($ed.ipAddress // "-")
    ] | map(tostring) | join("\t")
' "$ALERTS" "$SYSMON" | grep -v '^[[:space:]]*$' | sort -t$'\t' -k1,1)

# svc_healthsync logons originating from WORKSTATION hosts (WS-*): the
# authorization matrix permits server-origin network logons only.
svc_workstation_tsv=$(awk -F'\t' '$7 ~ /^WS-/ || $7 ~ /^ws-/' <<< "$svc_tsv")
svc_ws_count=$(wc -l <<< "$svc_workstation_tsv")

# --- Extract PsExec events for timeline correlation (agent = WS-RECV-03) ------
psexec_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601) as $utc
  | (.data.win.eventdata // {}) as $ed
  | select((($ed.image // "") + " " + ($ed.commandLine // "")) | test("(?i)psexec"))
  | select(.agent.name == "WS-RECV-03")
  | [
      .timestamp,
      ($utc | tostring),
      (.hunt_meta.target_host // .agent.name // "-"),
      ($ed.commandLine // "(no command line)")
    ] | map(tostring) | join("\t")
' "$ALERTS" "$SYSMON" | grep -v '^[[:space:]]*$' | sort -t$'\t' -k1,1)

echo "================================================================"
echo "   HUNT EXECUTION - H2: Credential Access (LSASS)"
echo "   Technique: T1003.001 LSASS Memory"
echo "================================================================"
echo

# --- Classify LSASS access events ----------------------------------------------
legit_cnt=0
anom_cnt=0
memory_read_cnt=0
timeline_file=$(mktemp)
report_file=$(mktemp)
trap 'rm -f "$timeline_file" "$report_file"' EXIT

while IFS=$'\t' read -r ts epoch cday ctime cmins host user srcimg timg gaccess pid ruleid; do
  # Legitimate system accessor check (advisory whitelist, case-insensitive
  # on the basename of the source image)
  basematch=false
  if [[ "${srcimg,,}" == *msmpeng* || "${srcimg,,}" == *wmiprvse* || "${srcimg,,}" == *wininit* ]]; then
    basematch=true
  fi

  staging=false
  if [[ "${srcimg,,}" == *windows\\temp* || "${srcimg,,}" == *users\\public* || "${srcimg,,}" == *programdata* ]]; then
    staging=true
  fi

  memread=false
  if [[ "$gaccess" == "0x1010" || "$gaccess" == "0x1410" || "$gaccess" == "0x143a" ]]; then
    memread=true
    memory_read_cnt=$((memory_read_cnt + 1))
  fi

  # Context flags (informational; the primary classifier is the whitelist)
  ctx=""
  mins_val=$((cmins))
  (( mins_val < BUSINESS_START || mins_val > BUSINESS_END )) && ctx="${ctx}off-hours;"
  [[ "$cday" == "Saturday" || "$cday" == "Sunday" ]] && ctx="${ctx}weekend;"
  [[ "$host" != "$EXPECTED_SOURCE" && "$host" == WS-* ]] && ctx="${ctx}workstation-host;"

  if [[ "$basematch" == "true" && "$staging" == "false" ]]; then
    legit_cnt=$((legit_cnt + 1))
    continue
  fi

  anom_cnt=$((anom_cnt + 1))

  {
    echo ""
    echo "  [A${anom_cnt}] ${ts}  (${cday} ${ctime} CT)"
    echo "    Host:           ${host}"
    echo "    User:           ${user}"
    echo "    Source Process: ${srcimg}"
    echo "    Target:         ${timg}"
    echo "    Access Mask:    ${gaccess}"
    if [[ "$memread" == "true" ]]; then
      echo "    -> Access mask consistent with MEMORY READ (dumping)"
    fi
    if [[ "$staging" == "true" ]]; then
      echo "    -> Source process in WRITABLE STAGING PATH (advisory TTP 4.1)"
    fi
    echo "    PID:            ${pid}   (rule ${ruleid})"
    if [[ -n "$ctx" ]]; then
      echo "    Context:        ${ctx%;}"
    fi
  } >> "$report_file"

  # Timeline entry (tab-delimited, epoch first for sorting)
  echo "${epoch} LSASS_ACCESS ${ts}  ${host}  ${srcimg} -> ${timg} (${gaccess})" >> "$timeline_file"

done <<< "$lsass_tsv"

echo "LSASS ACCESS EVENTS:"
echo "  Total LSASS access events: ${lsass_total}"
echo "  System/legitimate: ${legit_cnt}"
echo "  ANOMALOUS: ${anom_cnt}"
if [[ "$memory_read_cnt" -gt 0 ]]; then
  echo "  Events with memory-read access masks: ${memory_read_cnt}"
fi
echo

if [[ "$anom_cnt" -gt 0 ]]; then
  echo "ANOMALOUS LSASS ACCESS:"
  cat "$report_file"
  echo
fi

# --- Credential usage correlation ----------------------------------------------
echo "CREDENTIAL USAGE CORRELATION:"
echo "  svc_healthsync logon events found: $(wc -l <<< "$svc_tsv")"
echo "  svc_healthsync logons from WORKSTATION hosts (authorization violation): ${svc_ws_count}"
if [[ "$svc_ws_count" -gt 0 ]]; then
  echo ""
  echo "  svc_healthsync authentication from workstations:"
  while IFS=$'\t' read -r ts epoch cday ctime cmins acct ws ltype target ipaddr; do
    echo "    ${ts}  (${cday} ${ctime} CT)  ${ws} -> ${target}  logonType=${ltype}  ip=${ipaddr}"
    echo "${epoch} SVC_AUTH ${ts}  ${ws} -> ${target} (svc_healthsync logonType ${ltype})" >> "$timeline_file"
  done <<< "$svc_workstation_tsv"
fi
echo

# PsExec entries into the timeline
if [[ -n "$psexec_tsv" ]]; then
  while IFS=$'\t' read -r ts epoch target cmd; do
    echo "${epoch} PSEXEC_MOVE ${ts}  WS-RECV-03 -> ${target}  ${cmd}" >> "$timeline_file"
  done <<< "$psexec_tsv"
fi

# --- Unified credential-theft timeline -----------------------------------------
echo "CREDENTIAL THEFT TIMELINE (chronological, CT shown in event details):"
sort -k1,1n <<< "$(cat "$timeline_file" 2>/dev/null || true)" | cut -d' ' -f2- || true
echo

# --- Correlation verdict -------------------------------------------------------
lsass_before_svc=0
if [[ "$anom_cnt" -gt 0 && "$svc_ws_count" -gt 0 ]]; then
  first_lsass_epoch=$(awk '/LSASS_ACCESS/ {print $1; exit}' "$timeline_file" 2>/dev/null || echo "")
  first_svc_epoch=$(awk '/SVC_AUTH/ {print $1; exit}' "$timeline_file" 2>/dev/null || echo "")
  if [[ -n "${first_lsass_epoch:-}" && -n "${first_svc_epoch:-}" ]]; then
    delta=$(( first_svc_epoch - first_lsass_epoch ))
    if (( delta > 0 && delta <= 86400 )); then
      lsass_before_svc=1
    fi
  fi
fi

echo "FINDING:"
if [[ "$anom_cnt" -gt 0 && "$svc_ws_count" -gt 0 ]]; then
  echo "  Status: POSITIVE - HIGH CONFIDENCE"
  echo "  The attacker likely dumped credentials and later used svc_healthsync"
  echo "  for lateral movement."
  echo "  Evidence: ${anom_cnt} anomalous LSASS access event(s) (non-whitelisted"
  echo "            source process), ${svc_ws_count} svc_healthsync workstation"
  echo "            logon(s), correlated with $(wc -l <<< "$psexec_tsv") PsExec"
  echo "            lateral movement event(s) from WS-RECV-03"
  if [[ "$lsass_before_svc" -eq 1 ]]; then
    echo "  Chain confirmed: LSASS access PRECEDES service account use and"
    echo "            lateral movement (steal -> use -> move)"
  fi
elif [[ "$anom_cnt" -gt 0 || "$svc_ws_count" -gt 0 ]]; then
  echo "  Status: POSITIVE (partial) - MEDIUM CONFIDENCE"
  echo "  Evidence: ${anom_cnt} anomalous LSASS event(s), ${svc_ws_count} workstation"
  echo "            service account logon(s); full steal->use->move chain incomplete"
else
  echo "  Status: NEGATIVE - no anomalous LSASS access or service account abuse"
  echo "  Recommendation: document as hunted-and-cleared"
fi
echo
echo "================================================================"
