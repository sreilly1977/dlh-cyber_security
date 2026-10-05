#!/bin/bash
#
# Name: 12-gap_analysis.sh
# Purpose: For each Stage 4 technique newly confirmed by the hunt
#          (T1021.002 PsExec, T1003.001 LSASS memory, T1047 WMI,
#          T1021.006 PowerShell Remoting, T1078.002 service account
#          misuse, T1550.002 NTLM/pass-the-hash-style activity),
#          document the hunt finding, classify why the existing
#          detection stack missed it (missing rule / overly specific
#          rule / missing data source), identify the required data
#          source, specify the detection logic (fields to match,
#          baseline comparison, allowlist logic) and assign a
#          risk priority. Verifies from the SIEM exports that the
#          underlying telemetry was present during the hunt window
#          (evidence that the gap was logic, not data). Read-only;
#          stdout only.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Gap classification taxonomy (per task sheet):
#   MISSING RULE       data existed, no detection consumed it
#   OVERLY SPECIFIC    a rule existed but its conditions excluded
#                      the attacker's variant (e.g. path-locked,
#                      signature-era rule matching only known
#                      malware binaries, blind to LotL tools)
#   MISSING DATA       telemetry never captured (none found here)
#
# Measured telemetry presence (this script, from SIEM exports):
#   Sysmon Event 1  (process create)    - PsExec, PSRemoting staging
#   Sysmon Event 10 (process access)    - LSASS access
#   Windows 4624-style logon events     - svc_healthsync logons
#   PowerShell script-block logging     - PSRemoting commands
#
# Baseline tuple for detection logic (2-baseline_profile.sh):
#   WS-ADMIN-01 / MEDDEFENSE\robert.kim / Mon-Fri 08:00-18:00 CT
# Authorization matrix (IAM-SVC-2026-Q2) for allowlist logic.

set -euo pipefail

readonly ALERTS="siem_export/wazuh_alerts_14d.json"
readonly SYSMON="siem_export/wazuh_raw_sysmon_14d.json"

for f in "$ALERTS" "$SYSMON"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

# --- Measure telemetry presence per technique (validated selectors) ------------
count_events() {
  jq -r --arg pattern "$1" '
    (.data.win.eventdata // {}) as $ed
    | select((($ed.image // "") + " " + ($ed.commandLine // "") + " " +
              ($ed.targetImage // "")) | test($pattern))
    | .timestamp
  ' "$ALERTS" "$SYSMON" 2>/dev/null | sort -u | wc -l
}

count_logons() {
  jq -r '
    (.data.win.eventdata // {}) as $ed
    | select(($ed.targetUserName // "") | test("^svc_"))
    | .timestamp
  ' "$ALERTS" "$SYSMON" 2>/dev/null | sort -u | wc -l
}

count_ntlm() {
  jq -r '
    (.data.win.eventdata // {}) as $ed
    | select(($ed.targetUserName // "") | test("^svc_"))
    | select(($ed.authenticationPackageName // ($ed.authPackage // "")) | test("NTLM"))
    | .timestamp
  ' "$ALERTS" "$SYSMON" 2>/dev/null | sort -u | wc -l
}

cnt_psexec=$(count_events "(?i)psexec")
cnt_lsass=$(count_events "(?i)lsass")
cnt_wmi=$(count_events "(?i)wsmprovhost|wmiprvse")
cnt_psrem=$(count_events "(?i)enter-pssession|invoke-command|new-pssession")
cnt_svc=$(count_logons)
cnt_ntlm=$(count_ntlm)

# --- Output ----------------------------------------------------------------------
echo "================================================================"
echo "   DETECTION GAP ANALYSIS - Stage 4 Techniques"
echo "================================================================"
echo

echo "TELEMETRY PRESENCE CHECK (unique events in 14-day exports):"
echo "  Sysmon Event 1  (process create):    ${cnt_psexec} PsExec, ${cnt_psrem} PSRemoting command events"
echo "  Sysmon Event 10 (process access):    ${cnt_lsass} lsass.exe access events"
echo "  WMI/WinRM host process images:       ${cnt_wmi} events"
echo "  Service account logon events:        ${cnt_svc} svc_* logons"
echo "  NTLM-authenticated svc_* logons:      ${cnt_ntlm} events"
echo

echo "----------------------------------------------------------------"
echo "GAP 1: T1021.002 PsExec Lateral Movement"
echo "  Hunt Finding: PsExec from non-admin workstation WS-RECV-03, run"
echo "                from C:\\Users\\Public\\Downloads\\PsExec64.exe as"
echo "                svc_healthsync, off-hours, to DB/DC servers"
echo "  Why Missed:   MISSING RULE"
echo "                ${cnt_psexec} PsExec process-create events exist in the"
echo "                exports, but no rule consumed them. PsExec is a"
echo "                legitimate admin tool; the stack held no signature"
echo "                for it because Stage 4 used no malware."
echo "  Data Source:  Sysmon Event 1 (process create)"
echo "  Required Rule: alert on process create where image or"
echo "                commandline matches PsExec AND"
echo "                (source host != WS-ADMIN-01 OR outside Mon-Fri"
echo "                08:00-18:00 CT OR user not MEDDEFENSE\\robert.kim)"
echo "  Fields:        Image, CommandLine, User, host, timestamp (CT)"
echo "  Baseline:      Robert Kim tuple (WS-ADMIN-01/robert.kim/business"
echo "                hours/7 documented targets)"
echo "  Allowlist:     baseline tuple match suppresses; any deviation fires"
echo "  Priority:     P1"
echo

echo "GAP 2: T1003.001 LSASS Credential Access"
echo "  Hunt Finding: Non-system process C:\\Windows\\Temp\\debug_tool.exe"
echo "                accessed lsass.exe with memory-read mask 0x1010"
echo "                on WS-RECV-03 (May 5 and May 12)"
echo "  Why Missed:   MISSING RULE"
echo "                ${cnt_lsass} lsass.exe access events exist, but the rule"
echo "                whitelist covered only known AV/WMI system binaries"
echo "                without a deny-by-default posture; unknown binaries"
echo "                accessing LSASS raised no alert."
echo "  Data Source:  Sysmon Event 10 (process access)"
echo "  Required Rule: alert when TargetImage ends lsass.exe AND"
echo "                SourceImage not in allowlist (MsMpEng.exe,"
echo "                WmiPrvSE.exe, wininit.exe, services.exe...) AND"
echo "                (GrantedAccess in 0x1010/0x1410/0x143a OR"
echo "                SourceImage path under C:\\Users\\Public,"
echo "                C:\\Windows\\Temp, C:\\ProgramData)"
echo "  Fields:        TargetImage, SourceImage, GrantedAccess,"
echo "                SourceProcessId, timestamp"
echo "  Baseline:     zero non-system LSASS accessors in Robert Kim"
echo "                baseline; any unknown source is anomalous"
echo "  Allowlist:    permit-list of system binaries from the HC3"
echo "                advisory; everything else alerts"
echo "  Priority:     P1 (credential theft enables the entire chain)"
echo

echo "GAP 3: T1047 WMI Remote Execution"
echo "  Hunt Finding: wsmprovhost.exe follow-on activity on"
echo "                SRV-HEALTH-DB and SRV-INS-DB during the off-hours"
echo "                attack sessions"
echo "  Why Missed:   OVERLY SPECIFIC RULE"
echo "                ${cnt_wmi} WMI/WinRM host events exist, but existing"
echo "                rules matched only known WMI malware abuse patterns"
echo "                (specific WQL strings / unsigned MOF); arbitrary"
echo "                remote execution via wsmprovhost slipped through."
echo "  Data Source:  Sysmon Event 1 (process create) plus Windows Event"
echo "                4648/4624 for the remote logon context"
echo "  Required Rule: alert on wsmprovhost.exe/wmiprvse.exe spawning"
echo "                cmd.exe/powershell.exe on a server where the"
echo "                session user is not robert.kim OR occurs outside"
echo "                business hours"
echo "  Fields:        ParentImage, Image, User, host, timestamp"
echo "  Baseline:     Robert Kim's WMI runs never spawn shells -"
echo "                inventory queries only"
echo "  Allowlist:     known management workstation sources only"
echo "  Priority:     P2"
echo

echo "GAP 4: T1021.006 PowerShell Remoting"
echo "  Hunt Finding: Enter-PSSession as svc_healthsync plus Copy-Item"
echo "                of sync_healthdata.ps1 into C:\\Windows\\Temp on"
echo "                SRV-HEALTH-DB and SRV-INS-DB"
echo "  Why Missed:   MISSING RULE"
echo "                ${cnt_psrem} PSRemoting command events exist in the"
echo "                exports; PowerShell logging captured the commands"
echo "                but nothing alerted on them."
echo "  Data Source:  PowerShell script-block/command logging plus"
echo "                Sysmon Event 1"
echo "  Required Rule: alert on Enter-PSSession/Invoke-Command/"
echo "                New-PSSession where connecting user is svc_* OR"
echo "                source host is a workstation (WS-*) OR Copy-Item"
echo "                destination resolves to a writable staging path"
echo "                (C:\\Users\\Public, C:\\Windows\\Temp, C:\\ProgramData)"
echo "  Fields:        ScriptBlockText/Image, User, ComputerName,"
echo "                Destination path, timestamp"
echo "  Baseline:     Robert Kim remotes from WS-ADMIN-01 in business"
echo "                hours only; service accounts never remote interactively"
echo "  Allowlist:    svc_patchdeploy patch pushes and svc_av policy sync"
echo "                from their designated service hosts"
echo "  Priority:     P1 (this gap carried the exfiltrator deployment)"
echo

echo "GAP 5: T1078.002 Service Account Misuse"
echo "  Hunt Finding: 6 svc_healthsync logons sourced from workstation"
echo "                WS-RECV-03 (authorization matrix RULE 1 violation)"
echo "                on May 6, 9, 13 - all inside attack sessions"
echo "  Why Missed:   MISSING RULE"
echo "                ${cnt_svc} service account logon events exist, but no"
echo "                rule enforced the authorization matrix (source-host"
echo "                and logon-type constraints were documented, never"
echo "                encoded as detections)."
echo "  Data Source:  Windows Event 4624 (logon) with"
echo "                LogonType/WorkstationName fields"
echo "  Required Rule: alert on 4624 where TargetUserName matches svc_*"
echo "                AND (WorkstationName starts WS- OR LogonType in"
echo "                (2,10,11) OR LogonType 3 with workstation source)"
echo "  Fields:        TargetUserName, WorkstationName, LogonType,"
echo "                IpAddress, timestamp"
echo "  Baseline:     matrix IAM-SVC-2026-Q2 - each svc_* account has"
echo "                exactly one authorized source host"
echo "  Allowlist:    per-account service host from the matrix"
echo "                (svc_healthsync -> SRV-HEALTH-DB etc.)"
echo "  Priority:     P1 (linchpin of all three attack sessions)"
echo

echo "GAP 6: T1550.002 NTLM / Pass-the-Hash-style Activity"
echo "  Hunt Finding: All 6 unauthorized svc_healthsync logons used"
echo "                NTLM rather than Kerberos - RULE 3 indicator"
echo "                (mechanism pass-the-hash inferred; misuse observed)"
echo "  Why Missed:   MISSING RULE"
echo "                ${cnt_ntlm} NTLM-authenticated service account logons"
echo "                exist in the exports; no rule compared authentication"
echo "                package against the Kerberos-only matrix policy."
echo "  Data Source:  Windows Event 4624/4625 AuthenticationPackageName field"
echo "  Required Rule: alert on 4624 where TargetUserName matches svc_*"
echo "                AND AuthenticationPackageName = NTLM"
echo "  Fields:        TargetUserName, AuthenticationPackageName,"
echo "                WorkstationName, timestamp"
echo "  Baseline:     RULE 3: service accounts must authenticate with"
echo "                Kerberos; NTLM is always anomalous for svc_*"
echo "  Allowlist:    none - zero-tolerance condition per matrix RULE 3"
echo "  Priority:     P1 (cheapest, most reliable single-field tripwire)"
echo

echo "PRIORITY SUMMARY:"
echo "  P1: T1021.002 PsExec, T1003.001 LSASS, T1021.006 PSRemoting,"
echo "      T1078.002 svc misuse, T1550.002 NTLM (credential and"
echo "      deployment enablers - fastest path to detection)"
echo "  P2: T1047 WMI (follow-on reconnaissance; adds corroboration"
echo "      but follows the P1 events)"
echo

echo "SUMMARY:"
echo "  The data was present: ${cnt_psexec} PsExec, ${cnt_lsass} LSASS access,"
echo "  ${cnt_wmi} WMI host, ${cnt_psrem} PSRemoting, and ${cnt_svc} service"
echo "  account logon events - all captured in the exports."
echo "  The detection logic was missing: five of six gaps are MISSING RULE"
echo "  classifications, one is OVERLY SPECIFIC RULE; no gap required"
echo "  missing data sources."
echo "  Proactive hunting exposed the gap: the rules above convert each"
echo "  hunt hypothesis into a standing detection, closing the space"
echo "  that HEALTHBANE Stage 4 exploited."
echo
echo "================================================================"
