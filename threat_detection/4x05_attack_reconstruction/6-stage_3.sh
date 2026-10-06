#!/bin/bash
# Name: 6-stage_3.sh
# Purpose: Reconstruct Stage 3 of the HEALTHBANE attack (malware
#          deployment and capability establishment) using correlated
#          evidence from 4x03 malware analysis, 4x00 email evidence,
#          4x01 network forensics, and IR memory/disk/firewall
#          evidence. Documents the deployment timeline per component,
#          maps 4x03-sandboxed capabilities against observed MedDefense
#          usage, and assesses operational tempo across the Stage 2->3
#          transition. Builds on the outputs of 0-evidence_index.sh,
#          1-memory_analysis.sh, 2-disk_analysis.sh, 3-firewall_analysis.sh
#          and 4-correlation_matrix.sh.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

P0="previous_findings/4x00_phishing_summary.txt"
P1="previous_findings/4x01_network_timeline.txt"
P2="previous_findings/4x02_attack_mapping.json"
P3="previous_findings/4x03_malware_summary.txt"
IOCM="reference/healthbane_ioc_master.json"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$P0" "$P1" "$P2" "$P3" "$IOCM" "$MEM" "$DSK" "$FWJ"; do
  [[ -f "$f" ]] || die "missing $f"
done

# Gates: tokens verified present in the source files (per tasks 0-4 runs).
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$P0" "dmarsh"
req "$P1" "185.220.101.45"
req "$P3" "HEALTHBANE_S2_invoice.docm"
req "$P3" "svchost_update"
req "$P3" "RC4"
req "$IOCM" "sync_healthdata.ps1"
req "$MEM" "2026-04-22"
req "$DSK" "HealthSync Update Service"
req "$DSK" "01:47:33"
req "$DSK" "staging_export_001.zip"
req "$FWJ" "203.0.113.47"

cat <<'HEADER'
================================================================
   ATTACK RECONSTRUCTION: Stage 3
   Malware Deployment and Capability Establishment
   Dependencies: 0-evidence_index.sh (inventory),
                 4-correlation_matrix.sh (correlation baseline)
================================================================

STAGE DEFINITION AND RECONCILIATION:
  This task defines Stage 3 as tool deployment: dropper (Apr 15)
  through exfiltrator first staged output (May 8). Task 5's summary
  marked May 7 as the Stage 2/3 boundary under a phase-centric
  (access/credential/lateral) model. The two models overlap May 4-8:
  credential-access preparation (Defender exclusion May 4, LSASS
  dump May 5) interleaves with late Stage-3 tooling (scheduled task
  May 7, first exfil wave May 8). Both readings are retained; no
  evidence is affected, only the grouping convention.

DEPLOYMENT TIMELINE:

  2026-04-15T08:43:18Z       Dropper delivered (HEALTHBANE_S2_invoice.docm)
    Delivery: email attachment released from quarantine (4x01
              mail-flow observation; 4x00 established the recipient
              pool was the same campaign audience)
    Evidence: 4x03 (sample S1 analysis), 4x01 (quarantine release +
              HTTP download chain), 4x00 (campaign context)
    Technique: T1566.001 (delivery) -> T1203 Exploitation for Client
              Execution (VBA macro) -> T1204.002 User Execution:
              Malicious File
    Confidence: CONFIRMED (mail-flow + sample analysis + sandbox
              behavioral chain)

  2026-04-15T08:51:11Z       RAT downloaded (svchost_update.exe)
    Delivery: dropper macro fetches from update.healthbane-c2.net
              (4x01 PCAP HTTP GET; dropper chain verified in 4x03
              sandbox: XOR-0x37 + base64 deobfuscation, T1027)
    Evidence: 4x01 (URL + download), 4x03 (S2 sample = same hash)
    Technique: T1105 Ingress Tool Transfer, T1027 Obfuscated Files
              or Information
    Confidence: CONFIRMED (PCAP + hash match)

    NOTE ON THE APR 15 FIRST BEACON (08:51:38Z): the 4x01 PCAP
    covers the ENTIRE VLAN-3 SPAN, not WS-RECV-03 alone. Host-side
    evidence (memory boot window, disk BORN times) places first
    WS-RECV-03 execution at Apr 22. The Apr 15 beacon is therefore
    CAMPAIGN-LEVEL evidence (some VLAN-3 host beaconed -- possibly
    a transient execution before this host's infection took hold,
    possibly another victim), not confirmed WS-RECV-03 activity.
    Attributing it to WS-RECV-03 would contradict the forensic
    image; the reconstruction does not assert that join.

  2026-04-22T06:14:17Z       RAT first host-side execution + persistence
    (PID 3712 start within boot window 06:14:17Z; binary BORN
    06:14:38Z; Run-key HealthSync last write 06:14:47Z -- a 30-second
    install-to-persistence sequence)
    Evidence: 4x03 (S2 behavioral indicators: APPDATA copy + Run-key
              write), IR-MEM (PID 3712, forged PPID, RWX region),
              IR-DSK (F1 BORN time, R1 Run-key, prefetch)
    Technique: T1547.001 Boot or Logon Autostart Execution,
              T1055 Process Injection (PPID forgery)
    Confidence: CONVERGED (4x03 behavioral prediction + memory +
              disk, 3 sources; task 4 matrix)
    Note: inside the 16-day network blind spot (Apr 16 - May 02);
          the 7-day download-to-execution gap is unexplained by any
          source (user document-open delay vs attacker scheduling).

  ~2026-04-30              Exfiltration script deployed (sync_healthdata.ps1)
    (date per IOC-master first-seen / 4x03 analysis association;
    within the network blind spot -- no PCAP or firewall visibility.
    Local staging copy persisted on WS-RECV-03 per disk F5; the
    server-side variant stage1.ps1 reached SRV-HEALTH-DB on May 6
    02:36 CDT via admin-share Copy-Item per the $MFT timeline.)
    Evidence: 4x03 (S3 sample analysis), IOC master (first-seen
              association), IR-DSK (F5 allocated copy; $MFT for
              stage1.ps1 drop May 6), IR-MEM (heap config residue)
    Technique: T1059.001 PowerShell (script-based tooling)
    Confidence: PROBABLE for the Apr 30 delivery date (single-source
              association, blind-spot window); CONFIRMED for
              deployment itself (disk + memory artifacts)

  2026-05-04T18:11 CDT      Defense-evasion prep (Defender exclusion,
                            C:\Windows\Temp) -- bridges Stage 3/4
    Evidence: IR-MEM (K5, records03 SID), IR-DSK (R3, registry
              last-write), IR-NOTES (Robert Kim claim DISPUTED and
              contradicted by SID evidence)
    Technique: T1562.001 Impair Defenses
    Confidence: CONFIRMED (2 forensic sources; memory task 1)
    Note: precedes the first LSASS dump by ~9h -- tool-deployment
          prerequisite, hence its placement in this stage's timeline.

  2026-05-07T06:47:33Z       Redundant persistence + exfil automation
    (scheduled task "HealthSync Update Service", daily 02:00 CDT
    trigger, hidden, HighestAvailable; executes the encoded
    fetch-config-then-run-exfiltrator chain)
    Evidence: IR-MEM (TaskCache K2), IR-DSK (task XML + schtasks
              prefetch to the second), IR-FW (secondary C2 +38s)
    Technique: T1053.005 Scheduled Task/Job, T1027.010 Command
              and Scripting Interpreter Obfuscation (EncodedCommand)
    Confidence: CONFIRMED (3 sources)

  2026-05-08T07:38:14Z       First exfiltrator output (EXFIL BURST 1:
                            14 219 484 B, staging_export_001.zip,
                            47 138 patient rows)
    Evidence: IR-DSK (D1 lifecycle: create 02:36, read, delete 02:38
              CDT; byte count in $MFT), IR-FW (session bytes EXACT
              match), hb_cfg.json (clear_logs:true, channel c2_post)
    Technique: T1005 / T1074.001 / T1560.001 / T1041
    Confidence: CONFIRMED (byte-exact, two independent measurement
              systems -- strongest correlation in the campaign)
    Placement: the task's FIRST staged output marks the end of
              Stage 3 (capability established); the May 8-13 exfil
              waves themselves belong to Stage 4/impact treatment.

CAPABILITY ASSESSMENT (4x03 sandbox vs observed MedDefense usage):

  Component    Capability                Used at MedDefense?  Evidence
  ------------ -------------------------- -------------------- ---------------
  Dropper      Macro execution chain     YES                  4x01 download
                                                             chain + 4x03
  Dropper      XOR-0x37 + base64         YES (implied by      4x03 (analysis);
               deobfuscation              delivery success)    4x01 (PCAP)
  Dropper      PersistViaTask branch     YES                  IR-MEM K2 +
                                        (CORRECTED: 4x03       IR-DSK task XML
                                         marked UNCONFIRMED)   (May 7)
  RAT          C2 beacon + RC4 channel   YES                  IR-FW 3 958
                                                             sessions; IR-MEM
                                                             PID 3712
  RAT          Run-key persistence       YES                  IR-DSK R1,
                                                             IR-MEM K1
  RAT          Process hollowing /       YES                  IR-MEM (forged
               PPID forgery                                    PPID, RWX)
  RAT          Keylogger (gated)         NO                   4x03 sandbox
                                                             only; no
                                                             keystroke/log
                                                             artifacts in
                                                             IR-MEM or IR-DSK
  RAT          Cookie harvest (gated)    NO                   4x03 sandbox
                                                             only; no
                                                             browser-target
                                                             artifacts in IR
  RAT          'drop' verb (file push)   PROBABLE             config residue
                                                             (cmd set);
                                                             debug_tool.exe /
                                                             PsExec64.exe
                                                             arrival has no
                                                             other evidenced
                                                             mechanism, but
                                                             no PCAP-era
                                                             capture of the
                                                             pushes
  Exfiltrator  c2_post channel           YES                  hb_cfg.json
                                                             (memory + disk);
                                                             IR-FW byte-exact
  Exfiltrator  dns_chunk channel         NO (TESTED only)    4x01 T-150/T-151
                                                             DNS exfil TEST
                                                             pings (capability
                                                             test, not bulk);
                                                             actual waves all
                                                             c2_post
  Exfiltrator  SRV-HEALTH-DB SQL         YES                  4x03 template;
               template (health_records                       D1 contents
               dbo.patients)                                  match
  Exfiltrator  clear_logs gate            YES                  hb_cfg.json
                                                             true + May 9
                                                             evtx gap
  Exfiltrator  Script self-deletion      YES                  IR-DSK D-series
                                                             lifetimes;

  Net effect: of the 4x03 capability matrix, the attacker used the
  core chain (dropper -> RAT persistence -> scheduled-task-triggered
  exfiltration) and NONE of the optional surveillance capabilities
  (keylogger, cookies). Data-theft objective, not espionage-grade
  monitoring -- consistent with financially motivated intrusion.

STAGE 2 -> STAGE 3 TRANSITION (operational tempo):

  Dropper quarantine release -> RAT download:      8 minutes
    (2026-04-15 08:43:18Z -> 08:51:11Z; automated macro chain)

  RAT download -> RAT first host-side execution:   ~7 days
    (Apr 15 -> Apr 22; cause not determinable; blind spot)

  RAT execution -> first lateral movement:        ~14 days
    (Apr 22 -> May 6; includes tool-build time: Defender
    exclusion May 4, LSASS dump May 5)

  First lateral movement -> first exfil burst:    ~2 days
    (May 6 -> May 8; automated via scheduled task)

  Assessment: PATIENT, MULTI-WEEK operational tempo. The 8-minute
  automated delivery chain contrasts with multi-day dwell intervals
  between phases, all attacker actions clustered 01:00-04:00 CDT
  (task 3 temporal analysis: zero business-hours external activity).
  This profile indicates MANUAL operator-driven staging with
  AUTOMATED tooling at each step -- not an automated smash-and-grab,
  and not opportunistic malware. The redundancy pattern (dual
  persistence, secondary C2 provisioned with the task, diverse
  hosting providers) further indicates planned, sustained operations.

STAGE 3 TECHNIQUES (with citations):
  T1566.001  Spearphishing Link (delivery)     CONFIRMED  4x00/4x01
  T1203      Exploit for Client Exec (VBA)     CONFIRMED  4x03/4x01
  T1204.002  User Exec: Malicious File         CONFIRMED  4x01/4x03
  T1027      Obfuscated Files                  CONFIRMED  4x03 (XOR/base64)
  T1027.010  Command Obfuscation (b64)         CONFIRMED  IR-MEM/IR-DSK
  T1105      Ingress Tool Transfer             CONFIRMED  4x01 (RAT fetch)
                                                        PROBABLE (later drops)
  T1547.001  Boot/Logon Autostart (Run-key)    CONFIRMED  IR-MEM/IR-DSK
  T1053.005  Scheduled Task/Job                CONFIRMED  IR-MEM/IR-DSK/IR-FW
  T1055      Process Injection                 CONFIRMED  IR-MEM
  T1059.001  PowerShell                        CONFIRMED  IR-MEM/IR-DSK
  T1573.001  Encrypted Channel (RC4/HTTPS)     CONFIRMED  4x03/4x01/IR-FW
  T1562.001  Impair Defenses (Defender excl.)  CONFIRMED  IR-MEM/IR-DSK
  T1005      Data from Local System            CONFIRMED  IR-DSK (D1/D2/D3)
  T1074.001  Local Data Staging                CONFIRMED  IR-DSK/IR-FW
  T1560.001  Archive Collected Data            CONFIRMED  IR-DSK/IR-FW
  T1071.004  DNS (exfil channel)               TESTED ONLY 4x01 (T-150/T-151);
                                                        NOT used for bulk
  T1059.003  Cmd Shell                         CONFIRMED  IR-DSK (prefetch)

  Corrections to 4x03 carried forward: PersistViaTask branch and
  S3 execution upgraded UNCONFIRMED -> OBSERVED (IR corroboration).

UNRESOLVED (not asserted):
  - Exact delivery timestamp of sync_healthdata.ps1 (Apr 30 date is
    an IOC-master association inside the network blind spot; no
    packet capture or firewall session witnessed the transfer).
  - Delivery mechanism for debug_tool.exe and PsExec64.exe onto
    WS-RECV-03 (RAT 'drop' verb is the likely mechanism but no
    direct capture exists).
  - Attribution of the Apr 15 first beacon (VLAN-3-wide SPAN; host
    unknown).
  - Cause of the 7-day RAT download-to-execution delay.

================================================================
HEADER

echo "Script execution complete. Stage 3 reconstruction generated."
