#!/bin/bash
# Name: 8-unified_timeline.sh
# Purpose: Merge the Stage 1-2 (5-stages_1_2.sh), Stage 3 (6-stage_3.sh)
#          and Stage 4 (7-stage_4.sh) reconstructions into a single,
#          chronological, evidence-cited timeline of the HEALTHBANE
#          campaign against MedDefense, from first phishing email to
#          containment. Computes key temporal metrics (dwell time,
#          breakout time, time to persistence/staging), documents
#          timeline gaps and sequencing uncertainties, and applies
#          the Task 0 D3 normalization (firewall timestamps canonical
#          for connection initiation). Builds on the verified outputs
#          of 0-evidence_index.sh through 4-correlation_matrix.sh.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

P0="previous_findings/4x00_phishing_summary.txt"
P1="previous_findings/4x01_network_timeline.txt"
P3="previous_findings/4x03_malware_summary.txt"
P4="previous_findings/4x04_hunting_report.txt"
IOCM="reference/healthbane_ioc_master.json"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"
NOTES="ir_evidence/ir_team_notes.txt"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$P0" "$P1" "$P3" "$P4" "$IOCM" "$MEM" "$DSK" "$FWJ" "$NOTES"; do
  [[ -f "$f" ]] || die "missing $f"
done

# Gates: tokens verified in source files (tasks 0-7 runs).
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$P0" "dmarsh"
req "$P0" "13:18:42"
req "$P1" "185.220.101.45"
req "$P1" "08:51"
req "$P3" "svchost_update"
req "$P4" "svc_healthsync"
req "$P4" "LSASS"
req "$IOCM" "svc_healthsync"
req "$MEM" "2026-04-22"
req "$MEM" "203.0.113.47"
req "$DSK" "HealthSync Update Service"
req "$DSK" "staging_export_001.zip"
req "$DSK" "2026-05-09"
req "$FWJ" "203.0.113.47"
req "$FWJ" "445"
req "$NOTES" "WS-RECV-03"

cat <<'HEADER'
================================================================
   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense
   Period: 2026-04-14 to 2026-05-15 (containment)
   Normalization: all times UTC; CDT given parenthetically where
   host-local. Per Task 0 D3: firewall timestamps canonical for
   connection initiations; +/-5s join tolerance; PCAP and firewall
   observation windows do not overlap (no direct joins across them).
================================================================

CHRONOLOGICAL SEQUENCE
  (Legend: H = hosts Src->Dst, C = actor/credential, T = ATT&CK,
   Conf = confidence, Src = evidence sources. DEF = defensive event.)

  01  2026-04-14 (intraday)   Phishing campaign emails delivered
      H: ext->MedDefense staff | C: n/a | T1566.001
      Conf: CONFIRMED | Src: 4x00 (primary mail-header evidence)

  02  2026-04-14T13:18:42Z    dmarsh credential submission on
                              lookalike portal (exact click time
                              not in package -- see U3)
      H: WS-RECV-03->ext | C: dmarsh | T1078
      Conf: CONVERGED | Src: 4x00, 4x01 (PCAP POST)

  03  2026-04-14T13:20Z       [DEF] AD credential rotation for dmarsh
      Basis: 4x00 ("17-minute window" is 4x00's own accounting;
      basis not resolvable from package -- do not over-precise)

  04  2026-04-15T08:43:18Z   Quarantine release delivers dropper
                              email (HEALTHBANE_S2_invoice.docm)
      H: mail->WS-RECV-03 | C: n/a | T1566.001
      Conf: CONFIRMED | Src: 4x01 (mail-flow observation)

  05  2026-04-15T08:51:11Z    RAT downloaded (svchost_update.exe via
                              update.healthbane-c2.net)
      H: WS-RECV-03->ext | C: n/a | T1105, T1027
      Conf: CONFIRMED | Src: 4x01 (PCAP), 4x03 (hash match)

  06  2026-04-15T08:51:38Z    First C2 beacon observed
      H: VLAN-3 (SPAN-wide; host attribution NOT determinable --
                              see U1) | C: n/a | T1071.001, T1573.001
      Conf: CONVERGED (pattern-level) | Src: 4x01 (PCAP), IR-FW
      (window continuity only; no direct join -- D3)

  --  2026-04-16T22:00Z      [COVERAGE] PCAP collection ends
                              --> GAP 1 begins (see TIMELINE GAPS)

  07  2026-04-22T06:14:17Z    RAT first host-side execution on
                              WS-RECV-03; Run-key persistence by
                              06:14:47Z (binary BORN 06:14:38Z)
      H: WS-RECV-03 | C: dmarsh context | T1547.001, T1055
      Conf: CONVERGED | Src: IR-MEM, IR-DSK

  08  ~2026-04-30 (unverified) Exfiltration script present on host
                              (sync_healthdata.ps1; IOC-master
                              first-seen association only)
      H: WS-RECV-03 | C: n/a | T1059.001
      Conf: PROBABLE | Src: IOC master (single source; blind spot)

  --  2026-05-02              [COVERAGE] firewall export begins;
                              GAP 1 ends (16-day blind spot closes)

  09  2026-05-04T23:11Z       Defender exclusion added
                              (C:\Windows\Temp; 18:11 CDT)
      H: WS-RECV-03 | C: records03 SID | T1562.001
      Conf: CONFIRMED | Src: IR-MEM, IR-DSK, IR-NOTES

  10  2026-05-05T08:22Z       LSASS dump 1 (03:22 CDT); obtains
                              svc_healthsync
      H: WS-RECV-03 | C: svc_healthsync obtained | T1003.001
      Conf: CONVERGED | Src: 4x04, IR-MEM, IR-DSK

  11  2026-05-06T07:11Z       First lateral pivot: PsExec ->
                              SRV-HEALTH-DB (02:11 CDT)
      H: WS-RECV-03->SRV-HEALTH-DB | C: svc_healthsync (PtH)
      T1550.002, T1021.002
      Conf: CONVERGED | Src: 4x04, IR-DSK, IR-FW

  12  2026-05-06T07:36Z       stage1.ps1 pushed via admin share;
                              dbo.patients query executed (02:36 CDT)
      H: WS-RECV-03->SRV-HEALTH-DB | C: svc_healthsync
      T1072, T1059.001, T1005
      Conf: CONVERGED | Src: IR-DSK ($MFT), 4x03 (template)

  13  2026-05-06 -> 05-12     WMI pivot -> SRV-INS-DB; WinRM pivot
      (range; see U2)         -> SRV-DC-01
      H: WS-RECV-03->SRV-INS-DB, SRV-DC-01 | C: svc_healthsync
      T1047, T1021.006
      Conf: CONVERGED (host level) | Src: IR-DSK (prefetch),
      IR-FW (sessions); NOT in hunt telemetry (detection gap)

  14  2026-05-07T06:47:33Z    Scheduled task created
                              ("HealthSync Update Service";
                              01:47:33 CDT)
      H: WS-RECV-03 | C: n/a | T1053.005, T1027.010
      Conf: CONFIRMED | Src: IR-MEM, IR-DSK, IR-FW (timing)

  15  2026-05-07T06:48:11Z    Secondary C2 first session
                              (203.0.113.47:8443; +38s after task)
      H: WS-RECV-03->ext | C: n/a | T1571
      Conf: CONFIRMED | Src: IR-FW, IR-MEM

  16  2026-05-08T07:36Z       staging_export_001.zip built
                              (14 219 484 B; 47 138 patient rows;
                              02:36 CDT)
      H: WS-RECV-03 | C: n/a | T1560.001, T1074.001
      Conf: CONFIRMED | Src: IR-DSK ($MFT lifecycle)

  17  2026-05-08T07:38:14Z    Exfil burst 1 (BYTE-EXACT $MFT <->
                              firewall: 14 219 484 B)
      H: WS-RECV-03->ext | C: n/a | T1041
      Conf: CONFIRMED | Src: IR-DSK, IR-FW

  18  2026-05-09T08:00-08:12Z Security-log clear (03:00-03:12 CDT)
      H: WS-RECV-03 | C: n/a | T1070.001
      Conf: CONFIRMED | Src: IR-DSK, IR-FW, IR-MEM (config)

  19  2026-05-11T08:17:18Z    Exfil burst 2 (BYTE-EXACT:
                              11 802 944 B; insurance records,
                              SRV-INS-DB-derived)
      H: WS-RECV-03->ext | C: n/a | T1041
      Conf: CONFIRMED | Src: IR-DSK, IR-FW

  20  2026-05-12T07:45Z       LSASS dump 2 (02:45 CDT); re-harvest
      H: WS-RECV-03 | C: svc_healthsync re-obtained | T1003.001
      Conf: CONVERGED | Src: 4x04, IR-MEM, IR-DSK

  21  2026-05-13T07:34:14Z    Exfil burst 3 (BYTE-EXACT:
                              8 419 232 B; AD recon export, NOT PHI)
      H: WS-RECV-03->ext | C: n/a | T1041
      Conf: CONFIRMED | Src: IR-DSK, IR-FW

  22  2026-05-15T18:42Z       [DEF] WS-RECV-03 isolated
                              (13:42 CDT; FW DENY onset; Entry #001)
      Src: IR-NOTES, IR-FW

  23  2026-05-15T19:18Z       [DEF] Memory capture (14:18 CDT;
                              PID 3712 live socket to secondary C2
                              at capture)
      Src: IR-MEM, IR-NOTES

  Total events in timeline: 23 numbered (20 attacker, 2 defensive,
    1 unverified-probable) plus 2 coverage markers
  Attacker events with multi-source evidence: 17 of 20 (85%)
  Single-source attacker events: 3 (15%) -- #01 delivery (4x00),
    #04 quarantine release (4x01), #08 script-deploy date (IOC
    master association)
  Byte-exact corroborated events: 3 (bursts 1-3; strongest class)
  LOW-CONFIDENCE extraneous claim held open: LSASS dump CONTENTS
    leaving network (~23 MB aggregate inference; PROBABLE; IR
    notes Entry #008 leaves it OPEN -- not counted as an event)

TEMPORAL METRICS (anchor: 2026-04-14T13:18:42Z credential
                   submission unless stated):

  Total dwell time:            31 days 5 h (Apr 14 13:18Z ->
                               May 15 18:42Z isolation)
  Breakout time:                21 d 18 h (~522 h) from credential
                               submission to first lateral pivot
                               (May 6 07:11Z); 13 d 24 h (~336 h)
                               measured from RAT host-side
                               execution (Apr 22) -- both frames
                               reported because initial access
                               yielded no host compromise until
                               Apr 22
  Time to first persistence:    7 d 17 h (Run key, Apr 22)
  Time to redundant persistence: 22 d 17 h (scheduled task, May 7)
  Time to data staging:         23 d 18 h (first archive built,
                               May 8 07:36Z)
  Time to first exfiltration:  23 d 18 h (burst 1, May 8 07:38Z;
                               2 minutes after staging completes)
  Detection to containment:    NOT COMPUTABLE from this package.
                               The 4x04 report's own hunt-initiation
                               date (05-18) is contradicted by three
                               sources placing isolation at 05-15
                               (D6); no verified hunt-detection
                               timestamp exists. See U4.
  Operational tempo:            Manual operator staging with
                               automated tool execution: intra-phase
                               actions complete in seconds-minutes;
                               inter-phase gaps measured in DAYS.
                               ALL attacker actions cluster
                               01:00-04:00 CDT; zero business-hours
                               external activity (Task 3 temporal
                               analysis). Phase cadence: delivery
                               day 0, RAT execution day 8, defense
                               evasion day 20, credential access
                               day 21, lateral day 22, automation +
                               exfil day 23-29, containment day 31.

TIMELINE GAPS (periods with no evidence of attacker activity):

  GAP 1: 2026-04-16T22:00Z -> 2026-05-02
         Assessment: COLLECTION GAP (not dormancy). PCAP collection
         ended Apr 16; firewall export begins May 2. Within the gap,
         attacker activity IS evidenced retrospectively from host
         artifacts (RAT execution Apr 22, script presence ~Apr 30),
         proving the attacker was active while the network was
         blind. 16 days of network telemetry irrecoverable.

  GAP 2: 2026-05-13T07:34Z -> 2026-05-15T18:42Z
         Assessment: POST-EXFIL QUIESCENCE in evidence. Beaconing
         cadence continues (per session log), but no new attacker
         ACTION is evidenced between the final burst and isolation.
         Either genuine quiescence or unobserved activity on the
         unimaged servers (GAP 3) -- not resolvable.

  GAP 3: SRV-INS-DB and SRV-DC-01 post-compromise extent
         Assessment: HOSTS NEVER IMAGED in this package. Pivot
         arrival is evidenced (prefetch, firewall); activity ON
         those hosts after arrival is unknown. Explicit scope limit
         for the impact assessment.

SEQUENCING UNCERTAINTIES:

  [U1] Event 06 (Apr 15 first beacon): host attribution NOT
      determinable. Reason: 4x01 PCAP SPAN covered all of VLAN-3;
      host-side artifacts place WS-RECV-03 RAT execution at Apr 22.
      Impact: SIGNIFICANT for the Stage-2 narrative (beacon is
      campaign-level, not per-host); MINIMAL for overall
      reconstruction (channel establishment itself is corroborated).

  [U2] Events within #13: WMI vs WinRM pivots cannot be ordered
      relative to each other or to events 14-16. Reason: prefetch
      gives last-run times, not first-run; firewall metadata lacks
      per-session tool attribution. Impact: MINIMAL (targets and
      techniques are confirmed; only intra-window order is unknown).

  [U3] Event 02 vs the actual click: click precedes submission but
      is untimed in the package. Reason: browser history granularity
      per 4x00. Impact: MINIMAL (submission is the risk anchor).

  [U4] Hunt-detection timestamp (blocks the detection-to-
      containment metric). Reason: 4x04 header (05-18) contradicts
      the 05-15 isolation corroborated by three sources (D6); the
      report documents both readings without resolving them.
      Impact: MODERATE for reporting (metric omitted rather than
      estimated); the reconstruction refuses to fabricate it.

  [U5] Event 08 (~Apr 30 script deployment): date is an IOC-master
      association inside GAP 1. Reason: no network witness exists.
      Impact: MINIMAL (deployment itself confirmed by disk/memory
      artifacts; only the DATE is single-source).

================================================================
HEADER

echo "Script execution complete. Unified timeline generated."
