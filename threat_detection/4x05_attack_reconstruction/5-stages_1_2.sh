#!/bin/bash
# Name: 5-stages_1_2.sh
# Purpose: Reconstruct Stages 1-2 of the HEALTHBANE attack (Initial Access
#          through C2 Establishment) using correlated evidence from the
#          phishing investigation, network forensics, intelligence analysis,
#          and incident response firewall data. Integrates findings from
#          Task 0 (inventory), Task 1 (memory), Task 2 (disk), Task 3
#          (firewall), and Task 4 (correlation matrix). References
#          0-evidence_index.sh and 4-correlation_matrix.sh for source
#          validation and technique-mapping consistency.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

P0="previous_findings/4x00_phishing_summary.txt"
P1="previous_findings/4x01_network_timeline.txt"
P2="previous_findings/4x02_attack_mapping.json"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
CORR="4-correlation_matrix.sh"
INDEX="0-evidence_index.sh"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$P0" "$P1" "$P2" "$FWJ" "$MEM" "$DSK"; do
  [[ -f "$f" ]] || die "missing $f"
done

# Gates anchoring narrative claims to source evidence.
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$P0" "dmarsh"
req "$P0" "credential submission"
req "$P0" "13:18:42"
req "$P1" "beacon"
req "$P1" "08:51"
req "$P1" "185.220.101.45"
req "$FWJ" "185.220.101.45"
req "$FWJ" "203.0.113.47"
req "$MEM" "2026-04-22"
req "$DSK" "HealthSync Update Service"
req "$DSK" "01:47:33"

[[ -f "$CORR" ]] || echo "WARNING: $CORR not found; technique updates may need manual review."
[[ -f "$INDEX" ]] || echo "WARNING: $INDEX not found; coverage gaps not re-verified."

cat <<'HEADER'
================================================================
   ATTACK RECONSTRUCTION: Stages 1-2
   Initial Access through C2 Establishment
   Dependencies: 0-evidence_index.sh (inventory), 4-correlation_matrix.sh (matrix)
================================================================

STAGE 1: INITIAL ACCESS (Phishing Campaign)
  Timeline: Week 11 (campaign active 2026-04-14 to 2026-04-21)

  2026-04-14 (intraday)      Campaign emails delivered to MedDefense staff
    Evidence: 4x00 email batch analysis (8 emails analyzed, 3 confirmed
              malicious: portal password reset, HR benefits, M365 quota
              lures; lookalike domains with SPF Hardfail / DKIM Missing /
              DMARC Fail)
    Technique: T1566.001 Spearphishing Link
    Confidence: CONFIRMED (primary mail-header evidence from 4x00)

  2026-04-14T13:18:42Z       dmarsh credential submission on WS-RECV-03
                              (POST to lookalike portal; this is the
                              temporal anchor -- the exact click time is
                              not recorded in the package evidence)
    Evidence: 4x00 (user report + lookalike-domain analysis),
              4x01 (PCAP POST request to the lookalike domain)
    Technique: T1078 Valid Accounts (credentials obtained via phishing)
    Confidence: CONVERGED (2 independent sources: 4x00 email, 4x01 network)
    Impact: AD password rotation at 13:20Z per 4x00. The "17-minute
            window" figure is 4x00's own accounting (likely measured
            report-to-rotation; raw mail-server and DC logs are not in
            the package -- do not over-precise this interval).

  2026-04-15T08:43:18Z       Quarantine release of Stage 2 dropper email
    Evidence: 4x01 Network Timeline (invoice docm released from
              quarantine; HEALTHBANE_S2_invoice.docm)
    Technique: T1566.001 Spearphishing Link (second vector)
    Confidence: CONFIRMED (4x01 PCAP mail-flow observation)
    Note: First successful delivery of malware (macro-enabled document),
          24h after the credential submission.

STAGE 2: C2 ESTABLISHMENT
  Timeline: 2026-04-15 to 2026-05-07 (core channel Apr 15-22; the
            May 7 entries below conclude Stage 2 and straddle the
            Stage 2/3 boundary -- see Stage 1-2 Summary)

  2026-04-15T08:51:11Z       RAT download initiated
    Evidence: 4x01 PCAP (HTTP download via update.healthbane-c2.net)
              File: svchost_update.exe (dropped by the docm macro)
    Technique: T1105 Ingress Tool Transfer
    Confidence: CONFIRMED (PCAP URL + file-hash match to 4x03 S2)

  2026-04-15T08:51:38Z       First C2 beacon observed (primary channel)
    Evidence: 4x01 PCAP (TLS session to 185.220.101.45:443 via
              update.healthbane-c2.net). NOTE: the DNS exfil TEST
              pings (T-150/T-151) to 185.220.101.46 are a separate
              4x01 observation, NOT the beacon channel.
              IR-FW (session metadata confirms continuous 5-min
              beaconing to the same endpoint through the firewall
              export window; clock skew ~4s resolved per Task 0 D3
              -- firewall canonical for initiation, +/-5s join rule.
              The PCAP window ends 2026-04-16; the firewall export
              begins 2026-05-02 -- no single beacon appears in both,
              so this is pattern continuity, not a direct join.)
    Technique: T1071.001 Application Layer Protocol: Web
              T1573.001 Encrypted Channel (HTTPS / RC4 symmetric)
    Confidence: CONVERGED (PCAP + firewall metadata, pattern-level)
    Pattern: 5-minute beacon cadence, 3 958 sessions per firewall
             metadata, JA3 72a589da586844d7f0818ce684948eea.

  2026-04-22T06:14:17Z       RAT first execution on WS-RECV-03
    Evidence: IR-MEM (boot window 2026-04-22T06:14:17Z; PID 3712
              start), IR-DSK (F1 BORN 06:14:38Z; Run-key last write
              06:14:47Z)
    Technique: T1547.001 Registry Run Keys / Startup Folder
    Confidence: CONVERGED (memory boot window + disk persistence
              artifacts; note the 9-second creation-to-persistence
              sequence on disk)
    Note: Occurs within the 16-day network blind spot (Apr 16 - May 02).
          Retrospective evidence only (no PCAP/firewall visibility);
          7 days after the RAT download -- attacker-side delay or
          victim-side delay (document-open) not determinable from
          package evidence.

  2026-05-07T06:47:33Z       Persistent scheduled task created
  (01:47:33 CDT)               "HealthSync Update Service"
    Evidence: IR-MEM (TaskCache registry entry K2), IR-DSK (on-disk
              task XML at the same timestamp; schtasks prefetch
              run-time matches to the second), IR-FW (secondary C2
              first session 38 seconds later, see below)
    Technique: T1053.005 Scheduled Task/Job
    Confidence: CONFIRMED (memory + disk corroboration)

  2026-05-07T06:48:11Z       Secondary C2 channel first seen
                              (203.0.113.47:8443)
    Evidence: IR-FW (first session 06:48:11Z -- 38 seconds after task
              registration), IR-MEM (live ESTABLISHED socket held by
              PID 3712 at capture on May 15)
    Technique: T1571 Non-Standard Port
    Confidence: CONFIRMED (three-source correlation: memory + firewall
              + task-timing offset)
    Note: NOT operational during the April Stage 2 core period --
          first appearance May 7 indicates backup infrastructure
          deployed AFTER persistence was established. Not visible to
          4x01 PCAPs (collection ended Apr 16, before this channel
          existed).

STAGE 1-2 SUMMARY:
  Duration: 23 days from first credential submission (Apr 14) to
            redundant persistence (May 7). Core C2 channel dormant-to-
            active: Apr 15 (download/beacon-in-PCAP-era evidence) to
            Apr 22 (host-side first execution per boot-window artifacts).
  Stage boundary note: the May 7 scheduled task and secondary C2 close
            out Stage 2 and open Stage 3 (credential access and lateral
            movement begin May 4-5); they are included here because the
            reconstruction assigns them to "persistence redundancy."
  Techniques Mapped:
    Stage 1: T1566.001 (Spearphishing Link), T1078 (Valid Accounts)
    Stage 2: T1105 (Ingress Tool Transfer), T1071.001 (Web Protocol),
             T1573.001 (Encrypted Channel), T1547.001 (Run Key),
             T1053.005 (Scheduled Task), T1055 (Process Injection --
             PPID forgery observed in memory), T1571 (Non-Standard Port)
  IOCs Involved: 6 core (primary C2 IP, secondary C2 IP, C2 domain,
                 RAT hash, dmarsh account, WS-RECV-03 host)
                 Per Task 4 matrix: converged 5, single-source 1
                 (secondary C2 was single-source at discovery, since
                 confirmed by 3 IR sources; HealthSyncSingleton mutex
                 remains the only standing SINGLE-SOURCE indicator).
  Key Finding: Secondary C2 (203.0.113.47) was NOT operational during
            the April core of Stage 2. First appeared May 7, 38 seconds
            after scheduled-task registration -- suggesting the attacker
            provisioned backup infrastructure at the same session as
            establishing redundant persistence.
  Unresolved / not asserted:
            - Exact click time for the dmarsh phishing interaction
              (only the submission POST is evidenced).
              Whether dmarsh credentials were USED in the 17-minute
              pre-rotation window (Task 0 Q7): no evidence either way.
            - Cause of the 7-day download-to-execution delay (Apr 15 ->
              Apr 22).
  Clock skew: ~4s variance between PCAP and firewall clocks resolved
            per Task 0 D3 (firewall canonical for connection
            initiation; +/-5s join tolerance; observation windows do
            not overlap).

================================================================
HEADER

echo "Script execution complete. Reconstruction output generated."
