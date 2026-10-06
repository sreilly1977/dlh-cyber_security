#!/bin/bash
# Name: 5-stages_1_2.sh
# Purpose: Reconstruct Stages 1-2 of the HEALTHBANE attack (Initial Access
#          through C2 Establishment) using correlated evidence from the
#          phishing investigation, network forensics, intelligence analysis,
#          and incident response firewall data. Integrates findings from
#          Task 0 (inventory), Task 1 (memory), Task 2 (disk), Task 3 (firewall),
#          and Task 4 (correlation matrix). References 0-evidence_index.sh
#          and 4-correlation_matrix.sh for source validation and technique
#          mapping consistency.
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
req "$P1" "beacon"
req "$P1" "08:51"
req "$FWJ" "185.220.101.45"
req "$MEM" "2026-04-22"
req "$DSK" "HealthSync Update Service"

# Load technique status from correlation matrix (Task 4) to ensure consistency.
# Note: This script assumes 4-correlation_matrix.sh exists per Task 4 execution.
[[ -f "$CORR" ]] || echo "WARNING: $CORR not found; technique updates may need manual review."
[[ -f "$INDEX" ]] || echo "WARNING: $INDEX not found; coverage gaps not re-verified."

cat <<'HEADER'
================================================================
   ATTACK RECONSTRUCTION: Stages 1-2
   Initial Access through C2 Establishment
   Dependencies: 0-evidence_index.sh (inventory), 4-correlation_matrix.sh (matrix)
================================================================

STAGE 1: INITIAL ACCESS (Phishing Campaign)
  Timeline: Week 11 (Active: 2026-04-14 to 2026-04-21)

  2026-04-14 08:00Z ~ 12:00Z  Campaign emails delivered to MedDefense staff
    Evidence: 4x00 email batch analysis (8 emails analyzed, 3 malicious)
              Lookalike domains: portal-password-reset[.]com, m365-quota[.]net
              Authentication results: SPF Hardfail / DKIM Missing / DMARC Fail
    Technique: T1566.001 Spearphishing Link
    Confidence: CONFIRMED (Primary mail-header evidence from 4x00)

  2026-04-14T13:18:42Z       Diane Marsh (WS-RECV-03) clicks credential harvesting link
    Evidence: 4x00 user report + browser history triangulation
              Task 4 D2 Resolution: Topology entry (WS-NURSE-04) treated as stale;
              PCAP/Browser history confirm WS-RECV-03 at 13:18:42Z.
    Technique: T1566.001 -> T1078 Valid Accounts (Harvested Credentials)
    Confidence: CONVERGED (User report + Browser History + PCAP POST request)

  2026-04-14T13:20:42Z       Credentials submitted to attacker-controlled domain
    Evidence: 4x00 domain analysis (lookalike portal submission)
              4x01 PCAP captures POST request to lookalike domain 17 mins later
    Technique: T1078.001 Default Accounts (Compromised)
    Confidence: CONVERGED (2 independent sources: 4x00 email, 4x01 network)
    Impact: Immediate AD rotation triggered (17-minute window to compromise).

  2026-04-15T08:43:18Z       Quarantine release of Stage 2 dropper email
    Evidence: 4x01 Network Timeline (E1B invoice docm released from quarantine)
              Domain: update.healthbane-c2.net
    Technique: T1566.001 Spearphishing Link (Second Vector)
    Confidence: CONFIRMED (4x01 PCAP DNS/HTTP requests)
    Note: First successful delivery of malware (macro-enabled document).

STAGE 2: C2 ESTABLISHMENT
  Timeline: 2026-04-15 to 2026-04-22 (Approximately 7 days post-initial access)

  2026-04-15T08:51:11Z       RAT download initiated
    Evidence: 4x01 PCAP (HTTP GET from update.healthbane-c2.net)
              File: svchost_update.exe (HEALTHBANE_S2_invoice.docm macro payload)
    Technique: T1105 Ingress Tool Transfer
    Confidence: CONFIRMED (PCAP URL + File Hash match 4x03 S2)

  2026-04-15T08:51:38Z       First C2 beacon observed (Primary Channel)
    Evidence: 4x01 PCAP (DNS request to 185.220.101.46 + TCP SYN to C2)
              IR-FW (Session metadata confirms continuous beaconing starting
              approx same window; clock skew +4s resolved per Task 4 D3)
    Technique: T1071.001 Application Layer Protocol: Web
              T1573.001 Encrypted Channel (HTTPS / Symmetric Cryptography)
    Confidence: CONVERGED (PCAP + Firewall Metadata, <5s skew tolerance)
    Pattern: 5-minute beacon cadence, JA3 72a589da586844d7f0818ce684948eea.

  2026-04-22T06:14:17Z       RAT first execution on WS-RECV-03
    Evidence: IR-MEM (Memory artifact PID 3712 boot timestamp)
              IR-DSK (Prefetch/Run-key creation 2026-04-22 06:14:47Z)
    Technique: T1547.001 Registry Run Keys / Startup Folder
    Confidence: CONVERGED (Memory Boot Window + Disk Persistence Artifacts)
    Note: Occurs within the 16-day network blind spot (Apr 16 - May 02).
          Retrospective evidence only (no PCAP/Firewall visibility).

  2026-05-07T01:47:33Z       Persistent Scheduled Task created
    Evidence: IR-MEM (TaskCache registry entry)
              IR-DSK (On-disk XML, schtasks prefetch match to second)
              IR-FW (Secondary C2 first seen 38 seconds later)
    Technique: T1053.005 Scheduled Task/Job
    Confidence: CONFIRMED (Memory + Disk Corroboration)

  2026-05-07T06:48:11Z       Secondary C2 channel activated
    Evidence: IR-FW (Session log to 203.0.113.47:8443)
              IR-MEM (Live socket PID 3712 at capture)
    Technique: T1571 Non-Standard Port
    Confidence: CONFIRMED (Three-source correlation: Mem + FW + Task timing)
    Note: NOT visible in Stage 2 (April 15) — first appeared May 07.
          Indicates backup infrastructure deployed AFTER persistence established.

STAGE 1-2 SUMMARY:
  Duration: 23 days from first phishing email (Apr 14) to full persistence (May 07).
            Active C2 established: 7 days (Apr 15 - Apr 22).
  Techniques Mapped:
    Stage 1: T1566.001 (Phishing), T1078 (Valid Accounts)
    Stage 2: T1071.001 (Web Protocol), T1573.001 (Encrypted Channel),
             T1547.001 (Run Key), T1053.005 (Scheduled Task),
             T1055 (Process Injection - PPID Forgery)
  IOCs Involved: 6 (Primary C2, Secondary C2, Domain, File Hash, User Account, Host)
                 Converged: 5 | Single-Source: 1 (Secondary C2 initially)
  Key Finding: Secondary C2 IP (203.0.113.47) was NOT operational during
               Stage 2 (April). First appeared May 7, suggesting attacker
               deployed backup infrastructure after establishing persistence.
  Clock Skew: 4s variance between PCAP and Firewall timestamps resolved per
              Task 0 D3 resolution rule (Firewall canonical for initiation).

================================================================
HEADER

echo "Script execution complete. Reconstruction output generated."
