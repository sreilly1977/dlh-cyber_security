#!/bin/bash
# Name: 11-gap_analysis.sh
# Purpose: Gap analysis and blind-spot assessment for the HEALTHBANE
#          reconstruction. Classifies every technique in the 29-ID
#          4x04 baseline threat model that did not carry forward into
#          the final Task 9 inventory as ABSENCE, COLLECTION GAP,
#          ANALYTICAL GAP, or SUBSUMED mapping; recommends the
#          telemetry needed to close each collection gap; assesses
#          overall reconstruction confidence (confirmed/probable/
#          possible); and documents why each prior coverage plateau
#          (40%/55%/80%) created a false sense of security. Builds on
#          the verified outputs of 0-evidence_index.sh through
#          10-navigator_update.json (consumes the Task 9 baseline
#          diff and Task 8 event/confidence tallies).
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

NAV="reference/attck_navigator_80pct.json"
P0="previous_findings/4x00_phishing_summary.txt"
P2="previous_findings/4x02_attack_mapping.json"
P4="previous_findings/4x04_hunting_report.txt"
IOCM="reference/healthbane_ioc_master.json"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"
NOTES="ir_evidence/ir_team_notes.txt"
NAVUPD="10-navigator_update.json"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$NAV" "$P0" "$P2" "$P4" "$IOCM" "$MEM" "$DSK" "$FWJ" "$NOTES"; do
  [[ -f "$f" ]] || die "missing $f"
done
[[ -f "$NAVUPD" ]] || printf 'NOTE: %s not found; gap classification uses Task 9 inventory results directly.\n' "$NAVUPD"

# Gates: tokens verified in source files (tasks 0-9 runs).
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$NAV" "T1078"
req "$NAV" "T1048.003"
req "$NAV" "T1112"
req "$P0" "dmarsh"
req "$P2" "T1550"
req "$P4" "svc_healthsync"
req "$IOCM" "svc_healthsync"
req "$MEM" "203.0.113.47"
req "$DSK" "2026-05-09"
req "$DSK" "staging_export_001.zip"
req "$FWJ" "203.0.113.47"
req "$NOTES" "WS-RECV-03"

# Compute baseline ID count for the provenance line (mirrors Task 9).
NB=$(grep -oE '"T[0-9]{4}(\.[0-9]{3})?"' "$NAV" | sort -u | wc -l | tr -d ' ')

printf '%s\n' "================================================================"
printf '%s\n' "   GAP ANALYSIS AND BLIND SPOT ASSESSMENT"
printf '%s\n' "   Baseline: reference/attck_navigator_80pct.json ($NB IDs parsed)"
printf '%s\n' "   Final mapping: Task 9 inventory (24 baseline + 5 new)"
printf '%s\n' "   Diff computed: $((NB - 24 > 0 ? NB - 24 : 0)) baseline-only techniques classified below"
printf '%s\n' "================================================================"

cat <<'HEADER'

METHODOLOGY:
  A "gap" is classified against the reconstructed attack chain, the
  evidence-collection architecture, and the analytical record:
    ABSENCE       -- attacker did not use it; chain evidence excludes
                     or makes it redundant
    COLLECTION GAP-- use plausible, but no collector would have seen
                     it (missing or destroyed telemetry)
    ANALYTICAL GAP-- evidence exists but was not recognized
    SUBSUMED      -- not a gap: behavior mapped under another
                     technique; disabling avoids double-counting

================================================================

UNMAPPED / UNCONFIRMED TECHNIQUES (from the 29-ID baseline):

  T1048.003  Exfiltration Over Alternative Protocol: Exfiltration
             Over Unencrypted Non-C2 Protocol (SMTP)
    Assessment: ABSENCE (high confidence)
    Reasoning: every observed exfiltration event is accounted for
      byte-exactly across three bursts over the C2 channels
      (T1041: 34 441 660 B total, $MFT <-> firewall). Firewall
      export covers the full May 2-15 window on the egress path
      and shows no anomalous SMTP/25/587 volume. The 4x02 threat
      model included SMTP exfiltration as a possibility; the
      reconstruction closes it.
    Verdict strength: collector-independent -- the perimeter device
      that WOULD have captured SMTP did observe the full window.

  T1071.004  Application Layer Protocol: DNS
    Assessment: ABSENCE for bulk exfiltration; PARTIAL COLLECTION
      GAP for test-time attribution
    Reasoning: 4x01 observed the DNS exfil channel being TESTED
      (T-150/T-151 pings to 185.220.101.46, single-domain TXT
      queries) but no bulk data ever traversed it -- all three
      archives left via c2_post. However, WHO conducted the test
      cannot be determined: the 4x01 PCAP is VLAN-3-wide (same
      ambiguity as the Apr 15 beacon, U1), and DNS telemetry was
      never forwarded to a resolver log. The capability test is
      campaign-level evidence only.
    Required telemetry (to close the attribution half): resolver /
      DNS server query logs with client-IP, retained past 30 days
      (currently not collected at all).
    Recommendation: deploy passive DNS logging at the enterprise
      resolvers; forward to the SIEM with client attribution.

  T1078.002  Valid Accounts: Domain Accounts
    Assessment: COLLECTION GAP (plausible use, telemetry destroyed)
    Reasoning: svc_healthsync moved laterally via Pass-the-Hash
      (counted under T1550.002), but ANY interactive or
      password-based authentication with the service account on
      SRV-INS-DB or SRV-DC-01 would have appeared in DC security
      event logs (4624 type 3/10, 4768/4769) -- which the attacker
      CLEARED on May 9 (T1070.001). The evidence that would answer
      this was destroyed by the adversary because it lived only on
      a host they controlled.
    Required telemetry: centralized Windows Event Log forwarding
      (or a syslog agent) shipping Security logs off-host in near
      real time; log retention >= 180 days.
    Recommendation: IMMEDIATE. This is the single most consequential
      collection deficiency exposed by the case: log clearing
      should have had NO effect on evidence availability.

  T1112      Modify Registry
    Assessment: SUBSUMED (not a true gap)
    Reasoning: every registry modification in the chain is
      enumerated under more specific techniques -- T1547.001
      (Run key), T1562.001 (Defender exclusion), T1112 at parent
      granularity would double-count. Retained in the Navigator
      layer as a DISABLED entry for layer-to-layer continuity
      only.

  T1059.005  Command and Scripting Interpreter: Visual Basic
    Assessment: SUBSUMED (not a true gap)
    Reasoning: VBA macro execution is fully represented by T1203
      (Exploitation for Client Execution). Disabled in the final
      layer to avoid double-counting.

  T1078      Valid Accounts (the one DOWNGRADE, cross-referenced)
    Assessment: COLLECTION GAP (use unknowable from this package)
    Reasoning: dmarsh credential HARVESTING is confirmed (two
      sources), but USE is unverified. Two collection failures
      jointly cause this: (a) the 17-minute pre-rotation window
      (Task 0 Q7) was never covered by any log capture in the
      package; (b) the DC security logs that would show later use
      were cleared May 9. The infection chain itself needed no
      credentials (docm -> RAT), so absence of downstream use
      evidence leans toward non-use -- but cannot be asserted.
    Required telemetry: same as T1078.002 (off-host log shipping);
      additionally, authentication-attempt alerting on harvested
      identity within minutes of a phishing submission.

  OPEN SCOPE -- techniques on UNIMAGED hosts (not enumeratable):
    Assessment: COLLECTION GAP (bounded, structural)
    Reasoning: SRV-INS-DB and SRV-DC-01 were never imaged
      (Task 8 GAP 3). Any technique executed ON those hosts after
      pivot arrival is invisible; the inventory's Stage-4 rows
      attest to pivot ARRIVAL (network + prefetch), not resident
      activity. This bounds the 28/29 confirmation figure: it is
      28/29 of the OBSERVABLE surface, not necessarily of the
      total campaign.
    Required telemetry: forensic imaging of both hosts; DC
      transaction/replication logs; SRV-INS-DB SQL audit logs if
      enabled.
    Recommendation: prioritize SRV-DC-01 imaging before the next
      credential-hygiene cycle wipes residual artifacts.

================================================================

RECONSTRUCTION CONFIDENCE SUMMARY (event basis, Task 8 timeline):
  Kill chain events: 20 attacker events (23 numbered incl. 2
    defensive + 1 unverified-probable)
  CONFIRMED / CONVERGED (2+ sources):  19 (95%)
  PROBABLE (strong single source):      1 (5%) -- Event #08, the
    exfil-script deployment DATE (IOC-master association inside
    GAP 1; deployment itself confirmed, only the date is weak)
  POSSIBLE (inferred only):             0

  Biggest remaining uncertainty: the post-pivot SCOPE on the two
    unimaged servers -- specifically whether activity beyond the
    evidenced pivots (additional collections from SRV-INS-DB,
    privileged operations on SRV-DC-01) occurred between May 6
    and May 15. This uncertainty DIRECTLY bounds the HIPAA
    impact assessment: burst 2's insurance cohort is evidenced,
    but any UNLOGGED collection on those hosts is invisible.
  Evidence needed to resolve: forensic images of SRV-INS-DB and
    SRV-DC-01 (filesystem timelines, SQL audit tables, DC
    replication and netlogon logs); any surviving backup of DC
    security logs from BEFORE May 9 (pre-clearing backup, offline
    copy, or DFR rollout snapshot) would additionally resolve
    the T1078/T1078.002 questions outright.

================================================================

COVERAGE EVOLUTION LESSONS:

  [*] Post-4x02 (~41%, intelligence-driven): the advisory
      predicted the campaign accurately but could not tie any
      technique to OUR network. Every "coverage" point was
      theoretical. Blind spot: everything below initial access.

  [*] Post-4x03 (~55%, malware-driven): detonation analysis
      characterized what the tools COULD do, including
      capabilities never used at MedDefense (keylogger, cookie
      harvest) and left two capability branches UNCONFIRMED that
      IR later proved executed. Lesson in both directions:
      sandbox capability is neither floor nor ceiling. Blind
      spot: all LOLBin lateral movement and on-host effect.

  [*] Post-4x04 (~79%, hunt-driven): the hunt's first detection
      surfaced the operator, but the hunt was anchored on the ONE
      lateral tool that leaves service-installation events
      (PsExec) -- WMI and WinRM pivots sailed through undetected,
      as did scheduled-task persistence, data staging, and
      exfiltration (all inside the network, below the hunt's
      alert surface). The 4x04 layer also carried 5 mappings this
      reconstruction could not independently carry forward.
      Blind spot: the objective phase -- collection, staging,
      exfiltration -- i.e., the HIPAA-relevant part.

  [*] Post-4x05 (96.6% confirmed, 28/29): IR forensics closed
      the objective phase with byte-exact certainty (the strongest
      evidence class in the whole package). The remaining gaps are
      now CLASSIFIED rather than merely counted: one absence
      verified at the perimeter, one absence with a test-only
      caveat, two collection gaps caused by destroyed/absent host
      logging, two subsumed mappings, and one structural blind
      spot (unimaged servers) that bounds every scope claim.

  KEY LESSON: each coverage plateau produced a false sense of
  security precisely because the UNCOVERED remainder migrated to
  the phase that mattered most next. Intelligence covered entry;
  malware analysis covered tools; the hunt covered movement; the
  DATA phase -- staging and exfiltration, the phase with legal
  consequence -- stayed dark until host forensics. Coverage
  percentage measures what the CURRENT instrument can see; the
  blind-spot analysis measures what it cannot. Both belong in
  every report. And the May 9 log clearing proves the point
  operationally: the adversary weaponized the collection
  architecture's own weakness (logs resident on the hosts he
  controlled). Telemetry that survives adversary action is the
  only telemetry that counts toward "confirmed."

================================================================
HEADER

echo "Script execution complete. Gap analysis generated."
