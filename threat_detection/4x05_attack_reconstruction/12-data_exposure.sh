#!/bin/bash
# Name: 12-data_exposure.sh
# Purpose: Data exposure assessment for the HEALTHBANE campaign against
#          MedDefense. Maps the verified compromise chain (WS-RECV-03,
#          SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01) to the asset inventory,
#          classifies data access per host (confirmed / probable /
#          no-evidence), assesses exfiltration status against the
#          byte-exact Task 3 firewall correlation, categorizes exposure
#          by data type with disk-verified record counts, and evaluates
#          the HIPAA breach-notification threshold (discovery
#          2026-05-15, 60-day deadline 2026-07-14). Corrects the
#          guideline template's "exfiltration interrupted" premise
#          (exfiltration COMPLETED before containment) and rejects its
#          unsupported SRV-FILE-01 entry. Third exfil artifact is
#          query_results.csv (D3), not a staging_export_003.zip.
#          Builds on 0-evidence_index.sh through 11-gap_analysis.sh.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

INV="reference/meddefense_asset_inventory.txt"
P3="previous_findings/4x03_malware_summary.txt"
P4="previous_findings/4x04_hunting_report.txt"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"
NOTES="ir_evidence/ir_team_notes.txt"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$INV" "$P3" "$P4" "$MEM" "$DSK" "$FWJ" "$NOTES"; do
  [[ -f "$f" ]] || die "missing $f"
done

# Gates: tokens verified in source files (tasks 0-11 runs and the
# D-series grep: D3 artifact is query_results.csv, not a third zip).
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$INV" "WS-RECV-03"
req "$INV" "SRV-HEALTH-DB"
req "$INV" "SRV-INS-DB"
req "$INV" "SRV-DC-01"
req "$P3" "HEALTHBANE_S2_invoice.docm"
req "$P4" "svc_healthsync"
req "$MEM" "203.0.113.47"
req "$DSK" "staging_export_001.zip"
req "$DSK" "staging_export_002.zip"
req "$DSK" "query_results.csv"
req "$DSK" "51 002"
req "$DSK" "2026-05-09"
req "$FWJ" "203.0.113.47"
req "$NOTES" "WS-RECV-03"

cat <<'HEADER'
================================================================
   DATA EXPOSURE ASSESSMENT
   Period: 2026-04-14 (initial access) to 2026-05-15 (containment)
   Evidence basis: Tasks 0-11 verified reconstruction
================================================================

COMPROMISED SYSTEM MAPPING (verified lateral chain -> inventory):

  Host            Role (inventory)        Access Level
  --------------  ----------------------   ------------------------------
  WS-RECV-03      Records dept workstation CONFIRMED ACCESS
                  (staging + exfil host;  (full compromise: RAT,
                  low local sensitivity)  dual persistence, C2)
  SRV-HEALTH-DB   Health records database CONFIRMED ACCESS
                                          (stage1.ps1 deployed;
                                          dbo.patients query; data
                                          pulled to WS-RECV-03 over
                                          SMB; archive D1)
  SRV-INS-DB      Insurance database      CONFIRMED ACCESS
                                          (pivot via WMI, missed by
                                          hunt; data interaction
                                          PROVEN by recovered D2
                                          contents: 51 002 rows from
                                          insurance_db.dbo.policies;
                                          host itself never imaged)
  SRV-DC-01       Domain controller       CONFIRMED ACCESS
                                          (pivot via PS Remoting,
                                          missed by hunt; data
                                          interaction PROVEN by the
                                          2026-05-13 task run that
                                          produced the D3
                                          AD-enumeration CSV; host
                                          itself never imaged)

  NOT IN THE CHAIN (addressed deliberately):
  SRV-FILE-01     -- NO EVIDENCE of compromise in ANY source:
                     absent from the lateral chain (Tasks 7-8),
                     absent from disk prefetch/firewall sessions,
                     never cited by the hunt. The guideline
                     template listed it as "probable access";
                     that entry has NO evidentiary basis and is
                     rejected. An inventory listing is not
                     evidence of access.
  HR systems      -- no HR system appears anywhere in the pivot
                     chain or evidence package.

  Scope boundary (inherited from Task 11 GAP 3): SRV-INS-DB and
  SRV-DC-01 were never imaged. Data interaction is nonetheless
  CONFIRMED for both by the recovered staging contents (D2, D3);
  the boundary governs any interaction BEYOND those evidenced
  collections -- unknowable, and the reason imaging remains the
  top investigative recommendation.

EXFILTRATION STATUS:
  Data staged on WS-RECV-03:  YES -- 3 artifacts, 34 441 660 B
                              total (14 219 484 + 11 802 944 +
                              8 419 232)
  Artifacts (disk report naming):
    D1  staging_export_001.zip   patient records   (deleted,
                               recovered)
    D2  staging_export_002.zip  insurance records (deleted,
                               recovered; inner CSV
                               out_20260511031408.csv,
                               11 794 117 B uncompressed)
    D3  query_results.csv        AD enumeration   (deleted,
                               recovered via MFT residue,
                               entry 483 514)
  Data transmitted externally: YES -- ALL THREE ARTIFACTS,
                              BYTE-EXACT ($MFT byte counts <->
                              firewall session bytes; strongest
                              evidence class in the package)
  Destinations:                primary C2 185.220.101.45 (c2_post
                              over the encrypted channel) and
                              secondary C2 203.0.113.47:8443
  Interruption:                 NONE for the three waves --
                              exfiltration COMPLETED before
                              containment. The May 15 isolation
                              interrupted a projected FOURTH wave
                              (daily scheduled task, next run
                              May 16 02:00 CDT) and the live
                              secondary-C2 socket only.
  Additionally: ~23 MB elevated C2 volume consistent with the
                              LSASS dump CONTENTS leaving is rated
                              PROBABLE (aggregate inference only;
                              IR notes Entry #008 OPEN).

  CONCLUSION: CONFIRMED COMPLETE EXFILTRATION of all staged PHI
  and insurance data prior to containment. Any assessment
  stating exfiltration was "interrupted" contradicts the
  byte-exact evidence. This assessment is intentionally
  unambiguous for the board: data LEFT the network.

DATA EXPOSURE BY TYPE:

  Patient health records (PHI):
    Status:    EXFILTRATED (CONFIRMED, byte-exact)
    Evidence:  IR-DSK D1 lifecycle + contents; 4x03 SQL template
               (health_records.dbo.patients); IR-FW session match
    Scope:     47 138 patient rows (Task 2 disk analysis) in a
               14 219 484 B archive; first wave
               2026-05-08T07:38:14Z
    Incremental risk: the D-series lifecycles and daily task
               cadence imply INCREMENTAL export capability; the
               counterfactual fourth wave means later-record
               deltas may have been the next target. (Projection
               flagged as inference, not fact.)

  Insurance / billing data:
    Status:    EXFILTRATED (CONFIRMED, byte-exact)
    Evidence:  IR-DSK D2 + IR-FW match (2026-05-11T08:17:18Z,
               11 802 944 B); recovered inner CSV
               out_20260511031408.csv -- 51 002 rows from
               insurance_db.dbo.policies on SRV-INS-DB; disk
               analyst flagged HIGH SEVERITY
    Scope:     51 002 insurance member/policy rows --
               DISK-VERIFIED (recovered row count and header;
               NOT an arithmetic derivation). Header fields
               include policy_id, member_id, first/last name,
               SSN, plan_code, coverage dates. Presence of SSN
               makes this a PII exposure alongside HIPAA scope.
    Arithmetic check: 47 138 (patients) + 51 002 (insurance)
               = 98 140, the firewall-derived raw-row total --
               disk row counts and perimeter volume reconcile
               exactly.

  Employee records (HR):
    Status:    NOT EXPOSED (no evidence in any source)
    Evidence:  no HR system in the pivot chain, prefetch
               record, session logs, staging contents, or hunt
               findings

  Operational / directory data:
    Status:    EXFILTRATED (CONFIRMED, byte-exact)
    Evidence:  D3 query_results.csv + IR-FW match
               (2026-05-13T07:34:14Z, 8 419 232 B); AD
               enumeration produced by the 2026-05-13 scheduled-
               task run (cross-references LSASS dump 2 and the
               SRV-DC-01 pivot)
    Note:     NOT PHI; likely contains employee identifiers and
               directory metadata -- relevant to risk assessment
               and Security Rule review for Legal, outside the
               HIPAA PHI notification cohort

REGULATORY ASSESSMENT (HIPAA Breach Notification Rule):

  Threshold determination: MET -- a reportable breach occurred.
    Basis:  unauthorized ACQUISITION of unsecured PHI is
            confirmed (staging + byte-exact exfiltration of
            47 138 patient rows and 51 002 insurance rows,
            including SSN fields). Under the Breach
            Notification Rule, acquisition triggers the
            presumption of compromise unless a documented risk
            assessment shows low probability that PHI was
            actually acquired -- here acquisition is AFFIRMATIVELY
            evidenced, so the presumption question does not arise.
  Estimated scope:
    Raw row count:      98 140 (47 138 patient + 51 002
                        insurance; both disk-verified; equals
                        the firewall-derived total exactly)
    Deduplicated est.:  50 000 - 55 000 individuals (inventory-
                        based estimate; D4 resolution: Legal owns
                        the final dedup)
    Either figure vastly exceeds the 500-individual threshold
    for HHS OCR notification and simultaneous media notice.
  Timeline:
    Discovery (isolation + capture): 2026-05-15
    Notification deadline (60 days): 2026-07-14
    (60-day clock runs from DISCOVERY, not from the first
    exfiltration event on 2026-05-08.)
  Mitigating factors -- assessed honestly, most template
    candidates FAIL on the evidence:
    [!] "Staging interrupted before exfiltration": FALSE --
        all three waves completed before containment. Cannot
        be claimed.
    [!] Encryption of exfiltrated data in transit (TLS/RC4 C2
        channel): NOT a mitigation -- the attacker held the
        keys; this protects interception by THIRD parties only.
    [!] No evidence of encryption-at-rest protecting the staged
        artifacts is present in the package; none claimed.
    [+] Effective interruptions that DID occur: containment cut
        off the live secondary-C2 socket and the projected
        fourth exfil wave; no destructive capability was
        evidenced anywhere in the package (no ransomware/wiper
        behavior observed or asserted).
    [+] Affected credentials rotated (dmarsh same-day per 4x00;
        svc_healthsync handled by mid-incident hygiene per IR
        notes -- rotation itself prompted dump 2 on May 12).
  Detection-to-containment credit: NOT CLAIMABLE. The hunt
    detection date is unverifiable (4x04 internal inconsistency,
    D6/U4); only the 05-15 isolation is corroborated. No
    response-time credit is asserted.
  Recommended action: NOTIFY. Individual notifications to the
    deduplicated cohort; HHS OCR and contemporaneous media
    notice (>= 500 individuals) by 2026-07-14, subject to Legal
    confirming the dedup figure. Investigative priority per
    Task 11: image SRV-DC-01 and SRV-INS-DB BEFORE the
    credential-hygiene cycle destroys residual artifacts --
    their contents could alter (only upward or clarify) the
    scope determination.
  Disclaimer: this is an engineering evidence assessment. The
    reportability determination and cohort definition rest with
    Legal under Dr. Morales's review; all figures above are
    traceable to the cited evidence.

================================================================
HEADER

echo "Script execution complete. Data exposure assessment generated."
