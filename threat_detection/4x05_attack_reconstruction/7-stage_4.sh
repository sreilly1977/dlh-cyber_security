#!/bin/bash
# Name: 7-stage_4.sh
# Purpose: Reconstruct Stage 4 of the HEALTHBANE attack (lateral
#          movement, credential access, data staging, anti-forensics,
#          and containment) using correlated evidence from the 4x04
#          threat hunt, memory forensics, disk forensics, and
#          firewall session analysis. Builds on the outputs of
#          0-evidence_index.sh, 1-memory_analysis.sh, 2-disk_analysis.sh,
#          3-firewall_analysis.sh, and 4-correlation_matrix.sh.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

P4="previous_findings/4x04_hunting_report.txt"
IOCM="reference/healthbane_ioc_master.json"
INV="reference/meddefense_asset_inventory.txt"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"
NOTES="ir_evidence/ir_team_notes.txt"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$P4" "$IOCM" "$INV" "$MEM" "$DSK" "$FWJ" "$NOTES"; do
  [[ -f "$f" ]] || die "missing $f"
done

# Gates: tokens verified present in source files.
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$P4" "svc_healthsync"
req "$P4" "LSASS"
req "$IOCM" "svc_healthsync"
req "$INV" "SRV-HEALTH-DB"
req "$MEM" "svc_healthsync"
req "$MEM" "debug_tool"
req "$DSK" "PsExec64"
req "$DSK" "staging_export_001.zip"
req "$DSK" "staging_export_002.zip"
req "$DSK" "stage1.ps1"
req "$DSK" "2026-05-09"
req "$FWJ" "445"
req "$NOTES" "WS-RECV-03"

cat <<'HEADER'
================================================================
   ATTACK RECONSTRUCTION: Stage 4
   Lateral Movement, Data Staging, and Containment
   Dependencies: 0-evidence_index.sh, 1-memory_analysis.sh,
                 2-disk_analysis.sh, 3-firewall_analysis.sh,
                 4-correlation_matrix.sh
================================================================

LATERAL MOVEMENT CHAIN (all times CDT unless Z-suffixed):

  2026-05-04 18:11   Prerequisite: Defender exclusion added
                      (C:\Windows\Temp) on WS-RECV-03
    Tool/Action: registry modification (records03 SID)
    Evidence: IR-MEM (K5), IR-DSK (R3), IR-NOTES
    Technique: T1562.001 Impair Defenses
    Confidence: CONFIRMED (2 forensic sources + SID attribution)
    Note: Robert Kim (analyst) attributed this to internal activity;
          DISPUTED by the SID evidence and contradicted in IR notes.

  2026-05-05 03:22   Credential dump 1 on WS-RECV-03
    Tool: debug_tool.exe (attacker-supplied Mimikatz-class utility)
    Target: LSASS process memory
    Result: svc_healthsync credential obtained (NTLM hash + cleartext
             where enabled)
    Evidence: 4x04 (hunt H4 LSASS access), IR-MEM (stale handles +
              loaded module), IR-DSK (prefetch, out.dat residue)
    Technique: T1003.001 OS Credential Dumping: LSASS Memory
    Confidence: CONVERGED (3 independent sources; task 4 matrix)

  2026-05-06 02:11   First lateral pivot: WS-RECV-03 -> SRV-HEALTH-DB
    Tool: PsExec64.exe (via SMB/admin-share)
    Credential: svc_healthsync via Pass-the-Hash
    Evidence: 4x04 (hunt H1 anomalous PsExec), IR-DSK ($MFT: PSEXESVC
              residue, stage1.ps1 dropped 02:36), IR-FW (SMB/445
              sessions to server VLAN)
    Technique: T1550.002 Pass-the-Hash, T1021.002 SMB/Windows Admin
              Shares
    Confidence: CONVERGED (hunt + disk + firewall)

  2026-05-06 02:36   stage1.ps1 deployed to SRV-HEALTH-DB
    Tool: Copy-Item over admin share (same session)
    Evidence: IR-DSK ($MFT timeline on SRV-HEALTH-DB staging volume)
    Technique: T1072 Software Deployment Tools (script push),
              T1059.001 PowerShell
    Confidence: CONVERGED at host level (disk), single-source for the
              push mechanism (RAT 'drop' verb is the only consistent
              origin for debug_tool/PsExec64 arrival -- see Stage 3)

  Subsequent pivots (hunt period, May 6-12):
    WS-RECV-03 -> SRV-INS-DB     WMI (wmic; T1047)
    WS-RECV-03 -> SRV-DC-01      PowerShell Remoting (wsmprovhost;
                                  T1021.006)
    Evidence: IR-DSK (wmic prefetch x5, wsmprovhost prefetch), IR-FW
              (SMB/WinRM-family sessions per host), 4x04 (hunt
              H-series events; see below)
    Confidence: CONVERGED
    NOTE -- WHAT THE HUNT MISSED: hunt H-series telemetry anchored on
    the PsExec pattern (event IDs 7045/5145-family) and caught the
    SRV-HEALTH-DB pivot. The WMI pivot to SRV-INS-DB and the WinRM
    pivot to SRV-DC-01 produced no service-installation events and
    were BELOW the hunt's detection surface; IR disk prefetch and
    firewall metadata are the only witnesses. Detection lesson for
    the final report: the hunt's blind spot was exactly the
    living-off-the-land tool set the Stage 4 template warns about.

CREDENTIAL ASSESSMENT:
  Confirmed compromised:
    [1] dmarsh (end-user, WS-RECV-03) -- via phishing, Apr 14.
        4x00 + 4x01. Whether USED post-rotation: unknown (Task 0 Q7).
    [2] svc_healthsync (service account, SQL access on SRV-HEALTH-DB)
        -- via LSASS dump 1 (May 5), reused as PtH May 6 onward.
        4x04 + IR-MEM + IR-DSK + IOC master.
  Second dump (May 12 02:45 CDT, same tool/host):
    Purpose per IR notes: re-harvest after (unspecified) credential
    hygiene action mid-incident; dump 2's processed output feeds the
    May 13 AD-recon exfil burst (D3 staging contents). No additional
    DISTINCT credential identities were confirmed in either dump's
    residue beyond svc_healthsync and machine-account material --
    but note the dumps' full contents were NOT recovered (out.dat
    partial residue only), so "no other credentials" is NOT asserted
    as fact; scope is bounded by evidence.

DATA ACCESS AND STAGING SEQUENCE (pull-model, staged centrally):

  2026-05-06 02:36 +   Query execution on SRV-HEALTH-DB (stage1.ps1
                       runs dbo.patients template per 4x03 S3)
    Evidence: IR-DSK (D1 staging lifecycle: staging_export_001.zip
              created 02:36 CDT May 8 window lineage), 4x03 (SQL
              template health_records.dbo.patients)
    Data type: patient records
    Technique: T1005 Data from Local System

  Sequence determination: the attacker PULLED data from the database
  server back over SMB to WS-RECV-03 (admin-share read-back), then
  compressed and staged ON WS-RECV-03 before exfil over the C2
  channels. Staging was NOT performed on the DB host itself beyond
  the transient stage1.ps1 work file. Evidence: $MFT on WS-RECV-03
  shows the archive BORN-and-grow patterns locally (D1/D2/D3
  lifecycles), while SRV-HEALTH-DB's staging volume shows only the
  script drop; IR-FW SMB session byte-volumes for the May 6-8 window
  corroborate the server-to-workstation direction of the bulk
  transfer.

  2026-05-08 02:36-02:38 CDT   staging_export_001.zip built on WS-RECV-03
                               (14 219 484 B; 47 138 patient rows)
    Technique: T1560.001 Archive Collected Data, T1074.001 Local
              Data Staging
    Exfil: 2026-05-08T07:38:14Z, byte-exact to firewall session
            (34 441 660 B total across the three waves; see below).

  2026-05-11T08:17:18Z   Burst 2: staging_export_002.zip
                          (11 802 944 B; insurance records cohort,
                          SRV-INS-DB-derived -- the WMI pivot's yield)

  2026-05-12 02:45 CDT   Credential dump 2 (see above)

  2026-05-13T07:34:14Z   Burst 3: staging_export_003.zip
                          (8 419 232 B; AD reconnaissance export
                          derived from dump 2 + SRV-DC-01 access --
                          NOT PHI; changes the HIPAA impact scope
                          calculation, not the PHI cohort)
    Evidence for all three: IR-DSK ($MFT byte counts) + IR-FW
    (session bytes), BYTE-EXACT MATCHES per Task 3 -- the strongest
    correlations in the campaign.

  EXFILTRATION STATUS AT EACH MILESTONE: all three staged archives
  were CONFIRMED exfiltrated (CONFIRMED, byte-exact) before
  containment. The ~23 MB of elevated C2-channel volume consistent
  with the LSASS dumps themselves leaving is separately rated
  PROBABLE (aggregate-volume inference only; IR notes Entry #008
  leaves it OPEN).

PERSISTENCE AND OPERATIONAL SECURITY:
  Scheduled task (integrated): "HealthSync Update Service" created
    May 7 01:47:33 CDT, daily 02:00 CDT trigger, hidden,
    HighestAvailable (T1053.005; Task 1/T5 treatment) -- this is the
    mechanism that AUTOMATED the May 8/11/13 staging-and-exfil waves
    (fetch config from hb_cfg.json, run exfiltrator, clear logs,
    delete script per the D-series lifetimes).
  Anti-forensics (T1070 family):
    - Security-log clear May 9 03:00-03:12 CDT (evtx gap + recreated
      event-log file + clear_logs:true config): T1070.001
    - Self-deleting tooling (debug_tool/stage1 lifecycle deletions):
      T1070.004
    - Defender exclusion May 4: T1562.001
    Timing pattern: ALL attacker actions clustered 01:00-04:00 CDT,
    zero business-hours external activity (Task 3 temporal analysis).
  Operational-security ASSESSMENT: strong tradecraft on paper
    (living-off-the-land tools, log clearing, off-hours cadence,
    dual C2 channels). What EXPOSED them, in order:
    [1] The 4x04 hunt's behavioral detection of anomalous PsExec
        (the one lateral tool that leaves service-install telemetry).
    [2] The scheduled task's name pattern and cadence, surfaced by
        IR memory/disk once on-image.
    [3] The byte-exact exfil signature in $MFT vs firewall.
    Net: avoidance-defeating signal was VOLUME + CONSISTENCY, not
    any single IOC -- the same conclusion the 4x02 advisory drew.

CONTAINMENT TIMELINE:
  2026-05-15 13:42 CDT   WS-RECV-03 isolated (network DENY onset in
                          firewall export from 18:42Z; IR notes
                          Entry #001)
  2026-05-15 14:18 CDT   Memory capture taken (PID 3712 live
                          ESTABLISHED socket to 203.0.113.47:8443 at
                          capture -- the secondary C2 was STILL ACTIVE
                          at containment); disk image follows
  Hunt chronology note (Task 0 D6): the 4x04 report header's
    05-18 hunt-initiation date is contradicted by three corroborating
    sources for 05-15 isolation (notes, FW DENY, memory capture);
    the 05-15 sequence is authoritative.

  IF NOT CONTAINED (counterfactual, evidence-bounded):
    Unlike the classic 'staged data awaiting exfil' scenario, the
    three PHI/recon archives were ALREADY GONE by May 13. What the
    May 15 isolation actually interrupted:
    [1] The daily 02:00 CDT scheduled task -- the next run (May 16
        02:00) would have fetched fresh config and staged/exfil a
        FOURTH wave; the SQL template suggests repeated patient-
        record deltas (D1 pattern implies incremental exports).
    [2] Live secondary-C2 access (still established at capture).
    [3] Whatever stage of access remained on SRV-INS-DB and
        SRV-DC-01 -- extents not fully quantified; no imaging of
        those hosts occurred in this package (explicit gap).
    What we cannot claim: further credentials, additional databases,
    or destruction capability -- no destructive-capability evidence
    exists anywhere in the package, and the reconstruction does not
    assert one.

STAGE 4 TECHNIQUES (with citations):
  T1003.001  LSASS Memory              CONFIRMED  4x04/IR-MEM/IR-DSK
  T1550.002  Pass-the-Hash             CONFIRMED  4x04/IR-DSK
  T1021.002  PsExec/SMB Admin Shares   CONFIRMED  4x04/IR-DSK/IR-FW
  T1047      WMI                       CONFIRMED  IR-DSK (prefetch x5)
  T1021.006  PowerShell Remoting        CONFIRMED  IR-DSK (wsmprovhost)
  T1072      Software Deployment Tools CONFIRMED  IR-DSK (stage1 push)
  T1059.001  PowerShell                 CONFIRMED  IR-MEM/IR-DSK
  T1005      Data from Local System     CONFIRMED  IR-DSK (D1/D2/D3)
  T1074.001  Local Data Staging          CONFIRMED  IR-DSK/IR-FW
  T1560.001  Archive Collected Data     CONFIRMED  IR-DSK/IR-FW
  T1041      Exfil over C2 Channel      CONFIRMED  IR-FW/IR-DSK
                                        (byte-exact)
  T1053.005  Scheduled Task             CONFIRMED  IR-MEM/IR-DSK/IR-FW
  T1562.001  Impair Defenses            CONFIRMED  IR-MEM/IR-DSK
  T1070.001  Clear Event Logs           CONFIRMED  IR-DSK/IR-FW/IR-MEM
  T1070.004  File Deletion              CONFIRMED  IR-DSK

================================================================
HEADER

echo "Script execution complete. Stage 4 reconstruction generated."
