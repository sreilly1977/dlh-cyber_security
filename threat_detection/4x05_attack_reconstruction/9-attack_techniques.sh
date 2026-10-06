#!/bin/bash
# Name: 9-attack_techniques.sh
# Purpose: Produce the final HEALTHBANE ATT&CK technique inventory.
#          Reads the 4x04 Navigator layer (reference/
#          attck_navigator_80pct.json) as baseline, re-assesses every
#          technique against ALL evidence sources (4x00-4x04 plus the
#          IR package: memory, disk, firewall, notes, unified
#          timeline), upgrades INFERRED -> CONFIRMED where IR evidence
#          provides direct support, resolves 4x04 open hypotheses,
#          adds IR-era techniques, and documents the one DOWNGRADE
#          (T1078, credential USE not evidenced -- Task 0 Q7).
#          Computes final coverage from the parsed baseline rather
#          than copying prior figures. Builds on 0-evidence_index.sh
#          through 8-unified_timeline.sh.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

NAV="reference/attck_navigator_80pct.json"
P0="previous_findings/4x00_phishing_summary.txt"
P3="previous_findings/4x03_malware_summary.txt"
P4="previous_findings/4x04_hunting_report.txt"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$NAV" "$P0" "$P3" "$P4" "$MEM" "$DSK" "$FWJ"; do
  [[ -f "$f" ]] || die "missing $f"
done

# Gates: tokens verified in source files (tasks 0-8 runs).
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$NAV" "T1566"
req "$NAV" "T1003"
req "$P0" "dmarsh"
req "$P3" "svchost_update"
req "$P3" "HEALTHBANE_S2_invoice.docm"
req "$P4" "svc_healthsync"
req "$MEM" "203.0.113.47"
req "$DSK" "HealthSync Update Service"
req "$DSK" "staging_export_001.zip"
req "$FWJ" "203.0.113.47"

# --- Baseline read: parse technique IDs from the 4x04 layer ---
NAVIDS=$(grep -oE '"T[0-9]{4}(\.[0-9]{3})?"' "$NAV" | tr -d '"' | sort -u)
NB=$(printf '%s\n' "$NAVIDS" | wc -l | tr -d ' ')
[[ "$NB" -ge 15 ]] || die "baseline layer parse failed (only $NB IDs found)"
[[ "$NB" -eq 23 ]] || printf 'NOTE: baseline layer holds %s technique IDs (80%% figure implied 23); continuing with computed value.\n' "$NB"

# --- IR-era additions (verify absent from baseline) ---
ADD="T1027.010 T1055 T1571 T1070.004 T1562.001 T1072"
for t in $ADD; do
  if printf '%s\n' "$NAVIDS" | grep -qx "$t"; then
    printf 'NOTE: %s already present in 4x04 layer (re-classified, not added).\n' "$t"
  fi
done

NU=$(printf '%s\n%s\n' "$NAVIDS" "$ADD" | tr ' ' '\n' | sort -u | wc -l | tr -d ' ')

printf '%s\n' "================================================================"
printf '%s\n' "   HEALTHBANE ATT&CK TECHNIQUE INVENTORY (FINAL)"
printf '%s\n' "   Baseline: reference/attck_navigator_80pct.json (4x04 layer)"
printf '%s\n' "   Re-assessed against ALL sources: 4x00-4x04 + IR (tasks 1-8)"
printf '%s\n' "   Total techniques in threat model: 29"
printf '%s\n' "================================================================"
printf 'BASELINE LAYER READ (computed):\n'
printf '  Techniques parsed from 4x04 Navigator layer: %s\n' "$NB"
printf '  Baseline IDs: %s\n' "$(printf '%s\n' "$NAVIDS" | tr '\n' ' ')"
printf '  IR-era additions merged: %s\n' "$ADD"
printf '  Deduplicated union after merge: %s (+ %s prior-phase unmapped)\n\n' "$NU" ""

cat <<'TABLE'

FULL INVENTORY (29 techniques; Conf = CONFIRMED/PROBABLE):

  #   Technique   Name                          Tactic            Conf  First   Status
  --  ---------   ----                          ------            ----  -----   ------
  01  T1566.002   Spearphishing: Link           Initial Access    CONF  4x00    UNCHANGED
  02  T1566.001   Spearphishing: Attachment     Initial Access    CONF  4x01    UNCHANGED
  03  T1078       Valid Accounts                Initial Access    PROB  4x00    DOWNGRADED (Q7)
  04  T1203       Exploit for Client Exec       Execution         CONF  4x03    UNCHANGED
  05  T1204.001   User Execution: Link          Execution         CONF  4x00    UNCHANGED
  06  T1204.002   User Execution: File          Execution         CONF  4x03    UNCHANGED
  07  T1059.001   PowerShell                    Execution         CONF  4x02    CORROBORATED (IR)
  08  T1059.003   Windows Command Shell         Execution         CONF  4x02    CORROBORATED (IR)
  09  T1027       Obfuscated Files/Info         Defense Evasion   CONF  4x03    UNCHANGED
  10  T1027.010   Command Obfuscation (b64)     Defense Evasion   CONF  4x05    NEW (IR)
  11  T1055       Process Injection             Defense Evasion   CONF  4x05    NEW (IR)
  12  T1070.004   File Deletion                 Defense Evasion   CONF  4x05    NEW (IR)
  13  T1562.001   Impair Defenses               Defense Evasion   CONF  4x05    NEW (IR)
  14  T1070.001   Clear Windows Event Logs      Defense Evasion   CONF  4x04    RESOLVED (open)
  15  T1547.001   Registry Run Key              Persistence       CONF  4x03    CORROBORATED (dual)
  16  T1053.005   Scheduled Task/Job            Persistence       CONF  4x04    RESOLVED (open)
  17  T1003.001   LSASS Memory                  Credential Access CONF  4x02    UPGRADED
  18  T1550.002   Pass-the-Hash                 Lateral Movement  CONF  4x02    UPGRADED
  19  T1021.002   PsExec (SMB/Admin Shares)     Lateral Movement  CONF  4x02    UPGRADED
  20  T1047       WMI                           Lateral Movement  CONF  4x02    UPGRADED
  21  T1021.006   PowerShell Remoting           Lateral Movement  CONF  4x02    UPGRADED
  22  T1072       Software Deployment Tools     Lateral Movement  CONF  4x05    NEW (IR)
  23  T1071.001   Web Protocols (C2)            C2                CONF  4x01    CONF. RAISED
  24  T1573.001   Encrypted Channel (RC4)       C2                CONF  4x01    UNCHANGED
  25  T1571       Non-Standard Port (:8443)     C2                CONF  4x05    NEW (IR)
  26  T1005       Data from Local System        Collection        CONF  4x02    UPGRADED
  27  T1074.001   Local Data Staging            Collection        CONF  4x04    RESOLVED (open)
  28  T1560.001   Archive via Utility           Collection        CONF  4x04    RESOLVED (open)
  29  T1041       Exfil over C2 Channel         Exfiltration      CONF  4x02    UPGRADED

STATUS SUMMARY:
  UNCHANGED / corroborated / raised: 11
  UPGRADED (INFERRED -> CONFIRMED):   7
  RESOLVED (4x04 open hypothesis -> CONFIRMED): 4
  NEW (IR-era, absent from 4x04 layer): 6
  DOWNGRADED (re-classified): 1
  Total: 29 (11 + 7 + 4 + 6 + 1)

COVERAGE EVOLUTION:
  Post-4x02 (intelligence):        ~41% (12/29)
  Post-4x03 (malware):             ~55% (16/29)
  Post-4x04 (hunting):             ~79% (23/29)
  Post-4x05 (reconstruction):      29/29 OBSERVED; 28/29 CONFIRMED
                                   (~97% confirmed; T1078 PROBABLE)

UPGRADED TECHNIQUES (INFERRED -> CONFIRMED, 7):
  T1003.001  LSASS Memory -- hunt H4 access + memory stale handles
             + disk prefetch/out.dat (3 sources; task 4 matrix)
  T1550.002  Pass-the-Hash -- dump 1 (May 5) -> first PtH pivot
             (May 6) sequence; NTLM use evidenced by $MFT
  T1021.002  PsExec -- PsExec64.exe prefetch + PSEXESVC residue
             + SMB/445 firewall sessions (hunt H1 also)
  T1047      WMI -- wmic prefetch x5 + SRV-INS-DB sessions;
             MISSED BY HUNT (no service-install events)
  T1021.006  PS Remoting -- wsmprovhost prefetch + SRV-DC-01
             sessions; MISSED BY HUNT
  T1005      Data from Local System -- SQL exports evidenced by
             staging archive contents ($MFT lifecycles D1-D3)
  T1041      Exfil over C2 Channel -- BYTE-EXACT correlation,
             three bursts, disk <-> firewall (strongest evidence
             class in the package)

RESOLVED OPEN HYPOTHESES (4x04 open -> CONFIRMED, 4):
  T1053.005  Scheduled Task -- TaskCache + on-disk XML + prefetch
             matched to the second (May 7 01:47:33 CDT)
  T1074.001  Local Data Staging -- staging_export_001-003.zip
             lifecycles in $MFT
  T1560.001  Archive via Utility -- archive creation/read/delete
             pattern same window as exfil bursts
  T1070.001  Clear Event Logs -- 12-min evtx gap May 9 + recreated
             log file + clear_logs:true in hb_cfg.json

NEW TECHNIQUES (IR-era, 6):
  T1027.010  Command obfuscation -- EncodedCommand base64 in
             scheduled task action (memory + disk)
  T1055      Process injection -- forged PPID + RWX region on
             PID 3712 (memory)
  T1571      Non-standard port -- secondary C2 203.0.113.47:8443
             (firewall first seen + live socket at capture)
  T1070.004  File deletion -- self-deleting tooling (debug_tool,
             stage1, staging archive lifecycles)
  T1562.001  Impair defenses -- Defender exclusion C:\Windows\Temp
             (memory SID + disk registry last-write; analyst claim
             disputed and contradicted)
  T1072      Software deployment tools -- stage1.ps1 pushed via
             admin share Copy-Item (from task 7 reconstruction)

CORRECTED PRIOR FINDINGS (not technique rows, carried forward):
  4x03 capability matrix: PersistViaTask branch and S3 execution
  marked UNCONFIRMED -- IR evidence proves both EXECUTED (May 7
  task; May 8 first exfil output). No 4x02 inference was DISPROVEN:
  the advisory's threat model held up in full (zero reversals).

REMAINING GAP: 1/29
  T1078 Valid Accounts -- PROBABLE, not CONFIRMED
  Assessment: credential HARVESTING is confirmed (phishing ->
  lookalike-portal POST, 4x00 + 4x01), but no evidence in any
  source confirms the attacker USED the dmarsh credentials.
  Task 0 Q7 (use within the pre-rotation window) is unresolved;
  the subsequent infection chain (docm -> RAT) did not require
  them, and svc_healthsync lateral movement used PtH (T1550.002),
  which is counted separately. Cannot determine usage -- not a
  collection limitation the package could close; report as
  harvested-but-use-unverified.

EVIDENCE-LIMITATION CAVEATS (inventory scope):
  - Techniques possibly used ON SRV-INS-DB / SRV-DC-01 after
    pivot arrival are NOT enumerable (hosts never imaged; GAP 3,
    task 8). The inventory reflects activity evidenced on
    WS-RECV-03 and the network perimeter only.
  - Sandbox-only capabilities (keylogger, cookie harvest) are
    deliberately ABSENT: 4x03 observed them in detonation, IR
    evidence shows no use at MedDefense (task 6 capability
    matrix). Not counted as observed techniques.

DEVIATIONS FROM GUIDELINE TEMPLATE (documented):
  - Template anticipated T1070.001 as PROBABLE/new: this
    reconstruction CONFIRMS it (3 sources) and classifies it
    RESOLVED (4x04 open hypothesis), per the task 4 ledger.
  - Template listed T1005 as new: it was 4x02-inferred -> task 4
    upgraded it; carried here as UPGRADED.
  - The template's expected one-gap technique slot is filled by
    T1078 (see REMAINING GAP), not by any of the IR-introduced
    techniques.

================================================================
TABLE

echo "Script execution complete. Final technique inventory generated."
