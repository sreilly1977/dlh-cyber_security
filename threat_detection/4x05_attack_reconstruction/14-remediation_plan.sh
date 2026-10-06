#!/bin/bash
# Name: 14-remediation_plan.sh
# Purpose: Prioritized remediation plan for the HEALTHBANE campaign,
#          consolidating every vulnerability, detection gap, and
#          defensive weakness identified in Tasks 0-13 into a three-
#          tier plan (IMMEDIATE <= 48h, SHORT-TERM <= 2 weeks,
#          MEDIUM-TERM <= 3 months). Every action traces to a
#          specific reconstruction finding and ATT&CK technique,
#          carries an effort estimate and owning team, and respects
#          the sequencing lessons of the incident (mid-incident
#          credential rotation provoked LSASS dump 2; log rotation
#          and hygiene cycles are destroying residual artifacts on
#          unimaged hosts). Corrects the guideline template: the
#          "unknown IP" is known (203.0.113.47), exfiltration is
#          CONFIRMED COMPLETE (validation targets post-isolation
#          egress only), and host imaging enters as the most
#          time-critical immediate action.
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

P0="previous_findings/4x00_phishing_summary.txt"
P3="previous_findings/4x03_malware_summary.txt"
P4="previous_findings/4x04_hunting_report.txt"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"
NOTES="ir_evidence/ir_team_notes.txt"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$P0" "$P3" "$P4" "$MEM" "$DSK" "$FWJ" "$NOTES"; do
  [[ -f "$f" ]] || die "missing $f"
done

# Gates: tokens verified in source files (tasks 0-13 runs).
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$P0" "dmarsh"
req "$P3" "HEALTHBANE_S2_invoice.docm"
req "$P4" "svc_healthsync"
req "$P4" "PsExec"
req "$MEM" "203.0.113.47"
req "$MEM" "HealthSyncSingleton"
req "$DSK" "2026-05-09"
req "$DSK" "query_results.csv"
req "$DSK" "51 002"
req "$FWJ" "203.0.113.47"
req "$NOTES" "WS-RECV-03"

cat <<'HEADER'
================================================================
   PRIORITIZED REMEDIATION PLAN
   Based on HEALTHBANE Attack Reconstruction (Tasks 0-13)
   Plan date: 2026-06 (post-containment reference)
================================================================

FINDING BASIS (every action below traces to these):
  F1  dmarsh credentials phished and harvested (T1566/T1539)
  F2  RAT with dual persistence (run key + scheduled task)
      and dual C2 (T1547.001, T1053.005, T1071.001)
  F3  Secondary C2 203.0.113.47:8443 active at capture
      (T1071.001 / IOC D7 series)
  F4  LSASS dumps via svc_healthsync Pass-the-Hash (T1003.001,
      T1550.002); mid-incident rotation attempt PROVOKED
      dump 2 on 2026-05-12 (IR notes) -- sequencing lesson
  F5  Three pivots, only one detected by the hunt (T1021.002
      detected; T1047, T1021.006 missed -- no service-install
      telemetry)
  F6  Scheduled task drove staging nightly from ~2026-05-07
      (T1053.005), undetected through the detection period
  F7  Three staged archives, 34 441 660 B, all EXFILTRATED
      byte-exact before containment (T1074.001, T1560.001,
      T1041) -- see T12; "exfiltration interrupted" is FALSE
  F8  DC security logs cleared 2026-05-09 (T1070.001); logs
      were host-resident, so clearing destroyed the evidence
  F9  Two compromised servers (SRV-DC-01, SRV-INS-DB) never
      imaged; artifacts being consumed by hygiene cycles
      (T11 GAP 3) -- ACTIVE CLOCK
  F10 HIPAA breach threshold MET: 98 140 raw rows / est.
      50-55k individuals; deadline 2026-07-14 (T12)
  F11 Objective-phase activity invisible to ALL live detection
      (T13 matrix: forensic-column-only rows)
  F12 No egress alerting despite firewall data existing;
      no DNS resolver telemetry; no off-host log forwarding

================================================================
IMMEDIATE ACTIONS (within 48 hours)
================================================================
  Pri   Action                                  Finding  Effort  Owner
  ----  --------------------------------------  -------  ------  --------
  IM-1  Forensically image SRV-DC-01 and        F9       12h     IR Team
        SRV-INS-DB BEFORE hygiene/rotation
        cycles destroy residual artifacts.
        TIME-CRITICAL: the clock started at
        containment. Contents can only clarify
        or EXPAND the T12 scope.
  IM-2  Verify WS-RECV-03 isolation is           F2,F3    1h      Network
        complete at ALL layers: switch port,
        VLAN, firewall (both C2 IPs must show
        ZERO post-isolation sessions).
  IM-3  Sweep ALL workstations and servers for   F2,F6    4h      SOC
        the IOC set: scheduled tasks with
        encoded PowerShell actions, run-key
        entries, HealthSyncSingleton mutex,
        C2 IPs in local logs, prefetch for
        PsExec64/WmiPrvSE abuse.
  IM-4  Block 203.0.113.47 (and continue         F3       1h      Network
        blocking 185.220.101.45) at the
        perimeter in BOTH directions; add
        retro-hunt against firewall history
        for any OTHER host contacting either.
  IM-5  Validate NO post-isolation egress and    F7       2h      SOC
        that the fourth wave (projected
        2026-05-16 02:00 run) did NOT execute
        on any surviving copy of the task.
        NOTE: this does NOT re-open T12 --
        the three confirmed waves are settled;
        this checks for activity AFTER.
  IM-6  Formal evidence handoff to Legal with    F10      1h      IR+Legal
        the T12 assessment: 60-day clock from
        2026-05-15 discovery expires
        2026-07-14; legal hold on all forensic
        images, logs, and this package.
  IM-7  Rotate svc_healthsync credentials --     F4       2h      IT
        AFTER IM-1 imaging and IM-3 sweep.
        Sequencing is deliberate: the May 12
        mid-incident rotation PROVOKED LSASS
        dump 2; do not repeat that pattern.
        dmarsh already rotated same-day per 4x00.

  Immediate total: 7 actions, ~23h effort.
  Note: these are largely parallelizable across teams except
  the explicit IM-1 -> IM-7 sequence.

================================================================
SHORT-TERM ACTIONS (within 2 weeks)
================================================================
  Pri   Action                                  Finding  Effort  Owner
  ----  --------------------------------------  -------  ------  --------
  ST-1  Centralized off-host Windows Event      F8,F11   40h     IT+SOC
        Log forwarding, near-real-time,
        >= 180-day retention. HIGHEST
        PRIORITY of the plan: the one control
        whose absence the adversary actively
        weaponized (2026-05-09 log wipe
        destroyed the T1078 evidence).
  ST-2  Scheduled-task creation detection:      F6       8h      SOC
        alert on 4698/Sysmon task-create
        events, esp. powershell.exe -enc
        actions, SYSTEM context, non-admin
        originators. (Closes T1053.005.)
  ST-3  Data staging detection: file-create     F7       8h      SOC
        alerts on archives/CSVs in
        C:\Users\Public\ and equivalent
        world-writable paths by non-standard
        parents. (Closes T1074.001/T1560.001.)
  ST-4  First-contact external destination      F3       4h      SOC+Net
        alert for workstation-tier assets
        (new external IP/port pairs), plus
        signature for the secondary C2
        beacon pattern (8443, periodic).
  ST-5  Egress volume anomaly alerting:         F7,F12   8h      SOC
        per-host daily bytes-out vs 30-day
        baseline. Data ALREADY EXISTS in
        firewall exports -- alerting is the
        only new component. Three waves
        totaling 34 441 660 B would have
        alerted on day one.
  ST-6  Service account privilege review:       F4,F5    16h     IT
        svc_healthsync scope (which hosts,
        which DB rights), eliminate lateral
        reach it demonstrated; least
        privilege redesign.
  ST-7  Passive DNS / resolver logging with     F12      16h     Network
        client attribution, >= 90-day
        retention. Closes the attribution
        half of the DNS-channel gap (4x01).

  Short-term total: 7 actions, ~100h effort.

================================================================
MEDIUM-TERM ACTIONS (within 3 months)
================================================================
  Pri   Action                                  Finding  Effort  Owner
  ----  --------------------------------------  -------  ------  --------
  MT-1  Full Sysmon deployment on ALL           F5,F11   40h     IT+SOC
        endpoint tiers, feeding the SIEM;
        onboard the existing 4x03
        behavioral rules (mutex, RC4
        config, C2 URI shape) to the
        monitored pipeline. The rules were
        sound; the telescope was never
        pointed at the workstation tier.
  MT-2  Recurring hunt program: weekly          F5       Ongoing SOC
        micro-hunts, monthly full hunts,
        with hypothesis diversity reviews
        (the 4x04 hunt inherited its
        hypothesis's blind spots) AND a
        written containment SLA pairing
        every detection of an active
        operator with scoped isolation
        criteria (hours, not days -- the
        May 8-13 waves all postdated
        detection).
  MT-3  Network segmentation review:            F5       80h     Network
        workstation-to-server lateral paths
        (SMB to DB tier from user
        workstations was the entire Stage 3
        mechanism), tiered ACLs.
  MT-4  Memory forensics readiness:             F4       16h     IR Team
        capture tooling and runbooks on
        high-value hosts (DC, DB tier);
        validated by drill, not by incident.
  MT-5  Privileged access management:           F4,F5    120h    IT+Mgmt
        vaulting, JIT elevation, and
        harvested-identity alerting
        (authentication attempts on a
        phished identity within minutes of
        a reported submission -- closes the
        17-minute pre-rotation blind window
        from Task 0 Q7).
  MT-6  Log-retention and egress-data           F7,F12   24h     SOC+Net
        architecture policy: codify the
        >= 180-day log and >= 90-day DNS
        retention, and move firewall
        session exports from forensic-only
        to continuously-alerted telemetry.

  Medium-term total: 6 actions, ~280h effort plus ongoing.

================================================================
SUMMARY
================================================================
  Immediate:     7 actions, ~23h    (largely parallelizable)
  Short-term:    7 actions, ~100h
  Medium-term:   6 actions, ~280h + 1 ongoing program
  Total:         20 remediation items, ~403h plus the hunt program

  Sequencing constraints honored:
    - IM-1 (imaging) precedes IM-7 (rotation): artifact
      preservation over credential hygiene, per the May 12
      lesson in reverse.
    - ST-1 (off-host logging) outranks every other short-term
      item: it is the control whose absence was weaponized.
    - MT-2 pairs detection maturity with containment SLAs:
      the reconstruction's hardest finding is that detection
      SUCCEEDED and the data still left.

  Each action traces to a specific reconstruction finding
  (F1-F12) and, through them, to ATT&CK techniques and source
  evidence. No action exists without evidence-based
  justification.

================================================================
HEADER

echo "Script execution complete. Remediation plan generated."
