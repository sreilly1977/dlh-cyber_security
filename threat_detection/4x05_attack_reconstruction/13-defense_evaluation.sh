#!/bin/bash
# Name: 13-defense_evaluation.sh
# Purpose: Defensive posture evaluation for MedDefense across three
#          snapshots (pre-4x00 Module 3 baseline, post-4x04 hunt,
#          post-4x05 reconstruction). Assesses every detection
#          capability deployed through Module 4 (4x00 email rules,
#          4x02 YARA, 4x03 behavioral/mutex indicators, 4x04 hunting
#          rules) against the HEALTHBANE attack at its relevant
#          stage (YES/NO/PARTIAL with root cause), identifies the
#          structural failures (no schtasks monitoring, no staging
#          detection, no secondary C2 detection, T1070.001 log
#          clearing unseen, DNS telemetry absent, detection-to-
#          containment lag), and emits a technique-vs-capability
#          gap matrix plus recommended new rules. Corrects template
#          claims that conflict with the verified reconstruction
#          (patient-zero delivery succeeded; the hunt saw one of
#          three pivots; exfiltration completed post-detection).
# Author: Steve - Cybersecurity Engineer
# Date: 06 October 2026

set -u

P0="previous_findings/4x00_phishing_summary.txt"
P2="previous_findings/4x02_attack_mapping.json"
P3="previous_findings/4x03_malware_summary.txt"
P4="previous_findings/4x04_hunting_report.txt"
MEM="ir_evidence/memory_artifacts.txt"
DSK="ir_evidence/disk_forensics_report.txt"
FWJ="ir_evidence/firewall_sessions_ws_recv_03.json"
NOTES="ir_evidence/ir_team_notes.txt"
NAVUPD="10-navigator_update.json"

die() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

for f in "$P0" "$P2" "$P3" "$P4" "$MEM" "$DSK" "$FWJ" "$NOTES"; do
  [[ -f "$f" ]] || die "missing $f"
done
[[ -f "$NAVUPD" ]] || printf 'NOTE: %s absent; matrix drawn from Task 9 inventory directly.\n' "$NAVUPD"

# Gates: tokens verified in source files (tasks 0-12 runs).
req() { grep -Fqi -- "$2" "$1" || die "verification failed in $1: $2"; }
req "$P0" "dmarsh"
req "$P2" "T1550"
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
   DEFENSIVE POSTURE EVALUATION
   Attack window: 2026-04-14 -> 2026-05-15 (31 days)
   Evidence basis: Tasks 0-12 verified reconstruction
================================================================

DETECTION POSTURE EVOLUTION (coverage against the eventual
29-technique reconstruction):

  Snapshot              Coverage   Could see               Could not see
  Pre-Module (Wk 10)    ~15% (est) perimeter events,     everything below
                                   mail flow (family      the perimeter;
                                   level only), basic     on-host behavior,
                                   SIEM/host AV          LOLBin abuse, C2
                                                         in TLS, staging
  Post-Hunt  (Wk 16)    ~79%       initial access         objective phase:
                                   telemetry, malware     staging, archival,
                                   families (YARA/mutex), exfiltration; TWO
                                   ONE lateral pivot      of THREE pivots;
                                                         scheduled tasks
  Post-Recon (Wk 17)    96.6%      the full observable    what happened ON
 (mapping, not live)    (28/29      chain end-to-end,     the two unimaged
                        confirmed)  byte-exact exfil       hosts; T1078 use
                                   truth                (destroyed logs)

  IMPORTANT CAVEAT: the 96.6% is FORENSIC coverage (what the
  evidence can prove), not DETECTION coverage. The post-hunt
  LIVE detection coverage was materially lower -- see the gap
  matrix below.

WHAT WORKED (with corrections to the guideline's claims):

  [*] Mail-security capability: REAL but retrospective for
      patient zero. The 2026-04-14 lure was DELIVERED to
      dmarsh and opened -- the compromise itself proves it.
      The 4x00 header/content rules were BUILT FROM this
      campaign's dissection; they would catch the family on
      re-delivery. Credit: analytic capability, not prevention
      of the actual initial access.

  [*] 4x02 YARA rules (dropper signature): YES for the .docm
      family IF scanned on delivery -- but no gateway/mail
      file-scanning integration was evidenced in the package.
      Capability existed on paper; deployment path unclear.
      Rating: PARTIAL (rule logic sound, pipeline gap).

  [*] 4x03 behavioral indicators (mutex HealthSyncSingleton,
      RC4 config pattern, C2 URI shape): would have caught the
      RAT on execution ON A MONITORED HOST. They did not fire
      during the incident because WS-RECV-03 lacked the
      telemetry feed they depend on. Rating: NO in practice,
      YES in design -- evidence-type mismatch between rule
      requirement (process/memory events) and available
      telemetry (none from that workstation tier).

  [*] 4x04 proactive hunt: the ONLY control that found the
      operator in near-real-time. Detected the PsExec pivot
      (service-installation trail). Rating: YES for PsExec,
      NO for the WMI and WinRM pivots (no service-install
      telemetry from those mechanisms) -- found one of
      three lateral paths. Detection anchoring bias: the hunt
      hypothesis keyed on the tool that shouts loudest.

  [*] Containment itself: isolation on 2026-05-15 terminated
      the live secondary-C2 socket and the projected fourth
      wave. Late but effective.

WHAT FAILED (each tied to evidence):

  [*] No scheduled-task creation monitoring -> T1053.005
      (daily 02:00 task, created ~2026-05-07, ran THROUGH
      the entire hunt-and-detect period undetected; it drove
      staging on at least 2-3 runs).
  [*] No data staging detection -> T1074.001/T1560.001
      (three archives in C:\Users\Public\Tmp\ built and
      deleted over 6 days with zero alerts).
  [*] No secondary C2 detection -> 203.0.113.47:8443 was
      STILL ACTIVE at the moment of memory capture; no rule,
      hunt, or firewall alert ever flagged it.
  [*] T1070.001 log clearing on 2026-05-09 went unnoticed
      for six days, until disk forensics -- because logs were
      resident on the host the adversary controlled.
  [*] Detection-to-containment LAG: the operator was found
      (hunt) before the objective phase completed, yet ALL
      THREE exfiltration waves (05-08, 05-11, 05-13) and the
      05-09 log clearing occurred AFTER detection. Detection
      without prompt containment did not prevent the breach.
      (Exact detection date unverifiable, D6/U4 -- but the
      ordering holds for any date on/before 05-08.)
  [*] DNS telemetry absent -> the 4x01 DNS channel test and
      the Apr 15 beacon remained client-attribution-blind
      (VLAN-3-wide PCAP); a resolver log would have answered
      WHO, not just WHAT.
  [*] Forensic imaging gaps: two compromised servers were
      never imaged; residual-artifact loss risk is ACTIVE
      (Task 11/12 recommendation stands).

STRUCTURAL LESSONS (board-facing):

  [1] Signature/family rules catch KNOWN patterns. This
      operator used LOLBins and living-off-the-land craft
      (schtasks, WMI, WinRM, run keys) largely outside every
      deployed rule set.
  [2] Hunting is the countermeasure for unknown patterns --
      but it inherits its hypothesis's blind spots. The hunt
      saw the pivot its hypothesis anticipated; two pivots
      in the same phase stayed invisible for the same class
      of reason (missing service-installation telemetry).
  [3] Forensic evidence (memory, disk) reveals what rules and
      hunts cannot see in real-time -- AFTER the fact. It
      closes the historical record, not the incident.
  [4] No single evidence type covers the chain. Mail logs
      explained entry; PCAP explained transport; memory
      explained tools; disk explained objectives; firewall
      tied them together byte-exactly. Layered collection is
      not optional.
  [5] The scarcest resource was TIME-TO-ACTION, not detection
      capability. The operator was found mid-campaign and the
      data still left. Containment SLAs deserve the same
      engineering rigor as detection engineering.
  [6] Defense survives adversary action only if telemetry
      lives OFF the compromised host. The 05-09 log wipe
      weaponized log locality.

DETECTION GAP MATRIX (technique x capability at incident time;
  E=Email rules  Y=YARA  S=Suricata/perimeter  H=Hunt  F=Forensic):
  Technique           E     Y     S     H     F     Status
  T1566.001 phishing  YES   ---   ---   ---   ---   COVERED*
                                                    (*retro:
                                                    pt-zero
                                                    delivered)
  T1203 macro exec    ---   PART  ---   ---   YES   WEAK
  T1071.001 C2 http   ---   ---   PART  ---   YES   WEAK
  T1105 ingress tool ---   YES   ---    ---   YES   PARTIAL
  T1053.005 schtask  ---   ---   ---    NO    YES   GAP
  T1547.001 run key   ---   ---   ---   NO    YES   GAP
  T1003.001 LSASS     ---   ---   ---   NO    YES   GAP
  T1021.002 PsExec    ---   ---   ---   YES   YES   COVERED
  T1047 WMI pivot     ---   ---   ---   NO    YES   GAP
  T1021.006 WinRM piv ---   ---   ---   NO    YES   GAP
  T1070.001 log clr   ---   ---   ---   NO    YES   GAP
  T1074.001 staging   ---   ---   ---   NO    YES   GAP
  T1560.001 archive   ---   ---   ---   NO    YES   GAP
  T1041 exfil (C2)    ---   ---   NO**  NO    YES   GAP
  2nd C2 203.0.113.47 ---   ---   NO    NO    YES   GAP
                                                    (**bytes
                                                    EXISTED in
                                                    firewall
                                                    export; no
                                                    ALERT fed
                                                    on them)
  T1078 acct use      ---   ---   ---   ---   N/A   UNKNOWN
                                                     (logs destroyed)

  Matrix verdict: forensic column proves the chain; the live
  columns (E/Y/S/H) cover INITIAL ACCESS and ONE pivot. The
  entire objective phase was forensics-only.

NEW RULES RECOMMENDED (priority-ordered):

  [1] Sysmon EventID 4698/1 or native 4698 audit: alert on
      scheduled-task creation, esp. actions invoking
      powershell.exe -enc, running as SYSTEM, from
      non-admin contexts. Closes T1053.005 (cost of miss:
      the entire staging engine).
  [2] Sysmon EventID 11: alert on archive/CSV creation in
      C:\Users\Public\ (or equivalent world-writable temp)
      by non-standard parent processes. Closes T1074.001/
      T1560.001 (cost of miss: 34.4 MB of PHI).
  [3] Centralized off-host Windows Event Log forwarding,
      near-real-time, >= 180 day retention. Closes the
      T1070.001 residency failure and the T1078 UNKNOWN.
      HIGHEST priority of all: it is the one control whose
      absence the adversary actively weaponized.
  [4] Egress anomaly alert: cumulative bytes-out per host
      per day vs 30-day baseline (the data to compute it
      ALREADY EXISTS in the firewall exports; no new
      collector needed). Closes T1041 detection. Cost of
      miss: three waves totaling 34 441 660 B left unalerted.
  [5] New-external-destination alert for internal hosts:
      any first-contact external IP/port from a
      workstation-tier asset, feeding the SOC. Closes the
      secondary-C2 blind spot (203.0.113.47:8443 live for
      days post-detection).
  [6] Passive DNS/resolver logging with client attribution,
      retained >= 90 days. Closes the attribution half of
      the T1071.004 gap.
  [7] Deploy the 4x03 behavioral rules TO a monitored
      pipeline (Sysmon/WEL on workstation tier). The rules
      were sound; the telescope was never pointed at the
      sky that mattered.
  [8] Pair every future hunt with a CONTAINMENT SLA:
      detection of an active operator must trigger scoped
      isolation criteria within hours, not days.

================================================================
HEADER

echo "Script execution complete. Defensive posture evaluation generated."
