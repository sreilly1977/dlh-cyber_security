# HEALTHBANE Stage 4 Threat Hunting Report

**Project:** 4x04 Threat Hunting — Detection Gap Closure

**Classification:** Internal — MedDefense Security Operations

**Author:** Steve Reilly, Cybersecurity Engineer

**Date:** 05 October 2026

**Requested by:** James Chen, Security Operations Lead

**Audience:** SOC technical review and Dr. Morales / Executive Board

---

## 1. Executive Summary

### What Was Hunted and Why

Following Project 4x03's malware triage, HC3 threat intelligence identified
HEALTHBANE Stage 4 — lateral movement using legitimate administrative tools
(PsExec, WMI, PowerShell Remoting) and stolen service-account credentials —
as the attack phase in which intrusion becomes breach: attacker reach
extends from a single compromised workstation to core database
infrastructure. Our ATT&CK mapping showed six Stage 4 techniques with no
automated detection coverage: PsExec (T1021.002), WMI (T1047), LSASS
memory access (T1003.001), PowerShell Remoting (T1021.006), Domain
Accounts (T1078.002), and Pass-the-Hash (T1550.002). This hunt tested
whether that blind spot hid live adversary activity in the MedDefense
environment.

### Key Finding

**Yes — HEALTHBANE Stage 4 occurred in the MedDefense environment.**
Targeted hunts across Sysmon process, authentication, and network telemetry
confirmed every tested hypothesis (H1–H5): an attacker operating from
workstation WS-RECV-03 used the stolen `svc_healthsync` service account to
move laterally to three servers, dumped LSASS memory with a staged
credential-harvesting tool, and executed commands remotely via WMI and
PowerShell Remoting — all through tools and protocols that legacy
signature-based detection treats as legitimate administration.

### Impact Assessment

| System | Role | Attacker Reach |
|---|---|---|
| WS-RECV-03 | Workstation (patient records intake) | Patient intake workstation (entry point) |
| SRV-HEALTH-DB | Core health database server | Remote code execution via PsExec, WMI, WinRM |
| SRV-INS-DB | Insurance billing database server | Remote code execution via PsExec, WMI, WinRM |
| SRV-DC-01 | Domain controller | PsExec service installation reached |

Potentially exposed data: patient health records (SRV-HEALTH-DB) and
insurance/billing data (SRV-INS-DB). LSASS memory access on WS-RECV-03
means all credentials resident in that process — potentially including
domain-level accounts — should be considered compromised. The reach to
SRV-DC-01 indicates attempted reconnaissance or persistence against the
domain tier, raising organizational risk well beyond individual databases.

### Remediation Status

Five hunt-derived detection rules are drafted and validated against the
legitimate-activity baseline (zero false positives across all 93 baseline
events for four of five rules): four Wazuh endpoint rules and one Suricata
network rule. ATT&CK coverage improved from **48% (14/29 techniques) to
69% (20/29)**, closing the detection blind spot for all six Stage 4
techniques listed above. Immediate containment recommendations for
WS-RECV-03 and the `svc_healthsync` account are in Section 7.

> **Note on coverage figures:** Earlier 4x03 documentation cited 16/29
> (55%) pre-hunt coverage. The machine-readable 4x03 ATT&CK layer, when
> decoded, contains 14 observed techniques (48%). This report uses the
> layer figures as the single source of truth; the two-technique variance
> stems from narrative classifications made before the layer's final
> coloring and is documented in the 4x04 Task 11 output.

---

## 2. Hunt Methodology

### Hypothesis-Driven Approach

The hunt followed the intelligence-to-query pipeline rather than
open-ended anomaly browsing:

1. **Threat model (4x02/4x03):** HC3 advisory mapped to ATT&CK techniques;
   campaign stage narrative built for HEALTHBANE Stages 1–4.
2. **Gap analysis (Task 3):** Six Stage 4 techniques with no detection
   coverage identified from the 4x03 attack mapping.
3. **Baseline establishment (Task 2):** Robert Kim (MEDDEFENSE domain
   admin) profiled over two weeks — 93 legitimate events defining normal
   admin behavior: business hours, WS-ADMIN-01 as source, interactive
   admin accounts.
4. **Targeted queries (Tasks 4–9):** Five hypotheses (H1–H5), each a
   falsifiable statement about attacker behavior, tested with specific
   jq selectors against Sysmon/security/network telemetry.
5. **Timeline reconstruction (Task 10):** Correlated findings into a
   session-by-session chronology.
6. **Detection engineering (Tasks 11–13):** Findings translated into
   deployable rules; ATT&CK coverage updated and verified against source
   layers.

### Data Sources

- Sysmon operational logs (process creation Event 1, process access
  Event 10) — workstations and servers
- Windows Security event logs (interactive logon 4624, service
  installation 7045)
- Network flow and protocol telemetry (SMB/445, WinRM/5985-5986)
- Reference material: HC3 advisory, 4x03 ATT&CK mapping, authorization
  matrix for service accounts, Robert Kim activity baseline

### Baseline Establishment (Robert Kim Profile)

Legitimate administration at MedDefense concentrates around one domain
admin working business hours from one admin workstation. Critically for
hypothesis testing, the baseline contains **zero** occurrences of:
PsExec from any source other than WS-ADMIN-01, off-hours PsExec,
service-account usage by interactive admins, LSASS access from
non-system processes, service-account logons from workstations, and
WMI shell-spawning events. Every anomalous finding below therefore
represents a behavioral departure with no false-positive precedent.

---

## 3. Findings per Hypothesis

| # | Hypothesis | Status | Evidence | Confidence |
|---|---|---|---|---|
| H1 | PsExec lateral movement from non-admin source using service account, off-hours | **CONFIRMED** | 12 anomalous PsExec events: source WS-RECV-03, user `svc_healthsync`, off-hours, targets SRV-HEALTH-DB / SRV-INS-DB / SRV-DC-01 | High |
| H2 | LSASS memory dumping from staged tool in writable path | **CONFIRMED** | 2 unique `debug_tool.exe` process-access events on WS-RECV-03 against lsass.exe with 0x1010 (read) mask, binary staged in `C:\Windows\Temp` | High |
| H3 | WMI remote execution spawning shells on servers | **CONFIRMED** | 4 anomalous `wsmprovhost.exe` events on SRV-HEALTH-DB and SRV-INS-DB during attack sessions | High |
| H4 | PowerShell Remoting (WinRM) lateral movement | **CONFIRMED** | `Enter-PSSession` as `svc_healthsync`; `Copy-Item` of `sync_healthdata.ps1` to `C:\Windows\Temp` on database servers | High |
| H5 | Service-account credential misuse via NTLM from unauthorized host | **CONFIRMED** | 6 `svc_healthsync` NTLM logons with workstation-source `WS-RECV-03`, violating authorization matrix rules 1–3 (May 6, 9, 13) | High |

Confidence is assessed High across all hypotheses: multiple independent
log sources corroborate the same actor, account, and host cluster, with
baseline evidence confirming none of the activity matches legitimate
patterns.

---

## 4. Reconstructed Attack Timeline (Task 10)

> Timestamps below reflect Task 10 correlation; session-level detail and
> exact clock times are preserved in the Task 10 output.

| Phase | Event | Evidence |
|---|---|---|
| 1. Initial foothold | Attacker controls WS-RECV-03 (patient intake workstation) via earlier HEALTHBANE stages | Working assumption from Stages 1–3 (4x02/4x03) |
| 2. Credential access | `debug_tool.exe` (staged in `C:\Windows\Temp`) accesses lsass.exe with 0x1010 read mask on WS-RECV-03; `svc_healthsync` credentials harvested | Sysmon Event 10; Task 6 (H2) |
| 3. Credential misuse begins | First workstation-source NTLM logons as `svc_healthsync` from WS-RECV-03 — May 6 | Event 4624; Task 9 (H5) |
| 4. Lateral movement — SMB | PsExec (PsExec64.exe from `C:\Users\Public\Downloads`) installs services on SRV-HEALTH-DB, SRV-INS-DB, SRV-DC-01; 12 events total | Sysmon Event 1 / Event 7045; Task 4 (H1) |
| 5. Lateral movement — WMI | `wsmprovhost.exe` execution on SRV-HEALTH-DB and SRV-INS-DB; 4 shell-spawning events | Sysmon Event 1; Task 5 (H3) |
| 6. Persistence/staging via WinRM | `Enter-PSSession` as `svc_healthsync`; `sync_healthdata.ps1` copied to `C:\Windows\Temp` on database servers | Task 7 (H4) |
| 7. Continued credential misuse | Repeated `svc_healthsync` NTLM logons from WS-RECV-03 — May 9, May 13 | Event 4624; Task 9 (H5) |

**Kill-chain summary:** foothold → credential dump (T1003.001) →
service-account authentication abuse (T1078.002, T1550.002 indicator) →
remote services lateral movement (T1021.002, T1047, T1021.006) →
database server compromise. Every stage used native administrative
tooling, which is precisely why the pre-hunt detection stack never fired.

---

## 5. ATT&CK Update (Task 11)

### Coverage Improvement

- **Before hunt:** 14 observed / 29 total techniques (**48%**) — decoded
  from the 4x03 layer's OBSERVED color classification
- **After hunt:** 20 observed / 29 total techniques (**69%**)
- Six techniques reclassified from NOT COVERED to OBSERVED with hunt
  evidence attached; one of those (T1550.002, Pass-the-Hash) remains a
  documented hybrid: NTLM misuse observed, hash-reuse mechanism inferred

### Newly Confirmed Techniques

| Technique | Name | Pre-hunt status |
|---|---|---|
| T1021.002 | SMB/Admin Shares (PsExec) | Not covered |
| T1047 | Windows Management Instrumentation | Not covered |
| T1003.001 | LSASS Memory | Not covered |
| T1021.006 | Windows Remote Management | Not covered |
| T1078.002 | Domain Accounts | Not covered |
| T1550.002 | Pass the Hash | Not covered |

The hunt validated **6 of the 10 known coverage gaps (60%) as live
adversary behavior** — a strong argument that untested gaps in a threat
model should be presumed exploitable until hunted. Updated Navigator
layer: `healthbane_layer_v3.json` (29 techniques, four-tier legend).

---

## 6. Detection Improvements (Task 13)

Five hunt-derived rules, each with behavior, evidence citation, and
false-positive estimate derived from the Robert Kim baseline:

| Rule ID | Platform | Detection | ATT&CK | Level | FP Estimate |
|---|---|---|---|---|---|
| 100100 | Wazuh | PsExec execution from non-admin source / off-hours / service account | T1021.002 | 10 | Very Low (0 baseline events) |
| 100101 | Wazuh | LSASS access from non-system process, read masks, staging paths | T1003.001 | 12 | Very Low (0 baseline events) |
| 100102 | Wazuh | Service-account logon from workstation source (NTLM) | T1078.002, T1550.002 | 12 | Very Low (0 baseline events) |
| 100103 | Wazuh | WMI providers spawning cmd/powershell children | T1047 | 8 | Medium (legitimate remote-tool overlap) |
| 9000030 | Suricata | SMB service-control pipe pattern (\pipe\svcctl, \pipe\atsvc) from non-designated source, off-hours | T1021.002 | P1 | Low (patch deployments filtered by source host + hours) |

Full rule definitions, baseline logic, and hunt-evidence citations are in
the Task 13 script output. All five close detection gaps that previously
allowed the confirmed Stage 4 activity to pass unalerted. Four of five are
estimated very-low/zero false positive against the baseline; Rule 100103
requires tuning before full deployment.

---

## 7. Remaining Gaps and Recommendations

### Still Unknown (the uncovered ~31%)

Nine techniques in the v3 layer remain unconfirmed/unobserved. These
include areas where we retain no behavioral visibility, and the 4x03
"threat model without visibility" bucket that the hunt did not touch.
Notably absent from confirmed coverage: cloud-based exfiltration
channels, scheduled-task/registry persistence, and several
defense-evasion families. These should drive the next hunting cycle.

### Immediate Actions (0–2 weeks)

1. **Incident response on WS-RECV-03** — isolate and forensically image;
   bridge to Module 5 IR procedures. Assume the host is fully compromised.
2. **Credential reset:** `svc_healthsync` and every account resident in
   WS-RECV-03's LSASS at dump time (assume domain-level exposure).
3. **Verify integrity** of SRV-HEALTH-DB and SRV-INS-DB, including
   `C:\Windows\Temp\sync_healthdata.ps1` and any installed services
   (PsExec PSEXESVC remnants).

### Short-Term (2–8 weeks)

4. Rotate all service accounts; enforce the authorization matrix
   technically (source-host restrictions, deny interactive/workstation
   logon rights for svc_* accounts).
5. Privileged access review: which accounts can reach SRV-DC-01, and how
   a service account obtained that reach.
6. Deploy the five drafted rules to production after peer review and
   baseline regression testing (target: zero FPs on the 93-event
   Robert Kim profile).

### Medium-Term (2–6 months)

7. Full Sysmon deployment with standardized configuration across all
   endpoints and servers (process access auditing everywhere, not just
   where currently configured).
8. Behavioral analytics feeding the baseline: extend the Robert Kim
   profiling approach to continuous, automated baselining of admin
   accounts — the manual version of this proved decisive for the hunt.
9. Recurring hunting cadence: quarterly hypothesis-driven hunts against
   the remaining nine uncovered techniques.

---

## 8. Lessons Learned

**Why 48% ATT&CK coverage created a false sense of security.** Coverage
statistics measure what we have seen and mapped, not what adversaries do.
Six techniques were known threat-model items with zero detection — and
six turned out to be exactly what the attacker used. Worse, the
documented figure itself (55%) overstated reality (48%) because narrative
counts drifted from the machine-readable layer. Lesson: coverage must be
computed from maintained, machine-consumable artifacts, and known gaps
must be treated as probable adversary paths, not footnotes.

**Why reactive detection alone is insufficient against LOLBin attacks.**
Every Stage 4 action used signed, native administrative tooling —
PsExec, WMI, WinRM, standard logon events. Signature-based and
alert-on-known-bad approaches are structurally blind to an attacker who
looks like an administrator. Detection of this class of tradecraft
requires behavioral baselining: who legitimately runs these tools, from
where, and when. The five new rules encode exactly that distinction,
and none of them would exist without the hunt.

**Why proactive hunting must be a recurring discipline.** This hunt
started from an intelligence hypothesis, not an alert. Had we waited for
existing detections to fire, the intrusion would likely still be
undiscovered. The cycle — hypothesize from threat intelligence, baseline
the environment, hunt, confirm or falsify, engineer detections, update
the map — measurably improved coverage from 48% to 69% in one cycle. The
next cycle starts with the nine remaining techniques: **hunt → find →
detect → hunt again.**

---

*Appendices: Task 2 baseline profile (robert_kim_activity.json), Tasks
4–9 hypothesis outputs, Task 10 timeline correlation, Task 11 layer
(healthbane_layer_v3.json), Task 13 rule drafts (13-detection_rules.sh
output), 4x03 attack mapping (reference/4x03_attack_mapping.json).*
