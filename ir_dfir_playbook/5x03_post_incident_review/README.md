# Introduction

> "Learning is not compulsory… neither is survival." 
>
> — W. Edwards Deming

The incident is over. The forensic report is delivered. Most organizations stop here. The ones that do not are the ones that are harder to breach the next time.

In this project you close the loop on the incident. You audit every control that should have fired and assess why some did not. You identify the exact gaps. You write detection rules that target the observed TTPs, then test them against real and clean data to confirm they work without flooding the queue. You enrich the incident IOCs with open-source threat intelligence to understand who you were dealing with and what they typically do next. You update the hardening baseline, the risk register, and the IR playbooks with specific, evidence-driven changes. You deliver an implementation package another engineer can execute.

The output is not a list of recommendations. It is a set of artifacts that actually change the organization's posture.

## Why this matters

Post-incident improvement is where most organizations fail. The PIR happens, a slide deck is presented, a few action items are assigned with no owners or deadlines, and six months later the same gaps exist. The next incident finds exactly the same holes.

The professionals who build durable defenses know how to close this loop. They write the detection rule, test it before it goes to production, and verify it fires on the next real event. They update the playbook before the next incident, not during it. They use threat intelligence to anticipate the next move instead of reacting to the last one. They put numbers and owners and deadlines on improvements and then verify those improvements worked.

This is the work that compounding returns in defense are built on. One incident, handled well, makes the organization measurably harder to compromise. That is the professional difference between maintaining a SOC and building one.

## Context

The forensic report is in Helena Reyes's inbox. Dr. Patricia Morales has briefed the board. James Chen has opened the post-incident review and assigned it to you.

The question is no longer what happened. The question is: why did this get as far as it did, and what specifically changes now?

Chen's guidance: "Give me things we can actually deploy. Not slides. Not awareness posters. Rules that run, configs that change, playbook text that is better than it was."

---

# 0. Quiz

---

# [1. Audit Control Effectiveness](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x03_post_incident_review/control_effectiveness.yaml)

## Goal: 

Map every phase of the incident against the controls that should have acted and assess whether they did.

## Context: 

You cannot close a gap you have not measured. The audit is the measurement.

## Instructions: 

Create control_effectiveness.yaml. For each phase of the incident, document the controls expected, the controls that fired, the controls that missed, and the gap severity.

    Use forensic_findings_summary.md from the lab materials as the source evidence for the incident phases, observed attacker actions, missed controls, and findings.

Structure:

<pre>
phase: <incident phase name>
att_ck_technique: <T-number>
controls_expected: [list of controls that should exist for this phase]
controls_fired: [controls that triggered or acted during the incident]
controls_missed: [controls that should have acted but did not, or did not exist]
gap_severity: <critical | high | medium | low>
gap_reason: <one-line explanation>
</pre>

Cover at minimum these six phases drawn from the incident:

    Credential phishing and submission (T1566.002 + T1078)

    VPN access using stolen credentials from a foreign IP

    PowerShell → MSBuild LOLBin execution (T1127.001)

    C2 beaconing to external IPs (T1071.001)

    LSASS credential access and Kerberos ticket extraction (T1003.001 + T1558.003)

    Lateral movement and PHI access (T1550.003 + T1078)

**Expected output**

```yaml
- phase: <incident phase name>
  att_ck_technique:  <T-number>
  controls_expected:
    - [list of controls that should exist for this phase]
    - [list of controls that should exist for this phase]
    - [list of controls that should exist for this phase]
  controls_fired:
    - [controls that triggered or acted during the incident]
  controls_missed:
    - [controls that should have acted but did not, or did not exist]
    - [controls that should have acted but did not, or did not exist]
    - [controls that should have acted but did not, or did not exist]
  gap_severity:  <critical | high | medium | low>
  gap_reason: <one-line explanation>

- phase: <incident phase name>
  att_ck_technique:  <T-number>
  controls_expected:
    - [list of controls that should exist for this phase]
    - [list of controls that should exist for this phase]
    - [list of controls that should exist for this phase]
  controls_fired:
    - [controls that triggered or acted during the incident]
  controls_missed:
    - [controls that should have acted but did not, or did not exist]
    - [controls that should have acted but did not, or did not exist]
    - [controls that should have acted but did not, or did not exist]
  gap_severity:  <critical | high | medium | low>
  gap_reason: <one-line explanation>
```

---

# [2. Gap Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x03_post_incident_review/gap_analysis.md)

## Goal: 

Translate the control audit into a prioritized list of improvements, each bounded enough to assign and track.

## Context: 

A gap that cannot be assigned to an owner and measured is not a gap analysis. It is a wishlist.

## Instructions: 

Create gap_analysis.md with a structured table and a priority summary.

    Use control_effectiveness.yaml plus forensic_findings_summary.md.

The table must have these columns:

    Gap ID (GAP-001 through GAP-N)

    Phase (from Task 1)

    Gap description (what is absent or broken)

    Control category (preventive / detective / corrective)

    Recommended improvement (specific, actionable, not generic)

    Priority (P1 critical / P2 high / P3 medium)

    Linked findings (evidence or task reference)

After the table, add a Priority summary section listing only the P1 gaps with a one-line rationale for each.

Constraints:

    Descriptions must be specific to MedDefense, not generic.

    Recommendations must name the specific control, tool, or configuration change, not a category.

    At minimum eight gaps derived from the Task 1 audit.

**Expected output**

<pre>
# Gap Analysis: IR-2026-0414-01

## Gap Register
</pre>

| Gap ID | Phase | Gap Description | Control Category | Recommended Improvement | Priority | Linked Findings |
|---|---|---|---|---|---|---|
| GAP-001 | <incident phase name> | < description> | <preventive / detective / corrective> | <actionable action> | <P1/P2/P3> | control_eff phase 1 |
| GAP-002 | <incident phase name> | < description> | <preventive / detective / corrective> | <actionable action> | <P1/P2/P3> | control_eff phase 1 |
| GAP-003 | <incident phase name> | < description> | <preventive / detective / corrective> | <actionable action> | <P1/P2/P3> | control_eff phase 1 |
| … | … | … | … | … | … | … |

<pre>
## Priority summary

- **GAP-001** (P1): Credential theft went fully undetected; a proxy alert rule would have flagged the harvesting attempt at the earliest stage of the attack.
- **GAP-002** (P1): Foreign-IP VPN access is the point where a single control — conditional MFA — would have stopped the entire intrusion chain.
- ...
</pre>

---
