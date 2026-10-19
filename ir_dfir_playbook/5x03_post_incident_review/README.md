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

# [3. Write the Sigma Rule: PowerShell LOLBin Proxy Execution](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x03_post_incident_review/sigma_powershell_msbuild_lolbin.yml)

## Goal: 

Encode the initial execution technique as a detection rule that fires on the next attempt.

## Context: 

The attacker used msbuild.exe spawned by PowerShell to execute malicious inline C# without dropping a traditional executable. The detection did not exist before this incident.

## Instructions: 

Write a valid Sigma rule sigma_powershell_msbuild_lolbin.yml that detects msbuild.exe (or other trusted developer utilities) spawned by PowerShell or script host processes.

Required rule fields:

    title, id (UUID v4), status (test), description, references, author, date, tags

    logsource.category: process_creation and logsource.product: windows

    detection using ParentImage|endswith for PowerShell variants and Image|endswith for MSBuild and related LOLBins (reference the LOLBAS project for the full list)

    falsepositives: at least two specific, realistic false positive scenarios

    level: high

Validate syntax with sigma-cli check or yamllint. Document the ATT&CK technique in the tags field.

**Expected output**

```yml
title: PowerShell Spawning Trusted Developer Utility (LOLBin Proxy Execution)
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: test
description: ...
references:
  - ...
  - ...
author: <your_name>
date: <YYYY-MM-DD>
tags:
  - ...
  - ...
  - ...
logsource:
  category: ...
  product:...
detection:
  selection_parent:
    ParentImage|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
  selection_child:
    Image|endswith:
      - '\MSBuild.exe'
      - '\csc.exe'
      - '\vbc.exe'
      - '\jsc.exe'
  condition: selection_parent and selection_child
falsepositives:
  - ...
  - ...
level: ...
```

---

# [4. Write the Sigma Rule: MSBuild C2 Beaconing](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x03_post_incident_review/sigma_msbuild_network_connection.yml)
### advanced

## Goal: 

Detect the C2 communication channel opened by the LOLBin at the network level.

## Context: 

Writing two complementary rules for the same attack chain is how detection teams build layered coverage. If the process creation rule is evaded, the network rule catches the next step.

## Instructions: 

Write a valid Sigma rule sigma_msbuild_network_connection.yml that detects msbuild.exe initiating an outbound network connection.

Required fields: same structure as Task 3.

    logsource.category: network_connection and logsource.product: windows

    detection targeting Image|endswith: '\MSBuild.exe' with Initiated: 'true'

    Add a filter to reduce false positives from legitimate build activity: exclude connections to private RFC 1918 address ranges and to known NuGet/package manager CDN ranges (document your exclusion logic in comments)

    falsepositives: at minimum two specific scenarios involving legitimate MSBuild network activity

    level: medium (slightly lower than T3 because legitimate build systems generate similar events)

Document in a comment block at the top of the file why this rule is medium while the process creation rule is high.

**Expected output**

```yaml
# Rule: MSBuild C2 Network Connection
# Level rationale: Set to medium because MSBuild legitimately makes network connections
# during NuGet restore and package manager operations from developer workstations.
# This rule should be deployed alongside sigma_powershell_msbuild_lolbin.yml for layered coverage.
# A medium + high correlation (both rules firing for the same host within 5 minutes)
# should be escalated as high confidence.

title: MSBuild Initiating Outbound Network Connection
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: test
description: ...
...
detection:
  selection:
    Image|endswith: '\MSBuild.exe'
    Initiated: 'true'
  filter_rfc1918:
    DestinationIp|startswith:
      - '10.'
      - '172.16.'
      - '192.168.'
  filter_localhost:
    DestinationIp:
      - '127.0.0.1'
      - '::1'
  condition: selection and not filter_rfc1918 and not filter_localhost
falsepositives:
  - ...
  - ...
level: ...
```

---

# [5. Validate Your Detection Rules Against Real and Clean Data](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x03_post_incident_review/validate_rules.sh)

## Goal: 

Prove your rules fire on the attack, do not flood the queue on normal traffic, and tune any false positives before production.

## Context: 

A rule that was never tested is not a detection. It is a hypothesis. This task is where hypotheses become deployable rules.

## Instructions: 

Write validate_rules.sh. The script tests both Sigma rules from Tasks 3 and 4 against two provided log samples using sigma-cli or a compatible log matching tool.

Provided samples:

    incident_sysmon.jsonl: Sysmon process creation and network connection events from WST-WS-031 and WST-WS-017 during the incident window (02:40Z to 04:00Z on 2026-04-14)

    clean_sysmon.jsonl: 30-day Sysmon baseline from a representative clinical workstation class at MedDefense (no known incidents; includes developers running legitimate builds via Visual Studio and MSBuild)

For each rule and each sample, the script reports:

    Number of events matched

    Match rate as a percentage of total events in the sample

    For the clean sample only: a list of matched events summarizing the false positive pattern (if any)

After running the script, document your findings and any tuning decisions in rule_validation_report.md:

    Did the rule fire on the incident data? (expected: yes)

    What was the false positive rate on the clean baseline? (target: under 0.1 percent of total events)

    If the false positive rate exceeded the target, document what you changed in the rule and why

The tuned versions of the Sigma files replace the originals. Every change is noted in the report.

**Expected output**

```bash
$ ./validate_rules.sh

  [incident_sysmon.jsonl]
  Total events: 4,812
  Matches: 2
  Match rate: 0.042%
  Verdict: PASS (expected matches on PID 8104 at 02:46:58Z and PID 9201 at 03:27:13Z)

  [clean_sysmon.jsonl]
  Total events: 287,341
  Matches: 0
  False positive rate: 0.000%
  Verdict: PASS

  [incident_sysmon.jsonl]
  Total events: 4,812
  Matches: 2
  Match rate: 0.042%
  Verdict: PASS

  [clean_sysmon.jsonl]
  Total events: 287,341
  Matches: 14
  False positive rate: 0.005%
  Verdict: REVIEW : 14 matches are MSBuild NuGet restore connections to api.nuget.org
  Action: adding filter for DestinationHostname|endswith '.nuget.org'; re-running

  [clean_sysmon.jsonl after tuning]
  Matches: 0
  False positive rate: 0.000%
  Verdict: PASS
```

---

# [6. Update the Hardening Specification](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x03_post_incident_review/hardening_updates.md)

## Goal: 

Translate incident findings into specific, deployable configuration changes.

## Context: 

Hardening changes driven by evidence are the ones that survive budget reviews. Each change here links to a finding that justifies it.

## Instructions: 

Create hardening_updates.md. For each recommended change, specify: the control, the exact configuration, the gap it closes (by Gap ID from Task 2), and the validation test that confirms the change is in effect.

    Use Gap IDs from Task 2 and incident evidence from forensic_findings_summary.md.

Cover at minimum these four controls:

    PowerShell Constrained Language Mode for non-administrative user accounts: blocks [System.Management.Automation.ScriptBlock]::Create and .NET type loading that LOLBin techniques depend on. Document the GPO path and registry key.

    AppLocker or Windows Defender Application Control rule for MSBuild.exe: restrict execution of MSBuild.exe to members of BUILTIN\Administrators and named CI/CD service accounts. Document the rule XML structure.

    Conditional access policy for VPN authentication from new geographies: block or require step-up MFA when a VPN login originates from a country not previously seen for that account in the prior 30 days. Document the policy logic.

    Windows Credential Guard: prevents LSASS credential extraction by isolating credential material in a hypervisor-protected memory region. Document the enablement path and which Windows versions support it.

For each control, close with: the Gap IDs it addresses and a one-line validation test (a command or observable that confirms the control is active).

**Expected output**

<pre>
# Hardening Updates: IR-2026-0414-01

## HRD-001: PowerShell Constrained Language Mode

**Closes:** GAP-003, GAP-004
**Configuration:**
- GPO: Computer Configuration > Preferences > Windows Settings > Registry
- Key: HKLM\System\CurrentControlSet\Control\Session Manager\Environment
- Value name: __PSLockdownPolicy
- Value type: REG_SZ
- Value data: 4

**Effect:** Restricts PowerShell to Constrained Language Mode for standard users; blocks .NET type instantiation, COM object creation, and script block execution used in LOLBin proxy techniques.

**Applies to:** Non-administrative accounts on all clinical and administrative workstations.

**Validation:** Run `$ExecutionContext.SessionState.LanguageMode` as a standard user; expected output: ConstrainedLanguage

---

## HRD-002: AppLocker rule restricting MSBuild.exe
...
</pre>

---
