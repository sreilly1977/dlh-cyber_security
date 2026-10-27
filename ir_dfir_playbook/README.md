# IR/DFIR Playbook

Incident response and digital forensics study materials for a healthcare environment. Covers building the full IR capability from scratch (severity matrix, team structure, playbooks, communication templates), then running a live incident from first alert through containment, eradication, recovery validation, and handoff.

## Case Study: MedDefense

The scenario modules are built around MedDefense Health Systems, a regional healthcare organization running three hospital sites with approximately 2,000 staff. Learners take on the role of a security analyst building the baseline IR capability, then executing it against a live incident on a clinical workstation.

Supporting characters (Dr. Patricia Morales, CISO; James Chen, SOC Lead; Sarah Park, IT Director; Helena Reyes, General Counsel; Marcus Webb, Communications Director) and realistic artifacts (severity matrices, YAML playbooks, HHS OCR notification drafts, containment execution logs, eradication checklists) create an immersive, hands-on learning environment.

## Total Exercise Count

51 exercises across 6 modules

## Module Overview

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 1 | [`5x00_incident_response/`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x00_incident_response) | IR capability build: severity matrix with escalation rules, IR team structure and authority ceilings, reusable playbook template, populated playbooks (credential exposure, clinical degradation, insider access), and executive, legal, regulator, and patient communication templates aligned to 45 CFR 164.404 | 10 |
| 2 | [`5x01_Contain_Control/`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control) | Live incident execution: authoritative incident timeline, order-of-volatility evidence preservation, containment trade-off analysis and execution, eradication checklist with verification, proof-based recovery validation, and a stand-alone incident handoff package | 7 |
| 3 | [`5x02_evidence_trail/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x02_evidence_trail) | Forensic investigation of the contained WST-WS-031 incident: chain-of-custody records, memory and filesystem analysis, persistence mechanism analysis, artifact hash verification, a correlated multi-source timeline built from proxy, AD authentication, and SIEM logs, and a forensic report that withstands external scrutiny | 7 |
| 4 | [`5x03_post_incident_review/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x03_post_incident_review) | Closing the loop after the incident: control effectiveness assessment, gap analysis, Sigma detection rules written and validated against incident versus clean Sysmon telemetry, threat intel brief and IOC enrichment snapshot, playbook, risk register, and hardening updates, and an implementation package with owners and deadlines | 10 |
| 5 | [5x04_tabletop](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x04_tabletop) | Tabletop exercise (TTX) stress-testing the organization, not just the technical response: board readiness, legal and regulatory assessment under pressure, vendor communication, and business continuity decisions | 8 |
| 6 | [5x05_breach_response](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response) | Capstone live incident: an unscaffolded end-to-end response from first alert to board brief, applying the IR program, containment discipline, forensic rigor, and HIPAA breach assessment built across all prior modules | 13 |

### Additional Resources

| Directory | Description |
|-----------|-------------|
| [`5x00_shared/`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x00_shared) | Shared MedDefense organization profile: sites, technology footprint, regulatory posture, security organization, and canonical context facts used across all Module 5 projects |
| [`learning_objectives/`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/learning_objectives) | Module-specific learning objectives and competency mapping covering the IR lifecycle, severity classification, evidence preservation, containment trade-offs, and HIPAA reporting pathways |

## Working Through the Modules

Each module directory contains its own `README.md` with detailed exercise instructions. Work through modules sequentially: the containment, eradication, and handoff exercises in module 2 consume the severity model, escalation paths, and playbooks built in module 1. Later modules keep building on the same chain: [5x04_tabletop](./5x04_tabletop) tests the organization rather than the technical response, and [5x05_breach_response](./5x05_breach_response) is the capstone, an unscaffolded live incident that draws on everything built beforehand, including the tabletop methodology, without naming or guiding any of it.

Key focus areas include:

- **Severity Classification:** Deterministic SEV1–SEV4 grading tied to patient safety, data exposure, and service availability, with decision authority mapped per tier.
- **Playbook Design:** Standardized YAML skeletons an on-call analyst can execute at 3 AM without calling anyone.
- **Containment Trade-offs:** Weighing isolation, power-off, and selective process termination against business impact and evidentiary loss.
- **Evidence Preservation:** Capturing volatile memory, process trees, and network state before any containment action destroys them.
- **Regulatory Response:** HIPAA breach notification drafts aligned with 45 CFR 164.404 and the 60-day OCR reporting clock.
- **Organizational Readiness:** Designing and running a tabletop exercise, from capability mapping and inject scheduling to evaluation criteria and an after-action report with assignable findings.
- **Capstone Execution:** Running a full live incident end to end, from first alert through board brief, with no scaffolding and no step-by-step guidance.

Operational rules throughout:

- **Preserve first, contain second:** containment actions destroy volatile evidence that cannot be recovered once a host is isolated or powered off.
- **Document everything:** every conclusion must be supported by specific evidence from logs, authentication results, or forensic artifacts, recorded in the incident timeline as it happens.
- **Lab Environment:** perform investigations in your own isolated local lab environment. No centralized SIEM or preconfigured infrastructure is required.

### Getting Started

Begin with [5x00_incident_response](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x00_incident_response) — no prior modules are required, though the content assumes familiarity with detection concepts from Module 4.

## Related Directories

| Directory | Description |
|-----------|-------------|
| [`blue_team`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team) | Defensive operations, vulnerability management, and security architecture planning |
| [`threat_detection`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection) | Cybersecurity threat detection and analysis |
