# GRC

Governance, risk, and compliance (GRC) study materials for a healthcare environment. Covers proving an existing control set against recognized standards (NIST CSF 2.0, the HIPAA Security Rule, the CIS AWS Foundations Benchmark), writing enforceable policy, building a disaster recovery program that is actually tested, correcting identity and access management at scale, automating SOC triage, and running a security awareness program that changes behavior rather than generating completion certificates.

## Case Study: MedDefense

The scenario modules continue the MedDefense Health Systems storyline from the IR/DFIR Playbook. Four weeks after the Cobalt Strike incident, an HHS Office for Civil Rights desk audit notice arrives, and everything the incident exposed gets addressed with governance discipline: controls that exist but cannot be proven, a DR plan that has never been tested, service accounts holding Domain Admin with no documented function, 18 hours of daily manual alert triage, and a phishing click rate of 56%.

Learners take on the role of a security analyst translating fourteen weeks of technical security work into evidence, policy, and executive communication. Supporting characters (Dr. Patricia Morales, CISO; James Chen, SOC Lead; Sarah Park, IT Director; Helena Reyes, General Counsel; Robert Kim and Mike Torres, SOC analysts; Maria Santos, HR Director) and realistic artifacts (gap assessment matrices, signed policy headers, BIA tables, SHA-256 backup manifests, IAM findings JSON, playbook audit logs, and lure-calibrated phishing templates) create an immersive, hands-on learning environment.

## Total Exercise Count

40 exercises across 5 modules (each module contains one knowledge quiz plus seven hands-on tasks)

## Module Overview

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 1 | [`6x00_compliance_engine/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine) | Compliance engine: an evidence-referenced gap assessment against NIST CSF 2.0 and the HIPAA Security Rule, three enforceable policies written from scratch (Acceptable Use, Data Classification, Vendor Management), a CloudVault Medical vendor risk assessment, an OCR desk audit evidence package, and a board-facing CISO compliance brief | 8 |
| 2 | [`6x01_bc_dr/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr) | Business continuity and disaster recovery: a signed Business Impact Analysis across ten MedDefense systems with patient-safety-driven RTO, RPO and MTD values, a dependency-aware backup architecture, command-level recovery runbooks for the Laboratory Information System and Active Directory, clinical downtime procedures, a timed LIS recovery test against a 30-minute RTO, a formal gap analysis, and a DR master plan satisfying HIPAA 164.308(a)(7) | 8 |
| 3 | [`6x02_iam_scale/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x02_iam_scale) | Identity and access management: SAML SSO federation with Keycloak, least-privilege corrections to three AWS IAM policies, Vault-issued dynamic credentials replacing static service account passwords, a Python IAM audit script processing a 20-account inventory into severity-scored JSON findings, a professional audit report, a CIS AWS Foundations Benchmark assessment, and an identity program brief for the board | 8 |
| 4 | [`6x03_soc_playbook/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x03_soc_playbook) | SOC automation: a modular IOC enrichment engine, a SQLite-backed case manager, executable phishing triage and credential exposure playbooks with human-authorization checkpoints for destructive actions, a five-scenario integration test suite, an automation strategy gated by measured false-positive rates, and a one-page SOC lead brief | 8 |
| 5 | [`6x04_security_awareness/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x04_security_awareness) | Security awareness and human risk: an adversary-perspective social engineering threat profile, a 90-day four-wave phishing simulation campaign plan bounded by HR privacy rules, four deployable phishing templates, non-shaming post-click microtraining, four role-based one-page security guides, vishing scenario scripts, and an insider threat framework that protects the organization without creating a surveillance culture | 8 |

## Working Through the Modules

Work through the modules sequentially. They form one continuous narrative arc anchored in the OCR desk audit: the gap assessment in module 1 identifies the exact weaknesses the later modules remediate, including the untested DR plan addressed in module 2, the identity-layer failures addressed in module 3, the triage speed problem addressed in module 4, and the 56% click rate addressed in module 5.

Unlike the IR/DFIR Playbook modules, there are cross-module dependencies to be aware of. The security awareness templates in module 5 exploit the timing of the MFA rollout from module 3, and its employee segments are drawn from the module 3 IAM audit; the insider threat program cross-references the svc_helpdesk Domain Admin finding from that same audit; and the credential exposure playbook in module 4 consumes a privileged account inventory consistent with module 3's findings.

The modules also chain internally. In module 1, the CloudVault vendor risk assessment applies the Vendor Management Policy written one task earlier, and the audit evidence package cites every policy produced before it. In module 2, the timed recovery test executes the runbooks from the previous task against the RTO declared in the BIA, and the gap analysis turns every deviation into a corrected runbook and a revised RTO. In module 4, both playbooks call the enrichment engine and case manager built in tasks 1 and 2, and the integration test verifies all of them together.

Key focus areas include:

- **Gap Assessment:** Mapping deployed controls to NIST CSF 2.0 subcategories with evidence references, implementation status, severity, and specific remediation, not generic claims.
- **Enforceable Policy Writing:** Documents with teeth, from Acceptable Use to Data Classification to Vendor Management, that an auditor accepts and a department head can enforce.
- **Vendor Risk Management:** Tiered vendor requirements, an unconditional Business Associate Agreement rule before any ePHI access, and a questionnaire-driven risk assessment with a defensible approve or reject recommendation.
- **Business Impact Analysis:** Classifying systems by patient safety consequence at 1, 4 and 24 hours, with RTO and RPO values the backup schedule can mathematically satisfy.
- **Tested Recovery:** Timed recovery execution against a declared RTO, with every deviation documented, root-caused, and converted into runbook corrections.
- **Identity Hygiene:** SAML federation, least-privilege IAM corrections, TTL-based dynamic credentials, and scripted audits that surface dormant and over-privileged accounts with severity-scored findings.
- **SOC Automation:** Enrichment engines and executable playbooks with human checkpoints for destructive actions, deployed only after false-positive rates are measured.
- **Human Layer Risk:** Phishing and vishing simulations calibrated to real attacker behavior, role-targeted guidance, and insider threat indicators that respect HR and legal boundaries.

Operational rules throughout:

- **Evidence over assertion:** every status, finding, and verdict must cite a named artifact or material. Generic evidence such as "security documents" is not acceptable.
- **Everything must run:** scripts must execute and produce output, and playbooks must be verified against the provided test fixtures before they are declared complete.
- **Honest test reporting:** a result of "everything went fine" is not a result. Deviations, path mismatches, and failures are documented as they occur and turned into corrected runbooks.
- **Lab environment:** perform the work in your own isolated local lab environment. Exercise materials are provided under `/opt/meddefense/materials/` in the provided container. No centralized SIEM or preconfigured infrastructure is required.

### Getting Started

Begin with [`6x00_compliance_engine`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine). The module presumes fourteen weeks of previously built controls (endpoint hardening baselines, Sigma detection rules, IR playbooks, forensic findings, recovery validation, and the risk register), all provided as prior-controls materials, so you do not need to have built them yourself. Familiarity with the Module 5 Cobalt Strike incident from the IR/DFIR Playbook adds context but is not required.

## Related Directories

| Directory | Description |
|-----------|-------------|
| [`ir_dfir_playbook`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook) | Incident response and digital forensics: the Module 5 Cobalt Strike incident this GRC storyline continues from |
| [`blue_team`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team) | Defensive operations, vulnerability management, and security architecture planning |
| [`threat_detection`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection) | Cybersecurity threat detection and analysis |
