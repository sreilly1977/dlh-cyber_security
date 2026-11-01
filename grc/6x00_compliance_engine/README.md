# Introduction

> "Measure what is measurable, and make measurable what is not so."
>
> — Galileo Galilei

You have spent fourteen weeks building security controls. Endpoint hardening baselines. Sigma detection rules. IR playbooks. Forensic runbooks. A post-incident risk register. If an auditor walked in tomorrow and asked you to prove MedDefense has an adequate security program, could you?

That is exactly what compliance is about. Not checkboxes. Not policy binders that exist to say they exist. Compliance is the discipline of measuring your actual controls against a recognized standard, finding where reality falls short, closing those gaps with enforceable policy, and producing evidence an independent party can evaluate without asking you to explain everything verbally.

In this project you run that entire process. You map every major control MedDefense has deployed against NIST CSF 2.0 and the HIPAA Security Rule. You find the gaps and there will be gaps. You write three policies that currently do not exist in enforceable form. You evaluate a critical vendor. You package the results for an audit that is six weeks away.

The output of this project is a compliance package that could be handed to an auditor without a single verbal explanation. That is the standard.

## Why this matters

Security work without governance documentation does not survive an audit. A risk register that exists in a shared drive without an approval signature, hardening baselines deployed without documented evidence of review, detection rules running without a formal change management record: these are controls that exist technically but cannot be proven to an auditor. Auditors do not operate on trust. They operate on evidence.

The analyst who can build a gap assessment, write enforceable policy, evaluate vendor risk, and brief leadership on compliance posture is not just a technician. In regulated sectors like healthcare, finance, public services, and critical infrastructure, the compliance layer is often the hardest part of the job and the one most visible to leadership. GRC analyst, security program manager, compliance officer, and eventually CISO functions all require exactly this capability. Building it now means arriving at those roles with something most candidates do not have: a record of having actually done it.

## Context

Four weeks after the incident, an email lands in Dr. Patricia Morales's inbox. MedDefense has been selected for an HHS Office for Civil Rights desk audit. The audit letter requests documentation of HIPAA Security Rule compliance across 15 categories. The interview is in six weeks.

James Chen sends you a one-line message: "We have never done a formal compliance assessment against CSF or HIPAA. I need to know where we actually stand before they get here."

Sarah Park confirms that three organization-wide security policies (Acceptable Use, Data Classification, and Vendor Management) either do not exist in writing or were last reviewed in 2021. Helena Reyes flags that the CloudVault Medical relationship, brought in to handle clinical data backup, has no current security assessment on file and no executed Business Associate Agreement.

You have the controls. You built most of them. Now you prove they exist and close what is missing.

---

# 0. Quiz

---

# [1. Map Your Controls to the Framework](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine/gap_assessment.md)

## Goal: 

Produce an evidence-referenced gap assessment matrix that shows exactly where MedDefense stands against the 22 most auditable NIST CSF 2.0 subcategories.

## Context: 

The gap assessment is the foundation every other deliverable in this project depends on. It is only credible when gaps are documented alongside strengths.

## Instructions: 

Create gap_assessment.md. For each subcategory in the list below, document the implementation status, the specific evidence that supports it, the gap severity, and a one-line description of what is missing or weak.

Use These Materials

Use the following files from the provided material folder:

prior_controls/endpoint_hardening_baseline.md
prior_controls/sigma_detection_catalog.md
prior_controls/ir_playbook_index.md
prior_controls/forensic_findings_summary.md
prior_controls/recovery_validation_summary.md
prior_controls/security_awareness_training_status.md
risk_register/risk_register_updates.yaml
risk_register/risk_treatment_plan.md
compliance/nist_csf_2_0_subcategory_reference.md
compliance/hipaa_security_rule_crosswalk.md

Evidence references in gap_assessment.md must use these artifact names or None. Do not cite generic evidence such as "security documents" or "technical controls."

The evidence column must reference actual MedDefense artifacts by name: the risk register, the endpoint hardening baseline, the IR playbooks, the Sigma detection rules, the post-incident forensic report, the recovery validation script. If you built it, cite it. If it does not exist, say so clearly.

Required columns:

    CSF Function and Subcategory ID (e.g., DE.CM-01)

    Subcategory title (abbreviated to 5-7 words)

    Implementation status: Implemented, Partial, or Not Implemented

    Evidence reference (artifact name, or None)

    Gap severity: Critical, High, Medium, Low, or None

    Gap description (one line, specific not generic)

Subcategories to assess:

GOVERN: GV.OC-01, GV.PO-01, GV.SC-04, GV.SC-07

IDENTIFY: ID.AM-01, ID.RA-01, ID.RA-06

PROTECT: PR.AA-01, PR.AA-05, PR.AT-01, PR.DS-01, PR.PS-01, PR.PS-04

DETECT: DE.CM-01, DE.CM-06, DE.AE-02

RESPOND: RS.MA-01, RS.AN-03, RS.CO-02

RECOVER: RC.RP-01, RC.CO-01

After the matrix, add a Summary section with:

    Counts by implementation status

    Top 3 Critical or High gaps requiring pre-audit remediation, stated in one line each

    A one-paragraph note connecting the identified gaps to the upcoming governance and resilience work in this project

**Expected output**

<pre>
# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** <YYYY-MM-DD>
**Assessor:** <your_name>
**Framework version:** NIST CSF 2.0
**Regulatory context:** HIPAA Security Rule, 45 CFR Part 164

## Gap Assessment Matrix

</pre>
| CSF Function | Subcategory | Title (abbreviated) | Status | Evidence Reference | Gap Severity | Gap Description |
| --- | --- | --- | --- | --- | --- | --- |
| GOVERN | GV.OC-01 | Org risk strategy established | Partial | riskregisterupdates.yaml | High | Risk register exists and is updated post-incident; no board-approved risk appetite statement or formal governance charter |
| GOVERN | GV.PO-01 | Cybersecurity policy established | Not Implemented | None | Critical | No written AUP or data classification policy; verbal policy is not auditable |
| GOVERN | GV.SC-04 | Suppliers inventoried by criticality | Not Implemented | None | High | No formal vendor inventory; Nexus, CloudVault, and other ePHI-adjacent vendors are not tiered or catalogued |
| GOVERN | GV.SC-07 | Supplier risks in risk register | Not Implemented | None | High | Vendor risk not represented in the risk register; supply chain exposure identified in incident not yet formalized |
| IDENTIFY | ID.AM-01 | Asset inventory maintained | Partial | endpointhardeningbaseline | Medium | Clinical workstation inventory exists from hardening phase; cloud assets, network devices, and medical devices not inventoried |
| IDENTIFY | ID.RA-01 | Vulnerabilities identified and recorded | Implemented | riskregisterupdates.yaml; forensic_findings.md 	None | Vulnerability identification evident through incident findings and risk register entries |
| IDENTIFY | ID.RA-06 | Risk responses tracked | Partial | implementation_package.md | Medium | Treatment plans exist post-incident; no ongoing risk treatment tracking cadence or ownership assignments |
| PROTECT | PR.AA-01 | Identity and credential management | Partial | playbookcredentialexposure.yaml; eradication_checklist.yaml | High | Credential procedures exist in IR context only; no proactive IAM program, privileged access policy, or periodic access review |
| … | … | … | … | … | … | … |

<pre>
## Summary

**Implementation counts:**
- Implemented: X
- Partial: X
- Not Implemented: X

**Top 3 pre-audit priorities:**
1. GV.PO-01 (Critical): ...
2. PR.AT-01 (Critical): ...
3. RC.RP-01 (High): ...

**Connection to upcoming governance work:**
The Critical and High gaps above are not incidental. They represent the exact control areas this project and the projects that follow are designed to close...
</pre>

---

# [2. Write the Acceptable Use Policy](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine/acceptable_use_policy.md)

## Goal: 

Produce a policy document that MedDefense employees can actually be held accountable to.

## Context: 

GV.PO-01 is Critical and the AUP is the first document OCR auditors request. Every day it does not exist in writing is a day the organization is exposed.

## Instructions: 

Create acceptable_use_policy.md. Write it as a real policy, one a department head hands to a new employee on day one and enforces on day two. Not a summary of what an AUP should contain. Not a list of best practices. A document with teeth.

Use These Materials

compliance/prior_policy_inventory.md
templates/policy_header_template.md
compliance/hipaa_security_rule_crosswalk.md
prior_controls/security_awareness_training_status.md

The policy must close the documented written-policy gap in prior_policy_inventory.md. Use the template only for structure; write a complete MedDefense policy.

Required structure:

    Policy header: policy number, effective date, review date (annual), owner (IT Security), approved by (CISO).

    Purpose: two sentences. What this policy protects and why it exists.

    Scope: every person with access to a MedDefense system: employees, contractors, vendors with remote access, and temporary clinical staff. Named specifically, not generically.

    Acceptable use: MedDefense systems and accounts exist for MedDefense business purposes and authorized clinical care delivery. Not "reasonable personal use." That phrase is unenforceable.

    Prohibited activities: specific and non-negotiable. Must include:

    Accessing patient records outside the active care relationship for that patient

    Sharing credentials or permitting another person to use your account

    Installing unauthorized software on any MedDefense endpoint

    Connecting personal devices to the clinical network without IT Security authorization

    Transmitting MedDefense data using personal email, consumer cloud storage, or messaging applications

    Attempting to access systems, data, or network segments beyond your assigned role

    Entering or processing patient data into AI tools, external web services, or third-party platforms without an approved Business Associate Agreement

    PHI handling obligations: two sentences anchoring the policy to HIPAA minimum necessary requirements, without requiring users to understand HIPAA to follow the policy.

    Remote access: conditions for authorized remote access; prohibition on accessing MedDefense systems from public or shared Wi-Fi without an active VPN connection.

    Reporting obligations: what to report (suspicious email, anomalous system behavior, lost or stolen device, accidental PHI disclosure), how to report (IT Security ticket and phone), and when (immediately upon discovery).

    Consequences of violation: reference to the HR disciplinary process up to and including termination; note that violations may constitute HIPAA violations with personal liability.

    Acknowledgment and review: employees sign annually; new employees sign at onboarding before system access is granted.

Constraints:

    Tone: professional plain English. A clinical nurse on their first week must understand it without asking for clarification.

---

# [3. Write the Data Classification Policy](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine/data_classification_policy.md)
### advanced

## Goal: 

Give MedDefense a clear, enforced framework for handling data at every sensitivity level.

## Context: 

Without a classification policy, "protect sensitive data" is an aspiration. The auditor needs to see that data is categorized and that handling requirements are defined per category.

## Instructions: 

Create data_classification_policy.md. Define four classification tiers and the handling rules for each. Every tier must reference MedDefense's actual data landscape, not generic enterprise examples.

Use These Materials

templates/policy_header_template.md
compliance/prior_policy_inventory.md
compliance/hipaa_security_rule_crosswalk.md
prior_controls/forensic_findings_summary.md
vendor/cloudvault_contract_summary.md

Use MedDefense-specific data examples from the materials, including ePHI, lab results, backup archives, security configurations, employee records, contracts, and vendor data flows.

Required structure:

    Policy header: policy number, effective date, review date, owner (IT Security), approved by (CISO).

    Purpose and scope: three sentences. Applies to all data created, stored, transmitted, or processed by or on behalf of MedDefense.

    Classification tiers: four tiers. For each: definition, three or more examples from MedDefense operations, and the handling requirements below.

    Tier 1: Public: approved for release to the general public.

    Tier 2: Internal: for MedDefense employees and authorized contractors only. Unauthorized exposure causes operational inconvenience, not regulatory or patient harm.

    Tier 3: Confidential: exposure could cause financial, legal, or reputational harm. Includes employee records, financial data, contracts, strategic plans, security configurations.

    Tier 4: Restricted / ePHI: subject to the HIPAA Security Rule and Breach Notification Rule. Any unauthorized access triggers the four-factor breach risk assessment.

    Handling matrix: a table. Columns: Tier, Storage, Transmission, Internal sharing, External sharing, Disposal. Every cell is specific. "Use secure methods" is not a cell value.

    Disposal must specify a method for each tier: for Tier 4, NIST SP 800-88 media sanitization or equivalent for electronic media; secure cross-cut shred for paper.

    Classification responsibility: who classifies data at creation; the default when classification is unclear (Tier 3 until reviewed); who holds authority to reclassify.

    Exceptions process: who grants exceptions, how they are documented, and the maximum duration before re-review.

    Review cycle: annually and following any incident that exposed data handling as a control gap.

Constraints:

    Transmission requirements must name the protocol, not a category. "Encrypted transmission" is not sufficient. "TLS 1.2 or higher with server certificate verification" is.

---

# [4. Write the Vendor Management Policy](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine/vendor_management_policy.md)

## Goal: 

Establish enforceable security requirements for every third party with access to MedDefense systems or data before the CloudVault decision is made.

## Context: 

A Business Associate Agreement alone is not vendor management. The Nexus compromise entered through a trusted vendor with a signed contract and a legitimate software update mechanism.

## Instructions: 

Create vendor_management_policy.md. This policy must be specific enough for Sarah Park to use it to evaluate CloudVault Medical, and specific enough for Helena Reyes to draft BAA requirements from it.

Use These Materials

templates/policy_header_template.md
compliance/prior_policy_inventory.md
vendor/cloudvault_contract_summary.md
vendor/baa_status_note.md
vendor/cloudvault_subprocessor_list.md
compliance/hipaa_security_rule_crosswalk.md

The policy must be written so it can be used directly in Task 5 to evaluate CloudVault Medical.

Required structure:

    Policy header: policy number, effective date, review date, owner (IT Security and Procurement jointly), approved by (CISO).

    Purpose and scope: applies to all third parties with access to MedDefense systems, networks, or data: SaaS providers, managed service providers, cloud infrastructure providers, medical device vendors with network-connected products, and staffing agencies with IT system access.

    Vendor risk tiers: three tiers based on access and data exposure.

    Tier A (Critical): access to ePHI or clinical systems. Examples: scheduling platforms, imaging vendors, backup providers with PHI, Epic integration partners.

    Tier B (Standard): access to MedDefense internal systems or networks, but not ePHI.

    Tier C (Low): no system or data access. Physical vendors, office suppliers, facilities contractors.

    Pre-engagement requirements by tier: Tier A vendors must provide all of the following before any data access is permitted:

    SOC 2 Type II report or HITRUST CSF certification, current within 12 months

    Completed MedDefense vendor security questionnaire

    Penetration test results dated within 12 months, with a summary of critical findings and remediation status

    Identification of all sub-processors that will handle MedDefense data, with their jurisdictions

    An executed Business Associate Agreement before any ePHI access begins, with no exceptions

    BAA requirements: when required (any Tier A vendor; any vendor whose service may incidentally expose ePHI), minimum required content, and the specific incident notification SLA: the vendor must notify MedDefense within 24 hours of a confirmed or suspected security incident affecting MedDefense data.

    Ongoing monitoring: Tier A vendors reviewed annually. Material changes (ownership transfer, new sub-processors, data center relocation, significant security incidents) trigger an immediate out-of-cycle review.

    Vendor offboarding: access revoked within 24 hours of contract termination. Data return or certified destruction within 30 days. Documentation retained for six years per HIPAA.

    Incident notification obligations: the vendor notifies MedDefense within 24 hours of confirmed or suspected breach. MedDefense retains the right to conduct its own investigation independent of the vendor's.

Constraints:

    The BAA requirement is unconditional: no Tier A vendor onboards without an executed BAA.

---

# [5. Assess the Vendor](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine/vendor_risk_assessment.md)

## Goal: 

Apply the Vendor Management Policy to a real vendor decision and produce a defensible risk assessment before the CloudVault Medical contract is signed.

## Context: 

CloudVault Medical completed MedDefense's security questionnaire last week. Dr. Morales will not sign the contract without a security sign-off. This is that sign-off.

## Instructions: 

Create vendor_risk_assessment.md. Evaluate CloudVault Medical using the questionnaire responses below. For each item, assign a risk rating, describe the gap if any, and state the required action.

Use These Materials

vendor/cloudvault_security_questionnaire.md
vendor/cloudvault_contract_summary.md
vendor/cloudvault_subprocessor_list.md
vendor/baa_status_note.md
vendor_management_policy.md

CloudVault Medical must be evaluated against the Vendor Management Policy you created. If the vendor does not meet a Tier A requirement, document the gap and condition clearly.

CloudVault Medical: Security Questionnaire Responses
| # | Question | Response |
| --- | --- | --- |
| 1 | SOC 2 Type II certification | Yes; most recent report dated 11 months ago |
| 2 | HITRUST CSF certification | No |
| 3 | Encryption at rest | AES-256 |
| 4 | Encryption in transit | TLS 1.2 |
| 5 | Last penetration test date | 22 months ago; findings summary not provided |
| 6 | Sub-processors that may handle MedDefense data | Two disclosed: a US-based CDN provider and an EU-based data analytics firm |
| 7 | All data stored in US-only data centers | Primary datacenter is US-based; disaster recovery site location not disclosed |
| 8 | Incident notification SLA to customer | 72 hours after internal confirmation of a breach |
| 9 | Data deletion on contract termination | Within 90 days of written request |
| 10 | Background checks on staff with data access | At hire; no recurring checks |
| 11 | MFA on administrative and privileged accounts | Yes; TOTP-based |
| 12 | Vulnerability management cadence | Monthly scanning; quarterly remediation target for critical findings |
| 13 | Right-to-audit clause | Will permit with 60 days written notice |
| 14 | Business Associate Agreement | Willing to execute |
| 15 | PHI handling training for relevant staff | Annual online training module |

Required document structure:

    Vendor overview: vendor name, service type, proposed Tier classification under the Vendor Management Policy, and whether ePHI will be stored or processed.

    Findings table: one row per questionnaire item. Columns: Item number, Finding (abbreviated response), Risk rating (Pass / Acceptable / Concern / Critical Concern), Gap description (if rated Concern or Critical Concern), Required action.

    Critical findings: a dedicated paragraph for each item rated Critical Concern. Name the specific risk, what the finding means for MedDefense's regulatory exposure, and what the vendor must provide before approval.

    Recommendation: one of three options with explicit rationale.

    Approve

    Approve with Conditions

    Do Not Approve

    Required conditions (if Approve with Conditions): specific and measurable. Not "the vendor should improve their security posture." Something like: "Vendor must provide a penetration test report dated within the last 12 months and evidence that all critical findings identified therein have been remediated, prior to any ePHI access."

---

# [6. Package the Evidence for the Auditor](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine/audit_evidence_package.md)

## Goal: 

Demonstrate that the compliance documentation produced in this project, combined with prior security work, can answer eight specific OCR audit requests without verbal explanation.

## Context: 

OCR desk audits run entirely on submitted documentation. If the submission does not answer the question, the auditor rules against it regardless of what the organization actually does.

## Instructions: 

Create audit_evidence_package.md. The audit letter below contains eight specific evidence requests. For each request, document the evidence available, any gap, and the remediation action if evidence is incomplete.

Use These Materials

compliance/ocr_audit_letter.md
compliance/hipaa_security_rule_crosswalk.md
prior_controls/endpoint_hardening_baseline.md
prior_controls/sigma_detection_catalog.md
prior_controls/ir_playbook_index.md
prior_controls/forensic_findings_summary.md
prior_controls/recovery_validation_summary.md
prior_controls/security_awareness_training_status.md
risk_register/risk_register_updates.yaml
risk_register/risk_treatment_plan.md
acceptable_use_policy.md
data_classification_policy.md
vendor_management_policy.md
vendor_risk_assessment.md

For each OCR request, name the evidence artifact directly. If evidence is missing, write None or Partial and specify the owner and remediation timeline.

OCR Audit Letter: Evidence Requests

    Documentation of the organization's security risk analysis, including methodology (164.308(a)(1)(ii)(A))

    A risk management plan documenting how identified risks are being addressed and by whom (164.308(a)(1)(ii)(B))

    Evidence of security awareness and training delivered to workforce members in the past 12 months (164.308(a)(5))

    Audit control evidence demonstrating system activity review (164.312(b))

    Workforce security procedures including user access provisioning and periodic access review (164.308(a)(3))

    Business Associate Agreement for CloudVault Medical (164.308(b))

    Evidence of a periodic technical evaluation of security controls within the past 12 months (164.308(a)(8))

    Incident response procedures and evidence of testing or activation in the past 24 months (164.308(a)(6))

Required format for each request:

<pre>
### Request [N]: [Short title]

**HIPAA specification:** 164.xxx(x)
**Evidence status:** Full / Partial / None
**Evidence description:** [What exists, by artifact name]
**Gap:** [What is missing, if anything]
**Remediation owner and timeline:** [Specific, leave blank if no gap]
</pre>

After all eight requests, add a Readiness summary:

    Count of Full / Partial / None evidence

    Overall audit readiness rating (Ready / At Risk / Not Ready)

    One sentence naming the single biggest gap the auditor would focus on

---

# [7. Brief the CISO](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x00_compliance_engine/)
### advanced

## Goal: 

Translate the gap assessment and audit preparation findings into a one-page written communication for Dr. Morales to present to the board.

## Context: 

The board meets in 48 hours. They will ask one question: are we compliant? Dr. Morales needs an honest, plain-language answer with a clear call to action.

## Instructions: 

Create ciso_compliance_brief.md. Bound to one page when rendered. No jargon that requires a security background to parse. Every statement is supported by a finding from this project.

Use These Materials

templates/ciso_brief_template.md
gap_assessment.md
acceptable_use_policy.md
data_classification_policy.md
vendor_management_policy.md
vendor_risk_assessment.md
audit_evidence_package.md
risk_register/risk_register_updates.yaml

Required sections:
<pre>
# CISO Compliance Brief

## Current Compliance Posture

## Top Three Findings Before the Audit

## What We Have Completed

## What Must Be Completed Before the Audit

## Board Resolution Requested
</pre>

    Current compliance posture: one paragraph. What does the gap assessment show? The framing is honest: not alarming and not dismissive.

    Top three findings before the audit: the three most significant gaps, stated in business impact terms. Not subcategory identifiers. Instead: "We cannot prove to an auditor that our workforce is bound by documented security rules, because the Acceptable Use Policy did not exist in writing until this week."

    What we have completed: three to four bullet points of completed work that constitutes genuine audit evidence, referencing the real technical and procedural work already in place.

    What must be completed before the audit: three actions with named owners and deadlines.

    Approve and distribute AUP, Data Classification Policy, and Vendor Management Policy (owner: CISO; deadline: one week before audit)

    Complete CloudVault Medical risk assessment and execute BAA (owner: IT Security and Legal; deadline: two weeks before audit)

    Document the security awareness training gap and provide an interim remediation plan to the auditor (owner: IT Security; deadline: before audit date)

    Board resolution requested: one sentence. What action does the board need to take? (Example: formal approval of the three policies produced in this project.)

---
