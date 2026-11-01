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
