# MedDefense Health Systems — OCR Desk Audit Evidence Package

**Prepared for:** HHS Office for Civil Rights Desk Audit
**Prepared by:** Steve, IT Security
**Package date:** 2026-11-01
**Classification:** Confidential

---

### Request 1: Security Risk Analysis

**HIPAA specification:** 164.308(a)(1)(ii)(A)
**Evidence status:** Partial
**Evidence description:** `risk_register_updates.yaml` (version 2026.04) documents five identified risks R-001 through R-005 with severity, status, source artifacts, owners, and target dates. `forensic_findings_summary.md` documents the underlying threat and vulnerability analysis from the March 2026 Nexus/Cobalt Strike incident, including the vendor update channel compromise, LSASS credential access, service account over-privilege, and cloud logging gaps.
**Gap:** No documented risk analysis methodology (how likelihood, impact, and severity were derived) and no documented scope statement (which systems, facilities, and ePHI flows were assessed). The register was produced reactively following an incident, has no approval signature, and no review cadence. The risk register does not establish that an accurate and thorough organization-wide analysis was performed.
**Remediation owner and timeline:** IT Security, 2026-12-01: attach a methodology and scope statement to the risk register, obtain CISO approval, and document a recurring review cycle.

### Request 2: Risk Management Plan

**HIPAA specification:** 164.308(a)(1)(ii)(B)
**Evidence status:** Partial
**Evidence description:** `risk_treatment_plan.md` (version 1.0) maps each registered risk R-001 through R-005 to a treatment, an owner role, a target date, and a success criterion.
**Gap:** The plan has not been signed by the CISO and has not been presented to the Board Risk Committee, as the document itself acknowledges. Treatment progress is not evidenced beyond the plan's creation; no milestone tracking record exists.
**Remediation owner and timeline:** CISO, 2026-11-20: obtain CISO signature on `risk_treatment_plan.md` and present to the Board Risk Committee; document treatment milestone status against each target date.

### Request 3: Security Awareness and Training

**HIPAA specification:** 164.308(a)(5)
**Evidence status:** Partial
**Evidence description:** `security_awareness_training_status.md` documents training delivered in the reporting period 2025-05-01 to 2026-04-30 covering phishing recognition, password hygiene, suspicious email reporting, HIPAA minimum necessary access, lost device reporting, and remote access expectations, with completion broken down by workforce population (73% overall: 912 of 1,320 clinical, 338 of 410 administrative, 101 of 105 IT, 109 of 165 contractors).
**Gap:** Completion is 73% against a 95% internal target, leaving 540 workforce members overdue. Training records are not mapped to job roles, no phishing simulation metrics exist for the past 12 months, contractor completion evidence is incomplete, and no board-approved training plan exists for the next cycle.
**Remediation owner and timeline:** IT Security, 2026-12-15 (per risk R-002 target 2026-06-15, overdue): complete make-up training for all overdue users, document role-based assignments, and launch phishing simulation metrics.

### Request 4: Audit Controls

**HIPAA specification:** 164.312(b)
**Evidence status:** Partial
**Evidence description:** `sigma_detection_catalog.md` (version 2.1) documents nine detection rules SIG-001 through SIG-009 with data sources (Sysmon, PowerShell, Windows Security, AD Security, VPN logs, CloudTrail) and ATT&CK mappings. `endpoint_hardening_baseline.md` documents Sysmon deployment, PowerShell Script Block Logging, Linux auditd rules, and sudo log forwarding to `log-srv-01`.
**Gap:** Sysmon reaches only 198 of 280 clinical workstations; Script Block Logging is missing from several clinical OUs due to legacy GPO conflicts; medical devices and biomedical gateways forward no logs; CloudTrail is not enabled in the DR region; the catalog includes no formal detection engineering change-management record and SOC review evidence is informal.
**Remediation owner and timeline:** SOC Engineering / Infrastructure, 2027-01-15: raise Sysmon coverage above 95% of clinical endpoints, resolve GPO conflicts, and formalize weekly rule review records.

### Request 5: Workforce Security Procedures

**HIPAA specification:** 164.308(a)(3)
**Evidence status:** Partial
**Evidence description:** `acceptable_use_policy.md` (MED-SEC-AUP-001), created in this project, defines account ownership, credential-sharing prohibitions, role-based access expectations, and the acknowledgment requirement that all workforce members sign before system access is granted and annually thereafter.
**Gap:** User access provisioning, termination, and periodic access review procedures are not documented in written form. No evidence of any periodic access review exists; the `svc_epic_int` service account retained Domain Admin membership per `forensic_findings_summary.md`. The AUP is newly drafted and not yet approved or acknowledged by the workforce.
**Remediation owner and timeline:** CISO, 2026-11-15: approve and distribute the AUP; IT Security, 2026-12-31: document provisioning, termination, and periodic access review procedures and execute an initial privileged access review.

### Request 6: Business Associate Agreement

**HIPAA specification:** 164.308(b)
**Evidence status:** None
**Evidence description:** `baa_status_note.md` documents that CloudVault Medical is willing to execute a BAA but that none is signed. `vendor_risk_assessment.md` applies the `vendor_management_policy.md` (MED-SEC-VMP-001) Tier A requirements to CloudVault and documents the evaluation trail. No ePHI transfer to CloudVault has begun.
**Gap:** No executed BAA exists for CloudVault Medical, a Tier A vendor that would store backup archives containing ePHI. If the audit occurs before execution, the submission can only demonstrate that the vendor assessment and policy gate exist, not the executed agreement itself.
**Remediation owner and timeline:** Legal, before any ePHI transfer and before the audit interview: execute the BAA containing all terms enumerated in `baa_status_note.md` and the Vendor Management Policy, or maintain documented confirmation that no ePHI access has begun.

### Request 7: Periodic Technical Evaluation

**HIPAA specification:** 164.308(a)(8)
**Evidence status:** Partial
**Evidence description:** `endpoint_hardening_baseline.md` (baseline version 1.4, assessment date 2026-04-18) documents a technical evaluation of endpoint security controls across 280 Windows workstations, 3 Linux servers, and 26 administrative laptops within the past 12 months. `recovery_validation_summary.md` documents a partial DR restoration test on 2026-04-20. `forensic_findings_summary.md` documents control failures identified through incident investigation.
**Gap:** The evaluation is not a formal, recurring technical evaluation program: monthly review sign-off is not documented per the baseline's own evidence-quality assessment, medical devices were excluded from scope, and no approved evaluation schedule exists. Recovery testing is incomplete (AD tabletop only, Epic EHR untested, LIS retest pending).
**Remediation owner and timeline:** IT Security, 2026-12-31: document recurring technical evaluation and review sign-off records; Infrastructure, 2027-01-15: complete the pending LIS retest and establish the annual DR test calendar.

### Request 8: Incident Response Procedures

**HIPAA specification:** 164.308(a)(6)
**Evidence status:** Partial
**Evidence description:** `ir_playbook_index.md` documents seven maintained playbooks. Testing evidence within the past 24 months includes the Credential Exposure tabletop (2026-04-15), Ransomware Containment tabletop (2026-04-16), and live activation of the Phishing Triage playbook during a real phishing event (2026-04-09). `forensic_findings_summary.md` documents incident analysis and containment of the March 2026 incident within the 24-month window.
**Gap:** Playbooks lack formal CISO sign-off; no leadership-approved annual IR exercise schedule exists; three playbooks (Cloud Incident Response, Insider Threat Escalation, Vendor-Originated Incident) remain in draft and untested; insider threat workflow is not approved by HR; evidence of communication testing is incomplete.
**Remediation owner and timeline:** CISO, 2026-11-15: formally approve the active playbooks and the annual exercise schedule; IT Security and Procurement, 2026-12-31: finalize and test the vendor-originated incident playbook.

---

## Readiness Summary

**Evidence counts:**
- Full: 0
- Partial: 7
- None: 1

**Overall audit readiness rating:** Not Ready

No request currently reaches Full evidence status, and Request 6 has no executed instrument. The rating reflects the submission as it stands today: substantial technical and analytical work exists behind every control area, but the documentation trail an OCR desk auditor evaluates — approved methodologies, signed plans, executed agreements, and completed review records — is incomplete in all eight areas. The trajectory is recoverable within the audit window: the newly drafted policies require only approval and distribution, the risk treatment plan requires only signature and board presentation, and the BAA requires only execution.

**Single biggest gap:** The unexecuted Business Associate Agreement with CloudVault Medical, a Tier A vendor slated to hold ePHI-containing backup archives, is the one request answered with no evidence instrument at all and represents the most likely finding against MedDefense.
