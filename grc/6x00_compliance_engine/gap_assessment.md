# NIST CSF 2.0 Gap Assessment: MedDefense Health Systems

**Assessment date:** 2026-11-01
**Assessor:** Stephen Reilly
**Framework version:** NIST CSF 2.0
**Regulatory context:** HIPAA Security Rule, 45 CFR Part 164

## Gap Assessment Matrix

| CSF Function | Subcategory | Title (abbreviated) | Status | Evidence Reference | Gap Severity | Gap Description |
|---|---|---|---|---|---|---|
| GOVERN | GV.OC-01 | Org risk strategy established | Partial | risk_register_updates.yaml | High | Risk register exists post-incident; no board-approved risk appetite statement or formal governance charter |
| GOVERN | GV.PO-01 | Cybersecurity policy established | Not Implemented | None | Critical | Acceptable Use, Data Classification, and Vendor Management policies missing in enforceable written form per prior_policy_inventory.md |
| GOVERN | GV.SC-04 | Suppliers inventoried by criticality | Not Implemented | None | High | No formal vendor tiering process; Nexus and CloudVault not catalogued by criticality before incident |
| GOVERN | GV.SC-07 | Supplier risks in risk management | Not Implemented | None | High | Vendor risk process incomplete; supply chain exposure from Nexus incident not formally governed |
| IDENTIFY | ID.AM-01 | Asset inventory maintained | Partial | endpoint_hardening_baseline.md | Medium | Workstation inventory incomplete; biomedical devices and medical equipment inventory unknown |
| IDENTIFY | ID.RA-01 | Vulnerabilities identified and recorded | Implemented | forensic_findings_summary.md; risk_register_updates.yaml | None | Incident-driven vulnerability and threat identification captured in risk register entries R-001 through R-005 |
| IDENTIFY | ID.RA-06 | Risk responses tracked | Partial | risk_treatment_plan.md | Medium | Treatment plan exists but lacks CISO signature and formal Board Risk Committee presentation |
| PROTECT | PR.AA-01 | Identity and credential management | Partial | ir_playbook_index.md | High | Credential procedures exist in IR context only; no proactive periodic access review program documented |
| PROTECT | PR.AA-05 | Access permissions reviewed | Not Implemented | None | Critical | No evidence of periodic access review; svc_epic_int service account retained Domain Admin privileges during incident |
| PROTECT | PR.AT-01 | Workforce receives awareness training | Partial | security_awareness_training_status.md | Critical | 73% completion rate below 95% internal target; 540 workforce members overdue across all populations |
| PROTECT | PR.DS-01 | Data-at-rest protected | Partial | endpoint_hardening_baseline.md | Medium | BitLocker confirmed on 173 of 280 Windows endpoints; 107 clinical workstations unencrypted |
| PROTECT | PR.PS-01 | Secure configuration baselines | Partial | endpoint_hardening_baseline.md | High | Legacy GPOs override Script Block Logging; Sysmon deployed to 198 of 280 clinical workstations only |
| PROTECT | PR.PS-04 | Logs generated and reviewed | Partial | sigma_detection_catalog.md | High | Script Block Logging not enabled on all endpoints; CloudTrail missing from DR region us-east-2 |
| DETECT | DE.CM-01 | Networks and endpoints monitored | Partial | sigma_detection_catalog.md | High | Sysmon coverage below 80% of clinical endpoints; medical devices and biomedical gateways do not forward logs |
| DETECT | DE.CM-06 | External service provider activity monitored | Partial | cloudvault_security_questionnaire.md | Medium | CloudTrail not enabled in DR region; no visibility into CloudVault backup console administrative activity |
| DETECT | DE.AE-02 | Potentially adverse events analyzed | Implemented | forensic_findings_summary.md | None | Nexus/Cobalt Strike incident analysis completed with specific technical evidence from endpoint and proxy logs |
| RESPOND | RS.MA-01 | Incident response plan executed | Partial | ir_playbook_index.md | High | Playbooks exist and tabletop exercises completed but lack formal CISO sign-off and annual exercise schedule |
| RESPOND | RS.AN-03 | Analysis performed to support response | Implemented | forensic_findings_summary.md | None | Post-incident forensic analysis completed with specific technical evidence from endpoint and proxy logs |
| RESPOND | RS.CO-02 | Internal and external incident communication | Partial | ir_playbook_index.md | Medium | Evidence of communication testing incomplete; vendor-originated incident playbook remains draft only |
| RECOVER | RC.RP-01 | Recovery plan executed | Partial | recovery_validation_summary.md | High | LIS restore test exceeded declared RTO (41 minutes vs 30 minutes); Epic EHR and Active Directory untested |
| RECOVER | RC.CO-01 | Recovery communication performed | Partial | recovery_validation_summary.md | Medium | Clinical notification language missing from recovery process; timing log created manually |

## Summary

**Implementation counts:**
- Implemented: 4
- Partial: 14
- Not Implemented: 4

**Top 3 pre-audit priorities:**
1. GV.PO-01 (Critical): Draft, approve, and distribute Acceptable Use Policy, Data Classification Policy, and Vendor Management Policy before OCR audit per prior_policy_inventory.md
2. PR.AT-01 (Critical): Complete make-up security awareness training for 540 overdue workforce members to exceed 95% completion target per security_awareness_training_status.md
3. RS.MA-01 (High): Obtain formal CISO sign-off on incident response playbooks and establish approved annual IR exercise schedule per ir_playbook_index.md

**Connection to upcoming governance work:**
The Critical and High gaps above are not incidental; they represent the exact control areas this project and the projects that follow are designed to close. GV.PO-01, PR.AA-05, and GV.SC-04 are all addressed by the three missing policies that must be written, approved, and distributed. PR.AT-01 and ID.RA-06 require completing overdue workforce training and establishing a formal review cadence that transforms reactive incident artifacts into proactive compliance evidence. The DR and endpoint monitoring gaps under DE.CM-01, PR.PS-04, and RC.RP-01 demand technical remediation and documented validation tests that convert Partial status to Implemented before the six-week deadline. Without closing these gaps, MedDefense enters the HHS OCR desk audit with four Not Implemented controls and fourteen Partial ones—evidence that will be interpreted as control absence rather than technical strength.
