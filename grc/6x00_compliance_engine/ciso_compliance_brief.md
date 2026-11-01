# CISO Compliance Brief

**Prepared by:** Steve, IT Security
**Prepared for:** Dr. Patricia Morales, Chief Information Security Officer
**Date:** 2026-11-01
**Subject:** OCR desk audit readiness, HHS Office for Civil Rights

## Current Compliance Posture

We are not ready for the audit as of today, but the distance between us and ready is measured in weeks, not quarters. Our internal gap assessment found that of twenty-two auditable security control areas, four are not implemented, fourteen are partially implemented, and four are fully implemented. The pattern behind those numbers is consistent: the technical work exists, and the proof does not. We have hardened endpoints, working detection rules, tested incident response, and a current risk register, but an auditor does not accept technical work on trust — they accept documents, signatures, and records. That proof layer is what we have been building this month, and most of it now exists in draft and needs approval, not creation. One item, the CloudVault agreement, requires the vendor rather than us, and we have held the line correctly by refusing to move patient data without it.

## Top Three Findings Before the Audit

1. **We cannot prove our workforce is bound by documented security rules, because the Acceptable Use Policy, Data Classification Policy, and Vendor Management Policy did not exist in enforceable written form until this week.** An auditor treats an undocumented control as a nonexistent one, regardless of what we actually do day to day.

2. **We have no executed agreement with CloudVault Medical, the vendor being lined up to hold backup copies of our patient records.** We completed a formal security assessment and stopped the engagement under our new Vendor Management Policy because CloudVault fails four mandatory requirements, including the missing agreement itself and a stale penetration test. Holding patient data without that agreement would itself be a HIPAA violation, so stopping was the right call, but the auditor will ask about it and today our answer is a risk assessment, not a signed contract.

3. **More than one in four of our people have no documented security training in the past year.** Completion sits at 73% against our 95% target, meaning 540 employees and contractors are overdue, and the contractor population is worst at 66%. Trainings happened, but we cannot show the auditor an acceptably trained workforce.

## What We Have Completed

- **Endpoint protection program:** 231 of 280 clinical Windows workstations, all 3 Linux support servers, and 18 of 26 administrative laptops hardened to a documented baseline, with encryption verified on 173 endpoints (`endpoint_hardening_baseline.md`)
- **Threat detection:** a catalog of nine detection rules engineered specifically against the behaviors that hit us in March, active and mapped to known attack techniques (`sigma_detection_catalog.md`)
- **Tested incident response:** seven maintained playbooks, exercised in two tabletop exercises in April and proven in a live phishing incident the same month (`ir_playbook_index.md`)
- **A current, specific risk register and treatment plan:** five named risks with owners, deadlines, and success criteria, plus a completed gap assessment, three new policies, a vendor risk assessment, and a full evidence-by-evidence response package for all eight audit requests

## What Must Be Completed Before the Audit

| Action | Owner | Deadline |
|---|---|---|
| Approve and distribute the Acceptable Use Policy, Data Classification Policy, and Vendor Management Policy, and collect workforce acknowledgments | CISO | 2026-12-06, one week before the audit |
| Execute the CloudVault Medical Business Associate Agreement with corrected notification and deletion terms, or document that no patient data access has begun | IT Security and Legal | 2026-11-29, two weeks before the audit |
| Complete make-up security training for the 540 overdue workforce members, or provide the auditor an interim remediation plan with milestones for those still outstanding | IT Security | Before the audit date, 2026-12-13 |

## Board Resolution Requested

The Board Risk Committee approves the Acceptable Use Policy, Data Classification Policy, and Vendor Management Policy produced in this project, directs execution of the CloudVault Medical Business Associate Agreement under the conditions in the vendor risk assessment, and endorses the remediation timeline above to close the remaining audit readiness gaps before the HHS Office for Civil Rights desk audit.
