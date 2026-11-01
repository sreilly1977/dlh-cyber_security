# MedDefense Disaster Recovery Program Master Plan

**Version:** 1.0
**Classification:** Confidential
**Prepared by:** Steve, IT Security
**Date:** 2026-11-01
**CISO approval:** _________________________ Date: _________

## 1. Program Scope

This plan establishes MedDefense's disaster recovery program for the protection of electronic protected health information and continuity of patient care, satisfying the contingency planning requirements of HIPAA Security Rule 45 CFR 164.308(a)(7). It consolidates the Business Impact Analysis, backup architecture, recovery runbooks, clinical downtime procedures, and the tested recovery evidence produced during the 2026 DR program rebuild directed in response to the HHS OCR desk audit preparation.

The evidence chain this plan implements: BIA defines what is critical and why; the backup architecture defines how recovery objectives are supported; the runbooks define how recovery is executed; the downtime procedures define how care continues while systems are down; the recovery test record proves what the plan actually delivers; the gap analysis corrects what the test showed was wrong.

## 2. Covered Systems, Sites and Scenarios

Covered systems are the ten systems assessed in the Business Impact Analysis version 1.0: Active Directory, Epic EHR, Laboratory Information System, PACS/RIS, Pharmacy Dispensing System, Medical Device Integration Gateway, Network Core, Email and Secure Messaging, Backup and DR Infrastructure, and Security Operations Platform. Priority tiers, RTO, RPO and MTD values for each are governed by the BIA.

Covered scenarios: single-system failure with manual recovery from backup; dependency cascade failure; full data center loss with restoration from geographically separate backup copies; and ransomware or corruption events requiring restoration to a verified recovery point.

Site coverage: the primary data center and the geographically separate backup destinations defined in the backup architecture. Vendor-hosted recovery for Epic EHR per the vendor DR site arrangement.

## 3. Explicit Exclusions

This plan does not cover: regional disasters affecting the entire metropolitan area beyond the scope of geographically separate backup restoration; long-term archival records access governance beyond the retention periods in the backup architecture; routine degraded-performance incidents that do not meet activation criteria; clinical business continuity functions such as staffing surge and supply chain, which are owned by hospital emergency management; and systems outside the ten-system BIA inventory.

## 4. Roles and Responsibilities

| Role | Responsibility |
|---|---|
| Administrator on Call (ext. 7000) | Authorizes hospital-wide downtime declaration and emergency operations |
| IT Incident Commander (ext. 7200) | Confirms outage and recovery status; directs technical recovery execution |
| Clinical Applications Lead (ext. 7300) | Confirms Epic/LIS status; validates clinical fitness before release |
| Infrastructure Manager | Owns backup architecture, backup platform recovery, manifest integrity |
| Laboratory Systems Lead | Executes LIS recovery; owns LIS runbook currency |
| Systems Administrator | Executes Active Directory recovery |
| Network Engineering Lead | Executes Network Core recovery |
| SOC Manager | Maintains reduced-mode monitoring during recovery |
| CISO | Signs off on this plan; owns board reporting |
| Nursing Supervisor (ext. 7100) | Coordinates nursing units during downtime procedures |

## 5. Activation Criteria

Any one of the following triggers plan activation and the timed recovery process:

1. **Declared downtime by the Administrator on Call** following confirmed outage of a Tier 1 clinical system (Epic EHR, LIS, Pharmacy Dispensing System, Network Core, Active Directory, Backup and DR Infrastructure).
2. **Data integrity event:** confirmed corruption, ransomware encryption, or unauthorized modification of ePHI requiring restoration to a verified recovery point.
3. **Full or partial data center loss:** primary facility power, environmental or structural failure rendering production infrastructure unavailable.
4. **Missed recovery objective:** any Tier 1 system outage whose elapsed time reaches half of its declared MTD, regardless of cause, activating incident-level recovery management.
5. **Vendor declaration:** Epic vendor-side DR site activation or confirmed replication failure exceeding the 15-minute replication schedule.

## 6. Communication Plan — Ordered Notification Sequence

1. Administrator on Call (ext. 7000) authorizes the downtime declaration.
2. Nursing Supervisor (ext. 7100) and IT Incident Commander (ext. 7200) are notified and activated.
3. Clinical Applications Lead (ext. 7300) confirms affected system status and clinical impact scope.
4. Nursing units activate paper downtime procedures per the clinical downtime quick references in the unit downtime binders.
5. Affected system owner executes the applicable recovery runbook with timing recorded at each step.
6. Clinical teams receive recovery notification on validation: status against declared RTO with actual elapsed time, recovery point date, validation results, and outstanding paper reconciliation items.
7. Restoration announcement is issued by the IT Incident Commander only after clinical fitness validation.
8. Post-restoration reconciliation follows each clinical downtime procedure.
9. CISO is notified of any missed recovery objective for regulatory reporting assessment and board reporting.

## 7. Program Document Index

| Document | Filename | Version | Last Updated | Last Tested |
|---|---|---|---|---|
| Business Impact Analysis | business_impact_analysis.md | 1.0 | 01 November 2026 | N/A |
| Backup Architecture | backup_architecture.md | 1.0 | 01 November 2026 | N/A |
| Recovery Runbooks | recovery_runbooks.md | 1.0 | 01 November 2026 | 01 November 2026 |
| Clinical Downtime Procedures | clinical_downtime_procedures.md | 1.0 | 01 November 2026 | N/A |
| Recovery Test Record (LIS) | recovery_test_record.md | 1.0 | 01 November 2026 | 01 November 2026 |
| Gap Analysis | gap_analysis.md | 1.0 | 01 November 2026 | N/A |

## 8. Testing and Revision Schedule

| Activity | Frequency | Owner | Basis |
|---|---|---|---|
| LIS timed recovery test | Quarterly | Laboratory Systems Lead | 164.308(a)(7)(ii)(D) |
| Backup manifest verification check | Monthly | Infrastructure Manager | Finding 4, backup log review |
| AD restore test (non-authoritative) | Quarterly | Systems Administrator | 164.308(a)(7)(ii)(D) |
| Full document set revision review | Annual, or after any material infrastructure change | CISO | 164.308(a)(7)(ii)(D) |
| Cold-start revalidation of LIS RTO after runbook 2.0 adoption | One-time, by 15 December 2026 | Laboratory Systems Lead | Gap analysis remediation item |

The 01 November 2026 LIS recovery test satisfied the initial testing requirement; quarterly repetition sustains it. Every test records tester identity and date, per the verification standard established in the backup log review.

## 9. CISO Sign-off

By signing, the CISO approves this DR program master plan and its indexed deliverables as the organization's contingency plan of record under 45 CFR 164.308(a)(7), acknowledges the recovery test evidence appended, and commits to the remediation roadmap in the gap analysis.

CISO signature: _________________________ Date: _________
