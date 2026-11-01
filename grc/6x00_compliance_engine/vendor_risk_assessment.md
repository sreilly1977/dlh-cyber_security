# Vendor Risk Assessment: CloudVault Medical

**Assessment date:** 2026-11-01
**Assessor:** Steve, IT Security
**Reviewed against:** MedDefense Vendor Management Policy (MED-SEC-VMP-001)
**Classification:** Confidential

## 1. Vendor Overview

**Vendor:** CloudVault Medical
**Service type:** Encrypted clinical backup archive and disaster recovery storage
**Proposed tier classification:** Tier A (Critical) — CloudVault would store encrypted backup archives containing Epic EHR database exports, Laboratory Information System backups, PACS/RIS metadata exports, pharmacy dispensing system backups, and operational recovery logs that may contain patient identifiers. Because CloudVault support staff may access the backup management console, and CloudVault metadata may include patient identifiers, the exposure is direct, not incidental.
**ePHI stored or processed:** Yes. CloudVault is a Business Associate under HIPAA. The contract summary confirms the data set; the BAA status note confirms no BAA is currently executed.

## 2. Findings Table

| Item | Finding | Risk Rating | Gap Description | Required Action |
|---|---|---|---|---|
| 1 | SOC 2 Type II, report dated 11 months ago | Pass | — | Obtain the current SOC 2 Type II report and review exceptions before signature |
| 2 | No HITRUST CSF certification | Acceptable | SOC 2 Type II satisfies the policy's attestation requirement; HITRUST is an alternative, not an addition | None |
| 3 | Encryption at rest: AES-256 | Pass | — | None |
| 4 | Encryption in transit: TLS 1.2 | Acceptable | Protocol meets MedDefense minimum; verify server certificate verification is enforced | Confirm TLS configuration details in security review |
| 5 | Penetration test 22 months old; findings summary not provided | Critical Concern | Violates Tier A pre-engagement requirement 3 (Section 3): test must be dated within 12 months with critical findings summary and remediation status. 22 months is nearly twice the limit, and refusing the findings summary means remediation is unverifiable | Vendor must provide a penetration test report dated within the last 12 months, with a summary of critical findings and evidence of remediation, prior to any ePHI access |
| 6 | Two sub-processors disclosed: US-based CDN, EU-based analytics firm | Concern | Violates Tier A pre-engagement requirement 4 (Section 3): sub-processor disclosure is incomplete. Five open questions remain, including whether MetricLake Analytics GmbH receives patient identifiers, whether sub-processors are bound to HIPAA-equivalent safeguards, and whether they hold administrative access | Complete sub-processor data-flow and jurisdiction review, including EU cross-border assessment, approved by Legal and IT Security before any data transfer |
| 7 | DR site location not disclosed | Critical Concern | Violates Tier A pre-engagement requirement 4: undisclosed data center locations fail the requirement. MedDefense cannot complete data-location, jurisdiction, or breach notification planning without knowing where backup archives physically reside | Vendor must disclose the DR site location and jurisdiction before contract signature |
| 8 | Incident notification 72 hours after internal confirmation | Critical Concern | Violates the non-negotiable 24-hour notification SLA (Sections 4 and 7). HIPAA's breach notification clock starts at discovery; a 72-hour vendor window compresses MedDefense's containment and notification timeline | Contract must be renegotiated to 24 hours for confirmed or suspected incidents affecting MedDefense data, triggered on suspicion, before signature |
| 9 | Data deletion within 90 days of written request | Concern | Violates offboarding requirement (Section 6): certified data return or destruction is required within 30 days. A 90-day window extends MedDefense's exposure to ePHI in vendor custody after termination | Contract must be amended to require certified destruction or return within 30 days of written request |
| 10 | Background checks at hire only; no recurring checks | Concern | Periodic re-screening absent for staff with access to a console that manages ePHI-containing archives | Include recurring background checks for data-access staff in the security review conditions |
| 11 | MFA on administrative and privileged accounts: TOTP | Pass | — | None |
| 12 | Monthly scanning; quarterly remediation of critical findings | Acceptable | Quarterly remediation of critical findings is slower than ideal but within typical industry practice; confirm critical-finding definition | Review scan and remediation reports at first annual review |
| 13 | Right-to-audit with 60 days written notice | Acceptable | 60-day notice is a commercial norm; the BAA must separately preserve MedDefense's right to request evidence during incident investigation without the 60-day delay | Ensure BAA includes investigation-evidence clause independent of the audit provision |
| 14 | BAA willing to execute; not executed | Critical Concern | Violates the unconditional Tier A requirement (Section 3, item 5): no Tier A vendor may receive ePHI before an executed BAA. Willingness is not execution | Execute the BAA with all required terms from baa_status_note.md before any ePHI access; no exceptions |
| 15 | Annual online PHI handling training | Acceptable | Training exists but is generic; no role-specific or verification detail provided | Request training completion evidence for staff with MedDefense data access at onboarding |

**Summary of ratings:** Pass — 3, Acceptable — 5, Concern — 4, Critical Concern — 4.

## 3. Critical Findings

**Item 5 — Stale penetration test without findings summary.** CloudVault's most recent penetration test is 22 months old, and the vendor declined to provide a findings summary. This fails the Tier A pre-engagement requirement for a test dated within 12 months with documented remediation status. For MedDefense, the regulatory exposure is direct: 164.308(b) obliges MedDefense to obtain satisfactory assurances from business associates, and an assurance built on unaudited, outdated testing is not satisfactory. The Nexus incident demonstrated that the vendor trust boundary is exactly where MedDefense was compromised. Before approval, CloudVault must provide a penetration test report dated within the last 12 months, with a summary of critical findings and evidence of their remediation.

**Item 7 — Undisclosed DR site location.** CloudVault discloses its primary datacenter as US-based but refuses to disclose the disaster recovery site. This fails the sub-processor and data-location disclosure requirement: MedDefense cannot assess jurisdiction, applicable law, cross-border transfer obligations, or breach notification logistics for a location it cannot name. A DR site holding the only copies of recovery archives for a clinical system is a single point of compliance failure. Before approval, CloudVault must disclose the DR site location and jurisdiction, and it must be incorporated into the contract and the jurisdiction review.

**Item 8 — 72-hour incident notification.** CloudVault's offered SLA is 72 hours after *internal confirmation* of a breach. This fails the non-negotiable 24-hour SLA on two axes: the window itself, and the trigger (confirmed only, versus confirmed or suspected). The compounding effect is severe — MedDefense's own HIPAA breach notification obligations run on a discovery clock, and every hour consumed by the vendor's internal confirmation process is an hour MedDefense loses for containment, forensics, and notification. Delay was identified in the MedDefense environment as the factor that turns a small incident into a reportable breach. Before approval, the contract must require notification within 24 hours of a confirmed or suspected incident affecting MedDefense data.

**Item 14 — BAA not executed.** CloudVault states willingness to execute a Business Associate Agreement, but none is signed. Under the Vendor Management Policy, this is unconditional and non-waivable: no Tier A vendor receives ePHI before an executed BAA, and CloudVault is unambiguously Tier A. Executing ePHI transfer without a BAA would place MedDefense in direct violation of 164.308(b) and expose it to OCR enforcement exactly as it enters a desk audit. The BAA must include all terms enumerated in the policy and in `baa_status_note.md`: permitted uses, safeguard obligations, 24-hour breach notification, sub-processor flow-down, data return or certified destruction, investigation evidence rights, and termination support.

## 4. Recommendation

**Do Not Approve.**

CloudVault Medical fails four of the five Tier A pre-engagement requirements defined in the MedDefense Vendor Management Policy: penetration test currency (item 5), complete data-location disclosure (item 7), sub-processor disclosure adequacy (item 6, incomplete), and executed BAA (item 14), and its contractual terms conflict with mandatory policy requirements on incident notification (item 8) and data deletion (item 9). The SOC 2 Type II report, AES-256 encryption, and privileged-account MFA are genuine strengths, but under the Vendor Management Policy they do not substitute for the failed requirements — a lesson MedDefense learned through the Nexus incident, where a trusted, contracted vendor path became the initial access vector.

This recommendation is not a rejection of the CloudVault relationship. It is a determination that the vendor, as currently evidenced, may not receive ePHI or execute the contract in its present form. The path to approval is concrete and entirely within CloudVault's control: resolve the four critical concerns and the outstanding contract deviations, and re-present for security sign-off.

## 5. Required Conditions for Future Approval

Because the recommendation is Do Not Approve, the following conditions define what must change before this assessment can be revisited. All conditions must be satisfied prior to contract signature, and no ePHI may be transferred under any circumstances until every condition is closed:

1. **Execute the BAA** with all required terms, including 24-hour notification for confirmed or suspected incidents and sub-processor flow-down obligations, before any ePHI access.
2. **Provide a penetration test report dated within the last 12 months,** with a summary of critical findings and evidence that all critical findings have been remediated.
3. **Disclose the DR site location and jurisdiction,** and incorporate it into the contract and the data-flow review.
4. **Renegotiate the incident notification SLA** from 72 hours to 24 hours, triggered on confirmed or suspected incident.
5. **Renegotiate the data deletion window** from 90 days to certified return or destruction within 30 days of written request.
6. **Complete the sub-processor data-flow and jurisdiction review,** including the MetricLake Analytics GmbH EU assessment and resolution of the five open questions in `cloudvault_subprocessor_list.md`, approved by Legal and IT Security.

Progress against these conditions is owned by IT Security and Procurement jointly, consistent with the Vendor Management Policy. Until all six are closed and this assessment is reissued with a changed recommendation, the CloudVault engagement remains stopped, consistent with the initial recommendation in `cloudvault_contract_summary.md`: do not allow ePHI transfer until BAA execution and security conditions are resolved.
