# MedDefense Health Systems — Vendor Management Policy

**Policy number:** MED-SEC-VMP-001
**Policy title:** Vendor Management Policy
**Effective date:** 2026-11-01
**Review date:** 2027-11-01 (annual)
**Owner:** IT Security and Procurement, jointly
**Approved by:** Chief Information Security Officer (CISO)
**Classification:** Confidential
**Applies to:** All third parties with access to MedDefense systems, networks, or data, and to every MedDefense workforce member responsible for engaging, managing, or offboarding such third parties

---

## 1. Purpose and Scope

This policy establishes the security requirements that every third party must meet before, during, and after access to MedDefense systems, networks, or data. Its purpose is to ensure that vendor relationships never become the entry point for compromise, as occurred in the March 2026 Nexus update channel incident, in which a trusted vendor path was abused to deliver a Cobalt Strike beacon onto MedDefense endpoints. It applies to all third parties, including SaaS providers, managed service providers, cloud infrastructure providers, medical device vendors with network-connected products, staffing agencies with IT system access, and any subcontractor or sub-processor acting on such a vendor's behalf.

No third party may be granted system, network, or data access except through the process defined in this policy. Contract execution alone does not satisfy it; a signed contract without the security evidence defined below is a stopped engagement, not a completed one.

## 2. Vendor Risk Tiers

Every vendor is assigned a tier by IT Security and Procurement jointly at engagement, before any access is provisioned. Tier assignment is documented in the vendor register and reviewed at every reassessment.

| Tier | Criteria | Examples |
|---|---|---|
| **Tier A (Critical)** | Access to ePHI or clinical systems, in any form, including incidental exposure through metadata or backup archives | Backup and DR storage providers handling PHI; Epic EHR integration partners; imaging and PACS/RIS vendors; clinical scheduling platforms; laboratory and pharmacy system vendors; any vendor whose personnel or sub-processors may encounter patient identifiers |
| **Tier B (Standard)** | Access to MedDefense internal systems or networks, but no ePHI exposure | Managed IT service providers; HR and finance SaaS platforms; remote support tooling vendors; network equipment maintenance contractors with network access |
| **Tier C (Low)** | No system, network, or data access | Office suppliers; facilities and physical plant contractors; catering; grounds maintenance |

A vendor is Tier A whenever ePHI access or exposure is possible, not merely probable. Where tier classification is unclear, the vendor is treated as Tier A until IT Security resolves the classification. The CloudVault Medical engagement is Tier A: it would store encrypted backup archives containing Epic EHR exports, LIS backups, PACS/RIS metadata, pharmacy system backups, and operational recovery logs that may contain patient identifiers.

## 3. Pre-Engagement Requirements by Tier

No vendor receives any level of access until the requirements for its tier are complete. Partial completion means no access.

### Tier A requirements (all mandatory, before any data access)

1. **Independent security attestation:** SOC 2 Type II report or HITRUST CSF certification, current within 12 months of the engagement date.
2. **Completed MedDefense vendor security questionnaire,** reviewed and accepted by IT Security.
3. **Penetration test results dated within 12 months,** accompanied by a summary of critical findings and their remediation status. A refusal to provide a findings summary fails this requirement; an attestation without findings is not evidence.
4. **Complete sub-processor disclosure:** identification of every sub-processor that will handle MedDefense data, its jurisdiction, its role, and the data elements exposed to it. Undisclosed data center locations, including DR site locations, fail this requirement.
5. **Executed Business Associate Agreement, before any ePHI access begins, with no exceptions.**

Where a Tier A vendor offers encryption at rest, encryption in transit, and privileged account MFA, these controls satisfy good practice but do **not** substitute for any of the five requirements above. Certifications and technical safeguards do not discharge contractual and governance obligations, and MedDefense conducts its own risk assessment regardless of a vendor's attestations.

### Tier B requirements

Executed non-disclosure agreement; completed vendor security questionnaire; named individuals with access documented; MedDefense-approved remote access method where remote access is required.

### Tier C requirements

Written confirmation from the business owner that no system, network, or data access will occur. If scope changes during the engagement, the vendor must be re-tiered before expanded access.

## 4. Business Associate Agreement Requirements

**When a BAA is required:** any Tier A vendor, without exception, and any vendor whose service may incidentally expose ePHI, including exposure through metadata, telemetry, logs, or backup archive identifiers. A vendor that will store, transmit, process, or conceivably encounter ePHI is a Business Associate.

**Minimum BAA content:**

- Permitted uses and disclosures of ePHI, restricted to the services contracted
- Safeguard obligations for administrative, physical, and technical controls
- Breach notification to MedDefense within **24 hours** of a confirmed or suspected security incident affecting MedDefense data
- Sub-processor disclosure and HIPAA-equivalent flow-down obligations to every sub-processor
- Data return or certified destruction at termination
- MedDefense's right to request evidence and audit during incident investigation
- Termination support and access revocation commitments

**The 24-hour notification SLA is non-negotiable.** A vendor offering 72-hour notification does not meet MedDefense requirements, because HIPAA breach notification to affected individuals and to HHS runs on a 60-day clock that starts at discovery, and MedDefense cannot begin containment, forensics, or its own notification obligations on the vendor's internal timeline. Contract terms offering longer windows must be renegotiated before signature.

Cross-border sub-processor arrangements, such as EU-based analytics processors, additionally require a documented data-flow and jurisdiction review approved by Legal and IT Security before any data transfer begins.

## 5. Ongoing Monitoring

Tier A vendors undergo a full security review **annually**, including refreshed attestation evidence, updated sub-processor lists, and questionnaire renewal. Tier B vendors are reviewed every two years; Tier C on business-owner attestation.

The following material changes trigger an **immediate out-of-cycle review**, regardless of scheduled timing:

- Ownership transfer or acquisition
- New sub-processors handling MedDefense data
- Data center or DR site relocation
- A significant security incident at the vendor, whether or not MedDefense data was affected
- Material change in the sensitivity or volume of data accessed

Any vendor that fails an annual or out-of-cycle review has access suspended until deficiencies are remediated or the contract is terminated.

## 6. Vendor Offboarding

At contract termination or expiration:

1. All system, network, and remote access is revoked within **24 hours** of termination.
2. All MedDefense data in the vendor's possession is returned or destroyed with certification within **30 days** of written request.
3. Certificates of destruction or data return are retained in the vendor file.
4. All vendor engagement documentation, including questionnaires, attestations, BAAs, reviews, and correspondence, is retained for **six years** per HIPAA documentation retention requirements.

A vendor that cannot certify destruction within 30 days must identify the residual data, its location, and the destruction date in writing before the file is closed.

## 7. Incident Notification Obligations

Every Tier A vendor must notify MedDefense within **24 hours** of a confirmed or suspected security incident affecting MedDefense data, its availability, or its integrity. Notification is not conditioned on the vendor completing its own investigation; suspected is the trigger, not confirmed.

MedDefense retains the right to conduct its own investigation independent of the vendor's, to request evidence in support of that investigation, and to invoke contractual right-to-audit provisions. Vendor cooperation with a MedDefense-directed investigation is a continuing obligation under this policy and under the BAA.

## 8. Enforcement

A vendor's failure to meet any requirement of this policy results in suspension of the engagement until the deficiency is cured. A vendor's misrepresentation of its security posture terminates the engagement. Business owners who grant or extend vendor access outside this process are subject to the disciplinary consequences defined in the MedDefense Acceptable Use Policy (MED-SEC-AUP-001).

## 9. Review Cycle

IT Security and Procurement jointly review this policy at least annually, and additionally following any vendor-originated security incident. Changes are approved by the CISO. The first annual review of the full vendor population against these tier definitions is due within 90 days of the effective date of this policy.

---

## Related Documents

- MedDefense Acceptable Use Policy (MED-SEC-AUP-001)
- MedDefense Data Classification Policy (MED-SEC-DCP-001)
- CloudVault Medical Contract Summary
- CloudVault Medical Security Questionnaire
- CloudVault Medical Subprocessor List
- Business Associate Agreement Status Note (CloudVault Medical)
- MedDefense Risk Register (risk_register_updates.yaml)

---

## Acknowledgment

I acknowledge that I have read, understood and agree to comply with this policy.

Employee name:

Signature:

Date:
