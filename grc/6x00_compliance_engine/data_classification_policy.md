# MedDefense Health Systems — Data Classification Policy

**Policy number:** MED-SEC-DCP-001
**Policy title:** Data Classification Policy
**Effective date:** 2026-11-01
**Review date:** 2027-11-01 (annual)
**Owner:** IT Security
**Approved by:** Chief Information Security Officer (CISO)
**Classification:** Confidential
**Applies to:** All data created, stored, transmitted, or processed by or on behalf of MedDefense Health Systems

---

## 1. Purpose and Scope

This policy establishes a four-tier classification framework so that every piece of MedDefense data has a defined protection level and handling rules attached to it. It applies to all data created, stored, transmitted, or processed by or on behalf of MedDefense, in any format, on any system, by any workforce member or third party. Data handled by vendors on MedDefense's behalf, including backup archive providers and their subprocessors, is in scope and subject to the same tiers.

## 2. Classification Tiers

### Tier 1: Public

**Definition:** Data approved for release to the general public with no damage to MedDefense, its patients, or its workforce.

**Examples:**
- Published content on the MedDefense public website
- Approved press releases and community health announcements
- Publicly posted visitor guides and facility hours

### Tier 2: Internal

**Definition:** Data intended for MedDefense employees and authorized contractors only. Unauthorized exposure causes operational inconvenience, not regulatory or patient harm.

**Examples:**
- Internal staffing bulletins and department meeting notes
- IT maintenance calendars and non-sensitive service desk tickets
- Cafeteria menus, parking notices, and general facility announcements

### Tier 3: Confidential

**Definition:** Data whose exposure could cause financial, legal, or reputational harm to MedDefense. Includes employee records, financial data, contracts, strategic plans, and security configurations.

**Examples:**
- Employee personnel records and payroll data
- Vendor contracts and security questionnaires, including the CloudVault Medical contract summary and security questionnaire
- Security configurations: the Sigma detection rule catalog, the endpoint hardening baseline, the incident response playbook index, the forensic findings summary, the risk register, and DR runbooks
- Recovery logs that do not contain patient identifiers, and router, firewall, and server configurations

### Tier 4: Restricted / ePHI

**Definition:** Data subject to the HIPAA Security Rule and Breach Notification Rule, including all electronic protected health information. Any unauthorized access to this tier triggers the four-factor breach risk assessment under 45 CFR 164.402.

**Examples:**
- Epic EHR records and database exports
- Laboratory Information System results and backups
- PACS/RIS imaging and metadata exports
- Pharmacy dispensing system records
- Operational recovery logs that may contain patient identifiers
- Backup archives destined for CloudVault Medical, including transfer metadata that may include patient identifiers

## 3. Handling Matrix

| Tier | Storage | Transmission | Internal Sharing | External Sharing | Disposal |
|---|---|---|---|---|---|
| 1 — Public | No restriction | Any protocol | Anyone | No restriction | Standard deletion; paper in general waste |
| 2 — Internal | MedDefense-managed systems only | TLS 1.2 or higher within managed networks | All workforce members and authorized contractors | Only with department head approval | Standard deletion; paper in general waste |
| 3 — Confidential | MedDefense-managed systems with access restricted to role-based groups | TLS 1.2 or higher with server certificate verification; SFTP over SSH for bulk transfer | Named role-based groups on a need-to-know basis | Written approval of the data owner; executed NDA required first | NIST SP 800-88 Clear or cryptographic erase for electronic media; cross-cut shred for paper |
| 4 — Restricted / ePHI | Systems on the approved ePHI platform list; AES-256 encryption at rest; access limited by role to the minimum necessary for care or operations | TLS 1.2 or higher with server certificate verification through the approved encrypted transfer pipeline; MedDefense-managed VPN required for any remote transfer | Only workforce members with an active care or operational relationship to the patient; minimum necessary only | Only to vendors covered by an executed Business Associate Agreement; no Tier 4 data to personal email, consumer cloud storage, messaging apps, or AI tools | NIST SP 800-88 Purge or Destroy with certificate of sanitization retained; secure cross-cut shred for paper |

**Vendor data flows:** No Tier 4 data may be transferred to any third party, including CloudVault Medical and its subprocessors, until an executed Business Associate Agreement and a completed vendor security review are on file. Subprocessor data flows receiving Tier 4 or Tier 4-linked metadata must be documented and jurisdiction-approved before transfer begins.

## 4. Classification Responsibility

- **At creation:** the workforce member who creates the data classifies it at the moment of creation, using the tier definitions in Section 2.
- **Default:** if the classification is unclear, classify as Tier 3 until the data owner reviews it. Over-classification is corrected at review; under-classification is a policy violation.
- **Reclassification authority:** the accountable data owner, jointly with IT Security, may reclassify data. Disputes are resolved by the CISO, whose decision is final.
- **Data owners** for the major domains are: clinical systems (Clinical Applications Manager), infrastructure and backup archives (Infrastructure Manager), security operations data (IT Security), workforce records (Human Resources), and vendor and contract data (Legal and Procurement).

## 5. Exceptions Process

Exceptions to any handling requirement in this policy may be granted only by the CISO. Every exception must be documented in writing with the requester, the business justification, the compensating controls applied, and an expiry date. Exceptions are recorded in the MedDefense risk register with a unique risk entry, and no exception may exceed **ninety days** before mandatory re-review by the CISO. An expired exception is treated as no exception.

## 6. Review Cycle

IT Security reviews this policy at least annually, and additionally following any incident, tabletop, or audit finding that exposes data handling as a control gap. Changes are approved by the CISO, and material changes are communicated to all workforce members within thirty days, consistent with the Acceptable Use Policy acknowledgment cycle.

---

## Related Documents

- MedDefense Acceptable Use Policy (MED-SEC-AUP-001)
- MedDefense Vendor Management Policy (MED-SEC-VMP-001)
- MedDefense Endpoint Hardening Baseline
- MedDefense Incident Response Playbook Index
- CloudVault Medical Contract Summary
- CloudVault Medical Subprocessor List

---

## Acknowledgment

I acknowledge that I have read, understood and agree to comply with this policy.

Employee name:

Signature:

Date:
