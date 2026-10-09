# MedDefense Health Systems — Organization Profile

Shared reference for all Module 5 projects. Authoritative.

---

## Identity

- **Legal name:** MedDefense Health Systems
- **Type:** Regional non-profit integrated delivery network
- **Headquarters:** Portland, OR
- **Tax status:** 501(c)(3)
- **HIPAA Covered Entity:** Yes. Healthcare provider and healthcare clearinghouse activities.

## Sites and facilities

| Site | Role | Beds | Annual admissions |
|---|---|---|---|
| West Campus | Outpatient and specialty clinics; clinical laboratory | n/a | 58,000 visits |
| Main Hospital | Inpatient, ED, OR, ICU | 384 | 17,400 admissions |
| North Site | Long-term care and rehabilitation | 112 | 2,100 admissions |

- **Clinical workforce:** 2,000 staff total across all sites (physicians, nurses, techs, allied health, admin)
- **Patient records on hand:** approximately 180,000 active patient records

## Technology footprint

- **Electronic Health Record:** Epic (Hyperspace client, `epic.meddefense.local`)
- **Laboratory Information System:** MedDefense LIS (in-house build on a vendor platform, `lis.meddefense.local`)
- **Identity:** Hybrid — on-prem Active Directory (`meddefense.local`) synced to Azure AD; MFA enforced through Azure MFA with mobile app push
- **Endpoint security:** Wazuh EDR across all clinical workstations; Microsoft Defender for Endpoint on non-clinical fleet
- **SIEM:** Splunk Enterprise, 90-day hot retention, 12-month cold archive
- **Key SaaS vendors subject to BAA:**
  - Nexus Patient Scheduling
  - Twilio (patient SMS reminders via Nexus)
  - SendGrid (patient email reminders via Nexus)
  - Iron Mountain (offsite backup archival)

## Regulatory posture

- **HIPAA:** Covered Entity, Security Rule compliant per last risk assessment (2025-Q4). Breach Notification Rule obligations apply.
- **State laws:** Oregon Consumer Information Protection Act (ORS 646A.600). Washington My Health My Data Act (patients from WA residents seen at West Campus).
- **Payment data:** PCI-DSS SAQ B-IP for outpatient clinic point-of-service terminals (not SAQ D; no card storage).
- **Joint Commission:** Accredited. Reaccreditation due 2026-Q4.
- **CMS Conditions of Participation:** Active.

## Security organization

| Role | Person | Scope |
|---|---|---|
| CISO | Dr. Patricia Morales | Program authority, board reporting |
| SOC Lead / IR Commander | James Chen | 24x7 SOC operations and incident command |
| IT Director | Sarah Park | Infrastructure and clinical IT |
| Infrastructure Lead | Robert Kim | Network, servers, AD, cloud |
| Network Engineer | Mike Torres | Network operations; secondary IR evidence acquirer |
| General Counsel | Helena Reyes | Litigation hold, HIPAA regulatory authority |
| Communications Director | Marcus Webb | Internal and external crisis communication |

- **SOC staffing:** 3 analysts rotating 24x7 coverage. On-call pager rotation for overnight.
- **Third-party assistance:** Incident response retainer with an external DFIR firm (not named in the curriculum scenarios; student can reference as generic "IR retainer").

## Incident readiness baseline

- IR plan last updated 2025-10-02
- Tabletop exercises: conducted annually; last exercise 2025-08-14 focused on ransomware at Main Hospital. No supply-chain scenario has been exercised.
- Backup strategy: Nightly immutable snapshots, 30-day retention on-prem, 180-day retention at Iron Mountain
- RTO (board-committed): 4 hours for Epic, 8 hours for LIS, 24 hours for scheduling
- RPO: 1 hour for Epic, 4 hours for LIS, 24 hours for non-clinical systems

## Canonical context facts to use across all Module 5 projects

- When a project asks about "the organization," this is the organization. Do not invent conflicting details.
- When a project references a "clinical workstation at the West Campus," it is on `wst-ws-NN.meddefense.local`, in the `10.42.118.0/24` network segment.
- When a project references the Laboratory Information System, it is `LIS-WSIDE-01`.
- When a project references the scheduling platform, it is Nexus Patient Scheduling (see `nexus_vendor_profile.md`).
