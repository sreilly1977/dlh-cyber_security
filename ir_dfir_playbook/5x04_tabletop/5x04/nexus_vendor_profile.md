# Vendor Profile: Nexus Patient Scheduling

**Reference for 5x04 tabletop exercise. Not a real vendor.**

---

## Product

- **Name:** Nexus Patient Scheduling (SaaS)
- **Vendor:** Nexus Health Technologies, Inc. (Austin, TX)
- **Category:** Cloud-hosted patient appointment and pre-registration platform
- **Deployment model:** Multi-tenant SaaS; dedicated AWS region per customer pod (`us-east-1`, `us-west-2`)
- **Used by MedDefense since:** 2023-08-14

## Scope at MedDefense

- All three sites (West Campus / Main / North Site)
- Used for outpatient scheduling, pre-registration, and insurance eligibility checks
- Volume: approximately 3,500 patient-facing interactions per week
- Does not handle clinical charting. Does handle patient demographic data and insurance info (ePHI per HIPAA).

## Integration topology

- **Protocol:** HL7 FHIR R4 over HTTPS
- **Data flow:**
  - Outbound from MedDefense: scheduling requests, patient demographics, insurance eligibility queries
  - Inbound to MedDefense: confirmed appointments, wait-list notifications, automated schedule updates
- **Auth:** OAuth2 client credentials flow; short-lived access tokens bound to a service principal (`svc-nexus-prod`)
- **Network:** MedDefense calls Nexus at `https://fhir.nexushealth.io/v1/`; Nexus calls MedDefense at `https://ehr-ingest.meddefense.local/nexus-inbound/` over a site-to-site IPsec tunnel
- **Software update channel:** Automatic. Nexus pushes signed agent updates to the on-prem `nexus-agent` installed on a dedicated scheduling server (`SCHED-SVR-01`) at Main campus. Code-signing cert: "Nexus Health Technologies, Inc."

## Business Associate Agreement (BAA)

- **BAA in force:** Yes
- **Effective:** 2023-08-01
- **Last amended:** 2025-05-20 (aligned to HIPAA Security Rule 2025 update)
- **Key obligations:** Breach notification to MedDefense within 24 hours of discovery. Annual SOC 2 Type II report. Return or destroy PHI on termination.
- **Subprocessors disclosed:** AWS, Twilio (SMS appointment reminders), SendGrid (email reminders)

## Last security review

- **Date:** 2025-11-14 (five months prior to tabletop date)
- **Reviewer:** MedDefense Vendor Risk — Lisa Tanaka
- **Scope:** SOC 2 Type II review (2025-10 report), penetration test summary, incident history questionnaire
- **Residual findings:**
  - Signed update channel relies solely on code-signing cert validation; no independent hash pin at client side
  - No bill of materials for third-party npm dependencies in the on-prem agent
  - Incident communication path documented at the contact level but not tested in a joint exercise
- **Next scheduled review:** 2026-11-14

## Points of contact

| Role | Name | Contact |
|---|---|---|
| Account Executive | Priya Natarajan | priya.natarajan@nexushealth.io |
| CISO | Marcus Oduya | security@nexushealth.io |
| Incident response (24x7) | Nexus SecOps | +1 512 555 0184, soc@nexushealth.io |
| Legal / Counsel | Evelyn Park | legal@nexushealth.io |

## Notes for the tabletop facilitator

- The tabletop scenario revolves around a malicious signed update pushed through the automatic update channel.
- The residual finding about "no independent hash pin at client side" is the plausibility anchor — participants should be able to walk back from effect to cause without it feeling contrived.
- Nexus has not been in a confirmed public incident before; this exercise does not replay a real breach.
- Last incident communication test was 2024-09, so "we have never done a joint tabletop" is a realistic starting condition.
