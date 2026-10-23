# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** [Exercise date TBD]
**Classification:** Internal - Exercise Use Only
**Facilitator:** Steve (Cybersecurity Engineer)
**Scenario Version:** 1.0

---

## Organization Background

MedDefense operates three sites — West Campus, Main, and North Site — delivering outpatient care that depends heavily on reliable appointment scheduling. Approximately 3,500 patient-facing scheduling interactions flow through our systems each week, many involving protected health information (PHI). As a HIPAA-covered entity, MedDefense carries direct obligations for safeguarding ePHI, and these obligations extend through our Business Associate agreements to the vendors who process patient data on our behalf.

## Vendor Background

Nexus Patient Scheduling is a cloud-hosted, multi-tenant SaaS platform operated by Nexus Health Technologies, Inc. (Austin, TX). MedDefense has used Nexus since August 2023 across all three sites for outpatient scheduling, pre-registration, insurance eligibility checks, and associated staff rostering functions. Nexus processes patient demographic data, appointment data, and insurance information — all of it ePHI under HIPAA.

Integration with our Epic environment runs over HL7 FHIR R4 via HTTPS, authenticated with an OAuth2 service principal (`svc-nexus-prod`):

- Outbound from MedDefense to Nexus (`https://fhir.nexushealth.io/v1/`): scheduling requests, patient demographics, insurance eligibility queries
- Inbound from Nexus to MedDefense (`https://ehr-ingest.meddefense.local/nexus-inbound/`): confirmed appointments, wait-list notifications, automated schedule updates, delivered over a site-to-site IPsec tunnel

Nexus software updates are **automatic**. The vendor pushes digitally signed updates to the on-prem `nexus-agent` installed on our scheduling server, `SCHED-SVR-01`, at Main campus. Our update channel validates these packages against Nexus's code-signing certificate.

Our contractual posture with Nexus:

- A Business Associate Agreement is in force (effective 2023-08-01, last amended 2025-05-20), obligating Nexus to notify MedDefense of any breach **within 24 hours of discovery**, to provide an annual SOC 2 Type II report, and to return or destroy PHI on termination
- Nexus discloses three subprocessors: AWS, Twilio (SMS reminders), and SendGrid (email reminders)
- MedDefense's most recent vendor security review (November 2025) closed with residual findings noted on the vendor's side

Nexus has never been in a confirmed public security incident. Their last joint communication test with us was September 2024 — we have never exercised an incident with them.

## Opening Situation

Three days ago, unknown to MedDefense, Nexus Health Technologies' build infrastructure was compromised by a threat actor. The attacker pushed a **malicious update through Nexus's legitimate automatic update channel**. Because the package was signed with the vendor's valid code-signing certificate, it passed validation and deployed silently. The backdoor embedded in the update has been running on MedDefense's Nexus agent hosts at all three sites since deployment.

Today, **45 minutes ago**, the SOC flagged unusual outbound traffic from the Main campus scheduling server.

## Known Facts at Exercise Start

1. **Traffic alert:** The SOC observed anomalous outbound connections from `SCHED-SVR-01` to an unknown external IP address
2. **EDR telemetry:** The endpoint detection alert shows periodic outbound connections occurring at regular four-hour intervals, consistent with beaconing behavior
3. **Affected systems identified so far:** the Nexus agent hostnames serving all three sites
4. **Nothing else has been confirmed.** You do not yet know what data, if any, has left the environment

## Questions Before the Room

The following tensions have no pre-scripted answer. They are yours to work:

- **Appointments:** During the compromise window, patient appointment and pre-registration records may have been modified or exfiltrated. If schedule integrity is in question, what does tomorrow morning look like at the front desks of three clinics?
- **Vendor trust:** The malicious update arrived through Nexus's *signed* automatic update channel — the exact mechanism we rely on to keep this software safe and current. Does a signed update carry more or less weight in your risk decisions going forward? If you cannot trust the update channel, can you trust any remediation instructions the vendor sends you?
- **HIPAA obligations:** Nexus is our Business Associate. Their compromise may trigger MedDefense's breach-notification obligations under the BAA and HIPAA — but the facts establishing whether ePHI was actually breached are incomplete, and may stay incomplete for some time. Notification decisions may have to be made in uncertainty.

*You are not expected to have clean answers. You are expected to make decisions, name owners, and defend them.*
