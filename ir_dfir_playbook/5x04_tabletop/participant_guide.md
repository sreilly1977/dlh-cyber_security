# Participant Guide: Nexus Supply Chain Compromise Tabletop

**Exercise date:** <YYYY-MM-DD>
**Classification:** Internal - Exercise Use Only

## How this exercise works

This is a tabletop exercise. You will receive situation updates from the facilitator. You respond as you would in a real incident. The facilitator may probe or challenge your responses. There are no trick questions, but there are no easy ones either. The goal is not to perform well, the goal is to find where our response would break.

Read your section below before the exercise begins. You are accountable for the decisions listed under your name. If a decision on your list comes up in the room, the room will look to you. If you believe a decision on your list is actually someone else's to make, saying so — and explaining who and why — is itself a valid and wanted response.

---

## James Chen — SOC Lead

**Exercise decisions you own:**

- Detection interpretation and initial severity classification
- Evidence collection sequencing and preservation
- Technical scope assessment (what is compromised, what data was reachable)
- Containment recommendations — you recommend, you do not unilaterally execute

**Information you receive directly:**

- EDR alert details as they become available, including the four-hour beacon interval from SCHED-SVR-01
- Network telemetry and firewall logs for the scheduling server and the ehr-ingest endpoint
- FHIR API log data through the svc-nexus-prod integration
- Authority to task SOC analysts with specific collection requests

**Success looks like:**

- Severity is declared with explicit reasoning within the first inject
- Evidence is collected and preserved before any containment action that would alter it
- You identify that a trusted vendor binary is the source, not just a compromised host, and treat the update channel as part of the investigation scope
- Scope assessments reach the incident commander within 30 minutes of each new development

**Failure mode to watch for:**

- Treating this as a standard malware incident and missing the vendor trust dimension; containment focused on the endpoint while the provenance of the malicious binary — the vendor's update channel — goes unquestioned until someone hands you the answer.

---

## Sarah Park — IT Director

**Exercise decisions you own:**

- Whether and when the Nexus integration is suspended or restored
- Authorization chain for taking a business-critical system offline — or naming who holds it, if it is not you
- IT-side ownership of the vendor relationship during the incident
- Resourcing and prioritization of competing technical workstreams

**Information you receive directly:**

- Status of the Nexus agent deployment across all three sites (SCHED-SVR-01 at Main; agent coverage at West Campus and North Site)
- Knowledge that Nexus updates deploy automatically and are validated by code-signing certificate only
- Administrative access to the svc-nexus-prod service principal and visibility into the integration architecture
- The vendor relationship context: Nexus AE Priya Natarajan is your commercial contact; the BAA requires Nexus to notify MedDefense of a breach within 24 hours of their discovery

**Success looks like:**

- Any go/no-go decision on the Nexus integration is explicit, justified, and paired with a clinical downtime plan or a named owner and deadline for producing one
- You name a single vendor communication owner instead of letting three people contact Nexus independently
- Your decisions survive the challenge "who authorized this?" with a straight answer

**Failure mode to watch for:**

- Deferring the isolation decision because no one defined the authority in advance, letting the system run compromised through an entire clinic cycle while the authorization question circles. In supply chain incidents the cost of a slow decision is paid in exfiltrated records.

---

## Dr. Patricia Morales — CEO

**Exercise decisions you own:**

- Final arbitration of the security-versus-clinical-operations conflict when your leads cannot resolve it
- Public posture and tone for the organization
- Whether the board is informed now, and what they are told
- Ransom-like or extraordinary-cost decisions, if the scenario reaches one

**Information you receive directly:**

- Board expectations and pressure, delivered personally
- The organizational context you already carry: MedDefense handled its last incident on the strength of one knowledgeable person, which you have already said is not resilience
- Whatever the room tells you — which means the quality of what you receive depends on what you demand

**Success looks like:**

- When your leads deadlock, you force a specific recommendation with stated trade-offs, not an open-ended "figure it out"
- Your questions to the room are the board's questions: patient safety, regulatory exposure, what is confirmed, what is not, who owns what
- You resist the pull to paper over uncertainty for the board; you ask the room what they do not know

**Failure mode to watch for:**

- Stepping in too early and deciding for your team what they should decide themselves, which makes the exercise about you and hides exactly the decision-making gaps below you that this exercise exists to expose. Your default in this room should be "come back with a recommendation," used relentlessly.

---

## Helena Reyes — General Counsel

**Exercise decisions you own:**

- HIPAA breach notification analysis and timeline for MedDefense as covered entity
- Invoking the BAA against Nexus, in writing, and documenting their compliance or non-compliance
- Legal risk framing of the media statement and patient communications
- Preservation of legal privilege over investigative communications where applicable

**Information you receive directly:**

- The executed BAA with Nexus Health Technologies, effective 2023-08-01, last amended 2025-05-20: 24-hour breach notification from Nexus on discovery, annual SOC 2 Type II, PHI return or destruction on termination
- Vendor legal contact: Evelyn Park, legal@nexushealth.io
- Any formal notice Nexus issues under the BAA, verbatim, as soon as it arrives
- Knowledge that Nexus's disclosed subprocessors (AWS, Twilio, SendGrid) may carry independent exposure

**Success looks like:**

- You establish early and explicitly that MedDefense's notification duties as covered entity run independently of Nexus's as Business Associate — the breach being "theirs" does not pause your clock
- You distinguish between breach presumption, risk assessment, and confirmed breach, and you commit to a documented analysis path rather than waiting for forensic certainty
- Discrepancies in vendor statements (like a discovery date that does not fit the timeline) are pursued in writing, immediately

**Failure mode to watch for:**

- Treating notification as a vendor's problem because the vendor was the breached party, then discovering weeks later that the covered entity's obligation clock never stopped. This is the single most expensive mistake made in business associate compromises, and it is made by lawyers.

---

## Marcus Webb — Communications Director

**Exercise decisions you own:**

- Holding statement and external messaging, in coordination with legal
- Front-desk and clinical staff talking points for patient-facing questions
- Internal staff messaging so rumors do not outrun facts
- Media response timeline and approval chain

**Information you receive directly:**

- The reporter's inquiry, verbatim, with its deadline, before anyone else shapes your framing
- Social media monitoring signals
- Knowledge of the patient reminder channels: Twilio SMS and SendGrid email go out to patients directly — meaning patients may have already received communications generated during the compromise window before you say a word publicly

**Success looks like:**

- You have a usable holding statement committed before the reporter's deadline, acknowledging awareness without confirming unverified specifics
- Every external sentence is coordinated with legal before release, not after
- Your plan covers three audiences at once: media, front-desk staff who face patients tomorrow morning, and internal staff

**Failure mode to watch for:**

- Going quiet with no prepared position because facts are incomplete, ceding the narrative while a reporter works a same-day deadline. Silence is a statement, and it is drafted by whoever fills it, not by you.

---

## Robert Kim — Infrastructure Lead

**Exercise decisions you own:**

- Execution of containment: host isolation, IPsec tunnel controls, firewall rules on the beacon path
- Integrity of the technical evidence chain while containment proceeds
- Log availability and retention across SCHED-SVR-01, firewalls, and the ingest path
- Technical feasibility assessment of any vendor-directed remediation

**Information you receive directly:**

- Topology: MedDefense calls Nexus at fhir.nexushealth.io over the internet; Nexus calls ehr-ingest.meddefense.local over a site-to-site IPsec tunnel; the agent auto-update path terminates on SCHED-SVR-01 at Main
- Firewall, routing, and egress control authority for the beacon destination (193.42.100.77)
- What logging actually exists and what its retention is, when asked — including the gaps
- Update mechanics sufficient to answer: can we block the update channel, pin a known-good version, or is automatic update mandatory?

**Success looks like:**

- Containment options are presented as choices with consequences — block beacon only, sever tunnel, isolate host, each with what breaks clinically and technically
- When someone asks "can we log X?", you answer with what exists, not what should exist
- You flag when a proposed action destroys evidence, before taking it

**Failure mode to watch for:**

- Executing containment enthusiastically and destroying the forensic record in the process — reimaging the host, clearing logs, blocking the beacon before capture — leaving the PHI exposure question permanently unanswerable. The legal outcome of this incident will be decided by what evidence survives your first hour.

---

## Clinical Director Representative

**Exercise decisions you own:**

- The clinical impact assessment of any scheduling outage: which patients, which appointments, what fails without pre-registration and eligibility
- The manual scheduling fallback: is it defined, staffed, and printable before tomorrow morning
- Verification approach for tomorrow's schedule given integrity is in question
- Speaking for patient safety when security and operations collide — this is your lane, own it loudly

**Information you receive directly:**

- Appointment volumes across West Campus, Main, and North Site, including the sensitive categories (oncology follow-ups, post-operative checks) affected by any outage
- What front-desk staff actually have available when the Nexus portal is gone, including what paper processes exist or do not
- The SMS reminders patients have already received, including any quoting modified appointment times

**Success looks like:**

- When security says isolate, you respond with a quantified clinical cost, not a veto: how many patients, what risk, what the fallback costs, and what you need to accept the downtime
- By end of exercise there is a concrete plan for verifying tomorrow's schedule at three front desks before patients arrive
- You distinguish between inconvenience and patient harm, and prioritize accordingly under pressure

**Failure mode to watch for:**

- Flat refusal in the name of patient care with no alternative offered, forcing security to choose between overriding you and abandoning containment. "We cannot take scheduling down" is a position; "here is how we run three clinics without it, and here is what it costs" is leadership.

---

## Observer Guidance

Observers do not speak during the exercise. No exceptions, including clarifications you believe are corrections.

Your job is to capture what participants actually said and did, in the moment, without interpretation. Specifically:

- **Record decisions:** who made them, when (time from exercise start), and whether an owner and deadline were attached
- **Watch for the facilitator's probes** and note which responses were supported by evidence versus assertion
- **Track the deadlocks:** when a decision stalled, note what it stalled on — missing information, unclear authority, or unspoken disagreement
- **Note contradictions:** where two participants stated incompatible facts and no one reconciled them
- **Capture quotable moments:** verbatim statements that will be useful in the after-action review, including the things people almost said and did not

The after-action report is only as strong as your notes. "The room discussed the notification decision for fifteen minutes" is useless. "Legal was unsure whether the 24-hour clock was Nexus's obligation or ours; no one resolved it before moving on" is a finding.
