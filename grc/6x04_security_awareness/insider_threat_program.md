# Insider Threat Awareness Program: MedDefense Health Systems

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-10
**Version:** 1.0
**Classification:** Confidential — Legal review required before manager-facing deployment (HR Director Maria Santos's condition); Legal review required before the anonymous reporting path goes live (`reporting_and_triage_model.md`, `program_governance_roles.md`)
**Position statement:** "We are not building a surveillance program. We are building a framework for recognizing when something is wrong before it becomes a breach. There is a difference." — James Chen
**Materials basis:** `privileged_account_findings.md`, `iam_audit_summary_6x02.md`, `insider_threat_case_notes.md`, `technical_indicators_reference.md`, `reporting_and_triage_model.md`, `manager_reference_constraints.md`, `hr_privacy_rules.md`, `simulation_ethics_guidelines.md`

---

## Program Basis: What the Incident Actually Taught

The forensic investigation showed that `svc_helpdesk` — a service account the 6x02 IAM audit had already flagged as holding Domain Admin rights with no current business justification and over 300 days of dormancy — was used as a lateral movement pivot. The decisive fact for this program is not *who* used it. It is that the access patterns were observable before the incident: dormant account activation at 02:13, privileged access to systems outside the account's documented function, LSASS access from privileged context, IR escalation at 03:18 (`insider_threat_case_notes.md`, Case A; `campaign_reconstruction.md`). Whether that account was compromised externally or misused internally, the observable signals were identical — and the program's whole premise is that employees, managers, and the SOC each see one slice of those signals that the others cannot (`iam_audit_summary_6x02.md`: "employees may notice context before tools do").

The design obligation that follows is stated in `privileged_account_findings.md` and governs every section below: teach employees to report observable facts, not labels. "This account is active outside its documented purpose" is reportable. "Suspicious person" and "bad employee" are not, unless evidence supports formal escalation. This program observes **what happens to systems and access**, never **who people are**.

---

## 1. Behavioral Indicator Framework

Three categories, five observable indicators each. Every indicator is an observable fact, not psychological speculation, and every one names the role positioned to observe it. None of these indicators alone implies malice — each is a *signal for triage*, and triage exists precisely to sort innocent explanations (the documented cases include vendors who were just sloppy and a transferred employee whose access review simply never happened) from real risk.

### Category 1: Access-Based Indicators

Observable patterns in what accounts, systems, and data are touched, and when.

| # | Observable indicator | Observable by |
|---|---|---|
| 1-A1 | A privileged or service account is active outside its documented function or approved hours (the Case A signature: `svc_helpdesk`, documented for ticket routing, interactive logon at 02:13 and server access outside function) | SOC, IT operations (`insider_threat_case_notes.md`, Case A) |
| 1-A2 | An employee retains access inconsistent with their current role — access surviving a transfer, or groups left in place after contract end (`j.yamamoto` retained Server Admins after moving to Finance; `t.morrison` still enabled post-contract; `b.carter` disabled but still in privileged groups) | IT/IAM, HR, manager during role changes (`privileged_account_findings.md`, IAM-003/005/007) |
| 1-A3 | Data access inconsistent with assigned role or unit — patient records outside the employee's patient population, bulk downloads with no treatment, payment, or operations justification | SOC audit-log review; coworker context ("she doesn't work that floor") can originate a report (`technical_indicators_reference.md`, Indicators 5-6) |
| 1-A4 | A dormant account — one with no recent expected activity — suddenly reactivates, or a `svc_*` account logs in interactively rather than as automation | SOC, IT (`technical_indicators_reference.md`, Indicators 1-2; the 300-day-dormancy pivot) |
| 1-A5 | A remote support session, admin grant, or privileged action proceeds with no ticket, no change reference, or no expiration attached (Case C: vendor domain-admin request with no justification and no expiry) | IT helpdesk, sysadmins, SOC (`insider_threat_case_notes.md`, Case C) |

### Category 2: Behavioral Indicators

Observable workplace actions — things people *do with systems and process*, never personality traits, moods, or protected characteristics.

| # | Observable indicator | Observable by |
|---|---|---|
| 2-B1 | Repeated attempts to bypass an approval or verification process — the same workaround requested again after being declined (the privilege-approval path, the payment verification path) | Manager, IT (`manager_reference_constraints.md`, "repeated attempts to bypass process") |
| 2-B2 | Asking another employee for their credentials, MFA codes, or badge/pin — the single most reportable action in the workplace, in any framing ("just this once," "for the migration") | Coworker (the person asked), manager (`reporting_and_triage_model.md`, "employee asking for credentials or MFA codes") |
| 2-B3 | Admin or privileged actions performed from personal email, personal devices, or untracked sessions — outside consoles and ticketed workflows | IT, SOC (`privileged_account_findings.md`, failure modes; `iam_audit_summary_6x02.md`, MFA and admin discipline) |
| 2-B4 | Granting a vendor or outsider privileged access under time pressure, after being warned the request lacks justification | IT helpdesk, procurement, manager (`insider_threat_case_notes.md`, Case C) |
| 2-B5 | Undocumented removal, printing, photographing, or transfer of records or devices beyond the employee's work needs — observable logistics, not inferred motive | Coworker, manager; volume anomalies corroborated by SOC audit logs |

### Category 3: Contextual Indicators

Operational context that tools do not know and that changes the meaning of the other two categories. These are the items managers uniquely hold, per `manager_reference_constraints.md` (managers notice operational context tools may not know).

| # | Observable indicator | Observable by |
|---|---|---|
| 3-C1 | A role change, transfer, or contractor end date that did not trigger an access review — the human event preceding the access inconsistency in 1-A2 | Manager, HR (`iam_audit_summary_6x02.md`: managers must report role changes) |
| 3-C2 | An unusual access request that does not fit the requester's duties, presented with urgency or executive/vendor framing | Manager, IT (`manager_reference_constraints.md`, "unusual access requests") |
| 3-C3 | Unusual behavior inconsistent with assigned duties — a task or inquiry outside the person's function persisting across more than one occasion | Manager (`manager_reference_constraints.md`, "behavior inconsistent with assigned duties") |
| 3-C4 | A vendor, contractor, or "support" contact pressuring staff for elevated access or unusual accommodation, especially around change windows and deadlines | IT, manager, any employee receiving the pressure (`reporting_and_triage_model.md`, "suspicious vendor pressure") |
| 3-C5 | An employee showing confusion or distress after a security simulation or reporting event — signaling a support need, never a suspect flag (`manager_reference_constraints.md`, "signs of confusion after security simulation") | Manager, HR — routed to the support path in `hr_privacy_rules.md`, **not** to investigation |

**Boundary rule for all three categories:** no indicator involves protected characteristics, personal-life observation, monitoring of personal devices, or speculation about motive. A manager who cannot state an indicator as an observable fact ("she asked me for my MFA code yesterday") does not have a reportable indicator — and this document does not permit them to manufacture one.

---

## 2. Technical Indicator Framework

Five SOC-monitored signals, drawn from the detection logic and log sources in `technical_indicators_reference.md`, cross-referenced to the 6x02 IAM audit findings. These are machine-detectable counterparts of the human-observable indicators in Section 1; the SOC sees the pattern, but context from Section 1 often determines whether the pattern is benign.

### TI-1: Dormant Privileged Account Activation

- **Log source:** Windows Security Event 4624, IAM audit export
- **Detection logic:** privileged account inactive >90 days logs in
- **6x02 cross-reference:** the audit's dormant-account findings and the `svc_helpdesk` risk — this indicator fires on exactly the profile of the account used as the lateral movement pivot (dormant >300 days, then activation)
- **Triage question:** was this activity tied to an approved change or incident response?
- **Counterpart signal:** 1-A4; human context (a migration project ending, a forgotten installation) frequently explains the finding innocently — triage exists to check that

### TI-2: Service Account Interactive Logon

- **Log source:** Windows Security Event 4624, LogonType 2/10
- **Detection logic:** account name starts with `svc_` and an interactive logon occurs
- **6x02 cross-reference:** service accounts with excessive privileges — IAM-001 (`svc_epic_int`, Domain Admin, dormant) and IAM-002 (`svc_helpdesk`, Domain Admin); both accounts should never have a human-shaped logon at all
- **Triage question:** should this service account ever log in interactively? (Answer for these accounts is no; for correctly scoped accounts, almost never)
- **Counterpart signal:** 1-A1 — the Case A 02:13 interactive logon was the pre-incident observable

### TI-3: Privileged Group Membership Change Without Ticket

- **Log source:** Windows Security Events 4728/4732/4756
- **Detection logic:** user added to Domain Admins or Server Admins
- **Triage question:** is there an approved ticket and owner?
- **6x02 cross-reference:** the vendor-installation and migration-era privilege grants the audit documented — the class of change that TI-3 would have flagged at grant time instead of at incident time
- **Counterpart signals:** 1-A5, 3-C2 — helpdesk and managers hold the approval context the log lacks

### TI-4: LSASS Access From Privileged Context

- **Log source:** Sysmon Event ID 10
- **Detection logic:** suspicious process accesses LSASS
- **Incident cross-reference:** the Cobalt Strike credential-access stage of the Module 5 incident path — the point at which a human-layer failure became a credential-layer compromise
- **Triage question:** is this approved security tooling?
- **Counterpart signal:** 1-A1/1-A4 — TI-4 firing under a dormant-account or interactive-service-account context (TI-1/TI-2) is the highest-severity combination in this framework, because it reproduces the documented pivot exactly

### TI-5: Role-Inconsistent Patient Record Access and Bulk Off-Hours Transfer

- **Log source:** EHR audit log; file share audit and EDR telemetry
- **Detection logic:** user accesses records outside assigned unit or role pattern (Indicator 5); unusual volume, unusual time, sensitive directory (Indicator 6)
- **Privacy constraint:** these carry a special duty — EHR record-access review requires careful handling and minimum-necessary disclosure (`technical_indicators_reference.md`, privacy note; Case D lesson: access-based indicators must be triaged carefully and privately)
- **Triage question:** is there a treatment, payment, or operations reason?
- **Counterpart signals:** 1-A3, 3-C3 — the manager's context ("his role has no reason to touch that floor's charts") is often what converts a routine audit hit into a triageable event

**Framework note on correlation:** none of the five indicators is an accusation; each is a triage question with a documented innocent explanation. The insider threat posture this framework encodes is `privileged_account_findings.md` in operational form: watch the access, ask the question, involve HR and Legal only when evidence — not discomfort — supports it.

---

## 3. Reporting Process

Built directly on the channels, triage steps, and non-retaliation language in `reporting_and_triage_model.md`. The design goal: raise concerns without premature investigation and without any confrontation of a subject by a reporter or manager.

### 3.1 Reporting channels

| Channel | Intended use | Confidentiality |
|---|---|---|
| Anonymous web form | Employee concern without naming self | Anonymous; Legal-reviewed triage procedure required before launch (Maria Santos's condition) |
| security@meddefense.org | Non-urgent security concern | To IT Security |
| ext. 4-SECURITY | Immediate security concern — active account misuse, credential request, live remote-session request | To IT Security |
| HR hotline | Workplace concern with personnel sensitivity | To HR |
| Manager escalation | Operational context a manager is positioned to interpret | Manager forwards through the same intake — managers do **not** investigate |

**What to report — the observable-facts standard:** account used outside expected purpose, unusual access request, repeated bypass attempt, suspicious vendor pressure, data access inconsistent with role, someone asking for credentials or MFA codes, remote support request without ticket (`reporting_and_triage_model.md`). **What not to report:** speculation about personality, protected characteristics, or workplace disagreements. The distinction is not politeness; it is what triage can act on.

### 3.2 Anonymous path — documented triage procedure (required before go-live)

Legal review of this procedure is a launch precondition (`program_governance_roles.md`: "Legal review required before anonymous insider reporting launch"). The documented steps:

1. **Intake (automated):** the form records the report's date, channel, and stated observable facts — reporter identity is not captured, and the form states plainly what it does and does not record.
2. **Triage queue (IT Security):** a designated triage officer — not the reporter's chain of command, and not anyone named in the report — screens every submission for: (a) an observable fact vs. speculation, (b) an active/safety issue needing immediate routing to ext. 4-SECURITY handling, and (c) which downstream reviewer is appropriate.
3. **Evidence check (SOC/IT):** triage determines whether technical evidence exists for the claimed observation — TI-1 through TI-5 corroboration, IAM state, ticket records. An anonymous report with no verifiable observation is held for pattern-correlation, not investigated as an individual.
4. **Inclusion gates:** HR is included only if the concern involves employee conduct, manager action, or coaching; Legal is included if privacy, employment, or regulatory exposure exists. Neither is included by default.
5. **Minimum-necessary disclosure:** any onward communication shares only the facts required to triage the specific concern.
6. **Reporter acknowledgment:** where appropriate and feasible, acknowledgment is provided. Because anonymity blocks direct reply for form reports, the program publishes a quarterly transparency note summarizing report volume, triage outcomes, and corrections of the myth that anonymous reports vanish — a report that never visibly goes anywhere trains the workforce to stop reporting.

**Anti-abuse safeguards for the anonymous path:** the form rejects speculation-formatted submissions at step 2 (returned with an explanation of the observable-facts standard); reports that are demonstrably retaliatory in nature (aimed at a complainant in an open dispute) are referred to HR as a workplace-conduct matter, separate from security triage; and no anonymous report alone triggers an individual investigation — corroboration is always required.

### 3.3 Escalation threshold to HR and Legal

A concern escalates to HR and Legal when **one or more** of the following is documented — drawn verbatim from `reporting_and_triage_model.md`:

- technical evidence supports a policy violation
- a repeated pattern exists after coaching
- privileged access misuse is suspected
- patient record misuse is suspected
- a retaliation concern exists
- the manager is the subject of the report

Below that threshold, concerns stay in security triage and coaching channels. The 6x02 findings matter here: most of what the audit surfaced (dormant accounts, stale contractor access, unreviewed transfers) are hygiene defects with no individual wrongdoer — and treating them as such, through ticket and review workflows, is what keeps this program from being a surveillance program. Escalation describes evidence; triage describes curiosity.

### 3.4 Non-retaliation statement (with enforcement reference)

> MedDefense prohibits retaliation against any workforce member who raises a good-faith security or safety concern. Retaliation concerns are reviewed by HR and Legal. (`reporting_and_triage_model.md`, Non-Retaliation Statement)

Enforcement is structural, not aspirational: (a) retaliation is itself an escalation trigger listed in 3.3, mandating HR and Legal review; (b) consistent with the HR privacy boundary, no workforce member's good-faith report may appear in or influence any performance review (`hr_privacy_rules.md`, Performance Review Boundary); (c) simulation-related distress reporting follows the `hr_privacy_rules.md` support path, with no public naming; (d) the quarterly transparency note (3.2, step 6) makes non-retaliation publicly observable rather than merely promised.

### 3.5 What this process deliberately does not include

- no confrontation of a subject by reporters or managers (`manager_reference_constraints.md`)
- no search of personal devices under any circumstances
- no investigation launched on a single uncorroborated report
- no inclusion of a named employee's simulation results as insider-threat evidence — simulation data is training data under `hr_privacy_rules.md`, and the only documented bridge (privileged-segment repeat-click status prompting a technical fact-check) lives in `phishing_campaign_plan.md` Section 5 and reviews **account context**, never the person's motives

---

## 4. Manager Reference Guide

*(One page. Distributed to department managers after Legal review, per Maria Santos's condition. Companion to the section above — this page stands alone.)*

# Manager Reference: Noticing and Escalating Safely

**You are not an investigator.** You are the person positioned to notice operational context that tools never see. Your job is to observe, document, and escalate — through channels, not confrontations.

## Your responsibilities — what only you can notice

- role changes, transfers, and contractor end dates that should trigger access review (report them to IT/HR **when they happen**, not after an audit finds them)
- unusual access requests that do not fit the requester's duties
- behavior inconsistent with assigned duties, persisting across occasions
- repeated attempts to bypass approval processes after being declined
- signs of confusion or distress after a security simulation — route these to the support path, **never** to suspicion

## Before escalating — document

Write down, factually and privately:

- date and time
- the observable behavior (what happened, not what you infer from it)
- the system or process involved
- witnesses, if any
- the business context
- whether any immediate safety risk exists

If you cannot write the item as an observable fact, you do not yet have something to escalate. That standard protects your team as much as it protects the organization.

## When to escalate — to IT Security or HR

- the issue involves access to systems or patient records
- the behavior repeats after being addressed
- a vendor or employee requests unusual privilege
- a contractor or transferred employee still has old access
- an employee reports distress or fear after a simulation

Escalate through the standard channels: security@meddefense.org, ext. 4-SECURITY, the HR hotline, or the anonymous web form. You escalate the facts; triage decides the next step.

## What not to do — the non-negotiables

- **do not** confront the employee as a suspected insider
- **do not** search or ask to see personal devices
- **do not** tell the team about a concern — not even to "keep an eye out"
- **do not** include security-simulation clicks in performance review or any evaluative conversation
- **do not** draw conclusions about motive; that is for evidence, not intuition
- **do not** sit on urgent security reporting to "handle it locally" — if access, records, or money are involved, escalate now

## The tone we hold

This program is not surveillance. It is a safety and security reporting framework, and it survives only if the people inside it trust it. Preserve trust: escalate facts, protect individuals, and treat every colleague as a teammate having a rough day until evidence — not discomfort — says otherwise.

---

## 5. Culture and Ethics Statement

*(Distributed to all MedDefense employees. Word count: 200.)*

## Why This Program Exists — And What It Is Not

In our industry, the difference between a near-miss and a breach is often whether someone said something early. Our spring incident proved it: the warning signs were visible before the damage — a dormant account waking at 2 a.m., access that outlived a job change, a privilege granted without paperwork. Nobody needed to be a suspect for those signs to matter. They were just facts nobody had a way to raise.

This program gives us that way. It asks each of us to report **observable facts**: an account active outside its purpose, a request for credentials, a vendor pressing for access without a ticket, a data-access pattern that fits nobody's role. It asks managers to document what they see and escalate it — never to investigate colleagues themselves.

Here is what this program is not. It is not surveillance. We do not monitor personal devices or judge personalities, motives, or protected characteristics. Your security-training results are never performance data. Good-faith reports are always protected, and retaliation for raising one is itself a serious violation reviewed by HR and Legal.

You will never be punished for reporting honestly — including when you turn out to be wrong. Speak up about what you observe. It is the most protective thing any of us does.

---

## Deployment Conditions

1. **Legal review** of this document and the manager reference guide before any manager-facing distribution (HR Director's binding condition).
2. **Legal review** of the anonymous web form and its documented triage procedure (3.2) before the channel goes live — launch order: named channels first, anonymous path only after sign-off (`program_governance_roles.md`).
3. **Communications Lead** review of the employee-facing statement for plain language (`program_governance_roles.md`).
4. Anonymous-path go-live accompanied by the quarterly transparency-note commitment (3.2, step 6).
