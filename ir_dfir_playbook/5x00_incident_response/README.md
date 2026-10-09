# Introduction

> "Plans are nothing; planning is everything." 
>
> — Dwight D. Eisenhower

An incident will happen. Not if. When. The only thing you control is whether your organization is ready to respond or has to improvise.

In this project you build the incident response capability for a regional healthcare organization. You produce the severity model, the team structure, the playbooks an on-call analyst will follow at 3 AM, and the communication templates that will land on the CEO's phone and the regulator's desk. You ship the artifacts. Real ones. The kind that end up in the folder titled "IR" on a team's shared drive.

## Why this matters

Your first week on a SOC or IR team, someone hands you a wiki. Inside are playbooks, severity levels, contact trees, and communication templates. They exist because someone before you sat down and wrote them. Those documents are the only thing standing between a tired analyst and a bad decision at 2 AM. As you grow in this field, you will start writing them yourself. New threats, new regulations, new business units, new tooling: the playbooks have to keep up. The people who lead IR functions are the ones who can turn messy operational reality into a repeatable process that anyone on the team can follow under pressure.

In regulated industries the stakes are higher. When a healthcare, finance, or utilities organization is breached, the first thing auditors and regulators ask for is the IR plan. If it does not exist, or reads like a theory paper, the fines arrive fast. The artifacts you build here are the kind that survive that scrutiny, and the kind that keep a real response from falling apart.

## Context

MedDefense Health Systems runs three hospital sites, employs 2,000 staff, and holds the clinical records of patients who cannot unshare their data. Detection capability has been improving. Response capability has not. When something breaks, people call people. Decisions happen in hallways. Almost nothing gets written down.

Dr. Patricia Morales, Chief Information Security Officer, has authorized a formal incident response capability and funded it out of the operational risk budget. James Chen, SOC Lead, owns the delivery and has handed you the build. His brief: "Executive review is in three weeks. I do not want a theory paper. I want artifacts the on-call analyst opens at 2 AM and follows without calling me."

You will work with:

    Sarah Park, IT Director

    Robert Kim, Infrastructure Lead

    Mike Torres, Network Engineer

    Helena Reyes, General Counsel

    Marcus Webb, Communications Director

What you ship in this project becomes the baseline IR capability for the organization. It is what the next real alert will be handled against.

---

# [1. Draft the Severity Matrix](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/severity_matrix.md)

## Goal: 

Define a shared language for incident severity that the whole organization can agree with.

## Context: 

SEV1 must mean the same thing to a Tier 1 analyst, to the CISO, and to the General Counsel. A severity matrix lives on a wiki, a one-pager, a printed binder. Make it readable at a glance.

## Instructions: 

Produce severity_matrix.md with the following structure:

    A short Purpose section (two sentences maximum).

    A Severity Matrix table with one row per level (SEV1 through SEV4, SEV1 being the most severe) and one column per criterion: Patient Safety Impact, Data Exposure, Service Availability, Max Response Time, Decision Authority.

    A Level Definitions section with one subsection per severity level. Each subsection lists two to three MedDefense-specific example triggers.

    A short Escalation Rule section stating how a severity is raised or lowered during an active incident.

Constraints:

    Patient Safety Impact uses values: none, low, moderate, high.

    Data Exposure uses values: none, suspected, confirmed_limited, confirmed_broad.

    Service Availability uses values: none, degraded, partial_outage, full_outage.

    Max Response Time is expressed in minutes.

    Decision Authority is a named role, not a person.

Note: Go check [this ressource](https://www.openstatus.dev/guides/incident-severity-matrix)

**Expected output**

<pre>
# MedDefense Severity Matrix

## Purpose

Common severity language for all MedDefense incidents. Applied from first alert through closure.

## Severity Matrix

Level 	Patient Safety Impact 	Data Exposure 	Service Availability 	Max Response Time 	Decision Authority
SEV1 	high 	confirmed_broad 	full_outage 	15 min 	CISO
SEV2 	moderate 	confirmed_limited 	partial_outage 	30 min 	IR Commander
SEV3 	low 	suspected 	degraded 	60 min 	SOC Lead
SEV4 	none 	none 	none 	240 min 	SOC Analyst

## Level Definitions

### SEV1

- Ransomware affecting clinical systems across multiple sites

- Confirmed exfiltration of patient records at scale

- Patient monitoring system offline during active care

### SEV2

- Confirmed compromise of a clinical-access account

- Malware confirmed on a single workstation at a clinical site

- Suspected exfiltration under investigation

### SEV3

...

### SEV4

...

## Escalation Rule

Severity is reviewed at every status update. It increases when new evidence raises patient safety, data exposure, or service availability to the next tier. It decreases only after confirmed containment and IR Commander approval.
</pre>

---

# [2. Structure the IR Team and Escalation Path](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/ir_team_structure.yaml)

## Goal: 

Document who does what and who gets called when.

## Context: 

During an incident, no one should have to ask "who decides this?" The answer must be on the page.

## Instructions: 

Produce ir_team_structure.yaml with two top-level sections.

Under roles, define each of the six roles below with: primary (named staff and title), backup (named staff and title), responsibilities (three bullet points maximum), and authority_ceiling (highest severity this role can own without escalating).

    IR_Commander

    Technical_Lead

    Communications_Lead

    Legal_Liaison

    Executive_Sponsor

    Scribe

Under escalation, for each severity SEV1 through SEV4, define:

    on_detection: roles notified when the incident is first declared

    on_confirmation: roles notified when compromise is confirmed

    on_scope_expansion: roles notified when scope grows beyond the initial assessment

    time_threshold_minutes_to_escalate: how long an incident can remain without progress before it escalates one level

**Expected output**

```yaml
roles:
  IR_Commander:
    primary: James Chen, SOC Lead
    backup: Robert Kim, Infrastructure Lead
    responsibilities:
      - Owns the incident through closure
      - Runs the incident bridge and timeline
      - Authorizes containment actions within authority ceiling
    authority_ceiling: SEV2
  Technical_Lead:
    ...

escalation:
  SEV2:
    on_detection:
      - IR_Commander
      - Technical_Lead
    on_confirmation:
      - Communications_Lead
      - Legal_Liaison
    on_scope_expansion:
      - Executive_Sponsor
    time_threshold_minutes_to_escalate: 60
  SEV1:
    ...
```

---

# [3. Design the Playbook Template](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/playbook_template.yaml)

## Goal: 

Build the reusable skeleton every MedDefense playbook will follow.

## Context: 

Standardize before you scale. When every playbook answers the same questions in the same order, a tired analyst knows exactly where to look.

## Instructions: 

Produce playbook_template.yaml with the sections listed below. Use angle-bracket placeholders for content to be filled in per scenario.

Required sections:

    playbook_id

    title

    owner_role

    applies_to with triggers and indicators

    severity_mapping with initial and escalate_if

    immediate_actions (first 15 minutes)

    evidence_preservation (what must be captured before any containment action)

    containment_actions (each with a trade_off field)

    eradication_actions

    recovery_validation

    communication_plan (each entry links audience and template file)

    escalation_triggers

    post_incident_tasks

The template itself is not populated. It is the skeleton the next three tasks will use.

**Expected output**

```yaml
playbook_id: <PB-XXX>
title: <short descriptive title>
owner_role: <which IR role executes this playbook>
applies_to:
  triggers:
    - <detection rule ID or alert condition>
  indicators:
    - <IOC type or observable pattern>
severity_mapping:
  initial: <SEV1-4>
  escalate_if:
    - <condition that raises severity>
immediate_actions:
  - step: <first action>
    owner: <role>
    timebox_minutes: <number>
evidence_preservation:
  - artifact: <what to capture>
    method: <how>
    before_step: <containment action this must precede>
containment_actions:
  - step: <specific action>
    owner: <role>
    decision_point: <if applicable>
    trade_off: <what this action preserves or sacrifices>
eradication_actions:
  - <specific removal or reset>
recovery_validation:
  - check: <how to confirm>
    criterion: <what passes>
communication_plan:
  - audience: <role or stakeholder>
    trigger: <when to communicate>
    template: <template file name>
escalation_triggers:
  - <condition that raises severity or scope>
post_incident_tasks:
  - <handed to the post-incident review>
```

---

# [4. Populate Playbook: Credential Exposure](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/playbook_credential_exposure.yaml)

## Goal: 

Apply the template to a confirmed credential compromise.

## Context: 

A MedDefense user enters their credentials on a fake Microsoft login page. Within the hour, the attacker signs in from a foreign IP. The on-call analyst needs to act, in order, with the correct decision authority.

## Instructions: 

Populate playbook_credential_exposure.yaml from your template. Another analyst must be able to execute it without asking questions.

Must include:

    Concrete containment actions: Active Directory password reset, Azure AD session revocation, MFA device reset, VPN token revocation, Epic session termination.

    Evidence preservation before any reset: authentication logs, Azure AD sign-in log export, affected mailbox export, recent data access audit export.

    A HIPAA assessment trigger: was ePHI accessible from the compromised account during the exposure window?

    A documented decision point: reset immediately and lose attacker session visibility, or monitor briefly and risk further compromise.

Do not add new sections to the template. Only fill the ones already defined.

**Expected output**

    Full populated YAML. Every section from the template is filled with MedDefense-specific content.

---

# [5. Clinical Service Degradation](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/playbook_clinical_degradation.yaml)

## Goal: 

Handle a suspected incident on a patient-facing clinical system without damaging patient care.

## Context: 

The radiology imaging server is slow. Nurses cannot pull X-rays for patients waiting in the ER. It might be performance. It might be an incident. You cannot just unplug it.

## Instructions: 

Populate playbook_clinical_degradation.yaml from your template.

**Must include:**

    Triage criteria that separate incident from performance (specific indicators for each).

    Partial containment options that avoid full outage: network segmentation, account restriction, service throttling.

    Patient safety coordination: the clinical role contacted before any isolation action.

    Clinical workflow fallback: the moment the on-call clinical lead activates downtime procedures.

    A decision point: investigate under downtime, or continue service with elevated monitoring and constrained access.

---

# [6. Suspected Insider Data Access](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/playbook_insider_access.yaml)
### advanced

## Goal: 

Handle possible misuse of legitimate access without alerting the subject.

## Context: 

An audit flags that a nurse accessed 47 patient records across two weeks, for patients outside her assigned care team. It could be curiosity, identity theft, or a workflow reason you do not yet see. You cannot confront her. You still have to act.

## Instructions: 

Populate playbook_insider_access.yaml from your template.

**Must include:**

    Evidence preservation before any confrontation: access logs, workstation state, email and messaging archives.

    HR and Legal involvement: who is pulled in at which severity, and who is explicitly not.

    Silent investigation posture: specific actions to avoid that would alert the subject.

    Access containment without visible change: role-based scope reduction, access review workflow, not account disable.

    HIPAA reporting pathway if misuse is confirmed as a reportable event.

---

# [7. Build the Communication Templates](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/comms_executive_update.md)
### advanced

## Goal: 

Produce written artifacts the IR team fills in, not composes, during an incident.

## Context: 

No one writes a regulator notification from scratch at 3 AM. You open a template, fill in the blanks, and send. Writing happens calmly, in advance.

## Instructions: 

Produce four Markdown templates. Each uses bracketed placeholders such as [incident_id], [systems_affected], [data_types], [containment_status], [next_update_utc].

[comms_executive_update.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/comms_executive_update.md). Audience: CISO and IT Director. Purpose: recurring 30-minute status during an active incident. Tone: dense, factual, no narrative.

[comms_legal_notification.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/comms_legal_notification.md). Audience: General Counsel (Helena Reyes). Purpose: open a legal channel under privilege. Tone: factual, no speculation, no conclusions.

[comms_regulator_notification.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/comms_regulator_notification.md). Audience: HHS OCR. Purpose: HIPAA breach notification draft aligned with 45 CFR 164.404 content requirements. Tone: compliance-driven, no narrative framing.

[comms_patient_notification.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x00_incident_response/comms_patient_notification.md). Audience: affected patients. Purpose: required notification letter. Tone: plain language, non-alarming, action-oriented.

Each template must have three clearly marked zones: a header block (audience, classification, cadence), a body block (required fields as placeholders), and a footer block (next update or sign-off).

**Expected output**

Four Markdown files. Each is usable as-is when placeholders are filled.

<pre>
# Executive Status Update

**Audience:** CISO, IT Director
**Classification:** Internal, IR team only
**Cadence:** Every 30 minutes during active incident

## Incident identity

- Incident ID: [incident_id]

- Severity: [current_severity]

- Detected at: [detection_time_utc]

## Confirmed facts

- [confirmed_fact_1]

- [confirmed_fact_2]

## Current containment status

- [containment_state]

## Systems affected

- [systems_list]

## Data exposure status

- [data_exposure_state]

## Actions in the next 30 minutes

- [next_action_1]

- [next_action_2]

## Decisions needed from you

- [decision_if_any]

Next update: [next_update_utc]
Owner: [ir_commander_name]
</pre>

---
