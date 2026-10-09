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
