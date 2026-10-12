# Introduction

> "Everybody has a plan until they get punched in the mouth."
>
> — Mike Tyson

The alarm is going off. A process is talking to an IP it should not. A clinical workstation is executing code a clinical workstation should never run. You are on call. Nobody is coming to help you for the first thirty minutes.

In this project you run a live incident from the first alert to a clean handoff. You open the authoritative timeline, preserve the evidence that would disappear the moment you act, weigh containment options with their real costs, execute the chosen option, reassess when the scope expands on you, plan eradication as a checklist with verification, validate recovery with proof, and package the incident so another analyst can own it without asking a single question.

The outcome is not a narrative report. It is the paper trail of an incident, written in the order it happened, with the decisions and trade-offs captured on the page as they were made.

## Why this matters

Detection buys the first thirty seconds. Everything after that is response, and response is where careers are made or damaged.

Analysts who handle incidents well share a few habits. They open a timeline the moment they declare an incident. They preserve what they will need later before they touch anything. They pick containment actions deliberately, knowing what they gain and what they lose. They write down the decision the moment it is made, not after. They treat eradication as a list with verification, not a feeling. They validate recovery with evidence, not relief.

Those habits transfer across every environment, hospital, bank, SaaS, factory, public sector. They are what senior analysts grade on in hiring loops. They are what separates someone who "has handled incidents" from someone who handles them well.

Regulated environments raise the bar. When the incident touches patient data, payment data, or public services, the written record becomes the legal record. The artifacts you build here are the kind that survive that scrutiny and the kind that keep a real response from falling apart at the moment it matters.

## Context

It is 02:47 Z on a Tuesday morning. A monitoring rule fires on a MedDefense clinical workstation. An endpoint alert backs it up. The on-call pager goes off in your hand.

James Chen sends one message to the incident channel: "You own this. Contain it. Document everything."

The account showing activity belongs to Daniel Marsh, a laboratory technician at the West Campus. The host is WST-WS-031, a clinical workstation with access to the Laboratory Information System. No other analyst is online. Dr. Patricia Morales and Helena Reyes will wake up in the next two hours, and the first thing they will read is whatever you write between now and then.

---

# [1. Open the Incident Timeline]()

## Goal: 

Start the authoritative written record of the incident.

## Context: 

Every observation, decision, and action goes into one timeline, in time order, as it happens. If it is not on the timeline, it did not happen.

## Instructions: 

Create incident_timeline.md. The document is append-only and lives for the full duration of the incident.

    Use alert_A-20260414-9841.json and proxy_24h_dmarsh.log from the lab materials as the source evidence for the initial entries.

Required structure:

    Header block with: incident_id, declared_at (UTC), declared_by, initial_severity, current_severity, ir_commander, scribe.

    Legend defining entry types: OBSERVATION, DECISION, ACTION, COMMUNICATION, EVIDENCE.

    Entries as a chronological list. Each entry carries: timestamp (UTC, ISO 8601), type, actor, description (one line), source (alert ID, log file, artifact path), and certainty (one of confirmed, high, probable, possible).

Initial entries must include, at minimum:

    The alert firing at 02:47:11Z

    Your declaration of the incident

    The initial severity assignment and the rationale behind it

Rules:

    Append only. Never rewrite a past entry.

    If new information changes a past interpretation, append a new entry that references the old one.

    All timestamps are UTC.

**Expected output**

<pre>
# Incident Timeline: IR-YYYY-MMDD-01

## Header

- incident_id: IR-YYYY-MMDD-01
- declared_at: <timestamp>
- declared_by: <your_name>, on-call SOC
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: <your_name>

## Legend

- OBSERVATION: raw fact from an alert, log, or artifact
- DECISION: a choice made by an authorized actor, with rationale
- ACTION: an operation executed against an asset, with owner
- COMMUNICATION: a message sent or received, with audience
- EVIDENCE: a preserved artifact with hash and storage path

## Entries

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | powershell.exe parent of msbuild.exe on WST-WS-031 with outbound to 185.220.101.47:443 | source=alert A-20260414-9841 | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | <your_name> | Incident declared at SEV2: confirmed beaconing from clinical workstation; data exposure not confirmed yet | source=alert A-20260414-9841 + playbook PB-CRED-001 | certainty=confirmed

- ...
</pre>

---
