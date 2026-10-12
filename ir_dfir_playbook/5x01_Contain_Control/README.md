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

# [1. Open the Incident Timeline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control/incident_timeline.md)

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
 
# [2. Preserve Evidence Before Containment](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control/evidence_preservation.md)

## Goal: 

Capture volatile and short-lived evidence before any action that could destroy it.

## Context: 

Once you isolate, reset, or kill, certain evidence is gone. The order of operations is the work.

## Instructions: 

Create evidence_preservation.md as a runbook another analyst can follow end to end.

    Before writing the runbook, review evidence_store_init.sh, alert_A-20260414-9841.json, edr_wst_ws_031_24h.jsonl, proxy_24h_dmarsh.log, and auth_24h_dmarsh.json.

For each artifact, specify: what is captured, how (exact command or tool invocation), where it lands (evidence store path), hash algorithm and hash command, and ordering rationale (why this must precede the next containment step).

Cover at minimum:

    Volatile memory of WST-WS-031 (acquisition with winpmem or equivalent)

    Running process list with PIDs, command lines, parent PIDs

    Active network connections at the time of capture

    Full endpoint telemetry export for WST-WS-031 covering the 24 hours before the alert

    SIEM alert record exported in JSON

    Proxy and DNS logs for dmarsh for the 24 hours before the alert

    Authentication events for dmarsh for the 24 hours before the alert (Active Directory + Azure AD)

Every captured artifact carries a SHA-256 hash written to IR-YYYY-MMDD-01-hashes.txt. The runbook ends with a verification step that re-hashes the evidence store and compares against the original values.

**Expected output**

<pre>
# Evidence Preservation Runbook: IR-YYYY-MMDD-01

Evidence store: /evidence/IR-YYYY-MMDD-01/
Hash algorithm: SHA-256

## 1. Volatile memory, WST-WS-031

- what: full physical memory dump
- how: winpmem_3.3.rc3.exe -o \\evidence\IR-YYYY-MMDD-01\wst-ws-031.mem
- hash cmd: certutil -hashfile wst-ws-031.mem SHA256
- ordering: MUST precede any process kill or host isolation; memory state lost on power-off
- verification: hash written to /evidence/IR-YYYY-MMDD-01/hashes.txt

## 2. Process tree and network connections
...

## 8. Verification

- All artifacts re-hashed from the evidence store
- Hash values compared to original capture values
- Mismatches logged to the incident timeline as OBSERVATION entries
</pre>

---

# [3. Weigh Containment Options](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control/containment_decision.md)

## Goal: 

Choose a containment path with its trade-offs on the page.

## Context: 

Wrong containment preserves the attacker or destroys your evidence. The reasoning lives next to the decision.

## Instructions: 

Create containment_decision.md. Present at least three distinct containment strategies for WST-WS-031. For each strategy, document: action, effect on the attacker, effect on evidence, effect on patient care, time to execute, reversibility.

Then declare the chosen strategy with a rationale that references the trade-offs explicitly. The rationale is one paragraph, not one page.

Minimum candidate strategies to evaluate:

    Network isolation to a quarantine VLAN (block all outbound, allow forensic access from a jumpbox)

    Host power-off (immediate, destructive to volatile state)

    Selective process termination combined with a firewall egress block (fine-grained, observable)

Also document:

    The time window between evidence preservation (Task 2) and containment execution (Task 4)

    The approving authority for the chosen strategy

    A rollback plan if the chosen strategy causes unintended impact

Append a DECISION entry to incident_timeline.md linking to this document.

**Expected output**

<pre>
# Containment Decision: IR-YYYY-MMDD-01

## Candidate strategies

### A. Network isolation (quarantine VLAN)

- action: move WST-WS-031 to VLAN 999, block all outbound, allow IR jumpbox access only
- attacker effect: C2 severed; attacker on-host observation paused
- evidence effect: volatile state preserved
- patient care effect: one lab workstation unavailable; site has four spare workstations available
- time to execute: ~5 min
- reversibility: fully reversible

### B. Host power-off
...

### C. Selective process kill + egress block
...

## Chosen: A

Rationale: preserves volatile evidence for later forensic analysis, severs C2 immediately, remains fully reversible, and bounds the clinical impact because spare workstations are available in the lab. Option B destroys volatile evidence. Option C risks missed processes and does not address persistence.

## Execution window

- Evidence preservation end: 03:14Z
- Containment execution start: 03:16Z

## Approval

- Action authorized by James Chen, IR Commander, at 03:10Z

## Rollback plan

- If lab operations are blocked and spare workstations are unavailable, revert VLAN assignment within five minutes and fall back to Option C.
</pre>

---
