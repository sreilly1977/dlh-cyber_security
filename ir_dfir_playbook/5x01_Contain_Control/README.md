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

# [4. Execute Containment](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control/containment_execution.md)

## Goal: 

Carry out the chosen containment and record what actually happened.

## Context: 

Intent is not execution. The record must match what the evidence will later show was done.

## Instructions: 

Create containment_execution.md. List every concrete step executed against WST-WS-031. Each step carries: timestamp (UTC), actor, command or console action, expected result, observed result, deviation notes (if any).

Cover at minimum:

    VLAN reassignment or equivalent network isolation action

    Firewall egress rule blocking 185.220.101.47

    Evidence that outbound C2 is severed (packet capture or netflow gap with timestamps)

    Endpoint device containment flag set (if endpoint platform supports it)

    Confirmation the host is reachable only from the IR jumpbox

Append each step as an ACTION entry to incident_timeline.md.

**Expected output**

<pre>
# Containment Execution: IR-YYYY-MMDD-01

- 2026-04-14T03:16:04Z | <actor> | switchport VLAN reassign WST-WS-031 -> VLAN 999 | host reachable only from jumpbox | confirmed via ping from SOC jumpbox; timeout from user VLAN | no deviation

- 2026-04-14T03:17:21Z | <actor> | firewall deny outbound ip 185.220.101.47 | no new netflow to 185.220.101.47 after 03:17 | netflow confirmed zero packets to 185.220.101.47 from 03:17:21Z onward | no deviation

- 2026-04-14T03:19:02Z | <actor> | endpoint device containment flag SET on WST-WS-031 | only analyst tooling permitted outbound | confirmed in endpoint console | no deviation

- 2026-04-14T03:22:04Z | <actor> | verify isolation | ping from user VLAN fails, ping from jumpbox succeeds | verified | no deviation
</pre>

---

# 5 Quiz 

**No artefacts crated or output**

--

# [6. Plan Eradication with Verification](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control/eradication_checklist.yaml)

## Goal: 

List every eradication step paired with a verification that proves it was done.

## Context: 

Eradication is not a feeling. It is a list of specific items, each with a check that shows the item is gone.

## Instructions: 

Create eradication_checklist.yaml with an items array. Each item has: id, category, target_host, description, command_or_action, verification_command, expected_verification_result, status, executed_at, executed_by.

Categories used:

    malware_artifact: dropped files, scheduled tasks, registry persistence

    process: running processes tied to the attacker

    credential: compromised account password and active sessions

    machine_account: rotated machine account passwords for compromised hosts

    krbtgt: double-reset consideration with explicit rationale

    network: egress blocks and internal segmentation rules

Cover at minimum: the three affected hosts (WST-WS-031, WST-WS-017, LIS-WSIDE-01), the dmarsh account, the compromised Kerberos trust material, and both C2 IPs.

**Expected output**

```yaml
items:
  - id: ERAD-001
    category: malware_artifact
    target_host: WST-WS-031
    description: 
    command_or_action: remove X and X.exe
    verification_command: Test-Path on both paths and endpoint live-response file listing
    expected_verification_result: both paths return false and live-response returns no match
    status: pending
    executed_at: null
    executed_by: null

  - id: ERAD-002
    category: malware_artifact
    target_host: WST-WS-031
    description: Remove scheduled task persistence (random GUID name)
    command_or_action: schtasks /delete /tn <GUID> /f
    verification_command: schtasks /query | findstr <GUID>
    expected_verification_result: no matches
    status: pending

  - id: ERAD-006
    category: credential
    target_host: domain
    description: Reset dmarsh AD password and revoke Azure AD sessions and refresh tokens
    command_or_action: Set-ADAccountPassword + Revoke-AzureADUserAllRefreshToken
    verification_command: check Azure AD sign-in logs for reuse of prior tokens
    expected_verification_result: no successful sign-ins using prior tokens after reset
    status: pending

  - id: ERAD-010
    category: krbtgt
    target_host: domain
    description: Double-reset of krbtgt following confirmed Pass-the-Ticket
    command_or_action: Reset-ADAccountPassword -Identity krbtgt (twice, with full AD replication between resets)
    rationale: Pass-the-Ticket was observed on dmarsh; krbtgt material must be invalidated domain-wide to kill all outstanding forged tickets
    verification_command: audit TGT issuance timestamps and invalidate sessions older than reset
    expected_verification_result: no valid TGTs issued before the reset timestamp
    status: pending

  - id: ERAD-012
    category: network
    target_host: perimeter
    description: Egress deny for 185.220.101.47 and 91.234.99.107
    command_or_action: firewall policy update
    verification_command: netflow query for the last 24 hours toward both IPs
    expected_verification_result: zero packets
    status: pending
```

---

# [7. Validate Recovery](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control/recovery_validation.sh)
### advanced

## Goal: 

Prove the environment is clean and services are restored.

## Context: 

Assumption is not validation. Recovery is measured, not declared.

## Instructions: 

Write recovery_validation.sh, a bash script that runs a set of validation checks against a provided mock endpoint, SIEM, and netflow API, plus the local evidence store. Each check prints PASS or FAIL with a short reason.

    Use the mock validation API under mock_validation_api/. Start it with:

cd mock_validation_api
python3 -m http.server 8080 --bind 127.0.0.1

Your recovery_validation.sh should query the mock endpoints documented in mock_validation_api/README.md.

Required checks:

    No process tree of powershell.exe parent with msbuild.exe child in the last 24 hours across WST-WS-031, WST-WS-017, LIS-WSIDE-01

    No outbound connection to 185.220.101.47 or 91.234.99.107 in the last 24 hours

    No persistence artifacts on affected hosts (scheduled tasks with GUID names, Run key entries, dropped payloads in AppData\Local\Temp)

    Clinical service endpoints respond with HTTPS 200 on the provided health-check URLs for Epic and LIS

    Detection rule wz-edr-100041 is active and returns the expected hit from a synthetic event injection

    All artifact hashes in the evidence store re-match the values captured in Task 2

The script exits 0 only if every check passes. Any FAIL exits non-zero and prints a one-line summary of the failed checks at the end.

**Expected output**

```bash
$ ./recovery_validation.sh
[PASS] process tree: no powershell->msbuild in last 24h across WST-WS-031, WST-WS-017, LIS-WSIDE-01
[PASS] netflow: no outbound to 185.220.101.47 or 91.234.99.107 in last 24h
[PASS] persistence: no scheduled tasks, Run keys, or dropped payloads found
[PASS] service health: epic-api returns 200; lis-api returns 200
[PASS] detection: wz-edr-100041 returned expected synthetic hit at 2026-04-14T14:22:10Z
[PASS] evidence hashes: 14/14 artifacts match original SHA-256
ALL CHECKS PASSED
```

---

# [8. Package the Incident for Handoff](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x01_Contain_Control/incident_handoff.md)
### advanced

## Goal: 

Produce the single document a shift-relief analyst or a legal hold recipient can use as the authoritative record.

## Context: 

An incident is closed when someone else can own it with only the written record. The handoff package is that record.

## Instructions: 

Create incident_handoff.md. It must stand alone, no external memory, no verbal handoff required.

    Uses all generated artifacts plus hashes from Task 2

Required sections:

    Incident identity: id, severity, declared and closed timestamps, IR Commander, Scribe.

    Executive summary: 5 to 8 bullet points, no narrative.

    Scope: affected users, accounts, hosts, and data categories.

    Timeline: the full contents of incident_timeline.md, append-only, UTC.

    Decisions: reference to containment_decision.md plus a one-line recap of each decision taken.

    Evidence index: every preserved artifact with SHA-256 and storage path.

    Eradication status: reference to eradication_checklist.yaml with counts of complete versus pending.

    Recovery status: the output of recovery_validation.sh pasted in.

    Outstanding items: any action not yet complete, with owner and deadline.

    Regulatory posture: one paragraph stating whether HIPAA breach notification assessment is triggered and who owns it.

    Communications log: timestamped record of every status update issued, with audience and template used.

Length cap: 6 pages when rendered. Information density, not prose.

**Expected output**

A single complete incident_handoff.md for IR-YYYY-MMDD-01 with every section populated. Pastes from other task artifacts are allowed and expected.

---
