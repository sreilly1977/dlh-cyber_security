# Introduction

> "We don't rise to the level of our expectations; we fall to the level of our training." 
>
> — Archilochus

Everything you have built across this module gets used here. The IR program. The containment discipline. The forensic rigor. The detection rules and their validation. The post-incident improvement process. The tabletop methodology.

None of it is called out by name. None of it is guided step by step. Sunday evening, 19:43, MedDefense has a problem. You own the response from the first alert to the board brief the morning after.

This capstone does not introduce new techniques. It demands you apply the ones you have already built, at the same time, across the full incident lifecycle, in an environment you know. You will triage, contain, investigate, communicate, eradicate, recover, and improve, in that order, under that pressure, with nothing but your prior work as a reference.

Three review checkpoints are embedded in the capstone. They test whether you understand the principles behind what you have been doing, at the depth and difficulty the professional field expects. They are placed at the points where the operational work pauses long enough to ask a harder question.

# Why this matters

Incident response is a full-contact skill. Reading about containment is not the same as choosing between two containment strategies with patient care on the line. Understanding forensics is not the same as finding a 72-hour-old Cobalt Strike beacon in a memory dump. Knowing the HIPAA breach rule is not the same as writing the four-factor assessment for 1,847 patient files at midnight with a board meeting in nine hours.

The skills tested here, and the judgment required to apply them, are what the market looks for when it hires IR analysts, forensic investigators, detection engineers, and blue team leads. They appear in hiring exercises and practical interviews because they are the shape of the actual job.

# Context

Sunday, 19:43. Your personal device buzzes. It is Mike Torres.

"I need you on a call right now. Something is wrong at Site A. The on-call nurse says her workstation is crawling and files on her desktop look different. I checked the scheduling server, it is hammering the disk. I pulled the SIEM and I see a service installation alert on three hosts I have never seen before. I do not know what I am looking at."

You do.

The attacker gained initial access via a spearphishing email with a malicious Word document macro, delivered to the MedDefense on-call clinical coordinator on Thursday. The macro executed a PowerShell downloader that retrieved a Cobalt Strike beacon from a squatted Microsoft CDN domain. The beacon has been running for 72 hours.

During the dwell period, the attacker moved laterally to three additional workstations using extracted NTLM credential hashes, accessed the clinical documentation file server, and read 1,847 patient files, lab results and clinical notes. Ransomware staging scripts have been placed in system directories on four workstations. They have not yet executed.

You must contain this before Sunday is over.

Provided artifacts

    cs-ws-101.dd disk image of the initial compromised workstation, acquired before isolation

    cs-ws-101.mem memory dump of the same workstation, acquired at 19:38Z before the call

    proxy_72h.jsonl proxy logs for all MedDefense hosts covering the 72-hour dwell window

    sysmon_multihost.jsonl Sysmon process creation and network connection events across all affected hosts for the same window

    fileserver_access.evtx Windows Security Event Log from the file server covering the dwell period

---

# [0. Activate the IR Program](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/ir_activation.md)

## Goal: 

Open the incident, declare severity, and put the right people on the call.

## Context: 

Torres does not know what he is looking at. You do. The first decision you make sets the tempo for everything that follows.

## Instructions: 

Produce two artifacts.

[ir_activation.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/ir_activation.md): the formal record of the incident declaration. It must include: incident ID, declared at (UTC), declared by, initial severity with the explicit reasoning that supports it, which playbook was activated and why, who was notified in the first 15 minutes and at what time, and the first communication sent (verbatim, one paragraph, to the correct audience per your communication template).

[incident_timeline.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/incident_timeline.md): the append-only timeline that will be updated across every task in this capstone.

    Use torres_call_transcript.md before creating ir_activation.md. Treat the transcript as the initial operational signal that triggered the incident declaration and timeline opening.

Open it now with the first three entries: the initial user reports, the SIEM alert, and your incident declaration.

The timeline format is the one you established in earlier work: timestamp, type (OBSERVATION / DECISION / ACTION / COMMUNICATION / EVIDENCE), actor, description, source, certainty.

**Expected output**

<pre>
# IR Activation: IR-2026-0420-01

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52Z
- declared_by: <your_name>, on-call IR
- initial_severity: SEV1
- reasoning: ...
- playbook_activated: ...
- notifications:
    - 19:52Z: ...
    - 19:54Z: ...
    - 19:56Z: ...
- first_communication: executive_status_update sent to Dr. Morales at 20:05Z
</pre>

---

# [1. Preserve Evidence Across Four Hosts](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/evidence_preservation.md)

## Goal: 

Lock down the forensic record before any containment action changes it.

## Context: 

Four hosts are in scope. Each has a different urgency. Evidence preservation is not sequential, it is a parallel operation with a defined priority order.

## Instructions: 

Produce evidence_preservation.md. For each of the four affected hosts, define the acquisition priority, the exact commands or tools to capture volatile and non-volatile evidence, the SHA-256 verification step, and the chain of custody entry. The priority order must be explicitly justified based on the volatile state and the threat (ransomware staging, active beacon, credential material).

Affected hosts: WS-101 (initial compromised workstation), WS-104, WS-107, WS-112 (laterally compromised), and FILE-SVR-01 (file server with patient documentation access).

    Use torres_call_transcript.md to document the acquisition timeline and operational context around Torres's actions. The transcript may clarify timing assumptions and evidence handling sequence.

That is five hosts. The memory dump for WS-101 was already captured by Torres at 19:38Z. You must document that acquisition in the chain of custody even though you did not perform it, note the three-minute gap before Torres's call, and verify its integrity before any analysis.

For the remaining four, define the capture sequence and explicit rationale for the order chosen.

End the document with a chain of custody table covering all five hosts.

**Expected output**

<pre>
# Evidence Preservation: IR-YYYY-MMDD-01

## Priority order rationale

WS-101 is the initial compromise host; memory was already captured at 19:38Z by Mike Torres
(ART-001). Disk image must be captured before any containment action. WS-104 and WS-107
show active beaconing in Sysmon; memory must be captured before network isolation removes
C2 telemetry. FILE-SVR-01 has no active beacon but holds the PHI access record; disk image
priority is high but second to active-beacon hosts. WS-112 shows lateral logon events but
no current beacon activity; captured last.

## ART-001: cs-ws-101.mem (Torres acquisition)

- acquired_by: <name>
- acquired_at: <timestamp>
- tool: WinPmem
- sha256_at_acquisition: <recorded by Torres>
- sha256_verified_by_analyst: <computed at 20:10Z; must match>
- gap_note: 5-minute gap between acquisition (19:38Z) and declaration (19:52Z); state
  at acquisition reflects pre-call conditions; relevant for timeline correlation

## ART-002: cs-ws-101.dd

- priority: 1
- acquired_before: network isolation of WS-101
- tool: FTK Imager over IR jumpbox
- sha256: <computed and recorded at acquisition>
...
</pre>

---

# [2. Contain the Threat](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/containment_decision.md)

## Goal: 

Scope the compromise, choose a containment strategy, execute it, and document every trade-off.

## Context: 

Four workstations have an active Cobalt Strike beacon. The file server does not. Ransomware staging scripts exist but have not executed. The clinical site is operational. Every option costs something.

## Instructions: 

Produce two artifacts.

[containment_decision.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/containment_decision.md): present three containment strategies for the multi-host environment. For each: the action, the effect on the attacker, the effect on patient care, the evidence preserved and destroyed, the time to execute, and the reversibility. Declare the chosen strategy with a one-paragraph trade-off rationale that references the specific clinical and forensic stakes. Name the authorizing role and the rollback trigger.

[containment_execution.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/containment_execution.md): the step-by-step execution record. Each step carries: UTC timestamp, actor, action, expected outcome, observed outcome, deviation notes. Append each completed step as an ACTION entry to incident_timeline.md.

The execution record must cover: host isolation sequence for all five assets, the firewall egress rule for the C2 domain, the credential revocation sequence for accounts accessed during the 72-hour dwell, and the proof that the C2 beacon is severed.

**Expected output**

Structured Markdown following the formats established in prior projects. The decision document is bounded to one page. The execution record is append-only.

---

# 3. Quiz

---

# [4. Investigate the Full 72-Hour Attack Chain](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/forensic_findings.md)

## Goal: 

Reconstruct what the attacker did from first access to Sunday evening using all five artifact types.

## Context: 

You have memory, disk, proxy, Sysmon, and file server event logs. Each tells part of the story. None tells all of it. The forensic report is the synthesis.

## Instructions: 

Produce forensic_findings.md. Analyze all provided artifacts using the following toolchain. Document each finding with: the exact command run, the relevant output (abridged), the forensic conclusion, the ATT&CK technique, and the certainty level (confirmed, probable, possible).

    Use proxy_72h.sample.jsonl, sysmon_multihost.sample.jsonl, and fileserver_access.sample.json as schema references only. These files demonstrate field structure and event format; conclusions must come from the investigation artifacts.

Memory analysis (cs-ws-101.mem with Volatility 3)

    windows.pstree.PsTree: identify the process tree showing the beacon process and its parent

    windows.cmdline.CmdLine: extract command lines; identify the PowerShell downloader invocation

    windows.netscan.NetScan: confirm active C2 connection at time of capture

    windows.malfind.Malfind: identify injected memory regions in the beacon process

    windows.hashdump.Hashdump: NTLM hashes available in memory

Disk analysis (cs-ws-101.dd with TSK)

    Partition layout with mmls; filesystem metadata with fsstat

    File timeline with fls and mactime focused on AppData, Temp, and Windows\Tasks

    Extract and hash: the original malicious Word document, the PowerShell downloader script, the Cobalt Strike beacon DLL

Proxy log analysis (proxy_72h.jsonl)

    Identify the initial phishing URL access on Thursday

    Identify the first C2 beacon connection and its frequency pattern

    Identify any data staging or exfiltration patterns in the 72-hour window

Sysmon analysis (sysmon_multihost.jsonl)

    Map lateral movement: NTLM authentication events across WS-104, WS-107, WS-112

    Identify ransomware staging: cmd.exe or powershell.exe writing .bat or .ps1 scripts to system directories

    Identify service installation events matching the SIEM alert

File server analysis (fileserver_access.evtx)

    Identify the window when the attacker accessed patient files

    Count and categorize the 1,847 accessed records by file path and access time

    Determine which clinical accounts were used to authenticate

Close the document with an Attack chain summary table: one row per stage, with UTC timestamp range, ATT&CK technique, affected hosts, evidence source, and certainty.

**Expected output**

<pre>
# Forensic Findings: IR-2026-0420-01

## ART-001 verification

- sha256 at analysis start: <matches baseline>
- CoC entry updated: yes

## Memory analysis: cs-ws-101.mem

### Finding MEM-001: Beacon process in memory

$ vol -f cs-ws-101.mem windows.pstree.PsTree
...
* 4921  WINWORD.EXE    PPID=3104  Start: 2026-04-17T14:22:11Z
** 6201  powershell.exe PPID=4921  Start: 2026-04-17T14:22:44Z
*** 7318  svchost32.exe  PPID=6201  Start: 2026-04-17T14:23:02Z

Conclusion: WINWORD.EXE spawning PowerShell (macro execution); PowerShell spawning
svchost32.exe (naming mimicry; not a legitimate svchost path)
ATT&CK: T1566.001, T1059.001, T1036.005
Certainty: confirmed

### Finding MEM-002: Active C2 connection
...

## Attack chain summary
</pre>

---

# [5. Assess the Breach and Brief the Board](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/hipaa_assessment.md)

## Goal: 

Determine the regulatory obligation from the forensic findings and produce the executive brief that Dr. Morales presents Monday morning.

## Context: 

The file server evidence shows 1,847 patient files accessed. It is now 23:00 on Sunday. The board chair has requested a written brief by 07:00 Monday. Helena Reyes needs a HIPAA determination before she can advise.

## Instructions: 

Produce two artifacts.

[hipaa_assessment.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/): apply the HIPAA four-factor risk assessment to the 1,847 patient files accessed by the attacker. For each factor: state the evidence that supports your assessment, state the conclusion for that factor, and state the confidence level. End with a determination: does the four-factor assessment support a conclusion of low probability of compromise (no notification required), or does it fail to meet that threshold (notification required)? Name who makes the final determination and when.

[executive_brief.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/executive_brief.md): the document Dr. Morales will present to the board. Use the executive update template format. It must: name the incident clearly without jargon, state confirmed facts only (no speculation), describe the scope in patient terms (not technical terms), state the regulatory posture in one sentence, describe what has been done and what remains, and set the next update cadence.

    The same evidence structure is also available in fileserver_access.sample.json. Use findings from your forensic investigation rather than deriving conclusions from the sample file.

Constraints:

    The HIPAA assessment must reference specific forensic findings by evidence ID

    The executive brief is bounded to one page

    The executive brief contains no technical terms that require security knowledge to understand

    Every sentence in the executive brief is supported by something in the forensic findings

**Expected output**

<pre>
# HIPAA Breach Risk Assessment: IR-<YYYY-MMDD>-01

Assessment date: <YYYY-MM-DD>
Conducted by: <your_name>
Reviewed by: Helena Reyes, General Counsel (pending)
PHI involved: 1,847 patient files - lab results and clinical notes - accessed from FILE-SVR-01

## Factor 1: Nature and extent of PHI involved

Evidence: ...
Conclusion: ...
Confidence: ...

## Factor 2: ...
...
</pre>

---

# 6. Quiz

---

# [7. Eradicate and Validate Recovery](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/eradication_checklist.yaml)

## Goal: 

Remove every component of the attacker's foothold and prove the environment is clean.

## Context: 

A Cobalt Strike beacon with persistence, credential exposure across four hosts, staged ransomware scripts in four system directories, and a 72-hour dwell window. This is not a simple cleanup.

## Instructions: 

Produce two artifacts.

eradication_checklist.yaml: a YAML checklist with one item per eradication action. Each item: id, category, target_host, description, command_or_action, verification_command, expected_verification_result, status, executed_at, executed_by.

Categories must cover: beacon_process, persistence (service, registry run key, scheduled task), staged_payload (ransomware staging scripts), credential (all dwell-period accounts), kerberos (ticket invalidation), network (C2 domain egress block, squatted domain DNS sinkhole), machine_account (rotation for compromised hosts).

The checklist must cover all five hosts. Every item has a verification step. No item is marked complete without verification output.

recovery_validation.sh: a bash script that checks: no beacon process tree in the last 24 hours, no outbound connections to the C2 domain, no ransomware staging scripts in system directories across affected hosts, all clinical service endpoints responsive, all affected EDR agents reporting, the new Sigma rule (from Task 8) active in the SIEM. Exits 0 only if every check passes.

Expected output

$ ./recovery_validation.sh
[PASS] beacon: no svchost32.exe or related process tree in last 24h across all affected hosts
[PASS] c2: no outbound connections to staging.office365-cdn[.]net or 45.152.66.114
[PASS] ransomware staging: no .bat or .ps1 staging scripts found in Windows\System32 or ProgramData
[PASS] services: epic-api 200, lis-api 200, scheduling-api 200
[PASS] edr: all 5 hosts reporting to EDR console in last 5 minutes
[PASS] detection: sigma_cobalt_strike_beacon.yml active; synthetic test event returned expected hit
[PASS] evidence hashes: 11/11 artifacts match original SHA-256 baseline
ALL CHECKS PASSED


---

# [8. Improve the Defenses](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/sigma_cobalt_strike_beacon.yml)
### advanced

## Goal: 

Encode what this incident revealed into permanent changes to detection, hardening, and procedure.

## Context: 

The Cobalt Strike beacon ran for 72 hours. The macro executed without an alert. The NTLM lateral movement produced no detection. Three things must change before Monday.

## Instructions: 

Produce three artifacts.

[sigma_cobalt_strike_beacon.yml](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/sigma_cobalt_strike_beacon.yml): a Sigma rule targeting the Cobalt Strike process masquerading pattern observed in this incident: a process with a name mimicking a legitimate Windows service (e.g., svchost32.exe, lsass32.exe) running from a non-standard path, spawned by powershell.exe or wscript.exe. Include: full Sigma metadata (title, id, status, description, references, tags, author, date), correct logsource (process_creation, Windows), detection logic, at least two realistic false positives, and level high. Validate with yamllint.

[hardening_updates.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/hardening_updates.md): three specific, deployable hardening changes driven by the incident findings. Each change: the control, the exact configuration or GPO path, the gap it closes by Gap ID (write the gap IDs yourself based on the incident), and the validation test. Controls must include: macro execution restriction for non-developer workstations (ASR rule or Group Policy), NTLM relay mitigation (SMB signing enforcement), and one additional control of your choice that addresses a gap the investigation surfaced.

[playbook_delta.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/ir_dfir_playbook/5x05_breach_response/playbook_delta.md): two specific updates to the credential exposure playbook. For each update: the section changed, the before text (abbreviated), the after text, and the incident finding that justifies the change. Changes must be specific, not "improve detection" but the exact trigger condition, step, or decision node that is different.

    Use process and network patterns observed in sysmon_multihost.sample.jsonl as guidance when designing new detections. Improvements should target behaviors observed during the incident.

**Expected output**

A technically valid Sigma YAML, a hardening specification following the format established in prior projects, and a playbook delta document with before/after entries. All three artifacts are deployable without additional context.

---
