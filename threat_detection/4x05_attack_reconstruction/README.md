# Introduction

> "The investigator who can only see one piece of the puzzle will draw the wrong picture every time." 
> 
> — Adapted from Locard's Exchange Principle

Six weeks ago you opened a batch of suspicious emails and asked a simple question: is MedDefense being targeted ? The answer was yes. Since then you have chased the HEALTHBANE campaign across five investigation domains. You analyzed phishing lures and extracted IOCs. You decoded network traffic and found C2 beaconing hidden in routine HTTPS connections. You consumed threat intelligence from government advisories and commercial feeds and built an ATT&CK mapping that transformed scattered indicators into a structured adversary profile. You triaged three malware samples and understood exactly how the attacker turns a stolen credential into exfiltrated patient data. And you hunted proactively through 14 days of SIEM data, finding lateral movement that no detection rule caught.

Each investigation answered questions. Each also raised new ones. The phishing analysis could not tell you what happened after the click. The network forensics could not explain the malware payloads. The intelligence mapping could not confirm which techniques were actually used against MedDefense. The malware analysis could not reveal how the attacker moved laterally. And the threat hunt found lateral movement but could not determine the full scope of compromise.

You have five partial pictures. This project creates the complete one.

Attack reconstruction is the discipline of integrating evidence from multiple investigation domains into a single, coherent, chronological account of an attack. It is not a summary of previous work. It is an analytical process that reveals things no single investigation could: timeline contradictions that expose gaps in collection, technique correlations that confirm attribution confidence, evidence convergences that strengthen findings from LOW to HIGH confidence, and defensive blind spots that only become visible when you see the full kill chain.

This is the work that separates a junior analyst who produces findings from a senior analyst who produces understanding.

## Why This Matters

In professional incident response, the reconstruction report is the deliverable that matters most. It is the document that the CISO presents to the board. It is the artifact that legal counsel uses to determine regulatory notification obligations. It is the reference that detection engineering uses to close coverage gaps. It is the record that auditors review to assess whether the organization met its duty of care.

A reconstruction that misses a phase, contradicts its own evidence, or fails to connect findings across sources is worse than no report at all. It creates false confidence. It closes investigations that should remain open. It lets the attacker retain footholds that the analyst failed to connect.

## Context

Week seventeen at MedDefense Health Systems. Thursday morning.

James Chen stands at the whiteboard. The entire security operations team is present. Dr. Patricia Morales is on video. The whiteboard shows a timeline with five colored segments, each labeled with a project number. There are gaps between the segments.

"It has been six weeks since the first phishing email. In that time, this team has done more analytical work on a single campaign than most organizations manage in a year. But here is the problem."

He draws circles around the gaps on the whiteboard.

"We investigated in pieces. Each investigation was excellent. Each produced findings I would put in front of any auditor. But when I try to assemble them into a single story for the board, the pieces do not connect cleanly. The timestamp from the network analysis does not match the timestamp from the SIEM hunt. The IOC from the phishing investigation appears in the malware analysis but NOT in the network capture. The ATT&CK mapping from 4x02 says a technique was 'inferred' but the hunt from 4x04 confirmed a DIFFERENT variant of that technique."

He pauses.

"And then there is the incident response."

James explains: after the threat hunt recommended immediate incident response for WS-RECV-03, the IR team spent five days isolating the host, imaging its disk, capturing volatile memory before shutdown, and pulling 14 days of firewall session logs from the segment switch. Their evidence package arrived this morning.

"The IR findings make the reconstruction both easier and harder. Easier because they fill gaps we could not fill before. Harder because they surface things we did not expect."

He lists the surprises:

"First: the memory capture found a scheduled task on WS-RECV-03 that was set to execute every night at 02:00. That is a persistence mechanism we never detected. Our SIEM rules did not look for scheduled task creation. Our hunt hypotheses did not include persistence. The attacker was not just moving laterally. They were establishing a foothold."

"Second: the disk forensics recovered deleted files in a temporary directory. Compressed archives containing what appear to be database query results. Patient records. The attacker was STAGING data for exfiltration. They had already accessed the health records database and were preparing to move data out. Our network forensics from 4x01 found the DNS exfiltration CHANNEL but we assumed it was only used for C2. The disk evidence suggests it was also used -- or was about to be used -- for data exfiltration."

"Third: the firewall session logs show connections from WS-RECV-03 to an IP address that does not appear ANYWHERE in our previous investigations. Not in the phishing domains, not in the C2 infrastructure, not in the threat intelligence feeds. Either this is a secondary C2 channel we completely missed, or it is unrelated. I need to know which."

Dr. Morales speaks from the screen:

"The board meets in one week. They want three answers. First: exactly what happened, from start to finish, with evidence behind every claim. Second: exactly what data was at risk and whether any left our network. Third: exactly what we are doing to ensure this never happens again. I have presented incremental updates after each investigation. This time I need the complete picture. One report. One timeline. One recommendation package."

James turns to you.

"I need you to take everything we have -- every finding from every investigation, plus the new IR evidence -- and reconstruct the full HEALTHBANE attack against MedDefense. Not a summary of five projects. A RECONSTRUCTION. Every phase connected. Every technique mapped. Every IOC cross-referenced. Every gap identified and documented. Every claim supported by evidence from at least two independent sources where possible."

It contains:

New evidence (from incident response):

    ir_evidence/memory_artifacts.txt -- Volatile memory forensics from WS-RECV-03: process list at capture time, active network connections, loaded modules, registry hive extracts including scheduled task definitions

    ir_evidence/disk_forensics_report.txt -- Disk image analysis: recovered deleted files, prefetch entries, NTFS $MFT timeline for key directories, scheduled task XML, registry persistence keys, anti-forensics indicators

    ir_evidence/firewall_sessions_ws_recv_03.json -- Fourteen days of stateful firewall session logs for the WS-RECV-03 network segment (source IP, destination IP, port, protocol, bytes transferred, timestamps, session duration)

    ir_evidence/ir_team_notes.txt -- The IR team's preliminary observations (some confirmed, some flagged as unverified, some requiring analyst validation)

Previous investigation summaries (consolidated reference):

    previous_findings/4x00_phishing_summary.txt -- Key findings from the phishing dissection: campaign classification, extracted IOCs, credential exposure assessment, detection rules deployed

    previous_findings/4x01_network_timeline.txt -- Network forensics timeline: C2 beaconing pattern, DNS exfiltration indicators, lateral movement traces, PCAP-derived IOCs

    previous_findings/4x02_attack_mapping.json -- HEALTHBANE ATT&CK Navigator layer at 40% coverage (post-intelligence analysis) with technique confidence levels

    previous_findings/4x03_malware_summary.txt -- Malware triage findings: dropper capabilities, RAT C2 protocol, exfiltrator targeting and methodology, behavioral IOCs, ATT&CK update to 55%

    previous_findings/4x04_hunting_report.txt -- Threat hunt findings: confirmed Stage 4 lateral movement, behavioral anomalies, detection rules deployed, ATT&CK update to 80%, remaining gaps

Reference files:

    reference/network_topology.txt -- MedDefense network topology with host roles, VLANs and authorized users

    reference/healthbane_ioc_master.json -- Consolidated IOC database from all previous investigations (4x00 through 4x04)

    reference/attck_navigator_80pct.json -- Current ATT&CK Navigator layer at 80% coverage (post-4x04)

    reference/meddefense_asset_inventory.txt -- Asset classification with data sensitivity ratings (which systems hold patient data, financial data, operational data)

---

# [0. Evidence Inventory](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/0-evidence_index.sh)

## Goal: 

Catalog every evidence source available for the reconstruction, assess its reliability and coverage scope, and identify gaps in the evidence landscape that will constrain the reconstruction.

## Context: 

Professional reconstruction begins with an evidence inventory, not with analysis. An investigator who dives into individual artifacts before understanding what evidence exists, what it covers and what it does NOT cover will produce a reconstruction shaped by availability bias rather than analytical rigor. The inventory forces you to see the full evidence landscape before you start interpreting any single piece of it.

## Instructions: 

Write a script 0-evidence_index.sh that:

    Reads every evidence source in the reconstruction package (both ir_evidence/ and previous_findings/ and reference/)

    For each source, outputs a structured catalog entry containing:

    Source identifier (filename)

    Investigation phase (4x00 through 4x05-IR)

    Evidence type (email, network, intelligence, malware, SIEM, memory, disk, firewall)

    Temporal coverage (date range the evidence covers)

    Reliability assessment (HIGH: primary evidence collected under controlled conditions; MEDIUM: derived findings from a previous investigation; LOW: preliminary or unverified observations)

    Key IOCs or findings contained in the source (summary, not exhaustive)

    Produces a coverage matrix showing which evidence types cover which time periods, and identifies temporal gaps (periods with no evidence coverage) and domain gaps (attack phases with only one evidence source)

    Lists the critical questions the reconstruction must answer, derived from the evidence gaps

**Expected Output:**

```bash
$ ./0-evidence_index.sh

================================================================
   EVIDENCE INVENTORY - HEALTHBANE Reconstruction
   Analyst: [hostname]    Date: [date]
================================================================

SOURCE CATALOG:
  [01] 4x00_phishing_summary.txt
       Phase: 4x00 (Phishing Dissection)
       Type: Email analysis findings
       Coverage: Week 11 (initial campaign detection)
       Reliability: MEDIUM (derived summary, not raw evidence)
       Key content: 8 emails analyzed, 3 confirmed malicious,
                    campaign domains, SPF/DKIM failures, credential
                    exposure for Diane (WS-RECV-03 user)

  [02] 4x01_network_timeline.txt
       Phase: 4x01 (Network Forensics)
       Type: PCAP-derived findings
       Coverage: 48h window surrounding phishing incident
       Reliability: MEDIUM (derived timeline, not raw PCAPs)
       Key content: C2 beaconing (5-min intervals), DNS tunneling,
                    lateral movement traces

  [... additional sources ...]

  [11] ir_team_notes.txt
       Phase: 4x05-IR (Incident Response)
       Type: Preliminary observations
       Coverage: WS-RECV-03 capture (Week 16-17)
       Reliability: LOW (preliminary, some unverified)
       Key content: Observations requiring analyst validation

TEMPORAL COVERAGE MATRIX:
  Week 11  [EMAIL][NETWORK][--------][--------][--------][--------]
  Week 12  [------][--------][INTEL---][--------][--------][--------]
  Week 13  [------][--------][--------][MALWARE-][--------][--------]
  Week 14  [------][--------][--------][--------][SIEM----][--------]
  Week 15  [------][--------][--------][--------][SIEM----][--------]
  Week 16  [------][--------][--------][--------][SIEM----][IR------]

  GAP: No network capture data after Week 11 48h window
  GAP: No endpoint telemetry before Week 14 SIEM collection
  GAP: Memory/disk evidence only for WS-RECV-03, not other hosts

CRITICAL QUESTIONS FOR RECONSTRUCTION:
  [Q1] Does the new firewall evidence confirm or contradict the
       4x01 network timeline for WS-RECV-03 ?
  [Q2] What is the unknown IP in firewall sessions -- secondary
       C2 or unrelated traffic ?
  [Q3] Did the data staging succeed in exfiltrating patient data,
       or was it interrupted by the hunt ?
  [Q4] Are there additional persistence mechanisms beyond the
       scheduled task found on WS-RECV-03 ?
  [Q5] What ATT&CK techniques remain unmapped after integrating
       all evidence sources ?

================================================================
```

---

# [1. Memory Artifact Analysis](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/1-memory_analysis.sh)

## Goal: 

Analyze the volatile memory forensics from WS-RECV-03 to identify active processes, network connections, loaded modules and persistence mechanisms that were invisible to SIEM-based detection.

## Context: 

Memory forensics captures the state of a system at a specific moment in time. Unlike disk evidence (which shows what was stored) or network evidence (which shows what was transmitted), memory evidence shows what was RUNNING. A process that deleted itself from disk is still visible in memory. A network connection that completed before the PCAP started is still visible in memory. A credential that was used and discarded is still visible in memory.

The IR team captured WS-RECV-03's memory before shutting the system down. The memory artifacts file contains the extracted results: process list, network connections at time of capture, loaded DLLs, and registry hive extracts including scheduled task definitions. Your job is to analyze these artifacts for indicators relevant to the HEALTHBANE reconstruction.

## Instructions: 

Write a script 1-memory_analysis.sh that:

    Parses ir_evidence/memory_artifacts.txt and extracts:

    Running processes at capture time, identifying any process that matches known HEALTHBANE indicators (svchostupdate.exe, synchealthdata.ps1, or variants) or suspicious unsigned processes

    Active network connections, identifying any connection to known HEALTHBANE C2 infrastructure (from the IOC database) or to the unidentified IP flagged by James Chen

    Loaded modules or DLLs associated with credential access tools

    Scheduled task definitions extracted from the registry hive

    Cross-references each finding against reference/healthbane_ioc_master.json to determine whether the indicator is KNOWN (matches existing IOC), NEW (not in any previous investigation) or MODIFIED (variant of known IOC)

    For each finding, outputs: the artifact, its source location in memory, the ATT&CK technique it maps to, and its status (KNOWN/NEW/MODIFIED)

    Identifies the scheduled task persistence mechanism, documenting: task name, trigger schedule, action (what command it executes), creation timestamp, and the ATT&CK technique (T1053.005 Scheduled Task/Job)

**Expected Output:**

```bash
$ ./1-memory_analysis.sh

================================================================
   MEMORY ARTIFACT ANALYSIS - WS-RECV-03
   Source: ir_evidence/memory_artifacts.txt
================================================================

PROCESS ANALYSIS:
  PID   Process Name          Status    ATT&CK
  ---   ----                  ------    ------
  [...]  svchost.exe          LEGITIMATE (Microsoft signed, standard path)
  [...]  taskhostw.exe        LEGITIMATE (scheduled task host)
  [...]  [suspicious_process] SUSPICIOUS  T1059.001 PowerShell
         -> Command line contains encoded payload
         -> NOT in previous IOC database: NEW indicator

NETWORK CONNECTIONS (at capture):
  Source           Dest              Port  Status   IOC Match
  10.10.50.22      [C2_IP]           443   ESTAB    KNOWN (4x01)
  10.10.50.22      [unknown_IP]      8443  ESTAB    NEW
  10.10.50.22      10.10.30.10       445   ESTAB    KNOWN (4x04 lateral)

  NEW FINDING: Connection to [unknown_IP]:8443 confirms secondary
  C2 channel not observed in previous investigations.

CREDENTIAL ACCESS INDICATORS:
  [*] Module loaded: [credential_tool_indicator]
      ATT&CK: T1003.001 LSASS Memory
      Status: Confirms 4x04 hypothesis H4

PERSISTENCE MECHANISM:
  Scheduled Task: "HealthSync Update Service"
    Trigger: Daily at 02:00
    Action: powershell.exe -enc [encoded_command]
    Created: 2024-02-06T01:47:33
    ATT&CK: T1053.005 Scheduled Task/Job
    Status: NEW - not detected by any previous investigation

  CRITICAL: This scheduled task was created on Feb 06, two days
  after the initial credential dump (Feb 04 from 4x04 hunt).
  The attacker established persistence BEFORE deploying the
  exfiltration tooling.

SUMMARY:
  Known indicators confirmed: [N]
  New indicators discovered: [N]
  ATT&CK techniques identified: T1059.001, T1003.001, T1053.005
  Confidence: HIGH (primary volatile evidence)

================================================================
```

---
