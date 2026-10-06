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

# [2. Disk Forensics Analysis](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/2-disk_analysis.sh)

## Goal: 

Analyze the disk forensics report from WS-RECV-03 to identify persistence artifacts, data staging evidence, recovered deleted files and anti-forensics indicators.

## Context: 

Disk forensics captures what was stored. Unlike memory (which shows the running state at one moment), disk evidence shows the history: files created, modified, deleted and partially overwritten. The IR team analyzed the disk image and produced a structured report. Your job is to extract the findings relevant to the HEALTHBANE reconstruction.

The most significant finding flagged by James Chen is the recovered deleted files suggesting data staging. If the attacker was compressing and staging patient data before exfiltration, the impact assessment changes fundamentally. The difference between "attacker had access to the database server" and "attacker staged patient records for exfiltration" is the difference between a security incident and a reportable data breach.

## Instructions: 

Write a script 2-disk_analysis.sh that:

    Parses ir_evidence/disk_forensics_report.txt and extracts:

    Recovered deleted files: filenames, original paths, deletion timestamps, recoverable content indicators

    Prefetch entries: programs executed on WS-RECV-03 with first and last execution timestamps (programs that SHOULD NOT be on a records department workstation are suspicious)

    Scheduled task XML: full task definition confirming the memory findings from T1

    Registry persistence keys: any Run/RunOnce entries or service registrations

    NTFS $MFT timeline: file creation and modification events in key directories during the attack window (Feb 04-12)

    Anti-forensics indicators: evidence of log deletion, timestamp manipulation or artifact removal

    Cross-references the prefetch entries against the network topology to identify tools that a records department workstation should never have executed (e.g., PsExec, remote administration tools)

    Analyzes the recovered deleted files to determine:

    What data was being staged (file sizes, naming patterns, content indicators)

    Whether the staging was completed or interrupted

    The ATT&CK techniques involved (T1074.001 Local Data Staging, T1560.001 Archive Collected Data)

    Checks for anti-forensics activity and maps it to ATT&CK (T1070.001 Clear Windows Event Logs if applicable)

**Expected Output:**

```bash
$ ./2-disk_analysis.sh

================================================================
   DISK FORENSICS ANALYSIS - WS-RECV-03
   Source: ir_evidence/disk_forensics_report.txt
================================================================

RECOVERED DELETED FILES:
  File                      Orig Path            Deleted     Size
  staging_export_001.zip    C:\Users\Public\Tmp\  Feb 10     14.2 MB
  staging_export_002.zip    C:\Users\Public\Tmp\  Feb 11     11.8 MB
  query_results.csv         C:\Users\Public\Tmp\  Feb 10     8.4 MB

  ANALYSIS: Three files recovered from C:\Users\Public\Tmp\.
  Naming pattern suggests structured data export. CSV file size
  consistent with database query results. ZIP files created AFTER
  CSV, suggesting compression for exfiltration staging.
  ATT&CK: T1074.001 Local Data Staging, T1560.001 Archive via Utility
  CRITICAL: Staging occurred Feb 10-11, hunt detected activity Feb 12.
  The attacker was preparing to exfiltrate when the hunt interrupted.

PREFETCH ANALYSIS:
  Program              First Exec    Last Exec     Expected?
  PSEXEC.EXE           Feb 05 02:13  Feb 12 01:44  NO (records WS)
  POWERSHELL.EXE       Jan 15 09:00  Feb 12 02:01  PARTIAL (normal use
                                                     but off-hours suspect)
  [STAGING_TOOL]       Feb 09 23:41  Feb 11 01:15  NO (data collection)
  CMD.EXE              Jan 02 10:00  Feb 12 01:55  YES (standard)

SCHEDULED TASK (confirms memory analysis):
  Task XML: HealthSync Update Service
  Trigger: DailyTrigger, StartBoundary=02:00:00
  Action: powershell.exe -ExecutionPolicy Bypass -enc [base64]
  Registration: 2024-02-06T01:47:33
  -> CONFIRMED: matches memory artifact from T1

REGISTRY PERSISTENCE:
  HKLM\...\Run: No suspicious entries found
  HKCU\...\Run: No suspicious entries found
  -> Attacker relied on scheduled task, not registry run keys

ANTI-FORENSICS INDICATORS:
  [*] Windows Security Event Log: gap from Feb 08 03:00 to 03:12
      -> 12-minute gap consistent with selective event deletion
      ATT&CK: T1070.001 Clear Windows Event Logs
  [*] $MFT timestamps for C:\Users\Public\Tmp\: standard ordering
      -> No timestamp manipulation detected

NTFS TIMELINE (attack window Feb 04-12):
  Feb 04 01:23  credential_tool created in C:\Windows\Temp\
  Feb 06 01:47  Scheduled task XML written
  Feb 08 02:55  [Evidence of lateral movement tool usage]
  Feb 09 23:41  First staging tool execution
  Feb 10 14:22  query_results.csv created
  Feb 10 15:07  staging_export_001.zip created
  Feb 11 01:08  staging_export_002.zip created
  Feb 11 01:22  Deleted files: query_results.csv, staging zips
  Feb 12 01:44  Last PsExec execution (detected by 4x04 hunt)

SUMMARY:
  New ATT&CK techniques: T1074.001, T1560.001, T1070.001
  Evidence confirms data staging for exfiltration
  Staging interrupted before confirmed data exfiltration
  Anti-forensics: partial log deletion (12-min gap)

================================================================
```

---

# [3. Firewall Session Analysis](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/3-firewall_analysis.sh)

## Goal: 

Analyze 14 days of firewall session logs for WS-RECV-03 to map external communications, identify the unknown IP address, correlate network activity with the reconstructed timeline and determine whether data exfiltration occurred.

## Context: 

Firewall session logs record every connection that passes through the network boundary. Unlike PCAPs (which capture packet content), session logs capture metadata: who talked to whom, on what port, for how long, and how much data moved. This makes them ideal for answering the exfiltration question. If the attacker moved data out of the network, the bytes-transferred field will show it.

The 4x01 network forensics had PCAP coverage for only 48 hours. These firewall logs cover 14 days. This is the first evidence source that spans the full attack window. It will either confirm or reshape the timeline you built from partial evidence.

## Instructions: 

Write a script 3-firewall_analysis.sh that:

    Parses ir_evidence/firewall_sessions_ws_recv_03.json using jq and produces:

    Total session count for the 14-day period

    Breakdown by destination: internal (10.x.x.x) vs external, with session counts and total bytes for each

    Top 10 external destinations by total bytes transferred, with port and protocol

    Top 10 internal destinations by session count (identifying which internal servers WS-RECV-03 communicated with most)

    Identifies the unknown IP address flagged by James Chen:

    Session count, total bytes, port, protocol, time pattern

    Determines whether this IP correlates with any known HEALTHBANE infrastructure (by comparing port, protocol and communication pattern against 4x01 findings)

    Assesses whether this represents a secondary C2 channel, a staging server, or unrelated traffic

    Performs temporal analysis:

    Charts sessions per hour to identify off-hours activity clusters

    Correlates off-hours external connections with the 4x04 lateral movement timeline

    Identifies any large data transfers (bytes_out > threshold) and their timestamps

    Answers the critical exfiltration question: does the bytes-transferred data show evidence of data leaving the network ? Cross-references transfer volumes against the staging file sizes from T2.

**Expected Output:**

```bash
$ ./3-firewall_analysis.sh

================================================================
   FIREWALL SESSION ANALYSIS - WS-RECV-03
   Source: ir_evidence/firewall_sessions_ws_recv_03.json
   Period: 2024-02-01 to 2024-02-14
================================================================

SESSION OVERVIEW:
  Total sessions: [N]
  Internal destinations: [N] sessions ([bytes] total)
  External destinations: [N] sessions ([bytes] total)

TOP EXTERNAL DESTINATIONS (by bytes):
  Rank  IP              Port  Proto  Sessions  Bytes Out  Bytes In
  1     [C2_IP]         443   TCP    [N]       [bytes]    [bytes]
  2     [unknown_IP]    8443  TCP    [N]       [bytes]    [bytes]
  3     [legitimate]    80    TCP    [N]       [bytes]    [bytes]
  [...]

UNKNOWN IP INVESTIGATION:
  IP: [unknown_IP]:8443
  First seen: Feb 06 02:12
  Last seen: Feb 12 01:33
  Sessions: [N]
  Pattern: [N]-minute intervals, off-hours only (01:00-04:00)
  Bytes out: [total] | Bytes in: [total]

  ASSESSMENT: Communication pattern (fixed interval, off-hours,
  encrypted port) is consistent with secondary C2 channel.
  First seen Feb 06 -- same day as scheduled task creation.
  This IP does NOT appear in 4x01 PCAPs (collection window
  ended before Feb 06). NOT in IOC database.
  CONFIDENCE: PROBABLE secondary C2 infrastructure.
  -> NEW IOC: [unknown_IP] (secondary C2, high confidence)

TEMPORAL ANALYSIS:
  Business hours (08:00-18:00): [N] sessions/day avg
  Off-hours (18:00-08:00): [N] sessions/day avg
  Off-hours EXTERNAL sessions cluster on: Feb 05, 08, 11, 12
  -> Matches 4x04 lateral movement sessions exactly

EXFILTRATION ASSESSMENT:
  Largest single outbound transfer: [bytes] to [IP] on [date]
  Total outbound to C2 infrastructure: [bytes]
  Total outbound to unknown IP: [bytes]
  Staging file sizes (from T2): ~34.4 MB total

  FINDING: Total outbound bytes to suspicious destinations
  ([total]) is [LESS/MORE] than staging file sizes.
  [Assessment of whether exfiltration occurred or was interrupted]

================================================================
```

---

# [4. Cross-Evidence Correlation](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/4-correlation_matrix.sh)

## Goal: 

Cross-reference findings from all evidence sources to build a correlation matrix identifying convergences, contradictions, and gaps across the full evidence landscape.

## Context: 

This is the analytical core of the reconstruction. Until now, you have analyzed each evidence source independently, just as you analyzed each investigation domain independently throughout Module 4. The correlation step is where synthesis happens. It is the moment where five partial pictures become one complete picture -- or where contradictions reveal that your picture is still incomplete.

A correlation matrix maps findings to sources. A finding confirmed by three independent sources has HIGH confidence. A finding supported by one source and contradicted by another requires resolution. A finding present in one source and absent from all others could be real (the other sources lacked visibility) or false (the finding is an artifact of misinterpretation). Your job is to build this matrix and resolve every significant contradiction.

## Instructions: 

Write a script 4-correlation_matrix.sh that:

    Reads the outputs of T0-T3 plus all previous_findings/ summaries

    Builds an IOC correlation matrix:

    For each unique IOC (IP addresses, domains, file hashes, process names, account names), list which sources contain it

    Classify each IOC as: CONVERGED (2+ independent sources), SINGLE-SOURCE (one source only), or CONFLICTED (sources disagree)

    Identify NEW IOCs from the IR evidence that were not in the 4x04 IOC database

    Builds a timeline correlation matrix:

    For each key event in the attack chain, list which sources provide evidence for it

    Identify events with conflicting timestamps and document the resolution (clock skew, collection timing, timezone)

    Flag events supported by only one source as LOWER CONFIDENCE

    Builds a technique correlation matrix:

    For each ATT&CK technique observed, list which sources provide evidence

    Identify techniques that were INFERRED in 4x02 and can now be CONFIRMED or CORRECTED based on later evidence

    Identifies critical contradictions and resolves them with documented reasoning

**Expected Output:**

```bash
$ ./4-correlation_matrix.sh

================================================================
   CROSS-EVIDENCE CORRELATION MATRIX
   Sources: 4x00 through 4x05-IR (11 evidence files)
================================================================

IOC CORRELATION:
  IOC                    4x00  4x01  4x02  4x03  4x04  IR    Status
  [phish_domain]         YES   ---   YES   ---   ---   ---   CONVERGED
  [C2_IP]                ---   YES   YES   YES   ---   YES   CONVERGED
  [unknown_IP]           ---   ---   ---   ---   ---   YES   SINGLE-SOURCE
  svchost_update.exe     ---   ---   YES   YES   ---   YES   CONVERGED
  svc_healthsync         ---   ---   ---   ---   YES   YES   CONVERGED
  [staging_tool]         ---   ---   ---   ---   ---   YES   SINGLE-SOURCE
  [...]

  Summary: [N] CONVERGED, [N] SINGLE-SOURCE, [N] CONFLICTED
  New IOCs from IR: [N]

TIMELINE CORRELATION:
  Event                  Sources              Confidence  Notes
  Phishing delivery      4x00                 HIGH        Primary evidence
  Credential theft       4x00,4x01            CONVERGED   Timestamps match
  C2 establishment       4x01,IR-FW           CONVERGED   4s clock skew
  Malware deployment     4x03,IR-MEM          CONVERGED   Process confirmed
  Persistence install    IR-MEM,IR-DISK       CONVERGED   Feb 06 01:47
  Lateral mvmt start     4x04,IR-FW           CONVERGED   Feb 05
  Data staging           IR-DISK              SINGLE      Feb 10-11
  [...]

  CONTRADICTION RESOLVED:
  -> 4x01 network timeline shows C2 beacon start at [time]
  -> IR firewall shows first C2 session at [time - delta]
  -> Resolution: Firewall records TCP SYN (connection start),
     PCAP captured mid-session. [delta]s difference is consistent
     with normal collection point variance. Firewall timestamp
     adopted as authoritative for connection initiation.

TECHNIQUE CORRELATION:
  Technique              4x02    4x04    IR      Update
  T1566.001 Phishing     CONF    ---     ---     No change
  T1071.001 Web Proto    CONF    ---     CONF    Confidence +
  T1021.002 PsExec       INFER   CONF    CONF    UPGRADED
  T1053.005 Sched Task   ---     ---     CONF    NEW
  T1074.001 Data Staging ---     ---     CONF    NEW
  T1070.001 Log Clear    ---     ---     PROB    NEW
  [...]

  Techniques UPGRADED from INFERRED to CONFIRMED: [N]
  Techniques newly identified from IR evidence: [N]
  Techniques CORRECTED (4x02 inference was wrong): [N]

================================================================
```

---

# [5. Stage 1-2 Reconstruction](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/5-stages_1_2.sh)

## Goal: 

Reconstruct the HEALTHBANE Stages 1 and 2 (initial access through C2 establishment) using correlated evidence from the phishing investigation, network forensics, intelligence analysis, and incident response firewall data.

## Context: 

You are now building the attack narrative. Each stage of the reconstruction must be a chronological account supported by evidence citations. This is not a summary of your 4x00 or 4x01 findings. It is a reconstruction that integrates those findings with the new firewall evidence and with the broader intelligence context from 4x02.

Stages 1 and 2 represent the attacker's initial foothold. Stage 1 is the phishing delivery that harvested credentials. Stage 2 is the establishment of persistent remote access through the C2 channel. Your reconstruction must trace the path from the first email to the first confirmed C2 beacon, citing evidence from each source that contributes to the timeline.

## Instructions: 

Write a script 5-stages_1_2.sh that reconstructs Stages 1-2 of the HEALTHBANE attack against MedDefense:

    Stage 1 -- Initial Access (Phishing):

    Reconstruct the phishing campaign timeline using 4x00 findings

    Identify the specific email that resulted in credential compromise (Diane's click)

    Cite the evidence: email headers, domain analysis, SPF/DKIM results

    Map ATT&CK techniques with evidence citations: T1566.001 (Phishing: Spearphishing Link), T1078 (Valid Accounts -- credential harvesting)

    Establish the temporal anchor: exact timestamp of credential exposure

    Stage 2 -- C2 Establishment:

    Reconstruct the C2 establishment timeline using 4x01 network findings AND new firewall session data

    Correlate the C2 beaconing pattern (5-minute intervals from 4x01) with firewall session logs

    Determine whether the secondary C2 IP (from T3 firewall analysis) was active during Stage 2 or only appeared later

    Map ATT&CK techniques: T1071.001 (Application Layer Protocol: Web), T1573.001 (Encrypted Channel: Symmetric Cryptography), T1568 (Dynamic Resolution) if applicable

    Cite specific timestamps from both network and firewall sources, noting and resolving any discrepancies

    Confidence assessment:

    For each reconstructed event, assign a confidence level (CONFIRMED/PROBABLE/POSSIBLE) based on the number and quality of supporting sources

**Expected Output:**

```bash
$ ./5-stages_1_2.sh

================================================================
   ATTACK RECONSTRUCTION: Stages 1-2
   Initial Access through C2 Establishment
================================================================

STAGE 1: INITIAL ACCESS (Phishing Campaign)
  Timeline: Week 11 (campaign active: [date range])

  [timestamp] Campaign emails delivered to MedDefense staff
    Evidence: 4x00 email batch analysis (8 emails, 3 malicious)
    Technique: T1566.001 Spearphishing Link
    Confidence: CONFIRMED (primary email evidence)

  [timestamp] Diane (WS-RECV-03) clicks credential harvesting link
    Evidence: 4x00 investigation (URL analysis, domain registration)
    Technique: T1566.001 -> credential input on lookalike portal
    Confidence: CONFIRMED (user report + browser history)

  [timestamp] Credentials submitted to attacker-controlled domain
    Evidence: 4x00 (domain analysis), 4x01 (POST request in PCAP)
    Technique: T1078 Valid Accounts (obtained via phishing)
    Confidence: CONVERGED (2 independent sources)

STAGE 2: C2 ESTABLISHMENT
  Timeline: [date] (approximately [hours] after credential theft)

  [timestamp] First C2 beacon from WS-RECV-03
    Evidence: 4x01 (PCAP beacon analysis), IR-FW (session log)
    Technique: T1071.001 Application Layer Protocol: Web
    Confidence: CONVERGED (PCAP + firewall, [delta]s clock skew)

  [timestamp] C2 channel established: HTTPS to [C2_IP]:443
    Evidence: 4x01 (5-min beacon interval), IR-FW (session pattern)
    Pattern: [interval] beacon, [bytes] per session
    Confidence: CONFIRMED

  [timestamp] Secondary C2 channel to [unknown_IP]:8443
    Evidence: IR-FW only (first session: Feb 06 02:12)
    Note: NOT visible in 4x01 PCAPs (collection ended before Feb 06)
    Technique: T1071.001 (secondary channel)
    Confidence: PROBABLE (single source, but pattern consistent)

STAGE 1-2 SUMMARY:
  Duration: [hours/days] from phishing to established C2
  Techniques mapped: [list with IDs]
  IOCs: [count] (converged: [N], single-source: [N])
  Key finding: Secondary C2 at [unknown_IP] was NOT operational
  during Stage 2. First appeared Feb 06, suggesting attacker
  deployed backup infrastructure after establishing persistence.

================================================================
```

---

# [6. Stage 3 Reconstruction](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/6-stage_3.sh)
### advanced

## Goal: 

Reconstruct HEALTHBANE Stage 3 (malware deployment and capability establishment) using correlated evidence from the malware analysis, network forensics, memory forensics and disk forensics.

## Context: 

Stage 3 is where the attacker transitioned from access to capability. Stolen credentials gave them entry. The C2 channel gave them control. But Stage 3 gave them the TOOLS to achieve their objective: the dropper delivered the RAT, the RAT provided persistent access beyond the initial credential, and the exfiltration script targeted the patient data.

Your 4x03 malware analysis characterized these tools in isolation. The reconstruction must place them in chronological context: when was each tool deployed, from which host, through which delivery mechanism, and how do the deployment timestamps correlate with the C2 activity from Stage 2 and the lateral movement from Stage 4 ?

## Instructions: 

Write a script 6-stage_3.sh that reconstructs Stage 3:

    Malware Deployment Timeline:

    When was the dropper (HEALTHBANES2invoice.docm) delivered ? Correlate 4x03 analysis with 4x00 email evidence and 4x01 network timeline.

    When did the RAT (svchost_update.exe) first establish persistence ? Cross-reference 4x03 behavioral indicators with IR memory and disk evidence.

    When was the exfiltration script (sync_healthdata.ps1) deployed ? Cross-reference with disk forensics $MFT timeline and firewall session activity.

    Capability Mapping:

    For each malware component, document: delivery mechanism, persistence method, communication protocol, targeting and capability.

    Cross-reference the malware behavioral IOCs from 4x03 against the IR evidence to confirm which capabilities were ACTUALLY USED against MedDefense (vs capabilities observed in sandbox but not deployed in this environment).

    Stage 2 to Stage 3 Transition:

    Identify the exact point where the attacker moved from C2-only access to deploying malware tools.

    Document the time gap between C2 establishment and malware deployment (operational tempo indicator).

    Technique mapping with evidence citations for each technique.

**Expected Output:**

```bash
$ ./6-stage_3.sh

================================================================
   ATTACK RECONSTRUCTION: Stage 3
   Malware Deployment and Capability Establishment
================================================================

DEPLOYMENT TIMELINE:
  [timestamp] Dropper delivery (HEALTHBANE_S2_invoice.docm)
    Delivery: [mechanism based on evidence]
    Evidence: 4x03 (sample analysis), 4x00 (email with attachment)
    Technique: T1204.002 User Execution: Malicious File
    Confidence: CONFIRMED

  [timestamp] RAT persistence established (svchost_update.exe)
    Evidence: 4x03 (behavioral analysis), IR-MEM (process list),
              IR-DISK (prefetch first execution)
    Technique: T1547.001 Boot or Logon Autostart Execution
    Confidence: CONVERGED (3 sources)

  [timestamp] Exfiltration script staged (sync_healthdata.ps1)
    Evidence: 4x03 (sample analysis), IR-DISK ($MFT timeline)
    Technique: T1059.001 PowerShell
    Confidence: CONVERGED

CAPABILITY ASSESSMENT:
  Component         Capability          Used at MedDefense?  Evidence
  Dropper           Macro execution     YES                  4x03 + IR
  RAT               C2 + persistence    YES                  IR-MEM + IR-DISK
  RAT               Keylogging          UNCONFIRMED          4x03 sandbox only
  Exfiltrator       DNS exfil           PROBABLE             4x01 + IR-FW
  Exfiltrator       DB targeting        YES                  IR-DISK staging

OPERATIONAL TEMPO:
  C2 established -> Malware deployed: [N] hours
  Malware deployed -> Lateral movement start: [N] hours
  Assessment: Attacker operated on [fast/slow] tempo,
  suggesting [automated/manual] campaign execution.

STAGE 3 TECHNIQUES:
  T1204.002  User Execution: Malicious File     CONFIRMED
  T1547.001  Boot/Logon Autostart               CONFIRMED
  T1059.001  PowerShell                          CONFIRMED
  T1071.004  DNS (exfil channel)                 PROBABLE
  T1027      Obfuscated Files                    CONFIRMED (4x03)

================================================================
```

---

# [7. Stage 4 Reconstruction](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/7-stage_4.sh)

## Goal: 

Reconstruct HEALTHBANE Stage 4 (lateral movement and data staging) using correlated evidence from the threat hunt, memory forensics, disk forensics and firewall session analysis.

## Context: 

Stage 4 is the stage your threat hunt discovered. It is also the stage that revealed the limitations of detection-only security. The attacker used PsExec, WMI and PowerShell Remoting -- tools indistinguishable from legitimate administration. Your 4x04 hunt found the behavioral anomalies. The IR evidence now fills in the details that hunting alone could not provide.

The reconstruction of Stage 4 must answer the questions the hunt left open: exactly which hosts were compromised, exactly what credential was used and how it was obtained, exactly what the attacker accessed on the database server, and exactly how far the data staging progressed before the hunt interrupted it.

## Instructions: 

Write a script 7-stage_4.sh that reconstructs Stage 4:

    Lateral Movement Chain:

    Reconstruct the complete pivot chain: from WS-RECV-03 to each target host, with the tool used (PsExec/WMI/PSRemoting), the credential used, and the timestamp.

    Cross-reference the 4x04 hunt findings with IR firewall sessions and memory connections to confirm the full path.

    Identify any lateral movement steps that the hunt MISSED but the IR evidence reveals.

    Credential Access:

    Reconstruct how the attacker obtained the service account credential (svc_healthsync).

    Cross-reference the credential dumping finding from 4x04 (T1003.001 LSASS access) with the IR memory evidence.

    Determine whether additional credentials were compromised beyond what the hunt found.

    Data Access and Staging:

    Reconstruct exactly which systems the attacker accessed using the compromised credential.

    Map data staging activity (from T2 disk analysis) to the lateral movement timeline.

    Determine the sequence: did the attacker stage data directly on WS-RECV-03, or did they pull data from database servers to WS-RECV-03 first ?

    Persistence and Operational Security:

    Integrate the scheduled task finding (T1) into the Stage 4 timeline.

    Document the anti-forensics activity (T2) and its relationship to the overall operation.

    Assess the attacker's operational security: what did they do to avoid detection, and what ultimately exposed them ?

    Containment Moment:

    Reconstruct the exact point at which the 4x04 threat hunt interrupted the attacker's operation.

    Determine what the attacker would likely have done next if the hunt had not triggered incident response.

**Expected Output:**

```bash
$ ./7-stage_4.sh

================================================================
   ATTACK RECONSTRUCTION: Stage 4
   Lateral Movement, Data Staging, and Containment
================================================================

LATERAL MOVEMENT CHAIN:
  [Feb 04 01:23] Credential dump on WS-RECV-03
    Tool: [credential access tool]
    Target: LSASS process memory
    Result: svc_healthsync credential obtained
    Evidence: 4x04 (hunt H4), IR-MEM (loaded module), IR-DISK
    Technique: T1003.001 LSASS Memory
    Confidence: CONVERGED (3 sources)

  [Feb 05 02:14] First lateral movement: WS-RECV-03 -> SRV-HEALTH-DB
    Tool: PsExec
    Credential: svc_healthsync
    Evidence: 4x04 (hunt H1), IR-FW (session log)
    Technique: T1021.002 SMB/Windows Admin Shares
    Confidence: CONVERGED

  [... full chain with all pivots ...]

CREDENTIAL ASSESSMENT:
  Credentials confirmed compromised:
    [1] svc_healthsync (service account, database access)
        Source: 4x04 hunt + IR memory
    [2] [any additional credentials from IR evidence]

DATA ACCESS AND STAGING:
  [timestamp] Query execution on SRV-HEALTH-DB
    Evidence: IR-DISK (query_results.csv, 8.4 MB)
    Data type: [patient records / insurance data / ...]
    Technique: T1005 Data from Local System

  [timestamp] Data compression on WS-RECV-03
    Evidence: IR-DISK (staging_export_001.zip, 14.2 MB)
    Technique: T1560.001 Archive Collected Data

  [timestamp] Second staging archive created
    Evidence: IR-DISK (staging_export_002.zip, 11.8 MB)
    Technique: T1074.001 Local Data Staging

  STAGING FLOW: SRV-HEALTH-DB -> WS-RECV-03 -> staging archives
  EXFILTRATION STATUS: [Assessment based on T3 firewall analysis]

CONTAINMENT TIMELINE:
  [Feb 12] 4x04 threat hunt detected anomalous PsExec activity
  [date] Hunt report submitted, IR recommended
  [date] IR team isolated WS-RECV-03
  [date] Memory captured, disk imaged

  IF NOT CONTAINED: Based on staging file sizes (34.4 MB total)
  and firewall session patterns, the attacker was [N] sessions
  from completing exfiltration of staged data. Estimated time
  to complete: [hours].

================================================================
```

---

# [8. Unified Timeline Assembly](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/8-unified_timeline.sh)

## Goal: 

Merge all stage reconstructions into a single, chronological, evidence-cited timeline of the complete HEALTHBANE attack against MedDefense, from first phishing email to containment.

## Context: 

The unified timeline is the spine of the reconstruction report. It transforms four separate stage narratives into one continuous story. Every event must appear exactly once, in chronological order, with its evidence sources, ATT&CK mapping and confidence level.

This is also where remaining contradictions become visible. If Stage 2 C2 establishment overlaps with Stage 3 malware deployment in a way that is physically impossible (e.g., malware deployed before C2 was established), the timeline will expose it. If events from different sources appear out of sequence, the timeline forces resolution.

## Instructions: 

Write a script 8-unified_timeline.sh that:

    Merges the outputs of T5 (Stages 1-2), T6 (Stage 3) and T7 (Stage 4) into a single chronological sequence.

    For each event in the timeline, includes:

    Timestamp (with timezone notation and clock skew adjustment if applicable)

    Event description

    Source host(s) and target host(s)

    User/credential involved

    ATT&CK technique ID

    Evidence source(s) with convergence status

    Confidence level

    Calculates and documents key temporal metrics:

    Total dwell time (first access to containment)

    Breakout time (initial access to lateral movement)

    Time to data staging

    Time from detection (4x04 hunt) to containment (IR isolation)

    Operational tempo (average time between attack phases)

    Identifies and documents remaining timeline gaps: periods within the attack window where no evidence exists and the attacker's activity is unknown.

    Flags any events that could NOT be sequenced with confidence and explains why.

**Expected Output:**

```bash
$ ./8-unified_timeline.sh

================================================================
   UNIFIED ATTACK TIMELINE - HEALTHBANE vs MedDefense
   Period: [first event] to [containment]
================================================================

CHRONOLOGICAL SEQUENCE:

  #  Timestamp            Event                    ATT&CK     Conf   Sources
  -- --------             -----                    ------     ----   -------
  01 [date time]          Phishing emails sent     T1566.001  CONF   4x00
  02 [date time]          Diane clicks link        T1566.001  CONF   4x00
  03 [date time]          Credentials submitted    T1078      CONV   4x00,4x01
  04 [date time]          First C2 beacon          T1071.001  CONV   4x01,IR-FW
  05 [date time]          C2 channel stable        T1573.001  CONF   4x01
  [...]
  [N] [date time]         Last attacker activity   [tech]     [lvl]  [sources]
  [N+1] [date time]       Hunt detection (4x04)    ---        CONF   4x04
  [N+2] [date time]       IR isolation of host     ---        CONF   IR

  Total events in timeline: [N]
  Events with CONVERGED evidence: [N] ([pct]%)
  Events with SINGLE-SOURCE evidence: [N] ([pct]%)

TEMPORAL METRICS:
  Total dwell time:           [N] days ([first] to [containment])
  Breakout time:              [N] hours (initial access to lateral)
  Time to persistence:        [N] hours (access to scheduled task)
  Time to data staging:       [N] days (access to first staging file)
  Detection to containment:   [N] days (hunt finding to IR isolation)
  Operational tempo:          Activity clusters on [pattern] nights

TIMELINE GAPS:
  GAP 1: [date range] -- No evidence of attacker activity
         Assessment: [dormant period / collection gap / ...]
  GAP 2: [date range] -- Single source only (firewall)
         Assessment: [...]

SEQUENCING UNCERTAINTIES:
  [*] Events [N] and [N+1] cannot be definitively ordered.
      Reason: [single-source timestamps without cross-reference]
      Impact on reconstruction: [minimal/significant]

================================================================
```

---

# [9. Final ATT&CK Technique Identification](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/9-attack_techniques.sh)

## Goal: 

Enumerate every MITRE ATT&CK technique observed across all evidence sources, producing the definitive HEALTHBANE technique inventory with evidence citations and confidence levels.

## Context: 

Your ATT&CK mapping has evolved through the module. In 4x02, you mapped techniques from intelligence sources at 40% coverage. In 4x03, the malware analysis raised it to 55%. In 4x04, the threat hunt pushed it to 80%. The IR evidence introduces new techniques (scheduled task persistence, data staging, archive collection, log clearing) that were invisible before.

This task produces the FINAL technique inventory. Not a copy of the 4x04 Navigator layer with a few additions, but a complete re-assessment where every technique is re-evaluated with the full evidence picture. Some techniques that were INFERRED in 4x02 can now be CONFIRMED. Some that were CONFIRMED might need re-classification if the IR evidence contradicts earlier assumptions.

## Instructions: 

Write a script 9-attack_techniques.sh that:

    Reads reference/attck_navigator_80pct.json as the baseline

    For each technique already in the mapping:

    Re-assesses the confidence level using ALL evidence sources (not just the source that originally identified it)

    Upgrades INFERRED techniques to CONFIRMED where IR evidence provides direct support

    Documents any techniques that should be CORRECTED (4x02 inference was wrong) or DOWNGRADED (new evidence weakens the original assessment)

    Adds NEW techniques identified through the IR evidence:

    T1053.005 Scheduled Task/Job: Scheduled Task (from T1 memory analysis)

    T1074.001 Staged Data: Local Data Staging (from T2 disk analysis)

    T1560.001 Archive Collected Data: Archive via Utility (from T2 disk analysis)

    T1070.001 Indicator Removal: Clear Windows Event Logs (from T2 disk analysis)

    T1005 Data from Local System (from T7 data access reconstruction)

    Any additional techniques identified during the reconstruction

    Produces a complete technique inventory with:

    Technique ID and name

    Kill chain phase (tactic)

    Evidence sources

    Confidence level (CONFIRMED/PROBABLE/POSSIBLE)

    The investigation that first identified it (4x00-4x05)

    Whether it was UPGRADED, NEW, CORRECTED or UNCHANGED

    Calculates the final coverage percentage

**Expected Output:**

```bash
$ ./9-attack_techniques.sh

================================================================
   HEALTHBANE ATT&CK TECHNIQUE INVENTORY (FINAL)
   Total techniques in threat model: 29
================================================================

  #   Technique           Tactic          Conf    First ID  Status
  --  ---------           ------          ----    --------  ------
  01  T1566.001           Init Access     CONF    4x00      UNCHANGED
  02  T1078               Init Access     CONF    4x00      UNCHANGED
  03  T1071.001           C2              CONF    4x01      UNCHANGED
  04  T1573.001           C2              CONF    4x01      UNCHANGED
  [... all 4x02 techniques ...]
  [... all 4x03 techniques ...]
  [... all 4x04 techniques ...]
  [N]  T1053.005          Persistence     CONF    4x05-IR   NEW
  [N+1] T1074.001         Collection      CONF    4x05-IR   NEW
  [N+2] T1560.001         Exfiltration    CONF    4x05-IR   NEW
  [N+3] T1070.001         Def Evasion     PROB    4x05-IR   NEW
  [N+4] T1005             Collection      CONF    4x05-IR   NEW

COVERAGE EVOLUTION:
  Post-4x02 (intelligence):  ~40% (12/29 techniques)
  Post-4x03 (malware):       ~55% (16/29 techniques)
  Post-4x04 (hunting):       ~80% (23/29 techniques)
  Post-4x05 (reconstruction): ~96% (28/29 techniques)

UPGRADED TECHNIQUES (INFERRED -> CONFIRMED): [N]
  [List with evidence that confirmed them]

NEW TECHNIQUES (from IR evidence): [N]
  [List with evidence source]

REMAINING GAP: 1/29 techniques
  T[xxxx] [technique name]
  Assessment: [Cannot determine if used -- collection limitation
  OR technique not employed by this attacker]

================================================================
```

---

# [10. ATT&CK Navigator Layer Update](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/10-navigator_update.json)
### advanced

## Goal: 

Produce the definitive HEALTHBANE ATT&CK Navigator JSON layer with color-coded phases, confidence annotations and the final coverage percentage.

## Context: 

The Navigator layer is the visual representation of the technique inventory. It must be importable into the MITRE ATT&CK Navigator tool and must visually distinguish between attack phases (Stages 1-4), confidence levels and the investigation that identified each technique.

This is the layer James Chen will include in the board presentation. It must be correct, complete and self-explanatory.

## Instructions: 

Produce a file 10-navigator_update.json that:

    Contains a valid ATT&CK Navigator layer in JSON format

    Uses a color scheme that distinguishes:

    Stage 1 techniques (Initial Access)

    Stage 2 techniques (C2 and infrastructure)

    Stage 3 techniques (Malware deployment)

    Stage 4 techniques (Lateral movement and data staging)

    Cross-stage techniques (used across multiple phases)

    Includes metadata comments for each technique:

    Confidence level

    Evidence sources

    Investigation phase that identified it

    Represents the final coverage: approximately 96% of the 29-technique threat model

    Is valid JSON that can be imported into the ATT&CK Navigator without errors

---

# [11. Gap Analysis and Blind Spot Assessment](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/11-gap_analysis.sh)
### advanced

## Goal: 

Analyze the remaining ATT&CK gaps and assess whether each represents a genuine absence of attacker activity, a collection limitation, or a detection blind spot that requires remediation.

## Context: 

At 96% coverage, only one or two techniques remain unmapped. But coverage percentage alone is misleading. A gap in the ATT&CK mapping could mean three very different things:

    The attacker did not use that technique (genuine absence).

    The attacker used it but no evidence was collected to prove it (collection gap).

    The attacker used it and evidence exists but the analyst failed to recognize it (analytical gap).

Distinguishing between these three requires reasoning about the adversary's likely behavior, the evidence collection architecture and your own analytical blind spots. This is the highest level of ATT&CK maturity: knowing what you do not know and why you do not know it.

## Instructions: 

Write a script 11-gap_analysis.sh that:

    Lists every technique in the 29-technique threat model that is NOT in the final mapping

    For each gap, assesses:

    ABSENCE: The attacker likely did not use this technique. Evidence: [reason based on the reconstructed attack chain -- e.g., the technique is redundant with another they used, or it targets a capability they did not need]

    COLLECTION GAP: The attacker may have used this technique but evidence was not collected. Reason: [which evidence source would have captured it, and why it was not available]

    ANALYTICAL GAP: Evidence may exist but was not analyzed or recognized. Reason: [what additional analysis would be needed]

    For each COLLECTION GAP, recommends the specific telemetry or collection improvement that would close it

    Assesses the overall reconstruction confidence:

    What percentage of the kill chain is CONFIRMED vs PROBABLE vs POSSIBLE ?

    What is the single biggest remaining uncertainty ?

    What additional evidence would be needed to resolve it ?

    Documents the lessons learned about ATT&CK coverage limitations: why 80% coverage (pre-capstone) left significant blind spots, and why 96% is still not 100%

**Expected Output:**

```bash
$ ./11-gap_analysis.sh

================================================================
   GAP ANALYSIS AND BLIND SPOT ASSESSMENT
================================================================

UNMAPPED TECHNIQUES:

  T[xxxx] [technique name]
    Assessment: COLLECTION GAP
    Reasoning: [detailed reasoning about why evidence is absent]
    Required telemetry: [specific data source that would confirm
    or exclude this technique]
    Recommendation: [specific collection improvement]

RECONSTRUCTION CONFIDENCE SUMMARY:
  Kill chain events: [N] total
  CONFIRMED (2+ sources):  [N] ([pct]%)
  PROBABLE (strong single): [N] ([pct]%)
  POSSIBLE (inferred):      [N] ([pct]%)

  Biggest remaining uncertainty: [description]
  Evidence needed to resolve: [specific evidence]

COVERAGE EVOLUTION LESSONS:
  [*] At 40% (post-4x02): Intelligence identified the campaign
      but could not confirm which techniques were used against us.
      Blind spot: entire lateral movement phase invisible.

  [*] At 55% (post-4x03): Malware analysis confirmed deployment
      techniques but missed LOLBin activity entirely.
      Blind spot: Stage 4 completely undetected.

  [*] At 80% (post-4x04): Hunt found lateral movement but could
      not determine persistence, data staging or exfiltration scope.
      Blind spot: scheduled tasks, data staging, anti-forensics.

  [*] At 96% (post-4x05): IR evidence closed most gaps. Remaining
      gap is [description] -- a collection limitation, not an
      analytical failure.

  KEY LESSON: Each coverage increase revealed that the PREVIOUS
  level had created a false sense of security. 80% coverage
  sounds strong but left the most operationally critical
  techniques (persistence, staging, exfiltration) in the gap.

================================================================
```

---

# [12. Data Exposure Assessment](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/12-data_exposure.sh)

## Goal: 

Determine exactly which data was at risk, whether any data left the network, and what the regulatory and operational implications are.

## Context: 

This is the question Dr. Morales must answer for the board: was patient data compromised ? The answer is not binary. There is a spectrum between "no data was accessed" and "all records were exfiltrated." Your reconstruction must place MedDefense precisely on that spectrum, with evidence.

In healthcare, the difference between "data was accessed" and "data was exfiltrated" determines whether a HIPAA breach notification is required. The difference between "one record" and "500 records" determines the notification scope. These are not academic distinctions. They have legal, financial and reputational consequences. Your assessment must be defensible.

## Instructions: 

Write a script 12-data_exposure.sh that:

    Maps compromised hosts to the asset inventory (reference/meddefense_asset_inventory.txt) to determine what data each host stores or has access to

    For each compromised host, assesses:

    Confirmed access: evidence that the attacker interacted with data on this host (e.g., query_results.csv creation timestamp matches attacker activity window)

    Potential access: the attacker had credentials and network access to reach this host, but no direct evidence of data interaction

    No access: the host was not in the attacker's lateral movement chain

    Assesses exfiltration status:

    Was data staged ? (YES -- from T2 disk analysis)

    Was staged data transmitted outside the network ? (Based on T3 firewall analysis -- bytes-out comparison)

    If transmitted, to which destination and how much ?

    If NOT transmitted, what interrupted the exfiltration ?

    Produces a data exposure summary categorized by data type:

    Patient health records

    Insurance and billing data

    Employee records

    Operational data

    For each: confirmed exposed / potentially exposed / not exposed

    Assesses regulatory implications:

    Does the evidence meet the threshold for a reportable data breach ?

    What is the estimated scope (number of records at risk) ?

    What mitigating factors exist (encryption, access controls, interruption) ?

**Expected Output:**

```bash
$ ./12-data_exposure.sh

================================================================
   DATA EXPOSURE ASSESSMENT
================================================================

COMPROMISED SYSTEM MAPPING:
  Host            Role              Data Sensitivity  Access Level
  WS-RECV-03      Records Dept WS   LOW (local)       CONFIRMED ACCESS
  SRV-HEALTH-DB   Health Records    CRITICAL (PHI)    CONFIRMED ACCESS
  SRV-INS-DB      Insurance DB      HIGH (PII+fin)    PROBABLE ACCESS
  SRV-FILE-01     File Server       MEDIUM            PROBABLE ACCESS
  SRV-DC-01       Domain Controller HIGH (auth)       POSSIBLE ACCESS

EXFILTRATION STATUS:
  Data staged on WS-RECV-03: YES (34.4 MB in 3 files)
  Data transmitted externally: [ASSESSMENT based on firewall]
  Exfiltration channel: [C2 IP / unknown IP / DNS tunnel]
  Interruption: Hunt detection on [date], IR isolation on [date]

  CONCLUSION: [Data staging confirmed, exfiltration
  interrupted/partial/completed -- based on evidence]

DATA EXPOSURE BY TYPE:
  Patient health records (PHI):
    Status: [CONFIRMED ACCESSED / STAGED / EXFILTRATED]
    Evidence: IR-DISK query_results.csv, staging archives
    Estimated scope: [N records based on file sizes]

  Insurance/billing data:
    Status: [PROBABLE ACCESS based on credential scope]
    Evidence: [...]

  Employee records:
    Status: NOT EXPOSED (no evidence of HR system access)

REGULATORY ASSESSMENT:
  HIPAA breach notification threshold: [MET / NOT MET / UNCERTAIN]
  Basis: [specific evidence supporting the determination]
  Mitigating factors:
    [*] Staging interrupted before confirmed full exfiltration
    [*] [Encryption status of accessed data]
    [*] [Response time from detection to containment]
  Recommended action: [notify / investigate further / ...]

================================================================
```

---

# [13. Defensive Posture Evaluation](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/13-defense_evaluation.sh)
### advanced

## Goal: 

Evaluate MedDefense's detection and defense posture at three points in time: before the module (pre-4x00), after the threat hunt (post-4x04), and after the reconstruction (post-4x05), assessing what worked, what failed, and why.

## Context: 

The board will ask: "How did this happen ? Were our defenses inadequate ?" The answer is nuanced. MedDefense's defenses CAUGHT the phishing at Stage 1. The detection improvements from 4x02 and 4x03 WOULD HAVE caught Stage 3 if it had been deployed. The hunt FOUND Stage 4. The reconstruction COMPLETED the picture. The defenses were not inadequate -- they were incomplete. And the reconstruction reveals exactly which completions matter most.

## Instructions: 

Write a script 13-defense_evaluation.sh that:

    Evaluates detection posture at three snapshots:

    Pre-Module (Week 10): What detection capabilities existed before Module 4 ? (Module 3 SIEM, Suricata rules, basic Wazuh alerts). What would they have caught ? What would they have missed ?

    Post-Hunt (Week 16): What capabilities existed after 4x04 ? (4x00 email rules, 4x02 YARA rules, 4x03 behavioral indicators, 4x04 behavioral detection rules, 80% ATT&CK coverage). What did they catch ? What did they still miss ?

    Post-Reconstruction (Week 17): What is known now ? What additional detection rules are needed based on the reconstruction findings (scheduled task creation, data staging indicators, secondary C2 patterns) ?

    For each detection rule deployed throughout Module 4, assesses:

    Would it have detected the HEALTHBANE attack at its relevant stage ? (YES/NO/PARTIAL)

    If NO: why not ? (Rule logic gap, evidence type mismatch, timing)

    What modification would make it effective ?

    Identifies the structural defensive failures:

    No scheduled task creation monitoring

    No data staging detection

    No secondary C2 channel detection

    Insufficient baseline monitoring beyond Robert Kim's tools

    [Others identified during reconstruction]

    Produces a detection gap matrix: attack technique vs detection capability, showing which intersections are covered and which are not

**Expected Output:**

```bash
$ ./13-defense_evaluation.sh

================================================================
   DEFENSIVE POSTURE EVALUATION
================================================================

DETECTION POSTURE EVOLUTION:
  Snapshot         Coverage  Techniques Detected  Techniques Missed
  Pre-Module       ~15%      Basic SIEM alerts    Almost everything
  Post-Hunt (4x04) ~80%     Stages 1-3 + lateral  Persistence, staging
  Post-Recon (4x05) ~96%    Full chain mapped     1 collection gap

WHAT WORKED:
  [*] 4x00 email detection rules: caught phishing campaign
  [*] 4x02 YARA rules: would catch Stage 2 dropper on delivery
  [*] 4x04 behavioral rules: detected Stage 4 lateral movement
  [*] Proactive hunt: found activity no rule detected

WHAT FAILED:
  [*] No monitoring for scheduled task creation -> T1053.005 missed
  [*] No detection for data staging -> T1074.001 missed
  [*] No secondary C2 detection -> unknown IP undetected
  [*] Log gap (T1070.001) went unnoticed until disk forensics
  [*] 48h PCAP window insufficient for 14-day attack

STRUCTURAL LESSONS:
  [1] Detection rules catch known patterns. The attacker used
      techniques outside the rule set.
  [2] Proactive hunting is the only countermeasure for unknown
      patterns, but it requires hypotheses and time.
  [3] Forensic evidence (memory, disk) reveals artifacts that
      detection and hunting cannot see in real-time.
  [4] No single evidence type covers the full attack chain.
      Layered collection is mandatory.

DETECTION GAP MATRIX:
  Technique        SIEM  YARA  Suricata  Hunt  Forensic  Status
  T1566.001        YES   ---   ---       ---   ---       COVERED
  T1071.001        ---   ---   PARTIAL   ---   ---       WEAK
  T1053.005        NO    ---   ---       NO    YES       GAP
  T1074.001        NO    ---   ---       NO    YES       GAP
  T1070.001        NO    ---   ---       NO    YES       GAP
  [...]

NEW RULES RECOMMENDED:
  [1] Sysmon EventID 1: Alert on schtasks.exe creating tasks
      with encoded PowerShell in action field
  [2] Sysmon EventID 11: Alert on file creation in staging
      directories (C:\Users\Public\*) by non-standard processes
  [3] Firewall: Alert on new external destinations from
      previously-internal-only hosts

================================================================
```

---

# [14. Prioritized Remediation Plan](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction/14-remediation_plan.sh)
### advanced

## Goal: 

Produce a prioritized remediation plan that addresses the vulnerabilities and detection gaps exposed by the reconstruction, ordered by urgency and impact.

## Context: 

A reconstruction without a remediation plan is a forensic exercise, not a security operation. The board does not want to know only what happened. They want to know what MedDefense is doing to ensure it does not happen again. The remediation plan must be prioritized: not everything can be fixed simultaneously, and not everything is equally urgent.

The plan must distinguish between immediate actions (things that reduce risk RIGHT NOW), short-term improvements (things deployable within weeks) and medium-term enhancements (architectural changes requiring planning and investment). Each action must trace back to a specific finding in the reconstruction.

## Instructions: 

Write a script 14-remediation_plan.sh that:

    Lists every vulnerability, detection gap and defensive weakness identified in the reconstruction (from T0 through T13)

    For each item, documents:

    The specific reconstruction finding that exposed it

    The ATT&CK technique it relates to

    The risk if left unaddressed (what could an attacker exploit)

    Prioritizes remediation into three tiers:

    IMMEDIATE (within 48 hours):

    Credential rotation for ALL compromised accounts

    Verification that WS-RECV-03 isolation is complete

    Review of ALL other workstations for scheduled task indicators

    Verification that no data left the network (from T12 exfiltration assessment)

    SHORT-TERM (within 2 weeks):

    Deploy detection rules for newly identified techniques (T1053.005, T1074.001, T1070.001)

    Implement scheduled task creation monitoring across all endpoints

    Deploy data staging detection (file creation monitoring in staging directories)

    Add secondary C2 IP to blocklists and deploy detection for the communication pattern

    MEDIUM-TERM (within 3 months):

    Implement full Sysmon deployment with behavioral analytics

    Establish recurring threat hunting cadence (weekly micro-hunts, monthly full hunts)

    Review and harden service account permissions (principle of least privilege)

    Implement network segmentation improvements to limit lateral movement paths

    Deploy memory forensics readiness (crash dump configuration, memory capture tools on high-value hosts)

    For each remediation action, estimates effort (hours/days) and assigns a responsible team (SOC, IT, Network, Management)

**Expected Output:**

```bash
$ ./14-remediation_plan.sh

================================================================
   PRIORITIZED REMEDIATION PLAN
   Based on HEALTHBANE Attack Reconstruction
================================================================

IMMEDIATE ACTIONS (within 48 hours):
  Priority  Action                        Finding   Effort  Owner
  IM-1      Rotate svc_healthsync creds   T7,T1     2h     IT
  IM-2      Verify WS-RECV-03 isolation   T7        1h     IR Team
  IM-3      Scan all WS for sched tasks   T1,T2     4h     SOC
  IM-4      Confirm no data exfiltration  T12       2h     SOC
  IM-5      Block [unknown_IP] at FW      T3        1h     Network

SHORT-TERM (within 2 weeks):
  Priority  Action                        Finding   Effort  Owner
  ST-1      Deploy T1053.005 detection    T1,T11    8h     SOC
  ST-2      Deploy data staging alerts    T2,T11    8h     SOC
  ST-3      Deploy secondary C2 pattern   T3        4h     SOC
  ST-4      Review service account perms  T7        16h    IT
  ST-5      Extended PCAP collection      T11       8h     Network

MEDIUM-TERM (within 3 months):
  Priority  Action                        Finding   Effort  Owner
  MT-1      Full Sysmon deployment        T13       40h    IT+SOC
  MT-2      Recurring hunt program        T13       Ongoing SOC
  MT-3      Network segmentation review   T7        80h    Network
  MT-4      Memory forensics readiness    T1        16h    IR Team
  MT-5      Privileged access management  T7        120h   IT+Mgmt

SUMMARY:
  Immediate: [N] actions, ~[N]h total effort
  Short-term: [N] actions, ~[N]h total effort
  Medium-term: [N] actions, ~[N]h total effort
  Total remediation items: [N]

  Each action traces to a specific reconstruction finding.
  No action exists without evidence-based justification.

================================================================
```

---
