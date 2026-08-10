# [0. Sysmon Telemetry Validation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/0-sysmon_validation.ps1)

## Goal: 

Validate that Sysmon is correctly capturing security-relevant events by triggering specific actions and verifying each one produces the expected Event ID.

## Context: 

You deployed Sysmon, with a SwiftOnSecurity baseline plus 5 custom rules. But deployment does not equal coverage. A configuration error, a missing event type or an overly aggressive exclusion can create silent blind spots. This task proves that every critical Sysmon event type is actually firing by running a controlled test sequence and checking the results.

## Instructions: 

Write a PowerShell script 0-sysmon_validation.ps1 that triggers specific actions and verifies Sysmon captures each one:

    Process creation (Event ID 1): Launch cmd.exe /c whoami and verify the event includes the full command line

    Network connection (Event ID 3): Initiate an outbound connection (e.g., Test-NetConnection to a known IP) and verify the destination IP, port and process are logged

    File creation (Event ID 11): Create a file in C:\Windows\Temp\ and verify the event includes the target filename and creating process

    Registry modification (Event ID 13): Write a test registry value and verify the event includes the key path, value name and operation type

    DNS query (Event ID 22): Resolve a domain name and verify the query and result are logged

For each action: log the timestamp, search the Sysmon event log for the matching event, record whether it was captured with the correct Event ID and detail level.

**Expected Output:**

```PS
PS> .\0-sysmon_validation.ps1
[*] Running Sysmon telemetry validation...
    [1/5] Process creation (Event ID 1)...
          cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present   [PASS]
    [2/5] Network connection (Event ID 3)...
          Outbound TCP -> Sysmon EID 3 captured, dest IP/port present   [PASS]
    [3/5] File creation (Event ID 11)...
          C:\Windows\Temp\test.txt -> Sysmon EID 11 captured            [PASS]
    [4/5] Registry modification (Event ID 13)...
          HKCU\...\SysmonTest -> Sysmon EID 13 captured                 [PASS]
    [5/5] DNS query (Event ID 22)...
          nslookup example.com -> Sysmon EID 22 captured                [PASS]
[*] Cleanup: removing test artifacts...
Actions tested: 5 | Captured: 5 | Missed: 0
```

---

# [1. Sysmon ATT&CK Coverage Matrix](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/1-sysmon_coverage_matrix.ps1)

## Goal: Produce a structured coverage matrix that proves which attacker techniques are visible through the current Sysmon configuration and which require tuning.

## Context:
The original Sysmon gap task was useful, but it was too narrow. In this project, telemetry is not only a config check. The point is to prove whether endpoint instrumentation produces useful evidence for specific attacker behaviors. This rebuilt task turns the Sysmon configuration into an ATT&CK-aligned coverage matrix that later detection and handoff tasks can use.

Sysmon coverage must be measured in three dimensions:

    Whether the required Event IDs are enabled
    Whether the config filters out the activity
    Whether the resulting event has enough fields to support triage

## Instructions:
Write a PowerShell script named 1-sysmon_coverage_matrix.ps1.

The script must read sysmonconfig.xml and generate sysmon_coverage_matrix.json.

The script must:

    Parse enabled Sysmon event types from the XML
    Identify include/exclude rules that could suppress relevant events
    Map ATT&CK techniques to required Sysmon Event IDs
    Evaluate each technique as:

    covered
    partial
    blind

    Include the reason for the status
    Include a recommended tuning action for every partial or blind item
    Print a summary of coverage

Minimum ATT&CK mappings:

    T1059 Command and Scripting Interpreter — Sysmon EID 1
    T1053 Scheduled Task/Job — Sysmon EID 1
    T1547 Boot or Logon Autostart Execution — Sysmon EID 13
    T1055 Process Injection — Sysmon EID 8, 10
    T1071 Application Layer Protocol — Sysmon EID 3, 22
    T1574.002 DLL Side-Loading — Sysmon EID 7
    T1027 Obfuscated or Compressed Files — Sysmon EID 11, 15

Each matrix row must include:

    technique_id
    technique_name
    required_event_ids
    enabled_event_ids
    filter_conflicts
    coverage_status
    evidence_fields_expected
    recommendation

Expected Output:

```PS
PS> .\1-sysmon_coverage_matrix.ps1
[*] Parsing Sysmon config: sysmonconfig.xml
Enabled Event IDs: 1, 3, 7, 11, 12, 13, 22
Techniques assessed: 7
Covered: 5
Partial: 2
Blind: 0
Report saved to: sysmon_coverage_matrix.json
```

---

# [2. PowerShell Logging Validation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/2-powershell_logging_validation.ps1)

## Goal: 

Verify that PowerShell Script Block Logging, Module Logging and Transcription are correctly capturing commands of varying complexity.

## Context: 

PowerShell logging was enabled. But "enabled" does not mean "complete." Encoded commands should appear decoded in Script Block Logs. Module imports should appear in Module Logging. Remote operations should generate transcripts. This task proves each logging layer works against the types of PowerShell the Crimson Tide attacker actually used.

## Instructions: 

Write a PowerShell script 2-powershell_logging_validation.ps1 that:

    Executes a simple command (Get-Process) and checks Event ID 4104 (Script Block)

    Executes an encoded command (powershell -enc [base64 of Write-Host "Test"]) and checks that the decoded content appears in Event ID 4104

    Executes a module import (Import-Module ActiveDirectory) and checks Event ID 4103 (Module Logging)

    Executes a multi-line script block and verifies the full block is captured

    Checks that a transcription file was created in C:\PSTranscripts\ for the session

For each test: report CAPTURED / MISSED and the detail level (full content vs partial).

**Expected Output:**

```PS
PS> .\2-powershell_logging_validation.ps1
[*] Testing PowerShell logging coverage...
    [1/5] Simple command (Get-Process)...
          EID 4104: "Get-Process" captured                     [PASS]
    [2/5] Encoded command...
          Input: -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAi
          EID 4104: "Write-Host 'Test'" (decoded) captured     [PASS]
    [3/5] Module import...
          EID 4103: "Import-Module ActiveDirectory" captured   [PASS]
    [4/5] Multi-line script block...
          EID 4104: Full block captured (12 lines)             [PASS]
    [5/5] Transcription file...
          C:\PSTranscripts\*.txt exists, session recorded      [PASS]
Tests: 5 | Captured: 5 | Missed: 0
```

---

# [3. Windows Telemetry Normalizer](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/3-windows_telemetry_export.ps1)

## Goal: 

Export Windows telemetry into analyst-ready JSON with normalized timestamps, consistent field names, and event-specific enrichment.

## Context:

The original Windows export task focused on exporting logs. This rebuilt task focuses on producing data that can actually be consumed by the SOC. Raw EVTX data is not enough. The analyst needs consistent JSON records with standard fields across Security, Sysmon, and PowerShell logs.

This script becomes the Windows half of the final telemetry handoff package.

# Instructions:

Write a PowerShell script named 3-windows_telemetry_export.ps1.

The script must export telemetry from a configurable time window. The default window must be the last 24 hours.

The script must read from:

    Windows Security log
    Sysmon Operational log
    PowerShell Operational log

The script must generate windows_events_export.json.

Each exported event must include normalized common fields:

    timestamp
    hostname
    platform
    source_type
    channel
    event_id
    event_category
    provider
    raw_message

For key event types, extract enriched fields:

    4624: target user, logon type, source IP, workstation
    4625: target user, failure reason, source IP
    4672: privileged account
    4688: process name, command line, parent process if present
    4104: decoded script block text
    Sysmon 1: image, command line, parent image, hashes
    Sysmon 3: destination IP, destination port, process
    Sysmon 11: target filename, creating process
    Sysmon 13: registry key, value name
    Sysmon 22: query name, query results

The script must print counts per channel and top Event IDs.

**Expected Output:**

```PS
PS> .\3-windows_telemetry_export.ps1
[*] Exporting Windows telemetry from last 24 hours...
Security events: 847
Sysmon events: 1234
PowerShell events: 189
Total events: 2270
Top Event IDs: 4624, Sysmon-1, 4104, 4625
Output: windows_events_export.json
```

---

# [4. Windows Telemetry Quality Gate](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/4-windows_telemetry_quality.ps1)

## Goal: 

Assess whether exported Windows telemetry is complete, continuous, and useful enough for analyst handoff.

## Context:

Exported telemetry can still be low quality. It may have missing command lines, empty source IP fields, time gaps, or one noisy event type drowning out everything else. This task is rebuilt as a quality gate that accepts or rejects the Windows export before it enters the final handoff.

## Instructions:

Write a PowerShell script named 4-windows_telemetry_quality.ps1.

The script must read windows_events_export.json and produce windows_telemetry_quality.json.

The quality report must include:

    Event distribution

    count per Event ID
    percentage of total

    Channel distribution

    Security
    Sysmon
    PowerShell

    Time coverage

    events per hour
    hours with events
    hours without events

    Gap detection

    time periods longer than 30 minutes with no events

    Field completeness

    required fields populated vs empty/null per event type
    command line completeness for process events
    source IP completeness for logon events
    script block completeness for PowerShell events

    Quality score

    weighted score from 0–100
    assessment: good, acceptable, or poor

**Expected Output:**

```PS
PS> .\4-windows_telemetry_quality.ps1
[*] Analyzing windows_events_export.json...
Total events: 2270
Hours with events: 23/24
Largest gap: 60 minutes
Command-line completeness: 100%
Source IP completeness: 97%
Script block completeness: 100%
Quality score: 94.2% (good)
Report saved to: windows_telemetry_quality.json
```

---

# [5. auditd Rule Refinement](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/5-auditd_refine.sh)

## Goal: 

Refine the auditd configuration from 2x00 by adding detection-focused rules for process execution, network socket creation and additional sensitive file access, then validate every rule fires correctly.

## Context: 

The auditd rules from 2x00 Task 10 covered identity files, privilege escalation and suspicious tool execution. But they missed critical categories: process execution via execve (the Linux equivalent of Sysmon Event ID 1), network socket creation, SSH key file access and modifications to cron directories. This task fills those gaps to bring Linux telemetry closer to the visibility level Sysmon provides on Windows.

## Instructions: 

Write a script 5-auditd_refine.sh that:

    Loads the current auditd rules and reports the count

    Adds detection-focused rules:

        Process execution via execve (-a always,exit -F arch=b64 -S execve -k process_exec)

        Network socket creation (-a always,exit -F arch=b64 -S socket -S connect -k network_connect)

        SSH key file access (-w /home/*/.ssh/ -p rwa -k ssh_keys)

        Cron directory modifications (-w /etc/cron.d/ -p wa -k cron_persist and /var/spool/cron/)

        sudo configuration access (-w /etc/sudoers.d/ -p wa -k sudoers)

    Loads the updated rules

    Validates each new rule fires by triggering a test action and searching with ausearch

**Expected Output:**

```bash
$ sudo ./5-auditd_refine.sh
[*] Current auditd rules: 14
[*] Adding detection-focused rules...
    execve syscall tracking               [ADDED]
    socket/connect syscall tracking       [ADDED]
    SSH key file monitoring               [ADDED]
    Cron directory monitoring             [ADDED]
    sudoers.d monitoring                  [ADDED]
[*] Loading rules... augenrules --load: OK
[*] Total rules: 19
[*] Validating new rules...
    execve: ran /usr/bin/id -> ausearch -k process_exec    [CAPTURED]
    socket: curl localhost -> ausearch -k network_connect  [CAPTURED]
    ssh_keys: touch ~/.ssh/test -> ausearch -k ssh_keys    [CAPTURED]
    cron: touch /etc/cron.d/test -> ausearch -k cron_persist [CAPTURED]
    sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers [CAPTURED]
Rules added: 5 | Validation: 5/5 PASS
```

---

# [6. Linux Log Source Mapping](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/6-log_source_map.sh)

## Goal: 

Inventory all active log sources on the hardened Linux system, documenting their location, format, rotation policy, security relevance and event rate.

## Context: 

Linux telemetry comes from multiple sources with different formats: auditd produces structured records, auth.log uses syslog format, application logs vary by service. Before you can export this data in a consistent format, you need to know exactly what you have. This inventory becomes the input specification for your export script.

## Instructions: 

Write a script 6-log_source_map.sh that:

    Discovers all active log sources on the system: auth.log, syslog, audit.log, kern.log, dpkg.log, apache2 access/error logs and any other security-relevant sources

    For each source: file path, format type (syslog, JSON, audit, custom), rotation policy (from logrotate config), current file size, estimated events per hour, security relevance rating (critical, high, medium, low)

    Identifies any expected sources that are missing or not generating events

**Expected Output:**

```bash
$ ./6-log_source_map.sh
[*] Discovering log sources...
Source             Path                    Format    Rotation   Events/hr  Relevance
------             ----                    ------    --------   ---------  ---------
auth.log           /var/log/auth.log       syslog    90 days    42         critical
audit.log          /var/log/audit/audit.log audit     30 days    187        critical
syslog             /var/log/syslog         syslog    60 days    95         high
kern.log           /var/log/kern.log       syslog    30 days    12         medium
apache2 access     /var/log/apache2/access  combined  14 days    234        high
apache2 error      /var/log/apache2/error   custom    14 days    8          high
dpkg.log           /var/log/dpkg.log       custom    365 days   <1         medium
Sources found: 7 | Missing: 0
```

---

# [7. Linux Event Export](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/script 7-linux_export.sh)

## Goal: 

Export security-relevant Linux logs from a defined time window to structured JSON with normalized fields, parallel to the Windows export in Task 3.

## Context: 

The analyst in Module 3 needs Linux telemetry in the same structured format as Windows telemetry. auth.log records SSH logins and sudo usage. auditd records syscall-level events. syslog captures service activity. This script parses each format and produces consistent JSON that can be queried with jq alongside the Windows export.

## Instructions: 

Write a script 7-linux_export.sh that:

    Parses auth.log to extract SSH events (login success/failure, source IP, user), sudo events (user, command) and su events

    Parses auditd logs to extract syscall events (execve with command line, file access with path, network socket creation with destination)

    Parses syslog to extract service start/stop events and error conditions

    For each event: normalizes timestamp to ISO 8601 UTC, extracts hostname, source_type, event_category and key fields

**Expected Output:**

```bash
$ ./7-linux_export.sh
[*] Parsing auth.log... 523 events
    SSH logins: 47 | sudo: 312 | su: 8 | PAM: 156
[*] Parsing audit.log... 1,187 events
    execve: 478 | file_access: 423 | network: 156 | other: 130
[*] Parsing syslog... 312 events
    service: 89 | error: 23 | other: 200
Total events: 2,022
Time range: 2026-03-25T00:00:00Z to 2026-03-25T23:59:59Z
```

---

# [8. Linux Telemetry Quality Gate](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/8-linux_telemetry_quality.sh)

## Goal: 

Assess Linux telemetry quality using the same standard applied to Windows telemetry.

## Context:

This project is cross-platform. If Windows telemetry is measured strictly but Linux telemetry is only exported, the handoff becomes uneven. This rebuilt task makes Linux telemetry quality comparable to Windows telemetry quality by measuring distribution, field completeness, timestamp coverage, and visibility gaps.

## Instructions:

Write a Bash script named 8-linux_telemetry_quality.sh.

The script must read linux_events_export.json and produce linux_telemetry_quality.json.

The quality report must include:

    Event distribution

    count per event category
    count per source type
    percentage of total

    Time coverage

    events per hour
    hours with events
    hours without events

    Gap detection

    any period longer than 30 minutes with no events

    Field completeness

    timestamp
    hostname
    source_type
    event_category
    command line for execve
    source IP/user for SSH events
    path/operation/key for auditd file events

    Quality score

    weighted score from 0–100
    assessment: good, acceptable, or poor

The script must use jq for JSON parsing.

**Expected Output:**

```bash
$ ./8-linux_telemetry_quality.sh
[*] Analyzing linux_events_export.json...
Total events: 2022
Hours with events: 24/24
No gaps detected
execve command_line completeness: 100%
SSH source_ip completeness: 100%
auditd file path completeness: 100%
Quality score: 96.1% (good)
Report saved to: linux_telemetry_quality.json
```

---

# [9. Windows Attacker Simulation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/9-windows_attack_sim.ps1)

## Goal: 

Execute a controlled sequence of attacker-like actions on the hardened Windows endpoint and record the ground truth of what was executed.

## Context: 

The telemetry validation in Block 1 tested individual event types in isolation. This task tests them together in a realistic attack sequence. You will run the attacker's playbook from the Crimson Tide advisory against your own hardened endpoint: create a user, escalate privileges, run encoded PowerShell, establish persistence, initiate an outbound connection. Every action is logged with its exact timestamp so you can later prove (in Task 10) that your instrumentation captured each one.

## Instructions: 

Write a PowerShell script 9-windows_attack_sim.ps1 that executes the following sequence, recording each action with a precise timestamp:

    Create a new local user account (support_update)

    Add the user to the Administrators group

    Run an encoded PowerShell command (harmless payload, e.g., Write-Host "C2 beacon")

    Create a scheduled task for persistence (schtasks /create)

    Initiate an outbound network connection (Test-NetConnection to a safe external IP)

    Drop a file in a startup directory (C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\)

After execution, produce a ground truth JSON file recording: action number, description, exact timestamp, expected detection source (Sysmon Event ID, Security Event ID), MITRE ATT&CK technique.

Clean up all artifacts after logging.

**Expected Output:**

```PS
PS> .\9-windows_attack_sim.ps1
[*] Running Windows attacker simulation...
    [1/6] Creating local user 'support_update'...      2026-03-25T14:30:01Z
    [2/6] Adding to Administrators group...            2026-03-25T14:30:02Z
    [3/6] Running encoded PowerShell...                2026-03-25T14:30:03Z
    [4/6] Creating scheduled task...                   2026-03-25T14:30:04Z
    [5/6] Outbound network connection...               2026-03-25T14:30:05Z
    [6/6] Dropping file in Startup...                  2026-03-25T14:30:06Z
[*] Cleaning up artifacts...
    User removed, task deleted, file removed           [CLEAN]
Actions executed: 6
Ground truth saved to: windows_attack_log.json
```

---

# [10. Windows Detection Proof](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/10-windows_detection_proof.ps1)

## Goal: 

Correlate the Windows attack simulation log against captured telemetry to produce a detection matrix proving which actions were captured, by which source and with what detail.

## Context: 

You now have two datasets: the ground truth (Task 9) and the captured telemetry (Sysmon, Security, PowerShell logs). This task maps one to the other. For every action the attacker took, was it captured? By which source? With what Event ID? With what detail level? This detection matrix is the proof that your instrumentation works under realistic conditions.

## Instructions: 

Write a PowerShell script 10-windows_detection_proof.ps1 that:

    Reads windows_attack_log.json (ground truth from Task 9)

    For each simulated action, searches the Windows Event Logs (Security, Sysmon, PowerShell) within a 30-second window around the recorded timestamp

    Records: which source captured it, the Event ID, the detail level (full/partial/missed), the key fields present

Expected Output:

```PS
PS> .\10-windows_detection_proof.ps1
[*] Loading ground truth (6 actions)...
[*] Searching telemetry for each action...
Action                     Source         Event ID   Detail    Status
------                     ------         --------   ------    ------
Create user                Security       4720       Full      [CAPTURED]
Add to Administrators      Security       4732       Full      [CAPTURED]
Encoded PowerShell         PS ScriptBlock 4104       Full      [CAPTURED]
                           Sysmon         1          Full      [CAPTURED]
Scheduled task             Sysmon         1          Full      [CAPTURED]
Outbound connection        Sysmon         3          Full      [CAPTURED]
Startup file drop          Sysmon         11         Full      [CAPTURED]
Actions: 6 | Captured: 6/6 (100%) | Multi-source: 1
Report saved to: windows_detection_matrix.json
```

---

# [11. Linux Attacker Simulation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/11-linux_attack_sim.sh)

## Goal: 

Execute a controlled sequence of attacker-like actions on the hardened Linux endpoint and record the ground truth.

## Context: 

The same validation methodology applied to Windows now applies to Linux. The attacker actions mirror the Crimson Tide Linux-specific techniques: create a user, modify sudoers, execute from /tmp, attempt a reverse shell (to localhost, safe), establish cron persistence, access sensitive files.

## Instructions: 

Write a script 11-linux_attack_sim.sh that executes the following sequence with timestamps:

    Create a user (useradd testattacker)

    Modify sudoers (echo "testattacker ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/backdoor)

    Execute a binary from /tmp (cp /usr/bin/id /tmp/suspicious_bin && /tmp/suspicious_bin)

    Attempt a reverse shell to localhost (bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &' ; sleep 1 ; kill %1 2>/dev/null)

    Modify crontab (echo "* * * * * /tmp/beacon.sh" > /etc/cron.d/persistence_test)

    Access sensitive files (cat /etc/shadow > /dev/null)

Clean up all artifacts. Produce ground truth JSON.

**Expected Output:**

```bash
$ sudo ./11-linux_attack_sim.sh
[*] Running Linux attacker simulation...
    [1/6] Creating user testattacker...                2026-03-25T14:35:01Z
    [2/6] Modifying sudoers...                         2026-03-25T14:35:02Z
    [3/6] Executing from /tmp...                       2026-03-25T14:35:03Z
    [4/6] Reverse shell attempt (localhost)...         2026-03-25T14:35:04Z
    [5/6] Cron persistence...                          2026-03-25T14:35:05Z
    [6/6] Accessing /etc/shadow...                     2026-03-25T14:35:06Z
[*] Cleaning up artifacts...                           [CLEAN]
Actions executed: 6
Ground truth saved to: linux_attack_log.json
```

---

# [12. Linux Detection Proof](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/12-linux_detection_proof.sh)

## Goal: 

Correlate the Linux attack simulation log against captured telemetry to produce a detection matrix.

## Context: 

Same methodology as Task 10, applied to Linux sources: auditd, auth.log and syslog. For each attacker action, was it captured? By which source? With what detail? The detection matrix reveals whether the auditd rules from 2x00 and the refinements from Task 5 provide adequate coverage.

## Instructions: 

Write a script 12-linux_detection_proof.sh that:

    Reads linux_attack_log.json (ground truth from Task 11)

    For each action, searches auditd (via ausearch), auth.log and syslog within a 30-second window

    Records: source, audit key (if auditd), detail level, key fields present

    Produces a detection matrix as structured JSON

**Expected Output:**

```bash
$ sudo ./12-linux_detection_proof.sh
[*] Loading ground truth (6 actions)...
[*] Searching telemetry...
Action                     Source         Key              Detail    Status
------                     ------         ---              ------    ------
Create user                auditd         identity         Full      [CAPTURED]
                           auth.log       useradd          Full      [CAPTURED]
Modify sudoers             auditd         sudoers          Full      [CAPTURED]
Execute from /tmp          auditd         process_exec     Full      [CAPTURED]
Reverse shell              auditd         network_connect  Full      [CAPTURED]
Cron persistence           auditd         cron_persist     Full      [CAPTURED]
Access /etc/shadow         auditd         identity         Full      [CAPTURED]
Actions: 6 | Captured: 6/6 (100%) | Multi-source: 1
Report saved to: linux_detection_matrix.json
```

---

# [13. Consolidated Telemetry Export](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/13-consolidated_export.sh)

## Goal: 

Combine all Windows and Linux telemetry exports plus the attacker simulation telemetry into a single structured handoff package with normalized timestamps across platforms.

## Context: 

Module 3 starts with the SOC receiving raw telemetry from endpoints. The handoff package you build here IS that telemetry. It must contain: normal operational events (the bulk), the attacker simulation events (the signal the SOC must find) and the ground truth (so the SOC can validate their detections). Timestamps must be consistent across Windows and Linux (both in UTC ISO 8601).

## Instructions: Write a script 13-consolidated_export.sh that:

    Reads windows_events_export.json (Task 3) and linux_events_export.json (Task 7)

    Normalizes all timestamps to UTC ISO 8601 if not already

    Verifies field consistency across platforms (both must have: timestamp, hostname, source_type, event_category)

    Packages the attacker ground truth files (windows_attack_log.json, linux_attack_log.json) separately

    Produces the handoff directory structure:
    
    ```
    telemetry_handoff/
      windows_events.json
      linux_events.json
      attack_ground_truth.json   (combined Windows + Linux)
    ```
    
**Expected Output:**

```bash
$ ./13-consolidated_export.sh
[*] Loading Windows events (2,270)...
[*] Loading Linux events (2,022)...
[*] Normalizing timestamps to UTC...
    Windows: 2,270 events normalized
    Linux: 2,022 events normalized
[*] Verifying field consistency...
    Required fields present in all events    [OK]
[*] Combining ground truth...
    Windows actions: 6 | Linux actions: 6 | Total: 12
[*] Building handoff directory...
telemetry_handoff/
  windows_events.json     (2,270 events, 4.2 MB)
  linux_events.json       (2,022 events, 3.1 MB)
  attack_ground_truth.json (12 actions)
Total: 4,292 events across 2 platforms
```

---

# [14. Cross-Platform Coverage Assessment](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/14-coverage_assessment.sh)

## Goal: 

Produce the final telemetry coverage assessment that explains what the SOC can detect, what remains partially visible, and what is still blind.

## Context:

The original coverage assessment task was too broad. This rebuilt task makes the output precise and operational. It must combine the handoff package, detection matrices, and quality reports into a final metadata file that travels with the telemetry package.

The SOC should be able to read this file and immediately understand the strengths and limits of the dataset.

## Instructions:

Write a Bash script named 14-coverage_assessment.sh.

The script must read:

    telemetry_handoff/windows_events.json
    telemetry_handoff/linux_events.json
    telemetry_handoff/attack_ground_truth.json
    windows_detection_matrix.json
    linux_detection_matrix.json
    windows_telemetry_quality.json
    linux_telemetry_quality.json
    sysmon_coverage_matrix.json

The script must produce telemetry_coverage_assessment.json.

The assessment must include:

    Total events

    by platform
    by source type
    by event category

    Detection matrix summary

    total simulated actions
    captured actions
    missed actions
    multi-source detections

    ATT&CK coverage

    covered techniques
    partially covered techniques
    blind techniques
    source responsible for coverage

    Known gaps

    description
    impacted platform
    impacted technique
    reason
    recommended instrumentation improvement

    Quality summary

    Windows score
    Linux score
    final handoff confidence rating

The script must use jq.

**Expected Output:**

```bash
$ ./14-coverage_assessment.sh
[*] Loading telemetry handoff package...
Windows events: 2270
Linux events: 2022
Ground truth actions: 12
Detection matrix: 11/12 captured
ATT&CK covered: 9
ATT&CK partial: 2
ATT&CK blind: 1
Windows quality: 94.2
Linux quality: 96.1
Confidence: acceptable
Report saved to: telemetry_coverage_assessment.json
```

---

# [15. Handoff Validation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x02_eyes_on_endpoint/15-handoff_validation.sh)

## Goal: 

Validate the telemetry handoff package against quality gates to ensure it is ready for analyst consumption in futur.

## Context: 

This is the quality gate. If the handoff package is malformed, incomplete or inconsistent. This script is a meta-validator: it checks file existence, JSON validity, required field presence, minimum event counts per source, timestamp consistency across platforms and ground truth completeness. It is the final script you run before crossing from the builder role, into the analyst role.

## Instructions: 

Write a script 15-handoff_validation.sh that validates the telemetry_handoff/ directory:

    File existence: all 3 expected files present

    JSON validity: each file parses without errors

    Required fields: every event has timestamp, hostname, sourcetype, eventcategory

    Minimum event counts: Windows >= 1000 events, Linux >= 500 events, ground truth >= 10 actions

    Timestamp consistency: all timestamps are valid ISO 8601, all within a reasonable range, no future timestamps

    Cross-platform alignment: timestamp ranges overlap (both platforms cover the same period)

    Ground truth completeness: every action has a corresponding detection matrix entry

Report PASS/FAIL per check with a final verdict.

**Expected Output:**

```bash
$ ./15-handoff_validation.sh
[*] Validating telemetry_handoff/ ...
=== File Existence ===
[PASS] windows_events.json exists (4.2 MB)
[PASS] linux_events.json exists (3.1 MB)
[PASS] attack_ground_truth.json exists (12 KB)
=== JSON Validity ===
[PASS] windows_events.json: valid JSON, 2270 objects
[PASS] linux_events.json: valid JSON, 2022 objects
[PASS] attack_ground_truth.json: valid JSON, 12 objects
=== Required Fields ===
[PASS] All events have timestamp, hostname, source_type, event_category
=== Minimum Event Counts ===
[PASS] Windows: 2,270 >= 1,000
[PASS] Linux: 2,022 >= 500
[PASS] Ground truth: 12 >= 10
=== Timestamp Consistency ===
[PASS] All timestamps valid ISO 8601
[PASS] No future timestamps
[PASS] Range: 2026-03-25T00:00:00Z to 2026-03-25T23:59:59Z
=== Cross-Platform Alignment ===
[PASS] Windows and Linux time ranges overlap (23.5 hours shared)
=== Ground Truth Completeness ===
[PASS] 12/12 actions have detection matrix entries
VERDICT: PASS (14/14 checks)
Handoff package is ready for Module 3.
Report saved to: handoff_validation.json
```

---

