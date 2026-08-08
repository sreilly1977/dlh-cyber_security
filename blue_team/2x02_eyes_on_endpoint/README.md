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

# 
