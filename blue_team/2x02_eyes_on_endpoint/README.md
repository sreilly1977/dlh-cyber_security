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

# 
