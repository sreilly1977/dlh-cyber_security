# 0. Sysmon Telemetry Validation

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

#
