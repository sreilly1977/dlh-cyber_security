<#
.Synopsis
    3-telemetry_reference.ps1 - Windows Telemetry Reference Builder
.Purpose
    Builds a machine-readable Windows event reference that connects security
    events to detection use cases, mapping Event IDs to log source, audit
    dependency, detection meaning, attack phase, triage priority, and validation method.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 4, 2026
#>

param(
    [string]$OutputPath = "windows_event_reference.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# SECURITY LOG EVENTS
# ===========================================================================
$securityEvents = @(
    [PSCustomObject]@{
        event_id = 4624
        event_name = "Successful Logon"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Logon (Success)"
        security_meaning = "User successfully authenticated to the system. Critical for tracking lateral movement and tracking when privileged accounts are used."
        normal_frequency = "High - every legitimate user login"
        triage_priority = "Medium"
        crimson_tide_phase = "Execution, Persistence"
        example_suspicious_pattern = "Logon Type 3 (network) from unexpected IP, logon outside business hours for service account, NTLM authentication when Kerberos expected"
        validation_method = "Query Security log for 4624 events with LogonType 3 and cross-reference source IPs against known workstation ranges"
    }
        [PSCustomObject]@{
        event_id = 4625
        event_name = "Failed Logon"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Logon (Failure)"
        security_meaning = "A failed logon attempt. Authentication attempt failed. Key indicator for brute force, password spraying, and credential stuffing attacks."
        normal_frequency = "Low - occasional typos and expired passwords"
        triage_priority = "High"
        crimson_tide_phase = "Credential Access, Discovery"
        example_suspicious_pattern = "5+ failures for same account in 60 seconds, failures across many accounts from single IP, failures for disabled or service accounts"
        validation_method = "Query Security log for 4625 grouped by target account and source IP; threshold alert at 5 failures per 60 seconds"
    }
    [PSCustomObject]@{
        event_id = 4648
        event_name = "Explicit Credentials"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Logon (Success) - Explicit Credential Use"
        security_meaning = "A process attempted to log on using explicit credentials. Key for detecting RunAs usage, lateral movement via alternate credentials."
        normal_frequency = "Low - rare in normal operations"
        triage_priority = "High"
        crimson_tide_phase = "Credential Access, Lateral Movement"
        example_suspicious_pattern = "Explicit credentials used from non-admin workstation, elevated credentials on shared server, credentials targeting database service account"
        validation_method = "Query Security log for 4648 and correlate with source process and target account; alert on elevated credential use outside jump boxes"
    }
    [PSCustomObject]@{
        event_id = 4672
        event_name = "Special Logon"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Special Logon"
        security_meaning = "Account logged on with special privileges (Backup, Debug, SeTcb, SeSecurity). Detects when admin-level rights are exercised, not just assigned."
        normal_frequency = "Low - only when privileged rights are actually invoked"
        triage_priority = "High"
        crimson_tide_phase = "Privilege Escalation, Defense Evasion"
        example_suspicious_pattern = "Service account exercising debug privilege, unexpected backup privilege use outside scheduled backup window, special logon from non-DC system"
        validation_method = "Query Security log for 4647 and 4672 grouped by account; alert on service accounts gaining debug privilege"
    }
    [PSCustomObject]@{
        event_id = 4688
        event_name = "Process Creation"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Process Creation (Success)"
        security_meaning = "New process started. Combined with command-line logging, this is the backbone of endpoint detection."
        normal_frequency = "Very High - every program execution"
        triage_priority = "Critical"
        crimson_tide_phase = "Execution, Defense Evasion"
        example_suspicious_pattern = "powershell.exe -enc, cmd.exe launched by winword.exe, mimikatz.exe, certutil.exe for download"
        validation_method = "Query Security log for 4688 with process names matching known attack tool patterns; enable command-line logging via GPO"
    }
    [PSCustomObject]@{
        event_id = 4720
        event_name = "Account Created"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit User Account Management"
        security_meaning = "New user account was created. Critical for detecting persistence mechanisms through backdoor account creation."
        normal_frequency = "Very Low - only during onboarding or maintenance"
        triage_priority = "High"
        crimson_tide_phase = "Persistence, Defense Evasion"
        example_suspicious_pattern = "Account created outside business hours, account with admin-like name but created by non-Domain Admin, account created on DC via script"
        validation_method = "Query Security log for 4720 and correlate creator with approved account operators; alert on any new account created outside business hours"
    }
    [PSCustomObject]@{
        event_id = 4726
        event_name = "Account Deleted"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit User Account Management"
        security_meaning = "User account was deleted. Can indicate attacker covering tracks or insider sabotage removing legitimate accounts."
        normal_frequency = "Very Low - only during offboarding"
        triage_priority = "High"
        crimson_tide_phase = "Defense Evasion, Impact"
        example_suspicious_pattern = "Account deleted shortly after creation (cleanup of persistence account), bulk deletions, deletion of IT admin accounts by non-admin"
        validation_method = "Query Security log for 4726 and correlate with HR offboarding records; alert on deletions not matching approved offboarding workflow"
    }
    [PSCustomObject]@{
        event_id = 4732
        event_name = "Member Added to Group"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit Security Group Management"
        security_meaning = "Member added to a security group. Critical for detecting privilege escalation through group membership manipulation."
        normal_frequency = "Low - occasional role changes"
        triage_priority = "Critical"
        crimson_tide_phase = "Privilege Escalation, Persistence"
        example_suspicious_pattern = "Service account added to Domain Admins, user added to Enterprise Admins outside change window, bulk additions to privileged group"
        validation_method = "Query Security log for 4732 filtered for target groups Domain Admins, Enterprise Admins, G_IT_Admins; alert on any addition to Tier 0 groups"
    }
    [PSCustomObject]@{
        event_id = 1102
        event_name = "Audit Log Cleared"
        log_source = "Security"
        audit_or_sensor_dependency = "Audit System Integrity"
        security_meaning = "Security audit log was cleared. Strong indicator of cover-up activity and tampering with forensic evidence."
        normal_frequency = "None - should never occur in normal operations"
        triage_priority = "Critical"
        crimson_tide_phase = "Defense Evasion, Cover Tracks"
        example_suspicious_pattern = "Any occurrence outside approved maintenance window, log clearing followed by gap in process events, cleared by non-admin or service account"
        validation_method = "Query Security log for 1102; alert unconditionally and correlate with concurrent gaps in other event streams"
    }
)

# ===========================================================================
# POWERSHELL LOG EVENTS
# ===========================================================================
$powerShellEvents = @(
    [PSCustomObject]@{
        event_id = 4103
        event_name = "PowerShell Module Logging"
        log_source = "Microsoft-Windows-PowerShell/Operational"
        audit_or_sensor_dependency = "PowerShell Module Logging (Turn on Module Logging for all modules)"
        security_meaning = "PowerShell pipeline execution details including module, commands, and arguments. Critical for detecting obfuscated or encoded PowerShell attacks."
        normal_frequency = "Moderate - every PowerShell pipeline execution"
        triage_priority = "High"
        crimson_tide_phase = "Execution, Defense Evasion"
        example_suspicious_pattern = "Encoded commands, IEX with downloaded content, Set-MpPreference -DisableRealtimeMonitoring, Add-MpPreference -ExclusionPath, Invoke-Mimikatz module"
        validation_method = "Query PowerShell Operational log for 4103 containing 'IEX', 'Invoke-Expression', 'DownloadString', 'FromBase64String', 'Set-MpPreference'"
    }
    [PSCustomObject]@{
        event_id = 4104
        event_name = "PowerShell Script Block Logging"
        log_source = "Microsoft-Windows-PowerShell/Operational"
        audit_or_sensor_dependency = "PowerShell Script Block Logging (EnableScriptBlockLogging = 1)"
        security_meaning = "Full de-obfuscated script block content as executed. Reveals the actual code even when obfuscation techniques are used."
        normal_frequency = "Moderate - every script block compilation"
        triage_priority = "Critical"
        crimson_tide_phase = "Execution, Defense Evasion, Credential Access"
        example_suspicious_pattern = "Invoke-Mimikatz, Invoke-TokenManipulation, Set-MpPreference -DisableRealtimeMonitoring $true, New-NetTCPClient for reverse shell, Add-Type for Win32 API calls"
        validation_method = "Query PowerShell Operational log for 4104; search for known malicious patterns and API names; verify de-obfuscated content"
    }
)

# ===========================================================================
# SYSMON LOG EVENTS
# ===========================================================================
$sysmonEvents = @(
    [PSCustomObject]@{
        event_id = 1
        event_name = "Process Create"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon EventRule: Process Create"
        security_meaning = "Detailed process creation with full command line, parent process, hash, and signed status. The richest single source of endpoint telemetry."
        normal_frequency = "Very High - every process launch"
        triage_priority = "Critical"
        crimson_tide_phase = "Execution, Defense Evasion"
        example_suspicious_pattern = "winword.exe spawning cmd.exe or powershell.exe, certutil.exe -urlcache -split -f, rundll32.exe with remote URL, mshta.exe executing VBScript"
        validation_method = "Query Sysmon Operational log for Event 1; filter for suspicious parent-child process relationships and command-line patterns"
    }
    [PSCustomObject]@{
        event_id = 3
        event_name = "Network Connection"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon EventRule: Network Connection"
        security_meaning = "Process initiated network connection. Essential for detecting C2 communication, data exfiltration, and lateral movement over network protocols."
        normal_frequency = "High - every outbound network connection"
        triage_priority = "High"
        crimson_tide_phase = "C2, Lateral Movement, Exfiltration"
        example_suspicious_pattern = "PowerShell connecting to non-Microsoft IP on port 443, lsass.exe initiating network connections, connections to known C2 infrastructure, DNS queries to suspicious domains"
        validation_method = "Query Sysmon Operational log for Event 3; correlate destination IPs against threat intel feeds and known-good service ranges"
    }
    [PSCustomObject]@{
        event_id = 7
        event_name = "Image Loaded"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon EventRule: Image Loaded"
        security_meaning = "DLL or driver loaded by a process. Detects DLL injection, unsigned module loading, and exploitation of legitimate processes via malicious libraries."
        normal_frequency = "High - every DLL load"
        triage_priority = "Medium"
        crimson_tide_phase = "Defense Evasion, Privilege Escalation"
        example_suspicious_pattern = "Unsigned DLL loaded into lsass.exe, DLL loaded from temp directory, known vulnerable driver loaded, clr.dll loaded by non-.NET process"
        validation_method = "Query Sysmon Operational log for Event 7; filter for unsigned or untrusted signatures and unusual load paths"
    }
    [PSCustomObject]@{
        event_id = 11
        event_name = "File Create"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon EventRule: File Create"
        security_meaning = "File creation event. Critical for detecting dropped payloads, staged credentials, ransomware staging, and scheduled task XML creation."
        normal_frequency = "Very High - every file write to monitored locations"
        triage_priority = "High"
        crimson_tide_phase = "Persistence, Execution"
        example_suspicious_pattern = "Executable written to Startup folder, DLL dropped into System32, batch file created in Temp, encrypted file pattern indicating ransomware staging"
        validation_method = "Query Sysmon Operational log for Event 11; filter for executable drops in user-writable paths and startup locations"
    }
    [PSCustomObject]@{
        event_id = 13
        event_name = "Registry Value Set"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon EventRule: Registry Value Set"
        security_meaning = "Registry value modified. Detects persistence via autorun keys, registry modifications for defense evasion, and COM object hijacking."
        normal_frequency = "High - every registry write to monitored keys"
        triage_priority = "High"
        crimson_tide_phase = "Persistence, Defense Evasion"
        example_suspicious_pattern = "Run/RunOnce keys set by non-installer process, AppCompatDlls shim insertion, DisableRealtimeMonitoring registry value, Image File Execution Options debugger entry"
        validation_method = "Query Sysmon Operational log for Event 13; filter for persistence-related registry paths and defender-disabling modifications"
    }
    [PSCustomObject]@{
        event_id = 22
        event_name = "DNS Query"
        log_source = "Microsoft-Windows-Sysmon/Operational"
        audit_or_sensor_dependency = "Sysmon EventRule: DNS Query"
        security_meaning = "DNS query initiated by a process. Key for detecting C2 resolution, DNS tunneling, and dynamic DNS infrastructure used by threat actors."
        normal_frequency = "Very High - every DNS resolution"
        triage_priority = "High"
        crimson_tide_phase = "C2, Discovery"
        example_suspicious_pattern = "High-entropy subdomains indicating DNS tunneling, queries to newly registered domains, TXT queries with large response payloads, DNS to non-organizational DNS servers"
        validation_method = "Query Sysmon Operational log for Event 22; correlate queried domains against threat intel and passive DNS databases"
    }
)

# ===========================================================================
# ASSEMBLE AND EXPORT
# ===========================================================================
$allEvents = @($securityEvents + $powerShellEvents + $sysmonEvents)

$report = [PSCustomObject]@{
    reference_metadata = [PSCustomObject]@{
        generated_date = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
        environment = "MedDefense"
        purpose = "Connects Windows security events to detection use cases, bridging audit policy configuration, Sysmon deployment, PowerShell logging, and Module 3 detection work"
        threat_context = "Crimson Tide CISA advisory threat actor profile applied to MedDefense infrastructure"
        total_events_documented = $allEvents.Count
    }
    security_events = $securityEvents
    powershell_events = $powerShellEvents
    sysmon_events = $sysmonEvents
}

$report | ConvertTo-Json -Depth 5 | Out-File -FilePath $OutputPath -Force -Encoding UTF8

Write-Host "Security events mapped: $($securityEvents.Count)"
Write-Host "PowerShell events mapped: $($powerShellEvents.Count)"
Write-Host "Sysmon events mapped: $($sysmonEvents.Count)"
Write-Host "Total events documented: $($allEvents.Count)"
Write-Host "Reference saved to: $OutputPath" -ForegroundColor Green
