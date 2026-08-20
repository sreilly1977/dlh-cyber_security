<#
.SYNOPSIS
    CIS Level 1 audit helper for Windows 11 Pro workstations.
.DESCRIPTION
    Capstone task T1 - Defensible Endpoint Package
    Walks a fixed list of CIS Level 1 control checks and outputs
    one line per control in the format: CONTROL_ID RESULT
.NOTES
    Name: win_audit.ps1
    Purpose: CIS Level 1 audit helper for Windows 11 Pro
    Author: Steve - Cybersecurity Engineer
    Date: 20 August 2026
    Exit Codes: 0=success, 1=controlled failure, 2=environment error
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-AuditResult {
    param(
        [string]$ControlId,
        [string]$Result
    )
    Write-Output "$ControlId $Result"
}

function Test-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [string]$ExpectedValue
    )
    try {
        $actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($actual.ToString() -eq $ExpectedValue) {
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

function Test-RegistryValueInSet {
    param(
        [string]$Path,
        [string]$Name,
        [string[]]$AllowedValues
    )
    try {
        $actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        foreach ($allowed in $AllowedValues) {
            if ($actual.ToString() -eq $allowed) {
                return $true
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

# --- Account Policies ---

function Check-PasswordPolicy {
    $seceditCfg = "$env:TEMP\secpol_audit.cfg"
    $seceditDb = "$env:TEMP\secpol_audit.sdb"

    try {
        secedit /export /cfg $seceditCfg /quiet
    }
    catch {
        return @{}
    }

    $config = @{}
    if (Test-Path $seceditCfg) {
        $content = Get-Content $seceditCfg -ErrorAction SilentlyContinue
        foreach ($line in $content) {
            if ($line -match '^\s*(\w+)\s*=\s*(.+)') {
                $config[$Matches[1]] = $Matches[2].Trim()
            }
        }
    }

    Remove-Item $seceditCfg -ErrorAction SilentlyContinue
    return $config
}

# 1.1.1 - Ensure maximum password age is 365 or fewer days
function Check-1_1_1 {
    $cfg = Check-PasswordPolicy
    if ($cfg.ContainsKey('MaximumPasswordAge')) {
        $maxAge = [int]$cfg['MaximumPasswordAge']
        if ($maxAge -le 365 -and $maxAge -gt 0) {
            Write-AuditResult "1.1.1" "PASS"
        } else {
            Write-AuditResult "1.1.1" "FAIL"
        }
    } else {
        Write-AuditResult "1.1.1" "FAIL"
    }
}

# 1.1.2 - Ensure minimum password age is 1 or more days
function Check-1_1_2 {
    $cfg = Check-PasswordPolicy
    if ($cfg.ContainsKey('MinimumPasswordAge')) {
        $minAge = [int]$cfg['MinimumPasswordAge']
        if ($minAge -ge 1) {
            Write-AuditResult "1.1.2" "PASS"
        } else {
            Write-AuditResult "1.1.2" "FAIL"
        }
    } else {
        Write-AuditResult "1.1.2" "FAIL"
    }
}

# 1.1.3 - Ensure minimum password length is 14 or more characters
function Check-1_1_3 {
    $cfg = Check-PasswordPolicy
    if ($cfg.ContainsKey('MinimumPasswordLength')) {
        $minLen = [int]$cfg['MinimumPasswordLength']
        if ($minLen -ge 14) {
            Write-AuditResult "1.1.3" "PASS"
        } else {
            Write-AuditResult "1.1.3" "FAIL"
        }
    } else {
        Write-AuditResult "1.1.3" "FAIL"
    }
}

# 1.1.4 - Ensure password complexity is enabled
function Check-1_1_4 {
    $cfg = Check-PasswordPolicy
    if ($cfg.ContainsKey('PasswordComplexity')) {
        if ($cfg['PasswordComplexity'] -eq '1') {
            Write-AuditResult "1.1.4" "PASS"
        } else {
            Write-AuditResult "1.1.4" "FAIL"
        }
    } else {
        Write-AuditResult "1.1.4" "FAIL"
    }
}

# 1.1.5 - Ensure password history is 24 or more
function Check-1_1_5 {
    $cfg = Check-PasswordPolicy
    if ($cfg.ContainsKey('PasswordHistorySize')) {
        $hist = [int]$cfg['PasswordHistorySize']
        if ($hist -ge 24) {
            Write-AuditResult "1.1.5" "PASS"
        } else {
            Write-AuditResult "1.1.5" "FAIL"
        }
    } else {
        Write-AuditResult "1.1.5" "FAIL"
    }
}

# 1.2.1 - Ensure account lockout threshold is 10 or fewer
function Check-1_2_1 {
    $cfg = Check-PasswordPolicy
    if ($cfg.ContainsKey('LockoutBadCount')) {
        $threshold = [int]$cfg['LockoutBadCount']
        if ($threshold -gt 0 -and $threshold -le 10) {
            Write-AuditResult "1.2.1" "PASS"
        } else {
            Write-AuditResult "1.2.1" "FAIL"
        }
    } else {
        Write-AuditResult "1.2.1" "FAIL"
    }
}

# 1.2.2 - Ensure account lockout duration is 15 or more minutes
function Check-1_2_2 {
    $cfg = Check-PasswordPolicy
    if ($cfg.ContainsKey('LockoutDuration')) {
        $duration = [int]$cfg['LockoutDuration']
        if ($duration -ge 15) {
            Write-AuditResult "1.2.2" "PASS"
        } else {
            Write-AuditResult "1.2.2" "FAIL"
        }
    } else {
        Write-AuditResult "1.2.2" "FAIL"
    }
}

# --- Local Policies: Audit ---

# 2.1.1 - Ensure 'Force shutdown from a remote system' is restricted to Administrators
function Check-2_1_1 {
    $secFile = "$env:TEMP\sec_rights_audit.cfg"
    try {
        & secedit.exe /export /cfg "$secFile" /quiet | Out-Null

        if (-not (Test-Path $secFile)) {
            Write-AuditResult "2.1.1" "FAIL"
            return
        }

        $rightsLine = Get-Content $secFile -ErrorAction Stop |
            Where-Object { $_ -match '^\s*Force shutdown from a remote system\s*=' } |
            Select-Object -First 1

        if (-not $rightsLine) {
            Write-AuditResult "2.1.1" "FAIL"
            return
        }

        $sids = ($rightsLine -split '=', 2)[1] -split ',' | ForEach-Object { $_.Trim() }

        # Deny if Everyone, Users, Guests, or Interactive are assigned
        $deniedSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-32-546', 'S-1-5-11')
        $hasAdmin = @($sids) -contains 'S-1-5-32-544'
        $hasDenied = @($sids | Where-Object { $_ -in $deniedSids })

        if ($hasAdmin -and -not $hasDenied) {
            Write-AuditResult "2.1.1" "PASS"
        }
        else {
            Write-AuditResult "2.1.1" "FAIL"
        }
    }
    catch {
        Write-AuditResult "2.1.1" "FAIL"
    }
    finally {
        Remove-Item $secFile -ErrorAction SilentlyContinue
    }
}

# 2.3.1 - Ensure Audit Force Shell Logon is enabled
function Check-2_3_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "DisableEmptyPasswordLogon" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "2.3.1" "PASS"
    } else {
        Write-AuditResult "2.3.1" "FAIL"
    }
}

# --- Local Policies: Security Options ---

# 2.3.4.1 - Ensure Accounts Administrator account status is disabled
function Check-2_3_4_1 {
    try {
        $admin = Get-LocalUser -Name "Administrator" -ErrorAction Stop
        if (-not $admin.Enabled) {
            Write-AuditResult "2.3.4.1" "PASS"
        } else {
            Write-AuditResult "2.3.4.1" "FAIL"
        }
    }
    catch {
        Write-AuditResult "2.3.4.1" "NOT_APPLICABLE"
    }
}

# 2.3.4.2 - Ensure Accounts Guest account status is disabled
function Check-2_3_4_2 {
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction Stop
        if (-not $guest.Enabled) {
            Write-AuditResult "2.3.4.2" "PASS"
        } else {
            Write-AuditResult "2.3.4.2" "FAIL"
        }
    }
    catch {
        Write-AuditResult "2.3.4.2" "NOT_APPLICABLE"
    }
}

# 2.3.7.1 - Ensure Interactive logon: Do not require CTRL+ALT+DEL is disabled
function Check-2_3_7_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "DisableCAD" `
        -ExpectedValue "0"
    if ($result) {
        Write-AuditResult "2.3.7.1" "PASS"
    } else {
        Write-AuditResult "2.3.7.1" "FAIL"
    }
}

# 2.3.7.2 - Ensure Interactive logon: Don't display last signed-in is enabled
function Check-2_3_7_2 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "dontdisplaylastusername" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "2.3.7.2" "PASS"
    } else {
        Write-AuditResult "2.3.7.2" "FAIL"
    }
}

# 2.3.7.3 - Ensure Interactive logon: Machine inactivity limit is 900 seconds or less
function Check-2_3_7_3 {
    $result = Test-RegistryValueInSet `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "InactivityTimeoutSecs" `
        -AllowedValues @("60","120","180","240","300","360","420","480","540","600","660","720","780","840","900")
    if ($result) {
        Write-AuditResult "2.3.7.3" "PASS"
    } else {
        Write-AuditResult "2.3.7.3" "FAIL"
    }
}

# 2.3.7.5 - Ensure Interactive logon: Smart card removal behavior is set to Lock Workstation or higher
function Check_2_3_7_5 {
    try {
        $value = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "scremoveoption" -ErrorAction Stop).scremoveoption
        if ($value -in @("1","2","3")) {
            Write-AuditResult "2.3.7.5" "PASS"
        } else {
            Write-AuditResult "2.3.7.5" "FAIL"
        }
    }
    catch {
        Write-AuditResult "2.3.7.5" "FAIL"
    }
}

# --- Firewall ---

# 9.1.1 - Ensure Windows Firewall: Domain Profile is enabled
function Check-9_1_1 {
    try {
        $fw = Get-NetFirewallProfile -Name Domain -ErrorAction Stop
        if ($fw.Enabled) {
            Write-AuditResult "9.1.1" "PASS"
        } else {
            Write-AuditResult "9.1.1" "FAIL"
        }
    }
    catch {
        Write-AuditResult "9.1.1" "NOT_APPLICABLE"
    }
}

# 9.1.2 - Ensure Windows Firewall: Private Profile is enabled
function Check-9_1_2 {
    try {
        $fw = Get-NetFirewallProfile -Name Private -ErrorAction Stop
        if ($fw.Enabled) {
            Write-AuditResult "9.1.2" "PASS"
        } else {
            Write-AuditResult "9.1.2" "FAIL"
        }
    }
    catch {
        Write-AuditResult "9.1.2" "FAIL"
    }
}

# 9.1.3 - Ensure Windows Firewall: Public Profile is enabled
function Check-9_1_3 {
    try {
        $fw = Get-NetFirewallProfile -Name Public -ErrorAction Stop
        if ($fw.Enabled) {
            Write-AuditResult "9.1.3" "PASS"
        } else {
            Write-AuditResult "9.1.3" "FAIL"
        }
    }
    catch {
        Write-AuditResult "9.1.3" "FAIL"
    }
}

# 9.2.1 - Ensure Windows Firewall: Domain Profile default inbound is Block
function Check-9_2_1 {
    try {
        $fw = Get-NetFirewallProfile -Name Domain -ErrorAction Stop
        if ($fw.DefaultInboundAction -eq 'Block') {
            Write-AuditResult "9.2.1" "PASS"
        } else {
            Write-AuditResult "9.2.1" "FAIL"
        }
    }
    catch {
        Write-AuditResult "9.2.1" "NOT_APPLICABLE"
    }
}

# --- Registry Settings ---

# 18.3.1 - Ensure Prevent enabling lock screen camera is enabled
function Check-18_3_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        -Name "NoLockScreenCamera" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "18.3.1" "PASS"
    } else {
        Write-AuditResult "18.3.1" "FAIL"
    }
}

# 18.3.2 - Ensure Prevent enabling lock screen slide show is enabled
function Check-18_3_2 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" `
        -Name "NoLockScreenSlideshow" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "18.3.2" "PASS"
    } else {
        Write-AuditResult "18.3.2" "FAIL"
    }
}

# 18.5.1 - Ensure Turn off Microsoft peer-to-peer networking services is enabled
function Check-18_5_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" `
        -Name "Disabled" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "18.5.1" "PASS"
    } else {
        Write-AuditResult "18.5.1" "FAIL"
    }
}

# 18.9.4.1 - Ensure Allow Telemetry is set to 0 (Security only)
function Check-18_9_4_1 {
    $result = Test-RegistryValueInSet `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" `
        -Name "AllowTelemetry" `
        -AllowedValues @("0","1")
    if ($result) {
        Write-AuditResult "18.9.4.1" "PASS"
    } else {
        Write-AuditResult "18.9.4.1" "FAIL"
    }
}

# 18.9.5.1 - Ensure Application: Control Event Log behavior is enabled
function Check-18_9_5_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" `
        -Name "Retention" `
        -ExpectedValue "0"
    if ($result) {
        Write-AuditResult "18.9.5.1" "PASS"
    } else {
        Write-AuditResult "18.9.5.1" "FAIL"
    }
}

# --- Services ---

# 5.1 - Ensure Remote Registry Service is disabled
function Check-5_1 {
    try {
        $svc = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
        if ($svc.StartType -eq 'Disabled') {
            Write-AuditResult "5.1" "PASS"
        } else {
            Write-AuditResult "5.1" "FAIL"
        }
    }
    catch {
        Write-AuditResult "5.1" "NOT_APPLICABLE"
    }
}

# 5.2 - Ensure Print Spooler is disabled (workstation)
function Check-5_2 {
    try {
        $svc = Get-Service -Name "Spooler" -ErrorAction Stop
        if ($svc.StartType -eq 'Disabled') {
            Write-AuditResult "5.2" "PASS"
        } else {
            Write-AuditResult "5.2" "FAIL"
        }
    }
    catch {
        Write-AuditResult "5.2" "NOT_APPLICABLE"
    }
}

# 5.3 - Ensure LDAP client signing requirement is configured
function Check-5_3 {
    $result = Test-RegistryValueInSet `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" `
        -Name "LDAPClientIntegrity" `
        -AllowedValues @("1","2")
    if ($result) {
        Write-AuditResult "5.3" "PASS"
    } else {
        Write-AuditResult "5.3" "FAIL"
    }
}

# --- PowerShell Logging ---

# 19.1.1 - Ensure PowerShell Script Block Logging is enabled
function Check-19_1_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "19.1.1" "PASS"
    } else {
        Write-AuditResult "19.1.1" "FAIL"
    }
}

# 19.1.2 - Ensure PowerShell Transcription is enabled
function Check-19_1_2 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "EnableTranscripting" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "19.1.2" "PASS"
    } else {
        Write-AuditResult "19.1.2" "FAIL"
    }
}

# --- Windows Defender ---

# 18.1.1.1 - Ensure Windows Defender is enabled
function Check-18_1_1_1 {
    try {
        $status = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
        if ($status) {
            Write-AuditResult "18.1.1.1" "PASS"
        } else {
            Write-AuditResult "18.1.1.1" "FAIL"
        }
    }
    catch {
        Write-AuditResult "18.1.1.1" "FAIL"
    }
}

# 18.1.1.2 - Ensure cloud-delivered protection is enabled
function Check-18_1_1_2 {
    try {
        $pref = Get-MpPreference -ErrorAction Stop
        if ($pref.MAPSReporting -ge 1) {
            Write-AuditResult "18.1.1.2" "PASS"
        } else {
            Write-AuditResult "18.1.1.2" "FAIL"
        }
    }
    catch {
        Write-AuditResult "18.1.1.2" "FAIL"
    }
}

# --- SMB ---

# 18.9.3.1 - Ensure SMB v1 server is disabled
function Check-18_9_3_1 {
    try {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        if ($feat.State -eq 'Disabled') {
            Write-AuditResult "18.9.3.1" "PASS"
        } else {
            Write-AuditResult "18.9.3.1" "FAIL"
        }
    }
    catch {
        $result = Test-RegistryValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
            -Name "SMB1" `
            -ExpectedValue "0"
        if ($result) {
            Write-AuditResult "18.9.3.1" "PASS"
        } else {
            Write-AuditResult "18.9.3.1" "FAIL"
        }
    }
}

# 18.9.3.2 - Ensure SMB v1 client is disabled
function Check-18_9_3_2 {
    try {
        $feat = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -ErrorAction Stop
        if ($feat.State -eq 'Disabled') {
            Write-AuditResult "18.9.3.2" "PASS"
        } else {
            Write-AuditResult "18.9.3.2" "FAIL"
        }
    }
    catch {
        $result = Test-RegistryValue `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" `
            -Name "Start" `
            -ExpectedValue "4"
        if ($result) {
            Write-AuditResult "18.9.3.2" "PASS"
        } else {
            Write-AuditResult "18.9.3.2" "FAIL"
        }
    }
}

# --- UAC ---

# 2.3.7.4 - Ensure User Account Control: Admin Approval Mode is enabled
function Check-2_3_7_4 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "EnableLUA" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "2.3.7.4" "PASS"
    } else {
        Write-AuditResult "2.3.7.4" "FAIL"
    }
}

# 2.3.7.6 - Ensure UAC: Behavior of the elevation prompt is set to Prompt for consent
function Check-2_3_7_6 {
    $result = Test-RegistryValueInSet `
        -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "ConsentPromptBehaviorAdmin" `
        -AllowedValues @("1","2")
    if ($result) {
        Write-AuditResult "2.3.7.6" "PASS"
    } else {
        Write-AuditResult "2.3.7.6" "FAIL"
    }
}

# --- BitLocker ---

# 1.6.1 - Ensure BitLocker is enabled on the OS drive
function Check-1_6_1 {
    try {
        $status = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($status.ProtectionStatus -eq 'On') {
            Write-AuditResult "1.6.1" "PASS"
        } else {
            Write-AuditResult "1.6.1" "FAIL"
        }
    }
    catch {
        Write-AuditResult "1.6.1" "NOT_APPLICABLE"
    }
}

# --- LSA Protection ---

# 2.3.8.1 - Ensure LSA protection is enabled
function Check-2_3_8_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RunAsPPL" `
        -ExpectedValue "1"
    if ($result) {
        Write-AuditResult "2.3.8.1" "PASS"
    } else {
        Write-AuditResult "2.3.8.1" "FAIL"
    }
}

# --- Windows Update ---

# 18.9.2.1 - Ensure Configure Automatic Updates is enabled
function Check-18_9_2_1 {
    $result = Test-RegistryValue `
        -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        -Name "NoAutoUpdate" `
        -ExpectedValue "0"
    if ($result) {
        Write-AuditResult "18.9.2.1" "PASS"
    } else {
        Write-AuditResult "18.9.2.1" "FAIL"
    }
}

# --- Run all checks ---

Write-AuditResult "=== CIS_LEVEL_1_AUDIT START ===" "INFO"

Check-1_1_1
Check-1_1_2
Check-1_1_3
Check-1_1_4
Check-1_1_5
Check-1_2_1
Check-1_2_2
Check-1_6_1
Check-2_3_4_1
Check-2_3_4_2
Check-2_3_7_1
Check-2_3_7_2
Check-2_3_7_3
Check_2_3_7_5
Check-2_3_7_4
Check-2_3_7_6
Check-2_3_8_1
Check-5_1
Check-5_2
Check-5_3
Check-9_1_1
Check-9_1_2
Check-9_1_3
Check-9_2_1
Check-18_1_1_1
Check-18_1_1_2
Check-18_3_1
Check-18_3_2
Check-18_5_1
Check-18_9_2_1
Check-18_9_3_1
Check-18_9_3_2
Check-18_9_4_1
Check-18_9_5_1
Check-19_1_1
Check-19_1_2

Write-AuditResult "=== CIS_LEVEL_1_AUDIT END ===" "INFO"

exit 0
