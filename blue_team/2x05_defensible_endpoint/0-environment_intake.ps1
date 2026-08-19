<#
.SYNOPSIS
    Captures the raw state of the Hawthorne Windows endpoint before hardening.
.DESCRIPTION
    Collects host info, installed features, running services, local users,
    firewall state, audit policy, Sysmon presence, PowerShell logging state,
    and account/password policy into a structured JSON intake record.
.NOTES
    Name: 0-environment_intake.ps1
    Purpose: Capture raw state of Hawthorne Windows endpoint before hardening
    Author: Steve - Cybersecurity Engineer
    Exit Codes: 0=success, 1=controlled failure, 2=environment error
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptName = "0-environment_intake.ps1"
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$IntakeDir = "C:\Users\Analyst\Scripts"
$IntakeFile = Join-Path $IntakeDir "intake_$($Timestamp.Replace(':','-')).json"

function Write-InfoLog {
    param([string]$Message)
    Write-Host "[$ScriptName][INFO] $Message"
}

function Write-ErrorLog {
    param([string]$Message)
    Write-Host "[$ScriptName][ERROR] $Message" -ForegroundColor Red
}

function Test-Administrator {
    $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
        [System.Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $currentPrincipal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Invoke-WithErrorHandling {
    param(
        [scriptblock]$ScriptBlock,
        [string]$FallbackValue = $null
    )
    try {
        return & $ScriptBlock
    }
    catch {
        return $FallbackValue
    }
}

function Get-HostInformation {
    Write-InfoLog "Capturing host information..."

    $osInfo = Invoke-WithErrorHandling {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }

    $computerSystem = Invoke-WithErrorHandling {
        Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    }

    $hostname = if ($computerSystem) { $computerSystem.Name } else { $env:COMPUTERNAME }
    $osBuild = if ($osInfo) { $osInfo.BuildNumber } else { "unknown" }
    $osCaption = if ($osInfo) { $osInfo.Caption } else { "unknown" }
    $hotfixes = Invoke-WithErrorHandling {
        Get-HotFix -ErrorAction Stop |
            Select-Object -Property HotFixID, InstalledOn |
            Sort-Object -Property InstalledOn -Descending |
            Select-Object -First 5
    }

    $hotfixArray = @()
    if ($hotfixes) {
        foreach ($hf in $hotfixes) {
            $hotfixArray += [PSCustomObject]@{
                hotfix_id   = $hf.HotFixID
                installed_on = if ($hf.InstalledOn) { $hf.InstalledOn.ToString("yyyy-MM-dd") } else { "unknown" }
            }
        }
    }

    return [PSCustomObject]@{
        hostname       = $hostname
        os_caption     = $osCaption
        os_build       = $osBuild
        patch_level    = $hotfixArray
    }
}

function Get-InstalledFeatures {
    Write-InfoLog "Capturing installed feature count..."

    $featureCount = 0
    $featureSource = "unknown"

    $serverFeatures = Invoke-WithErrorHandling {
        Get-WindowsFeature -ErrorAction Stop |
            Where-Object { $_.InstallState -eq 'Installed' } |
            Measure-Object |
            Select-Object -ExpandProperty Count
    }

    if ($null -ne $serverFeatures -and $serverFeatures -gt 0) {
        $featureCount = $serverFeatures
        $featureSource = "Get-WindowsFeature (Server)"
    }
    else {
        $clientFeatures = Invoke-WithErrorHandling {
            Get-WindowsOptionalFeature -Online -ErrorAction Stop |
                Where-Object { $_.State -eq 'Enabled' } |
                Measure-Object |
                Select-Object -ExpandProperty Count
        }

        if ($null -ne $clientFeatures -and $clientFeatures -gt 0) {
            $featureCount = $clientFeatures
            $featureSource = "Get-WindowsOptionalFeature (Client)"
        }
    }

    return [PSCustomObject]@{
        installed_feature_count = $featureCount
        feature_source          = $featureSource
    }
}

function Get-RunningServices {
    Write-InfoLog "Capturing running services..."

    $runningServices = Invoke-WithErrorHandling {
        Get-Service -ErrorAction Stop |
            Where-Object { $_.Status -eq 'Running' } |
            Select-Object -ExpandProperty Name
    }

    if (-not $runningServices) {
        $runningServices = @()
    }

    return [PSCustomObject]@{
        running_services = @($runningServices)
    }
}

function Get-LocalUserAccounts {
    Write-InfoLog "Capturing local user accounts..."

    $localUsers = Invoke-WithErrorHandling {
        Get-LocalUser -ErrorAction Stop |
            Select-Object Name, Enabled, PasswordRequired, PasswordLastSet
    }

    $userArray = @()
    if ($localUsers) {
        foreach ($user in $localUsers) {
            $userArray += [PSCustomObject]@{
                name               = $user.Name
                enabled            = $user.Enabled
                password_required  = $user.PasswordRequired
                password_last_set  = if ($user.PasswordLastSet) {
                    $user.PasswordLastSet.ToString("yyyy-MM-ddTHH:mm:ssZ")
                } else {
                    $null
                }
            }
        }
    }

    return [PSCustomObject]@{
        local_users = $userArray
    }
}

function Get-FirewallProfiles {
    Write-InfoLog "Capturing Windows Firewall state per profile..."

    $firewallProfiles = Invoke-WithErrorHandling {
        Get-NetFirewallProfile -ErrorAction Stop
    }

    $profileArray = @()
    if ($firewallProfiles) {
        foreach ($fw in $firewallProfiles) {
            $profileArray += [PSCustomObject]@{
                profile_name    = $fw.Name
                enabled         = $fw.Enabled
                default_inbound = $fw.DefaultInboundAction
                default_outbound = $fw.DefaultOutboundAction
            }
        }
    }

    return [PSCustomObject]@{
        firewall_profiles = $profileArray
    }
}

function Get-AuditPolicy {
    Write-InfoLog "Capturing audit policy summary..."

    $auditOutput = Invoke-WithErrorHandling {
        auditpol /get /category:* 2>&1
    }

    $auditEntries = @()
    if ($auditOutput) {
        foreach ($line in $auditOutput) {
            $trimmed = $line.ToString().Trim()
            if ($trimmed -match '^\s*(.+?)\s+(Success|Failure|Success and Failure|No Auditing|Not Specified)\s*$' -and
                $trimmed -notmatch '^Category|^Subcategory|^---' -and
                $trimmed -notmatch 'Machine Name|Target| GUID') {

                $parts = $trimmed -split '\s{2,}'
                if ($parts.Count -ge 2) {
                    $auditEntries += [PSCustomObject]@{
                        subcategory = $parts[0].Trim()
                        setting     = $parts[-1].Trim()
                    }
                }
            }
        }
    }

    return [PSCustomObject]@{
        audit_policy = $auditEntries
    }
}

function Get-SysmonPresence {
    Write-InfoLog "Capturing Sysmon presence and version..."

    $sysmonPresent = $false
    $sysmonVersion = $null
    $eventChannelSize = 0

    $sysmonService = Invoke-WithErrorHandling {
        Get-Service -Name Sysmon -ErrorAction Stop
    }

    if ($sysmonService) {
        $sysmonPresent = $true

        $sysmonReg = Invoke-WithErrorHandling {
            Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WMI\DataCollector\Microsoft-Windows-Sysmon" -ErrorAction Stop
        }
        if ($sysmonReg -and $sysmonReg.PSObject.Properties['DriverVersion']) {
            $sysmonVersion = $sysmonReg.DriverVersion
        }

        $sysmonLogInfo = Invoke-WithErrorHandling {
            Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
        }
        if ($sysmonLogInfo) {
            $eventChannelSize = $sysmonLogInfo.FileSize
        }
    }

    return [PSCustomObject]@{
        sysmon_present       = $sysmonPresent
        sysmon_version       = $sysmonVersion
        event_channel_size   = $eventChannelSize
    }
}

function Get-PowerShellLoggingState {
    Write-InfoLog "Capturing PowerShell logging state..."

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

    $enableScriptBlock = $null
    $invokeStringLogging = $null

    $regProps = Invoke-WithErrorHandling {
        Get-ItemProperty -Path $regPath -ErrorAction Stop
    }

    if ($regProps) {
        if ($regProps.PSObject.Properties['EnableScriptBlockLogging']) {
            $enableScriptBlock = $regProps.EnableScriptBlockLogging
        }
        if ($regProps.PSObject.Properties['EnableTranscription']) {
            $invokeStringLogging = $regProps.EnableTranscription
        }
    }

    return [PSCustomObject]@{
        script_block_logging_enabled = $enableScriptBlock
        transcription_enabled        = $invokeStringLogging
    }
}

function Get-AccountPasswordPolicy {
    Write-InfoLog "Capturing account lockout and password policy..."

    $netAccountsRaw = Invoke-WithErrorHandling {
        net accounts 2>&1
    }

    $policy = [PSCustomObject]@{
        force_logoff_after              = $null
        password_min_age_days           = $null
        password_max_age_days          = $null
        password_min_length             = $null
        password_complexity            = $null
        password_history               = $null
        lockout_threshold              = $null
        lockout_duration_minutes       = $null
        lockout_window_minutes         = $null
    }

    if ($netAccountsRaw) {
        foreach ($line in $netAccountsRaw) {
            $text = $line.ToString().Trim()

            if ($text -match 'Force logoff time.*?:\s*(.+)') {
                $policy.force_logoff_after = $Matches[1].Trim()
            }
            elseif ($text -match 'Minimum password age \(days\):\s*(\d+)') {
                $policy.password_min_age_days = [int]$Matches[1]
            }
            elseif ($text -match 'Maximum password age \(days\):\s*(\d+)') {
                $policy.password_max_age_days = [int]$Matches[1]
            }
            elseif ($text -match 'Minimum password length:\s*(\d+)') {
                $policy.password_min_length = [int]$Matches[1]
            }
            elseif ($text -match 'Length of password history maintained:\s*(\d+)') {
                $policy.password_history = [int]$Matches[1]
            }
            elseif ($text -match 'Lockout threshold:\s*(\d+)') {
                $policy.lockout_threshold = [int]$Matches[1]
            }
            elseif ($text -match 'Lockout duration \(minutes\):\s*(\d+)') {
                $policy.lockout_duration_minutes = [int]$Matches[1]
            }
            elseif ($text -match 'Lockout observation window \(minutes\):\s*(\d+)') {
                $policy.lockout_window_minutes = [int]$Matches[1]
            }
        }

        $complexityRaw = Invoke-WithErrorHandling {
            net accounts /domain 2>&1
        }
        if (-not $complexityRaw) {
            $complexityRaw = Invoke-WithErrorHandling {
                secedit /export /cfg "$env:TEMP\secpol.cfg" 2>&1
                Get-Content "$env:TEMP\secpol.cfg" -ErrorAction SilentlyContinue
            }
        }

        if ($complexityRaw) {
            foreach ($line in $complexityRaw) {
                $text = $line.ToString().Trim()
                if ($text -match 'PasswordComplexity\s*=\s*(\d)') {
                    $policy.password_complexity = if ($Matches[1] -eq '1') { $true } else { $false }
                    break
                }
            }
        }
    }

    return [PSCustomObject]@{
        account_password_policy = $policy
    }
}

function Write-IntakeRecord {
    Write-InfoLog "Assembling intake record..."

    $records = @()

    $records += [PSCustomObject]@{ timestamp = $Timestamp }

    $hostInfo = Get-HostInformation
    $hostInfo.PSObject.Properties | ForEach-Object {
        $records += [PSCustomObject]@{ $_.Name = $_.Value }
    }

    $records += Get-InstalledFeatures
    $records += Get-RunningServices
    $records += Get-LocalUserAccounts
    $records += Get-FirewallProfiles
    $records += Get-AuditPolicy
    $records += Get-SysmonPresence
    $records += Get-PowerShellLoggingState
    $records += Get-AccountPasswordPolicy

    $merged = [ordered]@{}
    foreach ($record in $records) {
        $record.PSObject.Properties | ForEach-Object {
            if (-not $merged.Contains($_.Name)) {
                $merged[$_.Name] = $_.Value
            }
        }
    }

    $finalObject = [PSCustomObject]$merged
    $json = $finalObject | ConvertTo-Json -Depth 10

    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        $json | Out-File -FilePath $tempFile -Encoding UTF8
        Move-Item -Path $tempFile -Destination $IntakeFile -Force
    }
    catch {
        Write-ErrorLog "Failed to write intake file: $($_.Exception.Message)"
        Remove-Item -Path $tempFile -ErrorAction SilentlyContinue
        exit 1
    }

    $hash = (Get-FileHash -Path $IntakeFile -Algorithm SHA256).Hash
    Write-InfoLog "Intake record written: $IntakeFile"
    Write-InfoLog "Record hash: $hash"
}

function Main {
    Write-InfoLog "Starting environment intake for Hawthorne Windows endpoint..."
    Write-InfoLog "Timestamp: $Timestamp"

    Write-InfoLog "Validating execution environment..."

    if (-not (Test-Administrator)) {
        Write-ErrorLog "This script requires administrator privileges"
        exit 2
    }

    if (-not (Test-Path $IntakeDir)) {
        try {
            New-Item -ItemType Directory -Path $IntakeDir -Force | Out-Null
        }
        catch {
            Write-ErrorLog "Failed to create intake directory: $IntakeDir"
            exit 2
        }
    }

    try {
        $acl = Get-Acl -Path $IntakeDir
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $adminsRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
        )
        $acl.SetAccessRule($rule)
        $acl.SetAccessRule($adminsRule)
        $acl.SetAccessRuleProtection($true, $false)
        Set-Acl -Path $IntakeDir -AclObject $acl -ErrorAction Stop
    }
    catch {
        Write-ErrorLog "Failed to set permissions on intake directory: $($_.Exception.Message)"
        exit 1
    }

    Write-InfoLog "Directory ready: $IntakeDir"
    Write-IntakeRecord

    Write-InfoLog "Environment intake completed successfully"
    exit 0
}

Main
