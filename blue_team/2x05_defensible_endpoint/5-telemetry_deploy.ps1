# Name: 5-telemetry_deploy.ps1
# Purpose: Deploy telemetry (Sysmon + Script Block Logging), run controlled test sequences, verify coverage, and export evidence.
# Author: Stephen Reilly
# Exit Codes: 0=Success, 1=Control Failure (verification failed), 2=Environment Error (missing deps/files)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Configuration ---
$LogDir = "capstone\telemetry"
$WindowsEventsJson = Join-Path $PWD "$LogDir\windows_events.json"
$WindowsCoverageJson = Join-Path $PWD "$LogDir\windows_coverage.json"
$TestUser = "TestAuditUser"
$ScheduledTaskName = "MedDefenseTestTask"
$TestServiceName = "BITS"  # Background Intelligent Transfer Service (safe to control)

# Coverage tracking hashtable
$coverageStatus = @{
    "user_creation"      = "pending"
    "scheduled_task"     = "pending"
    "service_start_stop" = "pending"
    "powershell_command" = "pending"
}

# --- Logging Helper ---
function Write-LogStep {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[INFO] $timestamp - $Message"
}

function Write-FailExit {
    param([string]$Message)
    Write-LogStep "FAILURE: $Message"
    exit 1
}

function Write-EnvError {
    param([string]$Message)
    Write-LogStep "ENVIRONMENT ERROR: $Message"
    exit 2
}

# --- Pre-flight Checks ---
Write-LogStep "Checking environment dependencies..."

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-EnvError "This script must be run as Administrator."
}

# Check if Sysmon exists
$sysmonPath = "$env:SystemRoot\Sysmon.exe"
if (-not (Test-Path $sysmonPath)) {
    Write-EnvError "Sysmon not found at $sysmonPath"
}

# Ensure Log Directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# --- Deployment Phase ---
Write-LogStep "Verifying Sysmon installation and configuration..."

# Check Sysmon status and running
$sysmonService = Get-Service -Name "sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonService) {
    Write-FailExit "Sysmon service not found. Is Sysmon installed?"
}

if ($sysmonService.Status -ne 'Running') {
    Write-FailExit "Sysmon service is not running."
}

Write-LogStep "Sysmon is installed and running."

# Verify MedDefense configuration exists (check for sysmonconfig.xml or similar)
$sysmonConfigPath = Join-Path (Split-Path $sysmonPath -Parent) "sysmonconfig.xml"
if (Test-Path $sysmonConfigPath) {
    Write-LogStep "Sysmon configuration found at $sysmonConfigPath."
} else {
    Write-LogStep "Warning: Sysmon configuration file not found, but Sysmon is operational."
}

# --- Script Block Logging Verification ---
Write-LogStep "Verifying Script Block Logging is enabled..."

$scriptBlockRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
try {
    if (-not (Test-Path $scriptBlockRegistryPath)) {
        Write-FailExit "Script Block Logging registry path not found. Enable via Group Policy or registry first."
    }

    $enableScriptBlockLogging = Get-ItemProperty -Path $scriptBlockRegistryPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($null -eq $enableScriptBlockLogging -or $enableScriptBlockLogging.EnableScriptBlockLogging -ne 1) {
        Write-FailExit "Script Block Logging is not enabled (registry value not set to 1)."
    }

    Write-LogStep "Script Block Logging is active."
} catch {
    Write-FailExit "Failed to verify Script Block Logging registry settings: $_"
}

# --- Controlled Test Sequence ---
Write-LogStep "Starting controlled test sequence..."

# Record start time for event window
$testStartTime = Get-Date

# 1. Create Local User
Write-LogStep "Test 1: Creating local user '$TestUser'..."
try {
    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
        Write-LogStep "User '$TestUser' already exists, skipping creation (idempotent)."
    } else {
        New-LocalUser -Name $TestUser -Password (ConvertTo-SecureString "TempPass123!" -AsPlainText -Force) -AccountNeverExpires
    }
    Start-Sleep -Seconds 2
    $coverageStatus["user_creation"] = "pending"
} catch {
    Write-LogStep "Warning: Failed to create user: $_"
}

# 2. Create Scheduled Task
Write-LogStep "Test 2: Creating scheduled task '$ScheduledTaskName'..."
try {
    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo MedDefense test task"
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable
    Register-ScheduledTask -TaskName $ScheduledTaskName -Action $action -Principal $principal -Trigger $trigger -Settings $settings -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $coverageStatus["scheduled_task"] = "pending"
} catch {
    Write-LogStep "Warning: Failed to create scheduled task: $_"
}

# 3. Start and Stop Service
Write-LogStep "Test 3: Starting and stopping service '$TestServiceName'..."
try {
    $service = Get-Service -Name $TestServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-LogStep "Service '$TestServiceName' not found, using 'Spooler' as fallback."
        $testServiceName = "Spooler"
        $service = Get-Service -Name $testServiceName -ErrorAction SilentlyContinue
    }
    if ($null -eq $service) {
        Write-LogStep "Warning: Neither BITS nor Spooler service found. Skipping service test."
    } else {
        Start-Service -Name $testServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Stop-Service -Name $testServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $coverageStatus["service_start_stop"] = "pending"
    }
} catch {
    Write-LogStep "Warning: Failed to manage service: $_"
}

# 4. Run PowerShell Command (for Script Block Logging)
Write-LogStep "Test 4: Running authorized PowerShell command..."
try {
    Invoke-Expression "Get-Process -Name powershell | Select-Object -First 1" | Out-Null
    Write-Output "MedDefense test PowerShell command executed successfully" | Out-Null
    Start-Sleep -Seconds 2
    $coverageStatus["powershell_command"] = "pending"
} catch {
    Write-LogStep "Warning: Failed to execute PowerShell command: $_"
}

# --- Verification Phase ---
Write-LogStep "Verifying telemetry coverage..."

$verificationFailed = $false

function Test-EventExists {
    param(
        [string]$Channel,
        [string]$FilterXPath,
        [string]$ActionName,
        [TimeSpan]$LookbackMinutes = (New-TimeSpan -Minutes 10)
    )

    $startTime = (Get-Date).Add(-$lookbackMinutes)
    try {
        $events = Get-WinEvent -ListLog $Channel -MaxEvents 100 -ErrorAction SilentlyContinue |
            Where-Object { $_.TimeCreated -ge $startTime } |
            Where-Object { $filterXPath -match '.*' }  # XPath filtering via Get-WinEvent -FilterXPath

        # Alternative: Use Get-WinEvent with FilterXPath directly
        $filteredEvents = Get-WinEvent -FilterHashtable @{
            LogName = $channel
            StartTime = $startTime
        } -ErrorAction SilentlyContinue |
            Where-Object {
                $eventXml = [xml]$_.ToXml()
                $eventXml.Event.Data.Name -contains $expectedDataField 2>&1 | Out-Null
                $true
            }

        # Simpler approach: just check if any events exist in timeframe
        $eventCount = (Get-WinEvent -FilterHashtable @{
            LogName = $channel
            StartTime = $startTime
        } -ErrorAction SilentlyContinue | Measure-Object).Count

        if ($eventCount -gt 0) {
            Write-LogStep "PASS: Found $eventCount records in channel '$channel' for $actionName."
            $true
        } else {
            Write-LogStep "FAIL: No records found in channel '$channel' for $actionName."
            $false
        }
    } catch {
        Write-LogStep "FAIL: Error querying event channel '$channel': $_"
        $false
    }
}

# More reliable event verification per action

# 1. Verify User Creation (Security Event ID 4720)
Write-LogStep "Verifying user creation event..."
try {
    $userEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4720
        StartTime = $testStartTime.AddMinutes(-1)
    } -ErrorAction SilentlyContinue
    if ($userEvents.Count -gt 0) {
        Write-LogStep "PASS: Found $($userEvents.Count) user creation events."
        $coverageStatus["user_creation"] = "verified"
    } else {
        Write-LogStep "FAIL: No user creation events (Event ID 4720) found."
        $coverageStatus["user_creation"] = "failed"
        $verificationFailed = $true
    }
} catch {
    Write-LogStep "FAIL: Error checking user creation events: $_"
    $coverageStatus["user_creation"] = "failed"
    $verificationFailed = $true
}

# 2. Verify Scheduled Task (Sysmon Event ID 12 or Task Scheduler logs)
Write-LogStep "Verifying scheduled task event..."
try {
    # Check Sysmon for process creation that created the task
    $taskEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 1  # Process Creation
        StartTime = $testStartTime.AddMinutes(-1)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -like "*schtasks*" -or $_.Message -like "*$ScheduledTaskName*"
    }
    if ($taskEvents.Count -gt 0) {
        Write-LogStep "PASS: Found $($taskEvents.Count) scheduled task related events."
        $coverageStatus["scheduled_task"] = "verified"
    } else {
        # Fallback: Check Task Scheduler operational log
        $taskSchedulerEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-TaskScheduler/Operational'
            StartTime = $testStartTime.AddMinutes(-1)
        } -ErrorAction SilentlyContinue
        if ($taskSchedulerEvents.Count -gt 0) {
            Write-LogStep "PASS: Found $($taskSchedulerEvents.Count) Task Scheduler events (fallback)."
            $coverageStatus["scheduled_task"] = "verified"
        } else {
            Write-LogStep "FAIL: No scheduled task events found."
            $coverageStatus["scheduled_task"] = "failed"
            $verificationFailed = $true
        }
    }
} catch {
    Write-LogStep "FAIL: Error checking scheduled task events: $_"
    $coverageStatus["scheduled_task"] = "failed"
    $verificationFailed = $true
}

# 3. Verify Service Start/Stop (System Event IDs 7036)
Write-LogStep "Verifying service start/stop events..."
try {
    $serviceEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Id = 7036  # Service state change
        StartTime = $testStartTime.AddMinutes(-1)
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Message -like "*$testServiceName*"
    }
    if ($serviceEvents.Count -gt 0) {
        Write-LogStep "PASS: Found $($serviceEvents.Count) service state change events."
        $coverageStatus["service_start_stop"] = "verified"
    } else {
        Write-LogStep "FAIL: No service state change events found."
        $coverageStatus["service_start_stop"] = "failed"
        $verificationFailed = $true
    }
} catch {
    Write-LogStep "FAIL: Error checking service events: $_"
    $coverageStatus["service_start_stop"] = "failed"
    $verificationFailed = $true
}

# 4. Verify PowerShell Script Block Logging
Write-LogStep "Verifying PowerShell script block logging events..."
try {
    $powerShellEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id = 4104  # Script Block Execution
        StartTime = $testStartTime.AddMinutes(-1)
    } -ErrorAction SilentlyContinue
    if ($powerShellEvents.Count -gt 0) {
        Write-LogStep "PASS: Found $($powerShellEvents.Count) PowerShell script block events."
        $coverageStatus["powershell_command"] = "verified"
    } else {
        Write-LogStep "FAIL: No PowerShell script block events found."
        $coverageStatus["powershell_command"] = "failed"
        $verificationFailed = $true
    }
} catch {
    Write-LogStep "FAIL: Error checking PowerShell events: $_"
    $coverageStatus["powershell_command"] = "failed"
    $verificationFailed = $true
}

# --- Evidence Export ---
Write-LogStep "Exporting structured JSON evidence..."

# Build windows_events.json
$allEvents = @()

# Collect Sysmon Operational events from last 30 minutes
try {
    $sysmonEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        StartTime = (Get-Date).AddMinutes(-30)
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | ForEach-Object {
        [PSCustomObject]@{
            timestamp       = $_.TimeCreated.ToString("o")
            event_source    = "Sysmon"
            event_id        = $_.Id
            raw_message     = $_.Message.Substring(0, [Math]::Min(2000, $_.Message.Length))
        }
    }
    $allEvents += $sysmonEvents
} catch {
    Write-LogStep "Warning: Could not collect Sysmon events: $_"
}

# Collect PowerShell Operational events from last 30 minutes
try {
    $powerShellEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        StartTime = (Get-Date).AddMinutes(-30)
    } -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | ForEach-Object {
        [PSCustomObject]@{
            timestamp       = $_.TimeCreated.ToString("o")
            event_source    = "PowerShell"
            event_id        = $_.Id
            raw_message     = $_.Message.Substring(0, [Math]::Min(2000, $_.Message.Length))
        }
    }
    $allEvents += $powerShellEvents
} catch {
    Write-LogStep "Warning: Could not collect PowerShell events: $_"
}

# Export as JSON
try {
    $allEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $WindowsEventsJson -Encoding UTF8 -NoNewline
    Write-LogStep "Windows events exported to: $WindowsEventsJson"
} catch {
    Write-LogStep "Warning: Failed to export windows_events.json: $_"
}

# Build windows_coverage.json
$coverageObject = [PSCustomObject]@{
    timestamp       = (Get-Date).ToString("o")
    host            = $env:COMPUTERNAME
    source          = "Sysmon+PowerShell"
    test_actions    = $coverageStatus.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{
            action = $_.Key
            status = $_.Value
        }
    }
    overall_result  = if ($verificationFailed) { "FAIL" } else { "PASS" }
}

try {
    $coverageObject | ConvertTo-Json | Out-File -FilePath $WindowsCoverageJson -Encoding UTF8 -NoNewline
    Write-LogStep "Windows coverage exported to: $WindowsCoverageJson"
} catch {
    Write-LogStep "Warning: Failed to export windows_coverage.json: $_"
}

# --- Final Result ---
if ($verificationFailed) {
    Write-LogStep "Verification failed. Some test actions did not produce expected traces."
    Write-LogStep "Coverage report exported to: $WindowsCoverageJson"
    exit 1
} else {
    Write-LogStep "Telemetry deployment and verification successful."
    Write-LogStep "Evidence exported to: $WindowsEventsJson"
    Write-LogStep "Coverage report exported to: $WindowsCoverageJson"
    exit 0
}
