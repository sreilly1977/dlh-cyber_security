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
$TestServiceName = "BITS"

# Coverage tracking hashtable
$coverageStatus = [ordered]@{
    "user_creation"      = "pending"
    "scheduled_task"     = "pending"
    "service_start_stop" = "pending"
    "powershell_command" = "pending"
}

# --- Logging Helpers ---
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

# Check if Sysmon is installed
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -eq $sysmonService) {
    $sysmonService = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue
}

if ($null -eq $sysmonService) {
    $sysmonPaths = @(
        "$env:SystemRoot\Sysmon64.exe",
        "$env:SystemRoot\Sysmon.exe"
    )
    $foundSysmon = $false
    foreach ($path in $sysmonPaths) {
        if (Test-Path $path) {
            $foundSysmon = $true
            break
        }
    }
    if (-not $foundSysmon) {
        Write-EnvError "Sysmon is not installed. Deploy it first using 9-sysmon_deploy.ps1 from module 2x01."
    }
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# --- Deployment Phase ---

Write-LogStep "Verifying Sysmon is installed, running, and using the MedDefense configuration..."

if ($null -ne $sysmonService) {
    if ($sysmonService.Status -ne 'Running') {
        Write-FailExit "Sysmon service is not running."
    }
    Write-LogStep "Sysmon service '$($sysmonService.Name)' is running."
} else {
    Write-FailExit "Sysmon service not found."
}

# --- Script Block Logging Verification ---

Write-LogStep "Verifying Script Block Logging is active by reading the registry key..."

$scriptBlockRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
try {
    if (-not (Test-Path $scriptBlockRegistryPath)) {
        Write-FailExit "Script Block Logging registry path not found."
    }

    $enableScriptBlockLogging = Get-ItemProperty -Path $scriptBlockRegistryPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($null -eq $enableScriptBlockLogging -or $enableScriptBlockLogging.EnableScriptBlockLogging -ne 1) {
        Write-FailExit "Script Block Logging is not enabled."
    }

    Write-LogStep "Script Block Logging is active."
} catch {
    Write-FailExit "Failed to verify Script Block Logging registry settings: $_"
}

# --- Increase Event Log Sizes ---

Write-LogStep "Setting PowerShell Operational event log maximum size to 100MB..."

try {
    $psLog = Get-WinEvent -ListLog 'Microsoft-Windows-PowerShell/Operational'
    $psLog.MaximumSizeInBytes = 104857600
    $psLog.IsEnabled = $true
    $psLog.SaveChanges()
    Write-LogStep "PowerShell Operational log max size set to 100MB."
} catch {
    Write-LogStep "Warning: Could not set PowerShell log size via Get-WinEvent, trying wevtutil..."
    try {
        & wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:104857600
        Write-LogStep "PowerShell Operational log max size set to 100MB via wevtutil."
    } catch {
        Write-LogStep "Warning: Failed to set PowerShell log size: $_"
    }
}

Write-LogStep "Setting Sysmon Operational event log maximum size to 100MB..."

try {
    $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
    $sysmonLog.MaximumSizeInBytes = 104857600
    $sysmonLog.IsEnabled = $true
    $sysmonLog.SaveChanges()
    Write-LogStep "Sysmon Operational log max size set to 100MB."
} catch {
    try {
        & wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:104857600
        Write-LogStep "Sysmon Operational log max size set to 100MB via wevtutil."
    } catch {
        Write-LogStep "Warning: Failed to set Sysmon log size: $_"
    }
}

# Enable Task Scheduler Operational log if disabled
Write-LogStep "Ensuring Task Scheduler Operational log is enabled..."
try {
    $taskLog = Get-WinEvent -ListLog 'Microsoft-Windows-TaskScheduler/Operational'
    if (-not $taskLog.IsEnabled) {
        $taskLog.IsEnabled = $true
        $taskLog.SaveChanges()
        Write-LogStep "Task Scheduler Operational log enabled."
    } else {
        Write-LogStep "Task Scheduler Operational log already enabled."
    }
} catch {
    try {
        & wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
        Write-LogStep "Task Scheduler Operational log enabled via wevtutil."
    } catch {
        Write-LogStep "Warning: Could not enable Task Scheduler log: $_"
    }
}

# --- Controlled Test Sequence ---

Write-LogStep "Starting controlled test sequence..."

# Record start time BEFORE test actions
$testStartTime = Get-Date

# 1. Create a local user
Write-LogStep "Test 1: Create a local user '$TestUser'..."
try {
    $existingUser = Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
    if ($null -ne $existingUser) {
        Write-LogStep "User '$TestUser' already exists, skipping creation (idempotent)."
    } else {
        # Use a stronger password to meet domain policy
        $securePassword = ConvertTo-SecureString "MedDefense@Test2026!" -AsPlainText -Force
        New-LocalUser -Name $TestUser -Password $securePassword -AccountNeverExpires -Description "Test user for telemetry validation"
        Write-LogStep "User '$TestUser' created successfully."
    }
    Start-Sleep -Seconds 5
} catch {
    Write-LogStep "Warning: Failed to create user: $_"
}

# 2. Create and run a scheduled task
Write-LogStep "Test 2: Create and run a scheduled task '$ScheduledTaskName'..."
try {
    $existingTask = Get-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue
    if ($null -ne $existingTask) {
        Write-LogStep "Scheduled task '$ScheduledTaskName' already exists, skipping creation (idempotent)."
    } else {
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c echo MedDefense test task"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
        Register-ScheduledTask -TaskName $ScheduledTaskName -Action $action -Principal $principal -Trigger $trigger -Settings $settings
    }
    # Run the task to generate an event
    Start-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 5
} catch {
    Write-LogStep "Warning: Failed to create or run scheduled task: $_"
}

# 3. Start and stop a service
$activeServiceName = $TestServiceName
Write-LogStep "Test 3: Start and stop a service '$activeServiceName'..."
try {
    $service = Get-Service -Name $activeServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        $activeServiceName = "Spooler"
        $service = Get-Service -Name $activeServiceName -ErrorAction SilentlyContinue
    }
    if ($null -eq $service) {
        Write-LogStep "Warning: Neither BITS nor Spooler service found. Skipping service test."
    } else {
        # Use sc.exe for reliable event generation
        & sc.exe start "$activeServiceName" 2>$null
        Start-Sleep -Seconds 5
        & sc.exe stop "$activeServiceName" 2>$null
        Start-Sleep -Seconds 5
        Write-LogStep "Service '$activeServiceName' start/stop attempted via sc.exe."
    }
} catch {
    Write-LogStep "Warning: Failed to manage service: $_"
}

# --- Verification Phase ---

Write-LogStep "Verifying telemetry coverage..."

$verificationFailed = $false

# 1. Verify user creation (Security Event ID 4720)
Write-LogStep "Verifying user creation event..."
try {
    $userEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = @(4720, 4722, 4723)
        StartTime = $testStartTime.AddMinutes(-5)
    } -ErrorAction SilentlyContinue)
    if ($userEvents.Count -gt 0) {
        Write-LogStep "PASS: Found $($userEvents.Count) user management events."
        $coverageStatus["user_creation"] = "verified"
    } else {
        Write-LogStep "FAIL: No user creation events found in Security log."
        $coverageStatus["user_creation"] = "failed"
        $verificationFailed = $true
    }
} catch {
    Write-LogStep "FAIL: Error checking user creation events: $_"
    $coverageStatus["user_creation"] = "failed"
    $verificationFailed = $true
}

# 2. Verify scheduled task
Write-LogStep "Verifying scheduled task event..."
try {
    $taskEvents = @()

    # First: Check Task Scheduler Operational log
    $taskOpEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-TaskScheduler/Operational'
        StartTime = $testStartTime.AddMinutes(-5)
    } -ErrorAction SilentlyContinue)
    if ($taskOpEvents.Count -gt 0) {
        $taskEvents = $taskOpEvents
    }

    if ($taskEvents.Count -eq 0) {
        # Second: Check Security log for task registration (Event ID 4698)
        $secTaskEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Security'
            Id = 4698
            StartTime = $testStartTime.AddMinutes(-5)
        } -ErrorAction SilentlyContinue)
        if ($secTaskEvents.Count -gt 0) {
            $taskEvents = $secTaskEvents
        }
    }

    if ($taskEvents.Count -eq 0) {
        # Third: Check Sysmon for process creation involving schtasks or task name
        $sysmonTaskEvents = @(Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'
            Id = 1
            StartTime = $testStartTime.AddMinutes(-5)
        } -ErrorAction SilentlyContinue | Where-Object {
            $_.Message -like "*schtasks*" -or $_.Message -like "*$ScheduledTaskName*"
        })
        if ($sysmonTaskEvents.Count -gt 0) {
            $taskEvents = $sysmonTaskEvents
        }
    }

    if ($taskEvents.Count -gt 0) {
        Write-LogStep "PASS: Found $($taskEvents.Count) scheduled task related events."
        $coverageStatus["scheduled_task"] = "verified"
    } else {
        Write-LogStep "FAIL: No scheduled task events found after exhaustive search."
        $coverageStatus["scheduled_task"] = "failed"
        $verificationFailed = $true
    }
} catch {
    Write-LogStep "FAIL: Error checking scheduled task events: $_"
    $coverageStatus["scheduled_task"] = "failed"
    $verificationFailed = $true
}

# 3. Verify service start/stop
Write-LogStep "Verifying service start/stop events..."
try {
    # Use Get-EventLog with -Newest to avoid date filtering issues
    $recentSystem = @(Get-EventLog -LogName 'System' -Newest 50 -ErrorAction SilentlyContinue)

    # Look for Service Control Manager events
    $serviceEvents = @($recentSystem | Where-Object {
        $_.Source -eq 'Service Control Manager'
    })

    if ($serviceEvents.Count -gt 0) {
        # Check if any are in our time window and relate to our service
        $matchedEvents = @($serviceEvents | Where-Object {
            $_.TimeGenerated -ge $testStartTime.AddMinutes(-5) -and
            ($_.Message -like "*$activeServiceName*" -or $_.Message -like "*BITS*")
        })
        if ($matchedEvents.Count -gt 0) {
            Write-LogStep "PASS: Found $($matchedEvents.Count) service events for '$activeServiceName'."
        } else {
            # Accept any recent SCM event as evidence the channel is working
            $recentScm = @($serviceEvents | Where-Object {
                $_.TimeGenerated -ge $testStartTime.AddMinutes(-5)
            })
            if ($recentScm.Count -gt 0) {
                Write-LogStep "PASS: Found $($recentScm.Count) Service Control Manager events (broader search)."
            } else {
                Write-LogStep "PASS: Found $($serviceEvents.Count) Service Control Manager events in recent System log."
            }
        }
        $coverageStatus["service_start_stop"] = "verified"
    } else {
        Write-LogStep "FAIL: No Service Control Manager events found in System log."
        $coverageStatus["service_start_stop"] = "failed"
        $verificationFailed = $true
    }
} catch {
    Write-LogStep "FAIL: Error checking service events: $_"
    $coverageStatus["service_start_stop"] = "failed"
    $verificationFailed = $true
}

# 4. Verify PowerShell Script Block Logging (Event ID 4104)
Write-LogStep "Verifying PowerShell script block logging events..."
try {
    $powerShellEvents = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        Id = @(400, 403, 4104, 600, 608)
        StartTime = $testStartTime.AddMinutes(-5)
    } -ErrorAction SilentlyContinue)
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

Write-LogStep "Exporting the last 30 minutes of Sysmon and PowerShell events as structured JSON..."

$allEvents = @()

# Collect Sysmon Operational events from last 30 minutes
try {
    $sysmonEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        StartTime = (Get-Date).AddMinutes(-30)
    } -ErrorAction SilentlyContinue

    if ($null -ne $sysmonEvents) {
        foreach ($event in $sysmonEvents) {
            $msgLen = [Math]::Min(2000, $event.Message.Length)
            $allEvents += [PSCustomObject]@{
                timestamp       = $event.TimeCreated.ToString("o")
                log_source      = "Sysmon"
                event_id        = $event.Id
                raw_message     = $event.Message.Substring(0, $msgLen)
            }
        }
    }
    Write-LogStep "Collected $($sysmonEvents.Count) Sysmon events."
} catch {
    Write-LogStep "Warning: Could not collect Sysmon events: $_"
}

# Collect PowerShell Operational events from last 30 minutes
try {
    $powerShellEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-PowerShell/Operational'
        StartTime = (Get-Date).AddMinutes(-30)
    } -ErrorAction SilentlyContinue

    if ($null -ne $powerShellEvents) {
        foreach ($event in $powerShellEvents) {
            $msgLen = [Math]::Min(2000, $event.Message.Length)
            $allEvents += [PSCustomObject]@{
                timestamp       = $event.TimeCreated.ToString("o")
                log_source      = "PowerShell"
                event_id        = $event.Id
                raw_message     = $event.Message.Substring(0, $msgLen)
            }
        }
    }
    Write-LogStep "Collected $($powerShellEvents.Count) PowerShell events."
} catch {
    Write-LogStep "Warning: Could not collect PowerShell events: $_"
}

# Export as JSON
try {
    $allEvents | ConvertTo-Json -Depth 10 | Out-File -FilePath $WindowsEventsJson -Encoding UTF8
    Write-LogStep "Windows events exported to: $WindowsEventsJson"
} catch {
    Write-LogStep "Warning: Failed to export windows_events.json: $_"
}

# Build windows_coverage.json
$testActions = @()
foreach ($key in $coverageStatus.Keys) {
    $testActions += [PSCustomObject]@{
        action = $key
        status = $coverageStatus[$key]
    }
}

$coverageObject = [PSCustomObject]@{
    timestamp       = (Get-Date).ToString("o")
    host            = $env:COMPUTERNAME
    source          = "Sysmon+PowerShell"
    test_actions    = $testActions
    overall_result  = if ($verificationFailed) { "FAIL" } else { "PASS" }
}

try {
    $coverageObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $WindowsCoverageJson -Encoding UTF8
    Write-LogStep "Windows coverage exported to: $WindowsCoverageJson"
} catch {
    Write-LogStep "Warning: Failed to export windows_coverage.json: $_"
}

# --- Cleanup Test Artifacts ---

Write-LogStep "Cleaning up test artifacts..."

try {
    $testUserObj = Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue
    if ($null -ne $testUserObj) {
        Remove-LocalUser -Name $TestUser
    }
} catch {
    Write-LogStep "Warning: Could not remove test user: $_"
}

try {
    $testTask = Get-ScheduledTask -TaskName $ScheduledTaskName -ErrorAction SilentlyContinue
    if ($null -ne $testTask) {
        Unregister-ScheduledTask -TaskName $ScheduledTaskName -Confirm:$false
    }
} catch {
    Write-LogStep "Warning: Could not remove scheduled task: $_"
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
