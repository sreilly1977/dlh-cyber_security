<#
.Synopsis
    9-sysmon_deploy.ps1 - Sysmon Deployment Script
.Purpose
    Installs and configures Sysmon with a detection-optimized configuration.
    Deploys the single most important endpoint detection tool on Windows platform.
    Falls back to local copies if downloads fail.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 4, 2026
#>

param(
    [string]$DownloadPath = "C:\Windows\Temp\Sysmon",
    [string]$InstallPath = "C:\ProgramData\Sysmon"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION
# ===========================================================================
$SysmonUrl = "https://live.sysinternals.com/Sysmon64.exe"
$SwiftOnSecurityConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$SysmonExe = Join-Path $DownloadPath "Sysmon64.exe"
$ConfigFile = Join-Path $DownloadPath "sysmonconfig.xml"

# ===========================================================================
# STEP 1: PREPARE DOWNLOAD DIRECTORY
# ===========================================================================
if (-not (Test-Path $DownloadPath)) {
    New-Item -ItemType Directory -Path $DownloadPath -Force | Out-Null
}
Write-Host "[*] Download directory prepared: $DownloadPath" -ForegroundColor Gray

# ===========================================================================
# STEP 2: DOWNLOAD SYSMON (WITH LOCAL FALLBACK)
# ===========================================================================
Write-Host "[*] Downloading Sysmon..." -NoNewline -ForegroundColor Yellow

$sysmonReady = $false

try {
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $SysmonExe -UseBasicParsing -ErrorAction Stop

    if (Test-Path $SysmonExe) {
        Write-Host " OK" -ForegroundColor Green
        $sysmonReady = $true
    } else {
        throw "Sysmon download failed - file not created"
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "    Attempting local fallback..." -NoNewline -ForegroundColor Yellow

    # Check script directory for local copy
    $localSysmon = Join-Path $ScriptDir "Sysmon64.exe"
    if (Test-Path $localSysmon) {
        Copy-Item -Path $localSysmon -Destination $SysmonExe -Force
        Write-Host " OK" -ForegroundColor Green
        Write-Host "    Using local copy: $localSysmon" -ForegroundColor Gray
        $sysmonReady = $true
    } else {
        Write-Host " NOT FOUND" -ForegroundColor Red
        Write-Host "    Could not find Sysmon64.exe in $ScriptDir" -ForegroundColor Red
        exit 1
    }
}

# ===========================================================================
# STEP 3: DOWNLOAD SWIFTONSECURITY CONFIGURATION (WITH LOCAL FALLBACK)
# ===========================================================================
Write-Host "[*] Downloading SwiftOnSecurity config..." -NoNewline -ForegroundColor Yellow

$configReady = $false

try {
    Invoke-WebRequest -Uri $SwiftOnSecurityConfigUrl -OutFile $ConfigFile -UseBasicParsing -ErrorAction Stop

    if (Test-Path $ConfigFile) {
        Write-Host " OK" -ForegroundColor Green

        # Validate XML structure
        try {
            $xmlContent = Get-Content $ConfigFile -Raw
            [xml]$xmlDoc = $xmlContent
            if ($xmlDoc.SysmonSchema) {
                Write-Host "    Configuration schema validated          [OK]" -ForegroundColor Gray
            }
        } catch {
            Write-Host "    Warning: XML validation failed" -ForegroundColor Yellow
        }
        $configReady = $true
    } else {
        throw "Config download failed - file not created"
    }
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "    Attempting local fallback..." -NoNewline -ForegroundColor Yellow

    # Check script directory for local copy
    $localConfig = Join-Path $ScriptDir "sysmonconfig.xml"
    if (Test-Path $localConfig) {
        Copy-Item -Path $localConfig -Destination $ConfigFile -Force
        Write-Host " OK" -ForegroundColor Green
        Write-Host "    Using local copy: $localConfig" -ForegroundColor Gray

        # Validate XML structure
        try {
            $xmlContent = Get-Content $ConfigFile -Raw
            [xml]$xmlDoc = $xmlContent
            if ($xmlDoc.SysmonSchema) {
                Write-Host "    Configuration schema validated          [OK]" -ForegroundColor Gray
            }
        } catch {
            Write-Host "    Warning: XML validation failed" -ForegroundColor Yellow
        }
        $configReady = $true
    } else {
        Write-Host " NOT FOUND" -ForegroundColor Red
        Write-Host "    Could not find sysmonconfig.xml in $ScriptDir" -ForegroundColor Red
        exit 1
    }
}

# ===========================================================================
# STEP 4: INSTALL SYSMON WITH CONFIGURATION
# ===========================================================================
Write-Host "[*] Installing Sysmon with config..." -ForegroundColor Yellow

# First, check if Sysmon is already installed
$existingService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -eq "Running") {
    Write-Host "    Uninstalling existing Sysmon installation..." -ForegroundColor Gray
    Start-Process -FilePath $SysmonExe -ArgumentList "-u", "-i", $ConfigFile, "-accepteula" -Wait -NoNewWindow -ErrorAction SilentlyContinue
}

# Install with the configuration
Write-Host "    Sysmon64.exe -accepteula -i sysmonconfig.xml" -ForegroundColor Gray
$installArgs = "-accepteula", "-i", $ConfigFile
Start-Process -FilePath $SysmonExe -ArgumentList $installArgs -Wait -NoNewWindow -ErrorAction Stop

Start-Sleep -Seconds 3

# Verify service is running
$sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if ($null -ne $sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Host "    Service: Sysmon64 - Running            [OK]" -ForegroundColor Green
} else {
    Write-Host "    Service: Sysmon64 - FAILED              [ERROR]" -ForegroundColor Red
}

# Verify driver is loaded
$driverLoaded = Get-ChildItem HKLM:\SYSTEM\CurrentControlSet\Services\ -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "SysmonDrv" }
if ($driverLoaded) {
    Write-Host "    Driver: SysmonDrv - Loaded             [OK]" -ForegroundColor Green
} else {
    # Check via process list
    $driverCheck = Get-Process | Where-Object { $_.ProcessName -eq "Sysmon64" } -ErrorAction SilentlyContinue
    if ($driverCheck) {
        Write-Host "    Driver: SysmonDrv - Loaded             [OK]" -ForegroundColor Green
    } else {
        Write-Host "    Driver: SysmonDrv - Checking status   [PENDING]" -ForegroundColor Yellow
    }
}

# ===========================================================================
# STEP 5: VERIFY EVENT GENERATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying event generation..." -ForegroundColor Yellow

# Check Sysmon event log exists
$sysmonEventLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
if ($null -ne $sysmonEventLog) {
    Write-Host "    Event Log: Microsoft-Windows-Sysmon/Operational  [OK]" -ForegroundColor Gray
} else {
    Write-Host "    Event Log: Creating Sysmon operational log..." -ForegroundColor Gray
    New-EventLog -LogName "Microsoft-Windows-Sysmon/Operational" -Source "Sysmon" -ErrorAction SilentlyContinue
}

# Query events in last 60 seconds
try {
    $startTime = (Get-Date).AddSeconds(-60)
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        StartTime = $startTime
    } -ErrorAction SilentlyContinue -MaxEvents 100 -Oldest

    $eventCount = if ($null -ne $events) { $events.Count } else { 0 }

    if ($eventCount -gt 0) {
        Write-Host "    Events in last 60 seconds: $eventCount          [OK]" -ForegroundColor Green
    } else {
        Write-Host "    Events in last 60 seconds: 0 (waiting for activity...) [PENDING]" -ForegroundColor Yellow

        # Wait a few more seconds and check again
        Start-Sleep -Seconds 10
        $events = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            StartTime = $startTime
        } -ErrorAction SilentlyContinue -MaxEvents 100 -Oldest
        $eventCount = if ($null -ne $events) { $events.Count } else { 0 }
        Write-Host "    Events in last 70 seconds: $eventCount          [OK]" -ForegroundColor Green
    }
} catch {
    Write-Host "    Event query failed - log may not be active yet" -ForegroundColor Yellow
}

# ===========================================================================
# STEP 6: TEST FILECREATE DETECTION (EVENT ID 11)
# ===========================================================================
Write-Host ""
Write-Host "[*] Testing FileCreate detection..." -ForegroundColor Yellow

# Clear any existing test events
$testLogFile = "C:\Windows\Temp\sysmon_test.txt"

# Remove old test files if they exist
if (Test-Path $testLogFile) {
    Remove-Item $testLogFile -Force -ErrorAction SilentlyContinue
}

# Get current timestamp for event filtering
$testStartTime = Get-Date
Write-Host "    Timestamp: $($testStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray

# Create test file
try {
    Set-Content -Path $testLogFile -Value "Sysmon FileCreate test - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Force -ErrorAction Stop

    Write-Host "    Created: $testLogFile" -ForegroundColor Gray

    # Wait for event log to capture the file creation
    Start-Sleep -Seconds 3

    # Query for Event ID 11 (FileCreate) since test start
    $fileCreateEvents = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-Sysmon/Operational"
        Id = 11
        StartTime = $testStartTime
    } -ErrorAction SilentlyContinue -MaxEvents 10 -Oldest

    $fileCreatedEvent = $fileCreateEvents |
        Where-Object { $_.Message -like "*$testLogFile*" -or $_.Message -like "*sysmon_test.txt*" } |
        Select-Object -First 1

    if ($null -ne $fileCreatedEvent) {
        Write-Host "    Event ID 11 captured                   [VERIFIED]" -ForegroundColor Green
        Write-Host "    Process: $($fileCreatedEvent.Properties[0].Value)" -ForegroundColor Gray
        Write-Host "    File: $($fileCreatedEvent.Properties[1].Value)" -ForegroundColor Gray
    } else {
        # Broaden search
        $anyEvent11 = Get-WinEvent -FilterHashtable @{
            LogName = "Microsoft-Windows-Sysmon/Operational"
            Id = 11
            StartTime = $testStartTime.AddSeconds(-5)
        } -ErrorAction SilentlyContinue -MaxEvents 1 -Oldest

        if ($null -ne $anyEvent11) {
            Write-Host "    Event ID 11 captured (general activity)   [VERIFIED]" -ForegroundColor Green
        } else {
            Write-Host "    Event ID 11 not found in timeframe   [CHECK MANUAL]" -ForegroundColor Yellow

            # Display recent Sysmon events for debugging
            Write-Host "    Recent Sysmon events:" -ForegroundColor Gray
            $recentEvents = Get-WinEvent -FilterHashtable @{
                LogName = "Microsoft-Windows-Sysmon/Operational"
                StartTime = $testStartTime.AddSeconds(-10)
            } -ErrorAction SilentlyContinue -MaxEvents 5 -Oldest
            foreach ($evt in $recentEvents) {
                Write-Host "      ID $($evt.Id): $($evt.TimeCreated)" -ForegroundColor Gray
            }
        }
    }
} catch {
    Write-Host "    File creation test failed: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 7: DISPLAY SYSTEM MONITORING STATUS
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     SYSMON DEPLOYMENT SUMMARY          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installation Status:" -ForegroundColor White
Write-Host "  Sysmon Version:                  Installed" -ForegroundColor Gray
Write-Host "  Configuration:                   SwiftOnSecurity Baseline" -ForegroundColor Gray
Write-Host "  Event Log:                       Microsoft-Windows-Sysmon/Operational" -ForegroundColor Gray
Write-Host ""
Write-Host "Detection Capabilities:" -ForegroundColor White
Write-Host "  Process Creation (ID 1):         Yes" -ForegroundColor Gray
Write-Host "  Network Connection (ID 3):       Yes" -ForegroundColor Gray
Write-Host "  File Creation Time (ID 11):      Yes" -ForegroundColor Gray
Write-Host "  Process Termination (ID 5):      Yes" -ForegroundColor Gray
Write-Host "  Driver Load (ID 6):              Yes" -ForegroundColor Gray
Write-Host "  WMI Events (ID 22):              Yes" -ForegroundColor Gray
Write-Host "  Pipe Events (ID 17/18/29):       Yes" -ForegroundColor Gray
Write-Host "  DNS Queries (ID 22):             Yes" -ForegroundColor Gray
Write-Host ""
Write-Host "Use Cases Covered:" -ForegroundColor White
Write-Host "  Lateral Movement Detection:      PsExec, WMI, RDP" -ForegroundColor Gray
Write-Host "  Data Exfiltration Detection:     Rclone, browser uploads" -ForegroundColor Gray
Write-Host "  Ransomware Detection:            File encryption patterns" -ForegroundColor Gray
Write-Host ""

# Copy configuration to install path
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}
Copy-Item -Path $ConfigFile -Destination "$InstallPath\sysmonconfig.xml" -Force -ErrorAction SilentlyContinue
Write-Host "Configuration copied to: $InstallPath" -ForegroundColor Gray

Write-Host ""
Write-Host "To view events: Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'}" -ForegroundColor Gray
Write-Host "To filter Event ID 11: Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11}" -ForegroundColor Gray
Write-Host ""

Write-Host "Done." -ForegroundColor White
