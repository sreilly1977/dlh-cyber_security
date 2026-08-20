<#
.SYNOPSIS
    Runs the CIS Level 1 audit helper and persists the baseline score.
.DESCRIPTION
    Capstone task T1 - Defensible Endpoint Package
    Runs capstone\win_audit.ps1, captures full output to
    capstone\baseline\windows_baseline.log, and emits
    capstone\baseline\baseline_windows.json with the pass rate.
.NOTES
    Name: 1-baseline_snapshot.ps1
    Purpose: Run CIS Level 1 baseline audit and persist raw output + pass rate
             Capstone task T1 - Defensible Endpoint Package
    Author: Steve - Cybersecurity Engineer
    Date: 20 August 2026
    Exit Codes: 0=success, 1=controlled failure, 2=environment error
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptName = "1-baseline_snapshot.ps1"
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$CapstoneDir = Join-Path $ScriptDir "capstone"
$BaselineDir = Join-Path $CapstoneDir "baseline"
$AuditScript = Join-Path $CapstoneDir "win_audit.ps1"
$LogFile = Join-Path $BaselineDir "windows_baseline.log"
$JsonFile = Join-Path $BaselineDir "baseline_windows.json"

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

function Validate-Environment {
    Write-InfoLog "Validating execution environment..."

    if (-not (Test-Administrator)) {
        Write-ErrorLog "This script requires administrator privileges"
        exit 2
    }

    if (-not (Test-Path $AuditScript)) {
        Write-ErrorLog "Audit helper not found: $AuditScript"
        exit 2
    }

    Write-InfoLog "Environment validation complete"
}

function Ensure-Directories {
    Write-InfoLog "Creating baseline directory structure..."

    if (-not (Test-Path $BaselineDir)) {
        try {
            New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null
        }
        catch {
            Write-ErrorLog "Failed to create baseline directory: $BaselineDir"
            exit 2
        }
    }

    Write-InfoLog "Directory ready: $BaselineDir"
}

function Run-BaselineAudit {
    Write-InfoLog "Running win_audit.ps1 (CIS Level 1 controls)..."

    try {
        $auditOutput = & powershell.exe -ExecutionPolicy Bypass -File $AuditScript 2>&1
    }
    catch {
        Write-ErrorLog "Failed to execute win_audit.ps1: $($_.Exception.Message)"
        exit 1
    }

    if (-not $auditOutput) {
        Write-ErrorLog "win_audit.ps1 produced no output"
        exit 1
    }

    try {
        $auditOutput | Out-File -FilePath $LogFile -Encoding UTF8
    }
    catch {
        Write-ErrorLog "Failed to write log file: $($_.Exception.Message)"
        exit 1
    }

    Write-InfoLog "Raw log persisted: $LogFile"
    return $auditOutput
}

function Write-BaselineRecord {
    param([string[]]$AuditOutput)

    Write-InfoLog "Parsing audit results and writing baseline_windows.json..."

    $hostname = $env:COMPUTERNAME

    $passCount = 0
    $failCount = 0
    $naCount = 0
    $controlsTotal = 0

    foreach ($line in $AuditOutput) {
        $trimmed = $line.ToString().Trim()

        if ($trimmed -match '^===\s*CIS_LEVEL_1_AUDIT') {
            continue
        }

        if ($trimmed -match '^([\d._]+)\s+(PASS|FAIL|NOT_APPLICABLE)$') {
            $controlsTotal++
            $result = $Matches[2]
            switch ($result) {
                "PASS" { $passCount++ }
                "FAIL" { $failCount++ }
                "NOT_APPLICABLE" { $naCount++ }
            }
        }
    }

    if ($controlsTotal -eq 0) {
        Write-ErrorLog "No control results found in audit output"
        exit 1
    }

    $applicableTotal = $passCount + $failCount
    if ($applicableTotal -gt 0) {
        $passRate = [math]::Round(($passCount / $applicableTotal) * 100, 1)
    }
    else {
        $passRate = 0.0
    }

    $record = [PSCustomObject]@{
        timestamp           = $Timestamp
        hostname            = $hostname
        controls_total      = $controlsTotal
        pass_count          = $passCount
        fail_count          = $failCount
        na_count            = $naCount
        pass_rate_percent   = $passRate
        log_path            = $LogFile
    }

    try {
        $json = $record | ConvertTo-Json -Depth 5
        $json | Out-File -FilePath $JsonFile -Encoding UTF8
    }
    catch {
        Write-ErrorLog "Failed to write JSON file: $($_.Exception.Message)"
        exit 1
    }

    $hash = (Get-FileHash -Path $JsonFile -Algorithm SHA256).Hash
    Write-InfoLog "Baseline record written: $JsonFile"
    Write-InfoLog "Controls: $controlsTotal total, $passCount pass, $failCount fail, $naCount N/A"
    Write-InfoLog "Pass rate: $passRate% (of applicable controls)"
    Write-InfoLog "Record hash: $hash"
}

function Main {
    Write-InfoLog "Starting capstone baseline snapshot for Hawthorne Windows endpoint..."
    Write-InfoLog "Timestamp: $Timestamp"

    Validate-Environment
    Ensure-Directories

    $auditOutput = Run-BaselineAudit
    Write-BaselineRecord -AuditOutput $auditOutput

    Write-InfoLog "Capstone baseline snapshot completed successfully"
    exit 0
}

Main
