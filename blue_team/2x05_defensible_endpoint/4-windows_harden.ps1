<#
.SYNOPSIS
    Orchestrates the full Windows hardening pass and persists execution evidence.
.DESCRIPTION
    Capstone task T4 - Defensible Endpoint Package
    Invokes the composition of 2x01 hardening scripts in deterministic order,
    captures stdout and exit code of each sub-step into capstone\exec\windows_harden.log,
    then re-runs the CIS audit and computes the new pass rate.
    Emits capstone\exec\windows_harden.json with the same schema as the Linux sibling.
.NOTES
    Name: 4-windows_harden.ps1
    Purpose: Orchestrate Windows hardening and persist structured execution evidence
             Capstone task T4 - Defensible Endpoint Package
    Author: Steve - Cybersecurity Engineer
    Date: 20 August 2026
    Exit Codes: 0=success, 1=controlled failure, 2=environment error
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptName = "4-windows_harden.ps1"
$Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$CapstoneDir = Join-Path $ScriptDir "capstone"
$ExecDir = Join-Path $CapstoneDir "exec"
$HardeningScriptsDir = Join-Path $ScriptDir "2x01_windows_fortress"
$LogFile = Join-Path $ExecDir "windows_harden.log"
$JsonFile = Join-Path $ExecDir "windows_harden.json"
$BaselineFile = Join-Path $CapstoneDir "baseline\baseline_windows.json"
$TargetStateFile = Join-Path $CapstoneDir "target_state.json"
$AuditScript = Join-Path $CapstoneDir "win_audit.ps1"

$Steps = @()
$ControlsTouched = [System.Collections.ArrayList]::new()

function Write-InfoLog {
    param([string]$Message)
    Write-Host "[$ScriptName][INFO] $Message"
}

function Write-ErrorLog {
    param([string]$Message)
    Write-Host "[$ScriptName][ERROR] $Message" -ForegroundColor Red
}

function Write-StepLog {
    param([string]$Message)
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Add-Content -Path $LogFile -Value "[STEPS][$stamp] $Message"
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

    if (-not (Test-Path $BaselineFile)) {
        Write-ErrorLog "Baseline file not found: $BaselineFile - run T1 first"
        exit 2
    }

    if (-not (Test-Path $TargetStateFile)) {
        Write-ErrorLog "Target state not found: $TargetStateFile - run T2 first"
        exit 2
    }

    if (-not (Test-Path $HardeningScriptsDir)) {
        Write-ErrorLog "Hardening scripts directory not found: $HardeningScriptsDir"
        exit 2
    }

    Write-InfoLog "Environment validation complete"
}

function Ensure-Directories {
    Write-InfoLog "Ensuring exec directory exists..."

    if (-not (Test-Path $ExecDir)) {
        try {
            New-Item -ItemType Directory -Path $ExecDir -Force | Out-Null
        }
        catch {
            Write-ErrorLog "Failed to create exec directory: $ExecDir"
            exit 2
        }
    }

    Write-InfoLog "Directory ready: $ExecDir"
}

function Invoke-HardenStep {
    param(
        [string]$StepName,
        [string]$ScriptPath,
        [string[]]$ControlIds
    )

    if (-not (Test-Path $ScriptPath)) {
        Write-ErrorLog "Hardening script not found: $ScriptPath"
        return $false
    }

    Write-StepLog "Starting: $StepName - $ScriptPath"
    $startTime = Get-Date

    $outputFile = Join-Path $ExecDir "${StepName}_output.txt"
    $exitCode = 0

    try {
        $output = & powershell.exe -ExecutionPolicy Bypass -File $ScriptPath 2>&1
        $output | Out-File -FilePath $outputFile -Encoding UTF8
    }
    catch {
        $exitCode = 1
        $_.Exception.Message | Out-File -FilePath $outputFile -Encoding UTF8 -Append
    }

    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds

    $changed = $false
    if ((Test-Path $outputFile) -and (Get-Content $outputFile -Raw -ErrorAction SilentlyContinue) -ne "") {
        $changed = $true
    }

    Write-StepLog "Completed: $StepName - exit_code=$exitCode duration=$([math]::Round($duration,3))s"

    # Add control IDs to the touched list
    foreach ($id in $ControlIds) {
        if ($id) {
            [void]$ControlsTouched.Add($id)
        }
    }

    $stepRecord = [PSCustomObject]@{
        name              = $StepName
        script_path       = $ScriptPath
        exit_code         = $exitCode
        duration_seconds  = [math]::Round($duration, 3)
        changed           = $changed
    }

    $script:Steps += $stepRecord

    if ($exitCode -ne 0) {
        Write-ErrorLog "Step failed: $StepName exit code $exitCode - see $outputFile"
        return $false
    }

    return $true
}

function Orchestrate-Hardening {
    Write-InfoLog "Starting Windows hardening orchestration..."

    $allSuccess = $true

    # account policy - 4-password_policy.ps1
    if (-not (Invoke-HardenStep -StepName "account_policy" `
            -ScriptPath (Join-Path $HardeningScriptsDir "4-password_policy.ps1") `
            -ControlIds @("WIN-POL-01"))) {
        $allSuccess = $false
    }

    # audit policy - 5-audit_policy.ps1
    if (-not (Invoke-HardenStep -StepName "audit_policy" `
            -ScriptPath (Join-Path $HardeningScriptsDir "5-audit_policy.ps1") `
            -ControlIds @("WIN-AUD-01"))) {
        $allSuccess = $false
    }

    # Windows Firewall baseline - 11-firewall_hardening.ps1
    if (-not (Invoke-HardenStep -StepName "firewall_hardening" `
            -ScriptPath (Join-Path $HardeningScriptsDir "11-firewall_hardening.ps1") `
            -ControlIds @("WIN-FW-01"))) {
        $allSuccess = $false
    }

    # Sysmon installation with MedDefense config - 9-sysmon_deploy.ps1
    if (-not (Invoke-HardenStep -StepName "sysmon_deploy" `
            -ScriptPath (Join-Path $HardeningScriptsDir "9-sysmon_deploy.ps1") `
            -ControlIds @("WIN-SYS-01","WIN-SYS-02"))) {
        $allSuccess = $false
    }

    # PowerShell Script Block Logging enable - 6-powershell_security.ps1
    if (-not (Invoke-HardenStep -StepName "powershell_security" `
            -ScriptPath (Join-Path $HardeningScriptsDir "6-powershell_security.ps1") `
            -ControlIds @("WIN-PWR-01","WIN-SYS-03"))) {
        $allSuccess = $false
    }

    # AppLocker baseline - 12-applocker_config.ps1
    if (-not (Invoke-HardenStep -StepName "applocker_config" `
            -ScriptPath (Join-Path $HardeningScriptsDir "12-applocker_config.ps1") `
            -ControlIds @("WIN-APP-01"))) {
        $allSuccess = $false
    }

    # service minimization - 14-service_accounts.ps1
    if (-not (Invoke-HardenStep -StepName "service_minimization" `
            -ScriptPath (Join-Path $HardeningScriptsDir "14-service_accounts.ps1") `
            -ControlIds @("WIN-SVC-01"))) {
        $allSuccess = $false
    }

    if (-not $allSuccess) {
        Write-ErrorLog "One or more hardening steps failed"
        return $false
    }

    Write-InfoLog "All hardening steps completed successfully"
    return $true
}

function Read-BaselineScore {
    try {
        $baseline = Get-Content $BaselineFile -Raw | ConvertFrom-Json
        return [double]$baseline.pass_rate_percent
    }
    catch {
        Write-ErrorLog "Failed to read baseline score: $($_.Exception.Message)"
        return 0.0
    }
}

function Read-TargetScore {
    try {
        $target = Get-Content $TargetStateFile -Raw | ConvertFrom-Json
        $control = $target.controls | Where-Object { $_.id -eq "WIN-CIS-01" } | Select-Object -First 1
        if ($control) {
            return [double]$control.expected_value
        }
    }
    catch {
        Write-ErrorLog "Failed to read target score: $($_.Exception.Message)"
    }
    return 85.0
}

function Run-PostHardeningAssessment {
    Write-InfoLog "Running post-hardening CIS audit..."

    try {
        $auditOutput = & powershell.exe -ExecutionPolicy Bypass -File $AuditScript 2>&1
    }
    catch {
        Write-ErrorLog "Failed to execute win_audit.ps1: $($_.Exception.Message)"
        return -1.0
    }

    $passCount = 0
    $failCount = 0
    $naCount = 0
    $controlsTotal = 0

    foreach ($line in $auditOutput) {
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

    $applicableTotal = $passCount + $failCount
    if ($applicableTotal -gt 0) {
        $passRate = [math]::Round(($passCount / $applicableTotal) * 100, 1)
    }
    else {
        $passRate = 0.0
    }

    return $passRate
}

function Emit-ExecutionRecord {
    param([bool]$OrchestrationSuccess)

    Write-InfoLog "Writing execution evidence to windows_harden.json..."

    $cisBefore = Read-BaselineScore
    $cisAfter = Run-PostHardeningAssessment

    if ($cisAfter -lt 0) {
        $cisAfter = 0.0
    }

    $targetScore = Read-TargetScore
    $indexDelta = [math]::Round($cisAfter - $cisBefore, 1)

    $uniqueControls = $ControlsTouched | Sort-Object -Unique
    $controlsArray = @($uniqueControls)

    $hostname = $env:COMPUTERNAME

    $passed = $OrchestrationSuccess -and ($cisAfter -ge $targetScore)

    $record = [PSCustomObject]@{
        timestamp           = $Timestamp
        hostname            = $hostname
        steps               = $Steps
        cis_before          = $cisBefore
        cis_after           = $cisAfter
        index_delta         = $indexDelta
        target_pass_rate    = $targetScore
        controls_touched    = $controlsArray
        passed              = $passed
    }

    try {
        $json = $record | ConvertTo-Json -Depth 10
        $json | Out-File -FilePath $JsonFile -Encoding UTF8
    }
    catch {
        Write-ErrorLog "Failed to write JSON file: $($_.Exception.Message)"
        exit 1
    }

    $hash = (Get-FileHash -Path $JsonFile -Algorithm SHA256).Hash
    Write-InfoLog "Execution evidence written: $JsonFile"
    Write-InfoLog "CIS delta: $cisBefore -> $cisAfter delta=$indexDelta"
    Write-InfoLog "Target: $targetScore Passed: $passed"
    Write-InfoLog "Controls touched: $($controlsArray.Count)"
    Write-InfoLog "Record hash: $hash"
}

function Main {
    Write-InfoLog "Starting Windows hardening execution..."
    Write-InfoLog "Timestamp: $Timestamp"

    Validate-Environment
    Ensure-Directories

    # Compare against target-state controls to determine pass/fail
    $orchestrationSuccess = Orchestrate-Hardening

    Emit-ExecutionRecord -OrchestrationSuccess $orchestrationSuccess

    if (-not $orchestrationSuccess) {
        Write-ErrorLog "Hardening completed with failures - see $LogFile and per-step output files"
        exit 1
    }

    Write-InfoLog "Windows hardening execution completed"
    exit 0
}

Main
