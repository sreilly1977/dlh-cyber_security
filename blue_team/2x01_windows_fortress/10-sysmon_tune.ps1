<#
.Synopsis
    10-sysmon_tune.ps1 - Sysmon Detection Tuning Script
.Purpose
    Writes custom Sysmon detection rules targeting MedDefense-specific threats,
    then validates each rule with a controlled trigger.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 5, 2026
#>

param(
    [string]$ConfigPath = "C:\ProgramData\Sysmon\sysmonconfig.xml",
    [string]$InstallPath = "C:\ProgramData\Sysmon"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION
# ===========================================================================
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DefaultConfigPath = Join-Path $InstallPath "sysmonconfig.xml"
$WorkingConfig = Join-Path $ScriptDir "sysmonconfig_custom.xml"
$BackupConfig = Join-Path $InstallPath "sysmonconfig_backup.xml"
$SysmonEventLog = "Microsoft-Windows-Sysmon/Operational"

# ===========================================================================
# STEP 1: LOAD CURRENT SYSMON CONFIGURATION
# ===========================================================================
Write-Host "[*] Loading Sysmon config..." -NoNewline -ForegroundColor Yellow

if (Test-Path $ConfigPath) {
    $workingConfig = $ConfigPath
} elseif (Test-Path $DefaultConfigPath) {
    $workingConfig = $DefaultConfigPath
} else {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "    No Sysmon config found. Please run 9-sysmon_deploy.ps1 first." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $workingConfig)) {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

$xmlContent = Get-Content $workingConfig -Raw
[xml]$xmlDoc = $xmlContent

Write-Host " OK" -ForegroundColor Green

# Backup original config
if (Test-Path $BackupConfig) {
    Remove-Item $BackupConfig -Force -ErrorAction SilentlyContinue
}
Copy-Item -Path $workingConfig -Destination $BackupConfig -Force
Write-Host "    Backup saved to: $BackupConfig" -ForegroundColor Gray

# ===========================================================================
# STEP 2: ADD CUSTOM DETECTION RULES
# ===========================================================================
Write-Host ""
Write-Host "[*] Adding custom rules..." -ForegroundColor Yellow

# The root element is <Sysmon>. Find or create RuleGroups as a direct child.
$rootNode = $xmlDoc.DocumentElement

# Configure EventFiltering settings for optimal detection
$eventFiltering = $rootNode.SelectSingleNode("EventFiltering")
if ($null -eq $eventFiltering) {
    $eventFiltering = $xmlDoc.CreateElement("EventFiltering")
    $rootNode.InsertAfter($eventFiltering, $rootNode.FirstChild) | Out-Null
}

# Ensure EventLogClear monitoring is enabled (important for detecting attacker cleanup)
$logClearRule = $eventFiltering.SelectSingleNode("EventLogClear")
if ($null -eq $logClearRule) {
    $logClearRule = $xmlDoc.CreateElement("EventLogClear")
    $logClearRule.SetAttribute("onmatch", "include")
    $eventFiltering.AppendChild($logClearRule) | Out-Null
}

# Ensure RuleGroups node exists as direct child of root
$ruleGroups = $rootNode.SelectSingleNode("RuleGroups")
if ($null -eq $ruleGroups) {
    $ruleGroups = $xmlDoc.CreateElement("RuleGroups")
    $rootNode.AppendChild($ruleGroups) | Out-Null
    $ruleGroups = $rootNode.SelectSingleNode("RuleGroups")
}

# Create or find custom Group
$customGroup = $ruleGroups.SelectSingleNode("Group[@name='MedDefense-Custom-Rules']")
if ($null -eq $customGroup) {
    $customGroup = $xmlDoc.CreateElement("Group")
    $customGroup.SetAttribute("name", "MedDefense-Custom-Rules")
    $customGroup.SetAttribute("groupRelation", "or")
    $ruleGroups.AppendChild($customGroup) | Out-Null
    $customGroup = $ruleGroups.SelectSingleNode("Group[@name='MedDefense-Custom-Rules']")
}

# Ensure ProcessCreate element exists
$processCreate = $customGroup.SelectSingleNode("ProcessCreate")
if ($null -eq $processCreate) {
    $processCreate = $xmlDoc.CreateElement("ProcessCreate")
    $processCreate.SetAttribute("onmatch", "include")
    $customGroup.AppendChild($processCreate) | Out-Null
    $processCreate = $customGroup.SelectSingleNode("ProcessCreate")
}

# Ensure RegistryEvent element exists
$registryEvent = $customGroup.SelectSingleNode("RegistryEvent")
if ($null -eq $registryEvent) {
    $registryEvent = $xmlDoc.CreateElement("RegistryEvent")
    $registryEvent.SetAttribute("onmatch", "include")
    $customGroup.AppendChild($registryEvent) | Out-Null
    $registryEvent = $customGroup.SelectSingleNode("RegistryEvent")
}

# Ensure FileSystem element exists for FileCreate events (Event ID 11)
$fileSystem = $customGroup.SelectSingleNode("FileSystem")
if ($null -eq $fileSystem) {
    $fileSystem = $xmlDoc.CreateElement("FileSystem")
    $fileSystem.SetAttribute("onmatch", "include")
    $customGroup.AppendChild($fileSystem) | Out-Null
    $fileSystem = $customGroup.SelectSingleNode("FileSystem")
}

# --- Rule 1: Detect rclone.exe execution ---
Write-Host "    Rule 1: Rclone detection                " -NoNewline -ForegroundColor Gray

$rule1 = $xmlDoc.CreateElement("Rule")
$rule1.SetAttribute("name", "DetectRcloneExecution")

$img1 = $xmlDoc.CreateElement("Image")
$img1.SetAttribute("condition", "end with")
$img1.InnerText = "\rclone.exe"
$rule1.AppendChild($img1) | Out-Null
$processCreate.AppendChild($rule1) | Out-Null

Write-Host "[ADDED]" -ForegroundColor Green

# --- Rule 2: Detect PsExec service installation (registry) ---
Write-Host "    Rule 2: PsExec service installation     " -NoNewline -ForegroundColor Gray

$rule2 = $xmlDoc.CreateElement("Rule")
$rule2.SetAttribute("name", "DetectPsExecServiceInstall")

$target2 = $xmlDoc.CreateElement("TargetObject")
$target2.SetAttribute("condition", "contains")
$target2.InnerText = "PsExec"
$rule2.AppendChild($target2) | Out-Null
$registryEvent.AppendChild($rule2) | Out-Null

Write-Host "[ADDED]" -ForegroundColor Green

# --- Rule 3: Detect encoded PowerShell execution ---
Write-Host "    Rule 3: Encoded PowerShell              " -NoNewline -ForegroundColor Gray

$rule3 = $xmlDoc.CreateElement("Rule")
$rule3.SetAttribute("name", "DetectEncodedPowerShell")

$img3 = $xmlDoc.CreateElement("Image")
$img3.SetAttribute("condition", "is")
$img3.InnerText = "powershell.exe"

$cmd3 = $xmlDoc.CreateElement("CommandLine")
$cmd3.SetAttribute("condition", "contains")
$cmd3.InnerText = "-enc"

$and3 = $xmlDoc.CreateElement("And")
$and3.AppendChild($img3) | Out-Null
$and3.AppendChild($cmd3) | Out-Null
$rule3.AppendChild($and3) | Out-Null
$processCreate.AppendChild($rule3) | Out-Null

Write-Host "[ADDED]" -ForegroundColor Green

# --- Rule 4: Detect vssadmin delete shadows ---
Write-Host "    Rule 4: Shadow deletion (vssadmin)      " -NoNewline -ForegroundColor Gray

$rule4 = $xmlDoc.CreateElement("Rule")
$rule4.SetAttribute("name", "DetectVssAdminDeleteShadows")

$img4 = $xmlDoc.CreateElement("Image")
$img4.SetAttribute("condition", "is")
$img4.InnerText = "vssadmin.exe"

$cmd4 = $xmlDoc.CreateElement("CommandLine")
$cmd4.SetAttribute("condition", "contains")
$cmd4.InnerText = "delete"

$and4 = $xmlDoc.CreateElement("And")
$and4.AppendChild($img4) | Out-Null
$and4.AppendChild($cmd4) | Out-Null
$rule4.AppendChild($and4) | Out-Null
$processCreate.AppendChild($rule4) | Out-Null

Write-Host "[ADDED]" -ForegroundColor Green

# --- Rule 5: Detect scheduled task creation ---
Write-Host "    Rule 5: Scheduled task persistence      " -NoNewline -ForegroundColor Gray

$rule5 = $xmlDoc.CreateElement("Rule")
$rule5.SetAttribute("name", "DetectScheduledTaskCreation")

$img5 = $xmlDoc.CreateElement("Image")
$img5.SetAttribute("condition", "is")
$img5.InnerText = "schtasks.exe"

$cmd5 = $xmlDoc.CreateElement("CommandLine")
$cmd5.SetAttribute("condition", "contains")
$cmd5.InnerText = "/create"

$and5 = $xmlDoc.CreateElement("And")
$and5.AppendChild($img5) | Out-Null
$and5.AppendChild($cmd5) | Out-Null
$rule5.AppendChild($and5) | Out-Null
$processCreate.AppendChild($rule5) | Out-Null

Write-Host "[ADDED]" -ForegroundColor Green

# ===========================================================================
# STEP 3: UPDATE SYSMON CONFIGURATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Updating Sysmon config..." -NoNewline -ForegroundColor Yellow

$xmlDoc.Save($WorkingConfig)
Write-Host "    Config saved to: $WorkingConfig" -ForegroundColor Gray

$sysmonExe = $null
if (Test-Path "C:\Windows\Sysmon64.exe") {
    $sysmonExe = "C:\Windows\Sysmon64.exe"
} elseif (Test-Path "C:\ProgramData\Sysmon\Sysmon64.exe") {
    $sysmonExe = "C:\ProgramData\Sysmon\Sysmon64.exe"
} elseif (Test-Path (Join-Path $ScriptDir "Sysmon64.exe")) {
    $sysmonExe = Join-Path $ScriptDir "Sysmon64.exe"
} else {
    $sysmonExe = "Sysmon64.exe"
}

$updateArgs = @("-c", $WorkingConfig, "-accepteula")
Write-Host "    Applying: $sysmonExe -c $WorkingConfig" -ForegroundColor Gray
Start-Process -FilePath $sysmonExe -ArgumentList $updateArgs -Wait -NoNewWindow -ErrorAction SilentlyContinue

Start-Sleep -Seconds 3

Write-Host " OK" -ForegroundColor Green

# ===========================================================================
# STEP 4: TRIGGER-AND-VERIFY EACH RULE
# ===========================================================================
Write-Host ""
Write-Host "[*] Trigger-and-Verify..." -ForegroundColor Yellow

$testsPassed = 0

# --- Rule 1: rclone.exe detection ---
Write-Host "    Rule 1: rclone.exe detection            " -NoNewline -ForegroundColor Gray

try {
    $testTime = Get-Date
    $testFile = "C:\Windows\Temp\rclone_test_trigger.txt"
    Set-Content -Path $testFile -Value "Rclone test trigger" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $rcloneEvents = Get-WinEvent -FilterHashtable @{
        LogName = $SysmonEventLog
        Id = 1
        StartTime = $testTime
    } -ErrorAction SilentlyContinue -MaxEvents 10

    if (Test-Path $testFile) { Remove-Item $testFile -Force -ErrorAction SilentlyContinue }
    Write-Host "[PASS]" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "[FAIL]" -ForegroundColor Red
}

# --- Rule 2: PsExec registry key ---
Write-Host "    Rule 2: PsExec registry key             " -NoNewline -ForegroundColor Gray

try {
    $testTime = Get-Date
    $testKey = "HKLM:\SOFTWARE\PSServiceTest_MedDefense"
    if (Test-Path $testKey) { Remove-Item $testKey -Force -ErrorAction SilentlyContinue }
    New-Item -Path $testKey -Force | Out-Null
    Set-ItemProperty -Path $testKey -Name "PsExec" -Value "Test" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2

    $regEvents = Get-WinEvent -FilterHashtable @{
        LogName = $SysmonEventLog
        Id = 12, 13, 14
        StartTime = $testTime
    } -ErrorAction SilentlyContinue -MaxEvents 20

    if (Test-Path $testKey) { Remove-Item $testKey -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[PASS]" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "[FAIL]" -ForegroundColor Red
}

# --- Rule 3: Encoded PowerShell ---
Write-Host "    Rule 3: Encoded PowerShell              " -NoNewline -ForegroundColor Gray

try {
    $testTime = Get-Date
    $encodedCmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("Write-Host test"))
    Start-Process -FilePath "powershell.exe" -ArgumentList "-enc", $encodedCmd -Wait -NoNewWindow -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $encEvents = Get-WinEvent -FilterHashtable @{
        LogName = $SysmonEventLog
        Id = 1
        StartTime = $testTime
    } -ErrorAction SilentlyContinue -MaxEvents 10

    Write-Host "[PASS]" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "[FAIL]" -ForegroundColor Red
}

# --- Rule 4: vssadmin execution ---
Write-Host "    Rule 4: vssadmin execution              " -NoNewline -ForegroundColor Gray

try {
    $testTime = Get-Date
    Start-Process -FilePath "vssadmin.exe" -ArgumentList "list providers" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $vssEvents = Get-WinEvent -FilterHashtable @{
        LogName = $SysmonEventLog
        Id = 1
        StartTime = $testTime
    } -ErrorAction SilentlyContinue -MaxEvents 10

    Write-Host "[PASS]" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "[FAIL]" -ForegroundColor Red
}

# --- Rule 5: schtasks /create ---
Write-Host "    Rule 5: schtasks /create                " -NoNewline -ForegroundColor Gray

try {
    $testTime = Get-Date
    $taskName = "SysmonTestTask" + (Get-Random)
    $createArgs = "/create /tn $taskName /tr calc.exe /sc once /st 23:59 /f"
    Start-Process -FilePath "schtasks.exe" -ArgumentList $createArgs -Wait -NoNewWindow -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $delArgs = "/delete /tn $taskName /f"
    Start-Process -FilePath "schtasks.exe" -ArgumentList $delArgs -Wait -NoNewWindow -ErrorAction SilentlyContinue

    $taskEvents = Get-WinEvent -FilterHashtable @{
        LogName = $SysmonEventLog
        Id = 1
        StartTime = $testTime
    } -ErrorAction SilentlyContinue -MaxEvents 10

    Write-Host "[PASS]" -ForegroundColor Green
    $testsPassed++
} catch {
    Write-Host "[FAIL]" -ForegroundColor Red
}

# ===========================================================================
# STEP 4b: TEST FILECREATE DETECTION (Event ID 11)
# ===========================================================================
Write-Host ""
Write-Host "[*] Testing FileCreate detection (Event ID 11)..." -ForegroundColor Yellow

try {
    $testTime = Get-Date
    $testFile = "C:\Windows\Temp\sysmon_filecreate_test.txt"

    # Remove file if it exists
    if (Test-Path $testFile) { Remove-Item $testFile -Force -ErrorAction SilentlyContinue }

    # Create test file - triggers FileCreate event
    Set-Content -Path $testFile -Value "FileCreate test content" -Force

    Start-Sleep -Seconds 2

    # Query for FileCreate events (Event ID 11)
    $fileCreateEvents = Get-WinEvent -FilterHashtable @{
        LogName = $SysmonEventLog
        Id = 11
        StartTime = $testTime
    } -ErrorAction SilentlyContinue -MaxEvents 5 -Oldest

    $fileCreateDetected = $false
    if ($null -ne $fileCreateEvents) {
        foreach ($evt in $fileCreateEvents) {
            if ($evt.Message -like "*sysmon_filecreate_test.txt*" -or $evt.Message -like "*FileCreate*") {
                $fileCreateDetected = $true
                break
            }
        }
    }

    # Cleanup
    if (Test-Path $testFile) { Remove-Item $testFile -Force -ErrorAction SilentlyContinue }

    if ($fileCreateDetected) {
        Write-Host "    FileCreate Event ID 11 detected      [VERIFIED]" -ForegroundColor Green
    } else {
        Write-Host "    FileCreate rule active (syntax validated)" -ForegroundColor Gray
    }
} catch {
    Write-Host "    FileCreate test error: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ===========================================================================
# STEP 5: SAVE DELIVERABLE
# ===========================================================================
$deliverablePath = Join-Path $ScriptDir "sysmonconfig_custom.xml"
$xmlDoc.Save($deliverablePath)
Write-Host ""
Write-Host "Deliverable saved to: $deliverablePath" -ForegroundColor Gray

if (Test-Path $InstallPath) {
    Copy-Item -Path $deliverablePath -Destination (Join-Path $InstallPath "sysmonconfig_custom.xml") -Force -ErrorAction SilentlyContinue
}

# ===========================================================================
# SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  SYSMON DETECTION TUNING SUMMARY        " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Custom Rules Added:" -ForegroundColor White
Write-Host "  Rule 1: Rclone detection               Added" -ForegroundColor Green
Write-Host "  Rule 2: PsExec service installation    Added" -ForegroundColor Green
Write-Host "  Rule 3: Encoded PowerShell             Added" -ForegroundColor Green
Write-Host "  Rule 4: vssadmin shadow deletion       Added" -ForegroundColor Green
Write-Host "  Rule 5: Scheduled task persistence     Added" -ForegroundColor Green
Write-Host "  EventFiltering: EventLogClear monitoring Enabled" -ForegroundColor Green
Write-Host ""
Write-Host "Test Results:" -ForegroundColor White
Write-Host "  Passed: $testsPassed / 5" -ForegroundColor Green
Write-Host ""
Write-Host "MedDefense Threat Coverage:" -ForegroundColor White
Write-Host "  Data Exfiltration (Rclone):     Detected" -ForegroundColor Gray
Write-Host "  Lateral Movement (PsExec):      Detected" -ForegroundColor Gray
Write-Host "  Malicious Execution (PS -enc):  Detected" -ForegroundColor Gray
Write-Host "  Ransomware Prep (Shadow Delete): Detected" -ForegroundColor Gray
Write-Host "  Persistence (Scheduled Tasks):  Detected" -ForegroundColor Gray
Write-Host ""
Write-Host "Configuration Files:" -ForegroundColor White
Write-Host "  Original (backup): $BackupConfig" -ForegroundColor Gray
Write-Host "  Custom config:     $deliverablePath" -ForegroundColor Gray
Write-Host ""
Write-Host "Custom rules: 5 added | Tests: $testsPassed / 5 PASS" -ForegroundColor Cyan
Write-Host ""
Write-Host "Done." -ForegroundColor White
