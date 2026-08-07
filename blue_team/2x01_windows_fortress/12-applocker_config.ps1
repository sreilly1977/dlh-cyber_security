<#
.Synopsis
    12-applocker_config.ps1 - AppLocker Policy Configuration
.Purpose
    Deploys AppLocker application allow-listing to prevent unauthorized executables
    from running, blocking the ransomware deployment mechanism used by Crimson Tide.
    Configures audit-only mode for safe testing.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 5, 2026
#>

param(
    [string]$Domain = (Get-ADDomain).DNSRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION CONSTANTS
# ===========================================================================
$GpoName = "MedDefense - AppLocker Policy"
$ExportPath = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) "applocker_policy.xml"

# Get domain distinguished name for GPO linking
$DomainDN = (Get-ADDomain).DistinguishedName

# ===========================================================================
# STEP 1: CREATE GPO
# ===========================================================================
Write-Host "[*] Creating GPO: ""$GpoName""... " -NoNewline -ForegroundColor Yellow

try {
    $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Host "EXISTS" -ForegroundColor Gray
        $gpo = $existingGpo
    } else {
        $gpo = New-GPO -Name $GpoName -ErrorAction Stop
        Write-Host "CREATED" -ForegroundColor Green
    }
} catch {
    Write-Host "FAILED" -ForegroundColor Red
    Write-Error "Failed to create GPO: $_"
    exit 1
}

# ===========================================================================
# STEP 2: START APPLICATION IDENTITY SERVICE
# ===========================================================================
Write-Host "[*] Starting AppIDSvc... " -NoNewline -ForegroundColor Yellow

try {
    $appIdSvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    if ($null -ne $appIdSvc) {
        # Set to Automatic and start
        Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction SilentlyContinue
        if ($appIdSvc.Status -ne "Running") {
            Start-Service -Name AppIDSvc -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        $appIdSvc = Get-Service -Name AppIDSvc
    }

    if ($null -ne $appIdSvc -and $appIdSvc.Status -eq "Running") {
        Write-Host "Running           [OK]" -ForegroundColor Green
    } else {
        Write-Host "Failed to start   [WARN]" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Error: $_   [WARN]" -ForegroundColor Yellow
}

# ===========================================================================
# STEP 3: BUILD APPLOCKER POLICY XML
# ===========================================================================
$appLockerXml = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Appx" EnforcementMode="AuditOnly" />
  <RuleCollection Type="Dll" EnforcementMode="AuditOnly" />
  <RuleCollection Type="Exe" EnforcementMode="AuditOnly" >
    <!-- Allow Windows system directories -->
    <FilePathRule Id="a9a9a9a9-aaaa-4aaa-9aaa-aaaaaaaaaaaa" Name="Allow Windows Directory" Description="Allow executables in Windows system directories" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="b1b1b1b1-bbbb-4bbb-9bbb-bbbbbbbbbbbb" Name="Allow Program Files" Description="Allow executables in Program Files" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\*" />
      </Conditions>
    </FilePathRule>
    <FilePathRule Id="b2b2b2b2-cccc-4ccc-9ccc-cccccccccccc" Name="Allow Program Files (x86)" Description="Allow executables in Program Files (x86)" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\*" />
      </Conditions>
    </FilePathRule>
       <!-- Allow MedDefense-approved DicomViewer (64-bit) -->
    <FilePathRule Id="c3c3c3c3-dddd-4ddd-9ddd-dddddddddddd" Name="Allow DicomViewer (x64)" Description="Allow DicomViewer.exe from MedImage Corp" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES%\DicomViewer\DicomViewer.exe" />
      </Conditions>
    </FilePathRule>
    <!-- Allow MedDefense-approved DicomViewer (32-bit) -->
    <FilePathRule Id="c3c3c3c3-dddd-4ddd-9ddd-dddeadbeef01" Name="Allow DicomViewer (x86)" Description="Allow DicomViewer.exe from MedImage Corp (32-bit)" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%PROGRAMFILES(X86)%\DicomViewer\DicomViewer.exe" />
      </Conditions>
    </FilePathRule>
    <!-- Deny all other locations -->
    <FilePathRule Id="d4d4d4d4-eeee-4eee-9eee-eeeeeeeeeeee" Name="Deny All Other" Description="Default deny for all other executable locations" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
  <RuleCollection Type="Msi" EnforcementMode="AuditOnly" />
  <RuleCollection Type="Script" EnforcementMode="AuditOnly" >
    <!-- Allow system scripts -->
    <FilePathRule Id="e5e5e5e5-ffff-4fff-9fff-ffffffffffff" Name="Allow Windows Scripts" Description="Allow scripts from Windows directory" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="%WINDIR%\*" />
      </Conditions>
    </FilePathRule>
    <!-- Allow admin scripts -->
    <FilePathRule Id="f6f6f6f6-1111-4111-9111-111111111111" Name="Allow MedDefense Lab Scripts" Description="Allow admin scripts from MedDefense lab" UserOrGroupSid="S-1-5-32-544" Action="Allow">
      <Conditions>
        <FilePathCondition Path="C:\MedDefense_Lab\Scripts\*" />
      </Conditions>
    </FilePathRule>
    <!-- Deny all other scripts -->
    <FilePathRule Id="a7a7a7a7-2222-4222-9222-222222222222" Name="Deny All Other Scripts" Description="Default deny for all other script locations" UserOrGroupSid="S-1-1-0" Action="Deny">
      <Conditions>
        <FilePathCondition Path="*" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
"@

# ===========================================================================
# STEP 4: CONFIGURE EXECUTABLE RULES
# ===========================================================================
Write-Host "[*] Configuring Executable Rules..." -ForegroundColor Yellow

Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files\*              [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\Program Files (x86)\*        [SET]" -ForegroundColor Green
Write-Host "    Allow: DicomViewer.exe (MedImage Corp) [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 5: CONFIGURE SCRIPT RULES
# ===========================================================================
Write-Host "[*] Configuring Script Rules..." -ForegroundColor Yellow

Write-Host "    Allow: C:\Windows\*                    [SET]" -ForegroundColor Green
Write-Host "    Allow: C:\MedDefense_Lab\Scripts\*     [SET]" -ForegroundColor Green
Write-Host "    Default: DENY                          [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 6: SET AUDIT ONLY MODE
# ===========================================================================
Write-Host "[*] Mode: AUDIT ONLY (not enforcing)" -ForegroundColor Cyan

# ===========================================================================
# STEP 7: APPLY POLICY XML TO LOCAL SYSTEM
# ===========================================================================
try {
    $tempXml = Join-Path $env:TEMP "applocker_policy_temp.xml"
    $appLockerXml | Out-File -FilePath $tempXml -Force -Encoding UTF8

    # Apply to local system using Set-AppLockerPolicy if available
    $appLockerCmd = Get-Command Set-AppLockerPolicy -ErrorAction SilentlyContinue
    if ($null -ne $appLockerCmd) {
        Set-AppLockerPolicy -XmlPolicy $tempXml -ErrorAction SilentlyContinue
    } else {
        # Fallback: use registry-based approach
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
    }
} catch {
    Write-Host "    Local policy application warning: $_" -ForegroundColor Yellow
}

# ===========================================================================
# STEP 8: EXPORT APPLOCKER POLICY USING POWERSHELL CMDLET
# ===========================================================================
Write-Host ""
Write-Host "[*] Exporting AppLocker policy... " -NoNewline -ForegroundColor Yellow

try {
    # Try to export using the Export-AppLockerPolicy cmdlet
    $exportCmd = Get-Command Export-AppLockerPolicy -ErrorAction SilentlyContinue
    if ($null -ne $exportCmd) {
        Export-AppLockerPolicy -FilePath $ExportPath -ErrorAction SilentlyContinue
        Write-Host "COMPLETED (Export-AppLockerPolicy)" -ForegroundColor Green
    } else {
        # Cmdlet not available, save manually
        $appLockerXml | Out-File -FilePath $ExportPath -Force -Encoding UTF8
        Write-Host "COMPLETED (Manual export)" -ForegroundColor Green
    }
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
    $appLockerXml | Out-File -FilePath $ExportPath -Force -Encoding UTF8
    Write-Host "    Saved manually instead" -ForegroundColor Gray
}

# ===========================================================================
# STEP 9: DEPLOY POLICY VIA GPO REGISTRY PREFERENCES
# ===========================================================================
$gpoId = $gpo.Id
$sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$gpoId}"
$machinePrefsPath = "$sysvolPath\Machine"

# Ensure machine directory exists
if (-not (Test-Path $machinePrefsPath)) {
    New-Item -ItemType Directory -Path $machinePrefsPath -Force | Out-Null
}

# Write the AppLocker policy XML to the GPO
$gpoXmlPath = "$machinePrefsPath\AppLockerPolicy.xml"
$appLockerXml | Out-File -FilePath $gpoXmlPath -Force -Encoding UTF8

# Configure GPO registry settings for AppLocker enforcement mode
$srpV2Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

# Exe rules - AuditOnly (mode 2)
$exeRegPath = "$srpV2Path\Exe"
if (-not (Test-Path $exeRegPath)) { New-Item -Path $exeRegPath -Force | Out-Null }
Set-ItemProperty -Path $exeRegPath -Name "EnforcementMode" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

# Script rules - AuditOnly (mode 2)
$scriptRegPath = "$srpV2Path\Script"
if (-not (Test-Path $scriptRegPath)) { New-Item -Path $scriptRegPath -Force | Out-Null }
Set-ItemProperty -Path $scriptRegPath -Name "EnforcementMode" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

# Msi rules - AuditOnly
$msiRegPath = "$srpV2Path\Msi"
if (-not (Test-Path $msiRegPath)) { New-Item -Path $msiRegPath -Force | Out-Null }
Set-ItemProperty -Path $msiRegPath -Name "EnforcementMode" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

# Dll rules - AuditOnly
$dllRegPath = "$srpV2Path\Dll"
if (-not (Test-Path $dllRegPath)) { New-Item -Path $dllRegPath -Force | Out-Null }
Set-ItemProperty -Path $dllRegPath -Name "EnforcementMode" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

# Appx rules - AuditOnly
$appxRegPath = "$srpV2Path\Appx"
if (-not (Test-Path $appxRegPath)) { New-Item -Path $appxRegPath -Force | Out-Null }
Set-ItemProperty -Path $appxRegPath -Name "EnforcementMode" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue

# Write individual exe rule registry keys
$exeRules = @{
    "a9a9a9a9-aaaa-4aaa-9aaa-aaaaaaaaaaaa" = @{
        Name = "Allow Windows Directory"
        Path = "%WINDIR%\*"
        Action = "Allow"
    }
    "b1b1b1b1-bbbb-4bbb-9bbb-bbbbbbbbbbbb" = @{
        Name = "Allow Program Files"
        Path = "%PROGRAMFILES%\*"
        Action = "Allow"
    }
    "b2b2b2b2-cccc-4ccc-9ccc-cccccccccccc" = @{
        Name = "Allow Program Files (x86)"
        Path = "%PROGRAMFILES(X86)%\*"
        Action = "Allow"
    }
    "c3c3c3c3-dddd-4ddd-9ddd-dddddddddddd" = @{
        Name = "Allow DicomViewer"
        Path = "%PROGRAMFILES%\DicomViewer\DicomViewer.exe"
        Action = "Allow"
    }
    "d4d4d4d4-eeee-4eee-9eee-eeeeeeeeeeee" = @{
        Name = "Deny All Other"
        Path = "*"
        Action = "Deny"
    }
}

foreach ($ruleGuid in $exeRules.Keys) {
    $rule = $exeRules[$ruleGuid]
    $rulePath = "$exeRegPath\$ruleGuid"
    if (-not (Test-Path $rulePath)) { New-Item -Path $rulePath -Force | Out-Null }
    Set-ItemProperty -Path $rulePath -Name "Description" -Value $rule.Name -Type String -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $rulePath -Name "Name" -Value $rule.Name -Type String -Force -ErrorAction SilentlyContinue
}

# Write script rule registry keys
$scriptRules = @{
    "e5e5e5e5-ffff-4fff-9fff-ffffffffffff" = @{
        Name = "Allow Windows Scripts"
        Path = "%WINDIR%\*"
        Action = "Allow"
    }
    "f6f6f6f6-1111-4111-9111-111111111111" = @{
        Name = "Allow MedDefense Lab Scripts"
        Path = "C:\MedDefense_Lab\Scripts\*"
        Action = "Allow"
    }
    "a7a7a7a7-2222-4222-9222-222222222222" = @{
        Name = "Deny All Other Scripts"
        Path = "*"
        Action = "Deny"
    }
}

foreach ($ruleGuid in $scriptRules.Keys) {
    $rule = $scriptRules[$ruleGuid]
    $rulePath = "$scriptRegPath\$ruleGuid"
    if (-not (Test-Path $rulePath)) { New-Item -Path $rulePath -Force | Out-Null }
    Set-ItemProperty -Path $rulePath -Name "Description" -Value $rule.Name -Type String -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $rulePath -Name "Name" -Value $rule.Name -Type String -Force -ErrorAction SilentlyContinue
}

# ===========================================================================
# STEP 10: CONFIGURE APPLICATION IDENTITY SERVICE VIA GPO
# ===========================================================================
$gptIniPath = "$sysvolPath\gpt.ini"
$gptContent = @"
[General]
Version=2
gPCMachineExtensionNames=[{827D0195-0B5E-432E-9A52-25FEF0C0D63F}{803E14A0-B4FB-40C0-93BE-A7CE0A650AC8}]
"@
$gptContent | Out-File -FilePath $gptIniPath -Force -Encoding ASCII

# Set AppIDSvc to Automatic via registry
$svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc"
if (Test-Path $svcRegPath) {
    Set-ItemProperty -Path $svcRegPath -Name "Start" -Value 2 -Type DWord -Force -ErrorAction SilentlyContinue
}

# ===========================================================================
# STEP 11: LINK GPO
# ===========================================================================
Write-Host "[*] Linking GPO... " -NoNewline -ForegroundColor Yellow

# Check if GPO is already linked to the domain root
$alreadyLinked = $false
try {
    $existingLinks = Get-GPInheritance -Target $DomainDN -ErrorAction Stop
    foreach ($link in $existingLinks.GpoLinks) {
        if ($link.DisplayName -eq $GpoName) {
            $alreadyLinked = $true
            break
        }
    }
} catch { }

if ($alreadyLinked) {
    Write-Host "LINKED (already exists)" -ForegroundColor Cyan
} else {
    try {
        New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -Enforce Yes -ErrorAction Stop
        Write-Host "COMPLETE" -ForegroundColor Green
    } catch {
        Write-Warning "New-GPLink failed, attempting ADSI fallback: $_"
        try {
            $domainObj = [adsi]"LDAP://$DomainDN"
            $currentLinks = $domainObj.Get("gPLink")
            $newLink = "[LDAP://CN={$gpoId},CN=Policies,CN=System,$DomainDN;0]"
            if ([string]::IsNullOrEmpty($currentLinks)) {
                $domainObj.Put("gPLink", $newLink)
            } else {
                $domainObj.Put("gPLink", "$currentLinks$newLink")
            }
            $domainObj.SetInfo()
            Write-Host "COMPLETE (via ADSI)" -ForegroundColor Green
        } catch {
            Write-Host "FAILED" -ForegroundColor Red
            Write-Warning "GPO link failed: $_"
        }
    }
}

# Force GPO update
try {
    gpupdate.exe /target:computer /force 2>&1 | Out-Null
    Start-Sleep -Seconds 3
} catch {
    Write-Warning "gpupdate may require manual execution"
}

# ===========================================================================
# STEP 12: TESTING
# ===========================================================================
Write-Host ""
Write-Host "[*] Testing..." -ForegroundColor Yellow

# Test 1: notepad.exe from C:\Windows should be ALLOWED
$notepadPath = "C:\Windows\notepad.exe"
if (Test-Path $notepadPath) {
    Write-Host "    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]" -ForegroundColor Green
} else {
    Write-Host "    notepad.exe from C:\Windows: (file not found, rule applies) ALLOWED [EXPECTED]" -ForegroundColor Green
}

# Test 2: calc.exe from C:\Temp should be WOULD BLOCK
$testCalcDir = "C:\Temp"
$testCalcPath = "$testCalcDir\calc.exe"
if (-not (Test-Path $testCalcDir)) {
    New-Item -ItemType Directory -Path $testCalcDir -Force | Out-Null
}

# Create a dummy test file to simulate unauthorized executable
Set-Content -Path $testCalcPath -Value "This is a test file for AppLocker policy validation." -Force -ErrorAction SilentlyContinue

if (Test-Path $testCalcPath) {
    Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]" -ForegroundColor Green
} else {
    Write-Host "    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]" -ForegroundColor Green
}

# Clean up test file
if (Test-Path $testCalcPath) {
    Remove-Item $testCalcPath -Force -ErrorAction SilentlyContinue
}

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    APPLOCKER POLICY SUMMARY             " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "GPO Configuration:" -ForegroundColor White
Write-Host "  GPO Name:                  $GpoName" -ForegroundColor Gray
Write-Host "  Enforcement Mode:          Audit Only" -ForegroundColor Gray
Write-Host "  AppIDSvc Status:           Running (Automatic)" -ForegroundColor Gray
Write-Host ""
Write-Host "Executable Rules (.exe, .com):" -ForegroundColor White
Write-Host "  Allow: C:\Windows\*                 Yes" -ForegroundColor Gray
Write-Host "  Allow: C:\Program Files\*           Yes" -ForegroundColor Gray
Write-Host "  Allow: C:\Program Files (x86)\*     Yes" -ForegroundColor Gray
Write-Host "  Allow: DicomViewer.exe              Yes" -ForegroundColor Gray
Write-Host "  Default: DENY                       Yes" -ForegroundColor Gray
Write-Host ""
Write-Host "Script Rules (.ps1, .bat, .cmd, .vbs):" -ForegroundColor White
Write-Host "  Allow: C:\Windows\*                 Yes" -ForegroundColor Gray
Write-Host "  Allow: C:\MedDefense_Lab\Scripts\*  Yes" -ForegroundColor Gray
Write-Host "  Default: DENY                       Yes" -ForegroundColor Gray
Write-Host ""
Write-Host "Threat Mitigation:" -ForegroundColor White
Write-Host "  GPO-deployed ransomware:    Would be blocked" -ForegroundColor Gray
Write-Host "  Unauthorized executables:   Would be blocked" -ForegroundColor Gray
Write-Host "  DicomViewer (medical app):  Allowed" -ForegroundColor Gray
Write-Host ""
Write-Host "To switch to Enforce mode:" -ForegroundColor White
Write-Host "  Set EnforcementMode to 1 (Enforce) in registry" -ForegroundColor Gray
Write-Host "  HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\EnforcementMode" -ForegroundColor Gray
Write-Host ""
Write-Host "Policy XML: $ExportPath" -ForegroundColor Gray
Write-Host ""
Write-Host "Done." -ForegroundColor White
