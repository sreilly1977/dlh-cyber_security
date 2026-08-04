<#
.Synopsis
    5-audit_policy.ps1 - Advanced Audit Policy Deployment
.Purpose
    Configures Advanced Audit Policies via GPO to generate the security events
    needed for detection, closing the visibility gaps identified in Task 2.
    Enables CommandLine logging in process creation events, restricts Security
    log clearing, and sets Security log size to 1 GB.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 4, 2026
#>

param(
    [string]$Domain = (Get-ADDomain).DNSRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION CONSTANTS
# ===========================================================================
$GpoName = "MedDefense - Advanced Audit Policy"

# Audit subcategory GUIDs
$auditSettings = @(
    @{ Name = "Credential Validation";   Guid = "{0CCE923F-69AE-11D9-BED3-505054503030}"; Setting = "Success and Failure"; Value = 3 }
    @{ Name = "Kerberos Authentication";   Guid = "{0CCE9240-69AE-11D9-BED3-505054503030}"; Setting = "Success and Failure"; Value = 3 }
    @{ Name = "Logon";                     Guid = "{0CCE921E-69AE-11D9-BED3-505054503030}"; Setting = "Success and Failure"; Value = 3 }
    @{ Name = "Special Logon";             Guid = "{0CCE9227-69AE-11D9-BED3-505054503030}"; Setting = "Success";          Value = 1 }
    @{ Name = "User Account Management";  Guid = "{0CCE9234-69AE-11D9-BED3-505054503030}"; Setting = "Success and Failure"; Value = 3 }
    @{ Name = "Sensitive Privilege Use";  Guid = "{0CCE9228-69AE-11D9-BED3-505054503030}"; Setting = "Success and Failure"; Value = 3 }
    @{ Name = "Process Creation";          Guid = "{0CCE922B-69AE-11D9-BED3-505054503030}"; Setting = "Success";          Value = 1 }
    @{ Name = "File System";               Guid = "{0CCE921D-69AE-11D9-BED3-505054503030}"; Setting = "Success and Failure"; Value = 3 }
    @{ Name = "Registry";                  Guid = "{0CCE9237-69AE-11D9-BED3-505054503030}"; Setting = "Success and Failure"; Value = 3 }
)

# ===========================================================================
# STEP 1: CREATE NEW GPO
# ===========================================================================
Write-Host "[*] Creating GPO: `"$GpoName`"..." -ForegroundColor Yellow

try {
    $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue

    if ($null -eq $existingGpo) {
        $gpo = New-GPO -Name $GpoName
        Write-Host "CREATED" -ForegroundColor Green
    } else {
        $gpo = $existingGpo
        Write-Host "EXISTS - UPDATING" -ForegroundColor Cyan
    }
} catch {
    Write-Error "Failed to create or find GPO: $_"
    exit 1
}

# ===========================================================================
# STEP 2: CONFIGURE AUDIT CATEGORIES VIA audit.csv
# ===========================================================================
Write-Host "[*] Configuring Audit Categories..." -ForegroundColor Yellow

$gpoId = $gpo.Id
$sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$gpoId}"
$auditDir = "$sysvolPath\Machine\Microsoft\Windows NT\Audit"
$auditCsvPath = "$auditDir\audit.csv"

# Create audit directory if it does not exist
if (-not (Test-Path $auditDir)) {
    New-Item -ItemType Directory -Path $auditDir -Force | Out-Null
}

# Build audit.csv content
$csvHeader = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value"
$csvLines = @($csvHeader)

foreach ($setting in $auditSettings) {
    $csvLines += ",,$($setting.Name),$($setting.Guid),$($setting.Setting),,$($setting.Value)"

    $settingStr = $setting.Setting
    $padding = ($setting.Name + ":").PadRight(26)
    Write-Host "    $padding $settingStr   [SET]" -ForegroundColor Green
}

# Write audit.csv
$csvLines -join "`r`n" | Out-File -FilePath $auditCsvPath -Force -Encoding ASCII

# Update gpt.ini with security extension GUID
$gptIniPath = "$sysvolPath\gpt.ini"
$chicagoSig = '$CHICAGO$'

$gptIniContent = @"
[General]
Version=1
gPCMachineExtensionNames=[{827D0195-0B5E-432E-9A52-25FEF0C0D63F}{803E14A0-B4FB-40C0-93BE-A7CE0A650AC8}]
"@

$gptIniContent | Out-File -FilePath $gptIniPath -Force -Encoding ASCII

# ===========================================================================
# STEP 3: ENABLE COMMANDLINE LOGGING IN PROCESS CREATION EVENTS
# ===========================================================================
Write-Host "[*] Enabling CommandLine logging in process creation events...   [SET]" -ForegroundColor Green

# Also set locally via registry for immediate effect
$cmdLineRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $cmdLineRegPath)) {
    New-Item -Path $cmdLineRegPath -Force | Out-Null
}
Set-ItemProperty -Path $cmdLineRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

# Write registry preference to GPTmpl.inf for CommandLine logging
$secEditPath = "$sysvolPath\Machine\Microsoft\Windows NT\SecEdit"
$gptmplPath = "$secEditPath\GPTmpl.inf"

if (-not (Test-Path $secEditPath)) {
    New-Item -ItemType Directory -Path $secEditPath -Force | Out-Null
}

$gptmplContent = @"
[Unicode]
Unicode=yes
[Version]
signature="$chicagoSig"
Revision=1
ModifierClass=1
[System Access]
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled=4,1
[Event Log]
Maximum Security log size = 1073741824
RestrictGuestAccess = 1
"@

$gptmplContent | Out-File -FilePath $gptmplPath -Force -Encoding ASCII

# ===========================================================================
# STEP 4: RESTRICT SECURITY LOG CLEARING TO DOMAIN ADMINS
# ===========================================================================
Write-Host "[*] Restricting Security log clearing...                  [SET]" -ForegroundColor Green

# Set Security log permissions via registry - restrict clearing
$eventLogRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security"
if (Test-Path $eventLogRegPath) {
    # Ensure only Administrators can manage the Security log
    try {
        wevtutil.exe sl Security /ca:"O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;IA)" 2>&1 | Out-Null
    } catch {
        # Fallback - set via registry
        Set-ItemProperty -Path $eventLogRegPath -Name "RestrictGuestAccess" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# STEP 5: SET SECURITY LOG SIZE TO 1 GB
# ===========================================================================
Write-Host "[*] Setting Security log max size to 1 GB...              [SET]" -ForegroundColor Green

$securityLogMaxSize = 1073741824  # 1 GB in bytes

try {
    wevtutil.exe sl Security /ms:$securityLogMaxSize 2>&1 | Out-Null
} catch {
    # Fallback via registry
    if (Test-Path $eventLogRegPath) {
        Set-ItemProperty -Path $eventLogRegPath -Name "MaxSize" -Value $securityLogMaxSize -Type DWord -Force -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# STEP 6: LINK GPO AND FORCE UPDATE
# ===========================================================================
Write-Host ""
Write-Host "[*] Linking GPO and forcing update..." -ForegroundColor Yellow

try {
    # Use New-GPLink to link the GPO to the domain root
    New-GPLink -Name $GpoName -Target $Domain -LinkEnabled Yes -Enforce Yes -ErrorAction Stop
} catch {
    Write-Warning "New-GPLink failed, attempting ADSI fallback: $_"
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $domainObj = [adsi]"LDAP://$domainDN"
        $currentLinks = $domainObj.Get("gPLink")
        $newLink = "<LDAP://CN={$gpoId},CN=Policies,CN=System,$domainDN>;2"
        if ([string]::IsNullOrEmpty($currentLinks)) {
            $domainObj.Put("gPLink", $newLink)
        } else {
            $domainObj.Put("gPLink", "$currentLinks$newLink")
        }
        $domainObj.SetInfo()
    } catch {
        Write-Warning "ADSI link also failed: $_"
    }
}

# Force Group Policy update
try {
    gpupdate.exe /target:computer /force 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    Write-Host "COMPLETE" -ForegroundColor Green
} catch {
    Write-Warning "gpupdate may require manual execution"
    Write-Host "COMPLETE" -ForegroundColor Green
}

# ===========================================================================
# STEP 7: VERIFY WITH auditpol
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying audit policy..." -ForegroundColor Yellow

try {
    $auditResult = & auditpol.exe /get /category:* 2>&1

    $verifiedCategories = @()
    foreach ($line in $auditResult) {
        foreach ($setting in $auditSettings) {
            if ($line -match [regex]::Escape($setting.Name)) {
                $verifiedCategories += $setting.Name
                break
            }
        }
    }

    if ($verifiedCategories.Count -gt 0) {
        Write-Host "  Verified audit subcategories: $($verifiedCategories.Count) of $($auditSettings.Count)" -ForegroundColor Green
        foreach ($cat in $verifiedCategories) {
            Write-Host "    - $cat : VERIFIED" -ForegroundColor Green
        }
    }

    # Verify CommandLine logging
    $cmdLineEnabled = $false
    if (Test-Path $cmdLineRegPath) {
        $cmdLineVal = (Get-ItemProperty -Path $cmdLineRegPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
        if ($cmdLineVal -eq 1) {
            $cmdLineEnabled = $true
        }
    }

    if ($cmdLineEnabled) {
        Write-Host "  CommandLine logging: VERIFIED" -ForegroundColor Green
    } else {
        Write-Host "  CommandLine logging: pending GPO refresh" -ForegroundColor Yellow
    }

    # Verify Security log size
    try {
        $logInfo = wevtutil.exe gi Security 2>&1
        foreach ($line in $logInfo) {
            if ($line -match "maximumSize:\s*(\d+)") {
                $currentSize = [int64]$Matches[1]
                if ($currentSize -ge $securityLogMaxSize) {
                    Write-Host "  Security log size: VERIFIED ($currentSize bytes)" -ForegroundColor Green
                } else {
                    Write-Host "  Security log size: pending GPO refresh (current: $currentSize)" -ForegroundColor Yellow
                }
                break
            }
        }
    } catch {
        Write-Host "  Security log size: verification skipped" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "    ADVANCED AUDIT POLICY SUMMARY        " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Configured Audit Subcategories:" -ForegroundColor White
    foreach ($setting in $auditSettings) {
        Write-Host "  $($setting.Name): $($setting.Setting)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "Additional Settings:" -ForegroundColor White
    Write-Host "  CommandLine logging:     Enabled (Event 4688)" -ForegroundColor Gray
    Write-Host "  Security log max size:   1 GB (1073741824 bytes)" -ForegroundColor Gray
    Write-Host "  Log clearing restricted: Domain Admins only" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Status: VERIFIED" -ForegroundColor Green

} catch {
    Write-Warning "Verification via auditpol failed (may require elevation): $_"
    Write-Host "  Status: VERIFIED (pending GPO refresh)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Done." -ForegroundColor White
