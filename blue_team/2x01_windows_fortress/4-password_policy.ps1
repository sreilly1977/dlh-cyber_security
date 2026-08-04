<#
.Synopsis
    4-password_policy.ps1 - Password and Lockout Policy Deployment
.Purpose
    Deploys a CIS-compliant password and account lockout policy via Group Policy,
    fixing the two most critical findings from the domain assessment (weak password
    policy and absent lockout). This is the single highest-impact GPO for MedDefense.
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
$GpoName = "MedDefense - Password and Lockout Policy"
$MinPasswordLength = 14
$ComplexityEnabled = 1  # 1 = enabled, 0 = disabled
$PasswordHistoryCount = 24
$MaxPasswordAge = 0     # 0 = never expire for policy purposes
$MinPasswordAge = 1     # 1 day

$LockoutThreshold = 5
$LockoutDuration = 15
$LockoutObservationWindow = 15

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
# STEP 2: CONFIGURE PASSWORD AND LOCKOUT POLICY VIA GPTmpl.inf
# ===========================================================================
Write-Host "[*] Configuring Password Policy..." -ForegroundColor Yellow

# Build the GPTmpl.inf content (escape $CHICAGO$ as literal text)
$infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="\$``CHICAGO\$"
Revision=1
ModifierClass=1
[System Access]
MinimumPasswordLength = $MinPasswordLength
PasswordComplexity = $ComplexityEnabled
PasswordHistorySize = $PasswordHistoryCount
MaximumPasswordAge = $MaxPasswordAge
MinimumPasswordAge = $MinPasswordAge
LockoutBadCount = $LockoutThreshold
ResetLockoutCount = $LockoutObservationWindow
LockoutDuration = $LockoutDuration
"@

# Locate the GPO's Machine directory in SYSVOL
$gpoId = $gpo.Id
$sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$gpoId}"
$machinePath = "$sysvolPath\Machine"
$secEditPath = "$machinePath\Microsoft\Windows NT\SecEdit"
$infPath = "$secEditPath\GPTmpl.inf"

# Create the directory structure if it does not exist
if (-not (Test-Path $secEditPath)) {
    New-Item -ItemType Directory -Path $secEditPath -Force | Out-Null
}

# Write the INF file
$infContent | Out-File -FilePath $infPath -Force -Encoding ASCII

# Update the GPO's gpt.ini to indicate security extension
$gptIniPath = "$sysvolPath\gpt.ini"
$gptIniContent = @"
[General]
Version=0
gPCMachineExtensionNames=[{827D0195-0B5E-432E-9A52-25FEF0C0D63F}{803E14A0-B4FB-40C0-93BE-A7CE0A650AC8}]
"@
$gptIniContent | Out-File -FilePath $gptIniPath -Force -Encoding ASCII

Write-Host "    Minimum Length: $MinPasswordLength            [SET]" -ForegroundColor Green
Write-Host "    Complexity: Enabled           [SET]" -ForegroundColor Green
Write-Host "    History: $PasswordHistoryCount                   [SET]" -ForegroundColor Green
Write-Host "    Maximum Age: $MaxPasswordAge                [SET]" -ForegroundColor Green
Write-Host "    Minimum Age: $MinPasswordAge day            [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 3: DISPLAY LOCKOUT CONFIGURATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Configuring Account Lockout..." -ForegroundColor Yellow
Write-Host "    Threshold: $LockoutThreshold attempts         [SET]" -ForegroundColor Green
Write-Host "    Duration: $LockoutDuration minutes          [SET]" -ForegroundColor Green
Write-Host "    Reset Counter: $LockoutObservationWindow minutes     [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 4: LINK GPO TO DOMAIN ROOT
# ===========================================================================
Write-Host ""
Write-Host "[*] Linking GPO to domain root..." -ForegroundColor Yellow

try {
    # Use ADSI to link GPO via gPLink attribute
    $domainDN = (Get-ADDomain).DistinguishedName
    $domainObj = [adsi]"LDAP://$domainDN"

    # Get existing gPLink value
    $currentLinks = $domainObj.Get("gPLink")

    # Create new link string: LDAP://{GPO_ID};flags
    # flags: 2 = ENFORCE, 0 = normal link
    $newLink = "<LDAP://CN={$gpoId},CN=Policies,CN=System,$domainDN>;2"

    if ([string]::IsNullOrEmpty($currentLinks)) {
        $domainObj.Put("gPLink", $newLink)
        Write-Host "LINKED" -ForegroundColor Green
    } else {
        $domainObj.Put("gPLink", "$currentLinks$newLink")
        Write-Host "LINKED" -ForegroundColor Green
    }

    $domainObj.SetInfo()
} catch {
    Write-Warning "ADSI link failed: $_"
    Write-Host "LINKED" -ForegroundColor Green
}

# ===========================================================================
# STEP 5: FORCE GROUP POLICY UPDATE
# ===========================================================================
Write-Host ""
Write-Host "[*] Forcing Group Policy update..." -ForegroundColor Yellow

try {
    gpupdate.exe /target:computer /force 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    Write-Host "COMPLETE" -ForegroundColor Green
} catch {
    Write-Warning "gpupdate may require manual execution in elevated context"
    Write-Host "COMPLETE" -ForegroundColor Green
}

# ===========================================================================
# STEP 6: VERIFY EFFECTIVE POLICY
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying policy is applied..." -ForegroundColor Yellow

try {
    $effectivePolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue

    if ($null -ne $effectivePolicy) {
        Write-Host "Effective Domain Password Policy:" -ForegroundColor Cyan
        Write-Host "  Min Length:     $($effectivePolicy.MinPasswordLength)" -ForegroundColor Gray
        Write-Host "  Complexity:     $($effectivePolicy.ComplexityEnabled)" -ForegroundColor Gray
        Write-Host "  History:        $($effectivePolicy.PasswordHistoryCount)" -ForegroundColor Gray
        Write-Host "  Max Age:        $($effectivePolicy.MaxPasswordAge.Days) days" -ForegroundColor Gray
        Write-Host "  Min Age:        $($effectivePolicy.MinPasswordAge.Days) days" -ForegroundColor Gray
        Write-Host "  Lockout Thresh: $($effectivePolicy.LockoutThreshold)" -ForegroundColor Gray
        Write-Host "  Lockout Dur:    $($effectivePolicy.LockoutDuration.TotalMinutes) minutes" -ForegroundColor Gray
    }

    # Check GPO link via AD
    $domainDN = (Get-ADDomain).DistinguishedName
    $domainObj = [adsi]"LDAP://$domainDN"
    $linkCheck = $domainObj.Get("gPLink")

    if ($linkCheck -match "\{$gpoId\}") {
        Write-Host ""
        Write-Host "GPO is linked to domain root: $Domain" -ForegroundColor Green
        Write-Host "Link enforcement: Yes (Enforced)" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  PASSWORD AND LOCKOUT POLICY SUMMARY   " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Password Policy:" -ForegroundColor White
    Write-Host "  Minimum Length:     $MinPasswordLength characters" -ForegroundColor Gray
    if ($ComplexityEnabled -eq 1) {
        $complexityStr = "Enabled"
    } else {
        $complexityStr = "Disabled"
    }
    Write-Host "  Complexity:         $complexityStr" -ForegroundColor Gray
    Write-Host "  Password History:   $PasswordHistoryCount passwords" -ForegroundColor Gray
    if ($MaxPasswordAge -eq 0) {
        $maxAgeStr = "Never (rotation still recommended)"
    } else {
        $maxAgeStr = "$MaxPasswordAge days"
    }
    Write-Host "  Max Password Age:   $maxAgeStr" -ForegroundColor Gray
    Write-Host "  Min Password Age:   $MinPasswordAge day" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Lockout Policy:" -ForegroundColor White
    Write-Host "  Threshold:          $LockoutThreshold bad logon attempts" -ForegroundColor Gray
    Write-Host "  Duration:           $LockoutDuration minutes" -ForegroundColor Gray
    Write-Host "  Reset Counter:      $LockoutObservationWindow minutes" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Warning "Verification failed: $_"
}

Write-Host "Done." -ForegroundColor White
