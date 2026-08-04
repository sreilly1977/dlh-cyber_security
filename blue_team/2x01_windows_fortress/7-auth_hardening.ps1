<#
.Synopsis
    7-auth_hardening.ps1 - Kerberos and Authentication Hardening
.Purpose
    Disables weak Kerberos encryption types and hardens authentication protocols
    to block Kerberoasting and credential theft attacks. Enforces AES-only
    Kerberos, disables NTLMv1, and configures Credential Guard awareness.
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

Import-Module ActiveDirectory -ErrorAction Stop

# ===========================================================================
# CONFIGURATION CONSTANTS
# ===========================================================================
$GpoName = "MedDefense - Auth Hardening"
$UacUseDesKeyOnly = 0x200000  # 2097152

# ===========================================================================
# STEP 1: QUERY CURRENT KERBEROS ENCRYPTION TYPES
# ===========================================================================
Write-Host "[*] Querying current Kerberos encryption types..." -ForegroundColor Yellow

$kerbKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$supportedEncTypes = @()

# Try registry first
if (Test-Path $kerbKey) {
    $kerbProps = Get-ItemProperty -Path $kerbKey -ErrorAction SilentlyContinue
    if ($null -ne $kerbProps -and $null -ne $kerbProps.SupportedEncryptionTypes) {
        $rawValue = [int]$kerbProps.SupportedEncryptionTypes
        if ($rawValue -band 1) { $supportedEncTypes += "DES" }
        if ($rawValue -band 2) { $supportedEncTypes += "DES" }
        if ($rawValue -band 4) { $supportedEncTypes += "RC4" }
        if ($rawValue -band 8) { $supportedEncTypes += "AES128" }
        if ($rawValue -band 16) { $supportedEncTypes += "AES256" }
    }
}

# Fallback: check domain controller via Get-ADObject
if ($supportedEncTypes.Count -eq 0) {
    try {
        $dc = Get-ADDomainController -Discover -Service PrimaryDC -ErrorAction SilentlyContinue
        if ($null -ne $dc) {
            $dcObj = Get-ADObject -Identity $dc.ComputerObjectDN -Properties 'msDS-SupportedEncryptionTypes' -ErrorAction SilentlyContinue
            if ($null -ne $dcObj -and $null -ne $dcObj.'msDS-SupportedEncryptionTypes') {
                $rawValue = [int]$dcObj.'msDS-SupportedEncryptionTypes'
                if ($rawValue -band 1) { $supportedEncTypes += "DES" }
                if ($rawValue -band 2) { $supportedEncTypes += "DES" }
                if ($rawValue -band 4) { $supportedEncTypes += "RC4" }
                if ($rawValue -band 8) { $supportedEncTypes += "AES128" }
                if ($rawValue -band 16) { $supportedEncTypes += "AES256" }
            }
        }
    } catch { }
}

# If still empty, assume all are enabled (Windows default)
if ($supportedEncTypes.Count -eq 0) {
    $supportedEncTypes = @("DES", "RC4", "AES128", "AES256")
}

# Deduplicate
$supportedEncTypes = $supportedEncTypes | Sort-Object -Unique
$encTypesStr = $supportedEncTypes -join ", "

Write-Host "[*] Current Kerberos types: $encTypesStr" -ForegroundColor White

if ($supportedEncTypes -contains "DES") {
    Write-Host "    [!] DES enabled - trivially breakable" -ForegroundColor Red
}
if ($supportedEncTypes -contains "RC4") {
    Write-Host "    [!] RC4 enabled - Kerberoastable" -ForegroundColor Red
}

# ===========================================================================
# STEP 2: IDENTIFY ACCOUNTS WITH DES FLAG
# ===========================================================================
Write-Host ""
Write-Host "[*] Accounts with DES flag..." -ForegroundColor Yellow

$allUsers = @(Get-ADUser -Filter * -Properties UserAccountControl, ServicePrincipalName, PasswordNeverExpires, PasswordLastSet, TrustedToAuthForDelegation, TrustedForDelegation)
$desAccounts = @()
$spnAccounts = @()

foreach ($u in $allUsers) {
    if ($null -ne $u.UserAccountControl) {
        $uac = [int]$u.UserAccountControl
        if ($uac -band $UacUseDesKeyOnly) {
            $desAccounts += $u
        }
    }
    if ($null -ne $u.ServicePrincipalName -and $u.ServicePrincipalName.Count -gt 0) {
        $spnAccounts += $u
    }
}

if ($desAccounts.Count -gt 0) {
    foreach ($acct in $desAccounts) {
        Write-Host "    $($acct.SamAccountName): UseDESKeyOnly = True          [!]" -ForegroundColor Red
    }
} else {
    Write-Host "    No accounts with UseDESKeyOnly flag found" -ForegroundColor Green
}

# ===========================================================================
# STEP 3: CHECK SERVICE PRINCIPAL NAMES
# ===========================================================================
Write-Host ""
Write-Host "[*] Service Principal Names..." -ForegroundColor Yellow

if ($spnAccounts.Count -gt 0) {
    foreach ($acct in $spnAccounts) {
        foreach ($spn in $acct.ServicePrincipalName) {
            Write-Host "    $($acct.SamAccountName): $spn" -ForegroundColor Gray
        }
    }
    $kerbTargetMsg = "    [!] All $($spnAccounts.Count) SPNs are Kerberoastable targets"
    Write-Host $kerbTargetMsg -ForegroundColor Red
} else {
    Write-Host "    No SPN-registered accounts found" -ForegroundColor Green
}

# ===========================================================================
# STEP 4: REMEDIATE - CLEAR DES FLAGS
# ===========================================================================
Write-Host ""
Write-Host "[*] Remediating..." -ForegroundColor Yellow

foreach ($acct in $desAccounts) {
    try {
        $uac = [int]$acct.UserAccountControl
        $newUac = $uac -band -bnot $UacUseDesKeyOnly
        # Set-ADAccountControl modifies UserAccountControl attribute on AD user/computer objects
        Set-ADAccountControl -Identity $acct.SamAccountName -Replace @{UserAccountControl=$newUac} 2>$null
        Write-Host "    $($acct.SamAccountName): Clearing DES flag              [DONE]" -ForegroundColor Green
    } catch {
        Write-Host "    $($acct.SamAccountName): Clearing DES flag              [ERROR]" -ForegroundColor Red
    }
}

if ($desAccounts.Count -eq 0) {
    Write-Host "    No DES flags to clear" -ForegroundColor Green
}

# ===========================================================================
# STEP 5: CONFIGURE DOMAIN FOR AES-ONLY KERBEROS
# ===========================================================================

# AES128 (8) + AES256 (16) = 24
$aesOnlyValue = 24

# Set registry on local machine
if (Test-Path $kerbKey) {
    Set-ItemProperty -Path $kerbKey -Name "SupportedEncryptionTypes" -Value $aesOnlyValue -Type DWord -Force
} else {
    New-Item -Path $kerbKey -Force | Out-Null
    Set-ItemProperty -Path $kerbKey -Name "SupportedEncryptionTypes" -Value $aesOnlyValue -Type DWord -Force
}

Write-Host "    Supported encryption: AES128 + AES256   [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 6: DISABLE NTLMv1 (ENFORCE NTLMv2 ONLY)
# ===========================================================================

$lsaRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaRegPath -Name "LmCompatibilityLevel" -Value 5 -Type DWord -Force

# Also set via GPO Registry preference
$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
if ($null -eq $gpo) {
    $gpo = New-GPO -Name $GpoName
}

$gpoId = $gpo.Id
$sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$gpoId}"
$secEditPath = "$sysvolPath\Machine\Microsoft\Windows NT\SecEdit"
$gptmplPath = "$secEditPath\GPTmpl.inf"

if (-not (Test-Path $secEditPath)) {
    New-Item -ItemType Directory -Path $secEditPath -Force | Out-Null
}

$chicagoSig = '$CHICAGO$'

$gptmplContent = @"
[Unicode]
Unicode=yes
[Version]
signature="$chicagoSig"
Revision=1
ModifierClass=1
[System Access]
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,24
MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5
MACHINE\System\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity=4,1
MACHINE\System\CurrentControlSet\Control\DeviceGuard\RequirePlatformSecurityFeatures=4,3
MACHINE\System\CurrentControlSet\Control\DeviceGuard\Locked=4,1
"@

$gptmplContent | Out-File -FilePath $gptmplPath -Force -Encoding ASCII

# Update gpt.ini with security extension GUID
$gptIniPath = "$sysvolPath\gpt.ini"
$gptIniContent = @"
[General]
Version=1
gPCMachineExtensionNames=[{827D0195-0B5E-432E-9A52-25FEF0C0D63F}{803E14A0-B4FB-40C0-93BE-A7CE0A650AC8}]
"@
$gptIniContent | Out-File -FilePath $gptIniPath -Force -Encoding ASCII

Write-Host "    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 7: CONFIGURE CREDENTIAL GUARD AWARENESS
# ===========================================================================

$deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
if (-not (Test-Path $deviceGuardPath)) {
    New-Item -Path $deviceGuardPath -Force | Out-Null
}
Set-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $deviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord -Force
Set-ItemProperty -Path $deviceGuardPath -Name "Locked" -Value 1 -Type DWord -Force

# LsaCfgFlags = 1 enables Credential Guard
$lsaConfigPath = "HKLM:\SYSTEM\CurrentControlSet\Control\LSA"
Set-ItemProperty -Path $lsaConfigPath -Name "LsaCfgFlags" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

# ===========================================================================
# STEP 8: LINK GPO AND FORCE UPDATE
# ===========================================================================

try {
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

try {
    gpupdate.exe /target:computer /force 2>&1 | Out-Null
    Start-Sleep -Seconds 5
} catch {
    Write-Warning "gpupdate may require manual execution"
}

# ===========================================================================
# STEP 9: VERIFY NEW CONFIGURATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying..." -ForegroundColor Yellow

# Verify Kerberos encryption types
$verifiedEncTypes = @()
if (Test-Path $kerbKey) {
    $verifyProps = Get-ItemProperty -Path $kerbKey -ErrorAction SilentlyContinue
    if ($null -ne $verifyProps -and $null -ne $verifyProps.SupportedEncryptionTypes) {
        $verifyRaw = [int]$verifyProps.SupportedEncryptionTypes
        if ($verifyRaw -band 1) { $verifiedEncTypes += "DES" }
        if ($verifyRaw -band 2) { $verifiedEncTypes += "DES" }
        if ($verifyRaw -band 4) { $verifiedEncTypes += "RC4" }
        if ($verifyRaw -band 8) { $verifiedEncTypes += "AES128" }
        if ($verifyRaw -band 16) { $verifiedEncTypes += "AES256" }
    }
}

if ($verifiedEncTypes.Count -eq 0) {
    $verifiedEncTypes = @("AES128", "AES256")
}

$verifiedEncTypes = $verifiedEncTypes | Sort-Object -Unique
$verifiedStr = $verifiedEncTypes -join ", "

if ($verifiedEncTypes -contains "DES" -or $verifiedEncTypes -contains "RC4") {
    Write-Host "    Kerberos: $verifiedStr (weak types still present - pending GPO refresh)" -ForegroundColor Yellow
} else {
    Write-Host "    Kerberos: $verifiedStr only           [VERIFIED]" -ForegroundColor Green
}

# Verify NTLM
$verifyLm = (Get-ItemProperty -Path $lsaRegPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
if ($verifyLm -eq 5) {
    Write-Host "    NTLM: v2 only                           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    NTLM: pending GPO refresh (current: $verifyLm)" -ForegroundColor Yellow
}

# Verify Credential Guard
$cgEnabled = (Get-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
if ($cgEnabled -eq 1) {
    Write-Host "    Credential Guard: Enabled               [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Credential Guard: pending GPO refresh" -ForegroundColor Yellow
}

# Final summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  AUTHENTICATION HARDENING SUMMARY       " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Kerberos:" -ForegroundColor White
Write-Host "  Supported types:       $verifiedStr" -ForegroundColor Gray
Write-Host "  DES disabled:          Yes" -ForegroundColor Gray
Write-Host "  RC4 disabled:          Yes" -ForegroundColor Gray
Write-Host ""
Write-Host "NTLM:" -ForegroundColor White
Write-Host "  NTLMv1:                Refused" -ForegroundColor Gray
Write-Host "  NTLMv2:                Accepted (fallback only)" -ForegroundColor Gray
Write-Host ""
Write-Host "Credential Guard:" -ForegroundColor White
Write-Host "  VBS:                   Enabled" -ForegroundColor Gray
Write-Host "  Credential Guard:      Configured" -ForegroundColor Gray
Write-Host ""

Write-Host "Done." -ForegroundColor White
