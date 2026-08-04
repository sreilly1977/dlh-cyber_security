<#
.SYNOPSIS
    0-domain_baseline.ps1 - Active Directory Security Baseline Assessment
.PURPOSE
    Maps the complete security state of the MedDefense Active Directory domain,
    producing a structured report covering users, groups, service accounts,
    GPOs, password and lockout policies, Kerberos encryption, and privileged
    group membership.
.AUTHOR
    Steve - Cybersecurity Engineer
.DATE
    August 4, 2026
#>

param(
    [string]$OutputPath = ".\DomainBaseline_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$script:Findings = @()
$script:CriticalCount = 0
$script:HighCount = 0
$script:MediumCount = 0

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical", "High", "Medium")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category
    )

    $script:Findings += [PSCustomObject]@{
        Description = $Description
        Severity    = $Severity
        Category    = $Category
    }

    switch ($Severity) {
        "Critical" { $script:CriticalCount++ }
        "High"     { $script:HighCount++ }
        "Medium"   { $script:MediumCount++ }
    }
}

function Write-Section([string]$Title) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# ===========================================================================
# 1. DOMAIN INFORMATION
# ===========================================================================
Write-Host "[1/10] Gathering domain information..." -ForegroundColor Yellow

$domain = Get-ADDomain
$forest = Get-ADForest
$DCs    = Get-ADDomainController -Filter *

$domainFqdn = "$($domain.NetBIOSName).$($domain.DNSRoot)"

Write-Host "Domain:       $domainFqdn" -ForegroundColor Green
Write-Host "Forest Level: $($forest.ForestMode)" -ForegroundColor Gray
Write-Host "Domain Mode:  $($domain.DomainMode)" -ForegroundColor Gray
Write-Host "Domain Controllers:" -ForegroundColor Gray
foreach ($dc in $DCs) {
    Write-Host "  - $($dc.HostName) (Site: $($dc.Site))" -ForegroundColor Gray
}

# ===========================================================================
# 2. USER ACCOUNTS
# ===========================================================================
Write-Host ""
Write-Host "[2/10] Enumerating user accounts..." -ForegroundColor Yellow

$users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, TrustedToAuthForDelegation, CannotChangePassword

$enabledUsers    = @($users | Where-Object { $_.Enabled -eq $true })
$disabledUsers   = @($users | Where-Object { $_.Enabled -eq $false })
$pwNeverExpires  = @($users | Where-Object { $_.PasswordNeverExpires -eq $true })
$staleLogonUsers = @($users | Where-Object {
    $_.Enabled -eq $true -and
    $null -ne $_.LastLogonDate -and
    $_.LastLogonDate -lt (Get-Date).AddDays(-90)
})

Write-Host "User Accounts: $($users.Count)" -ForegroundColor Green
Write-Host "  Enabled:                $($enabledUsers.Count)" -ForegroundColor Gray
Write-Host "  Disabled:               $($disabledUsers.Count)" -ForegroundColor Gray
Write-Host "  Password Never Expires: $($pwNeverExpires.Count)" -ForegroundColor Red

if ($pwNeverExpires.Count -gt 0) {
    foreach ($u in $pwNeverExpires) {
        Write-Host "    - $($u.SamAccountName)" -ForegroundColor DarkRed
    }
    Add-Finding -Description "$($pwNeverExpires.Count) user accounts have 'PasswordNeverExpires' flag set" -Severity "High" -Category "Credential Management"
}

if ($staleLogonUsers.Count -gt 0) {
    Add-Finding -Description "$($staleLogonUsers.Count) enabled user accounts have not logged on in 90+ days" -Severity "Medium" -Category "Account Hygiene"
}

# ===========================================================================
# 3. GROUPS AND MEMBERS
# ===========================================================================
Write-Host ""
Write-Host "[3/10] Analyzing groups..." -ForegroundColor Yellow

$groups = @(Get-ADGroup -Filter * | Where-Object { $_.GroupScope -ne "Distribution" })

Write-Host "Security Groups: $($groups.Count)" -ForegroundColor Green

foreach ($grp in $groups) {
    $members = @(Get-ADGroupMember -Identity $grp.SamAccountName -ErrorAction SilentlyContinue)
    if ($members.Count -gt 0) {
        Write-Host "  Group: $($grp.Name) ($($members.Count) members)" -ForegroundColor Gray
    }
}

# ===========================================================================
# 4. SERVICE ACCOUNTS
# ===========================================================================
Write-Host ""
Write-Host "[4/10] Identifying service accounts..." -ForegroundColor Yellow

$svcAccounts = @($users | Where-Object {
    $_.SamAccountName -like "*svc*" -or
    $_.DistinguishedName -like "*OU=Service Accounts*"
})

$unconstrainedDeleg = @($svcAccounts | Where-Object { $_.TrustedToAuthForDelegation -eq $true })

Write-Host "Service Accounts: $($svcAccounts.Count)" -ForegroundColor Green

foreach ($svc in $svcAccounts) {
    $delegStr = if ($svc.TrustedToAuthForDelegation) { "UNCONSTRAINED" } else { "None" }
    $pwExpire = if ($svc.PasswordNeverExpires) { "NeverExpires" } else { "Expires" }
    Write-Host "  - $($svc.SamAccountName)" -ForegroundColor Gray
    Write-Host "      Delegation: $delegStr  |  Password: $pwExpire" -ForegroundColor Gray
}

Write-Host "  Unconstrained Delegation: $($unconstrainedDeleg.Count)" -ForegroundColor Red

if ($unconstrainedDeleg.Count -gt 0) {
    Add-Finding -Description "$($unconstrainedDeleg.Count) service account(s) have unconstrained delegation enabled" -Severity "Critical" -Category "Privilege Escalation"
}

$svcPwNever = @($svcAccounts | Where-Object { $_.PasswordNeverExpires -eq $true })
if ($svcPwNever.Count -gt 0) {
    Add-Finding -Description "$($svcPwNever.Count) service account(s) have PasswordNeverExpires set" -Severity "High" -Category "Service Account Security"
}

# ===========================================================================
# 5. GROUP POLICY OBJECTS
# ===========================================================================
Write-Host ""
Write-Host "[5/10] Retrieving GPOs..." -ForegroundColor Yellow

$gpos = @(Get-GPO -All)

Write-Host "GPOs: $($gpos.Count)" -ForegroundColor Green

foreach ($gpo in $gpos) {
    Write-Host "  - $($gpo.DisplayName)  [Status: $($gpo.GpoStatus)]" -ForegroundColor Gray
}

$nonDefaultGpos = @($gpos | Where-Object {
    $_.DisplayName -notmatch "Default" -and
    $_.DisplayName -notmatch "Default Domain"
})
$defaultOnly = $nonDefaultGpos.Count -eq 0

if ($defaultOnly) {
    Write-Host "  (Default only)" -ForegroundColor DarkGray
    Add-Finding -Description "Only default GPOs are configured - no custom security policies detected" -Severity "Medium" -Category "Configuration Management"
}

# ===========================================================================
# 6. PASSWORD POLICY
# ===========================================================================
Write-Host ""
Write-Host "[6/10] Checking password policy..." -ForegroundColor Yellow

$pwdPolicy = Get-ADDefaultDomainPasswordPolicy

$minLen     = $pwdPolicy.MinPasswordLength
$complexity = $pwdPolicy.ComplexityEnabled
$historyCnt = $pwdPolicy.PasswordHistoryCount
$maxAgeDays = [int]$pwdPolicy.MaxPasswordAge.TotalDays
$minAgeDays = [int]$pwdPolicy.MinPasswordAge.TotalDays

Write-Host "Password Minimum Length: $minLen" -ForegroundColor $(if ($minLen -lt 12) { "Red" } else { "Green" })
Write-Host "Complexity:              $(if ($complexity) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($complexity) { "Green" } else { "Red" })
Write-Host "Password History Count:  $historyCnt" -ForegroundColor Gray
Write-Host "Maximum Password Age:    $maxAgeDays days" -ForegroundColor Gray
Write-Host "Minimum Password Age:    $minAgeDays days" -ForegroundColor Gray

if ($minLen -lt 12) {
    Add-Finding -Description "Password minimum length ($minLen) is below recommended 12 characters" -Severity "High" -Category "Authentication"
}

if (-not $complexity) {
    Add-Finding -Description "Password complexity requirements are disabled" -Severity "Critical" -Category "Authentication"
}

if ($maxAgeDays -eq 0 -or $maxAgeDays -gt 90) {
    Add-Finding -Description "Password maximum age ($maxAgeDays days) exceeds 90 days or is set to never expire" -Severity "Medium" -Category "Authentication"
}

if ($historyCnt -lt 5) {
    Add-Finding -Description "Password history count ($historyCnt) is below recommended minimum of 5" -Severity "Medium" -Category "Authentication"
}

# ===========================================================================
# 7. ACCOUNT LOCKOUT POLICY
# ===========================================================================
Write-Host ""
Write-Host "[7/10] Checking account lockout policy..." -ForegroundColor Yellow

$lockoutThreshold = $pwdPolicy.LockoutThreshold
$lockoutDuration  = $pwdPolicy.LockoutDuration
$lockoutWindow    = $pwdPolicy.LockoutObservationWindow

if ($lockoutThreshold -eq 0) {
    Write-Host "Lockout Threshold: NOT CONFIGURED" -ForegroundColor Red
    Add-Finding -Description "Account lockout threshold is set to 0 - brute force attacks are unrestricted" -Severity "Critical" -Category "Authentication"
} else {
    Write-Host "Lockout Threshold:          $lockoutThreshold attempts" -ForegroundColor $(if ($lockoutThreshold -lt 5) { "Red" } else { "Green" })
}

Write-Host "Lockout Duration:          $([int]$lockoutDuration.TotalMinutes) minutes" -ForegroundColor Gray
Write-Host "Lockout Observation Window: $([int]$lockoutWindow.TotalMinutes) minutes" -ForegroundColor Gray

# ===========================================================================
# 8. KERBEROS ENCRYPTION TYPES
# ===========================================================================
Write-Host ""
Write-Host "[8/10] Checking Kerberos encryption types..." -ForegroundColor Yellow

$kerbKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
$kerbProps = $null

if (Test-Path $kerbKey) {
    $kerbProps = Get-ItemProperty -Path $kerbKey -ErrorAction SilentlyContinue
}

$encryptionMap = [ordered]@{
    1  = "DES-CBC-MD5"
    2  = "DES-CBC-SHA1"
    4  = "RC4-HMAC"
    8  = "AES128-HMAC-SHA1"
    16 = "AES256-HMAC-SHA1"
}

$enabledEnc = @()

if ($null -ne $kerbProps -and $null -ne $kerbProps.supportedEncryptionTypes) {
    $rawValue = [int]$kerbProps.supportedEncryptionTypes
    foreach ($bit in $encryptionMap.Keys) {
        if ($rawValue -band $bit) {
            $enabledEnc += $encryptionMap[$bit]
        }
    }
}

if ($enabledEnc.Count -eq 0) {
    Write-Host "Kerberos: No explicit encryption types configured - OS default applies" -ForegroundColor Yellow
    $kerbDisplay = "Default (OS-dependent)"
} else {
    $kerbDisplay = $enabledEnc -join ", "
    Write-Host "Kerberos: $kerbDisplay" -ForegroundColor $(if (($enabledEnc -match "DES") -or ($enabledEnc -match "RC4")) { "Red" } else { "Green" })
}

if ($enabledEnc -contains "DES-CBC-MD5" -or $enabledEnc -contains "DES-CBC-SHA1") {
    Add-Finding -Description "DES Kerberos encryption types are enabled - these are cryptographically broken" -Severity "Critical" -Category "Cryptography"
}

if ($enabledEnc -contains "RC4-HMAC") {
    Add-Finding -Description "RC4-HMAC Kerberos encryption is enabled - vulnerable to Kerberoasting attacks" -Severity "High" -Category "Cryptography"
}

if (-not ($enabledEnc -contains "AES256-HMAC-SHA1")) {
    Add-Finding -Description "AES256 Kerberos encryption not explicitly enabled" -Severity "Medium" -Category "Cryptography"
}

# ===========================================================================
# 9. PRIVILEGED USERS (Domain Admins / Enterprise Admins)
# ===========================================================================
Write-Host ""
Write-Host "[9/10] Identifying privileged users..." -ForegroundColor Yellow

$domAdminDNs    = @(Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction SilentlyContinue)
$entAdminDNs    = @(Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue)
$schemaAdminDNs = @(Get-ADGroupMember -Identity "Schema Admins" -Recursive -ErrorAction SilentlyContinue)

$domAdminUsers    = @($domAdminDNs    | Where-Object { $_.ObjectClass -eq "user" })
$entAdminUsers    = @($entAdminDNs    | Where-Object { $_.ObjectClass -eq "user" })
$schemaAdminUsers = @($schemaAdminDNs | Where-Object { $_.ObjectClass -eq "user" })

Write-Host "Domain Admins ($($domAdminUsers.Count)):" -ForegroundColor Cyan
foreach ($m in $domAdminUsers) {
    Write-Host "  - $($m.SamAccountName)" -ForegroundColor Yellow
}

Write-Host "Enterprise Admins ($($entAdminUsers.Count)):" -ForegroundColor Cyan
if ($entAdminUsers.Count -eq 0) {
    Write-Host "  (Empty - good practice)" -ForegroundColor Green
} else {
    foreach ($m in $entAdminUsers) {
        Write-Host "  - $($m.SamAccountName)" -ForegroundColor Yellow
    }
}

Write-Host "Schema Admins ($($schemaAdminUsers.Count)):" -ForegroundColor Cyan
if ($schemaAdminUsers.Count -eq 0) {
    Write-Host "  (Empty - good practice)" -ForegroundColor Green
} else {
    foreach ($m in $schemaAdminUsers) {
        Write-Host "  - $($m.SamAccountName)" -ForegroundColor Yellow
    }
}

$totalPrivileged = $domAdminUsers.Count + $entAdminUsers.Count + $schemaAdminUsers.Count
if ($totalPrivileged -gt 5) {
    Add-Finding -Description "Total privileged users ($totalPrivileged) across Domain/Enterprise/Schema Admins exceeds 5" -Severity "High" -Category "Access Control"
}

$builtinAdmin = Get-ADUser -Identity "Administrator" -Properties PasswordNeverExpires -ErrorAction SilentlyContinue
if ($null -ne $builtinAdmin -and $builtinAdmin.PasswordNeverExpires -eq $true) {
    Add-Finding -Description "Built-in Administrator account has PasswordNeverExpires enabled" -Severity "Medium" -Category "Account Hardening"
}

# ===========================================================================
# 10. SUMMARY REPORT
# ===========================================================================
Write-Host ""
Write-Host "[10/10] Generating summary..." -ForegroundColor Yellow

$totalFindings = $script:Findings.Count

# Safely extract DC hostname
$dcName = if ($DCs.Count -gt 0) { $DCs[0].HostName } else { "Unknown" }

Write-Section "SECURITY BASELINE SUMMARY"

Write-Host ""
Write-Host "Domain:               $domainFqdn" -ForegroundColor White
Write-Host "DC:                   $dcName" -ForegroundColor White
Write-Host "User Accounts:        $($users.Count)" -ForegroundColor White
Write-Host "  Password Never Expires: $($pwNeverExpires.Count)" -ForegroundColor Yellow
Write-Host "Service Accounts:     $($svcAccounts.Count)" -ForegroundColor White
Write-Host "  Unconstrained Delegation: $($unconstrainedDeleg.Count)" -ForegroundColor Red
Write-Host "GPOs:                 $($gpos.Count)$(if ($defaultOnly) { ' (Default only)' })" -ForegroundColor White
Write-Host "Password Min Length:  $minLen" -ForegroundColor White
Write-Host "Complexity:           $(if ($complexity) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
Write-Host "Lockout Threshold:    $(if ($lockoutThreshold -eq 0) { 'NOT CONFIGURED' } else { $lockoutThreshold })" -ForegroundColor White
Write-Host "Kerberos:             $kerbDisplay" -ForegroundColor White
Write-Host "Domain Admins:        $($domAdminUsers.SamAccountName -join ', ')" -ForegroundColor White
Write-Host "Findings:             $totalFindings (Critical: $($script:CriticalCount), High: $($script:HighCount), Medium: $($script:MediumCount))" -ForegroundColor $(if ($script:CriticalCount -gt 0) { "Red" } else { "Green" })

if ($totalFindings -gt 0) {
    Write-Host ""
    Write-Host "DETAILED FINDINGS:" -ForegroundColor Cyan
    foreach ($f in $script:Findings) {
        $color = switch ($f.Severity) {
            "Critical" { "Red" }
            "High"     { "DarkYellow" }
            "Medium"   { "Yellow" }
            default    { "Gray" }
        }
        Write-Host "  [$($f.Severity)] $($f.Description)  (Category: $($f.Category))" -ForegroundColor $color
    }
}

# ---------------------------------------------------------------------------
# JSON Export
# ---------------------------------------------------------------------------
$report = [PSCustomObject]@{
    Domain             = $domainFqdn
    ForestLevel        = $forest.ForestMode
    DomainMode         = $domain.DomainMode
    DomainControllers  = @($DCs | ForEach-Object { $_.HostName })
    TotalUsers         = $users.Count
    EnabledUsers       = $enabledUsers.Count
    DisabledUsers      = $disabledUsers.Count
    PwNeverExpires     = $pwNeverExpires.Count
    ServiceAccounts    = $svcAccounts.Count
    UnconstrainedDeleg = $unconstrainedDeleg.Count
    GPOCount           = $gpos.Count
    GPOs               = @($gpos | ForEach-Object { $_.DisplayName })
    PasswordPolicy     = [PSCustomObject]@{
        MinLength         = $minLen
        ComplexityEnabled = $complexity
        HistoryCount      = $historyCnt
        MaxAgeDays        = $maxAgeDays
        MinAgeDays        = $minAgeDays
    }
    LockoutPolicy      = [PSCustomObject]@{
        Threshold        = $lockoutThreshold
        DurationMinutes  = [int]$lockoutDuration.TotalMinutes
        ObsWindowMinutes = [int]$lockoutWindow.TotalMinutes
    }
    KerberosEncryption = $kerbDisplay
    DomainAdmins       = @($domAdminUsers.SamAccountName)
    EnterpriseAdmins   = @($entAdminUsers.SamAccountName)
    SchemaAdmins       = @($schemaAdminUsers.SamAccountName)
    Findings           = $script:Findings
    FindingSummary     = [PSCustomObject]@{
        Total    = $totalFindings
        Critical = $script:CriticalCount
        High     = $script:HighCount
        Medium   = $script:MediumCount
    }
    Timestamp          = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
}

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Force -Encoding UTF8

Write-Host ""
Write-Host "JSON report exported to: $OutputPath" -ForegroundColor Green
Write-Host ""
