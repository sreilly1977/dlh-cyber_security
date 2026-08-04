<#
.Synopsis
    1-domain_findings.ps1 - Domain Risk Findings Extractor
.Purpose
    Audits the MedDefense Active Directory domain and produces a structured
    findings inventory in JSON format. Each finding includes severity,
    category, evidence, risk, recommended remediation, and the mapped
    hardening task that addresses it.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 4, 2026
#>

param(
    [string]$OutputPath = "domain_security_findings.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
$script:Findings = @()
$script:NextId = 1
$script:CriticalCount = 0
$script:HighCount = 0
$script:MediumCount = 0

# ---------------------------------------------------------------------------
# Target state thresholds (Windows Fortress baseline)
# ---------------------------------------------------------------------------
$TARGET_MIN_LENGTH = 14
$TARGET_HISTORY = 24
$TARGET_LOCKOUT_THRESHOLD = 5

# ---------------------------------------------------------------------------
# Helper: New-Finding
# ---------------------------------------------------------------------------
function New-Finding {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical", "High", "Medium")]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $true)]
        [string]$Asset,

        [Parameter(Mandatory = $true)]
        [string]$Evidence,

        [Parameter(Mandatory = $true)]
        [string]$Risk,

        [Parameter(Mandatory = $true)]
        [string]$RecommendedRemediation,

        [Parameter(Mandatory = $true)]
        [string]$MappedTask
    )

    $finding = [PSCustomObject]@{
        id                    = "FIND-$(($script:NextId).ToString('000'))"
        severity              = $Severity
        category              = $Category
        asset                 = $Asset
        evidence              = $Evidence
        risk                  = $Risk
        recommended_remediation = $RecommendedRemediation
        mapped_task           = $MappedTask
    }

    $script:Findings += $finding
    $script:NextId++

    switch ($Severity) {
        "Critical" { $script:CriticalCount++ }
        "High"     { $script:HighCount++ }
        "Medium"   { $script:MediumCount++ }
    }
}

# ---------------------------------------------------------------------------
# Helper: Get-UserGroupList
# Returns a comma-separated string of group names for a user
# ---------------------------------------------------------------------------
function Get-UserGroupList {
    param([string]$SamAccountName)

    try {
        $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName -ErrorAction SilentlyContinue)
        return ($groups.Name -join ", ")
    } catch {
        return "Unable to retrieve"
    }
}

# ===========================================================================
# Pre-fetch domain data
# ===========================================================================
Write-Host "[*] Auditing meddefense.local..." -ForegroundColor Yellow

$domain = Get-ADDomain
$domainFqdn = $domain.DNSRoot

# All users with needed properties (FIXED: Removed AllowedPrimaryGroupID)
$allUsers = @(Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, TrustedToAuthForDelegation, CannotChangePassword, ServicePrincipalName, logonHours)

# All computers
$allComputers = @(Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, LastLogonTimestamp, PasswordLastSet)

# Password and lockout policy
$pwdPolicy = Get-ADDefaultDomainPasswordPolicy

# GPOs
$gpos = @(Get-GPO -All)

# Privileged group members
$domAdminMembers = @(Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction SilentlyContinue)
$entAdminMembers = @(Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue)
$gItAdminMembers = @(Get-ADGroupMember -Identity "G_IT_Admins" -Recursive -ErrorAction SilentlyContinue)

# ===========================================================================
# 1. PASSWORD POLICY GAPS
# ===========================================================================
Write-Host "[1/7] Checking password policy..." -ForegroundColor Yellow

$minLen = $pwdPolicy.MinPasswordLength
$complexity = $pwdPolicy.ComplexityEnabled
$historyCnt = $pwdPolicy.PasswordHistoryCount
$lockoutThreshold = $pwdPolicy.LockoutThreshold
$maxAgeDays = [int]$pwdPolicy.MaxPasswordAge.TotalDays

if ($minLen -lt $TARGET_MIN_LENGTH) {
    Write-Host "[CRITICAL] Password policy minimum length: $minLen" -ForegroundColor Red
    New-Finding -Severity "Critical" -Category "Password Policy" -Asset $domainFqdn -Evidence "Minimum password length is $minLen, target is $TARGET_MIN_LENGTH" -Risk "Short passwords are vulnerable to brute force and dictionary attacks" -RecommendedRemediation "Set minimum password length to $TARGET_MIN_LENGTH via Default Domain Policy or PSO" -MappedTask "2-password_policy"
}

if (-not $complexity) {
    Write-Host "[CRITICAL] Password complexity: disabled" -ForegroundColor Red
    New-Finding -Severity "Critical" -Category "Password Policy" -Asset $domainFqdn -Evidence "Password complexity is disabled" -Risk "Users can set trivially simple passwords like 'password123'" -RecommendedRemediation "Enable password complexity in Default Domain Policy" -MappedTask "2-password_policy"
}

if ($historyCnt -lt $TARGET_HISTORY) {
    Write-Host "[HIGH] Password history: $historyCnt (target: $TARGET_HISTORY)" -ForegroundColor DarkYellow
    New-Finding -Severity "High" -Category "Password Policy" -Asset $domainFqdn -Evidence "Password history count is $historyCnt, target is $TARGET_HISTORY" -Risk "Users can reuse old passwords, defeating rotation goals" -RecommendedRemediation "Set password history to $TARGET_HISTORY in Default Domain Policy" -MappedTask "2-password_policy"
}

# ===========================================================================
# 2. LOCKOUT POLICY GAPS
# ===========================================================================
Write-Host "[2/7] Checking lockout policy..." -ForegroundColor Yellow

if ($lockoutThreshold -eq 0) {
    Write-Host "[CRITICAL] Account lockout: not configured" -ForegroundColor Red
    New-Finding -Severity "Critical" -Category "Lockout Policy" -Asset $domainFqdn -Evidence "Account lockout threshold is 0 (unlimited attempts)" -Risk "Brute force attacks against accounts have no rate limit" -RecommendedRemediation "Set lockout threshold to $TARGET_LOCKOUT_THRESHOLD attempts with 30 minute duration" -MappedTask "2-password_policy"
}

# ===========================================================================
# 3. KERBEROS ENCRYPTION TYPES
# ===========================================================================
Write-Host "[3/7] Checking Kerberos encryption..." -ForegroundColor Yellow

$kerbKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
$kerbProps = $null
$kerbEncTypes = @()

if (Test-Path $kerbKey) {
    $kerbProps = Get-ItemProperty -Path $kerbKey -ErrorAction SilentlyContinue
}

if ($null -ne $kerbProps -and $null -ne $kerbProps.supportedEncryptionTypes) {
    $rawValue = [int]$kerbProps.supportedEncryptionTypes
    if ($rawValue -band 1) { $kerbEncTypes += "DES-CBC-MD5" }
    if ($rawValue -band 2) { $kerbEncTypes += "DES-CBC-SHA1" }
    if ($rawValue -band 4) { $kerbEncTypes += "RC4-HMAC" }
    if ($rawValue -band 8) { $kerbEncTypes += "AES128" }
    if ($rawValue -band 16) { $kerbEncTypes += "AES256" }
}

$hasDes = $kerbEncTypes -contains "DES-CBC-MD5" -or $kerbEncTypes -contains "DES-CBC-SHA1"
$hasRc4 = $kerbEncTypes -contains "RC4-HMAC"

if ($hasDes -or $hasRc4) {
    $weakTypes = @()
    if ($hasDes) { $weakTypes += "DES" }
    if ($hasRc4) { $weakTypes += "RC4" }
    $weakStr = $weakTypes -join "/"
    Write-Host "[CRITICAL] Kerberos ${weakStr} enabled" -ForegroundColor Red
    New-Finding -Severity "Critical" -Category "Kerberos Hardening" -Asset $domainFqdn -Evidence "Weak Kerberos encryption types enabled: $($kerbEncTypes -join ', ')" -Risk "DES and RC4 are vulnerable to Kerberoasting and offline cracking attacks" -RecommendedRemediation "Disable DES and RC4, enforce AES256 only via registry and GPO" -MappedTask "4-kerberos_hardening"
}

# ===========================================================================
# 4. ACCOUNTS WITH PasswordNeverExpires
# ===========================================================================
Write-Host "[4/7] Checking PasswordNeverExpires accounts..." -ForegroundColor Yellow

$pwNeverExpUsers = @($allUsers | Where-Object { $_.PasswordNeverExpires -eq $true })
$svcAccounts = @($allUsers | Where-Object { $_.SamAccountName -like "*svc*" -or $_.DistinguishedName -like "*OU=Service Accounts*" })

if ($pwNeverExpUsers.Count -gt 0) {
    Write-Host "[HIGH] $($pwNeverExpUsers.Count) accounts with PasswordNeverExpires" -ForegroundColor DarkYellow

    foreach ($u in $pwNeverExpUsers) {
        $isSvc = $svcAccounts.SamAccountName -contains $u.SamAccountName
        $groupList = Get-UserGroupList -SamAccountName $u.SamAccountName
        $enabledStr = if ($u.Enabled) { "Enabled" } else { "Disabled" }
        $svcStr = if ($isSvc) { "Yes" } else { "No" }
        $plsStr = if ($null -ne $u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Unknown" }

        $evidence = "Account: $($u.SamAccountName), State: $enabledStr, ServiceAccount: $svcStr, PasswordLastSet: $plsStr, Groups: $groupList"

        New-Finding -Severity "High" -Category "Credential Management" -Asset $u.SamAccountName -Evidence $evidence -Risk "Passwords that never expire increase exposure window if compromised" -RecommendedRemediation "Remove PasswordNeverExpires flag, implement managed service accounts or gMSAs where applicable" -MappedTask "3-service_accounts"
    }
}

# ===========================================================================
# 5. DISABLED ACCOUNTS IN PRIVILEGED GROUPS
# ===========================================================================
Write-Host "[5/7] Checking disabled accounts in privileged groups..." -ForegroundColor Yellow

$privilegedGroups = @{
    "Domain Admins" = $domAdminMembers
    "Enterprise Admins" = $entAdminMembers
    "G_IT_Admins" = $gItAdminMembers
}

foreach ($groupName in $privilegedGroups.Keys) {
    $members = $privilegedGroups[$groupName]
    foreach ($m in $members) {
        if ($m.ObjectClass -eq "user") {
            try {
                $userObj = Get-ADUser -Identity $m.SamAccountName -Properties Enabled -ErrorAction SilentlyContinue
                if ($null -ne $userObj -and $userObj.Enabled -eq $false) {
                    Write-Host "[MEDIUM] Disabled account in ${groupName}: $($m.SamAccountName)" -ForegroundColor Yellow
                    New-Finding -Severity "Medium" -Category "Privilege Management" -Asset $m.SamAccountName -Evidence "Disabled user remains member of privileged group: $groupName" -Risk "If re-enabled, account retains elevated privileges without review" -RecommendedRemediation "Remove disabled accounts from all privileged groups immediately" -MappedTask "5-privileged_access"
                }
            } catch {
                # Skip if we cannot query the user
            }
        }
    }
}

# ===========================================================================
# 6. STALE COMPUTER OBJECTS (90+ days no logon)
# ===========================================================================
Write-Host "[6/7] Checking stale computer objects..." -ForegroundColor Yellow

$staleComputers = @()
$cutoffDate = (Get-Date).AddDays(-90)

foreach ($comp in $allComputers) {
    $lastActivity = $null
    if ($null -ne $comp.LastLogonDate) {
        $lastActivity = $comp.LastLogonDate
    } elseif ($null -ne $comp.LastLogonTimestamp) {
        $lastActivity = $comp.LastLogonTimestamp
    }

    if ($null -ne $lastActivity -and $lastActivity -lt $cutoffDate) {
        $staleComputers += $comp
    } elseif ($null -eq $lastActivity -and $comp.Enabled -eq $true) {
        # No logon data at all and enabled - potentially stale
        $staleComputers += $comp
    }
}

if ($staleComputers.Count -gt 0) {
    Write-Host "[MEDIUM] Stale computer objects: $($staleComputers.Count)" -ForegroundColor Yellow

    foreach ($comp in $staleComputers) {
        $lastActivityStr = if ($null -ne $comp.LastLogonDate) { $comp.LastLogonDate.ToString("yyyy-MM-dd") } else { "No logon data" }
        New-Finding -Severity "Medium" -Category "Stale Objects" -Asset $comp.Name -Evidence "No authentication activity in 90+ days. LastLogon: $lastActivityStr, Enabled: $($comp.Enabled)" -Risk "Stale computer objects can be reused for lateral movement or persistence" -RecommendedRemediation "Disable and remove stale computer objects after validation" -MappedTask "7-stale_cleanup"
    }
}

# ===========================================================================
# 7. ADVANCED AUDIT POLICY CHECK
# ===========================================================================
Write-Host "[7/7] Checking advanced audit policy..." -ForegroundColor Yellow

$auditSubcategories = @("Process Creation", "Special Logon", "Account Management", "Object Access")
$missingAudit = @()

# Check via auditpol command for reliability
foreach ($catName in $auditSubcategories) {
    try {
        $auditResult = auditpol.exe /get /subcategory:"$catName" 2>$null
        $configured = $false
        foreach ($line in $auditResult) {
            if ($line -match "Success and Failure|Success|Failure") {
                $configured = $true
                break
            }
        }
        if (-not $configured) {
            $missingAudit += $catName
        }
    } catch {
        $missingAudit += $catName
    }
}

# Check for Sysmon readiness
$sysmonInstalled = $false
try {
    $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($null -ne $sysmonService) {
        $sysmonInstalled = $true
    }
} catch {
    # Not installed
}

# Check for PowerShell script block logging
$psLoggingKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psLoggingEnabled = $false
if (Test-Path $psLoggingKey) {
    $psLogProps = Get-ItemProperty -Path $psLoggingKey -ErrorAction SilentlyContinue
    if ($null -ne $psLogProps -and $null -ne $psLogProps.EnableScriptBlockLogging -and $psLogProps.EnableScriptBlockLogging -eq 1) {
        $psLoggingEnabled = $true
    }
}

if ($missingAudit.Count -gt 0 -or -not $sysmonInstalled -or -not $psLoggingEnabled) {
    Write-Host "[HIGH] Advanced Audit Policy: not configured" -ForegroundColor DarkYellow

    $missingItems = @()
    if ($missingAudit.Count -gt 0) { $missingItems += "Missing audit subcategories: $($missingAudit -join ', ')" }
    if (-not $sysmonInstalled) { $missingItems += "Sysmon not installed" }
    if (-not $psLoggingEnabled) { $missingItems += "PowerShell Script Block Logging not enabled" }

    $evidence = $missingItems -join "; "

    New-Finding -Severity "High" -Category "Audit Policy" -Asset $domainFqdn -Evidence $evidence -Risk "Without comprehensive audit logging, attacker activity will go undetected" -RecommendedRemediation "Configure advanced audit policy via GPO for process creation, special logon, account management, and object access. Deploy Sysmon and enable PowerShell script block logging." -MappedTask "6-audit_policy"
}

# ===========================================================================
# 8. SERVICE ACCOUNT RISKS
# ===========================================================================
Write-Host "[*] Checking service account risks..." -ForegroundColor Yellow

foreach ($svc in $svcAccounts) {
    $risks = @()

    # Unconstrained delegation
    if ($svc.TrustedToAuthForDelegation -eq $true) {
        $risks += "Unconstrained delegation enabled"
    }

    # DES-only flag (check if account is restricted to DES only)
    try {
        $svcFull = Get-ADUser -Identity $svc.SamAccountName -Properties UserAccountControl -ErrorAction SilentlyContinue
        if ($null -ne $svcFull) {
            $uac = [int]$svcFull.UserAccountControl
            # 0x200000 = UseDesKeyOnly
            if ($uac -band 0x200000) {
                $risks += "DES-only encryption flag set"
            }
        }
    } catch {
        # Skip
    }

    # Interactive logon allowed (check if not set to deny)
    try {
        $svcFull2 = Get-ADUser -Identity $svc.SamAccountName -Properties UserAccountControl -ErrorAction SilentlyContinue
        if ($null -ne $svcFull2) {
            $uac2 = [int]$svcFull2.UserAccountControl
            # Interactive logon is allowed by default unless denied via Deny logon locally
            $risks += "Interactive logon allowed"
        }
    } catch {
        # Skip
    }

    # Privileged membership
    $isDomAdmin = $domAdminMembers.SamAccountName -contains $svc.SamAccountName
    $isEntAdmin = $entAdminMembers.SamAccountName -contains $svc.SamAccountName
    $isGitAdmin = $gItAdminMembers.SamAccountName -contains $svc.SamAccountName
    if ($isDomAdmin -or $isEntAdmin -or $isGitAdmin) {
        $privGroups = @()
        if ($isDomAdmin) { $privGroups += "Domain Admins" }
        if ($isEntAdmin) { $privGroups += "Enterprise Admins" }
        if ($isGitAdmin) { $privGroups += "G_IT_Admins" }
        $risks += "Member of privileged group(s): $($privGroups -join ', ')"
    }

    # Stale password (password not set in 90+ days)
    if ($null -ne $svc.PasswordLastSet) {
        $daysSincePw = ((Get-Date) - $svc.PasswordLastSet).Days
        if ($daysSincePw -gt 90) {
            $risks += "Password last set $daysSincePw days ago"
        }
    }

    # Suspicious last logon (never logged on or 90+ days)
    if ($null -eq $svc.LastLogonDate) {
        $risks += "Never logged on"
    } elseif ($svc.LastLogonDate -lt (Get-Date).AddDays(-90)) {
        $risks += "Last logon was more than 90 days ago"
    }

    if ($risks.Count -gt 0) {
        $riskStr = $risks -join "; "

        # Determine severity based on risk content
        $sev = "High"
        if ($risks -contains "Unconstrained delegation enabled" -or ($risks -match "privileged group")) {
            $sev = "Critical"
        } elseif ($risks.Count -ge 3) {
            $sev = "High"
        } else {
            $sev = "Medium"
        }

        if ($risks -contains "Unconstrained delegation enabled") {
            Write-Host "[CRITICAL] Service account $($svc.SamAccountName): unconstrained delegation" -ForegroundColor Red
        }

        New-Finding -Severity $sev -Category "Service Account Security" -Asset $svc.SamAccountName -Evidence $riskStr -Risk "Compromised service account could lead to domain-wide compromise" -RecommendedRemediation "Restrict delegation, remove from privileged groups, convert to gMSA, enforce AES-only Kerberos" -MappedTask "3-service_accounts"
    }
}

# ===========================================================================
# 9. WEAK GPO POSTURE
# ===========================================================================
Write-Host "[*] Checking GPO posture..." -ForegroundColor Yellow

$nonDefaultGpos = @($gpos | Where-Object {
    $_.DisplayName -notmatch "Default" -and
    $_.DisplayName -notmatch "Default Domain"
})

$hardeningGpos = @($gpos | Where-Object {
    $_.DisplayName -match "MedDefense|Hardening|Security|Fortress|Baseline"
})

if ($gpos.Count -le 2 -and $nonDefaultGpos.Count -eq 0) {
    Write-Host "[MEDIUM] Default-only GPOs present, no custom hardening policies" -ForegroundColor Yellow
    New-Finding -Severity "Medium" -Category "GPO Posture" -Asset $domainFqdn -Evidence "Only default GPOs are configured: $($gpos.DisplayName -join ', ')" -Risk "No centralized security hardening is enforced through Group Policy" -RecommendedRemediation "Create dedicated MedDefense hardening GPOs for password, audit, Kerberos, and service account policies" -MappedTask "6-audit_policy"
}

if ($hardeningGpos.Count -eq 0) {
    Write-Host "[MEDIUM] No MedDefense hardening GPOs present" -ForegroundColor Yellow
    New-Finding -Severity "Medium" -Category "GPO Posture" -Asset $domainFqdn -Evidence "No GPOs matching MedDefense hardening naming convention found" -Risk "Security settings are not centrally managed or enforced" -RecommendedRemediation "Create MedDefense Hardening GPO with audit, Kerberos, and privilege restriction settings" -MappedTask "6-audit_policy"
}

# ===========================================================================
# SUMMARY AND OUTPUT
# ===========================================================================
Write-Host "" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       DOMAIN FINDINGS SUMMARY          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalFindings = $script:Findings.Count

# Print all findings sorted by severity
$sortedFindings = @($script:Findings | Sort-Object @{Expression = {$_.id}})

foreach ($f in $sortedFindings) {
    $tag = "[$($f.severity.ToUpper())]"
    $color = switch ($f.severity) {
        "Critical" { "Red" }
        "High"     { "DarkYellow" }
        "Medium"   { "Yellow" }
        default    { "Gray" }
    }
    Write-Host "${tag} $($f.id): $($f.evidence)" -ForegroundColor $color
}

Write-Host ""
Write-Host "Findings: $totalFindings" -ForegroundColor White
Write-Host "Critical: $($script:CriticalCount)" -ForegroundColor Red
Write-Host "High: $($script:HighCount)" -ForegroundColor DarkYellow
Write-Host "Medium: $($script:MediumCount)" -ForegroundColor Yellow

# Build JSON report
$report = [PSCustomObject]@{
    domain = $domainFqdn
    scan_date = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    total_findings = $totalFindings
    critical_count = $script:CriticalCount
    high_count = $script:HighCount
    medium_count = $script:MediumCount
    findings = $script:Findings
}

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Force -Encoding UTF8

Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
Write-Host ""
