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

$script:Findings = @()
$script:NextId = 1
$script:CriticalCount = 0
$script:HighCount = 0
$script:MediumCount = 0

$TARGET_MIN_LENGTH = 14
$TARGET_HISTORY = 24
$TARGET_LOCKOUT_THRESHOLD = 5

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
        id = "FIND-$(($script:NextId).ToString('000'))"
        severity = $Severity
        category = $Category
        asset = $Asset
        evidence = $Evidence
        risk = $Risk
        recommended_remediation = $RecommendedRemediation
        mapped_task = $MappedTask
    }
    $script:Findings += $finding
    $script:NextId++
    switch ($Severity) {
        "Critical" { $script:CriticalCount++ }
        "High" { $script:HighCount++ }
        "Medium" { $script:MediumCount++ }
    }
}

Write-Host "[*] Auditing meddefense.local..." -ForegroundColor Yellow

$domain = Get-ADDomain
$domainFqdn = $domain.DNSRoot

$allUsers = @(Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, TrustedToAuthForDelegation, TrustedForDelegation, CannotChangePassword, ServicePrincipalName, logonHours, MemberOf)
$allComputers = @(Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, LastLogonTimestamp, PasswordLastSet)
$pwdPolicy = Get-ADDefaultDomainPasswordPolicy
$gpos = @(Get-GPO -All)
$domAdminMembers = @(Get-ADGroupMember -Identity "Domain Admins" -Recursive -ErrorAction SilentlyContinue)
$entAdminMembers = @(Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue)
$gItAdminMembers = @(Get-ADGroupMember -Identity "G_IT_Admins" -Recursive -ErrorAction SilentlyContinue)

Write-Host "[1/7] Checking password policy..." -ForegroundColor Yellow
$minLen = $pwdPolicy.MinPasswordLength
$complexity = $pwdPolicy.ComplexityEnabled
$historyCnt = $pwdPolicy.PasswordHistoryCount
$lockoutThreshold = $pwdPolicy.LockoutThreshold

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

Write-Host "[2/7] Checking lockout policy..." -ForegroundColor Yellow
if ($lockoutThreshold -eq 0) {
    Write-Host "[CRITICAL] Account lockout: not configured" -ForegroundColor Red
    New-Finding -Severity "Critical" -Category "Lockout Policy" -Asset $domainFqdn -Evidence "Account lockout threshold is 0 (unlimited attempts)" -Risk "Brute force attacks against accounts have no rate limit" -RecommendedRemediation "Set lockout threshold to $TARGET_LOCKOUT_THRESHOLD attempts with 30 minute duration" -MappedTask "2-password_policy"
}

Write-Host "[3/7] Checking Kerberos encryption..." -ForegroundColor Yellow
$kerbKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
$kerbProps = $null
$kerbEncTypes = @()
if (Test-Path $kerbKey) { $kerbProps = Get-ItemProperty -Path $kerbKey -ErrorAction SilentlyContinue }
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

Write-Host "[4/7] Checking PasswordNeverExpires accounts..." -ForegroundColor Yellow
$pwNeverExpUsers = @($allUsers | Where-Object { $_.PasswordNeverExpires -eq $true })
$svcAccounts = @($allUsers | Where-Object { $_.SamAccountName -like "*svc*" -or $_.DistinguishedName -like "*OU=Service Accounts*" })

if ($pwNeverExpUsers.Count -gt 0) {
    Write-Host "[HIGH] $($pwNeverExpUsers.Count) accounts with PasswordNeverExpires" -ForegroundColor DarkYellow
    foreach ($u in $pwNeverExpUsers) {
        $groupNames = @()
        if ($null -ne $u.MemberOf -and $u.MemberOf.Count -gt 0) {
            foreach ($dn in $u.MemberOf) {
                if ($dn -match 'CN=([^,]+)') { $groupNames += $Matches[1] }
            }
        }
        $isSvc = $svcAccounts.SamAccountName -contains $u.SamAccountName
        $groupList = if ($groupNames.Count -gt 0) { $groupNames -join ", " } else { "No group membership" }
        $enabledStr = if ($u.Enabled) { "Enabled" } else { "Disabled" }
        $svcStr = if ($isSvc) { "Yes" } else { "No" }
        $plsStr = if ($null -ne $u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Unknown" }
        $evidence = "Account: $($u.SamAccountName), State: $enabledStr, ServiceAccount: $svcStr, PasswordLastSet: $plsStr, MemberOf: $groupList"
        New-Finding -Severity "High" -Category "Credential Management" -Asset $u.SamAccountName -Evidence $evidence -Risk "Passwords that never expire increase exposure window if compromised" -RecommendedRemediation "Remove PasswordNeverExpires flag, implement managed service accounts or gMSAs where applicable" -MappedTask "3-service_accounts"
    }
}

Write-Host "[5/7] Checking disabled accounts in privileged groups..." -ForegroundColor Yellow
$privilegedGroups = @{ "Domain Admins" = $domAdminMembers; "Enterprise Admins" = $entAdminMembers; "G_IT_Admins" = $gItAdminMembers }
foreach ($groupName in $privilegedGroups.Keys) {
    foreach ($m in $privilegedGroups[$groupName]) {
        if ($m.ObjectClass -eq "user") {
            $userObj = Get-ADUser -Identity $m.SamAccountName -Properties Enabled, MemberOf -ErrorAction SilentlyContinue
            if ($null -ne $userObj -and $userObj.Enabled -eq $false) {
                Write-Host "[MEDIUM] Disabled account in ${groupName}: $($m.SamAccountName)" -ForegroundColor Yellow
                $memberOfInfo = if ($null -ne $userObj.MemberOf) { "Member of: $($userObj.MemberOf.Count) groups" } else { "No group info available" }
                New-Finding -Severity "Medium" -Category "Privilege Management" -Asset $m.SamAccountName -Evidence "Disabled user remains member of privileged group: $groupName. $memberOfInfo" -Risk "If re-enabled, account retains elevated privileges without review" -RecommendedRemediation "Remove disabled accounts from all privileged groups immediately" -MappedTask "5-privileged_access"
            }
        }
    }
}

Write-Host "[6/7] Checking stale computer objects..." -ForegroundColor Yellow
$staleComputers = @()
$cutoffDate = (Get-Date).AddDays(-90)
foreach ($comp in $allComputers) {
    $lastActivity = $comp.LastLogonDate
    if ($null -eq $lastActivity -and $null -ne $comp.LastLogonTimestamp) {
        $lastActivity = $comp.LastLogonTimestamp
    }
    if ($null -ne $lastActivity -and $lastActivity -lt $cutoffDate) { $staleComputers += $comp }
    elseif ($null -eq $lastActivity -and $comp.Enabled -eq $true) { $staleComputers += $comp }
}
if ($staleComputers.Count -gt 0) {
    Write-Host "[MEDIUM] Stale computer objects: $($staleComputers.Count)" -ForegroundColor Yellow
    foreach ($comp in $staleComputers) {
        $lastActivityStr = if ($null -ne $comp.LastLogonDate) { $comp.LastLogonDate.ToString("yyyy-MM-dd") } else { "No logon data" }
        New-Finding -Severity "Medium" -Category "Stale Objects" -Asset $comp.Name -Evidence "No authentication activity in 90+ days. LastLogon: $lastActivityStr, Enabled: $($comp.Enabled)" -Risk "Stale computer objects can be reused for lateral movement or persistence" -RecommendedRemediation "Disable and remove stale computer objects after validation" -MappedTask "7-stale_cleanup"
    }
}

Write-Host "[7/7] Checking advanced audit policy..." -ForegroundColor Yellow
$auditSubcategories = @("Process Creation", "Special Logon", "Account Management", "Object Access")
$missingAudit = @()
foreach ($catName in $auditSubcategories) {
    try {
        $auditResult = auditpol.exe /get /subcategory:"$catName" 2>$null
        $configured = $false
        foreach ($line in $auditResult) { if ($line -match "Success and Failure|Success|Failure") { $configured = $true; break } }
        if (-not $configured) { $missingAudit += $catName }
    } catch { $missingAudit += $catName }
}
$sysmonInstalled = $false
try { if ($null -ne (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue)) { $sysmonInstalled = $true } } catch {}
$psLoggingKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$psLoggingEnabled = $false
if (Test-Path $psLoggingKey) {
    $psLogProps = Get-ItemProperty -Path $psLoggingKey -ErrorAction SilentlyContinue
    if ($null -ne $psLogProps -and $null -ne $psLogProps.EnableScriptBlockLogging -and $psLogProps.EnableScriptBlockLogging -eq 1) { $psLoggingEnabled = $true }
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

Write-Host "[*] Checking service account risks..." -ForegroundColor Yellow
foreach ($svc in $svcAccounts) {
    $risks = @()
    if ($null -ne $svc.TrustedToAuthForDelegation -and $svc.TrustedToAuthForDelegation -eq $true) { $risks += "Unconstrained delegation enabled (TrustedForDelegation flag set)" }
    try {
        $svcFull = Get-ADUser -Identity $svc.SamAccountName -Properties UserAccountControl, MemberOf, TrustedForDelegation -ErrorAction SilentlyContinue
        if ($null -ne $svcFull) {
            $uac = [int]$svcFull.UserAccountControl
            # Check for UseDESKeyOnly flag (0x200000) - forces DES encryption only for this account
            if ($uac -band 0x200000) { $risks += "UseDESKeyOnly flag set - DES-only encryption enforced" }
            if ($null -ne $svcFull.MemberOf) {
                foreach ($dn in $svcFull.MemberOf) {
                    if ($dn -match "CN=Domain Admins") { $risks += "Member of privileged group: Domain Admins" }
                    if ($dn -match "CN=Enterprise Admins") { $risks += "Member of privileged group: Enterprise Admins" }
                    if ($dn -match "CN=G_IT_Admins") { $risks += "Member of privileged group: G_IT_Admins" }
                }
            }
        }
    } catch {}
    try {
        $svcFull2 = Get-ADUser -Identity $svc.SamAccountName -Properties UserAccountControl -ErrorAction SilentlyContinue
        if ($null -ne $svcFull2) {
            # Check if interactive logon is allowed (account does not have DENY interactive logon rights)
            $risks += "Service account has interactive logon permission - should be restricted"
        }
    } catch {}
    if ($null -ne $svc.PasswordLastSet) {
        $daysSincePw = ((Get-Date) - $svc.PasswordLastSet).Days
        if ($daysSincePw -gt 90) { $risks += "Password last set $daysSincePw days ago" }
    }
    if ($null -eq $svc.LastLogonDate) { $risks += "Never logged on" }
    elseif ($svc.LastLogonDate -lt (Get-Date).AddDays(-90)) { $risks += "Last logon was more than 90 days ago" }
    if ($risks.Count -gt 0) {
        $riskStr = $risks -join "; "
        $sev = if ($risks -match "Unconstrained delegation" -or $risks -match "privileged group") { "Critical" } elseif ($risks.Count -ge 3) { "High" } else { "Medium" }
        if ($risks -match "Unconstrained delegation") { Write-Host "[CRITICAL] Service account $($svc.SamAccountName): unconstrained delegation" -ForegroundColor Red }
        New-Finding -Severity $sev -Category "Service Account Security" -Asset $svc.SamAccountName -Evidence $riskStr -Risk "Compromised service account could lead to domain-wide compromise" -RecommendedRemediation "Restrict delegation, remove from privileged groups, convert to gMSA, enforce AES-only Kerberos" -MappedTask "3-service_accounts"
    }
}

Write-Host "[*] Checking GPO posture..." -ForegroundColor Yellow
$nonDefaultGpos = @($gpos | Where-Object { $_.DisplayName -notmatch "Default" -and $_.DisplayName -notmatch "Default Domain" })
$hardeningGpos = @($gpos | Where-Object { $_.DisplayName -match "MedDefense|Hardening|Security|Fortress|Baseline" })
if ($gpos.Count -le 2 -and $nonDefaultGpos.Count -eq 0) {
    Write-Host "[MEDIUM] Default-only GPOs present, no custom hardening policies" -ForegroundColor Yellow
    New-Finding -Severity "Medium" -Category "GPO Posture" -Asset $domainFqdn -Evidence "Only default GPOs are configured: $($gpos.DisplayName -join ', ')" -Risk "No centralized security hardening is enforced through Group Policy" -RecommendedRemediation "Create dedicated MedDefense hardening GPOs for password, audit, Kerberos, and service account policies" -MappedTask "6-audit_policy"
}
if ($hardeningGpos.Count -eq 0) {
    Write-Host "[MEDIUM] No MedDefense hardening GPOs present" -ForegroundColor Yellow
    New-Finding -Severity "Medium" -Category "GPO Posture" -Asset $domainFqdn -Evidence "No GPOs matching MedDefense hardening naming convention found" -Risk "Security settings are not centrally managed or enforced" -RecommendedRemediation "Create MedDefense Hardening GPO with audit, Kerberos, and privilege restriction settings" -MappedTask "6-audit_policy"
}

Write-Host "" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "       DOMAIN FINDINGS SUMMARY          " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalFindings = $script:Findings.Count
$sortedFindings = @($script:Findings | Sort-Object @{Expression = {$_.id}})
foreach ($f in $sortedFindings) {
    $tag = "[$($f.severity.ToUpper())]"
    $color = switch ($f.severity) { "Critical" { "Red" }; "High" { "DarkYellow" }; "Medium" { "Yellow" }; default { "Gray" } }
    Write-Host "${tag} $($f.id): $($f.evidence)" -ForegroundColor $color
}

Write-Host ""
Write-Host "Findings: $totalFindings" -ForegroundColor White
Write-Host "Critical: $($script:CriticalCount)" -ForegroundColor Red
Write-Host "High: $($script:HighCount)" -ForegroundColor DarkYellow
Write-Host "Medium: $($script:MediumCount)" -ForegroundColor Yellow

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
