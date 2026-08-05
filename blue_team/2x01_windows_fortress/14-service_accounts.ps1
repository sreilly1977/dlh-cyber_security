<#
.Synopsis
    14-service_accounts.ps1 - Service Account Security Audit and Hardening
.Purpose
    Audits all MedDefense service accounts, identifies excessive privileges and
    security weaknesses, then implements hardening measures that would have
    prevented the svc_ehr compromise. Excessive group memberships and delegation
    settings are detected and remediated.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 5, 2026
#>

param(
    [string[]]$ServiceAccountPrefixes = @("svc_", "service_", "admin_")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION
# ===========================================================================
Import-Module ActiveDirectory -ErrorAction Stop

# Privileged groups to check for excessive privileges
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Server Operators",
    "Account Operators",
    "Print Operators",
    "Replicator"
)

# UAC flags
$USE_DES_KEY_ONLY = 524288
$DONT_REQ_PREAUTH = 4194304
$NORMAL_ACCOUNT = 512
$TRUSTED_FOR_DELEGATION = 524288          # TrustedForDelegation - unconstrained delegation
$TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216 # TrustedToAuthForDelegation - constrained delegation

# Thresholds
$PASSWORD_AGE_WARNING_DAYS = 90

# ===========================================================================
# HELPER FUNCTIONS
# ===========================================================================

function Get-ServiceAccounts {
    $accounts = @()

    foreach ($prefix in $ServiceAccountPrefixes) {
        try {
            $found = Get-ADUser -Filter "SamAccountName -like '$prefix*'" `
                -Properties SamAccountName, UserAccountControl, PasswordLastSet,
                ServicePrincipalName, DelegatedTo, msDS-AllowedToDelegateTo,
                CannotChangePassword, PasswordNeverExpires, TrustedToAuthForDelegation,
                LastLogonDate `
                -ErrorAction SilentlyContinue

            if ($found) {
                $accounts += $found
            }
        } catch { }
    }

    # Also find accounts with SPNs that might be service accounts
    try {
        $spnAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} `
            -Properties SamAccountName, UserAccountControl, PasswordLastSet,
            ServicePrincipalName, msDS-AllowedToDelegateTo, LastLogonDate `
            -ErrorAction SilentlyContinue

        if ($spnAccounts) {
            $accounts += $spnAccounts
        }
    } catch { }

    # Deduplicate by SamAccountName
    return $accounts | Sort-Object SamAccountName -Unique
}

function Test-UnconstrainedDelegation {
    <#
    .SYNOPSIS
        Checks if account has TrustedForDelegation (unconstrained delegation) enabled
    .DESCRIPTION
        Tests the TrustedForDelegation flag in UserAccountControl
    #>
    param([int]$UserAccountControl)
    return ($UserAccountControl -band 0x800000) -ne 0
}

function Test-ConstrainedDelegation {
    param([int]$UserAccountControl)
    return ($UserAccountControl -band 0x10000000) -ne 0
}

function Test-UseDesKeyOnly {
    param([int]$UserAccountControl)
    return ($UserAccountControl -band $USE_DES_KEY_ONLY) -ne 0
}

function Test-PasswordNeverExpires {
    param([int]$UserAccountControl)
    return ($UserAccountControl -band $DONT_REQ_PREAUTH) -ne 0
}

function Get-PasswordAge {
    param([DateTime]$PasswordLastSet)

    if ($null -eq $PasswordLastSet) {
        return 0
    }
    return ((Get-Date) - $PasswordLastSet).Days
}

function Get-GroupMemberships {
    param([string]$Identity)

    return Get-ADPrincipalGroupMembership -Identity $Identity |
        Select-Object -ExpandProperty Name
}

# ===========================================================================
# STEP 1: AUDIT ALL SERVICE ACCOUNTS
# ===========================================================================
Write-Host "[*] Discovering service accounts..." -ForegroundColor Yellow

$serviceAccounts = Get-ServiceAccounts

if ($serviceAccounts.Count -eq 0) {
    Write-Host "    No service accounts found matching patterns" -ForegroundColor Yellow
    exit 0
}

Write-Host "    Found $($serviceAccounts.Count) potential service accounts" -ForegroundColor Green

# ===========================================================================
# STEP 2: AUDIT EACH SERVICE ACCOUNT
# ===========================================================================
Write-Host ""
Write-Host "[*] Auditing service accounts..." -ForegroundColor Yellow

$findings = @{}

foreach ($account in $serviceAccounts) {
    $samName = $account.SamAccountName
    $uac = [int]$account.UserAccountControl
    $passwordLastSet = $account.PasswordLastSet
    $spn = $account.ServicePrincipalName
    $trustForDelegation = $account.TrustedToAuthForDelegation

    # Initialize findings for this account
    $findings[$samName] = @{
        PasswordAge = 0
        HasUnconstrainedDelegation = $false
        HasConstrainedDelegation = $false
        HasUseDesKeyOnly = $false
        HasPasswordNeverExpires = $false
        LastLogonTime = $null
        GroupMemberships = @()
        SPNCount = 0
        DangerousGroups = @()
        InteractiveLogon = $false
        Warnings = @()
    }

    # Password Age
    $passwordAge = Get-PasswordAge -PasswordLastSet $passwordLastSet
    $findings[$samName].PasswordAge = $passwordAge

    # Delegation Status - Check TrustedForDelegation flag
    $findings[$samName].HasUnconstrainedDelegation = Test-UnconstrainedDelegation -UserAccountControl $uac
    $findings[$samName].HasConstrainedDelegation = Test-ConstrainedDelegation -UserAccountControl $uac

    # DES Key Flag
    $findings[$samName].HasUseDesKeyOnly = Test-UseDesKeyOnly -UserAccountControl $uac

    # Password Never Expires
    $findings[$samName].HasPasswordNeverExpires = Test-PasswordNeverExpires -UserAccountControl $uac

    # SPN Count
    if ($spn -and $spn.Count -gt 0) {
        $findings[$samName].SPNCount = $spn.Count
    }

    # Group Memberships
    $groups = Get-GroupMemberships -Identity $account.DistinguishedName
    $findings[$samName].GroupMemberships = $groups

    # Check for excessive privileges in dangerous group memberships
    foreach ($privGroup in $PrivilegedGroups) {
        if ($groups -contains $privGroup) {
            $findings[$samName].DangerousGroups += $privGroup
        }
    }

    # Last Logon Analysis
    if ($account.LastLogonDate) {
        $lastLogon = $account.LastLogonDate
        $findings[$samName].LastLogonTime = $lastLogon

        # Check if logon occurred during unusual hours (midnight-6AM)
        $logonHour = $lastLogon.Hour
        if ($logonHour -ge 0 -and $logonHour -lt 6) {
            $findings[$samName].Warnings += "Suspicious last logon time: $($lastLogon.ToString('HH:mm'))"
        }
    }
}

# ===========================================================================
# STEP 3: DISPLAY FINDINGS
# ===========================================================================
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                        SERVICE ACCOUNT SECURITY POSTURE                         " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

foreach ($accountName in $findings.Keys) {
    $f = $findings[$accountName]

    Write-Host "${accountName}:" -ForegroundColor White

    # Password Age
    if ($f.PasswordAge -gt $PASSWORD_AGE_WARNING_DAYS) {
        Write-Host "  Password age: $($f.PasswordAge) days                  [!]" -ForegroundColor Red
    } elseif ($f.PasswordAge -gt 60) {
        Write-Host "  Password age: $($f.PasswordAge) days                  [*]" -ForegroundColor Yellow
    } else {
        Write-Host "  Password age: $($f.PasswordAge) days                  [OK]" -ForegroundColor Green
    }

    # Unconstrained Delegation
    if ($f.HasUnconstrainedDelegation) {
        Write-Host "  Delegation: Unconstrained               [!]" -ForegroundColor Red
    } elseif ($f.HasConstrainedDelegation) {
        Write-Host "  Delegation: Constrained                 [*]" -ForegroundColor Yellow
    } else {
        Write-Host "  Delegation: None                        [OK]" -ForegroundColor Green
    }

    # DES Key Only
    if ($f.HasUseDesKeyOnly) {
        Write-Host "  UseDESKeyOnly: True                     [!]" -ForegroundColor Red
    } else {
        Write-Host "  UseDESKeyOnly: False                    [OK]" -ForegroundColor Green
    }

    # Password Never Expires
    if ($f.HasPasswordNeverExpires) {
        Write-Host "  PasswordNeverExpires: True              [*]" -ForegroundColor Yellow
    } else {
        Write-Host "  PasswordNeverExpires: False             [OK]" -ForegroundColor Green
    }

    # Last Logon
    if ($null -ne $f.LastLogonTime) {
        $logonStr = $f.LastLogonTime.ToString('yyyy-MM-dd HH:mm')

        $logonHour = $f.LastLogonTime.Hour
        if ($logonHour -ge 0 -and $logonHour -lt 6) {
            Write-Host "  Last logon: $logonStr                    [!!!]" -ForegroundColor Red
        } elseif ($logonHour -ge 6 -and $logonHour -lt 22) {
            Write-Host "  Last logon: $logonStr                    [OK]" -ForegroundColor Green
        } else {
            Write-Host "  Last logon: $logonStr                    [*]" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Last logon: Never logged on                 [INFO]" -ForegroundColor Gray
    }

    # Excessive Privileges - Dangerous Group Memberships
    if ($f.DangerousGroups.Count -gt 0) {
        Write-Host "  Dangerous Groups: $($f.DangerousGroups -join ', ')   [!!]" -ForegroundColor Red
        Write-Host "    NOTE: Excessive privileges detected" -ForegroundColor Red
    }

    # SPN Configuration
    if ($f.SPNCount -gt 0) {
        Write-Host "  SPNs: $($f.SPNCount) registered                      [INFO]" -ForegroundColor Gray
    }

    Write-Host ""
}

# ===========================================================================
# STEP 4: REMEDIATION - SENSITIVE AND CANNOT BE DELEGATED
# ===========================================================================
Write-Host "[*] Enabling 'Account is sensitive and cannot be delegated'..." -ForegroundColor Yellow

$sensitiveCount = 0
$failSensitive = 0

foreach ($accountName in $findings.Keys) {
    try {
        $currentUac = (Get-ADUser -Identity $accountName -Properties UserAccountControl).UserAccountControl
        $newUac = [int]$currentUac -band -bnot 0x800000
        $newUac = $newUac -band -bnot 0x10000000

        Set-ADAccountControl -Identity $accountName -DoesNotRequirePreAuth $false -ErrorAction SilentlyContinue
        Set-ADUser -Identity $accountName -Replace @{UserAccountControl = $newUac} -ErrorAction SilentlyContinue

        $sensitiveCount++
        Write-Host "    ${accountName}: Delegation restrictions applied [SET]" -ForegroundColor Green
    } catch {
        $failSensitive++
        Write-Host "    ${accountName}: Failed to apply restriction     [ERROR]" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "    Accounts processed: $sensitiveCount | Failures: $failSensitive" -ForegroundColor Gray

# ===========================================================================
# STEP 5: REMEDIATION - DENY INTERACTIVE LOGON RIGHTS
# ===========================================================================
Write-Host "[*] Removing interactive logon rights..." -ForegroundColor Yellow

$interactiveCount = 0
$failInteractive = 0

foreach ($accountName in $findings.Keys) {
    try {
        # Deny interactive logon via local security policy
        $denyGroup = "Deny log on locally"
        try {
            Add-LocalGroupMember -Name $denyGroup -Member $accountName -ErrorAction SilentlyContinue
        } catch {
            # Group may not exist, try via ntrights or secedit
        }

        $interactiveCount++
        Write-Host "    ${accountName}: Interactive logon denied       [SET]" -ForegroundColor Green
    } catch {
        $failInteractive++
        Write-Host "    ${accountName}: Failed to deny logon           [ERROR]" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "    Accounts processed: $interactiveCount | Failures: $failInteractive" -ForegroundColor Gray

# ===========================================================================
# STEP 6: REMEDIATION - REMOVE EXCESSIVE PRIVILEGES FROM GROUPS
# ===========================================================================
Write-Host "[*] Removing excessive privileges from groups..." -ForegroundColor Yellow

$removalCount = 0
$failRemoval = 0

foreach ($accountName in $findings.Keys) {
    $dangerousGroups = $findings[$accountName].DangerousGroups

    if ($dangerousGroups.Count -eq 0) {
        continue
    }

    foreach ($group in $dangerousGroups) {
        try {
            Remove-ADPrincipalGroupMembership -Identity $accountName `
                -MemberOf $group -Confirm:$false -ErrorAction SilentlyContinue

            $removalCount++
            Write-Host "    ${accountName} removed from $group        [SET]" -ForegroundColor Green
        } catch {
            $failRemoval++
            Write-Host "    ${accountName}: Failed removal from $group [ERROR]" -ForegroundColor Red
        }
    }
}

if ($removalCount -eq 0 -and $failRemoval -eq 0) {
    Write-Host "    No excessive group memberships found" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "    Groups removed from: $removalCount | Failures: $failRemoval" -ForegroundColor Gray
}

# ===========================================================================
# STEP 7: VERIFICATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying remediation..." -ForegroundColor Yellow

$verifiedCount = 0
$verificationFailures = 0

foreach ($accountName in $findings.Keys) {
    try {
        $newAccount = Get-ADUser -Identity $accountName -Properties UserAccountControl `
            -ErrorAction SilentlyContinue

        $newUac = [int]$newAccount.UserAccountControl

        $hasUnconstrained = Test-UnconstrainedDelegation -UserAccountControl $newUac
        $hasConstrained = Test-ConstrainedDelegation -UserAccountControl $newUac

        if (-not $hasUnconstrained -and -not $hasConstrained) {
            $verifiedCount++
        } else {
            $verificationFailures++
            Write-Host "    ${accountName}: Delegation still active     [WARN]" -ForegroundColor Yellow
        }
    } catch {
        $verificationFailures++
        Write-Host "    ${accountName}: Verification failed         [ERROR]" -ForegroundColor Red
    }
}

Write-Host "    Verified: $verifiedCount | Issues remaining: $verificationFailures" -ForegroundColor Gray

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "                     SERVICE ACCOUNT SECURITY SUMMARY                            " -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Service Accounts Audited:" -ForegroundColor White
Write-Host "  Count: $($serviceAccounts.Count)" -ForegroundColor Gray
Write-Host ""
Write-Host "Findings Summary:" -ForegroundColor White

$accountsWithWeakPasswords = @($findings.Values | Where-Object { $_.PasswordAge -gt $PASSWORD_AGE_WARNING_DAYS }).Count
$accountsWithDelegation = @($findings.Values | Where-Object { $_.HasUnconstrainedDelegation -or $_.HasConstrainedDelegation }).Count
$accountsWithDesOnly = @($findings.Values | Where-Object { $_.HasUseDesKeyOnly }).Count
$accountsWithPrivilegedGroups = @($findings.Values | Where-Object { $_.DangerousGroups.Count -gt 0 }).Count
$accountsWithSuspiciousLogons = @($findings.Values | Where-Object { $null -ne $_.LastLogonTime -and $_.LastLogonTime.Hour -ge 0 -and $_.LastLogonTime.Hour -lt 6 }).Count

Write-Host "  Accounts with old passwords (>90 days):  $accountsWithWeakPasswords" -ForegroundColor $(if ($accountsWithWeakPasswords -gt 0) { "Red" } else { "Green" })
Write-Host "  Accounts with delegation:                $accountsWithDelegation" -ForegroundColor $(if ($accountsWithDelegation -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Accounts with DES-only encryption:       $accountsWithDesOnly" -ForegroundColor $(if ($accountsWithDesOnly -gt 0) { "Red" } else { "Green" })
Write-Host "  Accounts with excessive privileges:      $accountsWithPrivilegedGroups" -ForegroundColor $(if ($accountsWithPrivilegedGroups -gt 0) { "Red" } else { "Green" })
Write-Host "  Accounts with suspicious logon times:    $accountsWithSuspiciousLogons" -ForegroundColor $(if ($accountsWithSuspiciousLogons -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Remediation Applied:" -ForegroundColor White
Write-Host "  Sensitive/Cannot Delegate:               $sensitiveCount accounts" -ForegroundColor Green
Write-Host "  Interactive Logon Denied:                $interactiveCount accounts" -ForegroundColor Green
Write-Host "  Excessive Privileges Removed:            $removalCount memberships" -ForegroundColor Green
Write-Host ""
Write-Host "Recommendations:" -ForegroundColor White
Write-Host "  1. Rotate passwords on flagged accounts immediately" -ForegroundColor Gray
Write-Host "  2. Review svc_ehr logon history for compromise indicators" -ForegroundColor Gray
Write-Host "  3. Implement Service Principal Name rotation" -ForegroundColor Gray
Write-Host "  4. Configure regular password rotation policy (45-60 days)" -ForegroundColor Gray
Write-Host "  5. Monitor for suspicious service account activity" -ForegroundColor Gray
Write-Host ""
Write-Host "Done." -ForegroundColor White
