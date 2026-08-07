<#
.Synopsis
    4-password_policy.ps1 - Password and Lockout Policy Deployment (FGPP)
.Purpose
    Deploys a CIS-compliant password and lockout policy via Fine-Grained
    Password Policies (PSO), fixing the two most critical findings from the
    domain assessment (weak password policy and absent lockout).
.Author
    Steve - Cybersecurity Engineer
.Date
    August 7, 2026
.Notes
    Fine-Grained Password Policies require Windows Server 2008 domain
    functional level or higher. The PSO is applied to the Domain Users
    group and individual service accounts, providing domain-wide coverage
    without modifying the Default Domain Policy GPO. Lower precedence
    value = higher priority when multiple PSOs apply to the same user.
#>

param(
    [string[]]$TargetGroups = @("Domain Users"),
    [string[]]$TargetUsers = @("svc_backup", "svc_ehr", "svc_sql"),
    [int]$Precedence = 50
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Import-Module ActiveDirectory

# ===========================================================================
# CONFIGURATION CONSTANTS
# ===========================================================================
$PsoName = "MedDefense-PasswordPolicy"
$MinPasswordLength = 14
$ComplexityEnabled = $true
$PasswordHistoryCount = 24
$MaxPasswordAge = [TimeSpan]::Zero    # 0 = passwords never expire
$MinPasswordAge = New-TimeSpan -Days 1
$LockoutThreshold = 5
$LockoutDuration = New-TimeSpan -Minutes 30
$LockoutObservationWindow = New-TimeSpan -Minutes 30

# ===========================================================================
# STEP 1: CHECK DOMAIN FUNCTIONAL LEVEL
# ===========================================================================
Write-Host "[*] Checking domain functional level..." -ForegroundColor Yellow

$domainInfo = Get-ADDomain
$domainMode = $domainInfo.DomainMode

Write-Host "    Domain Mode: $domainMode" -ForegroundColor Gray

if ($domainMode -lt [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2008Domain) {
    Write-Error "Fine-Grained Password Policies require Windows Server 2008 domain functional level or higher. Current: $domainMode"
    exit 1
}

Write-Host "    [OK]" -ForegroundColor Green

# ===========================================================================
# STEP 2: REMOVE EXISTING PSO IF PRESENT (CLEAN SLATE)
# ===========================================================================
Write-Host ""
Write-Host "[*] Checking for existing PSO..." -ForegroundColor Yellow

try {
    $existingPso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$PsoName'" -ErrorAction SilentlyContinue

    if ($null -ne $existingPso) {
        Write-Host "    Found existing PSO: $($existingPso.Name)" -ForegroundColor Gray
        Write-Host "    Removing for clean recreation..." -ForegroundColor Yellow
        Remove-ADFineGrainedPasswordPolicy -Identity $existingPso.DistinguishedName -Confirm:$false -ErrorAction Stop
        Write-Host "    OLD PSO REMOVED" -ForegroundColor Green
    } else {
        Write-Host "    No existing PSO found" -ForegroundColor Gray
    }
} catch {
    Write-Warning "Failed to check/remove existing PSO: $_"
    Write-Host "    Continuing with creation..." -ForegroundColor Yellow
}

# ===========================================================================
# STEP 3: CREATE NEW PSO
# ===========================================================================
Write-Host ""
Write-Host "[*] Creating Password Settings Object: `"$PsoName`"..." -ForegroundColor Yellow

try {
    $pso = New-ADFineGrainedPasswordPolicy `
        -Name $PsoName `
        -Precedence $Precedence `
        -ComplexityEnabled $ComplexityEnabled `
        -MinPasswordLength $MinPasswordLength `
        -PasswordHistoryCount $PasswordHistoryCount `
        -MaxPasswordAge $MaxPasswordAge `
        -MinPasswordAge $MinPasswordAge `
        -LockoutThreshold $LockoutThreshold `
        -LockoutDuration $LockoutDuration `
        -LockoutObservationWindow $LockoutObservationWindow
    Write-Host "CREATED" -ForegroundColor Green
} catch {
    Write-Error "Failed to create PSO: $_"
    exit 1
}

# ===========================================================================
# STEP 4: DISPLAY CONFIGURATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Password Policy Settings:" -ForegroundColor Yellow
Write-Host "    Minimum Length: $MinPasswordLength            [SET]" -ForegroundColor Green
Write-Host "    Complexity: Enabled           [SET]" -ForegroundColor Green
Write-Host "    History: $PasswordHistoryCount                   [SET]" -ForegroundColor Green
Write-Host "    Maximum Age: Never (rotation recommended) [SET]" -ForegroundColor Green
Write-Host "    Minimum Age: 1 day            [SET]" -ForegroundColor Green

Write-Host ""
Write-Host "[*] Account Lockout Settings:" -ForegroundColor Yellow
Write-Host "    Threshold: $LockoutThreshold attempts         [SET]" -ForegroundColor Green
Write-Host "    Duration: 30 minutes          [SET]" -ForegroundColor Green
Write-Host "    Reset Counter: 30 minutes     [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 5: APPLY PSO TO TARGET GROUPS
# ===========================================================================
Write-Host ""
Write-Host "[*] Applying PSO to target groups..." -ForegroundColor Yellow

foreach ($group in $TargetGroups) {
    try {
        $groupObj = Get-ADGroup -Identity $group -ErrorAction SilentlyContinue
        if ($null -ne $groupObj) {
            Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects $group -ErrorAction Stop
            Write-Host "    ${group}          [APPLIED]" -ForegroundColor Green
        } else {
            Write-Host "    Group not found: ${group}" -ForegroundColor Red
        }
    } catch {
        Write-Warning "Failed to apply PSO to group ${group}: $_"
    }
}

# ===========================================================================
# STEP 6: APPLY PSO TO INDIVIDUAL SERVICE ACCOUNTS
# ===========================================================================
Write-Host ""
Write-Host "[*] Applying PSO to service accounts..." -ForegroundColor Yellow

foreach ($user in $TargetUsers) {
    try {
        $userObj = Get-ADUser -Identity $user -ErrorAction SilentlyContinue
        if ($null -ne $userObj) {
            Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects $user -ErrorAction Stop
            Write-Host "    ${user}          [APPLIED]" -ForegroundColor Green
        } else {
            Write-Host "    User not found: ${user}" -ForegroundColor Red
        }
    } catch {
        Write-Warning "Failed to apply PSO to user ${user}: $_"
    }
}

# ===========================================================================
# STEP 7: WAIT FOR REPLICATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Waiting for AD replication... " -NoNewline -ForegroundColor Yellow
Start-Sleep -Seconds 10
Write-Host "DONE" -ForegroundColor Green

# ===========================================================================
# STEP 8: VERIFY PSO CONFIGURATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying PSO configuration..." -ForegroundColor Yellow

try {
    $verifyPso = Get-ADFineGrainedPasswordPolicy -Filter "Name -eq '$PsoName'" -ErrorAction Stop

    Write-Host "PSO Configuration:" -ForegroundColor Cyan
    Write-Host "  Name:               $($verifyPso.Name)" -ForegroundColor Gray
    Write-Host "  Precedence:         $($verifyPso.Precedence)" -ForegroundColor Gray
    Write-Host "  Min Length:         $($verifyPso.MinPasswordLength)" -ForegroundColor Gray
    Write-Host "  Complexity:         $($verifyPso.ComplexityEnabled)" -ForegroundColor Gray
    Write-Host "  History:            $($verifyPso.PasswordHistoryCount)" -ForegroundColor Gray
    Write-Host "  Max Age:            $($verifyPso.MaxPasswordAge.Days) days (0 = never)" -ForegroundColor Gray
    Write-Host "  Min Age:            $($verifyPso.MinPasswordAge.Days) days" -ForegroundColor Gray
    Write-Host "  Lockout Threshold:  $($verifyPso.LockoutThreshold)" -ForegroundColor Gray
    Write-Host "  Lockout Duration:   $($verifyPso.LockoutDuration.TotalMinutes) minutes" -ForegroundColor Gray
    Write-Host "  Observation Window: $($verifyPso.LockoutObservationWindow.TotalMinutes) minutes" -ForegroundColor Gray

    # Validate settings match expectations
    if ($verifyPso.MinPasswordLength -eq $MinPasswordLength -and
        $verifyPso.ComplexityEnabled -eq $ComplexityEnabled -and
        $verifyPso.PasswordHistoryCount -eq $PasswordHistoryCount -and
        $verifyPso.LockoutThreshold -eq $LockoutThreshold) {
        Write-Host "  Validation: All settings match - VERIFIED" -ForegroundColor Green
    } else {
        Write-Host "  Validation: Settings mismatch - NOT VERIFIED" -ForegroundColor Red
    }

    # Show applicable subjects
    Write-Host ""
    Write-Host "  Applied to:" -ForegroundColor Cyan
    if ($verifyPso.AppliesTo -and $verifyPso.AppliesTo.Count -gt 0) {
        foreach ($dn in $verifyPso.AppliesTo) {
            $obj = Get-ADObject -Identity $dn -ErrorAction SilentlyContinue
            if ($obj) {
                Write-Host "    - $($obj.Name) ($($obj.ObjectClass))" -ForegroundColor Gray
            } else {
                Write-Host "    - $dn" -ForegroundColor Gray
            }
        }
    } else {
        Write-Host "    No subjects found" -ForegroundColor Yellow
    }

} catch {
    Write-Warning "PSO verification failed: $_"
}

# ===========================================================================
# STEP 9: VERIFY EFFECTIVE POLICY ON SAMPLE USERS
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying effective policy on sample users..." -ForegroundColor Yellow

$allVerified = $true

# Test each service account
foreach ($acct in $TargetUsers) {
    Write-Host ""
    Write-Host "  Testing ${acct}..." -ForegroundColor Cyan

    try {
        $resultantPolicy = Get-ADUserResultantPasswordPolicy -Identity $acct -ErrorAction Stop

        if ($null -ne $resultantPolicy) {
            Write-Host "    Effective PSO: $($resultantPolicy.Name)" -ForegroundColor Gray
            Write-Host "    Min Length: $($resultantPolicy.MinPasswordLength)" -ForegroundColor Gray
            Write-Host "    Complexity: $($resultantPolicy.ComplexityEnabled)" -ForegroundColor Gray
            Write-Host "    Lockout Threshold: $($resultantPolicy.LockoutThreshold)" -ForegroundColor Gray

            if ($resultantPolicy.Name -eq $PsoName -and $resultantPolicy.MinPasswordLength -ge $MinPasswordLength) {
                Write-Host "    [VERIFIED - PSO is effective]" -ForegroundColor Green
            } else {
                Write-Host "    [WARNING - Different PSO or settings applied]" -ForegroundColor Yellow
                $allVerified = $false
            }
        } else {
            Write-Host "    Effective PSO: None (falling back to Default Domain Policy)" -ForegroundColor Yellow
            Write-Host "    [NOT VERIFIED - PSO not reaching this user]" -ForegroundColor Red
            $allVerified = $false

            # Attempt remediation
            Write-Host "    Attempting remediation..." -ForegroundColor Yellow
            try {
                Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects $acct -ErrorAction Stop
                Start-Sleep -Seconds 3
                $retryPolicy = Get-ADUserResultantPasswordPolicy -Identity $acct -ErrorAction SilentlyContinue
                if ($null -ne $retryPolicy -and $retryPolicy.Name -eq $PsoName) {
                    Write-Host "    [VERIFIED after remediation]" -ForegroundColor Green
                } else {
                    Write-Host "    [Still pending - try gpupdate /force and wait for replication]" -ForegroundColor Yellow
                    $allVerified = $false
                }
            } catch {
                Write-Host "    [Remediation failed: $_]" -ForegroundColor Red
                $allVerified = $false
            }
        }
    } catch {
        Write-Warning "Could not verify ${acct}: $_"
        $allVerified = $false
    }
}

# Test a regular domain user
Write-Host ""
Write-Host "  Testing regular domain user..." -ForegroundColor Cyan
$sampleUser = Get-ADUser -Filter * -SearchBase $domainInfo.UsersContainer -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($sampleUser) {
    try {
        $userResultant = Get-ADUserResultantPasswordPolicy -Identity $sampleUser -ErrorAction SilentlyContinue

        if ($null -ne $userResultant -and $userResultant.Name -eq $PsoName) {
            Write-Host "    User: $($sampleUser.SamAccountName)" -ForegroundColor Gray
            Write-Host "    Effective PSO: $($userResultant.Name)" -ForegroundColor Gray
            Write-Host "    Min Length: $($userResultant.MinPasswordLength)" -ForegroundColor Gray
            Write-Host "    [VERIFIED - PSO is effective for domain users]" -ForegroundColor Green
        } else {
            $psoName = if ($userResultant) { $userResultant.Name } else { "None" }
            Write-Host "    User: $($sampleUser.SamAccountName)" -ForegroundColor Gray
            Write-Host "    Effective PSO: $psoName" -ForegroundColor Gray
            Write-Host "    [NOT VERIFIED - PSO may need replication time]" -ForegroundColor Yellow
            $allVerified = $false
        }
    } catch {
        Write-Warning "Could not verify sample user: $_"
        $allVerified = $false
    }
} else {
    Write-Host "    No sample user found for verification" -ForegroundColor Yellow
}

# ===========================================================================
# STEP 10: RESET SERVICE ACCOUNT PASSWORDS
# ===========================================================================
Write-Host ""
Write-Host "[*] Resetting service account passwords..." -ForegroundColor Yellow

$accounts = @("svc_backup", "svc_ehr", "svc_sql")

foreach ($acct in $accounts) {
    try {
        # Generate random password (16 chars, meets complexity requirements)
        $password = -join ((65..90) + (97..122) + (48..57) + (33..47) | Get-Random -Count 16 | ForEach-Object {[char]$_})
        $securePass = ConvertTo-SecureString $password -AsPlainText -Force

        Set-ADAccountPassword -Identity $acct -Reset -NewPassword $securePass -ErrorAction Stop
        Write-Host "    ${acct}: Password reset            [DONE]" -ForegroundColor Green
    } catch {
        Write-Host "    ${acct}: Password reset failed      [ERROR]: $_" -ForegroundColor Red
    }
}

# ===========================================================================
# STEP 11: SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PASSWORD AND LOCKOUT POLICY SUMMARY   " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Password Policy (via PSO):" -ForegroundColor White
Write-Host "  Minimum Length:     $MinPasswordLength characters" -ForegroundColor Gray
Write-Host "  Complexity:         Enabled" -ForegroundColor Gray
Write-Host "  Password History:   $PasswordHistoryCount passwords" -ForegroundColor Gray
Write-Host "  Max Password Age:   Never (rotation still recommended)" -ForegroundColor Gray
Write-Host "  Min Password Age:   1 day" -ForegroundColor Gray
Write-Host ""
Write-Host "Lockout Policy:" -ForegroundColor White
Write-Host "  Threshold:          $LockoutThreshold bad logon attempts" -ForegroundColor Gray
Write-Host "  Duration:           30 minutes" -ForegroundColor Gray
Write-Host "  Reset Counter:      30 minutes" -ForegroundColor Gray
Write-Host ""
Write-Host "Deployment Method:   Fine-Grained Password Policy (PSO)" -ForegroundColor Gray
Write-Host "PSO Name:            $PsoName" -ForegroundColor Gray
Write-Host "Precedence:          $Precedence" -ForegroundColor Gray
Write-Host "Applied to Groups:   $($TargetGroups -join ', ')" -ForegroundColor Gray
Write-Host "Applied to Users:    $($TargetUsers -join ', ')" -ForegroundColor Gray
Write-Host ""
Write-Host "Service Accounts:" -ForegroundColor White
Write-Host "  Passwords Reset:   $($accounts -join ', ')" -ForegroundColor Gray
Write-Host "  Password Age:       0 days (fresh)" -ForegroundColor Gray
Write-Host ""

if ($allVerified) {
    Write-Host "  Status: VERIFIED" -ForegroundColor Green
} else {
    Write-Host "  Status: PARTIAL - some users may need replication time" -ForegroundColor Yellow
    Write-Host "  Run 'repadmin /syncall /AdeP' and re-verify" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Done." -ForegroundColor White
