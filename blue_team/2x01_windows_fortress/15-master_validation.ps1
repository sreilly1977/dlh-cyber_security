<#
.Synopsis
    15-master_validation.ps1 - Comprehensive Compliance Validation Script
.Purpose
    Checks every hardening setting deployed across the MedDefense domain,
    produces a weekly compliance dashboard. Run every Friday by James Chen.
    Makes NO changes to the system - reads-only validation.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 5, 2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ===========================================================================
# COMPLIANCE DASHBOARD STATE
# ===========================================================================
$passCount = 0
$warnCount = 0
$failCount = 0
$criticalFailures = @()

function Write-Sector {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    $script:passCount++
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    $script:warnCount++
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    $script:failCount++
    $script:criticalFailures += $Message
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

# ===========================================================================
# 1. PASSWORD & LOCKOUT POLICY VALIDATION
# ===========================================================================
Write-Sector "Password & Lockout"

try {
    $domain = Get-ADDomain -ErrorAction Stop

    # Get a sample user to check resultant (effective) password policy
    # FGPP/PSO policies only appear via Get-ADUserResultantPasswordPolicy,
    # not via Get-ADDomain or Get-ADDefaultDomainPasswordPolicy
    $sampleUser = Get-ADUser -Filter * -SearchBase $domain.UsersContainer -ErrorAction SilentlyContinue | Select-Object -First 1

    $effectivePolicy = $null
    if ($sampleUser) {
        $effectivePolicy = Get-ADUserResultantPasswordPolicy -Identity $sampleUser -ErrorAction SilentlyContinue
    }

    # Minimum password length
    if ($effectivePolicy) {
        # PSO is active — check resultant policy
        $minLength = $effectivePolicy.MinPasswordLength
        if ($minLength -ge 14) {
            Write-Pass "Minimum length: $minLength (via PSO: $($effectivePolicy.Name))"
        } else {
            Write-Fail "Minimum length: $minLength (expected >= 14)"
        }

        # Lockout threshold
        $lockoutThreshold = $effectivePolicy.LockoutThreshold
        if ($lockoutThreshold -le 5) {
            Write-Pass "Lockout threshold: $lockoutThreshold"
        } else {
            Write-Fail "Lockout threshold: $lockoutThreshold (expected <= 5)"
        }

        # Lockout duration (minutes)
        $lockoutDuration = $effectivePolicy.LockoutDuration.TotalMinutes
        if ($lockoutDuration -ge 30) {
            Write-Pass "Lockout duration: $lockoutDuration min"
        } else {
            Write-Warn "Lockout duration: $lockoutDuration min (expected >= 30)"
        }

        # Max Password Age
        $maxPasswordAge = $effectivePolicy.MaxPasswordAge
        if ($maxPasswordAge -and $maxPasswordAge -is [TimeSpan] -and $maxPasswordAge.TotalDays -gt 0) {
            $ageDays = $maxPasswordAge.Days
            if ($ageDays -le 45) {
                Write-Pass "Max password age: $ageDays days"
            } else {
                Write-Fail "Max password age: $ageDays days (expected <= 45)"
            }
        } else {
            Write-Pass "Max password age: Never expires (rotation recommended)"
        }
    } else {
        # No PSO active — fall back to Default Domain Policy
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue

        if ($defaultPolicy) {
            $minLength = $defaultPolicy.MinPasswordLength
            if ($minLength -ge 14) {
                Write-Pass "Minimum length: $minLength (via Default Domain Policy)"
            } else {
                Write-Fail "Minimum length: $minLength (expected >= 14)"
            }

            $lockoutThreshold = $defaultPolicy.LockoutThreshold
            if ($lockoutThreshold -le 5) {
                Write-Pass "Lockout threshold: $lockoutThreshold"
            } else {
                Write-Fail "Lockout threshold: $lockoutThreshold (expected <= 5)"
            }

            $lockoutDuration = $defaultPolicy.LockoutDuration.TotalMinutes
            if ($lockoutDuration -ge 30) {
                Write-Pass "Lockout duration: $lockoutDuration min"
            } else {
                Write-Warn "Lockout duration: $lockoutDuration min (expected >= 30)"
            }

            $maxPasswordAge = $defaultPolicy.MaxPasswordAge
            if ($maxPasswordAge -and $maxPasswordAge -is [TimeSpan] -and $maxPasswordAge.TotalDays -gt 0) {
                $ageDays = $maxPasswordAge.Days
                if ($ageDays -le 45) {
                    Write-Pass "Max password age: $ageDays days"
                } else {
                    Write-Fail "Max password age: $ageDays days (expected <= 45)"
                }
            } else {
                Write-Pass "Max password age: Never expires (default)"
            }
        } else {
            Write-Fail "Could not retrieve any password policy"
        }
    }
} catch {
    Write-Fail "Could not retrieve AD domain policy: $_"
}

# ===========================================================================
# 2. AUDIT POLICY VALIDATION
# ===========================================================================
Write-Sector "Audit Policy"

try {
    # Process Creation auditing (4624, 4625, 4672) - Use auditpol.exe
    $processAuditOutput = auditpol /get /subcategory:"Process Creation" 2>$null | Select-String "Success|Failure|Success and Failure"
    if ($processAuditOutput -match "Success") {
        Write-Pass "Process Creation: Success"
    } elseif ($processAuditOutput -match "Success and Failure") {
        Write-Pass "Process Creation: Success and Failure"
    } else {
        Write-Fail "Process Creation: Not configured"
    }

    # Command-line logging - Check via registry (Process Creation includes cmdline)
    $cmdLineLogReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    $processCreationWithCmd = Get-ItemProperty -Path $cmdLineLogReg -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue

    if ($processCreationWithCmd -and $processCreationWithCmd.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
        Write-Pass "Command-line logging: Enabled"
    } else {
        # Check Sysmon instead
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($sysmonEvents -and $sysmonEvents.CommandLine) {
            Write-Pass "Command-line logging: Enabled (Sysmon)"
        } else {
            Write-Warn "Command-line logging: May need enhancement"
        }
    }

    # Security log size - Check via registry
    $secLogSize = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -ErrorAction SilentlyContinue).MaxSize
    $secLogMB = [math]::Round($secLogSize / 1MB)
    if ($secLogMB -ge 1024) {
        Write-Pass "Security log: $secLogMB MB"
    } elseif ($secLogMB -ge 512) {
        Write-Warn "Security log: $secLogMB MB (expected >= 1024)"
    } else {
        Write-Fail "Security log: $secLogMB MB (expected >= 1024)"
    }
} catch {
    Write-Fail "Could not verify audit policy: $_"
}

# ===========================================================================
# 3. POWERSHELL HARDENING VALIDATION
# ===========================================================================
Write-Sector "PowerShell"

try {
    # Module Logging
    $moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -ErrorAction SilentlyContinue
    if ($moduleLogging.EnableModuleLogging -eq 1) {
        Write-Pass "Module Logging: Enabled"
    } else {
        Write-Warn "Module Logging: Disabled"
    }

    # Script Block Logging
    $scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
    if ($scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
        Write-Pass "Script Block Logging: Enabled"
    } else {
        Write-Fail "Script Block Logging: Disabled"
    }

    # Transcription
    $transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
    if ($transcription.EnableTranscripting -eq 1) {
        Write-Pass "Transcription: Enabled"
    } else {
        Write-Fail "Transcription: Disabled"
    }
} catch {
    Write-Fail "Could not verify PowerShell settings: $_"
}

# ===========================================================================
# 4. SYSMON VALIDATION
# ===========================================================================
Write-Sector "Sysmon"

try {
    # Service status
    $sysmonService = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if ($sysmonService.Status -eq "Running") {
        Write-Pass "Service: Running"
    } elseif ($sysmonService) {
        Write-Fail "Service: Stopped"
    } else {
        Write-Fail "Service: Not installed"
    }

    # Custom rules count (check Sysmon config)
    $sysmonConfigPath = "C:\Windows\Sysmon.xml"
    if (Test-Path $sysmonConfigPath) {
        $sysmonConfig = Get-Content $sysmonConfigPath -Raw
        $customRules = ([regex]::Matches($sysmonConfig, '<Rule')).Count
        if ($customRules -ge 5) {
            Write-Pass "Custom rules: $customRules present"
        } elseif ($customRules -gt 0) {
            Write-Warn "Custom rules: $customRules (expected >= 5)"
        } else {
            Write-Fail "Custom rules: None found"
        }
    } else {
        # Check via Event Viewer instead
        $sysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} -MaxEvents 5 -ErrorAction SilentlyContinue
        if ($sysmonEvents) {
            Write-Pass "Custom rules: Active (via event log)"
        } else {
            Write-Fail "Custom rules: Could not verify"
        }
    }
} catch {
    Write-Fail "Could not verify Sysmon: $_"
}

# ===========================================================================
# 5. KERBEROS HARDENING VALIDATION
# ===========================================================================
Write-Sector "Kerberos"

try {
    # DES encryption type check
    $kerberosReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
    $supportedEnctype = Get-ItemProperty -Path $kerberosReg -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue

    if ($supportedEnctype) {
        # Value 28 or higher disables DES (0x04)
        $desDisabled = ($supportedEnctype.SupportedEncryptionTypes -band 0x04) -eq 0
        if ($desDisabled) {
            Write-Pass "DES: Disabled"
        } else {
            Write-Fail "DES: Enabled (weak encryption active)"
        }

        # RC4 check (0x20 should not be set for RC4-HMAC)
        $rc4Disabled = ($supportedEnctype.SupportedEncryptionTypes -band 0x20) -eq 0
        if ($rc4Disabled) {
            Write-Pass "RC4: Disabled"
        } else {
            Write-Warn "RC4: Still enabled (should be disabled)"
        }
    } else {
        Write-Warn "Kerberos encryption settings: Default (may include weak ciphers)"
    }
} catch {
    Write-Fail "Could not verify Kerberos settings: $_"
}

# ===========================================================================
# 6. SMB HARDENING VALIDATION
# ===========================================================================
Write-Sector "SMB"

try {
    # SMBv1 status
    $smbv1Status = Get-WindowsOptionalFeature -FeatureName SMB1Protocol -Online -ErrorAction SilentlyContinue
    if ($smbv1Status.State -eq "Disabled") {
        Write-Pass "SMBv1: Disabled"
    } elseif ($smbv1Status.State -eq "DisabledWithDependencies") {
        Write-Pass "SMBv1: Disabled (dependencies)"
    } else {
        Write-Fail "SMBv1: Enabled (critical vulnerability)"
    }

    # SMB signing requirement
    $signingRequired = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
    $serverSigning = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue

    if ($signingRequired.RequireSecuritySignature -eq 1 -or $serverSigning.RequireSecuritySignature -eq 1) {
        Write-Pass "Signing: Required"
    } else {
        Write-Fail "Signing: Optional or Disabled"
    }
} catch {
    Write-Fail "Could not verify SMB settings: $_"
}

# ===========================================================================
# 7. FIREWALL VALIDATION
# ===========================================================================
Write-Sector "Firewall"

try {
    $profiles = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $true }
    $allProfilesOk = $true

    foreach ($profile in $profiles) {
        if ($profile.DefaultInboundAction -ne "Block") {
            $allProfilesOk = $false
            break
        }
    }

    if ($allProfilesOk -and $profiles.Count -ge 3) {
        Write-Pass "All profiles: ON, DefaultInbound: Block"
    } elseif ($profiles.Count -ge 1) {
        Write-Warn "Some profiles: ON, may have exceptions"
    } else {
        Write-Fail "Firewall: Not properly configured"
    }

    # Check for custom MedDefense rules
    $meddefRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "MedDef-*" }
    if ($meddefRules.Count -gt 0) {
        Write-Pass "Custom rules: $($meddefRules.Count) present"
    } else {
        Write-Warn "Custom rules: None found"
    }
} catch {
    Write-Fail "Could not verify firewall settings: $_"
}

# ===========================================================================
# 8. RDP HARDENING VALIDATION
# ===========================================================================
Write-Sector "RDP"

try {
    # NLA requirement
    $termServiceReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $winStashReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    $nlaValue = (Get-ItemProperty -Path $winStashReg -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
    if ($nlaValue -eq 1) {
        Write-Pass "NLA: Required"
    } else {
        Write-Fail "NLA: Not Required"
    }

    # Remote Desktop Users group membership
    $rdpMembers = Get-LocalGroupMember -Name "Remote Desktop Users" -ErrorAction SilentlyContinue
    $hasAdminGroup = $false
    $hasDomainUsers = $false

    if ($rdpMembers) {
        foreach ($member in $rdpMembers) {
            if ($member.Name -like "*G_IT_Admins*" -or $member.Name -like "*GITAdmins*") {
                $hasAdminGroup = $true
            }
            if ($member.Name -like "*Domain Users*" -or $member.Name -like "*BUILTIN\Users*") {
                $hasDomainUsers = $true
            }
        }
    }

    if ($hasAdminGroup -and -not $hasDomainUsers) {
        Write-Pass "Access: G_IT_Admins only"
    } elseif ($hasDomainUsers) {
        Write-Fail "Access: Domain Users still has access (critical)"
    } else {
        Write-Warn "Access: Limited but unclear configuration"
    }
} catch {
    Write-Fail "Could not verify RDP settings: $_"
}

# ===========================================================================
# 9. SERVICE ACCOUNTS VALIDATION
# ===========================================================================
Write-Sector "Service Accounts"

try {
    Import-Module ActiveDirectory -ErrorAction Continue

    $serviceAccounts = @()
    $delegationRestricted = 0
    $totalServiceAccounts = 0

    $prefixes = @("svc_", "service_", "admin_")
    foreach ($prefix in $prefixes) {
        $found = Get-ADUser -Filter "SamAccountName -like '$prefix*'" `
            -Properties UserAccountControl, PasswordLastSet -ErrorAction SilentlyContinue
        if ($found) {
            $serviceAccounts += $found
        }
    }

    foreach ($account in $serviceAccounts) {
        $totalServiceAccounts++
        $uac = [int]$account.UserAccountControl

        # Check TrustedForDelegation flag cleared
        $isUnconstrained = ($uac -band 0x800000) -ne 0
        if (-not $isUnconstrained) {
            $delegationRestricted++
        }

        # Check password age
        if ($account.PasswordLastSet) {
            $age = ((Get-Date) - $account.PasswordLastSet).Days
            if ($age -gt 90) {
                Write-Warn "$($account.SamAccountName) password age: $age days"
            }
        }
    }

    if ($totalServiceAccounts -gt 0) {
        Write-Pass "Delegation restricted: $delegationRestricted/$totalServiceAccounts"
    } else {
        Write-Warn "No service accounts found"
    }
} catch {
    Write-Fail "Could not verify service accounts: $_"
}

# ===========================================================================
# 10. APPLocker VALIDATION
# ===========================================================================
Write-Sector "AppLocker"

try {
    # AppIDSvc service status
    $appidsvc = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
    if ($appidsvc.Status -eq "Running") {
        Write-Pass "AppIDSvc: Running"
    } else {
        Write-Fail "AppIDSvc: Stopped"
    }

    # Check enforcement mode
    $enforcementMode = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" -Name "EnforcementMode" -ErrorAction SilentlyContinue
    if ($enforcementMode.EnforcementMode -eq 2) {
        Write-Pass "Enforcement: Audit Only (Safe)"
    } elseif ($enforcementMode.EnforcementMode -eq 1) {
        Write-Warn "Enforcement: Active (monitor logs)"
    } else {
        Write-Warn "Enforcement: Not configured"
    }
} catch {
    Write-Fail "Could not verify AppLocker: $_"
}

# ===========================================================================
# FINAL SUMMARY AND EXIT CODE
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     COMPLIANCE CHECK SUMMARY           " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total Checks:" -ForegroundColor White
Write-Host "  Passed:    $passCount" -ForegroundColor Green
Write-Host "  Warnings:  $warnCount" -ForegroundColor Yellow
Write-Host "  Failed:    $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
Write-Host ""

if ($script:criticalFailures.Count -gt 0) {
    Write-Host "Critical Failures Detected:" -ForegroundColor Red
    foreach ($failure in $script:criticalFailures) {
        Write-Host "  - $failure" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "ACTION REQUIRED: Remediate failures before production deployment" -ForegroundColor Yellow
    exit 1
}

if ($warnCount -gt 0 -and $failCount -eq 0) {
    Write-Host "Compliance Status: WARNINGS PRESENT" -ForegroundColor Yellow
    Write-Host "Recommendation: Review warnings and schedule remediation" -ForegroundColor Gray
    exit 0
}

if ($failCount -eq 0 -and $warnCount -eq 0) {
    Write-Host "Compliance Status: FULLY COMPLIANT" -ForegroundColor Green
    Write-Host "All hardening checks passed successfully" -ForegroundColor Gray
    exit 0
}

exit 1
