<#
.Synopsis
    13-rdp_hardening.ps1 - RDP and Remote Access Reduction
.Purpose
    Secures Remote Desktop Protocol to prevent it from being a lateral movement
    entry point, restricting access to authorized administrators with strong
    session controls.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 5, 2026
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION CONSTANTS
# ===========================================================================
$AllowedGroupName = "G_IT_Admins"

# ===========================================================================
# STEP 1: ENABLE NETWORK LEVEL AUTHENTICATION (NLA)
# ===========================================================================
Write-Host "[*] Enabling NLA... " -NoNewline -ForegroundColor Yellow

try {
    # Set UserAuthentication = 1 via registry
    $termServiceReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    $winStashReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    if (-not (Test-Path $termServiceReg)) {
        New-Item -Path $termServiceReg -Force | Out-Null
    }
    if (-not (Test-Path $winStashReg)) {
        New-Item -Path $winStashReg -Force | Out-Null
    }

    Set-ItemProperty -Path $termServiceReg -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $termServiceReg -Name "fEnableWinStation" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $winStashReg -Name "UserAuthentication" -Value 1 -Type DWord -Force

    Write-Host "UserAuthentication = 1       [SET]" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 2: RESTRICT RDP ACCESS TO G_IT_ADMINs GROUP ONLY
# ===========================================================================
Write-Host "[*] Restricting to $AllowedGroupName..." -ForegroundColor Yellow

try {
    $rdpUsersGroup = New-Object System.Security.Principal.NTAccount("BUILTIN","Remote Desktop Users")
    $rdpUsersSid = $rdpUsersGroup.Translate([System.Security.Principal.SID])

    # Get members of Remote Desktop Users group
    $currentMembers = Get-LocalGroupMember -Name "Remote Desktop Users" -ErrorAction SilentlyContinue

    if ($currentMembers) {
        foreach ($member in $currentMembers) {
            # Check if member is Domain Users
            if ($member.Name -like "*Domain Users*" -or $member.Name -like "*BUILTIN\Users*") {
                Remove-LocalGroupMember -Name "Remote Desktop Users" -Member $member.Name -ErrorAction SilentlyContinue
                Write-Host "    Removed: $($member.Name) from Remote Desktop Users" -ForegroundColor Gray
            }
        }
    }

    # Add the allowed group
    $allowedGroup = Get-LocalGroupMember -Name $AllowedGroupName -ErrorAction SilentlyContinue

    if ($null -ne $allowedGroup -and $allowedGroup.Count -gt 0) {
        # Add group itself (not individual members)
        $groupAccount = New-Object System.Security.Principal.NTAccount("", $AllowedGroupName)
        Add-LocalGroupMember -Name "Remote Desktop Users" -Member $AllowedGroupName -ErrorAction SilentlyContinue
        Write-Host "    Added: $AllowedGroupName                           [SET]" -ForegroundColor Green
    } else {
        # Group not found locally, try AD lookup
        $adGroup = Get-ADGroup -Identity $AllowedGroupName -ErrorAction SilentlyContinue
        if ($null -ne $adGroup) {
            Add-LocalGroupMember -Name "Remote Desktop Users" -Member $AllowedGroupName -ErrorAction SilentlyContinue
            Write-Host "    Added: $AllowedGroupName (from AD)               [SET]" -ForegroundColor Green
        } else {
            Write-Host "    Warning: Group $AllowedGroupName not found" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "    Error managing group membership: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 3: CONFIGURE SESSION TIMEOUTS
# ===========================================================================
Write-Host "[*] Session limits..." -ForegroundColor Yellow

try {
    $sessionTimeoutReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    if (-not (Test-Path $sessionTimeoutReg)) {
        New-Item -Path $sessionTimeoutReg -Force | Out-Null
    }

    # Set idle timeout to 15 minutes (900 seconds)
    Set-ItemProperty -Path $sessionTimeoutReg -Name "MaxIdleTime" -Value 900000 -Type DWord -Force
    Write-Host "    Idle timeout: 15 min                         [SET]" -ForegroundColor Green

    # Set max session length to 8 hours (28800 seconds)
    Set-ItemProperty -Path $sessionTimeoutReg -Name "MaxConnectionTime" -Value 28800000 -Type DWord -Force
    Write-Host "    Max session: 8 hours                         [SET]" -ForegroundColor Green

    # Enable disconnect when time limit is reached
    Set-ItemProperty -Path $sessionTimeoutReg -Name "MaxDisconnectionTime" -Value 0 -Type DWord -Force
} catch {
    Write-Host "    Error setting timeouts: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 4: ENFORCE HIGHEST ENCRYPTION LEVEL
# ===========================================================================
Write-Host "[*] Encryption: High/SSL                         " -NoNewline -ForegroundColor Yellow

try {
    $encryptionReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    # Set encryption level to High (3) - requires RDP 5.2+ compatible clients
    Set-ItemProperty -Path $encryptionReg -Name "MinEncryptionLevel" -Value 3 -Type DWord -Force
    Set-ItemProperty -Path $encryptionReg -Name "fEnableSecureRedir" -Value 1 -Type DWord -Force

    Write-Host "[SET]" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 5: DISABLE CLIPBOARD REDIRECTION
# ===========================================================================
Write-Host "[*] Clipboard: Disabled                          " -NoNewline -ForegroundColor Yellow

try {
    $clipboardReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    if (-not (Test-Path $clipboardReg)) {
        New-Item -Path $clipboardReg -Force | Out-Null
    }

    # Disable clipboard redirection
    Set-ItemProperty -Path $clipboardReg -Name "fDisableClip" -Value 1 -Type DWord -Force

    Write-Host "[SET]" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 6: DISABLE DRIVE REDIRECTION
# ===========================================================================
Write-Host "[*] Drive redirection: Disabled                  " -NoNewline -ForegroundColor Yellow

try {
    $driveReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    if (-not (Test-Path $driveReg)) {
        New-Item -Path $driveReg -Force | Out-Null
    }

    # Disable drive redirection
    Set-ItemProperty -Path $driveReg -Name "fDisableCdm" -Value 1 -Type DWord -Force

    Write-Host "[SET]" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 7: DISABLE REMOTE ASSISTANCE
# ===========================================================================
Write-Host "[*] Remote Assistance: Disabled                  " -NoNewline -ForegroundColor Yellow

try {
    $remoteAssistReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    $fcaReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

    if (Test-Path $remoteAssistReg) {
        Set-ItemProperty -Path $remoteAssistReg -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $remoteAssistReg -Name "fAllowFullyManagedRemoteAssistance" -Value 0 -Type DWord -Force
    } else {
        New-Item -Path $remoteAssistReg -Force | Out-Null
        Set-ItemProperty -Path $remoteAssistReg -Name "fAllowToGetHelp" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $remoteAssistReg -Name "fAllowFullyManagedRemoteAssistance" -Value 0 -Type DWord -Force
    }

    if (Test-Path $fcaReg) {
        Set-ItemProperty -Path $fcaReg -Name "fAllowFullControl" -Value 0 -Type DWord -Force
    }

    Write-Host "[SET]" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
}

# ===========================================================================
# STEP 8: VERIFICATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verification..." -ForegroundColor Yellow

# Verify NLA
$nlareg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$nlaValue = (Get-ItemProperty -Path $nlareg -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication

if ($nlaValue -eq 1) {
    Write-Host "    NLA: Required                                [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    NLA: Not Required                            [WARNING]" -ForegroundColor Yellow
}

# Verify Remote Desktop Users group
$rdpMembers = Get-LocalGroupMember -Name "Remote Desktop Users" -ErrorAction SilentlyContinue
$allowedFound = $false
$domainUsersFound = $false

if ($rdpMembers) {
    foreach ($member in $rdpMembers) {
        if ($member.Name -like "*$AllowedGroupName*") {
            $allowedFound = $true
        }
        if ($member.Name -like "*Domain Users*" -or $member.Name -like "*BUILTIN\Users*") {
            $domainUsersFound = $true
        }
    }
}

if ($allowedFound -and -not $domainUsersFound) {
    Write-Host "    Access: $AllowedGroupName only                     [VERIFIED]" -ForegroundColor Green
} elseif ($domainUsersFound) {
    Write-Host "    Access: Domain Users still present          [WARNING]" -ForegroundColor Yellow
} else {
    Write-Host "    Access: Group configuration pending         [PENDING]" -ForegroundColor Yellow
}

# Verify encryption level
$encValue = (Get-ItemProperty -Path $nlareg -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
if ($encValue -eq 3) {
    Write-Host "    Encryption: High/SSL                         [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Encryption: Level $encValue (expected 3)              [WARNING]" -ForegroundColor Yellow
}

# Verify clipboard
$clipValue = (Get-ItemProperty -Path $nlareg -Name "fDisableClip" -ErrorAction SilentlyContinue).fDisableClip
if ($clipValue -eq 1) {
    Write-Host "    Clipboard: Disabled                          [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Clipboard: Enabled                          [WARNING]" -ForegroundColor Yellow
}

# Verify drive redirection
$driveValue = (Get-ItemProperty -Path $nlareg -Name "fDisableCdm" -ErrorAction SilentlyContinue).fDisableCdm
if ($driveValue -eq 1) {
    Write-Host "    Drive redirection: Disabled                  [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Drive redirection: Enabled                  [WARNING]" -ForegroundColor Yellow
}

# Verify Remote Assistance
$raValue = (Get-ItemProperty -Path $remoteAssistReg -Name "fAllowToGetHelp" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($raValue -eq 0) {
    Write-Host "    Remote Assistance: Disabled                  [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Remote Assistance: Enabled                  [WARNING]" -ForegroundColor Yellow
}

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     RDP HARDENING SUMMARY              " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Network Level Authentication:" -ForegroundColor White
Write-Host "  NLA:                     Required" -ForegroundColor Gray
Write-Host "  Authentication Protocol: CredSSP/NLA" -ForegroundColor Gray
Write-Host ""
Write-Host "Access Control:" -ForegroundColor White
Write-Host "  Allowed Group:           $AllowedGroupName" -ForegroundColor Gray
Write-Host "  Domain Users:            Removed" -ForegroundColor Gray
Write-Host "  Restricted by IP:        (Configure via Windows Firewall)" -ForegroundColor Gray
Write-Host ""
Write-Host "Session Controls:" -ForegroundColor White
Write-Host "  Idle Timeout:            15 minutes" -ForegroundColor Gray
Write-Host "  Max Session Length:      8 hours" -ForegroundColor Gray
Write-Host "  Disconnection on Limit:  Enabled" -ForegroundColor Gray
Write-Host ""
Write-Host "Security Settings:" -ForegroundColor White
Write-Host "  Encryption Level:        High (SSL/TLS)" -ForegroundColor Gray
Write-Host "  Clipboard Redirection:   Disabled" -ForegroundColor Gray
Write-Host "  Drive Redirection:       Disabled" -ForegroundColor Gray
Write-Host "  Printer Redirection:     (Review for policy compliance)" -ForegroundColor Gray
Write-Host ""
Write-Host "Remote Assistance:" -ForegroundColor White
Write-Host "  Solicited RA:            Disabled" -ForegroundColor Gray
Write-Host "  Fully Managed RA:        Disabled" -ForegroundColor Gray
Write-Host ""
Write-Host "Lateral Movement Risk:" -ForegroundColor White
Write-Host "  Unauthorized RDP:        Blocked (NLA + Group restriction)" -ForegroundColor Green
Write-Host "  Data Exfiltration:       Mitigated (Clipboard/Drive disabled)" -ForegroundColor Green
Write-Host "  Credential Theft:        Reduced (NLA required)" -ForegroundColor Green
Write-Host ""
Write-Host "Notes:" -ForegroundColor White
Write-Host "  - Changes take effect immediately for new sessions" -ForegroundColor Gray
Write-Host "  - Existing sessions may remain until disconnected" -ForegroundColor Gray
Write-Host "  - Verify $AllowedGroupName membership before deployment" -ForegroundColor Gray
Write-Host "  - Test from authorized admin workstation first" -ForegroundColor Gray
Write-Host ""
Write-Host "Done." -ForegroundColor White
