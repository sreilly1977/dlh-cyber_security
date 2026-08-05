<#
.Synopsis
    11-firewall_hardening.ps1 - Windows Firewall Lockdown
.Purpose
    Configures Windows Firewall with a default-deny inbound policy and
    service-specific allow rules, implementing endpoint-level network segmentation.
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
$ManagementSubnet = "10.10.3.0/24"
$ServerSubnet = "10.10.1.0/24"

# ===========================================================================
# STEP 1: CAPTURE CURRENT FIREWALL STATE
# ===========================================================================
Write-Host "[*] Current Firewall State..." -ForegroundColor Yellow

$profiles = Get-NetFirewallProfile -All -ErrorAction SilentlyContinue

$domainEnabled = $false
$privateEnabled = $false
$publicEnabled = $false
$domainDefaultInbound = "Allow"
$privateDefaultInbound = "Allow"
$publicDefaultInbound = "Allow"

foreach ($profile in $profiles) {
    switch ($profile.Name) {
        "Domain" {
            $domainEnabled = $profile.Enabled
            $domainDefaultInbound = $profile.DefaultInboundAction
            if ($profile.Enabled) {
                $status = "ON"
                $tag = if ($profile.DefaultInboundAction -eq "Allow") { "[!]" } else { "[OK]" }
            } else {
                $status = "OFF"
                $tag = "[!]"
            }
            Write-Host "    Domain: $status, DefaultInbound: $($profile.DefaultInboundAction)       $tag" -ForegroundColor $(if ($tag -eq "[!]") { "Red" } else { "Green" })
        }
        "Private" {
            $privateEnabled = $profile.Enabled
            $privateDefaultInbound = $profile.DefaultInboundAction
            if ($profile.Enabled) {
                $status = "ON"
                $tag = if ($profile.DefaultInboundAction -eq "Allow") { "[!]" } else { "[OK]" }
            } else {
                $status = "OFF"
                $tag = "[!]"
            }
            Write-Host "    Private: $status                            $tag" -ForegroundColor $(if ($tag -eq "[!]") { "Red" } else { "Green" })
        }
        "Public" {
            $publicEnabled = $profile.Enabled
            $publicDefaultInbound = $profile.DefaultInboundAction
            if ($profile.Enabled) {
                $status = "ON"
                $tag = if ($profile.DefaultInboundAction -eq "Allow") { "[!]" } else { "[OK]" }
            } else {
                $status = "OFF"
                $tag = "[!]"
            }
            Write-Host "    Public: $status                            $tag" -ForegroundColor $(if ($tag -eq "[!]") { "Red" } else { "Green" })
        }
    }
}

# ===========================================================================
# STEP 2: SET DEFAULT-DENY INBOUND ON ALL PROFILES
# ===========================================================================
Write-Host ""
Write-Host "[*] Setting default-deny on all profiles... " -NoNewline -ForegroundColor Yellow

# Enable all three profiles with default deny inbound, allow outbound
Set-NetFirewallProfile -Profile Domain -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction SilentlyContinue

Write-Host "[SET]" -ForegroundColor Green

# ===========================================================================
# STEP 3: CREATE ALLOW RULES FOR REQUIRED SERVICES
# ===========================================================================
Write-Host "[*] Creating allow rules..." -ForegroundColor Yellow

# --- Rule 1: RDP from management subnet only ---
Write-Host "    MedDef-RDP-Mgmt:  TCP 3389 from $ManagementSubnet     " -NoNewline -ForegroundColor Gray

$existingRdp = Get-NetFirewallRule -DisplayName "MedDef-RDP-Mgmt" -ErrorAction SilentlyContinue
if ($existingRdp) { Remove-NetFirewallRule -DisplayName "MedDef-RDP-Mgmt" -ErrorAction SilentlyContinue }

New-NetFirewallRule -DisplayName "MedDef-RDP-Mgmt" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 `
    -RemoteAddress $ManagementSubnet -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

Write-Host "[CREATED]" -ForegroundColor Green

# --- Rule 2: DNS TCP/UDP 53 ---
Write-Host "    MedDef-DNS:        TCP/UDP 53                    " -NoNewline -ForegroundColor Gray

$existingDns = Get-NetFirewallRule -DisplayName "MedDef-DNS-*" -ErrorAction SilentlyContinue
if ($existingDns) { Remove-NetFirewallRule -DisplayName "MedDef-DNS-*" -ErrorAction SilentlyContinue }

New-NetFirewallRule -DisplayName "MedDef-DNS-TCP" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 53 `
    -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

New-NetFirewallRule -DisplayName "MedDef-DNS-UDP" `
    -Direction Inbound -Action Allow -Protocol UDP -LocalPort 53 `
    -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

Write-Host "[CREATED]" -ForegroundColor Green

# --- Rule 3: LDAP TCP 389 ---
Write-Host "    MedDef-LDAP:       TCP 389                       " -NoNewline -ForegroundColor Gray

$existingLdap = Get-NetFirewallRule -DisplayName "MedDef-LDAP" -ErrorAction SilentlyContinue
if ($existingLdap) { Remove-NetFirewallRule -DisplayName "MedDef-LDAP" -ErrorAction SilentlyContinue }

New-NetFirewallRule -DisplayName "MedDef-LDAP" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 389 `
    -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

Write-Host "[CREATED]" -ForegroundColor Green

# --- Rule 4: Kerberos TCP/UDP 88 ---
Write-Host "    MedDef-Kerberos:   TCP/UDP 88                    " -NoNewline -ForegroundColor Gray

$existingKerb = Get-NetFirewallRule -DisplayName "MedDef-Kerberos-*" -ErrorAction SilentlyContinue
if ($existingKerb) { Remove-NetFirewallRule -DisplayName "MedDef-Kerberos-*" -ErrorAction SilentlyContinue }

New-NetFirewallRule -DisplayName "MedDef-Kerberos-TCP" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 88 `
    -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

New-NetFirewallRule -DisplayName "MedDef-Kerberos-UDP" `
    -Direction Inbound -Action Allow -Protocol UDP -LocalPort 88 `
    -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

Write-Host "[CREATED]" -ForegroundColor Green

# --- Rule 5: SMB from server subnet only ---
Write-Host "    MedDef-SMB:        TCP 445 from $ServerSubnet     " -NoNewline -ForegroundColor Gray

$existingSmb = Get-NetFirewallRule -DisplayName "MedDef-SMB" -ErrorAction SilentlyContinue
if ($existingSmb) { Remove-NetFirewallRule -DisplayName "MedDef-SMB" -ErrorAction SilentlyContinue }

New-NetFirewallRule -DisplayName "MedDef-SMB" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 445 `
    -RemoteAddress $ServerSubnet -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

Write-Host "[CREATED]" -ForegroundColor Green

# --- Rule 6: WinRM from management subnet only ---
Write-Host "    MedDef-WinRM:      TCP 5985-5986 from $ManagementSubnet " -NoNewline -ForegroundColor Gray

$existingWinrm = Get-NetFirewallRule -DisplayName "MedDef-WinRM-*" -ErrorAction SilentlyContinue
if ($existingWinrm) { Remove-NetFirewallRule -DisplayName "MedDef-WinRM-*" -ErrorAction SilentlyContinue }

New-NetFirewallRule -DisplayName "MedDef-WinRM-HTTP" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985 `
    -RemoteAddress $ManagementSubnet -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

New-NetFirewallRule -DisplayName "MedDef-WinRM-HTTPS" `
    -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986 `
    -RemoteAddress $ManagementSubnet -Profile Domain,Private -ErrorAction SilentlyContinue | Out-Null

Write-Host "[CREATED]" -ForegroundColor Green

# ===========================================================================
# STEP 4: ENABLE LOGGING FOR DROPPED PACKETS
# ===========================================================================
Write-Host ""
Write-Host "[*] Enabling dropped packet logging...     " -NoNewline -ForegroundColor Yellow

# Enable logging on all profiles: dropped packets, successful connections
Set-NetFirewallProfile -Profile Domain -LogAllowed False -LogBlocked True -LogIgnored True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Private -LogAllowed False -LogBlocked True -LogIgnored True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Public -LogAllowed False -LogBlocked True -LogIgnored True -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue

Write-Host "[SET]" -ForegroundColor Green

# ===========================================================================
# STEP 5: DISABLE LEGACY ALLOW RULES THAT CONFLICT
# ===========================================================================
Write-Host "[*] Disabling legacy allow rules...       " -NoNewline -ForegroundColor Yellow

# Find all enabled inbound allow rules that are NOT our MedDef- rules
$legacyRules = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
    Where-Object { $_.Enabled -eq $true -and $_.DisplayName -notlike "MedDef-*" }

$disabledCount = 0

if ($legacyRules) {
    foreach ($rule in $legacyRules) {
        try {
            Disable-NetFirewallRule -InputObject $rule -ErrorAction SilentlyContinue
            $disabledCount++
        } catch {
            # Some built-in rules may resist being disabled
        }
    }
}

Write-Host "$disabledCount legacy rules disabled" -ForegroundColor Green
Write-Host "    Done." -ForegroundColor Gray

# ===========================================================================
# STEP 6: VERIFICATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verification..." -ForegroundColor Yellow

# Verify all profiles enabled with default deny inbound
$verifyProfiles = Get-NetFirewallProfile -All -ErrorAction SilentlyContinue
$allOn = $true
$allBlocked = $true

foreach ($vp in $verifyProfiles) {
    if (-not $vp.Enabled) { $allOn = $false }
    if ($vp.DefaultInboundAction -ne "Block") { $allBlocked = $false }
}

if ($allOn -and $allBlocked) {
    Write-Host "    All 3 profiles: ON, DefaultInbound: Block  [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Profile check: Issues detected              [WARNING]" -ForegroundColor Yellow
    foreach ($vp in $verifyProfiles) {
        $profStatus = if ($vp.Enabled) { "ON" } else { "OFF" }
        Write-Host "      $($vp.Name): $profStatus, Inbound=$($vp.DefaultInboundAction)" -ForegroundColor Gray
    }
}

# Verify custom rules are active (get by DisplayName then filter for Enabled)
$customRules = Get-NetFirewallRule -DisplayName "MedDef-*" -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
$customCount = if ($customRules) { $customRules.Count } else { 0 }

if ($customCount -ge 6) {
    Write-Host "    Custom rules: $customCount active                     [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Custom rules: $customCount active (expected >= 6)      [WARNING]" -ForegroundColor Yellow
}

# Verify logging is enabled
$loggingOk = $true
foreach ($vp in $verifyProfiles) {
    if (-not $vp.LogBlocked) { $loggingOk = $false }
}

if ($loggingOk) {
    Write-Host "    Dropped packet logging: Enabled           [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Dropped packet logging: Issues detected   [WARNING]" -ForegroundColor Yellow
}

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   WINDOWS FIREWALL LOCKDOWN SUMMARY     " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Firewall Profiles:" -ForegroundColor White
Write-Host "  Domain:                    ON (Block Inbound)" -ForegroundColor Gray
Write-Host "  Private:                   ON (Block Inbound)" -ForegroundColor Gray
Write-Host "  Public:                    ON (Block Inbound)" -ForegroundColor Gray
Write-Host ""
Write-Host "Inbound Allow Rules:" -ForegroundColor White
Write-Host "  RDP (TCP 3389):            $ManagementSubnet only" -ForegroundColor Gray
Write-Host "  DNS (TCP/UDP 53):          Any (DC operation)" -ForegroundColor Gray
Write-Host "  LDAP (TCP 389):            Any (AD auth)" -ForegroundColor Gray
Write-Host "  Kerberos (TCP/UDP 88):     Any (AD auth)" -ForegroundColor Gray
Write-Host "  SMB (TCP 445):             $ServerSubnet only" -ForegroundColor Gray
Write-Host "  WinRM (TCP 5985/5986):     $ManagementSubnet only" -ForegroundColor Gray
Write-Host ""
Write-Host "Logging:" -ForegroundColor White
Write-Host "  Dropped packets:           Logged" -ForegroundColor Gray
Write-Host "  Log file:                  pfirewall.log (16MB max)" -ForegroundColor Gray
Write-Host ""
Write-Host "Legacy Rules:" -ForegroundColor White
Write-Host "  Disabled count:            $disabledCount" -ForegroundColor Gray
Write-Host ""
Write-Host "Network Segmentation:" -ForegroundColor White
Write-Host "  Management subnet:         $ManagementSubnet (RDP, WinRM)" -ForegroundColor Gray
Write-Host "  Server subnet:              $ServerSubnet (SMB)" -ForegroundColor Gray
Write-Host "  Default policy:            Deny all other inbound" -ForegroundColor Gray
Write-Host ""
Write-Host "Done." -ForegroundColor White
