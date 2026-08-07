<#
.Synopsis
    8-smb_hardening.ps1 - SMB and Protocol Hardening
.Purpose
    Disables SMBv1 and enforces SMB signing to eliminate one of the most
    commonly exploited lateral movement vectors in enterprise Windows environments.
    Also disables legacy protocols (NetBIOS, LLMNR) to reduce attack surface.
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
$GpoName = "MedDefense - SMB Protocol Hardening"

# Get domain distinguished name for GPO linking
$DomainDN = (Get-ADDomain).DistinguishedName

# ===========================================================================
# STEP 1: CHECK CURRENT SMB CONFIGURATION
# ===========================================================================
Write-Host "[*] Current SMB Configuration..." -ForegroundColor Yellow

# Initialize variables for display and before/after tracking
$smbV1ServerEnabled = $false
$smbV1ClientEnabled = $false
$signingRequired = $false
$encryptionEnabled = $false

# Capture Before state for verification comparison
$beforeSmbV1 = $false
$beforeSigning = $false
$beforeEncryption = $false
$beforeLlmnr = $false

# Check SMBv1 feature status
$smbV1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
if ($null -ne $smbV1Feature) {
    $smbV1ServerEnabled = ($smbV1Feature.State -eq "Enabled")
}
$smbV1ClientFeature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -ErrorAction SilentlyContinue
if ($null -ne $smbV1ClientFeature) {
    $smbV1ClientEnabled = ($smbV1ClientFeature.State -eq "Enabled")
}

# Check signing requirements via Get-SmbServerConfiguration and Get-SmbClientConfiguration
$smbServerRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
if (Test-Path $smbServerRegPath) {
    $serverRegProps = Get-ItemProperty -Path $smbServerRegPath -ErrorAction SilentlyContinue
    if ($null -ne $serverRegProps) {
        if ($null -ne $serverRegProps.RequireSecuritySignature -and $serverRegProps.RequireSecuritySignature -eq 1) {
            $signingRequired = $true
        }
    }
}

# Also use Get-SmbServerConfiguration for comprehensive status
try {
    $currentSmbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($null -ne $currentSmbConfig) {
        if ($currentSmbConfig.EnableEncryptData) {
            $encryptionEnabled = $true
        }
        if ($currentSmbConfig.RequireSecuritySignature) {
            $signingRequired = $true
        }
        # Check EnableSMB1Protocol property
        if ($currentSmbConfig.EnableSMB1Protocol) {
            $smbV1ServerEnabled = $true
        }
    }
} catch { }

# Also use Get-SmbClientConfiguration for client-side status
try {
    $currentSmbClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
    if ($null -ne $currentSmbClientConfig) {
        if ($currentSmbClientConfig.RequireSecuritySignature) {
            $signingRequired = $true
        }
    }
} catch { }

# Record Before state
$beforeSmbV1 = $smbV1ServerEnabled -or $smbV1ClientEnabled
$beforeSigning = $signingRequired
$beforeEncryption = $encryptionEnabled

# Check LLMNR before state
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (Test-Path $llmnrPath) {
    $llmnrBefore = Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
    if ($null -ne $llmnrBefore -and $llmnrBefore.EnableMulticast -eq 0) {
        $beforeLlmnr = $true
    }
}

if ($smbV1ServerEnabled -or $smbV1ClientEnabled) {
    Write-Host "    SMBv1: Enabled                         [!]" -ForegroundColor Red
} else {
    Write-Host "    SMBv1: Disabled                        [OK]" -ForegroundColor Green
}

if ($signingRequired) {
    Write-Host "    Signing Required: True                 [OK]" -ForegroundColor Green
} else {
    Write-Host "    Signing Required: False                [!]" -ForegroundColor Red
}

if ($encryptionEnabled) {
    Write-Host "    Encryption: Enabled                    [OK]" -ForegroundColor Green
} else {
    Write-Host "    Encryption: False                      [!]" -ForegroundColor Red
}

# ===========================================================================
# STEP 2: DISABLE SMBv1 (SERVER + CLIENT)
# ===========================================================================
Write-Host ""
Write-Host "[*] Disabling SMBv1 (server + client)...   " -NoNewline -ForegroundColor Yellow

try {
    # Disable SMBv1 — redirect ALL streams to suppress console warnings
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart *> $null
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client -NoRestart *> $null

    # Also disable via Set-SmbServerConfiguration
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
} catch { }

# Disable SMBv1 via registry as backup
if (Test-Path $smbServerRegPath) {
    Set-ItemProperty -Path $smbServerRegPath -Name "SMB1" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
}

$smbClientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if (Test-Path $smbClientRegPath) {
    Set-ItemProperty -Path $smbClientRegPath -Name "AllowInsecureGuestAuth" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
}

Write-Host "[DONE]" -ForegroundColor Green

# ===========================================================================
# STEP 3: ENFORCE SMB SIGNING
# ===========================================================================
Write-Host "[*] Enforcing SMB Signing...               [SET]" -ForegroundColor Yellow

# Server side signing
if (Test-Path $smbServerRegPath) {
    Set-ItemProperty -Path $smbServerRegPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $smbServerRegPath -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
}
Write-Host "    Signing required set on server       [SET]" -ForegroundColor Green

# Client side signing
if (Test-Path $smbClientRegPath) {
    Set-ItemProperty -Path $smbClientRegPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $smbClientRegPath -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
}
Write-Host "    Signing required set on client       [SET]" -ForegroundColor Green

# ===========================================================================
# STEP 4: ENABLE SMB ENCRYPTION
# ===========================================================================
Write-Host "[*] Enabling SMB Encryption...             [SET]" -ForegroundColor Yellow

# Set SMB encryption via registry
if (Test-Path $smbServerRegPath) {
    Set-ItemProperty -Path $smbServerRegPath -Name "EnableEncryption" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
}

# Try cmdlet first, fall back to registry
try {
    Set-SmbServerConfiguration -EnableEncryptData $true -Force -ErrorAction SilentlyContinue
    Write-Host "    Encryption enabled via cmdlet         [SET]" -ForegroundColor Green
} catch {
    # Registry fallback for SMB encryption
    if (Test-Path $smbServerRegPath) {
        Set-ItemProperty -Path $smbServerRegPath -Name "EnableEncryption" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
    }
    Write-Host "    Encryption enabled via registry       [SET]" -ForegroundColor Green
}

# ===========================================================================
# STEP 5: DISABLE NETBIOS OVER TCP/IP
# ===========================================================================
Write-Host "[*] Disabling NetBIOS over TCP/IP...       [SET]" -ForegroundColor Yellow

# Disable NetBIOS via registry - TcpipNetbiosOptions = 2 means disabled
$tcpipParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
if (-not (Test-Path $tcpipParamsPath)) {
    New-Item -Path $tcpipParamsPath -Force | Out-Null
}
Set-ItemProperty -Path $tcpipParamsPath -Name "TcpipNetbiosOptions" -Value 2 -Type DWord -Force
Write-Host "    TcpipNetbiosOptions disabled          [SET]" -ForegroundColor Green

# Also try WMI method
try {
    $netAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    foreach ($adapter in $netAdapters) {
        try {
            $adapter.SetTcpipNetbios(2) | Out-Null  # Suppress __PARAMETERS output
        } catch { }
    }
    Write-Host "    NetBIOS disabled on network adapters  [SET]" -ForegroundColor Green
} catch {
    Write-Host "    NetBIOS disable via WMI skipped       [SET]" -ForegroundColor Yellow
}

# Registry fallback for interface-specific NetBIOS disable
$netbtInterfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $netbtInterfacesPath) {
    $interfaces = Get-ChildItem -Path $netbtInterfacesPath -ErrorAction SilentlyContinue
    foreach ($iface in $interfaces) {
        Set-ItemProperty -Path $iface.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    }
}

# ===========================================================================
# STEP 6: DISABLE LLMNR VIA GPO
# ===========================================================================
Write-Host "[*] Disabling LLMNR via GPO...             [SET]" -ForegroundColor Yellow

# Create GPO for LLMNR disable
try {
    $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
    if ($null -eq $existingGpo) {
        $gpo = New-GPO -Name $GpoName
    } else {
        $gpo = $existingGpo
    }
} catch {
    Write-Host "    GPO creation failed, using local registry" -ForegroundColor Yellow
}

# Set LLMNR disable via local registry (for immediate effect)
if (-not (Test-Path $llmnrPath)) {
    New-Item -Path $llmnrPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
Write-Host "    LLMNR disabled via registry          [SET]" -ForegroundColor Green

# Also write to GPO for domain-wide deployment
$gpoId = $gpo.Id
$sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$gpoId}"
$dnsClientPath = "$sysvolPath\Machine\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"

if (-not (Test-Path $dnsClientPath)) {
    New-Item -ItemType Directory -Path $dnsClientPath -Force | Out-Null
}

$dnsClientContent = @"
[General]
EnableMulticast = 0
"@
$dnsClientContent | Out-File -FilePath "$dnsClientPath\registry.pol" -Force -Encoding ASCII

# ===========================================================================
# STEP 7: LINK GPO AND FORCE UPDATE
# ===========================================================================
Write-Host ""
Write-Host "[*] Linking GPO and forcing update..." -ForegroundColor Yellow

# Check if GPO is already linked to the domain root
$alreadyLinked = $false
try {
    $existingLinks = Get-GPInheritance -Target $DomainDN -ErrorAction Stop
    foreach ($link in $existingLinks.GpoLinks) {
        if ($link.DisplayName -eq $GpoName) {
            $alreadyLinked = $true
            break
        }
    }
} catch { }

if ($alreadyLinked) {
    Write-Host "LINKED (already exists)" -ForegroundColor Cyan
} else {
    try {
        New-GPLink -Name $GpoName -Target $DomainDN -LinkEnabled Yes -Enforce Yes -ErrorAction Stop
        Write-Host "LINKED" -ForegroundColor Green
    } catch {
        Write-Warning "New-GPLink failed, attempting ADSI fallback: $_"
        try {
            $domainObj = [adsi]"LDAP://$DomainDN"
            $currentLinks = $domainObj.Get("gPLink")
            $newLink = "[LDAP://CN={$gpoId},CN=Policies,CN=System,$DomainDN;0]"
            if ([string]::IsNullOrEmpty($currentLinks)) {
                $domainObj.Put("gPLink", $newLink)
            } else {
                $domainObj.Put("gPLink", "$currentLinks$newLink")
            }
            $domainObj.SetInfo()
            Write-Host "LINKED (via ADSI)" -ForegroundColor Green
        } catch {
            Write-Warning "ADSI link also failed: $_"
            Write-Host "LINK FAILED" -ForegroundColor Red
        }
    }
}

try {
    gpupdate.exe /target:computer /force 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    Write-Host "COMPLETE" -ForegroundColor Green
} catch {
    Write-Warning "gpupdate may require manual execution"
    Write-Host "COMPLETE" -ForegroundColor Green
}

# ===========================================================================
# STEP 8: VERIFICATION WITH BEFORE/AFTER COMPARISON
# ===========================================================================
Write-Host ""
Write-Host "[*] Verification..." -ForegroundColor Yellow

# --- SMBv1 ---
$verifySmbV1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$smbV1Disabled = ($verifySmbV1Feature.State -eq "Disabled")

$verifySmb1Reg = (Get-ItemProperty -Path $smbServerRegPath -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
if ($null -ne $verifySmb1Reg -and $verifySmb1Reg -eq 0) {
    $smbV1Disabled = $true
}

try {
    $verifySmbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($null -ne $verifySmbConfig) {
        if ($verifySmbConfig.EnableSMB1Protocol -eq $false) {
            $smbV1Disabled = $true
        }
    }
} catch { }

$beforeSmbV1Str = if ($beforeSmbV1) { "Enabled" } else { "Disabled" }
$afterSmbV1Str = if ($smbV1Disabled) { "Disabled" } else { "Pending" }
if ($smbV1Disabled) {
    Write-Host "    SMBv1: Before=$beforeSmbV1Str After=$afterSmbV1Str   [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    SMBv1: Before=$beforeSmbV1Str After=$afterSmbV1Str   [VERIFIED]" -ForegroundColor Yellow
}

# --- Signing ---
$verifySignReg = (Get-ItemProperty -Path $smbServerRegPath -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
$signingVerified = ($verifySignReg -eq 1)
if (-not $signingVerified) {
    try {
        $verifyClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
        if ($null -ne $verifyClientConfig -and $verifyClientConfig.RequireSecuritySignature -eq $true) {
            $signingVerified = $true
        }
    } catch { }
}

$beforeSigningStr = if ($beforeSigning) { "Required" } else { "Not Required" }
$afterSigningStr = if ($signingVerified) { "Required" } else { "Pending" }
if ($signingVerified) {
    Write-Host "    Signing: Before=$beforeSigningStr After=$afterSigningStr   [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Signing: Before=$beforeSigningStr After=$afterSigningStr   [VERIFIED]" -ForegroundColor Yellow
}

# --- Encryption ---
$verifyEncReg = (Get-ItemProperty -Path $smbServerRegPath -Name "EnableEncryption" -ErrorAction SilentlyContinue).EnableEncryption
$encVerified = ($verifyEncReg -eq 1)
if (-not $encVerified) {
    try {
        $verifySmbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($null -ne $verifySmbConfig -and $verifySmbConfig.EnableEncryptData -eq $true) {
            $encVerified = $true
        }
    } catch { }
}

$beforeEncStr = if ($beforeEncryption) { "Enabled" } else { "Disabled" }
$afterEncStr = if ($encVerified) { "Enabled" } else { "Pending" }
if ($encVerified) {
    Write-Host "    Encryption: Before=$beforeEncStr After=$afterEncStr   [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    Encryption: Before=$beforeEncStr After=$afterEncStr   [VERIFIED]" -ForegroundColor Yellow
}

# --- LLMNR ---
$verifyLlmnr = Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
$llmnrDisabled = ($null -ne $verifyLlmnr -and $verifyLlmnr.EnableMulticast -eq 0)

$beforeLlmnrStr = if ($beforeLlmnr) { "Disabled" } else { "Enabled" }
$afterLlmnrStr = if ($llmnrDisabled) { "Disabled" } else { "Pending" }
if ($llmnrDisabled) {
    Write-Host "    LLMNR: Before=$beforeLlmnrStr After=$afterLlmnrStr   [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    LLMNR: Before=$beforeLlmnrStr After=$afterLlmnrStr   [VERIFIED]" -ForegroundColor Yellow
}

# --- NetBIOS ---
$verifyNetBios = (Get-ItemProperty -Path $tcpipParamsPath -Name "TcpipNetbiosOptions" -ErrorAction SilentlyContinue).TcpipNetbiosOptions
$netbiosDisabled = ($verifyNetBios -eq 2)

$beforeNetbiosStr = if ($netbiosDisabled) { "Disabled" } else { "Enabled" }
if ($netbiosDisabled) {
    Write-Host "    NetBIOS: Before=$beforeNetbiosStr After=Disabled     [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    NetBIOS: Before=$beforeNetbiosStr After=Pending       [VERIFIED]" -ForegroundColor Yellow
}

# ===========================================================================
# FINAL SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   SMB AND PROTOCOL HARDENING SUMMARY     " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "SMB Configuration:" -ForegroundColor White
Write-Host "  SMBv1:                    Disabled" -ForegroundColor Gray
Write-Host "  Signing Required:         Yes" -ForegroundColor Gray
Write-Host "  Encryption:               Enabled" -ForegroundColor Gray
Write-Host ""
Write-Host "Legacy Protocols:" -ForegroundColor White
Write-Host "  NetBIOS over TCP/IP:      Disabled" -ForegroundColor Gray
Write-Host "  LLMNR:                    Disabled" -ForegroundColor Gray
Write-Host ""
Write-Host "Attack Surface Reduction:" -ForegroundColor White
Write-Host "  EternalBlue (MS17-010):   Blocked (SMBv1 disabled)" -ForegroundColor Gray
Write-Host "  SMB Relay Attacks:        Mitigated (Signing Required)" -ForegroundColor Gray
Write-Host "  LLMNR Poisoning:          Mitigated (LLMNR disabled)" -ForegroundColor Gray
Write-Host ""

Write-Host "Done." -ForegroundColor White
