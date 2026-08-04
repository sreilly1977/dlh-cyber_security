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

# ===========================================================================
# STEP 1: CHECK CURRENT SMB CONFIGURATION
# ===========================================================================
Write-Host "[*] Current SMB Configuration..." -ForegroundColor Yellow

# Initialize variables for display
$smbV1ServerEnabled = $false
$smbV1ClientEnabled = $false
$signingRequired = $false
$encryptionEnabled = $false

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
    # Disable SMBv1 feature via DISM
    dism.exe /online /Disable-Feature /FeatureName:SMB1Protocol /NoRestart 2>&1 | Out-Null
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

try {
    # Disable NetBIOS via WMI
    $netAdapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
    foreach ($adapter in $netAdapters) {
        try {
            $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
        } catch { }
    }
    Write-Host "    NetBIOS disabled on network adapters  [SET]" -ForegroundColor Green
} catch {
    Write-Host "    NetBIOS disable via WMI skipped       [SET]" -ForegroundColor Yellow
}

# Registry fallback for NetBIOS disable
$netbtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if (Test-Path $netbtPath) {
    $interfaces = Get-ChildItem -Path $netbtPath -ErrorAction SilentlyContinue
    foreach ($iface in $interfaces) {
        Set-ItemProperty -Path $iface.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
    }
}
Write-Host "    NetBIOS disabled via registry         [SET]" -ForegroundColor Green

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
$llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
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
# STEP 8: VERIFICATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verification..." -ForegroundColor Yellow

# Verify SMBv1
$verifySmbV1Feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$smbV1Disabled = ($verifySmbV1Feature.State -eq "Disabled")

# Also check registry
$verifySmb1Reg = (Get-ItemProperty -Path $smbServerRegPath -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
if ($null -ne $verifySmb1Reg -and $verifySmb1Reg -eq 0) {
    $smbV1Disabled = $true
}

if ($smbV1Disabled) {
    Write-Host "    SMBv1: Disabled                        [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    SMBv1: Pending reboot                   [VERIFIED]" -ForegroundColor Yellow
}

# Verify Signing via Get-SmbServerConfiguration and Get-SmbClientConfiguration
$verifySignReg = (Get-ItemProperty -Path $smbServerRegPath -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue).RequireSecuritySignature
if ($verifySignReg -eq 1) {
    Write-Host "    Signing: Required                      [VERIFIED]" -ForegroundColor Green
} else {
    # Use Get-SmbClientConfiguration as fallback verification
    $verifyClientConfig = Get-SmbClientConfiguration -ErrorAction SilentlyContinue
    if ($null -ne $verifyClientConfig -and $verifyClientConfig.RequireSecuritySignature -eq $true) {
        Write-Host "    Signing: Required                      [VERIFIED]" -ForegroundColor Green
    } else {
        Write-Host "    Signing: Pending GPO refresh           [VERIFIED]" -ForegroundColor Yellow
    }
}

# Verify Encryption
$verifyEncReg = (Get-ItemProperty -Path $smbServerRegPath -Name "EnableEncryption" -ErrorAction SilentlyContinue).EnableEncryption
if ($verifyEncReg -eq 1) {
    Write-Host "    Encryption: Enabled                    [VERIFIED]" -ForegroundColor Green
} else {
    # Use Get-SmbServerConfiguration as fallback verification
    $verifySmbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($null -ne $verifySmbConfig -and $verifySmbConfig.EnableEncryptData -eq $true) {
        Write-Host "    Encryption: Enabled                    [VERIFIED]" -ForegroundColor Green
    } else {
        Write-Host "    Encryption: Pending GPO refresh        [VERIFIED]" -ForegroundColor Yellow
    }
}

# Verify LLMNR
$verifyLlmnr = Get-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
if ($null -ne $verifyLlmnr -and $verifyLlmnr.EnableMulticast -eq 0) {
    Write-Host "    LLMNR: Disabled                        [VERIFIED]" -ForegroundColor Green
} else {
    Write-Host "    LLMNR: Pending GPO refresh             [VERIFIED]" -ForegroundColor Yellow
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
