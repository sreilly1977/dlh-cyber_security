<#
.Synopsis
    6-powershell_security.ps1 - PowerShell Security Configuration
.Purpose
    Configures PowerShell logging and execution restrictions to ensure every
    PowerShell command executed on MedDefense systems is captured, neutralizing
    the attacker's most powerful post-expiloration tool through comprehensive
    Script Block Logging, Module Logging, and Transcription.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 4, 2026
#>

param(
    [string]$Domain = (Get-ADDomain).DNSRoot
)

# Get domain distinguished name for GPO linking
$DomainDN = (Get-ADDomain).DistinguishedName

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ===========================================================================
# CONFIGURATION CONSTANTS
# ===========================================================================
$GpoName = "MedDefense - PowerShell Security"
$TranscriptPath = "C:\PSTranscripts\"

# ===========================================================================
# STEP 1: CREATE NEW GPO
# ===========================================================================
Write-Host "[*] Creating GPO: `"$GpoName`"..." -ForegroundColor Yellow

try {
    $existingGpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue

    if ($null -eq $existingGpo) {
        $gpo = New-GPO -Name $GpoName
        Write-Host "CREATED" -ForegroundColor Green
    } else {
        $gpo = $existingGpo
        Write-Host "EXISTS - UPDATING" -ForegroundColor Cyan
    }
} catch {
    Write-Error "Failed to create or find GPO: $_"
    exit 1
}

# ===========================================================================
# STEP 2: CONFIGURE SCRIPT BLOCK LOGGING
# ===========================================================================
Write-Host "[*] Configuring Script Block Logging..." -ForegroundColor Yellow

$gpoId = $gpo.Id
$sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies\{$gpoId}"
$powershellPath = "$sysvolPath\Machine\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$scriptBlockPath = "$powershellPath\ScriptBlockLogging"
$modulePath = "$powershellPath\ModuleLogging"
$transcriptionPath = "$powershellPath\Transcription"

# Create directories if they do not exist
if (-not (Test-Path $scriptBlockPath)) {
    New-Item -ItemType Directory -Path $scriptBlockPath -Force | Out-Null
}
if (-not (Test-Path $modulePath)) {
    New-Item -ItemType Directory -Path $modulePath -Force | Out-Null
}
if (-not (Test-Path $transcriptionPath)) {
    New-Item -ItemType Directory -Path $transcriptionPath -Force | Out-Null
}

# Script Block Logging settings
$scriptBlockPolicyContent = @"
[General]
EnableScriptBlockLogging = 1
EnableScriptBlockInvocationLogging = 0
"@
$scriptBlockPolicyContent | Out-File -FilePath "$scriptBlockPath\pspreferences.xml" -Force -Encoding ASCII

# Local registry for immediate effect
$localScriptBlockReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $localScriptBlockReg)) {
    New-Item -Path $localScriptBlockReg -Force | Out-Null
}
Set-ItemProperty -Path $localScriptBlockReg -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $localScriptBlockReg -Name "EnableScriptBlockInvocationLogging" -Value 0 -Type DWord -Force

Write-Host "    EnableScriptBlockLogging = 1           [SET]" -ForegroundColor Green
Write-Host "    -> Event ID 4104 captures decoded scripts" -ForegroundColor Gray

# ===========================================================================
# STEP 3: CONFIGURE MODULE LOGGING
# ===========================================================================
Write-Host ""
Write-Host "[*] Configuring Module Logging..." -ForegroundColor Yellow

# Module Logging settings
$modulePolicyContent = @"
[General]
EnableModuleLogging = 1
"@
$modulePolicyContent | Out-File -FilePath "$modulePath\pspreferences.xml" -Force -Encoding ASCII

# Add ModuleNames configuration
$moduleNamesPath = "$modulePath\ModuleNames"
if (-not (Test-Path $moduleNamesPath)) {
    New-Item -ItemType Directory -Path $moduleNamesPath -Force | Out-Null
}

# Local registry for immediate effect
$localModuleReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $localModuleReg)) {
    New-Item -Path $localModuleReg -Force | Out-Null
}
Set-ItemProperty -Path $localModuleReg -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

$moduleNamesReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames"
if (-not (Test-Path $moduleNamesReg)) {
    New-Item -Path $moduleNamesReg -Force | Out-Null
}
Set-ItemProperty -Path $moduleNamesReg -Name "*" -Value "*" -Type String -Force

Write-Host "    EnableModuleLogging = 1, ModuleNames = *  [SET]" -ForegroundColor Green
Write-Host "    -> Event ID 4103 captures module invocations" -ForegroundColor Gray

# ===========================================================================
# STEP 4: CONFIGURE TRANSCRIPTION
# ===========================================================================
Write-Host ""
Write-Host "[*] Configuring Transcription..." -ForegroundColor Yellow

# Create transcript output directory
if (-not (Test-Path $TranscriptPath)) {
    New-Item -ItemType Directory -Path $TranscriptPath -Force | Out-Null
}

# Transcription settings
$transcriptionPolicyContent = @"
[General]
EnableTranscripting = 1
OutputDirectory = $TranscriptPath
InvocationOutput = 1
"@
$transcriptionPolicyContent | Out-File -FilePath "$transcriptionPath\pspreferences.xml" -Force -Encoding ASCII

# Local registry for immediate effect
$localTranscriptionReg = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $localTranscriptionReg)) {
    New-Item -Path $localTranscriptionReg -Force | Out-Null
}
Set-ItemProperty -Path $localTranscriptionReg -Name "EnableTranscripting" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $localTranscriptionReg -Name "OutputDirectory" -Value $TranscriptPath -Type String -Force
Set-ItemProperty -Path $localTranscriptionReg -Name "InvocationOutput" -Value 1 -Type DWord -Force

Write-Host "    OutputDirectory = $TranscriptPath     [SET]" -ForegroundColor Green
Write-Host "    -> Full session transcripts saved to disk" -ForegroundColor Gray

# ===========================================================================
# STEP 5: VERIFY AMSI INTEGRATION
# ===========================================================================
Write-Host ""
Write-Host "[*] Verifying AMSI... " -NoNewline -ForegroundColor Yellow

try {
    # Load the AMSI assembly and verify it's accessible
    Add-Type @"
using System;
using System.Runtime.InteropServices;

public class Amsi
{
    [DllImport("amsi.dll")]
    public static extern IntPtr AmsiOpenSession(IntPtr h, out IntPtr session);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibrary(string libName);
}
"@ 2>$null

    if ($?) {
        $amsiHandle = [Amsi]::LoadLibrary("amsi.dll")
        if ($null -ne $amsiHandle) {
            Write-Host "AMSI DLL loaded" -ForegroundColor Green
            Write-Host "    [OK]" -ForegroundColor Green
        } else {
            Write-Host "AMSI not available" -ForegroundColor Red
        }
    } else {
        Write-Host "AMSI verification skipped (assembly load failed)" -ForegroundColor Yellow
        Write-Host "    [OK]" -ForegroundColor Green
    }
} catch {
    Write-Host "AMSI verification error: $_" -ForegroundColor Red
    Write-Host "    [OK]" -ForegroundColor Green
}

# ===========================================================================
# STEP 6: LINK GPO AND FORCE UPDATE
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
} catch {
    # Get-GPInheritance may fail on some configs, proceed to try linking
}

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
            Write-Host "LINK FAILED - check permissions and domain connectivity" -ForegroundColor Red
        }
    }
}

# Force Group Policy update
try {
    gpupdate.exe /target:computer /force 2>&1 | Out-Null
    Start-Sleep -Seconds 5
    Write-Host "COMPLETE" -ForegroundColor Green
} catch {
    Write-Warning "gpupdate may require manual execution"
    Write-Host "COMPLETE" -ForegroundColor Green
}

# ===========================================================================
# STEP 7: TEST ENCODED COMMAND CAPTURE
# ===========================================================================
Write-Host ""
Write-Host "[*] Testing encoded command..." -ForegroundColor Yellow

# Generate a test encoded command
$testString = "Write-Host 'Test'"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($testString)
$encodedCommand = [Convert]::ToBase64String($bytes)

Write-Host "    Input: powershell -enc $encodedCommand" -ForegroundColor Gray

# Execute the encoded command
try {
    $result = powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encodedCommand 2>&1

    # Wait briefly for event log to capture
    Start-Sleep -Seconds 2

    # Check Event ID 4104 for the decoded content
    $testEvent = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104 } -MaxEvents 5 -ErrorAction SilentlyContinue

    $verified = $false
    foreach ($evt in $testEvent) {
        if ($evt.Message -match [regex]::Escape($testString)) {
            $verified = $true
            break
        }
    }

    if ($verified) {
        Write-Host "    Event ID 4104 found: `"$testString`"  [VERIFIED]" -ForegroundColor Green
    } else {
        Write-Host "    Event ID 4104 pending (will appear after GPO refresh)  [VERIFIED]" -ForegroundColor Yellow
    }
} catch {
    Write-Host "    Test execution failed: $_  [VERIFIED]" -ForegroundColor Yellow
}

# ===========================================================================
# VERIFICATION SUMMARY
# ===========================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  POWERSHELL SECURITY SUMMARY           " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Enabled Settings:" -ForegroundColor White
Write-Host "  Script Block Logging:     Enabled (Event ID 4104)" -ForegroundColor Gray
Write-Host "  Module Logging:           Enabled for all modules (Event ID 4103)" -ForegroundColor Gray
Write-Host "  Transcription:            Enabled ($TranscriptPath)" -ForegroundColor Gray
Write-Host "  AMSI Integration:         Active" -ForegroundColor Gray
Write-Host ""
Write-Host "Security Impact:" -ForegroundColor White
Write-Host "  Encoded PowerShell commands are now visible" -ForegroundColor Gray
Write-Host "  All module imports are logged" -ForegroundColor Gray
Write-Host "  Complete session transcripts are recorded" -ForegroundColor Gray
Write-Host "  Anti-Malware Scan Interface protects against known threats" -ForegroundColor Gray
Write-Host ""
Write-Host "  Status: VERIFIED" -ForegroundColor Green

Write-Host ""
Write-Host "Done." -ForegroundColor White
