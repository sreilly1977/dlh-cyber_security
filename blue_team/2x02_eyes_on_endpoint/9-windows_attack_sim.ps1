<#
.Notes
    name:        9-windows_attack_sim.ps1
    purpose:     Execute controlled attacker simulation and record ground truth
    author:      Steve - Cybersecurity Engineer
    date:        August 10, 2026

.Purpose
    This script executes a realistic attack sequence against a hardened Windows endpoint
    and records ground truth data for telemetry validation. The sequence includes:

        1. Create local user account (support_update)
        2. Add user to Administrators group
        3. Run encoded PowerShell command
        4. Create scheduled task for persistence
        5. Initiate outbound network connection (Sysmon Event ID 3)
        6. Drop file in startup directory (Sysmon Event ID 11)

    After execution, all artifacts are cleaned up while preserving the ground truth log.

    Output: windows_attack_log.json with action details, timestamps, detection sources, and MITRE techniques
#>

Set-StrictMode -Version Latest

# Check for administrator privileges before starting
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] This script requires Administrator privileges. Please run as Administrator." -ForegroundColor Red
    exit 1
}

# Configuration
$Username = "support_update"
# Password must meet domain policy: min 14 chars, complexity enabled
$Password = "Simulat3d@ttack!2026"
$StartupPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
$SafeExternalIP = "8.8.8.8"
$OutputFile = "windows_attack_log.json"

# Initialize ground truth collection
$GroundTruth = @()
$actionCounter = 0

# Initialize cleanup tracking variables
$script:CleanupTaskName = $null
$script:CleanupFilePath = $null
$script:UserCreated = $false

function Get-UTCTimestamp {
    return (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ").ToString()
}

function Add-GroundTruthEntry {
    param (
        [int]$ActionNumber,
        [string]$Description,
        [string]$Timestamp,
        [string[]]$ExpectedDetectionSources,
        [string[]]$MitreTechniques
    )

    $Entry = [PSCustomObject]@{
        action_number             = $ActionNumber
        description               = $Description
        timestamp                 = $Timestamp
        expected_detection_source = $ExpectedDetectionSources
        mitre_attack_technique    = $MitreTechniques
    }

    $script:GroundTruth += $Entry
}

Write-Host "[*] Running Windows attacker simulation..."

try {
    # =========================================================================
    # Step 1: Create Local User Account (Security Event ID 4720)
    # =========================================================================
    $actionCounter++
    $Timestamp = Get-UTCTimestamp
    Write-Host "    [$actionCounter/6] Creating local user '$Username'...      $Timestamp"

    try {
        $SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $Username -Password $SecurePassword -AccountNeverExpires -Description "Attacker sim user" -ErrorAction Stop | Out-Null
        $script:UserCreated = $true

        Add-GroundTruthEntry -ActionNumber $actionCounter `
                             -Description "Created local user account '$Username'" `
                             -Timestamp $Timestamp `
                             -ExpectedDetectionSources @("Security Event ID 4720") `
                             -MitreTechniques @("T1136.001 - Account Creation: Local Account")
    } catch {
        Write-Host "          [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    }

    # =========================================================================
    # Step 2: Add User to Administrators Group (Security Event ID 4732)
    # =========================================================================
    $actionCounter++
    $Timestamp = Get-UTCTimestamp
    Write-Host "    [$actionCounter/6] Adding to Administrators group...      $Timestamp"

    try {
        if ($script:UserCreated) {
            $added = $false

            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $AdminGroup = Get-ADGroup -Filter "SID -eq 'S-1-5-32-544'" -ErrorAction Stop
                    if ($null -ne $AdminGroup) {
                        Add-ADGroupMember -Identity $AdminGroup -Members $Username -ErrorAction Stop
                        $added = $true
                    }
                } catch {
                    # AD method failed, will try net localgroup below
                }
            }

            if (-not $added) {
                $output = & net.exe localgroup administrators $Username /add 2>&1
                if ($LASTEXITCODE -ne 0) {
                    throw "net localgroup failed (exit $LASTEXITCODE): $output"
                }
            }

            Add-GroundTruthEntry -ActionNumber $actionCounter `
                                 -Description "Added user '$Username' to Administrators group" `
                                 -Timestamp $Timestamp `
                                 -ExpectedDetectionSources @("Security Event ID 4732") `
                                 -MitreTechniques @("T1078.001 - Valid Accounts: Domain Admins", "T1098 - Account Manipulation")
        } else {
            throw "Skipped: user creation failed"
        }
    } catch {
        Write-Host "          [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    }

    # =========================================================================
    # Step 3: Run Encoded PowerShell Command (PowerShell Event ID 4104, Sysmon Event ID 1)
    # =========================================================================
    $actionCounter++
    $Timestamp = Get-UTCTimestamp
    Write-Host "    [$actionCounter/6] Running encoded PowerShell...          $Timestamp"

    try {
        $Payload = "Write-Host 'C2 beacon'"
        $EncodedBytes = [System.Text.Encoding]::Unicode.GetBytes($Payload)
        $EncodedBase64 = [Convert]::ToBase64String($EncodedBytes)

        Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -enc $EncodedBase64" -Wait -ErrorAction Stop

        Add-GroundTruthEntry -ActionNumber $actionCounter `
                             -Description "Executed encoded PowerShell command (payload: Write-Host 'C2 beacon')" `
                             -Timestamp $Timestamp `
                             -ExpectedDetectionSources @("Security Event ID 4688", "PowerShell Event ID 4104", "Sysmon Event ID 1") `
                             -MitreTechniques @("T1059.001 - PowerShell", "T1140 - Deobfuscate/Decode Files or Information")
    } catch {
        Write-Host "          [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    }

    # =========================================================================
    # Step 4: Create Scheduled Task for Persistence (Sysmon Event ID 20, Security Event ID 4698)
    # =========================================================================
    $actionCounter++
    $Timestamp = Get-UTCTimestamp
    Write-Host "    [$actionCounter/6] Creating scheduled task...             $Timestamp"

    try {
        $TaskName = "WinUpdateService_$([GUID]::NewGuid().ToString().Substring(0,8))"

        # Use schtasks /create as required by the exercise
        $output = & schtasks.exe /create /tn $TaskName /tr "powershell.exe -WindowStyle Hidden -Command Write-Host 'Persistence task'" /sc onlogon /ru SYSTEM /rl highest 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw "schtasks failed (exit $LASTEXITCODE): $output"
        }

        $script:CleanupTaskName = $TaskName

        Add-GroundTruthEntry -ActionNumber $actionCounter `
                             -Description "Created scheduled task '$TaskName' for persistence" `
                             -Timestamp $Timestamp `
                             -ExpectedDetectionSources @("Security Event ID 4698", "Sysmon Event ID 20") `
                             -MitreTechniques @("T1053.005 - Scheduled Task/Job")
    } catch {
        Write-Host "          [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    }

    # =========================================================================
    # Step 5: Initiate Outbound Network Connection (Sysmon Event ID 3)
    # =========================================================================
    $actionCounter++
    $Timestamp = Get-UTCTimestamp
    Write-Host "    [$actionCounter/6] Outbound network connection...          $Timestamp"

    try {
        Test-NetConnection -ComputerName $SafeExternalIP -Port 443 -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null

        Add-GroundTruthEntry -ActionNumber $actionCounter `
                             -Description "Initiated outbound connection to $SafeExternalIP:443" `
                             -Timestamp $Timestamp `
                             -ExpectedDetectionSources @("Sysmon Event ID 3") `
                             -MitreTechniques @("T1071.001 - Application Layer Protocol: Web Protocols")
    } catch {
        Write-Host "          [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    }

    # =========================================================================
    # Step 6: Drop File in Startup Directory (Sysmon Event ID 11)
    # =========================================================================
    $actionCounter++
    $Timestamp = Get-UTCTimestamp
    Write-Host "    [$actionCounter/6] Dropping file in Startup...             $Timestamp"

    try {
        if (-not (Test-Path $StartupPath)) {
            New-Item -ItemType Directory -Path $StartupPath -Force | Out-Null
        }

        $StartupFile = Join-Path $StartupPath "update_helper.bat"
        $DummyContent = "@echo off`r`necho ATTACK SIMULATION MARKER - DO NOT EXECUTE`r`nrem Timestamp: $(Get-Date)"

        Set-Content -Path $StartupFile -Value $DummyContent -Force -ErrorAction Stop

        $script:CleanupFilePath = $StartupFile

        Add-GroundTruthEntry -ActionNumber $actionCounter `
                             -Description "Dropped file '$StartupFile' in startup directory" `
                             -Timestamp $Timestamp `
                             -ExpectedDetectionSources @("Sysmon Event ID 11") `
                             -MitreTechniques @("T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "T1105 - Ingress Tool Transfer")
    } catch {
        Write-Host "          [ERROR: $($_.Exception.Message)]" -ForegroundColor Red
    }

    # =========================================================================
    # Cleanup Phase
    # =========================================================================
    Write-Host "[*] Cleaning up artifacts..."

    $Cleaned = @()

    # Remove user account
    if ($script:UserCreated) {
        try {
            Remove-LocalUser -Name $Username -ErrorAction Stop
            $Cleaned += "User removed"
        } catch {
            Write-Host "    [WARNING: Failed to remove user: $($_.Exception.Message)]" -ForegroundColor Yellow
        }
    }

    # Delete scheduled task
    if ($null -ne $script:CleanupTaskName) {
        try {
            Unregister-ScheduledTask -TaskName $script:CleanupTaskName -Confirm:$false -ErrorAction Stop
            $Cleaned += "task deleted"
        } catch {
            Write-Host "    [WARNING: Failed to delete task: $($_.Exception.Message)]" -ForegroundColor Yellow
        }
    }

    # Remove startup file
    if ($null -ne $script:CleanupFilePath -and (Test-Path $script:CleanupFilePath)) {
        try {
            Remove-Item -Path $script:CleanupFilePath -Force -ErrorAction Stop
            $Cleaned += "file removed"
        } appear

    appear

    } catch {
        Write-Host "    [WARNING: Failed to remove file: $($_.Exception.Message)]" -ForegroundColor Yellow
    }
    appear
    if ($Cleaned.Count -gt 0) {
        Write-Host "    $($Cleaned -join ', ')                           [CLEAN]" -ForegroundColor Green
    }
    appear
    Write-Host "Actions executed: $actionCounter"
    Write-Host "Ground truth saved to: $OutputFile"

    # =========================================================================
    # Save Ground Truth JSON
    # =========================================================================
    try {
        $GroundTruth | ConvertTo-Json -Depth 5 | Out-File $OutputFile -Encoding UTF8 -Force
    } catch {
        Write-Host "[ERROR] Failed to save ground truth: $($_.Exception.Message)]" -ForegroundColor Red
        exit 1
    }

} catch {
    Write-Host "[CRITICAL ERROR] Simulation interrupted: $($_.Exception.Message)]" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    exit 1
}

Write-Host "[*] Simulation complete."
