<#
.Notes
    name:        10-windows_detection_proof.ps1
    purpose:     Correlate attack simulation log against captured telemetry to produce detection matrix
    author:      Steve - Cybersecurity Engineer
    date:        August 10, 2026

.Purpose
    This script correlates the Windows attack simulation log (ground truth from Task 9)
    against captured telemetry to prove which actions were detected by instrumentation.

    For each simulated action, it searches Windows Event Logs within a 60-second window
    around the recorded timestamp and determines:

        - Which source captured it (Security, Sysmon, PowerShell)
        - The Event ID that fired
        - Detail level (Full/Partial/Missed)
        - Key fields present in the event

    Output: windows_detection_matrix.json
#>

Set-StrictMode -Version Latest

# Configuration
$GroundTruthFile = "windows_attack_log.json"
$OutputFile = "windows_detection_matrix.json"
$TimeWindowSeconds = 60

# Action to expected detection mappings
# Broadened Event IDs to cover domain controller variations
$DetectionMappings = @{
    "local user account" = @{
        Sources = @(
            @{LogName="Security"; EventId=4720},  # User account created
            @{LogName="Security"; EventId=4722},  # User account enabled
            @{LogName="Microsoft-Windows-Sysmon/Operational"; EventId=1}
        )
        Keywords = @("support_update", "account", "user", "created")
    }
    "Administrators group" = @{
        Sources = @(
            @{LogName="Security"; EventId=4732},  # Member added to local group
            @{LogName="Security"; EventId=4728},  # Member added to global group
            @{LogName="Security"; EventId=4761}   # Member added to universal group
        )
        Keywords = @("Administrators", "support_update", "member", "added")
    }
    "encoded PowerShell" = @{
        Sources = @(
            @{LogName="Microsoft-Windows-PowerShell/Operational"; EventId=4104},
            @{LogName="Security"; EventId=4688},
            @{LogName="Microsoft-Windows-Sysmon/Operational"; EventId=1}
        )
        Keywords = @("Write-Host", "beacon", "enc", "powershell", "C2")
    }
    "scheduled task" = @{
        Sources = @(
            @{LogName="Microsoft-Windows-Sysmon/Operational"; EventId=20},
            @{LogName="Security"; EventId=4698},
            @{LogName="Microsoft-Windows-Sysmon/Operational"; EventId=1}
        )
        Keywords = @("scheduled", "task", "WinUpdateService", "schtasks")
    }
    "outbound connection" = @{
        Sources = @(@{LogName="Microsoft-Windows-Sysmon/Operational"; EventId=3})
        Keywords = @("8.8.8.8", "connection", "network")
    }
    "startup" = @{
        Sources = @(@{LogName="Microsoft-Windows-Sysmon/Operational"; EventId=11})
        Keywords = @("startup", "update_helper", "StartUp")
    }
}

function Get-UTCTimestamp {
    return (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ").ToString()
}

function Find-EventInRange {
    param (
        [string]$LogName,
        [int]$EventId,
        [DateTime]$TargetTime,
        [int]$WindowSeconds
    )

    $StartTime = $TargetTime.AddSeconds(-$WindowSeconds)
    $EndTime = $TargetTime.AddSeconds($WindowSeconds)

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogName
            Id        = $EventId
            StartTime = $StartTime
            EndTime   = $EndTime
        } -MaxEvents 20 -ErrorAction Stop

        if ($null -eq $Events) {
            return ,@()
        }
        return ,@($Events)
    } catch {
        return ,@()
    }
}

function Evaluate-DetailLevel {
    param (
        $Event,
        [string[]]$Keywords
    )

    if ($null -eq $Event) {
        return "Missed"
    }

    $MatchCount = 0
    $Message = ""
    if ($null -ne $Event.Message) {
        $Message = $Event.Message
    }

    foreach ($Keyword in $Keywords) {
        if ($Message -match $Keyword) {
            $MatchCount++
        }
    }

    if ($MatchCount -ge 2) {
        return "Full"
    } elseif ($MatchCount -ge 1) {
        return "Partial"
    } else {
        return "Partial"
    }
}

function Get-KeyFields {
    param ($Event)

    $Fields = @{}

    if ($null -eq $Event) {
        return $Fields
    }

    if ($null -ne $Event.Id) {
        $Fields["EventID"] = $Event.Id
    }

    if ($null -ne $Event.TimeCreated) {
        $Fields["Timestamp"] = $Event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    if ($null -ne $Event.ProviderName) {
        $Fields["Provider"] = $Event.ProviderName
    }

    if ($null -ne $Event.Message -and $Event.Message.Length -gt 0) {
        $Fields["HasMessage"] = $true
        $Fields["MessageLength"] = $Event.Message.Length
    }

    return $Fields
}

Write-Host "[*] Loading ground truth (6 actions)..."

try {
    if (-not (Test-Path $GroundTruthFile)) {
        Write-Host "[ERROR] Ground truth file '$GroundTruthFile' not found." -ForegroundColor Red
        Write-Host "Please run 9-windows_attack_sim.ps1 first to generate the attack log." -ForegroundColor Yellow
        exit 1
    }

    $RawJson = Get-Content $GroundTruthFile -Raw
    $GroundTruth = $RawJson | ConvertFrom-Json

    # Force array conversion
    if ($GroundTruth -isnot [array]) {
        $GroundTruth = @($GroundTruth)
    }

    $TotalActions = $GroundTruth.Length

    Write-Host "[*] Searching telemetry for each action..."
    Write-Host ""

    $DetectionMatrix = @()
    $MultiSourceCount = 0
    $CapturedCount = 0

    $headerFormat = "{0,-36} {1,-20} {2,-10} {3,-10} {4}"
    Write-Host ($headerFormat -f "Action", "Source", "Event ID", "Detail", "Status") -ForegroundColor Cyan
    Write-Host ($headerFormat -f "------", "------", "--------", "------", "------") -ForegroundColor Cyan

    # Use enumerator to avoid .Count issues
    $ActionEnumerator = $GroundTruth.GetEnumerator()
    while ($ActionEnumerator.MoveNext()) {
        $Action = $ActionEnumerator.Current
        if ($null -eq $Action) { continue }

        $ActionDesc = ""
        if ($null -ne $Action.description) { $ActionDesc = $Action.description }

        $ActionTimestamp = ""
        if ($null -ne $Action.timestamp) { $ActionTimestamp = $Action.timestamp }

        $MitreTech = @()
        if ($null -ne $Action.mitre_attack_technique) {
            if ($Action.mitre_attack_technique -is [array]) {
                $MitreTech = $Action.mitre_attack_technique
            } else {
                $MitreTech = @($Action.mitre_attack_technique)
            }
        }

        $ActionNum = 1
        if ($null -ne $Action.action_number) { $ActionNum = $Action.action_number }

        # Parse timestamp - strip trailing Z to parse as local time
        $CleanTimestamp = $ActionTimestamp -replace 'Z$', ''
        try {
            $TargetTime = [DateTime]::Parse($CleanTimestamp)
        } catch {
            Write-Host "  [ERROR] Could not parse timestamp: $ActionTimestamp" -ForegroundColor Red
            continue
        }

        $Rule = $null
        foreach ($Pattern in $DetectionMappings.Keys) {
            if ($ActionDesc -match $Pattern) {
                $Rule = $DetectionMappings[$Pattern]
                break
            }
        }

        if ($null -eq $Rule) {
            Write-Host "  [WARNING] No detection mapping found for: $ActionDesc" -ForegroundColor Yellow
            continue
        }

        $ActionResults = @()
        $SourcesCaptured = 0
        $FirstRow = $true

        foreach ($Source in $Rule.Sources) {
            $Events = Find-EventInRange -LogName $Source.LogName -EventId $Source.EventId -TargetTime $TargetTime -WindowSeconds $TimeWindowSeconds

            $MatchedEvent = $null
            if ($Events.Length -gt 0) {
                $MatchedEvent = $Events[0]
            }

            $DetailLevel = Evaluate-DetailLevel -Event $MatchedEvent -Keywords $Rule.Keywords
            $Status = if ($DetailLevel -ne "Missed") { "CAPTURED" } else { "MISSING" }

            $KeyFields = Get-KeyFields -Event $MatchedEvent

            $ShortSource = switch -Wildcard ($Source.LogName) {
                "Security" { "Security" }
                "*Sysmon*" { "Sysmon" }
                "*PowerShell*" { "PS ScriptBlock" }
                default { $Source.LogName }
            }

            $EventIdDisplay = if ($MatchedEvent) { [string]$MatchedEvent.Id } else { "-" }

            $Result = [PSCustomObject]@{
                Action       = $ActionDesc
                Source       = $Source.LogName
                SourceShort  = $ShortSource
                EventId      = $EventIdDisplay
                Detail       = $DetailLevel
                Status       = $Status
                KeyFields    = $KeyFields
                Timestamp    = $ActionTimestamp
                MitreTech    = $MitreTech
            }

            $ActionResults += $Result

            if ($DetailLevel -ne "Missed") {
                $SourcesCaptured++
            }

            $ActionDisplay = if ($FirstRow) {
                if ($ActionDesc.Length -gt 36) {
                    $ActionDesc.Substring(0, 36)
                } else {
                    $ActionDesc
                }
            } else { "" }
            Write-Host ($headerFormat -f $ActionDisplay, $ShortSource, $EventIdDisplay, $DetailLevel, "[$Status]")
            $FirstRow = $false
        }

        if ($SourcesCaptured -gt 0) {
            $CapturedCount++
        }
        if ($SourcesCaptured -gt 1) {
            $MultiSourceCount++
        }

        $DetectionMatrix += $ActionResults
    }

    Write-Host ""
    $CapturePct = if ($TotalActions -gt 0) { [math]::Round($CapturedCount / $TotalActions * 100, 0) } else { 0 }
    Write-Host "Actions: $TotalActions | Captured: $CapturedCount/$TotalActions ($CapturePct%) | Multi-source: $MultiSourceCount" -ForegroundColor Green

    $Summary = [PSCustomObject]@{
        GroundTruthFile       = $GroundTruthFile
        AnalysisTimestamp     = Get-UTCTimestamp
        TotalActions          = $TotalActions
        ActionsCaptured       = $CapturedCount
        CaptureRatePercent    = if ($TotalActions -gt 0) { [math]::Round($CapturedCount / $TotalActions * 100, 1) } else { 0 }
        MultiSourceDetections = $MultiSourceCount
        TimeWindowSeconds     = $TimeWindowSeconds
    }

    $Report = [PSCustomObject]@{
        Summary         = $Summary
        DetectionMatrix = $DetectionMatrix
        GroundTruth     = $GroundTruth
    }

    $Report | ConvertTo-Json -Depth 10 | Out-File $OutputFile -Encoding UTF8 -Force

    Write-Host "Report saved to: $OutputFile"
    Write-Host ""

    Write-Host "Detection Summary by Action:" -ForegroundColor Cyan
    Write-Host "----------------------------" -ForegroundColor Cyan

    $SummaryEnumerator = $GroundTruth.GetEnumerator()
    while ($SummaryEnumerator.MoveNext()) {
        $Action = $SummaryEnumerator.Current
        if ($null -eq $Action) { continue }

        $ActionDesc = ""
        if ($null -ne $Action.description) { $ActionDesc = $Action.description }

        $ActionNum = 1
        if ($null -ne $Action.action_number) { $ActionNum = $Action.action_number }

        $ShortDesc = if ($ActionDesc.Length -gt 55) {
            $ActionDesc.Substring(0, 55)
        } else {
            $ActionDesc
        }
        $CaptureStatus = "[MISSING]"

        $FilteredMatrix = @($DetectionMatrix | Where-Object { $_.Action -eq $ActionDesc })
        $HasCapture = $false
        foreach ($r in $FilteredMatrix) {
            if ($r.Status -eq "CAPTURED") {
                $HasCapture = $true
                break
            }
        }
        if ($HasCapture) {
            $CaptureStatus = "[CAPTURED]"
        }

        Write-Host "  $ActionNum. $ShortDesc $CaptureStatus" -ForegroundColor White

        $CapturedResults = @($FilteredMatrix | Where-Object { $_.Status -eq "CAPTURED" })
        foreach ($cr in $CapturedResults) {
            $EventId = if ($null -ne $cr.EventId) { $cr.EventId } else { "-" }
            $Detail = if ($null -ne $cr.Detail) { $cr.Detail } else { "-" }
            $SourceShort = if ($null -ne $cr.SourceShort) { $cr.SourceShort } else { "Unknown" }
            Write-Host "      Source: $SourceShort | Event ID: $EventId | Detail: $Detail" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "Telemetry Source Statistics:" -ForegroundColor Cyan
    Write-Host "----------------------------" -ForegroundColor Cyan

    $UniqueSources = @($DetectionMatrix | Select-Object -ExpandProperty SourceShort -Unique)
    foreach ($Source in $UniqueSources) {
        $SourceEvents = @($DetectionMatrix | Where-Object { $_.SourceShort -eq $Source })
        $CapturedForSource = 0
        $TotalForSource = 0

        foreach ($se in $SourceEvents) {
            $TotalForSource++
            if ($se.Status -eq "CAPTURED") {
                $CapturedForSource++
            }
        }

        Write-Host "  $Source : $CapturedForSource/$TotalForSource captured" -ForegroundColor White
    }

} catch {
    Write-Host "[CRITICAL ERROR] Script failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    exit 1
}
