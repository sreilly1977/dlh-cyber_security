<#
.Notes
    name:        4-windows_telemetry_quality.ps1
    purpose:     Assess Windows telemetry export quality and produce a quality report
    author:      Steve - Cybersecurity Engineer
    date:        August 8, 2026

.Purpose
    This script reads windows_events_export.json and evaluates the quality
    of the exported telemetry across six dimensions:

        - Event distribution (count and percentage per Event ID)
        - Channel distribution (Security, Sysmon, PowerShell)
        - Time coverage (events per hour, gaps)
        - Gap detection (periods > 30 minutes with no events)
        - Field completeness (required fields per event type)
        - Quality score (weighted 0-100 with assessment)

    Output: windows_telemetry_quality.json
#>

param(
    [string]$InputFile = 'windows_events_export.json',
    [string]$OutputFile = 'windows_telemetry_quality.json'
)

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

# ── Constants ────────────────────────────────────────────────────────────────

$script:InputFile  = $InputFile
$script:OutputFile = $OutputFile

# Weights for quality score (must sum to 100)
$script:Weights = @{
    Coverage      = 25
    Completeness  = 30
    Continuity    = 25
    Distribution  = 20
}

# ── Functions ─────────────────────────────────────────────────────────────────

function Get-SafeProperty {
    param($Object, [string]$Name)

    if ($null -eq $Object) { return $null }

    # Handle dictionaries (OrderedDictionary, Hashtable)
    if ($Object -is [System.Collections.IDictionary]) {
        # Case-insensitive key lookup
        foreach ($key in $Object.Keys) {
            if ([string]$key -eq $Name) {
                return $Object[$key]
            }
        }
        return $null
    }

    # Handle PSCustomObject
    try {
        $prop = $Object.PSObject.Properties[$Name]
        if ($null -ne $prop) {
            return $prop.Value
        }
    }
    catch {
        # Fall through
    }
    return $null
}

function Get-EventDistribution {
    param($Records)

    $dist = @{}
    foreach ($record in $Records) {
        $channel = $record.channel
        $eventId = [int]$record.event_id

        if ($channel -eq 'sysmon') {
            $key = "Sysmon-$eventId"
        }
        elseif ($channel -eq 'powershell') {
            $key = "PS-$eventId"
        }
        else {
            $key = "$eventId"
        }

        if ($dist.ContainsKey($key)) {
            $dist[$key]++
        }
        else {
            $dist[$key] = 1
        }
    }

    $total = $Records.Count
    if ($total -eq 0) { $total = 1 }

    $sorted = $dist.GetEnumerator() | Sort-Object Value -Descending
    $entries = @()
    foreach ($entry in $sorted) {
        $entries += [PSCustomObject]@{
            event_id = $entry.Name
            count    = $entry.Value
            percent  = [math]::Round(($entry.Value / $total) * 100, 1)
        }
    }

    return $entries
}

function Get-ChannelDistribution {
    param($Records)

    $channels = @{
        Security   = 0
        Sysmon     = 0
        PowerShell = 0
    }

    foreach ($record in $Records) {
        $channel = $record.channel
        if ($channels.ContainsKey($channel)) {
            $channels[$channel]++
        }
    }

    $total = $Records.Count
    if ($total -eq 0) { $total = 1 }

    return [ordered]@{
        Security   = [PSCustomObject]@{ count = $channels.Security;   percent = [math]::Round(($channels.Security / $total) * 100, 1) }
        Sysmon     = [PSCustomObject]@{ count = $channels.Sysmon;     percent = [math]::Round(($channels.Sysmon / $total) * 100, 1) }
        PowerShell = [PSCustomObject]@{ count = $channels.PowerShell; percent = [math]::Round(($channels.PowerShell / $total) * 100, 1) }
    }
}

function Get-TimeCoverage {
    param($Records, [DateTime]$StartTime, [DateTime]$EndTime)

    $totalHours = [math]::Ceiling(($EndTime - $StartTime).TotalHours)
    if ($totalHours -lt 1) { $totalHours = 1 }

    # Initialize hourly buckets
    $hourly = @{}
    for ($i = 0; $i -lt $totalHours; $i++) {
        $bucketTime = $StartTime.AddHours($i).ToString('yyyy-MM-ddTHH:00')
        $hourly[$bucketTime] = 0
    }

    foreach ($record in $Records) {
        try {
            $eventTime = [DateTime]$record.timestamp
            $bucket = $eventTime.ToString('yyyy-MM-ddTHH:00')
            if ($hourly.ContainsKey($bucket)) {
                $hourly[$bucket]++
            }
            else {
                $hourly[$bucket] = 1
            }
        }
        catch {
            # Skip records with invalid timestamps
        }
    }

    $hoursWithEvents = 0
    $hoursWithoutEvents = 0
    $perHour = @()

    foreach ($key in ($hourly.Keys | Sort-Object)) {
        $count = $hourly[$key]
        if ($count -gt 0) {
            $hoursWithEvents++
        }
        else {
            $hoursWithoutEvents++
        }
        $perHour += [PSCustomObject]@{ hour = $key; count = $count }
    }

    return [ordered]@{
        hours_total          = $totalHours
        hours_with_events    = $hoursWithEvents
        hours_without_events = $hoursWithoutEvents
        events_per_hour      = $perHour
    }
}

function Get-GapDetection {
    param($Records, [DateTime]$StartTime, [DateTime]$EndTime)

    # Sort all event timestamps
    $timestamps = @()
    foreach ($record in $Records) {
        try {
            $timestamps += [DateTime]$record.timestamp
        }
        catch {
            # Skip invalid
        }
    }

    $timestamps = $timestamps | Sort-Object
    $gaps = @()
    $largestGapMinutes = 0

    # Gap from StartTime to first event
    if ($timestamps.Count -gt 0) {
        $firstGap = ($timestamps[0] - $StartTime).TotalMinutes
        if ($firstGap -gt 30) {
            $gaps += [PSCustomObject]@{
                start   = $StartTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                end     = $timestamps[0].ToString('yyyy-MM-ddTHH:mm:ssZ')
                minutes = [math]::Round($firstGap, 0)
            }
            if ($firstGap -gt $largestGapMinutes) {
                $largestGapMinutes = $firstGap
            }
        }

        # Gaps between events
        for ($i = 1; $i -lt $timestamps.Count; $i++) {
            $gap = ($timestamps[$i] - $timestamps[$i - 1]).TotalMinutes
            if ($gap -gt 30) {
                $gapStart = $timestamps[$i - 1]
                $gapEnd = $timestamps[$i]
                $gaps += [PSCustomObject]@{
                    start   = $gapStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    end     = $gapEnd.ToString('yyyy-MM-ddTHH:mm:ssZ')
                    minutes = [math]::Round($gap, 0)
                }
                if ($gap -gt $largestGapMinutes) {
                    $largestGapMinutes = $gap
                }
            }
        }

        # Gap from last event to EndTime
        $lastGap = ($EndTime - $timestamps[-1]).TotalMinutes
        if ($lastGap -gt 30) {
            $gaps += [PSCustomObject]@{
                start   = $timestamps[-1].ToString('yyyy-MM-ddTHH:mm:ssZ')
                end     = $EndTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                minutes = [math]::Round($lastGap, 0)
            }
            if ($lastGap -gt $largestGapMinutes) {
                $largestGapMinutes = $lastGap
            }
        }
    }
    else {
        # No events at all
        $totalGap = ($EndTime - $StartTime).TotalMinutes
        if ($totalGap -gt 30) {
            $gaps += [PSCustomObject]@{
                start   = $StartTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                end     = $EndTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                minutes = [math]::Round($totalGap, 0)
            }
            $largestGapMinutes = $totalGap
        }
    }

    return [ordered]@{
        gaps_detected       = $gaps.Count
        largest_gap_minutes = [math]::Round($largestGapMinutes, 0)
        gaps               = $gaps
    }
}

function Get-FieldCompleteness {
    param($Records)

    $completeness = [ordered]@{}

    $processEvents = @()
    $logonEvents = @()
    $powerShellEvents = @()
    $allRecords = @()

    foreach ($record in $Records) {
        $eventId = [int]$record.event_id
        $channel = $record.channel

        $allRecords += $record

        if ($eventId -eq 4688 -or ($channel -eq 'sysmon' -and $eventId -eq 1)) {
            $processEvents += $record
        }

        if ($eventId -eq 4624 -or $eventId -eq 4625) {
            $logonEvents += $record
        }

        if ($eventId -eq 4104 -and $channel -eq 'powershell') {
            $powerShellEvents += $record
        }
    }

    # Command-line completeness for process events
    $cmdTotal = $processEvents.Count
    $cmdPopulated = 0
    foreach ($rec in $processEvents) {
        $cmd = $null
        $enriched = Get-SafeProperty -Object $rec -Name 'enriched'
        if ($null -ne $enriched) {
            $cmd = Get-SafeProperty -Object $enriched -Name 'CommandLine'
            if ($null -eq $cmd -or [string]$cmd -eq '') {
                $cmd = Get-SafeProperty -Object $enriched -Name 'command_line'
            }
        }
        if ($null -ne $cmd -and [string]$cmd -ne '') {
            $cmdPopulated++
        }
    }
    $cmdPercent = if ($cmdTotal -gt 0) { [math]::Round(($cmdPopulated / $cmdTotal) * 100, 1) } else { 0 }
    $completeness.command_line = [PSCustomObject]@{
        total     = $cmdTotal
        populated = $cmdPopulated
        percent   = $cmdPercent
    }

    # Source IP completeness for logon events
    $ipTotal = $logonEvents.Count
    $ipPopulated = 0
    foreach ($rec in $logonEvents) {
        $ip = $null
        $enriched = Get-SafeProperty -Object $rec -Name 'enriched'
        if ($null -ne $enriched) {
            $ip = Get-SafeProperty -Object $enriched -Name 'IpAddress'
            if ($null -eq $ip -or [string]$ip -eq '') {
                $ip = Get-SafeProperty -Object $enriched -Name 'source_ip'
            }
        }
        if ($null -ne $ip -and [string]$ip -ne '' -and [string]$ip -ne '-') {
            $ipPopulated++
        }
    }
    $ipPercent = if ($ipTotal -gt 0) { [math]::Round(($ipPopulated / $ipTotal) * 100, 1) } else { 0 }
    $completeness.source_ip = [PSCustomObject]@{
        total     = $ipTotal
        populated = $ipPopulated
        percent   = $ipPercent
    }

    # Script block completeness for PowerShell events
    $sbTotal = $powerShellEvents.Count
    $sbPopulated = 0
    foreach ($rec in $powerShellEvents) {
        $sb = $null
        $enriched = Get-SafeProperty -Object $rec -Name 'enriched'
        if ($null -ne $enriched) {
            $sb = Get-SafeProperty -Object $enriched -Name 'script_block_text'
            if ($null -eq $sb -or [string]$sb -eq '') {
                $sb = Get-SafeProperty -Object $enriched -Name 'ScriptBlockText'
            }
        }
        if ($null -ne $sb -and [string]$sb -ne '') {
            $sbPopulated++
        }
    }
    $sbPercent = if ($sbTotal -gt 0) { [math]::Round(($sbPopulated / $sbTotal) * 100, 1) } else { 0 }
    $completeness.script_block = [PSCustomObject]@{
        total     = $sbTotal
        populated = $sbPopulated
        percent   = $sbPercent
    }

    # Overall required fields check (common fields)
    $reqFields = @('timestamp', 'hostname', 'platform', 'source_type', 'channel', 'event_id', 'provider')
    $reqTotal = 0
    $reqPopulated = 0
    foreach ($rec in $allRecords) {
        foreach ($field in $reqFields) {
            $reqTotal++
            $val = Get-SafeProperty -Object $rec -Name $field
            if ($null -ne $val -and [string]$val -ne '') {
                $reqPopulated++
            }
        }
    }
    $reqPercent = if ($reqTotal -gt 0) { [math]::Round(($reqPopulated / $reqTotal) * 100, 1) } else { 0 }
    $completeness.required_fields = [PSCustomObject]@{
        total     = $reqTotal
        populated = $reqPopulated
        percent   = $reqPercent
    }

    return $completeness
}

function Get-QualityScore {
    param(
        $TimeCoverage,
        $Gaps,
        $Completeness,
        $ChannelDist,
        $TotalEvents
    )

    # Coverage score: hours with events / total hours
    $coverageRatio = 0
    if ($TimeCoverage.hours_total -gt 0) {
        $coverageRatio = $TimeCoverage.hours_with_events / $TimeCoverage.hours_total
    }
    $coverageScore = $coverageRatio * $script:Weights.Coverage

    # Completeness score: average of command_line, source_ip, script_block, required_fields
    $completenessScores = @()
    $cmdObj = Get-SafeProperty -Object $Completeness -Name 'command_line'
    if ($null -ne $cmdObj -and $cmdObj.total -gt 0) {
        $completenessScores += $cmdObj.percent
    }
    $ipObj = Get-SafeProperty -Object $Completeness -Name 'source_ip'
    if ($null -ne $ipObj -and $ipObj.total -gt 0) {
        $completenessScores += $ipObj.percent
    }
    $sbObj = Get-SafeProperty -Object $Completeness -Name 'script_block'
    if ($null -ne $sbObj -and $sbObj.total -gt 0) {
        $completenessScores += $sbObj.percent
    }
    $reqObj = Get-SafeProperty -Object $Completeness -Name 'required_fields'
    if ($null -ne $reqObj -and $reqObj.total -gt 0) {
        $completenessScores += $reqObj.percent
    }

    $avgCompleteness = 0
    if ($completenessScores.Count -gt 0) {
        $avgCompleteness = ($completenessScores | Measure-Object -Average).Average
    }
    $completenessScore = ($avgCompleteness / 100) * $script:Weights.Completeness

    # Continuity score: penalize for gaps
    $gapCount = $Gaps.gaps_detected
    $continuityRatio = [math]::Max(0, 1 - ($gapCount * 0.1))
    $continuityScore = $continuityRatio * $script:Weights.Continuity

    # Distribution score: check for single-event-type dominance
    $distScore = $script:Weights.Distribution
    $totalForDist = $TotalEvents
    if ($totalForDist -eq 0) { $totalForDist = 1 }

    # Penalize if any single channel is > 80% of total
    if ($null -ne $ChannelDist) {
        foreach ($channel in @('Security', 'Sysmon', 'PowerShell')) {
            $ch = Get-SafeProperty -Object $ChannelDist -Name $channel
            if ($null -ne $ch -and $ch.count -gt 0) {
                $ratio = $ch.count / $totalForDist
                if ($ratio -gt 0.80) {
                    $distScore *= 0.7
                }
            }
        }
    }

    $rawScore = $coverageScore + $completenessScore + $continuityScore + $distScore
    $score = [math]::Round($rawScore, 1)

    if ($score -ge 80) {
        $assessment = 'good'
    }
    elseif ($score -ge 60) {
        $assessment = 'acceptable'
    }
    else {
        $assessment = 'poor'
    }

    return [ordered]@{
        score      = $score
        assessment = $assessment
        components = [ordered]@{
            coverage     = [math]::Round($coverageScore, 1)
            completeness = [math]::Round($completenessScore, 1)
            continuity   = [math]::Round($continuityScore, 1)
            distribution = [math]::Round($distScore, 1)
        }
    }
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

Write-Host "[*] Analyzing $script:InputFile..."

# Read the export file
if (-not (Test-Path $script:InputFile)) {
    Write-Host "[!] Error: $script:InputFile not found. Run 3-windows_telemetry_export.ps1 first."
    exit 1
}

$rawJson = Get-Content -Path $script:InputFile -Raw -Encoding UTF8
$export = $null
try {
    $export = $rawJson | ConvertFrom-Json
}
catch {
    Write-Host "[!] Error: Failed to parse $script:InputFile as JSON: $($_.Exception.Message)"
    exit 1
}

$records = @($export.events)

# Determine time window from export metadata
$exportTime = [DateTime]::UtcNow
$exportTimeStr = Get-SafeProperty -Object $export -Name 'export_time'
if ($null -ne $exportTimeStr) {
    try { $exportTime = [DateTime]$exportTimeStr } catch { }
}

$hours = 24
$timeWindowStr = Get-SafeProperty -Object $export -Name 'time_window'
if ($null -ne $timeWindowStr) {
    $twStr = [string]$timeWindowStr
    if ($twStr -match '(\d+)') {
        $hours = [int]$Matches[1]
    }
}

$startTime = $exportTime.AddHours(-$hours)
$endTime = $exportTime

$totalEvents = $records.Count
Write-Host "Total events: $totalEvents"

# Build quality report components
$eventDist = Get-EventDistribution -Records $records
$channelDist = Get-ChannelDistribution -Records $records
$timeCoverage = Get-TimeCoverage -Records $records -StartTime $startTime -EndTime $endTime
$gapDetection = Get-GapDetection -Records $records -StartTime $startTime -EndTime $endTime
$completeness = Get-FieldCompleteness -Records $records
$qualityScore = Get-QualityScore -TimeCoverage $timeCoverage -Gaps $gapDetection -Completeness $completeness -ChannelDist $channelDist -TotalEvents $totalEvents

# Console output
Write-Host "Hours with events: $($timeCoverage.hours_with_events)/$($timeCoverage.hours_total)"
Write-Host "Largest gap: $($gapDetection.largest_gap_minutes) minutes"

$cmdComp = 0
$cmdObj = Get-SafeProperty -Object $completeness -Name 'command_line'
if ($null -ne $cmdObj -and $cmdObj.total -gt 0) {
    $cmdComp = $cmdObj.percent
}
elseif ($null -ne $cmdObj) {
    $cmdComp = 100
}
Write-Host "Command-line completeness: $cmdComp%"

$ipComp = 0
$ipObj = Get-SafeProperty -Object $completeness -Name 'source_ip'
if ($null -ne $ipObj -and $ipObj.total -gt 0) {
    $ipComp = $ipObj.percent
}
elseif ($null -ne $ipObj) {
    $ipComp = 100
}
Write-Host "Source IP completeness: $ipComp%"

$sbComp = 0
$sbObj = Get-SafeProperty -Object $completeness -Name 'script_block'
if ($null -ne $sbObj -and $sbObj.total -gt 0) {
    $sbComp = $sbObj.percent
}
elseif ($null -ne $sbObj) {
    $sbComp = 100
}
Write-Host "Script block completeness: $sbComp%"

Write-Host "Quality score: $($qualityScore.score)% ($($qualityScore.assessment))"

# Build final report
$report = [ordered]@{
    report_time          = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    source_file          = $script:InputFile
    total_events         = $totalEvents
    time_window          = "$hours hours"
    event_distribution   = $eventDist
    channel_distribution = $channelDist
    time_coverage        = $timeCoverage
    gap_detection        = $gapDetection
    field_completeness   = $completeness
    quality_score        = $qualityScore
}

$json = $report | ConvertTo-Json -Depth 8
$json | Set-Content -Path $script:OutputFile -Encoding UTF8

Write-Host "Report saved to: $script:OutputFile"
