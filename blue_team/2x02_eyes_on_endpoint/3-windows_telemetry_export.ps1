<#
.Notes
    name:        3-windows_telemetry_export.ps1
    purpose:     Export Windows telemetry into analyst-ready JSON with normalized fields
    author:      Steve - Cybersecurity Engineer
    date:        August 8, 2026

.Purpose
    This script exports telemetry from three Windows event logs into a single
    normalized JSON file suitable for SOC consumption:

        - Windows Security log (Event IDs 4624, 4625, 4672, 4688, and others)
        - Sysmon Operational log (EID 1, 3, 11, 13, 22)
        - PowerShell Operational log (EID 4104, 4103, and others)

    Each event is normalized with common fields:
        timestamp, hostname, platform, source_type, channel, event_id,
        event_category, provider, raw_message

    Key event types receive enriched fields extracted from event properties.

    Usage:
        .\3-windows_telemetry_export.ps1
        .\3-windows_telemetry_export.ps1 -Hours 48
        .\3-windows_telemetry_export.ps1 -StartTime "2026-08-07 00:00:00" -EndTime "2026-08-08 23:59:59"

    Output: windows_events_export.json
#>

param(
    [int]$Hours = 24,
    [DateTime]$StartTime,
    [DateTime]$EndTime
)

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

# ── Constants ────────────────────────────────────────────────────────────────

$script:OutputFile = 'windows_events_export.json'

$script:Channels = @{
    Security   = @{
        LogName    = 'Security'
        SourceType = 'windows_security'
        Provider   = 'Microsoft-Windows-Security-Auditing'
    }
    Sysmon     = @{
        LogName    = 'Microsoft-Windows-Sysmon/Operational'
        SourceType = 'sysmon'
        Provider   = 'Microsoft-Windows-Sysmon'
    }
    PowerShell = @{
        LogName    = 'Microsoft-Windows-PowerShell/Operational'
        SourceType = 'powershell'
        Provider   = 'Microsoft-Windows-PowerShell'
    }
}

# Event categories by event ID
$script:EventCategories = @{
    4624  = 'Logon'
    4625  = 'Logon Failure'
    4672  = 'Privileged Logon'
    4688  = 'Process Creation'
    4634  = 'Logoff'
    4670  = 'Permissions Change'
    4720  = 'Account Created'
    4722  = 'Account Enabled'
    4724  = 'Password Reset'
    4738  = 'Account Modified'
    4740  = 'Account Locked'
    4768  = 'Kerberos TGT Request'
    4769  = 'Kerberos Service Ticket'
    4771  = 'Kerberos Preauth Failed'
    4776  = 'NTLM Authentication'
    1     = 'Process Creation'
    2     = 'File Creation Time'
    3     = 'Network Connection'
    5     = 'Process Termination'
    6     = 'Driver Load'
    7     = 'Image Load'
    8     = 'CreateRemoteThread'
    9     = 'RawAccessRead'
    10    = 'Process Access'
    11    = 'File Creation'
    12    = 'Registry Object Add/Delete'
    13    = 'Registry Value Set'
    14    = 'Registry Object Rename'
    15    = 'File Stream Creation'
    17    = 'Pipe Created'
    18    = 'Pipe Connected'
    22    = 'DNS Query'
    23    = 'File Delete'
    25    = 'Process Tampering'
    26    = 'File Delete Detected'
    4103  = 'Module Logging'
    4104  = 'Script Block Logging'
    4105  = 'Script Block Start'
    4106  = 'Script Block End'
}

# ── Functions ─────────────────────────────────────────────────────────────────

function Get-HostName {
    return $env:COMPUTERNAME
}

function Convert-ToIsoTimestamp {
    param($EventTime)

    if ($null -eq $EventTime) {
        return (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
    return $EventTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Get-EventCategory {
    param([int]$EventId)

    if ($script:EventCategories.ContainsKey($EventId)) {
        return $script:EventCategories[$EventId]
    }
    return 'Other'
}

function Get-EventProperty {
    param(
        $Event,
        [int]$Index
    )

    $props = @($Event.Properties)
    if ($Index -lt $props.Count -and $null -ne $props[$Index].Value) {
        return [string]$props[$Index].Value
    }
    return $null
}

function Get-EventPropertyByName {
    param(
        $Event,
        [string]$Name
    )

    try {
        $xml = [xml]$Event.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
        $node = $xml.SelectSingleNode("//e:Data[@Name='$Name']", $ns)
        if ($null -ne $node) {
            return $node.InnerText
        }
    }
    catch {
        # Fall through
    }
    return $null
}

function Build-CommonFields {
    param(
        $Event,
        [string]$SourceType,
        [string]$Channel
    )

    $timestamp = Convert-ToIsoTimestamp -EventTime $Event.TimeCreated
    $hostname  = Get-HostName
    $eventId   = [int]$Event.Id
    $category  = Get-EventCategory -EventId $eventId
    $provider  = $Event.ProviderName

    # Truncate raw message to avoid excessively large JSON
    $rawMessage = $Event.Message
    if ($null -ne $rawMessage -and $rawMessage.Length -gt 2000) {
        $rawMessage = $rawMessage.Substring(0, 2000) + '...[truncated]'
    }

    $record = [ordered]@{
        timestamp      = $timestamp
        hostname       = $hostname
        platform       = 'windows'
        source_type    = $SourceType
        channel        = $Channel
        event_id       = $eventId
        event_category = $category
        provider       = $provider
        raw_message    = $rawMessage
    }

    return $record
}

function Enrich-SecurityEvent {
    param($Event, $BaseRecord)

    $enriched = [ordered]@{}
    $eventId  = [int]$Event.Id

    switch ($eventId) {
        4624 {
            $targetUser  = Get-EventProperty -Event $Event -Index 5
            $domain      = Get-EventProperty -Event $Event -Index 6
            $logonType   = Get-EventProperty -Event $Event -Index 8
            $sourceIp    = Get-EventProperty -Event $Event -Index 18
            $workstation = Get-EventProperty -Event $Event -Index 11

            $enriched.TargetUserName   = if ($null -ne $targetUser) { "$domain\$targetUser" } else { $null }
            $enriched.LogonType        = $logonType
            $enriched.IpAddress        = $sourceIp
            $enriched.WorkstationName  = $workstation
        }
        4625 {
            $targetUser  = Get-EventProperty -Event $Event -Index 5
            $domain      = Get-EventProperty -Event $Event -Index 6
            $failureType = Get-EventProperty -Event $Event -Index 8
            $sourceIp    = Get-EventProperty -Event $Event -Index 19
            $subStatus   = Get-EventProperty -Event $Event -Index 16

            $enriched.TargetUserName   = if ($null -ne $targetUser) { "$domain\$targetUser" } else { $null }
            $enriched.FailureReason    = $failureType
            $enriched.SubStatus        = $subStatus
            $enriched.IpAddress        = $sourceIp
        }
        4672 {
            $targetUser = Get-EventProperty -Event $Event -Index 1
            $domain     = Get-EventProperty -Event $Event -Index 2

            $enriched.PrivilegedAccount = if ($null -ne $targetUser) { "$domain\$targetUser" } else { $null }
        }
        4688 {
            $processName   = Get-EventProperty -Event $Event -Index 5
            $commandLine   = Get-EventProperty -Event $Event -Index 8
            $parentProcess = Get-EventProperty -Event $Event -Index 13

            $enriched.ProcessName       = $processName
            $enriched.CommandLine       = $commandLine
            $enriched.ParentProcessName = $parentProcess
        }
        default {
            # No enrichment for other security events
        }
    }

    return $enriched
}

function Enrich-SysmonEvent {
    param($Event, $BaseRecord)

    $enriched = [ordered]@{}
    $eventId  = [int]$Event.Id

    switch ($eventId) {
        1 {
            $enriched.image        = Get-EventPropertyByName -Event $Event -Name 'Image'
            $enriched.command_line = Get-EventPropertyByName -Event $Event -Name 'CommandLine'
            $enriched.parent_image = Get-EventPropertyByName -Event $Event -Name 'ParentImage'
            $enriched.hashes       = Get-EventPropertyByName -Event $Event -Name 'Hashes'
            $enriched.user         = Get-EventPropertyByName -Event $Event -Name 'User'
            $enriched.process_guid = Get-EventPropertyByName -Event $Event -Name 'ProcessGuid'
        }
        3 {
            $enriched.destination_ip   = Get-EventPropertyByName -Event $Event -Name 'DestinationIp'
            $enriched.destination_port = Get-EventPropertyByName -Event $Event -Name 'DestinationPort'
            $enriched.process          = Get-EventPropertyByName -Event $Event -Name 'Image'
            $enriched.protocol         = Get-EventPropertyByName -Event $Event -Name 'Protocol'
            $enriched.source_ip        = Get-EventPropertyByName -Event $Event -Name 'SourceIp'
            $enriched.source_port      = Get-EventPropertyByName -Event $Event -Name 'SourcePort'
        }
        11 {
            $enriched.target_filename  = Get-EventPropertyByName -Event $Event -Name 'TargetFilename'
            $enriched.creating_process = Get-EventPropertyByName -Event $Event -Name 'Image'
        }
        13 {
            $enriched.registry_key = Get-EventPropertyByName -Event $Event -Name 'TargetObject'
            $enriched.value_name   = Get-EventPropertyByName -Event $Event -Name 'Details'
            $enriched.process      = Get-EventPropertyByName -Event $Event -Name 'Image'
        }
        22 {
            $enriched.query_name    = Get-EventPropertyByName -Event $Event -Name 'QueryName'
            $enriched.query_results = Get-EventPropertyByName -Event $Event -Name 'QueryResults'
            $enriched.process       = Get-EventPropertyByName -Event $Event -Name 'Image'
        }
        default {
            # No enrichment for other Sysmon events
        }
    }

    return $enriched
}

function Enrich-PowerShellEvent {
    param($Event, $BaseRecord)

    $enriched = [ordered]@{}
    $eventId  = [int]$Event.Id

    switch ($eventId) {
        4104 {
            $scriptBlock = $null
            try {
                $props = @($Event.Properties)
                if ($props.Count -ge 3 -and $null -ne $props[2].Value) {
                    $scriptBlock = [string]$props[2].Value
                }
            }
            catch {
                $scriptBlock = Get-EventPropertyByName -Event $Event -Name 'ScriptBlockText'
            }

            if ($null -eq $scriptBlock) {
                $scriptBlock = Get-EventPropertyByName -Event $Event -Name 'ScriptBlockText'
            }

            $enriched.script_block_text = $scriptBlock

            if ($null -ne $scriptBlock -and $scriptBlock.Length -gt 0) {
                $enriched.decoded = $true
            }
        }
        4103 {
            $moduleName  = $null
            $commandName = $null
            try {
                $props = @($Event.Properties)
                if ($props.Count -ge 1 -and $null -ne $props[0].Value) {
                    $moduleName = [string]$props[0].Value
                }
                if ($props.Count -ge 2 -and $null -ne $props[1].Value) {
                    $commandName = [string]$props[1].Value
                }
            }
            catch {
                # Fall through
            }

            $enriched.module_name  = $moduleName
            $enriched.command_name = $commandName
        }
        default {
            # No enrichment for other PowerShell events
        }
    }

    return $enriched
}

function Export-TelemetryFromChannel {
    param(
        [string]$LogName,
        [string]$SourceType,
        [string]$ChannelLabel,
        [DateTime]$StartTime,
        $EndTime
    )

    $allRecords = [System.Collections.ArrayList]::new()

    if ($null -eq $script:CachedEvents[$ChannelLabel]) {
        Write-Host "$ChannelLabel events: 0"
        return @()
    }

    $events = @($script:CachedEvents[$ChannelLabel])

    if ($events.Count -eq 0) {
        Write-Host "$ChannelLabel events: 0"
        return @()
    }

    $count = 0
    foreach ($event in $events) {
        $base = Build-CommonFields -Event $event -SourceType $SourceType -Channel $ChannelLabel

        $enriched = [ordered]@{}
        switch ($SourceType) {
            'windows_security' { $enriched = Enrich-SecurityEvent -Event $event -BaseRecord $base }
            'sysmon'            { $enriched = Enrich-SysmonEvent -Event $event -BaseRecord $base }
            'powershell'        { $enriched = Enrich-PowerShellEvent -Event $event -BaseRecord $base }
        }

        $finalRecord = [ordered]@{}
        foreach ($key in $base.Keys) {
            $finalRecord[$key] = $base[$key]
        }
        if ($enriched.Count -gt 0) {
            $finalRecord['enriched'] = [PSCustomObject]$enriched
        }

        $null = $allRecords.Add([PSCustomObject]$finalRecord)
        $count++
    }

    if ($ChannelLabel -eq 'Security') {
        Write-Host "Security events: $count"
    }
    elseif ($ChannelLabel -eq 'Sysmon') {
        Write-Host "Sysmon events: $count"
    }
    elseif ($ChannelLabel -eq 'PowerShell') {
        Write-Host "PowerShell events: $count"
    }
    else {
        Write-Host "$ChannelLabel events: $count"
    }

    return @($allRecords)
}

function Get-TopEventIds {
    param($Records, [int]$Top = 10)

    $idCounts = @{}
    foreach ($record in $Records) {
        $channel = $record.channel
        $eventId = $record.event_id

        if ($channel -eq 'sysmon') {
            $key = "Sysmon-$eventId"
        }
        elseif ($channel -eq 'powershell') {
            $key = "PS-$eventId"
        }
        else {
            $key = "$eventId"
        }

        if ($idCounts.ContainsKey($key)) {
            $idCounts[$key]++
        }
        else {
            $idCounts[$key] = 1
        }
    }

    $sorted = $idCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $Top
    $topIds = @()
    foreach ($entry in $sorted) {
        $topIds += $entry.Name
    }

    return ($topIds -join ', ')
}

function Export-JsonReport {
    param(
        $Records,
        [string]$OutputPath,
        [hashtable]$Counts
    )

    $report = [ordered]@{
        export_time    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        hostname       = (Get-HostName)
        time_window    = "$($Counts.hours) hours"
        total_events   = $Records.Count
        channel_counts = [ordered]@{
            security   = $Counts.security
            sysmon     = $Counts.sysmon
            powershell = $Counts.powershell
        }
        events         = $Records
    }

    $json = $report | ConvertTo-Json -Depth 6
    $json | Set-Content -Path $OutputPath -Encoding UTF8
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

# Calculate time window based on parameters
if ($null -eq $StartTime) {
    $StartTime = (Get-Date).AddHours(-$Hours)
}

$endLabel = if ($null -ne $EndTime) { $EndTime } else { 'now' }
Write-Host "[*] Exporting Windows telemetry from $StartTime to $endLabel..."

# Query ALL three logs UPFRONT before any processing to avoid
# circular log evicting events during processing
$script:CachedEvents = @{}

# PowerShell FIRST - it's the most vulnerable to circular log eviction
Write-Host "  Querying PowerShell log..."
$psFilter = @{
    LogName   = $script:Channels.PowerShell.LogName
    StartTime = $StartTime
}
if ($null -ne $EndTime) { $psFilter.EndTime = $EndTime }
try {
    $script:CachedEvents['PowerShell'] = @(Get-WinEvent -FilterHashtable $psFilter -MaxEvents 50000 -ErrorAction Stop)
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        $script:CachedEvents['PowerShell'] = @()
    } else {
        Write-Host "[!] Error reading PowerShell log: $($_.Exception.Message)"
        $script:CachedEvents['PowerShell'] = @()
    }
}

# Security log
Write-Host "  Querying Security log..."
$secFilter = @{
    LogName   = $script:Channels.Security.LogName
    StartTime = $StartTime
}
if ($null -ne $EndTime) { $secFilter.EndTime = $EndTime }
try {
    $script:CachedEvents['Security'] = @(Get-WinEvent -FilterHashtable $secFilter -MaxEvents 50000 -ErrorAction Stop)
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        $script:CachedEvents['Security'] = @()
    } else {
        Write-Host "[!] Error reading Security log: $($_.Exception.Message)"
        $script:CachedEvents['Security'] = @()
    }
}

# Sysmon log
Write-Host "  Querying Sysmon log..."
$sysFilter = @{
    LogName   = $script:Channels.Sysmon.LogName
    StartTime = $StartTime
}
if ($null -ne $EndTime) { $sysFilter.EndTime = $EndTime }
try {
    $script:CachedEvents['Sysmon'] = @(Get-WinEvent -FilterHashtable $sysFilter -MaxEvents 50000 -ErrorAction Stop)
} catch {
    if ($_.Exception.Message -match 'No events were found') {
        $script:CachedEvents['Sysmon'] = @()
    } else {
        Write-Host "[!] Error reading Sysmon log: $($_.Exception.Message)"
        $script:CachedEvents['Sysmon'] = @()
    }
}

Write-Host ""

$allRecords = [System.Collections.ArrayList]::new()
$counts = @{ hours = $Hours; security = 0; sysmon = 0; powershell = 0 }

# Export Security log
$securityRecords = @(Export-TelemetryFromChannel `
    -LogName $script:Channels.Security.LogName `
    -SourceType $script:Channels.Security.SourceType `
    -ChannelLabel 'Security' `
    -StartTime $StartTime `
    -EndTime $EndTime)
$counts.security = $securityRecords.Count
if ($securityRecords.Count -gt 0) {
    $null = $allRecords.AddRange($securityRecords)
}

# Export Sysmon log
$sysmonRecords = @(Export-TelemetryFromChannel `
    -LogName $script:Channels.Sysmon.LogName `
    -SourceType $script:Channels.Sysmon.SourceType `
    -ChannelLabel 'Sysmon' `
    -StartTime $StartTime `
    -EndTime $EndTime)
$counts.sysmon = $sysmonRecords.Count
if ($sysmonRecords.Count -gt 0) {
    $null = $allRecords.AddRange($sysmonRecords)
}

# Export PowerShell log
$psRecords = @(Export-TelemetryFromChannel `
    -LogName $script:Channels.PowerShell.LogName `
    -SourceType $script:Channels.PowerShell.SourceType `
    -ChannelLabel 'PowerShell' `
    -StartTime $StartTime `
    -EndTime $EndTime)
$counts.powershell = $psRecords.Count
if ($psRecords.Count -gt 0) {
    $null = $allRecords.AddRange($psRecords)
}

$totalEvents = $allRecords.Count
Write-Host "Total events: $totalEvents"

$topIds = Get-TopEventIds -Records $allRecords -Top 10
Write-Host "Top Event IDs: $topIds"

Export-JsonReport -Records $allRecords -OutputPath $script:OutputFile -Counts $counts

Write-Host "Output: $script:OutputFile"
