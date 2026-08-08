<#
.Notes
    name:        1-sysmon_coverage_matrix.ps1
    purpose:     Parse Sysmon config and generate an ATT&CK-aligned coverage matrix
    author:      Steve - Cybersecurity Engineer
    date:        August 8, 2026

.Purpose
    This script reads sysmonconfig.xml and produces sysmon_coverage_matrix.json,
    evaluating coverage of seven minimum ATT&CK techniques across three dimensions:

        1. Whether the required Sysmon Event IDs are enabled
        2. Whether include/exclude rules could suppress relevant events
        3. Whether the resulting event has enough fields to support triage

    Each technique is rated as covered, partial, or blind, with a reason
    and a recommended tuning action for any gap found.

    T1059   - Command and Scripting Interpreter  EID 1
    T1053   - Scheduled Task/Job                  EID 1
    T1547   - Boot or Logon Autostart Execution   EID 13
    T1055   - Process Injection                   EID 8, 10
    T1071   - Application Layer Protocol          EID 3, 22
    T1574.002 - DLL Side-Loading                  EID 7
    T1027   - Obfuscated or Compressed Files      EID 11, 15
#>

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

# ── Constants ────────────────────────────────────────────────────────────────

$script:ConfigSearchPaths = @(
    '.\sysmonconfig.xml'
    "$PSScriptRoot\sysmonconfig.xml"
    'C:\Windows\sysmonconfig.xml'
    'C:\Windows\Sysmon\sysmonconfig.xml'
    'C:\ProgramData\Sysmon\sysmonconfig.xml'
    'C:\MedDefense_Lab\sysmonconfig.xml'
    'C:\MedDefense_Lab\Scripts\Endpoint\sysmonconfig.xml'
)

# Sysmon event type name to Event ID mapping
$script:EventTypeToIds = @{
    'ProcessCreate'        = @(1)
    'FileCreateTime'      = @(2)
    'NetworkConnect'      = @(3)
    'ProcessTerminate'    = @(5)
    'DriverLoad'          = @(6)
    'ImageLoad'           = @(7)
    'CreateRemoteThread'  = @(8)
    'RawAccessRead'       = @(9)
    'ProcessAccess'       = @(10)
    'FileCreate'          = @(11)
    'RegistryEvent'       = @(12, 13, 14)
    'FileCreateStreamHash' = @(15)
    'PipeEvent'           = @(17, 18)
    'WmiEvent'            = @(19, 20, 21)
    'DnsQuery'            = @(22)
    'FileDelete'          = @(23)
    'ClipboardChange'     = @(24)
    'ProcessTampering'     = @(25)
    'FileDeleteDetected'  = @(26)
}

# Reverse lookup: EID to event type name
$script:EidToType = @{}
foreach ($typeName in $script:EventTypeToIds.Keys) {
    foreach ($eid in $script:EventTypeToIds[$typeName]) {
        $script:EidToType[$eid] = $typeName
    }
}

# Evidence fields expected per Sysmon EID
$script:EidEvidenceFields = @{
    1  = @('CommandLine', 'Image', 'ParentImage', 'ParentCommandLine', 'ProcessGuid', 'ProcessId', 'CurrentDirectory', 'User', 'Hashes')
    3  = @('DestinationIp', 'DestinationPort', 'Image', 'SourceIp', 'SourcePort', 'Protocol', 'User')
    7  = @('ImageLoaded', 'Image', 'Signed', 'Signature', 'Hashes')
    8  = @('SourceImage', 'TargetImage', 'NewThreadId', 'StartFunction', 'StartAddress')
    10 = @('SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace')
    11 = @('TargetFilename', 'Image', 'CreationUtcTime')
    12 = @('EventType', 'TargetObject', 'Image')
    13 = @('EventType', 'TargetObject', 'Details', 'Image')
    14 = @('EventType', 'TargetObject', 'Image')
    15 = @('TargetFilename', 'Contents', 'Image', 'Hash')
    22 = @('QueryName', 'QueryResults', 'Image')
}

# ── ATT&CK Technique Definitions ─────────────────────────────────────────────

$script:AttackMappings = @(
    @{
        technique_id   = 'T1059'
        technique_name = 'Command and Scripting Interpreter'
        required_eids  = @(1)
    }
    @{
        technique_id   = 'T1053'
        technique_name = 'Scheduled Task/Job'
        required_eids  = @(1)
    }
    @{
        technique_id   = 'T1547'
        technique_name = 'Boot or Logon Autostart Execution'
        required_eids  = @(13)
    }
    @{
        technique_id   = 'T1055'
        technique_name = 'Process Injection'
        required_eids  = @(8, 10)
    }
    @{
        technique_id   = 'T1071'
        technique_name = 'Application Layer Protocol'
        required_eids  = @(3, 22)
    }
    @{
        technique_id   = 'T1574.002'
        technique_name = 'DLL Side-Loading'
        required_eids  = @(7)
    }
    @{
        technique_id   = 'T1027'
        technique_name = 'Obfuscated or Compressed Files'
        required_eids  = @(11, 15)
    }
)

# ── Functions ─────────────────────────────────────────────────────────────────

function Read-SysmonConfig {
    # Search common locations for sysmonconfig.xml
    foreach ($searchPath in $script:ConfigSearchPaths) {
        if (Test-Path $searchPath) {
            try {
                $xml = [xml](Get-Content -Path $searchPath -Raw)
                Write-Host "[*] Found Sysmon config: $searchPath"
                return $xml
            }
            catch {
                Write-Host "[!] Failed to parse Sysmon config XML at $searchPath : $($_.Exception.Message)"
                exit 1
            }
        }
    }

    # Check registry for configured config file path
    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon\Parameters'
    if (Test-Path $regPath) {
        $regConfig = Get-ItemProperty -Path $regPath -Name 'ConfigFile' -ErrorAction SilentlyContinue
        if ($null -ne $regConfig -and -not [string]::IsNullOrEmpty($regConfig.ConfigFile)) {
            $regPathValue = $regConfig.ConfigFile
            if (Test-Path $regPathValue) {
                try {
                    $xml = [xml](Get-Content -Path $regPathValue -Raw)
                    Write-Host "[*] Found Sysmon config via registry: $regPathValue"
                    return $xml
                }
                catch {
                    Write-Host "[!] Failed to parse Sysmon config XML at $regPathValue : $($_.Exception.Message)"
                    exit 1
                }
            }
        }

        # Sysmon64 uses a different registry path
        $regPath64 = 'HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64\Parameters'
        if (Test-Path $regPath64) {
            $regConfig64 = Get-ItemProperty -Path $regPath64 -Name 'ConfigFile' -ErrorAction SilentlyContinue
            if ($null -ne $regConfig64 -and -not [string]::IsNullOrEmpty($regConfig64.ConfigFile)) {
                $regPathValue = $regConfig64.ConfigFile
                if (Test-Path $regPathValue) {
                    try {
                        $xml = [xml](Get-Content -Path $regPathValue -Raw)
                        Write-Host "[*] Found Sysmon config via registry: $regPathValue"
                        return $xml
                    }
                    catch {
                        Write-Host "[!] Failed to parse Sysmon config XML at $regPathValue : $($_.Exception.Message)"
                        exit 1
                    }
                }
            }
        }

        # Sysmon may store config directly in registry (binary blob)
        $embeddedConfig = Get-ItemProperty -Path $regPath -Name 'Config' -ErrorAction SilentlyContinue
        if ($null -ne $embeddedConfig -and $null -ne $embeddedConfig.Config) {
            Write-Host '[!] Sysmon config is embedded in registry (not a file). Export it with: sysmon -c print > sysmonconfig.xml'
            Write-Host '[!] Then re-run this script with the file available.'
            exit 1
        }
    }

    Write-Host '[!] Sysmon config not found in any of the following locations:'
    foreach ($p in $script:ConfigSearchPaths) {
        Write-Host "    $p"
    }
    Write-Host '[!] You can also run: sysmon -c print > sysmonconfig.xml to export the current config.'
    exit 1
}

function Get-EnabledEventTypes {
    param($ConfigXml)

    if ($null -eq $ConfigXml) {
        return @{}
    }

    $result = @{}

    $filtering = $ConfigXml.SelectSingleNode('//EventFiltering')
    if ($null -eq $filtering) {
        return $result
    }

    foreach ($child in $filtering.ChildNodes) {
        if ($child.NodeType -ne 'Element') { continue }

        $typeName = $child.LocalName
        $onMatch  = $child.GetAttribute('onmatch')

        if ([string]::IsNullOrEmpty($onMatch)) {
            $onMatch = 'include'
        }

        $rules = $child.SelectNodes('.//Rule')
        $ruleCount = @($rules).Count

        $ruleFields = @()
        foreach ($rule in $rules) {
            foreach ($attr in $rule.Attributes) {
                $ruleFields += $attr.Name
            }
        }

        $result[$typeName] = @{
            onmatch   = $onMatch
            ruleCount = $ruleCount
            fields    = ($ruleFields | Sort-Object -Unique)
        }
    }

    return $result
}

function Get-EnabledEventIds {
    param($EnabledTypes)

    if ($null -eq $EnabledTypes) {
        return @()
    }

    $enabledIds = [System.Collections.Generic.List[int]]::new()

    foreach ($typeName in $EnabledTypes.Keys) {
        if ($script:EventTypeToIds.ContainsKey($typeName)) {
            foreach ($eid in $script:EventTypeToIds[$typeName]) {
                if (-not $enabledIds.Contains($eid)) {
                    $enabledIds.Add($eid)
                }
            }
        }
    }

    $arr = @()
    foreach ($id in $enabledIds) {
        $arr += $id
    }
    return ($arr | Sort-Object)
}

function Get-FilterConflicts {
    param(
        $EnabledTypes,
        [int[]]$RequiredEids
    )

    if ($null -eq $EnabledTypes) {
        return @()
    }

    $conflicts = [System.Collections.ArrayList]::new()

    foreach ($eid in $RequiredEids) {
        $typeName = $script:EidToType[$eid]
        if (-not $EnabledTypes.ContainsKey($typeName)) { continue }

        $config = $EnabledTypes[$typeName]
        $onMatch = $config['onmatch']
        $ruleCount = $config['ruleCount']

        if ($onMatch -eq 'include' -and $ruleCount -gt 0) {
            $msg = "EID $eid ($typeName): onmatch=include with $ruleCount rule(s) - events NOT matching rules are suppressed"
            $null = $conflicts.Add($msg)
        }
        elseif ($onMatch -eq 'exclude' -and $ruleCount -gt 0) {
            $msg = "EID $eid ($typeName): onmatch=exclude with $ruleCount rule(s) - matching events are dropped (verify no ATT&CK-relevant activity excluded)"
            $null = $conflicts.Add($msg)
        }
    }

    return @($conflicts)
}

function Get-CoverageStatus {
    param(
        [int[]]$RequiredEids,
        [int[]]$EnabledEids,
        $FilterConflicts
    )

    $conflictCount = 0
    if ($null -ne $FilterConflicts) {
        $conflictCount = @($FilterConflicts).Count
    }

    $enabledCount = 0
    foreach ($eid in $RequiredEids) {
        if ($EnabledEids -contains $eid) {
            $enabledCount++
        }
    }

    $reasons = [System.Collections.ArrayList]::new()
    $status  = ''

    if ($enabledCount -eq $RequiredEids.Count) {
        if ($conflictCount -gt 0) {
            $status = 'partial'
            $null = $reasons.Add('All required EIDs are enabled but filter rules may suppress relevant events:')
            foreach ($c in $FilterConflicts) {
                $null = $reasons.Add($c)
            }
        }
        else {
            $status = 'covered'
            $null = $reasons.Add('All required EIDs are enabled with no restrictive filter conflicts')
        }
    }
    elseif ($enabledCount -eq 0) {
        $status = 'blind'
        $missing = @($RequiredEids | Where-Object { $EnabledEids -notcontains $_ })
        $missingStr = ($missing | ForEach-Object { "$_" }) -join ', '
        $null = $reasons.Add("No required EIDs are enabled. Missing: $missingStr")
        if ($conflictCount -gt 0) {
            foreach ($c in $FilterConflicts) {
                $null = $reasons.Add($c)
            }
        }
    }
    else {
        $status = 'partial'
        $missing = @($RequiredEids | Where-Object { $EnabledEids -notcontains $_ })
        $missingStr = ($missing | ForEach-Object { "$_" }) -join ', '
        $null = $reasons.Add("Some required EIDs are enabled. Missing: $missingStr")
        if ($conflictCount -gt 0) {
            $null = $reasons.Add('Additionally, filter rules may suppress relevant events:')
            foreach ($c in $FilterConflicts) {
                $null = $reasons.Add($c)
            }
        }
    }

    return @{
        status  = $status
        reasons = @($reasons)
    }
}

function Get-TuningRecommendation {
    param(
        [string]$TechniqueId,
        [string]$TechniqueName,
        [int[]]$RequiredEids,
        [int[]]$EnabledEids,
        [string]$CoverageStatus,
        $FilterConflicts
    )

    $recs = [System.Collections.ArrayList]::new()

    if ($CoverageStatus -eq 'blind' -or $CoverageStatus -eq 'partial') {
        $missingEids = @($RequiredEids | Where-Object { $EnabledEids -notcontains $_ })
        foreach ($eid in $missingEids) {
            $typeName = $script:EidToType[$eid]
            $null = $recs.Add("Enable ${typeName} (EID $eid) in sysmonconfig.xml under <EventFiltering>")
        }
    }

    $conflictCount = 0
    if ($null -ne $FilterConflicts) {
        $conflictCount = @($FilterConflicts).Count
    }

    if ($conflictCount -gt 0) {
        foreach ($conflict in $FilterConflicts) {
            if ($conflict -match 'onmatch=include') {
                $null = $recs.Add('Review include rules - consider switching to onmatch exclude or broadening match patterns')
            }
            elseif ($conflict -match 'onmatch=exclude') {
                $null = $recs.Add('Review exclude rules - ensure no ATT&CK-relevant activity is being filtered out')
            }
        }
    }

    if ($recs.Count -eq 0) {
        $null = $recs.Add('No tuning required - coverage is complete')
    }

    return ($recs -join '; ')
}

function Get-EvidenceFields {
    param([int[]]$RequiredEids)

    $fields = [System.Collections.Generic.List[string]]::new()
    foreach ($eid in $RequiredEids) {
        if ($script:EidEvidenceFields.ContainsKey($eid)) {
            foreach ($f in $script:EidEvidenceFields[$eid]) {
                if (-not $fields.Contains($f)) {
                    $fields.Add($f)
                }
            }
        }
    }
    return ($fields | Sort-Object)
}

function Build-CoverageMatrix {
    param(
        $EnabledTypes,
        [int[]]$EnabledEids
    )

    $matrix = [System.Collections.Generic.List[object]]::new()
    $stats  = @{ covered = 0; partial = 0; blind = 0 }

    foreach ($mapping in $script:AttackMappings) {
        $required  = $mapping['required_eids']
        $enabled   = @($required | Where-Object { $EnabledEids -contains $_ })
        $conflicts = Get-FilterConflicts -EnabledTypes $EnabledTypes -RequiredEids $required
        $eval      = Get-CoverageStatus -RequiredEids $required -EnabledEids $EnabledEids -FilterConflicts $conflicts
        $recommend = Get-TuningRecommendation -TechniqueId $mapping['technique_id'] -TechniqueName $mapping['technique_name'] -RequiredEids $required -EnabledEids $EnabledEids -CoverageStatus $eval['status'] -FilterConflicts $conflicts
        $fields    = Get-EvidenceFields -RequiredEids $required

        $conflictCount = 0
        if ($null -ne $conflicts) {
            $conflictCount = @($conflicts).Count
        }

        $conflictStr = 'none'
        if ($conflictCount -gt 0) {
            $conflictStr = ($conflicts -join ' | ')
        }

        $enabledStr = 'none'
        if ($enabled.Count -gt 0) {
            $enabledStr = ($enabled | Sort-Object) -join ', '
        }

        $row = [ordered]@{
            technique_id             = $mapping['technique_id']
            technique_name           = $mapping['technique_name']
            required_event_ids       = ($required | Sort-Object) -join ', '
            enabled_event_ids        = $enabledStr
            filter_conflicts         = $conflictStr
            coverage_status          = $eval['status']
            evidence_fields_expected = ($fields -join ', ')
            recommendation           = $recommend
        }

        $matrix.Add([PSCustomObject]$row)

        switch ($eval['status']) {
            'covered' { $stats['covered']++ }
            'partial' { $stats['partial']++ }
            'blind'   { $stats['blind']++ }
        }
    }

    return @{ matrix = $matrix; stats = $stats }
}

function Export-CoverageMatrix {
    param(
        $Matrix,
        [string]$OutputPath
    )

    $techniques = @()
    foreach ($row in $Matrix['matrix']) {
        $techniques += [PSCustomObject]$row
    }

    $jsonObject = [ordered]@{
        generated_at = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        techniques   = $techniques
        summary      = [PSCustomObject]@{
            total_assessed = $Matrix['matrix'].Count
            covered        = $Matrix['stats']['covered']
            partial        = $Matrix['stats']['partial']
            blind          = $Matrix['stats']['blind']
        }
    }

    $jsonObject | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

$outputPath = 'sysmon_coverage_matrix.json'

Write-Host '[*] Parsing Sysmon config...'

$xmlDoc = Read-SysmonConfig
$enabledTypes = Get-EnabledEventTypes -ConfigXml $xmlDoc
$enabledIds   = Get-EnabledEventIds -EnabledTypes $enabledTypes

if ($null -eq $enabledIds -or @($enabledIds).Count -eq 0) {
    Write-Host '[!] No enabled Sysmon event IDs found. Check your sysmonconfig.xml.'
    exit 1
}

$enabledIdsStr = ($enabledIds | ForEach-Object { "$_" }) -join ', '
Write-Host "Enabled Event IDs: $enabledIdsStr"

$result = Build-CoverageMatrix -EnabledTypes $enabledTypes -EnabledEids $enabledIds

Write-Host "Techniques assessed: $($result['matrix'].Count)"
Write-Host "Covered: $($result['stats']['covered'])"
Write-Host "Partial: $($result['stats']['partial'])"
Write-Host "Blind: $($result['stats']['blind'])"

Export-CoverageMatrix -Matrix $result -OutputPath $outputPath

Write-Host "Report saved to: $outputPath"
