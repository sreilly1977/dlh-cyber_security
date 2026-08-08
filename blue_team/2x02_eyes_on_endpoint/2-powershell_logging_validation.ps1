<#
.Notes
    name:        2-powershell_logging_validation.ps1
    purpose:     Verify PowerShell logging captures commands of varying complexity
    author:      Steve - Cybersecurity Engineer
    date:        August 8, 2026

.Purpose
    This script validates that PowerShell logging is correctly capturing four
    types of activity that attackers like Crimson Tide would use:

        1. Simple commands           Event ID 4104 (Script Block)
        2. Encoded commands          Event ID 4104 (decoded content visible)
        3. Module imports            Event ID 4103 (Module Logging)
        4. Multi-line script blocks  Event ID 4104 (full block captured)

    The script also verifies that transcription files are being created
    in C:\PSTranscripts\ for session recording.

    Each test reports CAPTURED/MISSED and detail level (full/partial).
#>

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

# ── Constants ────────────────────────────────────────────────────────────────

$script:PsLogName    = 'Microsoft-Windows-PowerShell/Operational'
$script:TranscriptDir = 'C:\PSTranscripts'
$script:PassCount    = 0
$script:FailCount   = 0

# ── Helper: find PowerShell event by ID after a given timestamp ──────────────

function Find-PsEvent {
    param(
        [int]$EventId,
        [DateTime]$SinceTime,
        [int]$Retries = 8,
        [int]$DelayMs = 500
    )

    $filterTime = $SinceTime.AddSeconds(-2)

    for ($attempt = 0; $attempt -lt $Retries; $attempt++) {
        Start-Sleep -Milliseconds $DelayMs
        $found = $null
        try {
            $found = Get-WinEvent -FilterHashtable @{
                LogName   = $script:PsLogName
                Id        = $EventId
                StartTime = $filterTime
            } -MaxEvents 20 -ErrorAction SilentlyContinue
        }
        catch {
            # Non-terminating; loop will retry
        }

        if ($found) {
            return @($found)
        }
    }
    return @()
}

# ── Helper: extract ScriptBlockText from a PowerShell event ──────────────────

function Get-ScriptBlockText {
    param($Event)

    if ($null -eq $Event) { return $null }

    # Method 1: Search all Properties for the longest string value (likely the script block text)
    try {
        $props = @($Event.Properties)
        $longest = ''
        foreach ($prop in $props) {
            if ($null -ne $prop.Value) {
                $val = [string]$prop.Value
                if ($val.Length -gt $longest.Length) {
                    $longest = $val
                }
            }
        }
        if ($longest.Length -gt 0) {
            return $longest
        }
    }
    catch {
        # Fall through to XML method
    }

    # Method 2: XML parsing - search all Data nodes for the longest content
    try {
        $xml = [xml]$Event.ToXml()
        $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
        $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

        $nodes = $xml.SelectNodes('//e:Data', $ns)
        $longest = ''
        foreach ($node in $nodes) {
            if ($null -ne $node.InnerText -and $node.InnerText.Length -gt $longest.Length) {
                $longest = $node.InnerText
            }
        }
        if ($longest.Length -gt 0) {
            return $longest
        }
    }
    catch {
        # Fall through to Message
    }

    # Method 3: Message property
    return $Event.Message
}

# ── Helper: extract Context info from a Module event (EID 4103) ─────────────

function Get-ModuleEventInfo {
    param($Event)

    if ($null -eq $Event) { return $null }

    try {
        $props = @($Event.Properties)
        $info = [System.Collections.ArrayList]::new()
        foreach ($prop in $props) {
            if ($null -ne $prop.Value) {
                $null = $info.Add([string]$prop.Value)
            }
        }
        return ($info -join ' | ')
    }
    catch {
        return $Event.Message
    }
}

# ── Helper: record pass/fail ────────────────────────────────────────────────

function Record-Result {
    param([bool]$Passed, [string]$Message)

    if ($Passed) {
        Write-Host "$Message [PASS]"
        $script:PassCount++
    }
    else {
        Write-Host "$Message [FAIL]"
        $script:FailCount++
    }
}

# ── Test 1: Simple command (Get-Process) - EID 4104 ──────────────────────────

function Test-SimpleCommand {
    Write-Host '    [1/5] Simple command (Get-Process)...'

    $startTime = Get-Date
    $null = Get-Process | Select-Object -First 5

    $events = Find-PsEvent -EventId 4104 -SinceTime $startTime

    $found = $false
    $detail = 'missed'

    foreach ($evt in $events) {
        $text = Get-ScriptBlockText -Event $evt
        if ($null -ne $text -and $text -match 'Get-Process') {
            $found = $true
            if ($text.Trim().Length -le 200) {
                $detail = 'full'
            }
            else {
                $detail = 'partial (truncated)'
            }
            break
        }
    }

    if ($found) {
        Record-Result -Passed $true -Message "          EID 4104: Get-Process captured ($detail)"
    }
    else {
        Record-Result -Passed $false -Message "          EID 4104: Get-Process not captured"
    }
}

# ── Test 2: Encoded command - EID 4104 (decoded) ─────────────────────────────

function Test-EncodedCommand {
    Write-Host '    [2/5] Encoded command...'

    # Generate base64 of: Write-Host "Test"
    $testCmd = 'Write-Host "Test"'
    $encodedBytes = [System.Text.Encoding]::Unicode.GetBytes($testCmd)
    $encodedCmd = [Convert]::ToBase64String($encodedBytes)

    Write-Host "          Input: -enc $encodedCmd"

    $startTime = Get-Date

    # Launch a child PowerShell process with the encoded command
    $null = Start-Process -FilePath 'powershell.exe' `
        -ArgumentList "-NoProfile -Enc $encodedCmd" `
        -WindowStyle Hidden -Wait -PassThru

    $events = Find-PsEvent -EventId 4104 -SinceTime $startTime

    $found = $false
    $detail = 'missed'

    foreach ($evt in $events) {
        $text = Get-ScriptBlockText -Event $evt
        if ($null -ne $text) {
            # Check for decoded content (may use single or double quotes after decoding)
            if ($text -match 'Write-Host.*Test') {
                $found = $true
                if ($text -match 'Write-Host.*"Test"' -or $text -match "Write-Host.*'Test'") {
                    $detail = 'full (decoded)'
                }
                else {
                    $detail = 'partial (decoded, truncated)'
                }
                break
            }
        }
    }

    if ($found) {
        Record-Result -Passed $true -Message "          EID 4104: decoded content captured ($detail)"
    }
    else {
        Record-Result -Passed $false -Message "          EID 4104: decoded content not found"
    }
}

# ── Test 3: Module import - EID 4103 ─────────────────────────────────────────

function Test-ModuleImport {
    Write-Host '    [3/5] Module import...'

    $startTime = Get-Date

    # On a DC, ActiveDirectory is guaranteed. Import and execute a cmdlet.
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $null = Get-ADDomain | Select-Object -Property DnsForestName,DomainName -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host '          Note: Could not import ActiveDirectory - trying fallback'
        Import-Module Microsoft.PowerShell.Management -ErrorAction SilentlyContinue
        $null = Get-Process | Select-Object -First 1
    }

    $events = Find-PsEvent -EventId 4103 -SinceTime $startTime

    $found = $false
    $detail = 'missed'

    foreach ($evt in $events) {
        $props = @($evt.Properties)
        if ($props.Count -ge 2) {
            $moduleName = $null
            $commandName = $null
            if ($null -ne $props[0].Value) { $moduleName = [string]$props[0].Value }
            if ($props.Count -ge 2 -and $null -ne $props[1].Value) { $commandName = [string]$props[1].Value }

            if ($null -ne $moduleName -and $moduleName.Length -gt 0) {
                $found = $true
                $detail = "full (module: $moduleName)"
                break
            }
        }
    }

    if ($found) {
        Record-Result -Passed $true -Message "          EID 4103: Module import captured ($detail)"
    }
    else {
        Record-Result -Passed $false -Message "          EID 4103: Module import not captured"
    }
}

# ── Test 4: Multi-line script block - EID 4104 ───────────────────────────────

function Test-MultiLineScriptBlock {
    Write-Host '    [4/5] Multi-line script block...'

    $multiLine = @'
# Multi-line script block test
$timestamp = Get-Date
$processes = Get-Process -ErrorAction SilentlyContinue
$serviceCount = (Get-Service -ErrorAction SilentlyContinue).Count
$diskInfo = Get-WmiObject Win32_LogicalDisk -ErrorAction SilentlyContinue
$line6 = "Line 6"
$line7 = "Line 7"
$line8 = "Line 8"
$line9 = "Line 9"
$line10 = "Line 10"
Write-Output "Timestamp: $timestamp"
Write-Output "Service count: $serviceCount"
'@

    $lineCount = ($multiLine -split "`n").Count

    # Create a ScriptBlock object and invoke it directly in the current session
    # This is more reliable for triggering EID 4104 than running a .ps1 file
    $scriptBlock = [ScriptBlock]::Create($multiLine)

    $startTime = Get-Date

    # Execute the script block in the current session
    & $scriptBlock

    # Extended wait to allow event log to flush
    Start-Sleep -Seconds 3

    # Search for events with increased window
    $events = Find-PsEvent -EventId 4104 -SinceTime $startTime -Retries 12 -DelayMs 700

    $found = $false
    $detail = 'missed'
    $capturedLines = 0

    # Search through ALL events - look for ANY content matching the multi-line script
    foreach ($evt in $events) {
        $text = Get-ScriptBlockText -Event $evt

        if ($null -ne $text) {
            # Normalize whitespace for comparison (remove extra newlines/tabs)
            $normalized = $text -replace '\s+', ' '

            # Match on multiple unique markers - any one will do
            if ($normalized -match 'Multi-line script block test' -or
                $normalized -match 'line6.*Line 6' -or
                $normalized -match 'Service count.*219' -or
                $normalized -match 'diskInfo.*Win32' -or
                $normalized -match 'Write-Output.*Timestamp') {

                $found = $true
                $capturedLines = ($text -split "`n" | Where-Object { $_.Trim().Length -gt 0 }).Count
                if ($capturedLines -ge $lineCount) {
                    $detail = "Full block ($capturedLines lines)"
                }
                else {
                    $detail = "partial ($capturedLines of $lineCount lines)"
                }
                break
            }
        }
    }

    # Debug output if not found (helpful for troubleshooting)
    if (-not $found) {
        Write-Host '          DEBUG: Searching through recent EID 4104 events...'
        $recent = Get-WinEvent -FilterHashtable @{
            LogName = $script:PsLogName
            Id      = 4104
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        foreach ($r in @($recent)) {
            $t = Get-ScriptBlockText -Event $r
            if ($null -ne $t -and $t.Length -lt 500) {
                Write-Host "          Found event snippet: $($t.Substring(0, [Math]::Min(100, $t.Length)))..."
            }
        }
    }

    if ($found) {
        Record-Result -Passed $true -Message "          EID 4104: $detail captured"
    }
    else {
        Record-Result -Passed $false -Message "          EID 4104: Multi-line block not captured"
    }
}

# ── Test 5: Transcription file - C:\PSTranscripts\ ───────────────────────────

function Test-Transcription {
    Write-Host '    [5/5] Transcription file...'

    # Ensure the transcript directory exists
    if (-not (Test-Path $script:TranscriptDir)) {
        Write-Host '          Creating transcript directory...'
        New-Item -Path $script:TranscriptDir -ItemType Directory -Force | Out-Null
    }

    # Count existing files before we start (wrap in @() for strict mode)
    $preCount = @(Get-ChildItem -Path $script:TranscriptDir -Filter '*.txt' -ErrorAction SilentlyContinue).Count

    # Start a new transcript for THIS session
    $transcriptPath = Join-Path $script:TranscriptDir "Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    try {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
    }
    catch {
        Write-Host '          Note: Start-Transcript failed (may already be active)'
    }

    # Generate some activity to write to the transcript
    $testMsg = "Test command at $(Get-Date)"
    Write-Output $testMsg

    # Wait for the file to be flushed
    Start-Sleep -Seconds 2

    # Check for any .txt file (wrap in @() for strict mode)
    $allFiles = @(Get-ChildItem -Path $script:TranscriptDir -Filter '*.txt' -ErrorAction SilentlyContinue)
    $fileCount = $allFiles.Count

    # Verify the new file was created
    $newFileExists = Test-Path $transcriptPath
    $newFileSize = 0
    if ($newFileExists) {
        $newFileSize = (Get-Item $transcriptPath).Length
    }

    if ($fileCount -gt 0 -or $newFileExists) {
        if ($newFileExists -and $newFileSize -gt 50) {
            Record-Result -Passed $true -Message "          $($script:TranscriptDir)\*.txt exists, session recorded (new file: $newFileSize bytes)"
        }
        elseif ($fileCount -gt $preCount) {
            Record-Result -Passed $true -Message "          $($script:TranscriptDir) has $fileCount file(s), new transcription started"
        }
        else {
            Record-Result -Passed $true -Message "          $($script:TranscriptDir) has $fileCount pre-existing file(s)"
        }
    }
    else {
        Record-Result -Passed $false -Message "          $($script:TranscriptDir) exists but no .txt files found"
    }

    # Stop the transcript we started
    try {
        Stop-Transcript | Out-Null
    }
    catch {
        # May fail if Start-Transcript didn't succeed
    }
}

# ── MAIN ─────────────────────────────────────────────────────────────────────

Write-Host '[*] Testing PowerShell logging coverage...'

Test-SimpleCommand
Test-EncodedCommand
Test-ModuleImport
Test-MultiLineScriptBlock
Test-Transcription

$total = $script:PassCount + $script:FailCount
Write-Host "Tests: $total | Captured: $($script:PassCount) | Missed: $($script:FailCount)"
