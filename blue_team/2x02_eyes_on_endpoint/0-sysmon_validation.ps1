<#
.Notes
    name:        0-sysmon_validation.ps1
    purpose:     Validate Sysmon telemetry coverage by triggering and verifying five key Event IDs
    author:      Steve - Cybersecurity Engineer
    date:        August 8, 2026

.Purpose
    This script validates that Sysmon is correctly capturing five critical Event IDs
    by triggering controlled actions and verifying each produces the expected telemetry:

        EID 1  - Process creation      Launches cmd.exe /c whoami and verifies CommandLine field
        EID 3  - Network connection    Opens TCP to 1.1.1.1:53 and verifies DestinationIp/Port
        EID 11 - File creation         Creates .exe in TEMP and verifies TargetFilename/Image
        EID 13 - Registry modification Writes to HKCU Run key and verifies TargetObject/EventType
        EID 22 - DNS query             Resolves google.com via nslookup and verifies QueryName/Results

    A diagnostic pre-check scans for recent events of each type before testing.
    All test artifacts (files, registry values) are cleaned up on completion.
#>

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

# ── Constants ────────────────────────────────────────────────────────────────
$script:SysmonLogName       = 'Microsoft-Windows-Sysmon/Operational'
$script:TestFilePath        = "$env:TEMP\sysmon_test.txt"
$script:TestFileWinTemp     = 'C:\Windows\Temp\sysmon_test.exe'
$script:TestRegPath         = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$script:TestRegValue        = 'SysmonTest'
$script:TestRegDisplay      = 'HKCU\...\Run\SysmonTest'
$script:TestDomain          = 'google.com'
$script:TestDestIp          = '1.1.1.1'
$script:TestDestPort        = 53
$script:TestFileDesktop     = "$env:USERPROFILE\Desktop\sysmon_test.txt"
$script:TestFileCTemp       = 'C:\Temp\sysmon_test.txt'
$script:TestFileExe         = "$env:TEMP\sysmon_test.exe"

# ── Results tracking ──────────────────────────────────────────────────────────
$script:passCount = 0
$script:failCount = 0

# ── Helper: find Sysmon event by ID after a given timestamp ───────────────────
function Find-SysmonEvent {
    param(
        [int]$EventId,
        [DateTime]$SinceTime,
        [int]$Retries = 6,
        [int]$DelayMs = 500
    )

    # Subtract 1 second to guard against clock precision issues
    $filterTime = $SinceTime.AddSeconds(-1)

    for ($attempt = 0; $attempt -lt $Retries; $attempt++) {
        Start-Sleep -Milliseconds $DelayMs
        $found = $null
        try {
            $found = Get-WinEvent -FilterHashtable @{
                LogName   = $script:SysmonLogName
                Id        = $EventId
                StartTime = $filterTime
            } -MaxEvents 10 -ErrorAction SilentlyContinue
        }
        catch {
            # Non-terminating with SilentlyContinue; loop will retry
        }

        if ($found) {
            $events = @($found)
            return $events[0]
        }
    }
    return $null
}

# ── Helper: extract named data fields from a Sysmon event ─────────────────────
function Get-SysmonEventData {
    param($Event)

    $hash = @{}
    $xml = [xml]$Event.ToXml()
    $ns = New-Object System.Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')
    $nodes = $xml.SelectNodes('//e:Data', $ns)
    foreach ($node in $nodes) {
        $name = $node.GetAttribute('Name')
        if (-not [string]::IsNullOrEmpty($name)) {
            $hash[$name] = $node.InnerText
        }
    }
    return $hash
}

# ── Pre-flight: verify Sysmon is installed and running ────────────────────────
function Test-SysmonReady {
    # Sysmon64 registers as "Sysmon64"; the 32-bit build registers as "Sysmon"
    $svc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue |
        Where-Object { $null -ne $_ } |
        Select-Object -First 1

    if ($null -eq $svc) {
        Write-Host '[!] Sysmon service not found. Install Sysmon before running this script.'
        exit 1
    }
    if ($svc.Status -ne 'Running') {
        Write-Host "[!] Sysmon service ($($svc.Name)) is $($svc.Status). Start it with: Start-Service $($svc.Name)"
        exit 1
    }
}

# ── Diagnostic: check which Event IDs are configured in Sysmon ────────────────
function Get-SysmonEventConfig {
    param([int[]]$IdsToCheck = @(1, 3, 11, 13, 22))

    Write-Host '[*] Checking Sysmon event coverage...'
    foreach ($id in $IdsToCheck) {
        $testEvents = $null
        try {
            $testEvents = Get-WinEvent -FilterHashtable @{
                LogName = $script:SysmonLogName
                Id      = $id
            } -MaxEvents 1 -ErrorAction SilentlyContinue
        }
        catch {
            # No events found for this ID
        }

        # Wrap in @() to handle both single objects and arrays under strict mode
        $eventCount = @($testEvents).Count
        if ($eventCount -gt 0) {
            Write-Host "    Event ID $id : ENABLED (recent events found)"
        }
        else {
            Write-Host "    Event ID $id : NO RECENT EVENTS (may be disabled or no activity yet)"
        }
    }
    Write-Host ''
}

# ── Test 1: Process Creation (EID 1) ───────────────────────────────────────────
function Test-ProcessCreation {
    Write-Host '    [1/5] Process creation (Event ID 1)...'

    $startTime = Get-Date
    $null = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c whoami' `
        -WindowStyle Hidden -Wait -PassThru

    $evt = Find-SysmonEvent -EventId 1 -SinceTime $startTime
    if ($null -eq $evt) {
        Write-Host '          cmd.exe /c whoami -> No Sysmon EID 1 found              [FAIL]'
        $script:failCount++
        return
    }

    $data = Get-SysmonEventData -Event $evt
    if ($data.ContainsKey('CommandLine') -and $data['CommandLine'] -match 'whoami') {
        Write-Host '          cmd.exe /c whoami -> Sysmon EID 1 captured, cmdline present   [PASS]'
        $script:passCount++
    }
    else {
        Write-Host '          cmd.exe /c whoami -> Sysmon EID 1 found, cmdline missing     [FAIL]'
        $script:failCount++
    }
}

# ── Test 2: Network Connection (EID 3) ────────────────────────────────────────
function Test-NetworkConnection {
    Write-Host '    [2/5] Network connection (Event ID 3)...'

    $startTime = Get-Date
    $null = Test-NetConnection -ComputerName $script:TestDestIp -Port $script:TestDestPort -WarningAction SilentlyContinue

    Start-Sleep -Milliseconds 500

    $evt = Find-SysmonEvent -EventId 3 -SinceTime $startTime
    if ($null -eq $evt) {
        Write-Host '          Outbound TCP -> No Sysmon EID 3 found                     [FAIL]'
        $script:failCount++
        return
    }

    $data = Get-SysmonEventData -Event $evt
    if ($data.ContainsKey('DestinationIp') -and $data.ContainsKey('DestinationPort')) {
        Write-Host '          Outbound TCP -> Sysmon EID 3 captured, dest IP/port present   [PASS]'
        $script:passCount++
    }
    else {
        Write-Host '          Outbound TCP -> Sysmon EID 3 found, details missing          [FAIL]'
        $script:failCount++
    }
}

# ── Test 3: File Creation (EID 11) ────────────────────────────────────────────
function Test-FileCreation {
    Write-Host '    [3/5] File creation (Event ID 11)...'

    # SwiftOnSecurity uses FileCreate onmatch="include" with specific extension
    # rules. A plain .txt file will not match. An .exe extension is monitored
    # because it detects executable drops in user-writable locations.

    # Remove any leftover files from previous runs
    $cleanupPaths = @(
        $script:TestFileExe,
        $script:TestFileWinTemp,
        $script:TestFileDesktop,
        $script:TestFileCTemp,
        $script:TestFilePath
    )
    foreach ($p in $cleanupPaths) {
        if (Test-Path $p) {
            Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
        }
    }

    # Attempt 1: .exe in user TEMP (SwiftOnSecurity monitors executable drops in temp)
    $startTime = Get-Date
    $null = New-Item -Path $script:TestFileExe -ItemType File -Force
    Set-Content -Path $script:TestFileExe -Value 'Sysmon telemetry validation test file.'
    Start-Sleep -Milliseconds 1000

    $evt = Find-SysmonEvent -EventId 11 -SinceTime $startTime
    $displayPath = $script:TestFileExe

    # Attempt 2: .exe in C:\Windows\Temp
    if ($null -eq $evt) {
        $startTime = Get-Date
        $null = New-Item -Path $script:TestFileWinTemp -ItemType File -Force
        Set-Content -Path $script:TestFileWinTemp -Value 'Sysmon telemetry validation test file.'
        Start-Sleep -Milliseconds 1000

        $evt = Find-SysmonEvent -EventId 11 -SinceTime $startTime
        $displayPath = $script:TestFileWinTemp
    }

    # Attempt 3: .exe on Desktop
    if ($null -eq $evt) {
        $desktopExe = "$env:USERPROFILE\Desktop\sysmon_test.exe"
        $startTime = Get-Date
        $null = New-Item -Path $desktopExe -ItemType File -Force
        Set-Content -Path $desktopExe -Value 'Sysmon telemetry validation test file.'
        Start-Sleep -Milliseconds 1000

        $evt = Find-SysmonEvent -EventId 11 -SinceTime $startTime
        $displayPath = $desktopExe
    }

    # Attempt 4: .exe in C:\Temp
    if ($null -eq $evt) {
        if (-not (Test-Path 'C:\Temp')) {
            New-Item -Path 'C:\Temp' -ItemType Directory -Force | Out-Null
        }
        $cTempExe = 'C:\Temp\sysmon_test.exe'
        $startTime = Get-Date
        $null = New-Item -Path $cTempExe -ItemType File -Force
        Set-Content -Path $cTempExe -Value 'Sysmon telemetry validation test file.'
        Start-Sleep -Milliseconds 1000

        $evt = Find-SysmonEvent -EventId 11 -SinceTime $startTime
        $displayPath = $cTempExe
    }

    if ($null -eq $evt) {
        Write-Host "          $displayPath -> No Sysmon EID 11 found (path may be excluded) [FAIL]"
        $script:failCount++
        return
    }

    $data = Get-SysmonEventData -Event $evt
    if ($data.ContainsKey('TargetFilename') -and $data.ContainsKey('Image')) {
        Write-Host "          $displayPath -> Sysmon EID 11 captured            [PASS]"
        $script:passCount++
    }
    else {
        Write-Host "          $displayPath -> Sysmon EID 11 found, details missing [FAIL]"
        $script:failCount++
    }
}

# ── Test 4: Registry Modification (EID 13) ───────────────────────────────────
function Test-RegistryModification {
    Write-Host '    [4/5] Registry modification (Event ID 13)...'

    $startTime = Get-Date
    Set-ItemProperty -Path $script:TestRegPath `
        -Name $script:TestRegValue -Value 'cmd.exe /c echo sysmon_validation' -Type String

    $evt = Find-SysmonEvent -EventId 13 -SinceTime $startTime
    if ($null -eq $evt) {
        Write-Host "          $($script:TestRegDisplay) -> No Sysmon EID 13 found                 [FAIL]"
        $script:failCount++
        return
    }

    $data = Get-SysmonEventData -Event $evt
    if ($data.ContainsKey('TargetObject') -and $data.ContainsKey('EventType')) {
        Write-Host "          $($script:TestRegDisplay) -> Sysmon EID 13 captured                 [PASS]"
        $script:passCount++
    }
    else {
        Write-Host "          $($script:TestRegDisplay) -> Sysmon EID 13 found, details missing     [FAIL]"
        $script:failCount++
    }
}

# ── Test 5: DNS Query (EID 22) ────────────────────────────────────────────────
function Test-DnsQuery {
    Write-Host '    [5/5] DNS query (Event ID 22)...'

    $startTime = Get-Date

    # Trigger 1: ping goes through the Windows DNS client, which Sysmon hooks
    $null = Start-Process -FilePath 'ping.exe' -ArgumentList '-n', '1', $script:TestDomain `
        -WindowStyle Hidden -Wait -PassThru

    Start-Sleep -Milliseconds 1000

    $evt = Find-SysmonEvent -EventId 22 -SinceTime $startTime

    # Trigger 2: nslookup as fallback
    if ($null -eq $evt) {
        $null = Start-Process -FilePath 'nslookup.exe' -ArgumentList $script:TestDomain `
            -WindowStyle Hidden -Wait -PassThru

        Start-Sleep -Milliseconds 1000
        $evt = Find-SysmonEvent -EventId 22 -SinceTime $startTime
    }

    # Trigger 3: Invoke-WebRequest as last resort
    if ($null -eq $evt) {
        try {
            $null = Invoke-WebRequest -Uri "http://$($script:TestDomain)/" -TimeoutSec 3 -UseBasicParsing
        }
        catch {
            # Even failed connections trigger DNS queries
        }

        Start-Sleep -Milliseconds 1000
        $evt = Find-SysmonEvent -EventId 22 -SinceTime $startTime
    }

    if ($null -eq $evt) {
        Write-Host "          $($script:TestDomain) -> No Sysmon EID 22 found                [FAIL]"
        $script:failCount++
        return
    }

    $data = Get-SysmonEventData -Event $evt
    if ($data.ContainsKey('QueryName') -and $data.ContainsKey('QueryResults')) {
        Write-Host "          $($script:TestDomain) -> Sysmon EID 22 captured                [PASS]"
        $script:passCount++
    }
    else {
        Write-Host "          $($script:TestDomain) -> Sysmon EID 22 found, details missing     [FAIL]"
        $script:failCount++
    }
}

# ── Cleanup test artifacts ─────────────────────────────────────────────────────
function Invoke-Cleanup {
    Write-Host '[*] Cleanup: removing test artifacts...'

    # Remove test files from all locations (including .exe variants)
    $cleanupPaths = @(
        $script:TestFilePath,
        $script:TestFileDesktop,
        $script:TestFileCTemp,
        $script:TestFileExe,
        $script:TestFileWinTemp,
        "$env:USERPROFILE\Desktop\sysmon_test.exe",
        "$env:USERPROFILE\Desktop\sysmon_test.txt",
        'C:\Temp\sysmon_test.exe',
        'C:\Temp\sysmon_test.txt',
        'C:\Windows\Temp\sysmon_test.exe',
        'C:\Windows\Temp\sysmon_test.txt'
    )
    foreach ($p in $cleanupPaths) {
        if (Test-Path $p) {
            Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
        }
    }

    # Remove just the test value, not the entire Run key
    if (Get-ItemProperty -Path $script:TestRegPath -Name $script:TestRegValue -ErrorAction SilentlyContinue) {
        Remove-ItemProperty -Path $script:TestRegPath -Name $script:TestRegValue -Force -ErrorAction SilentlyContinue
    }
}

# ── Wrapper: run a test function and catch unexpected errors ──────────────────
function Invoke-Test {
    param([scriptblock]$Test)

    try {
        & $Test
    }
    catch {
        Write-Host "          Unexpected error: $($_.Exception.Message)   [FAIL]"
        $script:failCount++
    }
}

# ══ MAIN ══════════════════════════════════════════════════════════════════════
Test-SysmonReady

Get-SysmonEventConfig -IdsToCheck @(1, 3, 11, 13, 22)

Write-Host '[*] Running Sysmon telemetry validation...'

Invoke-Test ${function:Test-ProcessCreation}
Invoke-Test ${function:Test-NetworkConnection}
Invoke-Test ${function:Test-FileCreation}
Invoke-Test ${function:Test-RegistryModification}
Invoke-Test ${function:Test-DnsQuery}

Invoke-Cleanup

$total = $script:passCount + $script:failCount
Write-Host "Actions tested: $total | Captured: $($script:passCount) | Missed: $($script:failCount)"
