<#
.Synopsis
    2-eventlog_assessment.ps1 - Windows Event Log Assessment
.Purpose
    Assesses current event logging capability by checking which critical Event IDs
    the domain is generating, verifying audit policy configuration and actual
    log generation within the last 24 hours.
.Author
    Steve - Cybersecurity Engineer
.Date
    August 4, 2026
#>

param(
    [string]$OutputPath = "eventlog_assessment.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Critical Event IDs and their corresponding audit subcategories
$eventDefinitions = @(
    @{ Id = 4624; Description = "Successful Logon"; Subcategory = "Logon" }
    @{ Id = 4625; Description = "Failed Logon"; Subcategory = "Logon" }
    @{ Id = 4648; Description = "Explicit Credentials"; Subcategory = "Logon" }
    @{ Id = 4688; Description = "Process Creation"; Subcategory = "Process Creation" }
    @{ Id = 4720; Description = "Account Created"; Subcategory = "User Account Management" }
    @{ Id = 4726; Description = "Account Deleted"; Subcategory = "User Account Management" }
    @{ Id = 4732; Description = "Member Added to Group"; Subcategory = "Security Group Management" }
    @{ Id = 4672; Description = "Special Logon"; Subcategory = "Special Logon" }
    @{ Id = 1102; Description = "Audit Log Cleared"; Subcategory = "System Integrity" }
)

Write-Host "[*] Assessing Windows Event Log Capability..." -ForegroundColor Yellow

# 1. Get current audit policy using auditpol
Write-Host "[1/3] Retrieving current audit policy..." -ForegroundColor Yellow
$auditRawOutput = auditpol.exe /get /category:* 2>&1
$auditConfig = @{}

# Parse auditpol output to map subcategories to their status
foreach ($line in $auditRawOutput) {
    if ($line -match '^\s*(.+?)\s+(Success and Failure|Success|Failure|No Auditing)\s*$') {
        $subcategory = $matches[1].Trim()
        $status = $matches[2].Trim()
        $auditConfig[$subcategory] = $status
    }
}

# 2. Query Security event log for Event IDs generated in the last 24 hours
Write-Host "[2/3] Querying Security event log for last 24 hours..." -ForegroundColor Yellow
$generatedEvents = @{}
$startTime = (Get-Date).AddHours(-24)

try {
    # Query the Security log once for all target events for efficiency
    $targetIds = $eventDefinitions | ForEach-Object { $_.Id }
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $targetIds; StartTime = $startTime } -ErrorAction SilentlyContinue

    if ($null -ne $events) {
        foreach ($event in $events) {
            $generatedEvents[$event.Id] = $true
        }
    }
} catch {
    Write-Warning "Could not query Security event log (may require elevation). Assuming no events generated."
}

# 3. Correlate and display results
Write-Host "[3/3] Correlating audit policy and event log data..." -ForegroundColor Yellow
Write-Host ""

$results = @()

$header = "{0,-10} {1,-25} {2,-25} {3}" -f "Event ID", "Description", "Audit Subcategory", "Status"
Write-Host $header
Write-Host ("-" * $header.Length)

foreach ($def in $eventDefinitions) {
    $isConfigured = $false
    $subcat = $def.Subcategory

    if ($auditConfig.ContainsKey($subcat)) {
        if ($auditConfig[$subcat] -match "Success and Failure|Success|Failure") {
            $isConfigured = $true
        }
    }

    $isGenerating = $generatedEvents.ContainsKey($def.Id)

    if ($isGenerating) {
        $status = "[GENERATING]"
    } elseif ($isConfigured) {
        $status = "[CONFIGURED BUT NOT GENERATING]"
    } else {
        $status = "[NOT CONFIGURED]"
    }

    $row = "{0,-10} {1,-25} {2,-25} {3}" -f $def.Id, $def.Description, $def.Subcategory, $status
    Write-Host $row

    $results += [PSCustomObject]@{
        event_id = $def.Id
        description = $def.Description
        audit_subcategory = $def.Subcategory
        audit_status = $auditConfig[$subcat]
        status = $status
    }
}

# Export results to JSON
$report = [PSCustomObject]@{
    assessment_time = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    total_events_checked = $results.Count
    results = $results
}

$report | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutputPath -Force -Encoding UTF8
Write-Host ""
Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
