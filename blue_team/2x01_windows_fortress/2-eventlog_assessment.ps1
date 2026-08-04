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

# Critical Event IDs and their corresponding audit categories/subcategories
$eventDefinitions = @(
    @{ Id = 4624; Description = "Successful Logon"; AuditSubcategory = "Logon" }
    @{ Id = 4625; Description = "Failed Logon"; AuditSubcategory = "Logon" }
    @{ Id = 4648; Description = "Explicit Credentials"; AuditSubcategory = "Logon" }
    @{ Id = 4688; Description = "Process Creation"; AuditSubcategory = "Process Tracking" }
    @{ Id = 4720; Description = "Account Created"; AuditSubcategory = "Account Management" }
    @{ Id = 4726; Description = "Account Deleted"; AuditSubcategory = "Account Management" }
    @{ Id = 4732; Description = "Member Added to Group"; AuditSubcategory = "Account Management" }
    @{ Id = 4672; Description = "Special Logon"; AuditSubcategory = "Special Logon" }
    @{ Id = 1102; Description = "Audit Log Cleared"; AuditSubcategory = "System Integrity" }
)

Write-Host "[*] Assessing Windows Event Log Capability..." -ForegroundColor Yellow

# 1. Get current audit policy using auditpol
Write-Host "[1/3] Retrieving current audit policy..." -ForegroundColor Yellow
$auditConfig = @{}

try {
    $auditRawOutput = & auditpol.exe /get /category:* 2>&1
    foreach ($line in $auditRawOutput) {
        if ($line -match '^\s*(.+?)\s+(Success and Failure|Success|Failure|No Auditing)\s*$') {
            $subcategory = $Matches[1].Trim()
            $status = $Matches[2].Trim()
            $auditConfig[$subcategory] = $status
        }
    }
} catch {
    Write-Warning "Could not retrieve audit policy via auditpol (may require elevation). Continuing with assumed 'No Auditing' for all subcategories."
}

# 2. Query Security event log for Event IDs generated in the last 24 hours
Write-Host "[2/3] Querying Security event log for last 24 hours..." -ForegroundColor Yellow
$generatedEvents = @{}
$startTime = (Get-Date).AddHours(-24)

try {
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
    $subcat = $def.AuditSubcategory

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

    $row = "{0,-10} {1,-25} {2,-25} {3}" -f $def.Id, $def.Description, $def.AuditSubcategory, $status
    Write-Host $row

    $results += [PSCustomObject]@{
        event_id = $def.Id
        description = $def.Description
        audit_subcategory = $def.AuditSubcategory
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
