<#
.SYNOPSIS
    Aligns Windows Firewall to MedDefense segmentation rules from segmentation_rules.json
.DESCRIPTION
    Reads the segmentation contract, sets profile defaults, removes stale MedDefense rules,
    creates inbound firewall rules for each terminating flow, and enables blocked connection logging.
.NOTES
    Name:        6-windows_firewall.ps1
    Purpose:     Translate segmentation_rules.json into Windows Firewall rules via PowerShell
    Author:      Steve - Cybersecurity Engineer
    Date:        August 14, 2026
    Requires:    Run as Administrator on a domain-joined Windows host
#>

Set-StrictMode -Version Latest

$ErrorActionPreference = "Stop"

# Configuration
$SegmentationFile = Join-Path $PSScriptRoot "segmentation_rules.json"
$OutputJson = Join-Path $PSScriptRoot "windows_firewall_evidence.json"
$LogFileName = "%systemroot%\system32\LogFiles\Firewall\meddefense.log"

# Verify input exists
if (-not (Test-Path $SegmentationFile)) {
    Write-Host "[!] Error: segmentation_rules.json not found at $SegmentationFile" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Reading segmentation_rules.json..."

# Read and parse the segmentation rules JSON
$config = Get-Content $SegmentationFile -Raw | ConvertFrom-Json

# Build a zone lookup hashtable for CIDR resolution
$zoneLookup = @{}
foreach ($zone in $config.zones) {
    $zoneLookup[$zone.name] = $zone.cidr
}

# ---------------------------------------------------------------
# Determine local zone by matching host IP addresses against zone CIDRs
# This ensures only flows terminating on this host's zone are created as inbound rules
# ---------------------------------------------------------------
Write-Host "[*] Detecting local zone..."

$localZone = "INTERNAL"
$hostIPs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" }

foreach ($zone in $config.zones) {
    $cidr = $zone.cidr
    $networkParts = $cidr.Split("/")
    $networkAddr = $networkParts[0]
    $prefixLen = [int]$networkParts[1]

    foreach ($ip in $hostIPs) {
        $ipAddr = $ip.IPAddress
        try {
            $ipObj = [System.Net.IPAddress]::Parse($ipAddr)
            $netObj = [System.Net.IPAddress]::Parse($networkAddr)

            $ipBytes = $ipObj.GetAddressBytes()
            $netBytes = $netObj.GetAddressBytes()

            # Calculate subnet mask from prefix length
            $maskBytes = [byte[]]::new(4)
            for ($i = 0; $i -lt 4; $i++) {
                if ($prefixLen -gt 8) {
                    $maskBytes[$i] = 255
                    $prefixLen -= 8
                } elseif ($prefixLen -gt 0) {
                    $maskBytes[$i] = [byte](255 -shl (8 - $prefixLen))
                    $prefixLen = 0
                } else {
                    $maskBytes[$i] = 0
                }
            }

            # Reset prefixLen for next iteration
            $prefixLen = [int]$networkParts[1]

            $match = $true
            for ($i = 0; $i -lt 4; $i++) {
                if (($ipBytes[$i] -band $maskBytes[$i]) -ne ($netBytes[$i] -band $maskBytes[$i])) {
                    $match = $false
                    break
                }
            }

            if ($match) {
                $localZone = $zone.name
                break
            }
        } catch {
            continue
        }
    }

    if ($localZone -ne "INTERNAL") { break }
}

Write-Host "    Local zone: $localZone"

Write-Host "[*] Setting profile defaults..."

# ---------------------------------------------------------------
# Set DefaultInboundAction = Block, DefaultOutboundAction = Allow
# Enable dropped connection logging for all three profiles:
# Domain, Private, and Public
# ---------------------------------------------------------------
$profiles = @("Domain", "Private", "Public")
$profileSettings = @()

foreach ($profile in $profiles) {
    Set-NetFirewallProfile -Name $profile `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -LogBlocked True `
        -LogFileName $LogFileName

    $status = "DefaultInboundAction=Block  LogBlocked=True   [SET]"
    Write-Host ("  {0,-8} {1}" -f "$profile`:", $status)

    $profileSettings += @{
        profile         = $profile
        default_inbound = "Block"
        default_outbound = "Allow"
        log_blocked     = $true
        log_filename    = $LogFileName
    }
}

# ---------------------------------------------------------------
# Remove any pre-existing rule whose DisplayName starts with MedDefense-
# This makes the script idempotent: re-running cleans and rebuilds
# ---------------------------------------------------------------
Write-Host "[*] Clearing previous MedDefense-* rules..."

$existingRules = Get-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue
$removedCount = 0
if ($existingRules) {
    $removedCount = @($existingRules).Count
    Remove-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue
}
Write-Host ("  [{0} removed]" -f $removedCount)

# ---------------------------------------------------------------
# Create inbound firewall rules from the flow matrix
# For each allow flow that terminates on this host (dst_zone matches
# local zone), create a New-NetFirewallRule with:
#   DisplayName: MedDefense-<src_zone>-<proto>-<dport>
#   Direction Inbound, Action Allow
#   Protocol and LocalPort from the flow
#   RemoteAddress from the source zone CIDR
#   Profile Any
# ---------------------------------------------------------------
Write-Host "[*] Creating rules from flow matrix..."

$createdRules = @()
$ruleCount = 0

foreach ($flow in $config.flows) {
    # Skip deny_all flows - they are enforced by the default Block policy
    if ($flow.action -ne "allow") {
        continue
    }

    # Only create inbound rules for flows that terminate on the local host's zone
    if ($flow.dst_zone -ne $localZone) {
        continue
    }

    # Skip "any" protocol flows as they are not specific port-based rules
    if ($flow.proto -eq "any") {
        continue
    }

    # Resolve source zone CIDR from the zone lookup
    $sourceCidr = $zoneLookup[$flow.src_zone]
    if (-not $sourceCidr) {
        Write-Host ("  [SKIP] Unknown source zone: {0}" -f $flow.src_zone) -ForegroundColor Yellow
        continue
    }

    # Build DisplayName: MedDefense-<src_zone>-<proto>-<dport>
    $protoUpper = $flow.proto.ToUpper()
    $displayName = "MedDefense-$($flow.src_zone)-$protoUpper-$($flow.dport)"

    # Create the firewall rule
    $params = @{
        DisplayName    = $displayName
        Direction      = "Inbound"
        Action         = "Allow"
        Protocol       = $flow.proto
        LocalPort      = [int]$flow.dport
        RemoteAddress  = $sourceCidr
        Profile        = "Any"
        Description    = $flow.justification
    }

    try {
        New-NetFirewallRule @params -ErrorAction Stop | Out-Null
        $ruleCount++

        $statusLine = "Inbound Allow $($flow.proto) $($flow.dport)   [CREATED]"
        Write-Host ("  {0,-30} {1}" -f $displayName, $statusLine)

        $createdRules += @{
            display_name   = $displayName
            direction      = "Inbound"
            action         = "Allow"
            protocol       = $flow.proto
            local_port     = [int]$flow.dport
            remote_address = $sourceCidr
            src_zone       = $flow.src_zone
            dst_zone       = $flow.dst_zone
            profile        = "Any"
            justification  = $flow.justification
        }
    }
    catch {
        Write-Host ("  {0,-30} [FAILED: {1}]" -f $displayName, $_.Exception.Message) -ForegroundColor Red
    }
}

# ---------------------------------------------------------------
# Export the resulting rules as JSON evidence for downstream comparison
# ---------------------------------------------------------------
Write-Host "[*] Exporting evidence to $OutputJson..."

$generatedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

$evidence = @{
    generated_at       = $generatedAt
    hostname            = $env:COMPUTERNAME
    local_zone          = $localZone
    segmentation_source = "segmentation_rules.json"
    profile_settings    = $profileSettings
    rules_removed       = $removedCount
    rules_created       = $createdRules
    summary = @{
        total_flows     = $config.flows.Count
        allow_flows     = ($config.flows | Where-Object { $_.action -eq "allow" }).Count
        deny_flows      = ($config.flows | Where-Object { $_.action -eq "deny_all" }).Count
        rules_created   = $ruleCount
        rules_removed   = $removedCount
    }
}

$evidenceJson = $evidence | ConvertTo-Json -Depth 10
Set-Content -Path $OutputJson -Value $evidenceJson -Encoding UTF8

Write-Host ""
Write-Host "[*] Windows Firewall alignment complete."
Write-Host "    Local zone:   $localZone"
Write-Host "    Rules created: $ruleCount"
Write-Host "    Rules removed: $removedCount"
Write-Host "    Evidence JSON: $OutputJson"
