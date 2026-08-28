# Name: windows_firewall_alignment.ps1
# Purpose: Align Windows Firewall to the same segmentation contract as nftables on Hawthorne-App-01
# Author: Steve - Cybersecurity Engineer
# Date: 21 August 2026

Set-StrictMode -Version Latest

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

Get-NetFirewallRule -DisplayName "MedDefense-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName "MedDefense-SSH-Management" -Direction Inbound -Protocol TCP -LocalPort 22 -RemoteAddress 192.168.10.0/24 -Action Allow
New-NetFirewallRule -DisplayName "MedDefense-HTTP-Public" -Direction Inbound -Protocol TCP -LocalPort 80 -RemoteAddress Any -Action Allow
New-NetFirewallRule -DisplayName "MedDefense-HTTPS-Public" -Direction Inbound -Protocol TCP -LocalPort 443 -RemoteAddress Any -Action Allow
New-NetFirewallRule -DisplayName "MedDefense-MySQL-AppNetwork" -Direction Inbound -Protocol TCP -LocalPort 3306 -RemoteAddress 10.10.2.0/24 -Action Allow

$blockedPorts = @(
    @{Port=23;  Proto="TCP"; Name="Telnet"},
    @{Port=21;  Proto="TCP"; Name="FTP"},
    @{Port=513; Proto="TCP"; Name="Rlogin"},
    @{Port=514; Proto="TCP"; Name="RSH"},
    @{Port=2049;Proto="TCP"; Name="NFS"},
    @{Port=111; Proto="TCP"; Name="RPCBind"},
    @{Port=445; Proto="TCP"; Name="SMB"},
    @{Port=161; Proto="UDP"; Name="SNMP"}
)

foreach ($rule in $blockedPorts) {
    New-NetFirewallRule -DisplayName "MedDefense-Block-$($rule.Name)" -Direction Inbound -Protocol $rule.Proto -LocalPort $rule.Port -RemoteAddress Any -Action Block
}

Write-Output "Windows Firewall aligned to MedDefense segmentation contract for Hawthorne-App-01."
