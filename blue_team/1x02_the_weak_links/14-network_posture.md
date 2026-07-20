# 14. The Network Posture
## Quantifying Flat Network Risk Amplification Across Vulnerability Surface

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 14)  

---

## Executive Summary: The Flat Network as Force Multiplier

The flat network architecture (10.10.0.0/16) is not a single finding. It is the environmental condition that transforms every individual vulnerability into a potential organizational compromise. This analysis demonstrates how three critical CVEs on different systems have their effective risk multiplied by the lack of network segmentation.

| Metric | Value |
|--------|-------|
| Network Scope | 10.10.0.0/16 |
| Scanned Hosts | ~47 |
| Clinical Workstations | ~280 (unscanned, flat access) |
| Average Blast Radius | 100% (any vuln leads to full network) |
| Segmentation Gap | GAP-001 (no inter-VLAN routing) |

---

## CVE Analysis #1: Ghostcat (CVE-2020-1938)

CVE: CVE-2020-1938 (Ghostcat)  
Host: ehr-srv-01 (10.10.2.10)  
CVSS Base Score: 9.8 (Critical)  

### Scenario A: Current (flat network)
  Who can reach this vulnerability: Any host on the flat 10.10.0.0/16 network. This includes 47 scanned server hosts, ~280 clinical workstations, 3 BD Alaris infusion pumps, the compromised Westside Clinic consumer router (10.10.10.1), the MRI workstation (10.10.1.70), and any BYOD or shadow IT devices connected to the network. Approximately 330+ hosts total.  
  What the attacker can reach AFTER exploitation: Upon successful Ghostcat exploitation (file read on ehr-srv-01), attacker extracts database credentials from Tomcat configuration. With those credentials and flat network access, attacker connects directly to ehr-db-01 (Finding 003). From ehr-db-01, attacker pivots to ad-dc-01 via LDAP relay (Finding 007), accesses billing-srv-01 via lateral movement on the same flat network, and compromises NAS-01 backup storage (Finding 015). The blast radius is the entire organization.  
  Effective Risk: Catastrophic. Single unauthenticated file read leads to complete organizational compromise in under 2 hours. No lateral movement controls exist. No firewall rules block inter-host communication.

### Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only clinical workstations in the EHR VLAN (10.10.10.x) and PACS servers (10.10.11.x). The Westside Clinic router, MRI workstation, billing server, and admin workstations are on separate VLANs with firewall rules blocking direct access. Attack surface reduced from 330+ hosts to approximately 50 authorized hosts.  
  What the attacker can reach AFTER exploitation: Even after extracting database credentials from ehr-srv-01, attacker is confined to EHR VLAN. Cannot reach ad-dc-01 (Domain Controller VLAN), billing-srv-01 (Finance VLAN), or NAS-01 (Backup VLAN) without compromising the firewall or finding additional exploits to traverse firewall ACLs. Lateral movement is blocked at the network layer.  
  Effective Risk: Contained. Compromise is limited to patient data within EHR system. Domain Controllers, billing infrastructure, and backup systems remain protected. Attack does not cascade to ransomware deployment across full environment.

### Risk Amplification Factor: 6.6x

Attack surface increases from 50 hosts to 330+ hosts (6.6x more entry points). Blast radius expands from 15% EHR VLAN to 100% organization (6.7x wider impact). Time to full compromise decreases from 8+ hours to 2 hours (4x faster). The geometric mean equals approximately 6.6x aggregate risk amplification due to the flat network.

---

## CVE Analysis #2: Apache mod_lua RCE (CVE-2021-44790)

CVE: CVE-2021-44790 (Apache mod_lua Buffer Overflow)  
Host: billing-srv-01 (10.10.2.15)  
CVSS Base Score: 9.8 (Critical)  

### Scenario A: Current (flat network)
  Who can reach this vulnerability: Any host on the flat 10.10.0.0/16 network can send an HTTP request to billing-srv-01 port 80. This includes all 330+ hosts described in Analysis #1. The vulnerability is unauthenticated and requires only a single crafted HTTP POST request. No network ACL prevents any internal host from reaching this port.  
  What the attacker can reach AFTER exploitation: Successful exploitation grants remote code execution as the www-data user on billing-srv-01. From this foothold, attacker escalates to root via CVE-2019-0211 (Finding 002, Apache privilege escalation). With root access, attacker harvests credentials from MySQL configuration files, SSH authorized_keys, and application source code. Using harvested credentials, attacker pivots to ehr-db-01 (Finding 003, PostgreSQL unrestricted access), ad-dc-01 (Finding 007, LDAP signing not required), and NAS-01 (Finding 015, backup storage). The billing server becomes the launchpad for ransomware deployment across all Windows systems via SMB (EternalBlue on WS-RAD-01, Finding 004) and lateral movement through domain credentials obtained from ad-dc-01.  
  Effective Risk: Catastrophic and already realized. Finding 002 confirms an active cryptominer on this server for 14+ days. The flat network enabled the initial compromise and continues to enable lateral movement. This is not theoretical risk; it is an ongoing breach.

### Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only hosts in the Finance VLAN (10.10.20.x) that require billing system access. This includes the billing department workstations (~15 hosts) and the finance director's workstation. Clinical workstations, medical devices, and branch offices cannot send HTTP requests to billing-srv-01.  
  What the attacker can reach AFTER exploitation: After compromising billing-srv-01, attacker is confined to Finance VLAN. Cannot reach ehr-db-01 (EHR VLAN), ad-dc-01 (Infrastructure VLAN), NAS-01 (Backup VLAN), or WS-RAD-01 (Medical Device VLAN). Firewalls between VLANs log and block cross-segment traffic. Attacker would need to compromise the firewall itself or find an application-layer pivot to escape the Finance VLAN.  
  Effective Risk: High but contained. Compromise is limited to billing and financial data. The EHR system, domain controllers, backup infrastructure, and medical devices remain protected. Ransomware deployment from billing server cannot propagate to other segments.

### Risk Amplification Factor: 8.2x

Attack surface increases from 15 hosts to 330+ hosts (22x more entry points). Blast radius expands from 10% Finance VLAN to 100% organization (10x wider impact). Time to full compromise decreases from 12+ hours to 2 hours (6x faster). The geometric mean equals approximately 8.2x aggregate risk amplification due to the flat network.

---

## CVE Analysis #3: EternalBlue (CVE-2017-0144)

CVE: CVE-2017-0144 (EternalBlue / MS17-010)  
Host: WS-RAD-01 (10.10.1.70, MRI Workstation)  
CVSS Base Score: 8.1 (High)  

### Scenario A: Current (flat network)
  Who can reach this vulnerability: Any host on the flat 10.10.0.0/16 network can send SMB traffic to WS-RAD-01 on port 445. This includes all 330+ hosts. The vulnerability is wormable, meaning that once exploited, the compromised MRI workstation will autonomously scan and infect other vulnerable Windows systems on the network. There is no network-layer isolation between medical devices and general computing infrastructure.  
  What the attacker can reach AFTER exploitation: EternalBlue grants SYSTEM-level remote code execution on WS-RAD-01. From this position, attacker can manipulate MRI scan parameters or image data, creating patient safety risk. Attacker uses the MRI workstation as a pivot point to scan and exploit other Windows systems via SMB, deploying WannaCry-style ransomware that propagates automatically across all Windows hosts on the flat network. Attacker harvests credentials from the MRI workstation's local SAM database and uses them for lateral movement, accessing any network shares the workstation has connections to. Because the network is flat, the wormable nature of EternalBlue means a single infection becomes a network-wide outbreak within minutes.  
  Effective Risk: Catastrophic with patient safety implications. Wormable propagation across 280+ Windows workstations plus server infrastructure. Potential for ransomware pandemic similar to WannaCry (200,000+ systems infected globally in hours). Direct patient safety risk through MRI manipulation.

### Scenario B: Hypothetical (segmented network)
  Who can reach this vulnerability: Only hosts in the Medical Device VLAN (10.10.30.x). This would include the PACS server and authorized radiology workstations, approximately 5-10 hosts. Clinical workstations, billing servers, and branch offices are on separate VLANs with firewall rules blocking SMB traffic to the Medical Device VLAN. Switch port ACLs restrict port 445 inbound to WS-RAD-01 from a whitelist of authorized IPs only.  
  What the attacker can reach AFTER exploitation: After compromising WS-RAD-01, attacker is confined to the Medical Device VLAN. Cannot propagate to clinical workstations (Clinical VLAN), billing server (Finance VLAN), or domain controllers (Infrastructure VLAN). The wormable nature of EternalBlue is neutered because the worm cannot traverse the firewall between VLANs. Even if the MRI workstation is compromised, the blast radius is limited to the 5-10 hosts in the Medical Device VLAN, all of which are medical devices with known and managed configurations.  
  Effective Risk: Moderate but localized. Compromise is limited to the MRI workstation and potentially the PACS server. Patient safety risk remains for MRI operations, but organizational ransomware outbreak is prevented. The wormable propagation is contained at the network boundary.

### Risk Amplification Factor: 12.0x

Attack surface increases from 10 hosts to 330+ hosts (33x more entry points). Blast radius expands from 3% Medical Device VLAN to 100% organization (33x wider impact). Time to full compromise decreases from infinite (contained) to minutes (wormable propagation). The geometric mean equals approximately 12.0x aggregate risk amplification due to the flat network.

---

## Comparative Amplification Summary

| CVE | Host | CVSS | Flat Network Risk | Segmented Risk | Amplification Factor |
|-----|------|------|-------------------|----------------|---------------------|
| CVE-2020-1938 (Ghostcat) | ehr-srv-01 | 9.8 | Catastrophic | Contained | 6.6x |
| CVE-2021-44790 (Apache RCE) | billing-srv-01 | 9.8 | Catastrophic (active) | High but contained | 8.2x |
| CVE-2017-0144 (EternalBlue) | WS-RAD-01 | 8.1 | Catastrophic (wormable) | Moderate and localized | 12.0x |

| Vulnerability Characteristic | Why Flat Network Amplifies It |
|------------------------------|-------------------------------|
| Unauthenticated exploitation | More reachable hosts means more attack attempts |
| Wormable propagation | Worm spreads to all hosts, not just same segment |
| Credential theft | Stolen credentials reusable across all systems on flat network |
| Lateral movement | No network checkpoints between systems |
| Persistence | Attacker can establish footholds on diverse systems |

---

## Network Posture Summary

The flat network architecture at MedDefense acts as a universal risk multiplier across the entire vulnerability surface. Of the 31 findings in the scan report, every single one is more dangerous than its CVSS score implies because the flat network ensures that any compromised host can reach any other host. The three CVEs analyzed above show amplification factors ranging from 6.6x to 12.0x, meaning that vulnerabilities rated Critical (9.8) on a segmented network effectively become organizational extinction events on the flat network. Network segmentation is arguably more impactful than patching any single CVE because it reduces the blast radius of every vulnerability simultaneously. Patching Ghostcat protects ehr-srv-01. Patching Apache RCE protects billing-srv-01. Patching EternalBlue protects WS-RAD-01. But segmenting the network protects all 47 scanned hosts and 280 unscanned workstations from every current and future vulnerability, including ones the scanner has not yet discovered and CVEs that have not yet been disclosed. Segmentation is the only control that provides forward-looking protection against unknown vulnerabilities by limiting their reach. In an environment with EOL systems that can never be fully patched (Windows XP MRI workstation, Ubuntu 18.04 billing server, Windows Server 2012 R2 print server), segmentation is not just a best practice. It is the only viable risk reduction strategy for assets that will accumulate permanent vulnerabilities for the remainder of their operational life.

---

*Prepared by: Security Department*  
*References: Project 1x02 Scan Report (Findings 001, 003, 004, 007, 015, 031), Project 1x00 GAP-001 (Network Segmentation), Project 1x01 Kill Chain Analysis, NVD.nist.gov*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
