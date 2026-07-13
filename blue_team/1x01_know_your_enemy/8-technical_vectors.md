# Technical Attack Vector Assessment
## MedDefense Health Systems – Non-Human Attack Vectors

**Date:** July 13, 2026  
**Classification:** CONFIDENTIAL – TECHNICAL ASSESSMENT  
**References:** Project 1x00 Network Scan Summary, Asset Registry, Control Matrix, Gap Analysis  

---

## Vector 1: Vulnerable Software

| Field | Assessment |
|-------|------------|
| **Vector Category** | Vulnerable Software |
| **MedDefense Evidence** | Apache 2.4.29 running on `billing-srv-01` and `web-srv-01` with known remote code execution vulnerabilities (CVE-2021-41773, CVE-2021-42013). Ubuntu 18.04 LTS reached End-of-Life in April 2023, no longer receiving security updates. Both servers have been identified as exploitable via automated vulnerability scanners across the internet. |
| **Affected Asset(s)** | `billing-srv-01`, `web-srv-01`, any other systems running unpatched software versions |
| **Actor Most Likely to Exploit** | Unskilled/Opportunistic Attacker (automated scanning), Ransomware Groups (manual exploitation after initial access) |
| **Exploitation Scenario** | An attacker runs an automated vulnerability scanner against MedDefense's public IP range and identifies the Apache 2.4.29 instance on `web-srv-01`. Using the publicly available PoC exploit for CVE-2021-41773, they execute arbitrary code and establish a reverse shell. From there, they move laterally across the flat network to deploy ransomware. The billing-srv-01 cryptominer is proof this vector is already active. |
| **Current Protection** | C-001 (Network Firewall) — FortiGate 100F provides perimeter filtering but does not inspect encrypted traffic or block exploit payloads at the application layer. C-002 (DMZ Segmentation) — weak enforcement allows outbound connections to internal systems. |
| **Gap Reference** | **GAP-008** (Apache 2.4.29 Vulnerability — exploited twice), **GAP-010** (No Vulnerability Management Program) |

---

## Vector 2: Unsupported Systems

| Field | Assessment |
|-------|------------|
| **Vector Category** | Unsupported Systems |
| **MedDefense Evidence** | Windows XP workstation connected to the MRI scanner (EOL since April 2014, no patches for over a decade). Windows Server 2012 R2 on `print-srv-01` (EOL since October 2023, no security patches for over two years). Both systems run services that are unpatched for critical vulnerabilities like EternalBlue (MS17-010), PrintNightmare (CVE-2021-34527), and numerous SMB/RPC exploits. |
| **Affected Asset(s)** | `MRI-WORKSTATION` (Windows XP), `print-srv-01` (Windows Server 2012 R2) |
| **Actor Most Likely to Exploit** | Ransomware Groups (lateral movement), Unskilled/Opportunistic Attacker (automated exploits), Insider Threat (local access) |
| **Exploitation Scenario** | An attacker who gains any foothold on the internal network (e.g., through phishing on a workstation) scans for Windows XP systems and identifies the MRI workstation. They exploit an unpatched SMB vulnerability to gain remote code execution with SYSTEM privileges. Because the system cannot be patched, the compromise is permanent — the attacker can maintain persistence indefinitely without fear of patch-based remediation. The print server presents the same problem for lateral movement to any connected printer queue. |
| **Current Protection** | None documented. No network segmentation isolates these legacy systems from general IT traffic. No virtual patching or intrusion prevention signatures deployed. |
| **Gap Reference** | **GAP-001** (Flat Network — legacy systems directly accessible), **GAP-010** (No Vulnerability Management — legacy systems never inventoried for EOL status), **GAP-012** (Endpoint Protection Gaps — no modern AV on legacy systems) |

---

## Vector 3: Open Service Ports

| Field | Assessment |
|-------|------------|
| **Vector Category** | Open Service Ports |
| **MedDefense Evidence** | MySQL (port 3306) on `billing-srv-01` is accessible network-wide rather than restricted to the application server. PostgreSQL (port 5432) on `ehr-db-01` is similarly exposed to all 10.10.0.0/16 subnets. RDP (port 3389) is enabled on multiple workstations without MFA. Medical IoT devices have HTTP management interfaces listening on various ports with no firewall rules restricting access. |
| **Affected Asset(s)** | `billing-srv-01`, `ehr-db-01`, 120 BD Alaris pumps, 80 Philips monitors, all workstations with RDP enabled |
| **Actor Most Likely to Exploit** | Ransomware Groups (database credential theft), Insider Threat (data exfiltration), Nation-State APT (data theft via database queries) |
| **Exploitation Scenario** | An attacker who obtains domain credentials (through phishing, brute-force, or vendor account compromise) scans the network and identifies the PostgreSQL service on port 5432. Using stolen database credentials or SQL injection through a vulnerable web application, they authenticate to the EHR database and begin bulk data exfiltration. Because there are no network ACLs restricting database access, the attacker can query 50,000 patient records in minutes without triggering any alerts. |
| **Current Protection** | C-001 (Network Firewall) — configured for perimeter filtering only, no internal traffic inspection. C-005 (Access Control Lists) — not documented or implemented for database ports. |
| **Gap Reference** | **GAP-001** (Flat Network — databases reachable from any compromised host), **GAP-015** (DMZ Misconfiguration — outbound from DMZ to database ports permitted), **GAP-016** (No DLP — exfiltration undetected) |

---

## Vector 4: Default Credentials

| Field | Assessment |
|-------|------------|
| **Vector Category** | Default Credentials |
| **MedDefense Evidence** | PACS workstation uses shared account "raduser/radiology1" with static password shared across 15 radiology techs. BD Alaris infusion pump management interfaces use vendor-default admin/admin credentials. Medical device web interfaces on Philips monitors have not had default credentials changed. Dr. Patel's personal NAS has default credentials (unencrypted, unmanaged). |
| **Affected Asset(s)** | PACS Workstation (Radiology), 120 BD Alaris Pumps, 80 Philips Monitors, Dr. Patel's Personal NAS, any other vendor devices not audited |
| **Actor Most Likely to Exploit** | Unskilled/Opportunistic Attacker (scripted attacks), Ransomware Groups (lateral movement), Insider Threat (unauthorized access) |
| **Exploitation Scenario** | An attacker on the internal network (either from a phished workstation or compromised vendor session) discovers the BD Alaris pump management console by scanning for medical device ports. They log in with the well-documented default credentials (admin/admin) that were never changed from factory settings. From the pump console, they explore network connections and pivot to the clinical workstation network. The shared PACS account allows the attacker to access imaging data without attribution, masking their activity in the logs. |
| **Current Protection** | C-007 (Shared Account Management) exists but is not enforced for Radiology department. No automated password auditing tool deployed to detect default credentials on medical devices. |
| **Gap Reference** | **GAP-007** (Medical Device Network Exposure — default credentials on 200+ devices), **GAP-003** (No Centralized Log Management — shared account activity indistinguishable from legitimate use) |

---

## Vector 5: Unsecure Networks

| Field | Assessment |
|-------|------------|
| **Vector Category** | Unsecure Networks |
| **MedDefense Evidence** | Entire MedDefense network operates as flat 10.10.0.0/16 broadcast domain with no VLANs, no internal firewalls, and no zone separation. Westside Clinic uses consumer-grade Netgear Nighthawk router with no firewall rules, connected via site-to-site VPN to Central headquarters. WiFi network segmentation between guest and corporate networks not verified; Bluetooth connectivity on clinical devices creates wireless attack surface. |
| **Affected Asset(s)** | Entire MedDefense network (~2,000 workstations, 12 servers, 200 medical devices), Westside Clinic network (10.10.10.0/24), all wireless endpoints |
| **Actor Most Likely to Exploit** | All actors — especially Ransomware Groups (lateral movement), Opportunistic Attackers (automated scanning), Insider Threat (internal access) |
| **Exploitation Scenario** | An attacker compromises a single workstation via phishing (or gains access through the unsecured Westside VPN connection). Because the network is flat, they immediately have Layer 2 visibility to all devices on the broadcast domain. They scan the network using tools like BloodHound and nmap, identify domain controllers, database servers, and medical devices within minutes. They then pivot from workstation to server to database without encountering any network-based controls. The Westside router provides a second entry point that bypasses the central FortiGate entirely. |
| **Current Protection** | C-002 (DMZ Segmentation) — only applies to external perimeter, no internal segmentation. C-019 (Wireless Security Policy) — policy exists but enforcement on clinical devices unknown. |
| **Gap Reference** | **GAP-001** (Flat Network Architecture — critical risk amplifier), **GAP-009** (Shadow IT / Undocumented Devices — Westside router unknown to security team), **GAP-011** (Physical Security — server rooms unlocked, enabling unauthorized network access) |

---

## Vector 6: Removable Devices / Unmanaged Endpoints

| Field | Assessment |
|-------|------------|
| **Vector Category** | Removable Devices |
| **MedDefense Evidence** | No Group Policy Object (GPO) disabling USB storage on workstations. Clinical iPads lack Mobile Device Management (MDM) enrollment, meaning stolen devices can access O365 without wipe capability. Shadow IT devices (Dr. Patel's NAS, personal laptops connected to office ports) exist on the network without IT awareness. |
| **Affected Asset(s)** | All ~2,000 workstations, clinical iPads, personal devices connected by staff |
| **Actor Most Likely to Exploit** | Insider Threat (data exfiltration via USB), Opportunistic Attacker (malware introduction via infected thumb drives), Malicious Insider (shadow IT for data storage) |
| **Exploitation Scenario** | A disgruntled employee or malicious insider copies 3,000 patient records from the EHR onto a USB thumb drive and removes them from the facility. Because no GPO restricts USB storage, the transfer completes without any logging or blocking. Alternatively, an attacker places an infected USB drive in the parking lot (social engineering bait); a curious employee plugs it in, and malware executes on the workstation. Without MDM, stolen iPads provide direct access to O365 and OneDrive from any internet-connected device. |
| **Current Protection** | C-006 (Password Policy) — does not address removable media. C-019 (Wireless Security Policy) — mentions BYOD but lacks enforcement mechanism. No DLP solution monitors file copy operations. |
| **Gap Reference** | **GAP-012** (Endpoint Protection Gaps — no MDM for mobile devices), **GAP-016** (No DLP — removable media exfiltration undetected), **GAP-009** (Shadow IT — unmanaged devices on network) |

---

## Summary Table

| Vector Category | Primary Gap ID | Actor Likelihood | Risk Severity |
|-----------------|----------------|------------------|---------------|
| Vulnerable Software | GAP-008, GAP-010 | Critical (Already Active) | Critical |
| Unsupported Systems | GAP-001, GAP-010, GAP-012 | High | Critical |
| Open Service Ports | GAP-001, GAP-015, GAP-016 | High | Critical |
| Default Credentials | GAP-007, GAP-003 | High | Critical |
| Unsecure Networks | GAP-001, GAP-009, GAP-011 | Critical | Critical |
| Removable Devices | GAP-012, GAP-016, GAP-009 | Medium | High |

---

## Vector Assessment Conclusion

Every technical vector category documented in the Sec+ 2.2 framework exists within MedDefense's environment with no effective protective controls. The flat network architecture (GAP-001) acts as a force multiplier for all vectors, meaning a successful exploit in any category grants unrestricted access to the entire organization. The billing-srv-01 cryptominer demonstrates that vulnerable software and open ports are not theoretical risks — they are active, exploited attack paths. Supporting evidence from three real-world healthcare breaches confirms that these same vectors caused catastrophic compromises at comparable organizations in the past 24 months. Prioritizing remediation of GAP-001 (Segmentation), GAP-008 (Apache RCE), GAP-010 (Vulnerability Management), and GAP-007 (Default Credentials) addresses the highest-risk vectors with the most immediate impact.
