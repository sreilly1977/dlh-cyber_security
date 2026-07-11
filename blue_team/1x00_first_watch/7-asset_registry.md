# MedDefense Health Systems -- Complete Asset Registry
## Consolidated from All Sources (Tasks 0-7)

---

## Asset Registry

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|--------------|-------------|-------------------|-----------------|--------|-------|
| A-001 | ehr-srv-01 | Server | Central, Basement Server Room | IT / Clinical | Ubuntu 20.04 LTS | EHR Application Server | 10.10.2.10 (Servers) | Active | PostgreSQL DB accessible from entire network; SSH key auth configured |
| A-002 | ehr-db-01 | Server | Central, Basement Server Room | IT / Clinical | Ubuntu 20.04 LTS | EHR Database (PostgreSQL) | 10.10.2.11 (Servers) | Active | DB port 5432 accessible from entire 10.10.0.0/16; critical PHI storage |
| A-003 | pacs-srv-01 | Server | Central, Basement Server Room | Radiology | Windows Server 2016 | PACS Imaging Server | 10.10.2.12 (Servers) | Active | Shared account access ("raduser"); images not backed up |
| A-004 | billing-srv-01 | Server | Central, Basement Server Room | Finance | Ubuntu 18.04 LTS | Billing/Claims Processing | 10.10.2.15 (Servers) | Active | Compromised twice (Jan ransomware, current cryptominer); MySQL port exposed |
| A-005 | ad-dc-01 | Server | Central, Basement Server Room | IT Admin | Windows Server 2019 | Primary Domain Controller | 10.10.2.20 (Servers) | Active | LDAP/Kerberos; all Windows systems authenticate here |
| A-006 | ad-dc-02 | Server | Central, Basement Server Room | IT Admin | Windows Server 2019 | Secondary Domain Controller | 10.10.2.21 (Servers) | Active | Not in Veeam backup scope per Artifact 5 |
| A-007 | file-srv-01 | Server | Central, Basement Server Room | IT Admin | Windows Server 2016 | Department File Shares | 10.10.2.30 (Servers) | Active | Mixed PHI/Internal data; tested recovery 6 hours for single server |
| A-008 | print-srv-01 | Server | Central, Basement Server Room | IT Admin | Windows Server 2012 R2 | Print Server | 10.10.2.31 (Servers) | Active | **EOL Oct 2023**; unverified per artifact 2 but present in scan |
| A-009 | backup-srv-01 | Server | Central, Basement Server Room | IT Admin | Ubuntu 22.04 LTS | Backup Server (Veeam agent) | 10.10.2.40 (Servers) | Active | Backs up to NAS-01 in same rack/network |
| A-010 | NAS-01 | Data Store | Central, Basement Server Room | IT Admin | Synology DSM 7 | Veeam Backup Target | 10.10.2.41 (Servers) | Active | Management port 5000/5001 accessible from entire network; 14-day retention |
| A-011 | web-srv-01 | Server | Central, DMZ | IT Marketing | Ubuntu 20.04 LTS | Public Website + Patient Portal | 10.10.2.50 (DMZ) | Active | Previously defaced (Incident D); Apache 2.4.29 vulnerability suspected |
| A-012 | ws-srv-01 | Server | Westside Clinic Server Closet | IT Admin | Windows Server 2016 | Local File Server + Scheduling | 10.10.10.10 (Westside) | Active | Not backed up to central Veeam; no firewall protection |
| A-013 | UNKNOWN-01 | Shadow IT | Central, Basement Server Room | Unknown | Linux 4.x | Unknown Web Services | 10.10.2.99 (Servers) | Shadow IT | No hostname in DNS; SSH + ports 8888/9090; Sarah has no documentation |
| A-014 | WS-RAD-01 | IoT Medical / Endpoint | Central, Radiology | Radiology | **Windows XP SP3** | MRI Control Workstation | 10.10.1.70 (Workstations) | Active | **EOL since 2014**; connected to PACS; cannot be patched/upgraded |
| A-015 | MRI Scanner | IoT Medical | Central, Radiology | Radiology | Proprietary (Windows-based) | Imaging Study Production | 10.10.3.60 (Medical) | Active | Siemens MAGNETOM; $2.1M cost; 6/12 year lifespan; vendor-certified only on XP |
| A-016 | MON-VITALS-3F-01 | IoT Medical | Central, 3rd Floor Nursing | Nursing | Unknown Vendor | Vital Signs Monitoring | 10.10.3.47 (Medical) | Active | Firmware v2.1.3 (last updated 2019); IP/firmware displayed on screen |
| A-017 | Philips IntelliVue Monitors (80 units) | IoT Medical | Central (ICU, ER, Floors) | Nursing / Clinical | Proprietary Firmware | Patient Vital Monitoring | 10.10.3.0/24 (Medical) | Active | HTTP/HTTPS management accessible network-wide; 2575 port exposed |
| A-018 | BD Alaris Infusion Pumps (120 units) | IoT Medical | Central (ICU, ER, Floors) | Nursing / Clinical | Firmware 12.1.2 | Medication Delivery | 10.10.3.0/24 (Medical) | Active | Known CVEs (vendor bulletin 18mo ago); dosage network-updatable |
| A-019 | NURSE-CALL-01/02 | IoT Medical | Central, All Floors | Nursing | IP-based System | Nurse Call Integration | 10.10.3.50/51 (Medical) | Active | SIP port 5060; integrated with phone system |
| A-020 | BADGE-READER-MAIN/SVR/ER | Physical Infrastructure | Central (Main/ER entrances) | Facilities | HID Global | Access Control Integration | 10.10.3.60/61/62 (Medical) | Active | Connected to Active Directory; generic badge for all employees |
| A-021 | FortiGate 100F | Network Device | Central, Basement Server Room | IT Network | FortiOS | Perimeter Firewall | 10.10.0.1 (Gateway) | Active | Rules 2-3 allow ALL services from VPN; no egress filtering (Rule 4) |
| A-022 | Cisco Core Switch | Network Device | Central, Basement Server Room | IT Network | IOS | Network Backbone | 10.10.0.1 (Gateway) | Active | Model unknown; Marcus notes flat network, no VLANs |
| A-023 | Netgear Nighthawk Router | Network Device | Westside Clinic | IT Network | Netgear Firmware | Site-to-Site VPN Endpoint | 10.10.10.1 (Westside Gateway) | Active | Consumer-grade; handles VPN to Central; Marcus flagged as unacceptable |
| A-024 | Ubiquiti UniFi APs (12+ units) | Network Device | Central (All floors) | IT Network | UniFi OS | Wireless Access Points | 10.10.1.200-211 (Workstations) | Active | Guest WiFi isolation unverified; 22/443 exposed |
| A-025 | WS-RECEPTION-01/02 | Endpoint | Central, Reception Desk | Reception | Windows 10 (19045) | Patient Check-in Terminal | 10.10.1.10/11 (Workstations) | Active | RDP enabled (3389); Adware.Generic detected 20 days ago |
| A-026 | WS-ADMIN-03 | Endpoint | Central, Admin Wing | Administration | Windows 10 (19045) | Admin Workstation | 10.10.1.52 (Workstations) | Active | Phish.URL blocked 8 days ago; RDP enabled |
| A-027 | WS-NURSE-3F-07 | Endpoint | Central, 3rd Floor Nursing | Nursing | Windows 10 (19045) | Clinical Workstation | 10.10.1.41-42 (Workstations) | Active | Trojan.GenericKD quarantined 3 days ago |
| A-028 | WS-PHARM-01/02 | Endpoint | Central, Pharmacy | Pharmacy | Windows 10 (19045) | Medication Management Terminal | 10.10.1.60/61 (Workstations) | Active | CryptoMiner PUA blocked 15 days ago (WS-FIN-12 similar) |
| A-029 | TC-ER-01-04 | Endpoint | Central, Emergency Dept | Emergency | Linux (thin client) | Emergency Room Display | 10.10.1.100-103 (Workstations) | Active | SSH port exposed; ~60 thin clients total per documentation |
| A-030 | LAPTOP-HQ-01-25 | Endpoint | Corporate HQ / Remote | Various | Windows 11 | Mobile Workstations | 10.10.20.200-225 (HQ) | Active | Intermittent presence; ~30 total; remote-capable |
| A-031 | iPad Physician Tablets (~25 units) | Endpoint | Central (Rounds) | Clinical/Medicine | iPadOS | Physician Rounds Access | Unknown (possibly WiFi) | Unknown | MDM status unclear; not in Sophos scope; not in network scan |
| A-032 | WS-WC-XRAY | IoT Medical | Westside Clinic | Radiology | Vendor-specific | X-ray Workstation | 10.10.10.100 (Westside) | Active | Port 4242 open; vendor-specific OS |
| A-033 | UNKNOWN-02 (Westside) | Shadow IT | Westside Clinic Server Closet | Unknown | Linux 5.x | Monitoring Tool (Grafana/Node.js?) | 10.10.10.200 (Westside) | Shadow IT | Port 3000 open; Sarah notes "someone plugged something in unofficially" |
| A-034 | WS-UNK-MARCUS | Shadow IT | Westside Clinic | Unknown | Unknown | Unknown Server | Unknown (Unconfirmed) | Unknown | Marcus's note: "might be another server in closet at Westside"; never confirmed |
| A-035 | CT Scanner (GE Revolution) | IoT Medical | Central, Radiology | Radiology | Unknown OS | Computed Tomography Imaging | 10.10.3.70 (Medical) | Active | OS unknown per Marcus notes; not in network scan; critical imaging device |
| A-036 | EHR Application | Application | All sites | Clinical | Web-based (PHP/Python?) | Electronic Health Records | N/A (runs on ehr-srv-01) | Active | Vendor-managed audit log (48hr export delay); PHI primary repository |
| A-037 | O365 E3 | Application | All sites | All Departments | SaaS Cloud | Email, SharePoint, OneDrive | Internet | Active | $432,000/year; NOT in Veeam backup scope per Artifact 5 |

---

## Reconciliation Notes

### A. Assets Found in Network Scan NOT in Documentation (Shadow IT / Undocumented)

| Asset | Evidence | Risk Implications |
|-------|----------|-------------------|
| **10.10.2.99 (UNKNOWN-01)** | Network scan shows Linux device with SSH + web services (ports 8888/9090). Sarah's note: "I have no idea what this is. Could be Marcus's or the intern's." Not in any IT documentation, asset list, or service inventory. | High risk — could be a backdoor, test server with weak security, or unauthorized application. Running web services on a server segment suggests potential attack surface. No accountability for patches, backups, or access control. |
| **10.10.10.200 (Westside Unknown)** | Network scan shows Linux device with ports 22/80/3000. Sarah's note: "Another mystery device. Someone at Westside plugged something in. Port 3000 is often Grafana or Node.js. Could be monitoring tool someone set up unofficially." | Medium-High risk — shadow IT on Westside network. If it's a Grafana instance, it may have database credentials or admin access. If it's a developer's test server, it could be vulnerable to SQL injection or remote code execution. No security controls applied. |
| **iPad Physician Tablets** | Mentioned in onboarding packet (~25 units) but **NOT** in network scan (no MDM, no asset tracking, possibly on guest WiFi). Sophos coverage explicitly excludes mobile devices. | Medium risk — patient data potentially accessible on unmanaged devices. No visibility into whether tablets are jailbroken, whether apps are approved, or whether data is cached locally. Potential PHI leak vector. |
| **Approx. 290 Additional Workstations** | Network scan notes: "Approximately 290 additional Windows workstations detected in this subnet but omitted for brevity." Documentation only lists ~320 Central, ~45 Westside, ~120 HQ (~485 total). Some discrepancy in counts. | Low-Medium risk — indicates incomplete asset inventory. If workstations aren't documented, they may not receive antivirus updates, patching, or security monitoring. |
| **Additional Medical Devices** | Network scan detected "~65 additional Philips monitors and ~110 additional BD Alaris pumps" beyond documented counts. Documentation says ~80 monitors, ~120 pumps. | Medium risk — undiscovered medical devices could have unknown vulnerabilities, outdated firmware, or misconfigurations. No asset owner accountable for them. |

---

### B. Assets in Documentation NOT in Network Scan (Decommissioned / Offline / Different Network)

| Asset | Documentation Reference | Possible Explanations |
|-------|------------------------|----------------------|
| **WS-UNK-MARCUS (Westside unconfirmed server)** | Onboarding packet: Marcus's note "There might be another server in the closet at Westside. Mike Torres mentioned it but I never confirmed." | Likely never existed or was decommissioned before the scan. Marked as "unconfirmed" in asset list, so not necessarily expected in scan. |
| **CT Scanner (GE Revolution)** | Onboarding packet: "CT scanner: 1x GE Revolution (Central) -- unknown OS". Marcus notes CT exists but OS is unknown. | May not have been discovered during scan because: (a) proprietary protocol not responding to standard Nmap probes; (b) physically disconnected; (c) on a different network segment (unlikely given flat architecture). OS unknown increases risk. |
| **~15 Non-Reporting Sophos Devices** | Sophos report: "Devices not reporting: 15 (3.9%)" including "Offline >30 days: 7" | These devices are documented in asset inventory but were unreachable during scan window. May be powered off, decommissioned, or have Sophos disabled. 7 devices offline >30 days should be investigated for decommissioning or theft. |
| **Guest WiFi Infrastructure** | Marcus's notes: "Guest WiFi at Central DOES exist (separate SSID) but I'm not convinced it's actually isolated." | Guest WiFi SSID not visible in scan (expected if properly isolated), but if isolation is broken as Marcus suspected, guest network devices could be scanning the internal network. Lack of guest network devices in scan doesn't prove isolation. |

---

### C. Discrepancies and Contradictions Between Sources

| Issue | Source A | Source B | Resolution Required |
|-------|----------|----------|---------------------|
| **Westside Server Closet Security** | Onboarding packet (Artifacts): "Westside has basically zero physical security for IT equipment. The 'server closet' doesn't lock." | Network scan: Two undocumented devices found on Westside network (10.10.10.1 and 10.10.10.200). | Confirms physical insecurity — anyone could plug in devices. Need to verify who owns 10.10.10.200 and secure the closet. |
| **Print Server Existence** | Onboarding packet (Artifact 2): print-srv-01 listed as "[UNVERIFIED]" and "Nobody seems to care." | Network scan: 10.10.2.31 print-srv-01 detected, Windows Server 2012, ports 135/139/445/9100. | Server exists and is active despite being marked unverified. Still running EOL OS (Server 2012 R2). Update asset status to Active, prioritize replacement. |
| **Network Segmentation Status** | Marcus's notes (onboarding): "Flat network at Central. Medical devices, workstations, servers all on the same broadcast domain (10.10.0.0/16)." | Network scan Notes: "During scanning, all subnets were reachable from the scan host (Sarah's workstation at HQ, 10.10.20.10) without any access restrictions. This confirms... no network segmentation is enforced." | Both sources agree — no segmentation exists. Scan validates Marcus's assessment. Requires immediate VLAN/firewall implementation. |
| **Linux Server Endpoint Protection** | Onboarding packet (Artifact 4): "Linux servers: 0 (NOT covered -- not supported by current Sophos tier)." | Network scan: Multiple Linux systems detected (ehr-srv-01, ehr-db-01, backup-srv-01, web-srv-01, UNKNOWN-01, WS-WC-XRAY, 2 mystery devices). | Confirms zero endpoint protection on Linux systems. Cryptominer on billing-srv-01 (Ubuntu 18.04) demonstrates this gap's consequences. Critical remediation item. |
| **Backup Coverage** | Onboarding packet (Artifact 5): Lists excluded systems: PACS, ad-dc-02, print-srv-01, Westside server, medical device configs, O365. | Network scan: Confirms existence of all excluded systems (pacs-srv-01, ad-dc-02, print-srv-01, ws-srv-01, medical devices detected, O365 is SaaS). | All excluded systems confirmed active and unprotected by backup. Single-point-of-failure risk validated. |
| **Database Port Exposure** | Marcus's notes: "ehr-db-01: PostgreSQL is accessible from the entire 10.10.0.0/16 range. Should be restricted to ehr-srv-01 only." | Network scan: "PostgreSQL on ehr-db-01 (10.10.2.11:5432) is accessible from the entire internal network. Should be restricted to ehr-srv-01." | Both sources confirm database exposure. MySQL on billing-srv-01 (port 3306) also exposed. Both need firewall rules restricting access to application server only. |
| **RDP Exposure** | Marcus's notes: No specific mention of RDP configuration. | Network scan: "RDP (3389) is enabled on reception and admin workstations. No network-level restriction." Additionally visible in port listings for WS-RECEPTION-01/02, WS-ADMIN-01/02/03. | RDP enabled without network restrictions creates lateral movement path. Should be restricted via firewall or NLA enforcement. |
| **MRI Control Workstation** | Task 6: "MRI workstation runs Windows XP Embedded. Must communicate with PACS server." | Network scan: WS-RAD-01 detected at 10.10.1.70 running Windows XP SP3, flagged "** END OF LIFE **" by nmap. | Both sources confirm Windows XP on MRI workstation. Scan provides exact IP and version. Validates compensation control requirement from Task 6. |

---

## Summary Statistics

| Category | Count | Confirmed Active | Shadow IT/Undocumented | At-Risk (EOL/Unsupported) |
|----------|-------|------------------|------------------------|---------------------------|
| **Servers** | 12 | 12 | 1 (UNKNOWN-01) | 3 (print-srv-01, billing-srv-01, WS-RAD-01) |
| **Endpoints (Workstations)** | ~485 | ~460 | 0 | 1 (WS-RAD-01) |
| **Endpoints (Mobile)** | ~55 | Unknown | ~25 (iPads) | 0 |
| **IoT Medical Devices** | ~210 | ~205 | 0 | 3 (MRI, CT, vitals monitor) |
| **Network Devices** | 16 | 16 | 0 | 1 (Netgear consumer router) |
| **Applications** | 2 | 2 | 0 | 0 |
| **Physical Infrastructure** | 4 | 4 | 0 | 0 |
| **Shadow IT / Mystery** | 3 | N/A | 3 | 2 (both mystery Linux boxes) |
| **Total** | **~793** | **~699** | **3** | **9** |

---

## Critical Findings from Reconciliation

1. **Two undocumented Linux systems exist on production networks** with no ownership, no documentation, and no security controls. These must be identified immediately.

2. **CT Scanner OS remains unknown** — it exists per documentation but wasn't discovered during network scan, suggesting it may use proprietary protocols or is inadequately inventoried.

3. **Shadow IT at both Central and Westside** — Marcus's and Sarah's notes warned of "unknown" devices; network scan confirms two active undocumented systems. This suggests either: (a) developers/testers installing servers without IT approval, or (b) attackers establishing persistence.

4. **Asset count discrepancies** between documentation (~485 workstations) and scan (290+ additional in 10.10.1.0/24 alone, plus Westside and HQ) indicate significant inventory management failure.

5. **All critical security gaps identified in Tasks 4-6 are confirmed by scan** — flat network, EOL systems, database exposure, no Linux endpoint protection, backup exclusions. The scan provides empirical validation of the qualitative assessments.
