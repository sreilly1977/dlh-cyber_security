# 10. The Complete Control Matrix
## Consolidated Authoritative Control Inventory — MedDefense Health Systems

---

## Part 1: Control Registry (Updated)

### Existing Controls

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence/Source |
|------------|-------------|----------|----------|---------------------|---------------|-----------------|
| C-001 | FortiGate 100F Perimeter Firewall with Policy Rules | Technical | Preventive | Entire Central network perimeter; DMZ (web-srv-01); internal server segment | **Adequate** | Has Deny-All catch-all and DMZ segmentation, but Rules 2-3 allow ALL services from VPN and Rule 4 has no egress filtering. Miner on billing-srv-01 communicated freely to mining pools. (Artifact 1) |
| C-002 | DMZ Network Segmentation for Public Web Server | Technical | Preventive | Internal server segment — protects EHR, billing, DCs from direct internet exposure | **Adequate** | web-srv-01 isolated in DMZ with HTTP/HTTPS-only inbound rule. However, web-srv-01 runs Apache 2.4.29 with suspected RCE vulnerabilities — same as billing-srv-01. (Artifact 1) |
| C-003 | Site-to-Site VPN Tunnels (Westside and HQ) | Technical | Preventive | Inter-site data in transit; authentication and encryption of site-to-site communications | **Adequate** | IPSec tunnels are active and logged. However, VPN rules allow ALL services to server subnet. Westside VPN terminates on consumer Netgear router — if router compromised, attacker has full server access. (Artifact 1) |
| C-004 | SSH Key-Based Authentication (ehr-srv-01 only) | Technical | Preventive | ehr-srv-01 (EHR Application Server) — SSH access control | **Strong** | Properly configured with PasswordAuthentication no, PubkeyAuthentication yes. However, only covers 1 of 5 Linux servers. All other Linux servers remain password-based. (Artifact 2) |
| C-005 | SSH Hardening Configuration (ehr-srv-01 only) | Technical | Preventive | ehr-srv-01 — SSH service hardening, session management, logging | **Strong** | Comprehensive hardening: PermitRootLogin no, MaxAuthTries 3, X11Forwarding no, AllowTcpForwarding no, Protocol 2, LogLevel VERBOSE. Only applied to one server. (Artifact 2) |
| C-006 | Active Directory Password Policy with Account Lockout | Administrative | Preventive | All Windows endpoints and servers joined to AD; user account credentials organization-wide | **Weak** | 8-char minimum is below modern NIST recommendations (minimum 12+). 90-day rotation encourages predictable passwords. Linux systems configured individually with inconsistent enforcement. MFA not enforced. (Artifact 3) |
| C-007 | Shared Account Management Procedure | Administrative | Preventive | Shared credential lifecycle; systems using shared accounts (PACS "raduser") | **Weak** | Policy states shared accounts are "discouraged" but permitted. No technical enforcement. "raduser/radiology1" remains active after Marcus reported it. No evidence of password rotation when staff depart. (Artifact 3) |
| C-008 | Sophos Endpoint Protection (Windows Workstations) | Technical | Preventive + Detective | 387 Windows 10/11 workstations across all three sites | **Adequate** | 88.1% signature currency rate. 31 devices with outdated signatures, 15 not reporting. No coverage on Windows servers, Linux servers, iPads, or medical devices. Detected PUA.CryptoMiner on WS-FIN-12 but missed the actual miner on billing-srv-01 (Linux, not covered). (Artifact 4) |
| C-009 | Veeam Nightly Backup System | Technical | Corrective | EHR app/database, billing server, primary DC, file shares, public website | **Weak** | Backs up to local NAS in same rack/room/network — correlated failure risk. No offsite/cloud replication (budget denied). PACS, ad-dc-02, Westside server, O365, medical devices excluded. DR test never performed. January ransomware recovered from 3-week-old backup due to misconfigured cron job. (Artifact 5) |
| C-010 | On-Site Security Guard (Central Main Entrance) | Physical | Preventive + Deterrent | Central main entrance; visitor access to MedDefense Central | **Weak** | One guard, main entrance only, Mon-Fri 07:00-19:00. No night/weekend coverage. No patrols. No coverage at Westside or HQ. Server room, network closets, and administrative wing have no physical access control beyond the same generic badge all 2,000 employees carry. (Artifact 6) |
| C-011 | CCTV Camera System (Central and Westside) | Physical | Detective | Central main entrance, ER entrance, parking garage; Westside front entrance | **Weak** | 4 analog cameras at Central covering non-critical areas. No cameras near server room, network closets, or administrative wing. Self-monitored by whoever is at the desk. 30-day retention at Central, 48-hour retention at Westside. HQ cameras inaccessible to MedDefense. (Artifact 6) |
| C-012 | Annual Security Awareness Training Program | Administrative | Preventive | Organizational human layer; all staff across all sites | **Weak** | 45-minute generic online module. 71% completion at Central, 58% at Westside. No phishing simulations. No healthcare-specific content (PHI handling, medical device security). No role-specific training. Last conducted 10 months ago. (Artifact 7) |
| C-013 | FortiGate Local Log Storage | Technical | Detective | Firewall activity; network traffic metadata at the perimeter | **Adequate** | All firewall policies have logging enabled. 30-day retention. Not forwarded to any external or centralized system. If FortiGate is compromised, logs are tampered. (Artifacts 1, 8) |
| C-014 | Server-Level Logging (Windows, Linux, Apache) | Technical | Detective | Server event histories; Apache access logs; system authentication logs | **Weak** | No centralization. No automated alerting. No log integrity protection. Manual review only "when something breaks." Billing-srv-01 cryptominer ran 14 days undetected despite generating observable logs. (Artifact 8) |
| C-015 | MFA Policy Recommendation (Remote Access) | Administrative | Preventive | Remote access sessions (intended scope) | **Weak** | Policy states MFA is "recommended" but not required. No enforcement mechanism. Only James Chen's personal account has MFA (self-configured). 2,000 users have no MFA on any system. (Artifact 3) |
| C-016 | EHR Application Audit Log (Vendor-Managed) | Technical | Detective | EHR system access records; PHI access audit trail | **Adequate** | Audit log exists and is maintained by vendor (MedTech Solutions). However, exports require 48-hour turnaround. No real-time alerting. No direct access to audit data. Cannot detect PHI snooping in real time. (Artifact 8) |
| C-017 | NTFS File Share Permissions | Technical | Preventive | Department file shares on file-srv-01; HR records, department documents | **Adequate** | NTFS ACLs control folder-level access. However, flat network means any device on 10.10.0.0/16 can reach SMB ports (139/445). No DLP to detect mass downloads. Incident F confirmed unmanaged laptop on HR share segment for 3 weeks. (Task 9 Data Map, Artifact from onboarding) |
| C-018 | O365 Cloud Encryption (Microsoft-Managed) | Technical | Preventive | Email, SharePoint, OneDrive data at rest and in transit to Microsoft cloud | **Adequate** | Microsoft-managed encryption (TLS in transit, AES at rest). However, O365 data is not backed up locally. Account compromise (no MFA) gives attacker direct access to encrypted data with valid credentials. No visibility into Microsoft-side incidents. (Task 9 Data Map, Artifact 4) |
| C-019 | Guest WiFi SSID Segregation (Central) | Technical | Preventive | Guest network isolation from internal corporate network | **Weak** | Separate guest SSID exists on Ubiquiti APs. However, Marcus was "not convinced it's actually isolated." Never formally verified. If isolation is broken, guest users can reach 10.10.0.0/16 including medical devices and servers. (Task 0 onboarding, Marcus notes) |
| C-020 | TLS/HTTPS for Public Web Server and Patient Portal | Technical | Preventive | Patient portal data in transit; web-srv-01 communications | **Adequate** | HTTPS (port 443) available on web-srv-01 in DMZ. Firewall permits HTTP and HTTPS. However, billing-srv-01 uses HTTP only (port 80, no TLS). Patient portal authentication is username/password only — no MFA. (Artifact 1, Task 9 Data Map) |

### Proposed Compensating Controls (Designed in Task 6 — Not Yet Deployed)

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence/Source |
|------------|-------------|----------|----------|---------------------|---------------|-----------------|
| C-021 | Network Micro-Segmentation (VLAN Isolation for Medical Devices) | Technical | Preventive (Compensating) | MRI workstation, PACS server, all medical IoT devices on 10.10.3.0/24 | **Not Deployed** | Designed in Task 6. Dedicates VLAN for imaging devices with strict firewall rules (DICOM-only to PACS). FortiGate already has VLAN capability. Marcus noted segmentation "planned for next fiscal year" 5 months ago. |
| C-022 | Host-Based Firewall and Application Whitelisting (MRI Workstation) | Technical | Preventive (Compensating) | MRI control workstation (WS-RAD-01, Windows XP) | **Not Deployed** | Designed in Task 6. Restricts inbound connections to DICOM only. Blocks unauthorized process execution. Technically challenging on Windows XP — third-party whitelisting tool required. |
| C-023 | Enhanced Monitoring and Alerting for Imaging Segment | Technical | Detective (Compensating) | MRI workstation, PACS server, medical imaging VLAN | **Not Deployed** | Designed in Task 6. Dedicated IDS sensor on imaging VLAN with alerts for Windows XP exploit signatures, unusual outbound connections, and process anomalies. Marcus researched Wazuh but never installed. |
| C-024 | Administrative Access Control and Change Management Policy (MRI) | Administrative | Preventive (Compensating) | MRI control workstation; radiology department access | **Not Deployed** | Designed in Task 6. Named-user access only, documented change approval, USB media prohibition, quarterly access reviews, mandatory suspicious-activity reporting. |
| C-025 | Physical Access Restriction to MRI Control Console | Physical | Preventive + Detective (Compensating) | MRI control workstation physical access | **Not Deployed** | Designed in Task 6. Locked enclosure or badge-controlled access, camera with 90-day retention. Currently MRI room has unrestricted physical access. |

---

## Part 2: Updated Control Summary Matrix

| | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| **Technical** | C-001 (Adequate), C-002 (Adequate), C-003 (Adequate), C-004 (Strong), C-005 (Strong), C-008 (Adequate), C-017 (Adequate), C-018 (Adequate), C-019 (Weak), C-020 (Adequate), C-021 *(proposed)*, C-022 *(proposed)* | C-008 (Adequate), C-013 (Adequate), C-014 (Weak), C-016 (Adequate), C-023 *(proposed)* | C-009 (Weak) | C-021 *(proposed)*, C-022 *(proposed)*, C-023 *(proposed)* | *(empty)* |
| | **Count: 10 active (2 proposed) / Avg: Adequate** | **Count: 4 active (1 proposed) / Avg: Weak-Adequate** | **Count: 1 active / Avg: Weak** | **Count: 0 active (3 proposed) / Avg: N/A** | **Count: 0 / Avg: N/A** |
| **Administrative** | C-006 (Weak), C-007 (Weak), C-012 (Weak), C-015 (Weak), C-024 *(proposed)* | *(empty)* | *(empty)* | C-024 *(proposed)* | *(empty)* |
| | **Count: 4 active (1 proposed) / Avg: Weak** | **Count: 0 / Avg: N/A** | **Count: 0 / Avg: N/A** | **Count: 0 active (1 proposed) / Avg: N/A** | **Count: 0 / Avg: N/A** |
| **Physical** | C-010 (Weak), C-025 *(proposed)* | C-011 (Weak), C-025 *(proposed)* | *(empty)* | C-010 (Weak) | *(empty)* |
| | **Count: 1 active (1 proposed) / Avg: Weak** | **Count: 1 active (1 proposed) / Avg: Weak** | **Count: 0 / Avg: N/A** | **Count: 0 active (1 proposed) / Avg: N/A** | **Count: 1 / Avg: Weak** |

### Matrix Summary by Cell

| Cell | Active Controls | Average Effectiveness | Proposed Controls | Gap Severity |
|------|----------------|----------------------|-------------------|--------------|
| Technical / Preventive | 10 | Adequate | 2 | Low — strongest area |
| Technical / Detective | 4 | Weak-Adequate | 1 | High — no SIEM, no centralization |
| Technical / Corrective | 1 | Weak | 0 | Critical — sole backup is co-located and untested |
| Technical / Compensating | 0 | N/A | 3 | Critical — no compensating controls for unpatchable systems |
| Technical / Deterrent | 0 | N/A | 0 | Medium — no login banners, honeypots, or deception |
| Administrative / Preventive | 4 | Weak | 1 | High — policies exist but lack enforcement |
| Administrative / Detective | 0 | N/A | 0 | Critical — no access reviews, no compliance audits |
| Administrative / Corrective | 0 | N/A | 0 | Critical — no IR plan, no DR plan, no BCP |
| Administrative / Compensating | 0 | N/A | 1 | High — no risk acceptance documentation |
| Administrative / Deterrent | 0 | N/A | 0 | Medium — no AUP enforcement or disciplinary framework |
| Physical / Preventive | 1 | Weak | 1 | Critical — generic badges, unlocked closets |
| Physical / Detective | 1 | Weak | 1 | Critical — no cameras in critical areas |
| Physical / Corrective | 0 | N/A | 0 | High — no physical incident response procedures |
| Physical / Compensating | 0 | N/A | 1 | High — no alternative controls for unsecured areas |
| Physical / Deterrent | 1 | Weak | 0 | Medium — guard presence only during business hours |

---

## Part 3: Control Coverage Map — Top 5 Critical Assets

### Critical Asset #1: ehr-db-01 (EHR Database Server)

| Control Function | Controls Present | Effectiveness | Gaps |
|---|---|---|---|
| **Preventive** | C-001 (firewall — indirect, perimeter only), C-006 (password policy — but Linux configured individually, not via GPO) | Weak | No database firewall restricting port 5432 to ehr-srv-01 only; SSH password auth still enabled (only ehr-srv-01 was migrated to key auth); no MFA on database access; no database-level encryption at rest; no network segmentation isolating the database |
| **Detective** | C-014 (server syslog — local only), C-016 (EHR audit log — vendor managed, 48hr delay) | Weak | No real-time alerting on database queries; no SIEM correlating DB access with other events; no database activity monitoring (DAM); audit log requires 48 hours to export — cannot detect real-time PHI snooping |
| **Corrective** | C-009 (Veeam backup — ehr-db-01 is in backup scope) | Weak | Backup is on NAS in same rack/room/network; no offsite replication; recovery never tested for this specific server; no cloud backup; if ransomware hits, backup is likely lost simultaneously |
| **Compensating** | None | N/A | No compensating controls for the flat network exposure; no compensating controls for the unencrypted DB port exposure |

**Coverage Assessment: Under-Protected** — The most critical data asset in the organization has indirect perimeter protection, weak authentication, no network-level access restriction on its database port, no real-time monitoring, and a backup that would likely fail in a ransomware scenario. The database is one network hop away from the currently compromised billing-srv-01.

---

### Critical Asset #2: ad-dc-01 (Primary Domain Controller)

| Control Function | Controls Present | Effectiveness | Gaps |
|---|---|---|---|
| **Preventive** | C-001 (firewall — indirect, perimeter only), C-006 (password policy via GPO — enforced on Windows) | Adequate-Weak | No MFA on domain admin accounts; no tiered admin model (Tier 0/1/2 separation); no LAPS for local admin password management; no Credential Guard; DC is on flat network reachable from any compromised system; SSH/NPS not relevant but SMB (445) and LDAP (389) exposed to entire network |
| **Detective** | C-014 (Windows Event Log — local, manual review) | Weak | No centralized AD logging; no alerting on new account creation, group membership changes, or DC sync events; no SIEM; no ATA/Defender for Identity equivalent; an attacker creating backdoor accounts would go unnoticed |
| **Corrective** | C-009 (Veeam backup — ad-dc-01 IS in scope) | Weak | ad-dc-02 is NOT backed up — if ad-dc-01 is destroyed, the secondary DC is the only recovery path and it has no backup itself; AD restore is complex (System State restore, FSMO role seizure); never tested |
| **Compensating** | None | N/A | No compensating controls for flat network exposure; DCs should be on isolated management VLAN — they are not |

**Coverage Assessment: Under-Protected** — The authentication backbone for 2,000 users and all systems has GPO-enforced password policy and perimeter firewall (indirect), but no MFA, no tiered administration, no centralized monitoring, and an incomplete backup strategy (secondary DC has no backup). An attacker on the flat network can reach the DC directly on SMB/LDAP/RPC ports.

---

### Critical Asset #3: BD Alaris Infusion Pump Fleet (120 units)

| Control Function | Controls Present | Effectiveness | Gaps |
|---|---|---|---|
| **Preventive** | None | N/A | No network segmentation (flat 10.10.0.0/16); no firewall rules protecting medical device VLAN; no host-based firewall on pumps; no MFA on pump management interface; vendor-recommended network isolation NOT implemented despite 18-month-old security bulletin |
| **Detective** | None | N/A | No IDS monitoring medical device traffic; no SIEM alerts for anomalous pump communications; no device-level logging forwarded anywhere; ~190 medical devices generate no centralized logs |
| **Corrective** | None | N/A | Device configurations NOT backed up (excluded from Veeam); no configuration management database; if pump settings are altered maliciously, there is no known-good configuration to restore |
| **Compensating** | C-021 (proposed — VLAN isolation), C-022 (proposed — host firewall), C-023 (proposed — monitoring) | Not Deployed | All compensating controls are designed but not implemented. Vendor cannot patch firmware on schedule; network isolation is the recommended mitigation and it does not exist |

**Coverage Assessment: Unprotected** — 120 network-connected medical devices delivering intravenous medication to patients have zero preventive, detective, corrective, or compensating controls. They sit on the same flat network as every compromised system. Known CVEs exist in their firmware. The vendor issued a security bulletin 18 months ago recommending exactly the controls (C-021 through C-023) that remain undeployed. An attacker on any system in the network can reach these pumps directly.

---

### Critical Asset #4: billing-srv-01 (Billing/Claims Processing Server)

| Control Function | Controls Present | Effectiveness | Gaps |
|---|---|---|---|
| **Preventive** | C-001 (firewall — indirect, perimeter only; no egress filtering), C-006 (password policy — Linux, individually configured, inconsistent) | Weak | Apache 2.4.29 with known RCE vulnerabilities (CVE-2021-41773/42013) — exploited TWICE; SSH password auth still enabled (not migrated to key auth); MySQL port 3306 exposed to entire network; HTTP not HTTPS for billing app; Ubuntu 18.04 approaching EOL with no ESM; no WAF; server is CURRENTLY COMPROMISED |
| **Detective** | C-014 (syslog — local, manual review only), C-008 (Sophos — does NOT cover Linux servers) | Weak | No endpoint protection on this Linux server; no IDS/IPS; no SIEM alerting; cryptominer ran 14 days undetected; outbound connections to 3 mining pools not flagged; no file integrity monitoring; no process monitoring |
| **Corrective** | C-009 (Veeam backup — billing-srv-01 is in scope) | Weak | Backup on same NAS in same rack; January ransomware used 3-week-old backup due to misconfigured cron; current backup integrity uncertain — the compromised server may have corrupted data that is being backed up nightly; no offsite replication |
| **Compensating** | None | N/A | No compensating controls for the unpatched Apache vulnerability; no WAF to filter exploit attempts; no network isolation despite two confirmed compromises through the same vector |

**Coverage Assessment: Unprotected** — This server is actively compromised and has been for 14+ days. It has the weakest preventive posture of any critical asset (unpatched Apache, password SSH, exposed MySQL, no endpoint protection). The existing controls failed to prevent either the January ransomware or the current cryptominer. The backup exists but was unreliable in January and may contain compromised data now. This server is a confirmed, ongoing security breach that remains uncontained.

---

### Critical Asset #5: FortiGate 100F (Perimeter Firewall)

| Control Function | Controls Present | Effectiveness | Gaps |
|---|---|---|---|
| **Preventive** | C-006 (password policy — for admin access to firewall), C-005 (SSH hardening — not confirmed on FortiGate specifically) | Adequate | Admin access exists but MFA not enforced; no confirmation of admin account auditing; FortiGate admin password strength unknown; no two-factor for firewall management; if admin credentials are compromised via phishing, attacker controls the entire perimeter |
| **Detective** | C-013 (local log storage — 30-day retention, not forwarded) | Adequate | Firewall policies have logging enabled. However, logs are local-only — if firewall is compromised, logs can be tampered. No SIEM to correlate firewall events with server/workstation logs. No alerting on configuration changes or failed admin login attempts |
| **Corrective** | None | N/A | Firewall configuration is not backed up separately; no documented procedure for firewall recovery; if FortiGate fails or is reset, the 2000+ line configuration must be reconstructed manually; no spare firewall unit for HA/failover |
| **Compensating** | None | N/A | No secondary firewall or IDS/IPS behind the FortiGate; if it is bypassed or compromised, no secondary detection exists; no network segmentation behind the firewall to limit blast radius |

**Coverage Assessment: Under-Protected** — The FortiGate is MedDefense's single most important security control, but it has no redundancy (single device), no configuration backup, no centralized log forwarding, and no MFA on admin access. Its ruleset is overly permissive (ALL services from VPN, no egress filtering). If this device fails or is compromised, there is no secondary control between the internet and the internal network.

---

## Coverage Summary Table

| Rank | Critical Asset | Preventive | Detective | Corrective | Compensating | Coverage Assessment |
|------|---------------|------------|-----------|------------|--------------|---------------------|
| 1 | ehr-db-01 | Weak | Weak | Weak | None | **Under-Protected** |
| 2 | ad-dc-01 | Adequate-Weak | Weak | Weak | None | **Under-Protected** |
| 3 | BD Alaris Pumps (120) | None | None | None | None (proposed only) | **Unprotected** |
| 4 | billing-srv-01 | Weak | Weak | Weak | None | **Unprotected** (active compromise) |
| 5 | FortiGate 100F | Adequate | Adequate | None | None | **Under-Protected** |

---

## Key Findings from Control Coverage Analysis

**1. No critical asset has compensating controls.** Zero out of five top assets have deployed compensating controls. The three proposed controls from Task 6 (C-021 through C-023) remain undeployed. This means every unpatchable or legacy system operates without any mitigation layer.

**2. Two of the five most critical assets are Unprotected.** The BD Alaris infusion pumps have literally no controls — preventive, detective, corrective, or compensating. The billing server is actively compromised with minimal and ineffective existing controls.

**3. Detective coverage is universally weak across critical assets.** Every critical asset rated Weak for detective controls. No SIEM, no centralized logging, no real-time alerting, and no database/device activity monitoring means that compromise of any critical asset could go undetected for weeks — as demonstrated by the 14-day cryptominer on billing-srv-01.

**4. Corrective capabilities are weak and untested everywhere.** The sole corrective control (Veeam backup) is co-located with production, has never been fully tested, excludes critical assets, and was unreliable during the January ransomware incident. No incident response plan or disaster recovery procedure exists to guide corrective actions.

**5. The firewall protects the perimeter but nothing behind it.** The FortiGate is the single point of security for the entire network. Behind it, the flat network means that any single compromise can reach any asset. The firewall has no redundancy, no config backup, and no secondary detection layer.
