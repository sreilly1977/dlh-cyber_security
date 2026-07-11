# Security Controls Inventory: MedDefense Health Systems
## Dual-Axis Taxonomy Classification

---

## Control Registry

---

**Control ID:** C-001

**Control Name:** FortiGate 100F Perimeter Firewall with Policy Rules

**Description:** Fortinet FortiGate 100F deployed at Central as the perimeter firewall. Policy includes an explicit inbound allow rule for HTTP/HTTPS to web-srv-01 in the DMZ, outbound NAT for internal traffic, and a Deny-All catch-all rule (Rule 5) that blocks all traffic not explicitly permitted. All rules have logging enabled (logtraffic all or utm).

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Entire Central network perimeter; DMZ (web-srv-01); internal server segment

**Source:** Artifact 1 (Firewall Configuration Extract)

---

**Control ID:** C-002

**Control Name:** DMZ Network Segmentation for Public Web Server

**Description:** web-srv-01 (public website + patient portal) is placed in a dedicated DMZ interface on the FortiGate. Inbound traffic from the WAN is restricted to HTTP and HTTPS only (Rule 1), and the destination is limited to web-srv-01 specifically — not the broader internal network. This separates the internet-facing server from internal systems.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Internal server segment; EHR, billing, domain controllers, and other internal systems protected from direct internet exposure

**Source:** Artifact 1 (Firewall Configuration Extract)

---

**Control ID:** C-003

**Control Name:** Site-to-Site VPN Tunnels (Westside and HQ)

**Description:** IPSec/site-to-site VPN tunnels connect Westside Clinic and Corporate HQ to Central's FortiGate firewall. VPN traffic from both sites is directed to the internal server subnet. Traffic is logged with UTM inspection enabled (logtraffic utm).

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** Inter-site data in transit; authentication and encryption of site-to-site communications

**Source:** Artifact 1 (Firewall Configuration Extract)

---

**Control ID:** C-004

**Control Name:** SSH Key-Based Authentication (ehr-srv-01)

**Description:** ehr-srv-01 has been migrated to SSH public key authentication only. `PasswordAuthentication no` is set, eliminating password-based SSH logins. This was the only server Marcus completed before departing; all other Linux servers retain password-based SSH authentication.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** ehr-srv-01 (EHR Application Server) — SSH access control

**Source:** Artifact 2 (SSH Configuration)

---

**Control ID:** C-005

**Control Name:** SSH Hardening Configuration (ehr-srv-01)

**Description:** ehr-srv-01's sshd_config includes: `PermitRootLogin no`, `MaxAuthTries 3`, `LoginGraceTime 60`, `ClientAliveInterval 300` with `ClientAliveCountMax 2`, `X11Forwarding no`, `AllowTcpForwarding no`, `Protocol 2`, `PermitEmptyPasswords no`, `ChallengeResponseAuthentication no`, and `LogLevel VERBOSE`. These settings collectively reduce the SSH attack surface and improve session security.

**Category:** Technical

**Function:** Preventive

**Asset(s) Protected:** ehr-srv-01 (EHR Application Server) — SSH service hardening, session management, logging

**Source:** Artifact 2 (SSH Configuration)

---

**Control ID:** C-006

**Control Name:** Active Directory Password Policy with Account Lockout

**Description:** Organizational password policy requiring: minimum 8 characters, complexity (uppercase, lowercase, number, special character), 90-day rotation, 5-password history, and account lockout after 5 failed attempts for 30 minutes. Enforced through Active Directory Group Policy for Windows systems. Linux systems are configured individually (inconsistent enforcement).

**Category:** Administrative

**Function:** Preventive

**Asset(s) Protected:** All Windows endpoints and servers joined to Active Directory; user account credentials organization-wide

**Source:** Artifact 3 (Password Policy)

---

**Control ID:** C-007

**Control Name:** Shared Account Management Procedure

**Description:** Policy states that shared accounts are discouraged but permitted when individual accounts are not technically feasible. Requirement exists to change shared account passwords when any user with access leaves the organization.

**Category:** Administrative

**Function:** Preventive

**Asset(s) Protected:** Shared credential lifecycle; systems using shared accounts (documented: PACS workstation "raduser")

**Source:** Artifact 3 (Password Policy)

---

**Control ID:** C-008

**Control Name:** Sophos Endpoint Protection (Windows Workstations)

**Description:** Sophos Endpoint Protection deployed on 387 managed Windows 10/11 workstations (approximately 88.1% with current signatures). Provides real-time malware detection, blocking, and quarantine. Recent detections include adware, cryptominer PUA, phishing URLs, and trojans — all blocked or quarantined. Not deployed on Windows servers (license not purchased) or Linux servers (not supported by current tier). iPads are not in scope.

**Category:** Technical

**Function:** Preventive (real-time blocking/quarantine) and Detective (threat identification and logging)

**Asset(s) Protected:** Windows 10/11 workstations across all three sites

**Source:** Artifact 4 (Sophos Antivirus Status Report)

---

**Control ID:** C-009

**Control Name:** Veeam Nightly Backup System

**Description:** Veeam Backup & Replication (Community Edition) performs nightly full backups at 02:00 AM of selected VMs (ehr-srv-01, ehr-db-01, billing-srv-01, ad-dc-01, file-srv-01, web-srv-01) to a local Synology NAS (24TB RAID5) with 14-day retention. Partial recovery was tested 8 months ago (file-srv-01 restore, took 6 hours). No full DR test has been performed.

**Category:** Technical

**Function:** Corrective

**Asset(s) Protected:** EHR application and database, billing server, primary domain controller, file shares, public website

**Source:** Artifact 5 (Backup Configuration)

---

**Control ID:** C-010

**Control Name:** On-Site Security Guard (Central Main Entrance)

**Description:** ClearView Security provides one uniformed guard stationed at the Central main entrance lobby, Monday through Friday, 07:00–19:00. Duties include visitor registration, badge verification, and incident reporting. Guard does not patrol floors, restricted areas, or parking. No coverage at Westside, HQ, or during nights/weekends.

**Category:** Physical

**Function:** Preventive (badge verification, visitor access control) and Deterrent (uniformed presence)

**Asset(s) Protected:** Central main entrance; visitor access to MedDefense Central

**Source:** Artifact 6 (Physical Security Contract)

---

**Control ID:** C-011

**Control Name:** CCTV Camera System (Central and Westside)

**Description:** Central has 4 analog cameras (main entrance x2, ER entrance, parking garage entrance) recording to a local DVR with 30-day retention. Westside has 1 camera at front entrance recording to a local SD card with approximately 48-hour retention. No cameras cover server room, network closets, or administrative wing. Footage is self-monitored by whoever is at the security desk. HQ cameras are building-managed with no MedDefense access.

**Category:** Physical

**Function:** Detective

**Asset(s) Protected:** Central main entrance, ER entrance, parking garage; Westside front entrance

**Source:** Artifact 6 (Physical Security Contract)

---

**Control ID:** C-012

**Control Name:** Annual Security Awareness Training Program

**Description:** "CyberSafe Basics" — a 45-minute third-party online module covering password hygiene, phishing email recognition, physical security awareness (tailgating, clean desk), and reporting suspicious activity. Mandatory annually for all staff. Last conducted 10 months ago. Completion rates: HQ 94%, Central 71%, Westside 58%. No phishing simulations, role-specific training, or PHI handling education.

**Category:** Administrative

**Function:** Preventive

**Asset(s) Protected:** Organizational human layer; all staff across all sites

**Source:** Artifact 7 (Training Records)

---

**Control ID:** C-013

**Control Name:** FortiGate Local Log Storage

**Description:** FortiGate firewall stores its own logs locally with 30-day retention. Logs are not forwarded to any external or centralized system. All firewall policies have logging enabled (logtraffic all or logtraffic utm).

**Category:** Technical

**Function:** Detective

**Asset(s) Protected:** Firewall activity; network traffic metadata at the perimeter

**Source:** Artifact 1 (Firewall Configuration — logging), Artifact 8 (Log Management)

---

**Control ID:** C-014

**Control Name:** Server-Level Logging (Windows, Linux, Apache)

**Description:** Windows servers write events to Event Viewer (checked manually on demand). Linux servers use standard syslog to /var/log. Apache logs on web-srv-01 and billing-srv-01 rotate weekly via logrotate with 4-week retention. No centralization, no automated alerting, no log integrity protection (no hashing or write-once storage).

**Category:** Technical

**Function:** Detective

**Asset(s) Protected:** Server event histories; Apache access logs; system authentication logs

**Source:** Artifact 8 (Log Management)

---

**Control ID:** C-015

**Control Name:** MFA Policy Recommendation (Remote Access)

**Description:** Password policy document states that MFA is recommended for remote access but is not currently required. No enforcement mechanism exists. Only James Chen's personal account has MFA configured (self-set up).

**Category:** Administrative

**Function:** Preventive (policy-level only — not technically enforced)

**Asset(s) Protected:** Remote access sessions (intended but not realized)

**Source:** Artifact 3 (Password Policy)

---

**Control ID:** C-016

**Control Name:** EHR Application Audit Log (Vendor-Managed)

**Description:** The EHR system maintains its own application-level audit log, managed by the vendor (MedTech Solutions). Exports can be requested but require 48-hour turnaround. No real-time alerting or direct access to audit data.

**Category:** Technical

**Function:** Detective

**Asset(s) Protected:** EHR system access records; PHI access audit trail

**Source:** Artifact 8 (Log Management)

---

## Control Summary Matrix

| | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| **Technical** | C-001, C-002, C-003, C-004, C-005, C-008 | C-008, C-013, C-014, C-016 | C-009 | *(empty)* | *(empty)* |
| **Administrative** | C-006, C-007, C-012, C-015 | *(empty)* | *(empty)* | *(empty)* | *(empty)* |
| **Physical** | C-010 | C-011 | *(empty)* | *(empty)* | C-010 |

---

## Matrix Gap Analysis

### Empty Cells and Their Significance

| Empty Cell | What's Missing | Risk Implication |
|---|---|---|
| **Technical / Compensating** | No compensating controls deployed for systems that cannot be patched (e.g., MRI on Windows XP, print-srv-01 on Server 2012 R2). Network isolation or VLAN segmentation for legacy/medical devices has not been implemented. | Unpatchable systems remain fully exposed on the flat 10.10.0.0/16 network |
| **Technical / Deterrent** | No technical deterrents such as login banners warning of monitoring/prosecution, honeypots, or deception technology. | Attackers face no psychological or technical friction beyond core preventive controls |
| **Administrative / Detective** | No administrative detective controls — no scheduled access reviews, periodic permission audits, or compliance attestation processes. | Permission creep, orphaned accounts, and unauthorized access go undetected through procedural gaps |
| **Administrative / Corrective** | No incident response plan, no disaster recovery plan, no business continuity plan, no formal post-incident review process. | When incidents occur (and they have — January ransomware, cryptominer), response is improvised with no structured corrective procedure or lessons-learned loop |
| **Administrative / Compensating** | No documented exceptions or risk acceptance process for systems that cannot meet baseline controls. | Insecure configurations persist without formal risk acknowledgment or compensating control documentation |
| **Administrative / Deterrent** | No acceptable use policy enforcement, no disciplinary framework for security violations, no published security consequences. | Staff who prop open fire exits, leave workstations unlocked, or ignore badge protocols face no documented repercussions |
| **Physical / Corrective** | No physical incident recovery procedures — no documented response to physical breaches, no key/badge revocation process, no physical security incident playbook. | Physical security events (propped doors, unauthorized access) cannot be formally responded to or corrected |
| **Physical / Compensating** | No compensating physical controls for areas without badge readers or cameras (e.g., Westside server closet has no lock — no alternative control compensates for this). | Locations lacking primary physical controls have no fallback mechanisms |

---

## Key Observations

**1. Heavy preventive bias with minimal detective capability.** Of 16 controls identified, 10 are preventive. Only 6 are detective, and all of them are passive (logs that are manually checked, cameras that are self-monitored, training that doesn't include simulations). There is no active detection — no SIEM, no IDS/IPS, no automated alerting, no real-time monitoring.

**2. Zero corrective or compensating controls across all three categories.** The organization has no documented incident response plan, no DR/BCP, and no compensating controls for unpatchable systems. When things go wrong, the response is improvised (as demonstrated by the January ransomware incident). Legacy systems like the MRI scanner and print server receive no compensating protection.

**3. Administrative controls exist on paper but lack enforcement.** The password policy is enforced via GPO for Windows but not Linux. MFA is "recommended" but not required. Training completion is 58–71% at clinical sites with no enforcement mechanism. Shared account management has no technical enforcement.

**4. Physical controls are geographically and temporally sparse.** Security coverage exists only at Central's main entrance during business hours. Westside has a single camera with 48-hour retention. The server room, network closets, and administrative wing have no physical controls at all.

**5. Critical asset coverage gaps.** Sophos endpoint protection covers only Windows workstations — not Windows servers, not Linux servers (where the cryptominer was running), not medical devices, not iPads. The Veeam backup excludes PACS imaging, the secondary domain controller, Westside's server, and all O365 data. The most critical assets have the least protection.
