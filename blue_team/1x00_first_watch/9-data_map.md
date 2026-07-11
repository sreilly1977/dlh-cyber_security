# 9. The Data Map
## Sensitive Data Lifecycle & Protection Gap Analysis — MedDefense Health Systems

---

## Data Classification Scheme

| Level | Definition | Examples at MedDefense |
|-------|------------|----------------------|
| **Restricted** | Highest sensitivity. Unauthorized access causes severe harm. Regulatory penalties. | Patient medical records, SSNs, insurance data, medical imaging, medication profiles |
| **Confidential** | Sensitive internal information. Unauthorized access causes significant harm. | Employee salaries, vendor contracts, IT service pricing, strategic plans |
| **Internal** | Not for public disclosure but limited impact if exposed. | Internal memos, org charts, meeting notes, non-PHI department schedules |
| **Public** | Intended for public consumption. No harm if disclosed. | Website content, public phone numbers, press releases |

---

## Data Lifecycle Map

---

### Data Category 1: Patient Medical Records (EHR)

| Field | Detail |
|-------|--------|
| **Classification** | Restricted |
| **At Rest (where)** | PostgreSQL database on ehr-db-01 (10.10.2.11); nightly Veeam backup on NAS-01 (10.10.2.41) in same rack as production; EHR vendor may retain copies for support purposes (MedTech Solutions, 4hr SLA) |
| **In Transit (how)** | HTTPS/TLS between ehr-srv-01 and clinical workstations on the flat 10.10.0.0/16 network; no separate encryption layer beyond TLS; database queries traverse internal network unencrypted between application server and database server (port 5432 plaintext) |
| **In Use (by whom, on what)** | Physicians on iPads (~25 unmanaged devices) during rounds; nurses at ~400 clinical workstations across Central and Westside; pharmacists at pharmacy terminals; lab technicians at lab workstations; ER staff on thin clients (TC-ER-01-04); viewed on screens at nurse stations where sessions remain logged in between shifts (Observation 3, Task 3) |
| **Current Protection** | SSH key authentication on ehr-srv-01 only (other Linux servers still password-based); password policy enforced via AD GPO (8-char/90-day); Sophos endpoint protection on Windows workstations (88.1% coverage); Veeam nightly backup (14-day retention); EHR vendor audit log (48hr export delay) |
| **Protection Gaps** | PostgreSQL port 5432 accessible from entire 10.10.0.0/16 — any compromised system can directly query the database (confirmed by network scan); no database-level encryption at rest; no MFA on EHR application login; unattended EHR sessions at nurse stations with no auto-lock policy and organizational culture discouraging logout (Task 3, Observation 3); iPads are unmanaged with no MDM — PHI may be cached locally on devices that leave the hospital; EHR audit log is vendor-controlled with 48-hour export delay — no real-time alerting on unauthorized PHI access; backup is co-located with production in same room, same rack, same network — ransomware would destroy both copies simultaneously; shared "raduser" account on PACS workstation means EHR-derived imaging access is unattributable |

---

### Data Category 2: Medical Imaging Data (PACS)

| Field | Detail |
|-------|--------|
| **Classification** | Restricted |
| **At Rest (where)** | PACS server storage on pacs-srv-01 (10.10.2.12) running Windows Server 2016; DICOM image archive — explicitly excluded from Veeam backup ("too large, would fill the NAS"); MRI and CT raw data stored on device-local storage before transfer to PACS |
| **In Transit (how)** | DICOM protocol (port 104/11112) from MRI workstation (10.10.1.70, Windows XP) and CT scanner to pacs-srv-01; traffic traverses flat network with no encryption layer; DICOM images queried by radiologist workstations (WS-RAD-01/02) via DICOM protocol over plaintext internal network |
| **In Use (by whom, on what)** | Radiologists on WS-RAD-01 (Windows XP, MRI control) and WS-RAD-02 (Windows 10); referring physicians viewing studies through EHR integration; surgeons reviewing pre-operative imaging in surgical suites |
| **Current Protection** | PACS server is on the server subnet; Windows Defender or Sophos? — Sophos does NOT cover Windows servers (license not purchased per Artifact 4); PACS is excluded from backup entirely — no recovery mechanism exists if PACS storage fails or is encrypted by ransomware |
| **Protection Gaps** | DICOM traffic is unencrypted on the flat network — any device on 10.10.0.0/16 can capture patient imaging data via packet sniffing; MRI control workstation runs Windows XP (EOL 2014) with no compensating controls (no VLAN, no host firewall, no application whitelisting — see Task 6); PACS has NO backup — loss of pacs-srv-01 means permanent loss of all historical imaging studies; shared "raduser/radiology1" credential means imaging access is unattributable to individual clinicians; PACS server management interface accessible from entire network (port 4242 open); CT scanner OS unknown — cannot assess encryption, authentication, or vulnerability status |

---

### Data Category 3: Financial / Billing Data

| Field | Detail |
|-------|--------|
| **Classification** | Restricted (contains patient identifiers + financial data: SSNs, insurance IDs, credit card processing) |
| **At Rest (where)** | MySQL database on billing-srv-01 (10.10.2.15, Ubuntu 18.04); no backup encryption (Veeam backup exists but stores data in plaintext on NAS); billing application files on Apache web root (/var/www/html/) — same directory where the cryptominer binary was planted |
| **In Transit (how)** | HTTP (port 80) between billing application and finance workstations — no HTTPS/TLS on the billing web interface; MySQL queries between Apache and database on localhost; no encryption between billing server and insurance payer clearinghouse (external transmission method unknown) |
| **In Use (by whom, on what)** | Finance/billing staff at WS-FIN-* workstations at Central; finance staff at HQ via site-to-site VPN; one of these workstations (WS-FIN-12) had a PUA.CryptoMiner detection 15 days ago (Artifact 4) |
| **Current Protection** | Veeam nightly backup with 14-day retention; Sophos on finance workstations (Windows endpoints covered); MySQL database behind Apache application layer |
| **Protection Gaps** | Server is currently compromised — cryptominer running as www-data with database access; MySQL port 3306 is accessible from entire 10.10.0.0/16; billing web interface uses HTTP not HTTPS — credentials and data transmitted in cleartext; Ubuntu 18.04 approaching EOL with no ESM activated; attacker has had 14+ days of potential database access — all billing data may already be exfiltrated; backup was 3 weeks stale during January ransomware — current backup reliability is questionable |

---

### Data Category 4: Employee HR Records

| Field | Detail |
|-------|--------|
| **Classification** | Confidential (salaries, SSNs, performance reviews, medical leave records, background check results) |
| **At Rest (where)** | HR shared drive on file-srv-01 (10.10.2.30, Windows Server 2016); O365 SharePoint and OneDrive (cloud, $432K/year license); possible local copies on HR department workstations at Corporate HQ |
| **In Transit (how)** | SMB/CIFS file shares over internal network (ports 139/445) between HQ workstations and file-srv-01 via site-to-site VPN; O365 traffic over HTTPS to Microsoft cloud |
| **In Use (by whom, on what)** | HR staff at Corporate HQ (WS-HQ-* workstations); HR Director; potentially executive leadership for salary reviews; IT intern's personal laptop was on the same network segment as HR file share for 3 weeks (Incident F) |
| **Current Protection** | Windows file share permissions (NTFS ACLs); O365 Microsoft-managed encryption; Veeam backup of file-srv-01; password policy via AD |
| **Protection Gaps** | Flat network means HR file share is reachable from any device on 10.10.0.0/16 — including the currently compromised billing-srv-01; Incident F confirmed that an unmanaged personal laptop with torrent client was on the same segment as the HR share for 3 weeks, potentially exposing HR data to peer-to-peer file sharing; no DLP (Data Loss Prevention) solution deployed to detect or prevent mass file downloads from HR shares; O365 data is not backed up locally ("Microsoft handles it") — no recovery path if Microsoft tenant is compromised or account is deleted; no access review process to verify who has NTFS permissions to HR folders |

---

### Data Category 5: System Credentials & Configuration Data

| Field | Detail |
|-------|--------|
| **Classification** | Restricted (compromise enables full system takeover — credentials are the keys to all other data) |
| **At Rest (where)** | Active Directory NTDS.dit on ad-dc-01/ad-dc-02 (password hashes for all 2,000 users); SSH keys on ehr-srv-01 (only server with key auth configured); laminated credential sheet taped to wall in 2nd-floor network closet (switch admin username/password, Task 3 Observation 2); config.json with Monero wallet credentials at /var/www/html/.cache/ on billing-srv-01; Veeam backup files on NAS-01 containing copies of all server configurations and credentials |
| **In Transit (how)** | Kerberos/LDAP between workstations and domain controllers (ports 88/389/636); SSH sessions between admin workstations and servers (password-based on all except ehr-srv-01); SMB between workstations and file shares |
| **In Use (by whom, on what)** | IT sysadmins (Tom Reeves et al.) from WS-ADMIN-01/02/03 with RDP enabled; network technicians configuring switches; automated service accounts running applications; the billing server's www-data account (currently compromised) may have access to database credentials stored in application configuration files |
| **Current Protection** | AD password policy (8-char/90-day/complexity/lockout); SSH key auth on ehr-srv-01 only; account lockout after 5 failed attempts; NTFS permissions on credential stores |
| **Protection Gaps** | Plaintext credentials physically taped to wall in unlocked network closet (Task 3, Observation 2) — accessible to anyone walking the corridor; SSH password authentication still enabled on billing-srv-01, ehr-db-01, backup-srv-01, web-srv-01, and UNKNOWN-01; no MFA anywhere except James Chen's personal account; Active Directory NTDS.dit is accessible to anyone who compromises a domain admin account — and domain admin credentials may be stored in Veeam backup files on the NAS; LDAPS (port 636) is open but unclear if LDAP signing/channel binding is enforced; 15 non-reporting Sophos devices may have cached credentials; the compromised www-data account on billing-srv-01 may have read access to application-level database credentials |

---

### Data Category 6: Audit Logs & Security Telemetry

| Field | Detail |
|-------|--------|
| **Classification** | Confidential (contain security-relevant information: user activity patterns, authentication events, error messages that may reveal system architecture) |
| **At Rest (where)** | FortiGate local storage (30-day retention, not forwarded); Windows Event Logs on individual servers (manual review only); Linux syslog in /var/log on each server individually; Apache logs on web-srv-01 and billing-srv-01 (4-week logrotate retention); EHR audit log managed by vendor MedTech Solutions (48-hour export delay); Synology NAS logs; DVR footage (30-day retention, then overwritten) |
| **In Transit (how)** | No centralized forwarding — logs remain on source devices; no syslog relay or SIEM ingestion; EHR audit exports requested via vendor portal |
| **In Use (by whom, on what)** | Tom Reeves (sysadmin) checking manually "when something breaks"; no designated log reviewer; James Chen has no access to real-time logs; ClearView guard reviewing DVR footage on demand only |
| **Current Protection** | Standard OS file permissions on log files; FortiGate local storage; DVR local storage |
| **Protection Gaps** | No log integrity protection — no hashing, no write-once storage, no blockchain anchoring (Artifact 8); an attacker with admin access can modify or delete logs to cover tracks; FortiGate logs are stored on the FortiGate itself — if the firewall is compromised, logs are tampered; no correlation across log sources — the billing server's outbound connections to mining pools appeared in local netstat but were never correlated with firewall logs; 30-day retention is below HIPAA's 6-year retention requirement for access logs (45 CFR §164.316(b)(2)); EHR audit log is vendor-controlled with 48-hour delay — rapid response to PHI snooping is impossible; Marcus researched Wazuh SIEM but never deployed it; approximately 190 medical devices generate no centralized logs whatsoever |

---

### Data Category 7: Patient Portal Data (Web-Facing)

| Field | Detail |
|-------|--------|
| **Classification** | Restricted (lab results, appointment information, provider messaging — all PHI) |
| **At Rest (where)** | web-srv-01 (10.10.2.50, Ubuntu 20.04) in the DMZ; patient portal application backend; database on billing-srv-01 or separate application database (unclear from documentation) |
| **In Transit (how)** | HTTPS/TLS from patient browsers to web-srv-01 (ports 80/443); internal API calls from web-srv-01 to backend databases over flat internal network; patient authentication via username/password only |
| **In Use (by whom, on what)** | Patients accessing from external internet via personal devices; web-srv-01 serving portal pages and processing requests |
| **Current Protection** | DMZ placement with FortiGate inbound rules restricting to HTTP/HTTPS; firewall logging enabled; Veeam backup of web-srv-01 |
| **Protection Gaps** | Broken access control confirmed in Incident B (Feb 2) — any authenticated patient could view other patients' lab results by modifying URL parameters; this was identified and presumably fixed, but no formal verification or penetration test has been conducted since; Apache 2.4.29 on web-srv-01 is the same version suspected on billing-srv-01 — known RCE vulnerabilities (CVE-2021-41773/42013) may be exploitable; no WAF (Web Application Firewall) deployed; no MFA on patient portal accounts; patient portal shares infrastructure with the public website that was defaced in Incident D — if the web server is compromised, patient portal data is exposed; no rate limiting or anomaly detection on portal authentication — credential stuffing attacks could go undetected |

---

### Data Category 8: Network Configuration Data

| Field | Detail |
|-------|--------|
| **Classification** | Confidential (firewall rules, VPN configurations, switch configurations, network topology — enables targeted attacks if disclosed) |
| **At Rest (where)** | FortiGate configuration file (2000+ lines, stored on firewall); switch configurations on Cisco devices; Marcus's network diagram on shared drive S:\Security\Notes; laminated credential sheet in network closet (contains switch admin credentials); IT documentation scattered across ServiceDesk ticketing, spreadsheets, and "people's heads" per onboarding context |
| **In Transit (how)** | SSH/Telnet to network devices for configuration (unknown if Telnet is disabled); SNMP (ports/status unknown); VPN tunnel configurations between sites |
| **In Use (by whom, on what)** | Network technicians configuring switches and APs; Sarah Park managing FortiGate; IT staff accessing documentation on shared drives |
| **Current Protection** | FortiGate admin interface (authentication required); SSH on managed devices (credentials on laminated sheet in closet) |
| **Protection Gaps** | Network documentation is incomplete, scattered, and partially inaccurate — Marcus's network diagram is acknowledged as "simplified" and "messier in reality"; credential sheet is physically exposed in an unlocked network closet (Task 3, Observation 2); no NAC (Network Access Control) — any device can connect to any switch port on the flat network; FortiGate admin password strength and admin account list unknown; if the laminated credentials have been photographed by any passerby over the unknown period they've been posted, switch management is already compromised; SNMP community strings (if configured) are likely default or simple given overall security maturity |

---

### Data Category 9: Medical Device Operational Data

| Field | Detail |
|-------|--------|
| **Classification** | Restricted (real-time patient vitals, medication delivery records, device status — all PHI) |
| **At Rest (where)** | On-device storage on Philips IntelliVue monitors (~80 units); BD Alaris infusion pumps (~120 units); nurse call system database; badge reader access logs on HID Global system |
| **In Transit (how)** | HL7/DICOM protocols over the flat 10.10.0.0/16 network; HTTP/HTTPS to device management interfaces (ports 80/443 exposed on all medical devices per network scan); SIP (port 5060) for nurse call system |
| **In Use (by whom, on what)** | Nurses viewing real-time vitals on monitor displays; pharmacists programming infusion pump dosage rates; facilities staff managing badge access; device management interfaces accessible from any network device |
| **Current Protection** | Vendor-provided device authentication (strength unknown); physical placement in patient rooms and clinical areas; nurse call system integrated with phone system |
| **Protection Gaps** | All medical device management interfaces (HTTP/HTTPS on ports 80/443) are accessible from the entire flat network per network scan — any compromised system can reach device admin panels; BD Alaris firmware 12.1.2 has known CVEs (vendor bulletin 18 months old, network isolation recommended but not implemented); MON-VITALS-3F-01 displays its IP address (10.10.3.47) and firmware version (v2.1.3, last updated 2019) on screen — providing reconnaissance information to anyone in the patient room (Task 3, Observation 4); no network segmentation isolating medical devices from general IT traffic; device configurations are not backed up per Veeam configuration; default credentials on medical devices are a known industry problem — no evidence of credential hardening; physical access to devices in patient rooms is unrestricted (patients, visitors, anyone) |

---

## Consolidated Data Flow Summary Matrix

| Data Category | Classification | At Rest Encryption | In Transit Encryption | In Use Access Control | Overall Protection Rating |
|---|---|---|---|---|---|
| Patient Medical Records (EHR) | Restricted | ❌ None (DB-level encryption absent) | ⚠️ Partial (TLS to app, plaintext to DB) | ⚠️ Weak (no MFA, shared sessions, unmanaged iPads) | **Poor** |
| Medical Imaging (PACS) | Restricted | ❌ None | ❌ None (DICOM plaintext) | ⚠️ Weak (shared raduser account) | **Very Poor** |
| Financial / Billing | Restricted | ❌ None | ❌ None (HTTP not HTTPS) | ⚠️ Weak (compromised server) | **Critical** |
| Employee HR Records | Confidential | ⚠️ Partial (O365 encrypted, file share not) | ⚠️ Partial (VPN + SMB) | ⚠️ Weak (flat network exposure, Incident F) | **Poor** |
| System Credentials | Restricted | ❌ None (plaintext on wall, in configs) | ⚠️ Partial (SSH on 1 server) | ❌ None (no vault, no MFA) | **Critical** |
| Audit Logs | Confidential | ❌ None (no integrity protection) | ❌ None (no forwarding) | ❌ None (manual, no review process) | **Very Poor** |
| Patient Portal Data | Restricted | ❌ Unknown (depends on app) | ✅ HTTPS to DMZ | ❌ Weak (Broken AC in Incident B) | **Poor** |
| Network Config Data | Confidential | ❌ None (creds on wall) | ❌ Unknown (Telnet?) | ⚠️ Weak (exposed credentials) | **Critical** |
| Medical Device Data | Restricted | ❌ Unknown (device-dependent) | ❌ None (HL7/DICOM plaintext) | ❌ None (default creds likely) | **Very Poor** |

Legend: ✅ Adequate | ⚠️ Partial | ❌ Absent

---

## Data Risk Summary

MedDefense's most significant data protection weakness is the **complete absence of encryption and access control for Restricted data in transit across the flat network**. Every category of Restricted data — patient medical records flowing between the EHR application server and the PostgreSQL database (port 5432 plaintext), DICOM imaging studies traveling from the MRI workstation to the PACS server (port 104 plaintext), billing credentials and financial data transiting HTTP between finance workstations and billing-srv-01 (port 80 cleartext), and medical device telemetry including real-time patient vitals and medication delivery data crossing the unsegmented 10.10.0.0/16 broadcast domain — moves across a network where any compromised system can intercept it. This means the cryptographic protections that should distinguish "authorized user viewing patient data" from "attacker sniffing the wire" simply do not exist. The billing-srv-01 compromise demonstrates this is not theoretical: an attacker has been running code on that server for 14+ days with www-data privileges, and the flat network gives that compromised account a direct path to the EHR database on port 5432, the PACS server on port 11112, the domain controllers on ports 389/445/88, and every medical device on the 10.10.3.0/24 segment. The gap between the data's Restricted classification and its near-total lack of in-transit protection is the widest in the organization, and it exists because Marcus's recommendation for network segmentation was placed "on the roadmap" five months ago and never acted upon — the same roadmap where physical security, offsite backups, and server hardening also wait indefinitely.
