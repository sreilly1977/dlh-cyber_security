# 12. The Gap Analysis
## Prioritized Security Gap Analysis — MedDefense Health Systems

---

## Methodology

This gap analysis cross-references four foundational documents produced during the security posture assessment:

- **Asset Criticality Assessment (Task 8):** Identifies what matters most and why
- **Data Map (Task 9):** Identifies what sensitive data exists, where it lives, and how it moves
- **Complete Control Matrix (Task 10):** Identifies what protections exist and their effectiveness
- **Shadow IT Findings (Task 11):** Identifies systems operating outside all governance

A gap exists where the distance between asset criticality/data sensitivity and control coverage is unacceptable — meaning the controls either do not exist, are deployed but inadequate, or fail to cover the specific asset or data state in question.

---

## Prioritized Gap Registry

---

### GAP-001: Flat Network Architecture — No Segmentation Between Critical Systems

**Title:** All servers, workstations, medical devices, and IoT share a single unsegmented broadcast domain (10.10.0.0/16)

**Affected Asset(s):**
- ehr-db-01 (Critical) — EHR database, port 5432 exposed to all
- ad-dc-01/ad-dc-02 (Critical) — Domain controllers, ports 389/445/88 exposed to all
- pacs-srv-01 (Critical) — PACS server, port 11112 exposed to all
- billing-srv-01 (Critical, actively compromised) — MySQL port 3306 exposed to all
- BD Alaris infusion pumps (Critical) — 120 pumps, ports 80/443 exposed to all
- Philips IntelliVue monitors (Critical) — 80 monitors, ports 80/443/2575 exposed to all
- MRI workstation WS-RAD-01 (Critical, Windows XP) — SMB ports 135/139/445 exposed to all
- NAS-01 (Critical backup target) — Management ports 5000/5001 exposed to all

**Data at Risk:**
- Patient Medical Records (Restricted) — PostgreSQL traffic between ehr-srv-01 and ehr-db-01 traverses the flat network in plaintext
- Medical Imaging Data (Restricted) — DICOM traffic between MRI/CT and PACS traverses the flat network unencrypted
- Medical Device Operational Data (Restricted) — Real-time vitals and medication delivery data on the same segment as all IT systems
- System Credentials (Restricted) — LDAP/Kerberos/SMB authentication traffic traverses the flat network

**Current Control Status:**
- C-001 (FortiGate firewall) — Perimeter only; no internal segmentation rules
- C-002 (DMZ for web-srv-01) — Only web server is segmented; all internal systems are not
- Marcus noted segmentation was "planned for next fiscal year" 5 months ago; never implemented
- Network scan confirms: "all subnets were reachable from the scan host without any access restrictions"

**What is Missing:**
- Technical / Preventive (Compensating) — No VLAN segmentation isolating servers, medical devices, workstations, or management networks
- Technical / Preventive — No internal firewall rules restricting east-west traffic between segments
- Technical / Preventive — No database firewall restricting PostgreSQL/MySQL access to application servers only

**Risk Level:** Critical

**Risk Justification:** The flat network is the single largest force multiplier for every other gap in this assessment. It means that any single system compromise — whether through the active billing-srv-01 cryptominer, a phishing-driven endpoint infection, or a medical device vulnerability — grants the attacker direct network access to every critical asset in the organization. The currently compromised billing-srv-01 can directly query the EHR database on port 5432, reach the domain controllers on port 445, communicate with 120 infusion pumps on ports 80/443, and access the backup NAS management interface. This is not a theoretical risk; the attacker is already on the network.

**Potential Impact:** Lateral movement from any compromised system to all critical assets. The billing-srv-01 attacker has had 14+ days of unrestricted network access to EHR, PACS, domain controllers, medical devices, and backup infrastructure. PHI exfiltration, ransomware propagation (as demonstrated in January), credential theft via SMB relay, and medical device tampering are all achievable from the current foothold. A ransomware operator who gains access to any single system could encrypt all servers and the NAS simultaneously — production and backup in one stroke.

---

### GAP-002: Active Compromise on billing-srv-01 — Uncontained for 14+ Days

**Title:** Cryptominer running as www-data on billing-srv-01 with outbound connections to three mining pools; no containment, eradication, or investigation initiated

**Affected Asset(s):**
- billing-srv-01 (Critical, actively compromised)
- All servers on 10.10.2.0/24 (reachable from compromised host via flat network)
- All medical devices on 10.10.3.0/24 (reachable via flat network)

**Data at Risk:**
- Financial/Billing Data (Restricted) — MySQL database on billing-srv-01 containing patient financial data, insurance IDs, and claims information; attacker has www-data access with potential database read capability
- System Credentials (Restricted) — Application configuration files in Apache web root may contain database credentials; SSH keys or service accounts may be accessible
- Patient Medical Records (Restricted) — ehr-db-01 is one network hop away on port 5432; attacker can directly query the EHR database

**Current Control Status:**
- C-008 (Sophos) — Does NOT cover Linux servers; no endpoint protection on billing-srv-01
- C-014 (Server logging) — Local syslog only; no alerting; nobody reviewed the logs
- C-001 (FortiGate) — No egress filtering (Rule 4 allows ALL outbound); mining pool connections not blocked
- Sysadmin treated this as a performance issue and recommended hardware upgrade (Task 2)

**What is Missing:**
- Technical / Detective — No Linux endpoint protection, no IDS/IPS, no SIEM alerting, no process monitoring
- Technical / Preventive — No egress filtering on firewall; no WAF to prevent Apache exploitation
- Administrative / Corrective — No incident response plan to trigger containment, investigation, or eradication
- Technical / Corrective — No tested recovery procedure; backup may contain compromised data

**Risk Level:** Critical

**Risk Justification:** This is not a gap in protection — it is an active, confirmed security breach that has been running for over two weeks with zero security response. The attacker has sustained access to a server on the flat network with database credentials, outbound connectivity, and unrestricted lateral access to all critical assets. The server was already compromised once (January ransomware) through the same Apache vulnerability, rebuilt without patching, and re-exploited. This represents a complete failure of detection, response, and remediation cycles.

**Potential Impact:** The attacker has had 14+ days to exfiltrate billing data containing patient financial information (SSNs, insurance IDs). They may have already pivoted to the EHR database, domain controllers, or medical devices — no forensic investigation has been conducted to determine the scope of compromise. If the attacker chooses to deploy ransomware instead of (or in addition to) mining, the entire server infrastructure and co-located backup are at risk. Every day this remains uncontained, the potential scope of data exfiltration and lateral compromise grows.

---

### GAP-003: No Centralized Log Management or SIEM

**Title:** Security-relevant logs are siloed across 8+ independent systems with no aggregation, correlation, alerting, or centralized retention

**Affected Asset(s):**
- All servers (ehr-srv-01, ehr-db-01, pacs-srv-01, billing-srv-01, ad-dc-01/02, file-srv-01, print-srv-01, backup-srv-01, web-srv-01)
- FortiGate 100F firewall
- All ~485 workstations across three sites
- All ~210 medical devices (generating no centralized logs)
- Shadow IT systems (UNKNOWN-01, UNKNOWN-02, Raspberry Pi)

**Data at Risk:**
- Audit Logs & Security Telemetry (Confidential) — Log data revealing user activity patterns, authentication events, system architecture, and security-relevant events
- All Restricted data categories — because without detection, compromise of any data goes unnoticed

**Current Control Status:**
- C-013 (FortiGate local logs) — 30-day retention, not forwarded
- C-014 (Server logging) — Local /var/log, manual review only, no alerting
- C-016 (EHR audit log) — Vendor-managed, 48-hour export delay
- Marcus researched Wazuh SIEM but never installed it (Artifact 8)

**What is Missing:**
- Technical / Detective (Centralized) — No SIEM, no log aggregation, no correlation engine
- Technical / Detective (Automated) — No automated alerting on security events
- Administrative / Detective — No scheduled log review process, no designated log reviewer
- Technical / Detective (Log integrity) — No hashing, no write-once storage, no tamper protection

**Risk Level:** Critical

**Risk Justification:** The absence of centralized detection is the reason the billing-srv-01 cryptominer ran for 14 days undetected. It is the reason no one noticed the January ransomware until finance couldn't process claims on Monday morning. It is the reason that the EHR database could be queried by an attacker without any alert being generated. Without detection capability, every other control becomes reactive — MedDefense learns about compromises when systems fail or someone complains, not when security events occur. The 48-hour EHR audit log delay means that even when a PHI access anomaly is identified, the window for response is measured in days, not minutes.

**Potential Impact:** Continued undetected compromise. The current billing-srv-01 attacker could exfiltrate the entire EHR database over a weekend without triggering any alert. A new attacker could compromise a domain controller, create backdoor accounts, and maintain persistent access for months before being discovered — if ever. Medical device tampering could go undetected until a patient is harmed and a clinical investigation traces the cause. The organization has no evidentiary capability for post-incident forensics because logs are ephemeral, uncorrelated, and unprotected.

---

### GAP-004: No Multi-Factor Authentication on Any System Except One Personal Account

**Title:** MFA is documented as "recommended" but not enforced; 2,000 users authenticate to all systems with single-factor credentials

**Affected Asset(s):**
- ad-dc-01/ad-dc-02 (Critical) — Domain admin authentication is password-only
- ehr-srv-01/ehr-db-01 (Critical) — EHR application access is password-only
- billing-srv-01 (Critical) — Billing application access is password-only
- web-srv-01 (High) — Patient portal authentication is password-only
- All ~485 workstations — Windows login is password-only
- O365/Exchange (High) — Email access is password-only
- FortiGate 100F (Critical) — Firewall admin access — MFA status unknown

**Data at Risk:**
- Patient Medical Records (Restricted) — Accessible via any compromised credential
- Financial/Billing Data (Restricted) — Accessible via any compromised credential
- Employee HR Records (Confidential) — Accessible via any compromised credential
- System Credentials (Restricted) — Domain admin credentials grant access to all systems
- Patient Portal Data (Restricted) — Accessible via credential stuffing (Incident B proved broken access control)

**Current Control Status:**
- C-006 (Password policy) — 8-char minimum, 90-day rotation, complexity. Weak by modern standards.
- C-015 (MFA recommendation) — Policy states "recommended" but not required; only James Chen's personal account has MFA

**What is Missing:**
- Technical / Preventive — MFA enforcement on all remote access (VPN, O365, patient portal)
- Technical / Preventive — MFA on privileged accounts (domain admins, server admins, firewall admin)
- Technical / Preventive — MFA on EHR and billing application access
- Administrative / Preventive — Updated MFA policy with enforcement timeline

**Risk Level:** Critical

**Risk Justification:** Single-factor authentication with an 8-character minimum password policy is trivially defeated by modern attack techniques. Phishing (Sophos detected Phish.URL on WS-ADMIN-03 8 days ago), credential stuffing (patient portal has no rate limiting), and password spraying (lockout after 5 attempts for 30 minutes is a weak deterrent) are all viable attack vectors. The phishing detection proves active phishing campaigns are targeting MedDefense. Once a single credential is compromised, the flat network and absence of MFA mean the attacker can access every system that credential has permissions for — potentially including domain admin if a privileged user is phished.

**Potential Impact:** A single successful phishing email to a domain admin, IT staff member, or clinical user provides authenticated access to EHR, billing, file shares, and email. If the compromised account has elevated privileges, the attacker can create persistent backdoor accounts, modify group policies, exfiltrate PHI, and deploy ransomware — all while appearing as a legitimate authenticated user. The January ransomware may have entered this way. Without MFA, there is no second factor to stop a compromised credential from becoming a full system breach.

---

### GAP-005: Backup Infrastructure — Single Point of Failure with No Offsite Replication

**Title:** Veeam backups and production servers share the same physical room, rack, and network; no offsite/cloud replication; critical assets excluded from backup

**Affected Asset(s):**
- backup-srv-01 (Critical) — Backup server
- NAS-01 (Critical) — Backup target, same room/rack as production
- pacs-srv-01 (Critical) — NOT backed up ("too large")
- ad-dc-02 (Critical) — NOT backed up ("redundant with ad-dc-01")
- ws-srv-01 (High) — Westside server, NOT backed up ("not in scope")
- O365 data (High) — NOT backed up locally ("Microsoft handles it")
- All medical device configurations — NOT backed up

**Data at Risk:**
- Patient Medical Records (Restricted) — EHR backup is co-located with production; ransomware destroys both
- Medical Imaging Data (Restricted) — PACS has NO backup; imaging studies are irretrievable if lost
- Financial/Billing Data (Restricted) — Billing backup exists but may contain compromised data from current infection
- Employee HR Records (Confidential) — File share backup is co-located; correlated failure risk

**Current Control Status:**
- C-009 (Veeam backup) — Weak: local NAS only, no offsite replication, 14-day retention, never DR-tested
- Cloud backup quote ($14,400/year) denied by CFO (Artifact 5)
- January ransomware recovered from 3-week-old backup due to misconfigured cron job

**What is Missing:**
- Technical / Corrective — Offsite/cloud backup replication (AWS S3 quote denied)
- Technical / Corrective — Backup coverage for PACS, ad-dc-02, Westside server, O365, medical devices
- Technical / Corrective — Tested disaster recovery procedure (never performed)
- Administrative / Corrective — Disaster recovery plan and business continuity plan (do not exist)

**Risk Level:** Critical

**Risk Justification:** The backup system represents the organization's last line of defense, and it is stored in the same room as the systems it protects. If ransomware encrypts the servers (as it did in January), it will also encrypt the NAS on the same network. If there is a fire, flood, or physical theft in the server room, production and backup are lost simultaneously. PACS imaging has no backup at all — years of diagnostic studies would be permanently lost. The secondary domain controller has no backup — if ad-dc-01 fails, recovery depends entirely on ad-dc-02 remaining functional. Recovery has never been tested; the one partial test (file-srv-01, 8 months ago) took 6 hours for a single server. Full recovery of all systems would take days to weeks assuming the backups are intact — which they may not be.

**Potential Impact:** In a ransomware scenario, MedDefense loses all production systems AND all backups simultaneously. The January ransomware incident — 4 days of billing downtime with a 3-week-old backup — would be repeated across EHR, billing, file shares, and the website simultaneously. Full recovery time would be measured in weeks. During that time, the hospital would operate on paper records, medication orders would be unverifiable, imaging studies would be unavailable, and patient safety would be directly endangered. PACS imaging, if lost, cannot be recovered — patient diagnostic histories are permanently destroyed.

---

### GAP-006: No Incident Response Plan, Disaster Recovery Plan, or Business Continuity Plan

**Title:** No documented procedures exist for responding to security incidents, recovering from disasters, or maintaining clinical operations during IT outages

**Affected Asset(s):**
- Organization-wide — all assets, all sites, all departments

**Data at Risk:**
- All data categories — because unstructured response leads to evidence destruction, incomplete remediation, and prolonged exposure
- Patient Medical Records (Restricted) — clinical operations depend on EHR; no documented fallback procedure exists beyond ad-hoc paper records

**Current Control Status:**
- C-009 (Veeam backup) — Exists but is the only corrective control and is inadequate (see GAP-005)
- January ransomware response was "improvised for 4 days" per Marcus's notes
- No IR plan, no DR plan, no BCP documented anywhere in the provided materials

**What is Missing:**
- Administrative / Corrective — Formal incident response plan with roles, responsibilities, and escalation procedures
- Administrative / Corrective — Disaster recovery plan with RTO/RPO definitions and recovery procedures per system
- Administrative / Corrective — Business continuity plan for clinical operations during IT outages
- Administrative / Corrective — Post-incident review process for lessons learned
- Administrative / Corrective — Communication plan for breach notification (HIPAA Breach Notification Rule compliance)

**Risk Level:** Critical

**Risk Justification:** MedDefense has already experienced multiple incidents (January ransomware, patient portal broken access control, pharmacy dosage error, website defacement, EHR outage, intern laptop on network) and responded to none of them through a structured process. The January ransomware took 4 days to resolve through improvisation. The billing-srv-01 cryptominer has been running 14+ days with no response. The EHR outage (Incident E) forced physicians to paper records with no documented procedure. Each incident resulted in lost forensic evidence (server was restarted, logs overwritten), incomplete remediation (Apache vulnerability not patched after rebuild), and no organizational learning. Without IR/DR/BCP, every future incident will be handled the same way — chaotically, slowly, and with greater damage than necessary.

**Potential Impact:** The next ransomware incident (and based on current posture, it is a matter of when, not if) will result in days-to-weeks of clinical disruption, potential patient harm from inability to access medical records, permanent loss of unbacked-up data (PACS, O365), regulatory penalties for delayed breach notification, and reputational damage. The lack of a DR plan means that even a non-malicious event (power failure, hardware failure, natural disaster) could cause extended outages with no documented recovery path. The UPS provides only 20 minutes of power — after that, clinical operations depend on procedures that do not exist.

---

### GAP-007: Medical Device Network Exposure — No Isolation for Life-Critical IoT

**Title:** 120 BD Alaris infusion pumps and 80 Philips patient monitors with known vulnerabilities are on the same network as all IT systems with no segmentation or compensating controls

**Affected Asset(s):**
- BD Alaris infusion pumps, 120 units (Critical) — Firmware 12.1.2, known CVEs, vendor security bulletin recommending network isolation (18 months old, not implemented)
- Philips IntelliVue monitors, 80 units (Critical) — Firmware unknown, management interfaces exposed
- MRI workstation WS-RAD-01 (Critical) — Windows XP SP3, EOL since 2014
- MON-VITALS-3F-01 (Critical) — Unknown vendor, firmware v2.1.3 last updated 2019, IP/firmware displayed on screen

**Data at Risk:**
- Medical Device Operational Data (Restricted) — Real-time patient vitals, medication delivery records, device configurations
- Patient Medical Records (Restricted) — Medical devices may bridge to EHR/PACS networks

**Current Control Status:**
- No controls exist for medical devices (Task 10 Coverage Map: BD Alaris pumps = Unprotected)
- C-021 (proposed VLAN isolation) — Designed in Task 6, not deployed
- C-022 (proposed host firewall/whitelisting) — Designed in Task 6, not deployed
- C-023 (proposed monitoring/alerting) — Designed in Task 6, not deployed
- BD Alaris vendor security bulletin recommending network isolation — not followed for 18 months

**What is Missing:**
- Technical / Compensating — Network segmentation isolating medical devices from general IT
- Technical / Preventive — Host-based firewalls on medical devices
- Technical / Detective — IDS monitoring medical device traffic
- Technical / Corrective — Backup of medical device configurations
- Administrative / Preventive — Medical device security policy and inventory management

**Risk Level:** Critical

**Risk Justification:** These are not data servers where a breach means stolen information — these are devices that directly deliver medication and monitor patient vitals. The BD Alaris pumps deliver intravenous medication at controlled rates; an integrity compromise could alter dosage, causing overdose or underdose. The Philips monitors display real-time vital signs; an integrity compromise could suppress alarms or fabricate normal readings during a cardiac event. The vendor has explicitly stated (18 months ago) that network isolation is required as a security mitigation. This guidance has been ignored. The MRI workstation runs Windows XP (EOL 2014) with no compensating controls, on the same network as a currently compromised server. These devices represent the most direct path from cyber compromise to patient death in the entire MedDefense environment.

**Potential Impact:** An attacker who reaches the BD Alaris pump fleet (trivially achievable from billing-srv-01 or any compromised endpoint on the flat network) could alter medication delivery rates for 120 pumps simultaneously. A patient receiving heparin at 10x the prescribed rate would suffer a fatal hemorrhage. Suppressing a Philips monitor's cardiac alarm during an arrhythmia event would delay clinical response, potentially causing preventable death. These are not hypothetical scenarios — the vulnerabilities are known, the devices are exposed, and the access path exists through the currently compromised billing-srv-01.

---

### GAP-008: Apache 2.4.29 Vulnerability on Multiple Servers — Known RCE, Exploited Twice, Unpatched

**Title:** billing-srv-01 and web-srv-01 run Apache 2.4.29 with known remote code execution vulnerabilities (CVE-2021-41773, CVE-2021-42013); billing-srv-01 was exploited twice

**Affected Asset(s):**
- billing-srv-01 (Critical, actively compromised) — Apache 2.4.29, exploited for ransomware (January) and cryptominer (current)
- web-srv-01 (High) — Apache 2.4.29, same version, public-facing in DMZ, suspected vulnerable
- Any other server running Apache (unknown — no vulnerability scan has been performed)

**Data at Risk:**
- Financial/Billing Data (Restricted) — billing-srv-01 database accessible to attacker via www-data
- Patient Portal Data (Restricted) — web-srv-01 processes patient lab results, appointments, and provider messages
- System Credentials (Restricted) — Apache process may have access to application configuration files containing database credentials

**Current Control Status:**
- C-001 (FortiGate) — Perimeter firewall allows HTTP/HTTPS to web-srv-01; does not inspect or filter exploit payloads
- C-002 (DMZ) — web-srv-01 is in DMZ but the vulnerability is in the application layer, not blocked by network placement
- C-020 (TLS/HTTPS) — Encrypts transport but does not prevent exploitation of the web server itself
- No WAF (Web Application Firewall) deployed
- No vulnerability scanning performed on any server

**What is Missing:**
- Technical / Preventive — Apache patch/update to version 2.4.58+ or later on all servers
- Technical / Preventive (Compensating) — WAF in front of public-facing web servers
- Technical / Detective — Vulnerability scanning program for all servers
- Administrative / Corrective — Rebuild procedure mandating vulnerability remediation before production deployment

**Risk Level:** Critical

**Risk Justification:** This vulnerability has already been exploited twice on billing-srv-01 — first delivering ransomware, then delivering a cryptominer. The server was rebuilt between incidents but the vulnerability was not patched, proving that MedDefense's rebuild procedures do not include security remediation. web-srv-01 runs the same Apache version and is publicly accessible — it is the most likely candidate for the next compromise. The January incident demonstrates that this is not a theoretical risk; it is a confirmed, repeated pattern.

**Potential Impact:** web-srv-01 exploitation would compromise the patient portal, exposing PHI for all portal users and potentially providing a foothold into the internal network (the DMZ is separated from internal, but the server may have application-level connections to backend databases). If the same attacker who compromised billing-srv-01 also exploits web-srv-01, they gain a second persistent foothold with public-facing access. Any other server running Apache 2.4.29 (unknown — no scan performed) is equally at risk. Until Apache is patched or a WAF is deployed, these servers will continue to be exploited.

---

### GAP-009: Unmanaged Shadow IT Systems on Production Network

**Title:** At least 4 undocumented systems exist on MedDefense's network with no owner, no security controls, and no oversight

**Affected Asset(s):**
- UNKNOWN-01 (10.10.2.99) — Linux device on server subnet, SSH + web services on 8888/9090; Sarah: "no idea what this is"
- UNKNOWN-02 (10.10.10.200) — Linux device at Westside, SSH + port 3000; Sarah: "someone plugged something in"
- Raspberry Pi (A-040) — 2nd floor Central, network monitor set up by departed intern/Marcus; credentials unknown
- Dr. Patel's NAS (A-038) — Personal consumer NAS on Cardiology network, potential PHI storage
- iPad fleet (~25 units) — Unmanaged mobile devices accessing EHR during physician rounds

**Data at Risk:**
- Patient Medical Records (Restricted) — Raspberry Pi may contain captured network traffic with PHI and credentials; iPads cache EHR data locally
- Medical Device Operational Data (Restricted) — Unknown systems may have access to medical device network
- System Credentials (Restricted) — Raspberry Pi may contain captured Kerberos/LDAP/SMB authentication traffic
- Research Data (Restricted) — Dr. Patel's NAS stores cardiology research with possible patient identifiers
- Marketing/Strategic Data (Confidential) — Marketing Google Drive contains patient testimonials and strategic documents (cloud-based, separate risk profile)

**Current Control Status:**
- No control from the Task 10 matrix covers any of these systems
- They are invisible to Sophos (not enrolled), invisible to Veeam (not in scope), invisible to logging (not forwarding), and invisible to physical security (in unlocked areas or cloud-based)
- The Raspberry Pi has been running unattended for 3-6 months

**What is Missing:**
- Technical / Preventive — NAC (Network Access Control) to prevent unauthorized devices from connecting to the network
- Technical / Detective — Network device profiling and anomaly detection to identify new/unknown devices
- Administrative / Preventive — Technology procurement and approval policy
- Administrative / Detective — Regular asset reconciliation between network scans and asset registry

**Risk Level:** High

**Risk Justification:** Each undocumented system represents an unmonitored attack surface. The Raspberry Pi is the highest risk — it was designed to capture network traffic, meaning it likely contains months of captured packets including credentials and PHI. UNKNOWN-01 sits on the server subnet (where all critical assets reside) running web services with unknown vulnerabilities. Dr. Patel's NAS stores potential PHI on a consumer device with default credentials and unpatched firmware. The iPads access EHR data on unmanaged devices that leave the building daily. These systems exist because MedDefense has no process to prevent or detect their deployment.

**Potential Impact:** An attacker who compromises any shadow system gains an unmonitored foothold — no logs, no alerts, no Sophos detection, no backup visibility. The Raspberry Pi could be used as a credential harvesting platform (captured authentication traffic) or a C2 relay. UNKNOWN-01 on the server subnet provides direct access to EHR, PACS, and domain controllers. Dr. Patel's NAS, if exploited via known consumer NAS vulnerabilities, exposes research data containing PHI and becomes another lateral movement platform. The iPads, if lost or stolen, expose cached patient data with no remote wipe capability.

---

### GAP-010: No Vulnerability Management Program

**Title:** No systematic process exists for identifying, prioritizing, and remediating vulnerabilities across MedDefense's infrastructure

**Affected Asset(s):**
- All servers (12 active, various OS versions including EOL Ubuntu 18.04, Windows Server 2012 R2)
- All endpoints (~485 Windows 10/11, some with outdated Sophos signatures)
- Medical devices (Windows XP MRI, firmware 12.1.2 BD Alaris with known CVEs, 2019 firmware vitals monitor)
- Network devices (Cisco switches with unknown firmware, Netgear consumer router)
- Shadow IT systems (unknown OS, unknown patch level)

**Data at Risk:**
- All Restricted and Confidential data — vulnerability exploitation is the primary vector for data compromise
- Specifically: billing-srv-01 Apache RCE (already exploited), BD Alaris CVEs (ignored for 18 months), MRI Windows XP (EOL 10+ years), print-srv-01 Windows Server 2012 R2 (EOL 2023)

**Current Control Status:**
- No vulnerability scanner is deployed
- No vulnerability scan has ever been performed
- Marcus noted "formal vulnerability assessment of all servers" as something he "hadn't gotten to"
- No patch management process documented
- EOL systems (print-srv-01, billing-srv-01, MRI) remain in production with no compensating controls

**What is Missing:**
- Technical / Detective — Vulnerability scanning (Nessus, OpenVAS, or equivalent) on all assets
- Technical / Preventive — Patch management process for OS and application updates
- Administrative / Preventive — Vulnerability management policy with remediation SLAs
- Technical / Compensating — Compensating controls for systems that cannot be patched
- Administrative / Corrective — Risk acceptance documentation for systems that cannot be remediated within SLA

**Risk Level:** High

**Risk Justification:** MedDefense operates multiple EOL/unsupported systems (Windows XP MRI, Windows Server 2012 R2 print server, Ubuntu 18.04 billing server) with no documented vulnerability assessment, no patch management, and no compensating controls. The Apache vulnerability on billing-srv-01 was exploited twice because nobody identified or patched it. The BD Alaris CVEs were identified by the vendor 18 months ago but never acted upon. Without a vulnerability management program, MedDefense cannot know what its exposure surface looks like — it is operating blind with known-vulnerable systems on a flat network.

**Potential Impact:** Continued exploitation of known vulnerabilities. The Apache RCE that compromised billing-srv-01 likely exists on web-srv-01 and potentially other servers. The BD Alaris pump vulnerabilities remain exploitable from any network device. The print server's EOL OS has hundreds of known vulnerabilities. Without scanning, MedDefense cannot prioritize remediation — the Board cannot make informed budget decisions about what to fix first because nobody has quantified the vulnerability landscape. Every unpatched vulnerability is a potential entry point for the next ransomware, cryptominer, or data exfiltration attack.

---

### GAP-011: Physical Security Failures Across Critical Infrastructure Areas

**Title:** Server room, network closets, and fire exits lack adequate physical access controls, surveillance, and monitoring

**Affected Asset(s):**
- Central server room (contains all Critical servers, NAS, domain controllers)
- 2nd-floor network closet (unlocked, contains switches, patch panels, and laminated admin credentials)
- MRI control room (Windows XP workstation accessible)
- Westside server closet (no lock on door)
- Emergency exit between public area and IT/administrative wing

**Data at Risk:**
- System Credentials (Restricted) — Laminated switch admin credentials taped to wall in unlocked closet
- Patient Medical Records (Restricted) — Server room contains ehr-db-01 with all patient data
- Financial/Billing Data (Restricted) — Server room contains billing-srv-01
- All backup data — Server room contains NAS-01 with all backups

**Current Control Status:**
- C-010 (Guard service) — Weak: main entrance only, business hours only, no patrols
- C-011 (CCTV) — Weak: no cameras in server room, network closets, or administrative wing
- Badge access uses generic badges shared by all 2,000 employees
- No visitor log for server room access
- 2nd-floor network closet door is ajar with no lock
- Westside server closet door does not lock
- Emergency exit propped open with handwritten "do not close" sign

**What is Missing:**
- Physical / Preventive — Dedicated badge access (not generic) for server room with individual attribution
- Physical / Detective — Cameras covering server room door, network closets, and administrative wing
- Physical / Preventive — Locks on all network closets and Westside server closet
- Physical / Preventive — Door alarms or alerts on fire exits and restricted area doors
- Administrative / Preventive — Visitor access log and escort policy for server room
- Administrative / Corrective — Physical security incident response procedure

**Risk Level:** High

**Risk Justification:** Physical access to the server room grants direct access to all critical servers, the backup NAS, and the domain controllers. Any of 2,000 employees can enter using a generic badge with no audit trail. The 2nd-floor network closet provides switch admin credentials to anyone who walks by. The fire exit provides unauthenticated access from a public waiting area to the IT department. Marcus escalated server room access to Sarah Park 5 months ago; she said it was "on the roadmap." The pattern of documented risk ignored by IT operations is consistent with the authority gap between James (security) and Sarah (IT).

**Potential Impact:** Physical access to the server room enables disk cloning, memory extraction, console-level access to domain controllers, USB malware injection, and direct hardware sabotage. The exposed network credentials enable remote switch reconfiguration from any location. The propped fire exit allows social engineers to walk from the public waiting area to IT staff workstations, where they can observe screens, steal documentation, or plug in rogue devices. These are not theoretical — the conditions have persisted for months and were documented by Marcus before his departure.

---

### GAP-012: Endpoint Protection Gaps — No Coverage on Servers, Linux, or Mobile Devices

**Title:** Sophos endpoint protection covers only Windows workstations; Windows servers, all Linux servers, iPads, and medical devices have zero endpoint protection

**Affected Asset(s):**
- Windows servers (15 units) — NOT covered (server license not purchased)
- Linux servers (ehr-srv-01, ehr-db-01, billing-srv-01, backup-srv-01, web-srv-01, UNKNOWN-01, UNKNOWN-02) — NOT covered (not supported by current tier)
- iPads (~25 units) — NOT covered (no MDM deployed)
- Medical devices (~210 units) — NOT covered
- 15 Sophos-managed devices not reporting (possibly decommissioned, lost, or compromised)

**Data at Risk:**
- Patient Medical Records (Restricted) — EHR servers have no endpoint protection
- Financial/Billing Data (Restricted) — billing-srv-01 has no endpoint protection (cryptominer was not detected)
- Medical Device Operational Data (Restricted) — Medical devices have no endpoint protection

**Current Control Status:**
- C-008 (Sophos) — Adequate on Windows workstations (88.1% coverage); completely absent on all other platforms
- Marcus requested server protection license 4 months ago — budget not approved
- No alternative EDR/XDR solution deployed

**What is Missing:**
- Technical / Preventive — Endpoint protection on Windows servers (license purchase required)
- Technical / Preventive — EDR/XDR on Linux servers (Sophos or alternative)
- Technical / Preventive — MDM for iPad fleet
- Technical / Detective — Process monitoring and file integrity monitoring on all servers
- Technical / Detective — Behavioral analysis on medical devices (where supported)

**Risk Level:** High

**Risk Justification:** The billing-srv-01 cryptominer ran for 14 days undetected specifically because Sophos does not cover Linux servers. If endpoint protection had been deployed on billing-srv-01, the miner (PUA.CryptoMiner) would likely have been detected — Sophos successfully blocked a PUA.CryptoMiner on WS-FIN-12 just 15 days ago. The gap between workstation coverage (where detection works) and server coverage (where it doesn't) means that the most critical assets (servers) have less protection than the least critical (workstations). Windows servers without endpoint protection are also exposed — 15 server licenses at an estimated $20-40/device/year would cost roughly $300-600 annually.

**Potential Impact:** Malware on servers goes undetected until manual observation reveals symptoms (as happened with billing-srv-01). Cryptominers, ransomware, backdoors, and data exfiltration tools can run indefinitely on unprotected servers. The iPad fleet, if compromised or lost, exposes cached PHI with no remote wipe or device tracking capability. Medical devices without endpoint protection are exploitable without detection — a compromised infusion pump's altered behavior would only be noticed when a patient is harmed.

---

### GAP-013: Unencrypted Data in Transit Across Internal Network

**Title:** All sensitive data — PHI, financial data, credentials, and medical device telemetry — traverses the flat internal network without encryption

**Affected Asset(s):**
- ehr-db-01 (Critical) — PostgreSQL on port 5432, plaintext between app server and database
- pacs-srv-01 (Critical) — DICOM on port 104/11112, plaintext between imaging devices and PACS
- billing-srv-01 (Critical) — HTTP on port 80, plaintext between workstations and billing app
- All medical devices — HL7/DICOM/SIP on plaintext ports
- ad-dc-01/ad-dc-02 (Critical) — LDAP on port 389, plaintext (LDAPS on 636 available but unclear if enforced)
- file-srv-01 (High) — SMB on ports 139/445, encryption status unknown

**Data at Risk:**
- Patient Medical Records (Restricted) — EHR database queries traverse network in plaintext
- Medical Imaging Data (Restricted) — DICOM images traverse network in plaintext
- Financial/Billing Data (Restricted) — Billing credentials and data traverse network via HTTP
- System Credentials (Restricted) — LDAP/SMB authentication may traverse network in plaintext
- Medical Device Operational Data (Restricted) — HL7 telemetry and pump commands traverse network in plaintext

**Current Control Status:**
- C-020 (TLS/HTTPS) — Covers only web-srv-01 and patient portal external traffic
- C-018 (O365 encryption) — Covers only Microsoft cloud traffic
- No internal encryption between application servers and databases
- No DICOM TLS encryption
- No HTTP-to-HTTPS redirect on billing-srv-01

**What is Missing:**
- Technical / Preventive — TLS encryption for PostgreSQL connections (SSL mode on ehr-db-01)
- Technical / Preventive — DICOM TLS for imaging traffic
- Technical / Preventive — HTTPS for billing application
- Technical / Preventive — LDAP signing and channel binding enforcement
- Technical / Preventive — SMB encryption on file share connections

**Risk Level:** High

**Risk Justification:** The flat network (GAP-001) combined with unencrypted internal traffic creates a universal packet sniffing opportunity. Any compromised system on 10.10.0.0/16 can capture PHI, credentials, and financial data traversing the network. The billing-srv-01 attacker, running as www-data on the server subnet, is positioned to capture EHR database queries, PACS imaging transfers, and LDAP authentication traffic from adjacent systems. The network scan confirmed all subnets are reachable without restriction, meaning a single promiscuous-mode device anywhere on the network can intercept all sensitive traffic.

**Potential Impact:** An attacker with network access (already achieved via billing-srv-01) can capture patient medical records, imaging studies, billing credentials, and authentication tokens in transit. This enables passive data exfiltration without needing to compromise additional systems — the data simply flows past the attacker's network interface. Captured LDAP credentials could provide domain user hashes for offline cracking. Captured DICOM images constitute PHI exposure requiring breach notification. The combination of flat network + unencrypted traffic means that the entire data lifecycle (at rest, in transit, in use) is unprotected during the transit phase for every data category.

---

## Gap Distribution Summary

### Gaps by Risk Level

| Risk Level | Count | Gap IDs |
|------------|-------|---------|
| **Critical** | 9 | GAP-001, GAP-002, GAP-003, GAP-004, GAP-005, GAP-006, GAP-007, GAP-008, GAP-013 |
| **High** | 4 | GAP-009, GAP-010, GAP-011, GAP-012 |
| **Medium** | 0 | — |
| **Low** | 0 | — |
| **Total** | 13 | — |

### Gaps by Affected Asset Category

| Asset Category | Number of Gaps Affecting | Most Severe Gap |
|----------------|------------------------|-----------------|
| **Servers (all)** | 11 | GAP-001 (flat network), GAP-002 (active compromise), GAP-008 (Apache RCE) |
| **Medical IoT** | 5 | GAP-007 (no isolation for life-critical devices) |
| **Network Infrastructure** | 4 | GAP-001 (no segmentation), GAP-003 (no SIEM detection) |
| **Endpoints** | 3 | GAP-004 (no MFA), GAP-012 (no server endpoint protection) |
| **Data/Backup** | 3 | GAP-005 (backup single point of failure) |
| **Shadow IT** | 2 | GAP-009 (undocumented systems) |
| **Physical Security** | 2 | GAP-011 (physical access failures) |
| **Organization-wide** | 3 | GAP-003 (no SIEM), GAP-004 (no MFA), GAP-006 (no IR/DR/BCP) |

### Gaps by Control Category and Function

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---------|-----------|-----------|------------|-------------|-----------|
| **Technical** | GAP-001, GAP-004, GAP-008, GAP-010, GAP-012, GAP-013 | GAP-003, GAP-010, GAP-012 | GAP-005 | GAP-001, GAP-007, GAP-008, GAP-010 | — |
| **Administrative** | GAP-004, GAP-007, GAP-009, GAP-010 | GAP-009 | GAP-006 | GAP-007, GAP-010 | — |
| **Physical** | GAP-011 | GAP-011 | GAP-011 | GAP-011 | — |

### Concentration Analysis

**The gaps are most heavily concentrated in three areas:**

1. **Technical Preventive controls** (6 gaps) — The flat network, lack of MFA, unpatched Apache, no vulnerability management, no endpoint protection on servers, and unencrypted internal traffic all represent preventive control failures. This is the organization's largest deficit category.

2. **Technical Detective controls** (3 gaps) — No SIEM, no vulnerability scanning, no endpoint detection on servers/Linux/mobile. The organization is blind to active threats — it cannot detect, correlate, or alert on security events across any platform.

3. **Administrative Corrective controls** (1 gap, but organization-wide impact) — The absence of incident response, disaster recovery, and business continuity plans is a single gap that affects the entire organization's ability to recover from any incident.

**Critical insight:** Nine of thirteen gaps (69%) are rated Critical, meaning they affect Critical-rated assets or Restricted data and have no detective or corrective controls. This is not a situation with a few isolated weaknesses — it is a systemic posture problem where the majority of identified gaps pose existential risk to the organization's mission of patient care.

---

## The Story for the Board

MedDefense Health Systems operates a 350-bed hospital and two satellite facilities serving a community of 50,000+ patients, but protects its most critical data — patient medical records, diagnostic imaging, and financial information — with a security infrastructure that was never designed, never assessed, and never tested. The organization has experienced at least six security incidents in six months, including ransomware that halted billing for four days and a cryptominer that has been running on the billing server for over two weeks without detection. The single most critical vulnerability — a flat network connecting all servers, workstations, and life-saving medical devices — was identified five months ago and remains unfixed. The backup system that should provide recovery in a crisis sits in the same rack as the servers it protects, with no offsite copy. There is no plan for what to do when the next incident occurs.

The 13 gaps identified in this analysis are not independent — they form an interlocking chain of failure. The flat network (GAP-001) enables lateral movement from the compromised billing server (GAP-002) to the EHR database and medical devices (GAP-007). The lack of SIEM (GAP-003) means this movement goes undetected. The lack of MFA (GAP-004) means that stolen credentials provide persistent access. The lack of an incident response plan (GAP-006) means that when the compromise is eventually discovered, there is no structured process to contain it. And the co-located, untested backup (GAP-005) means that if ransomware strikes, there may be no recovery at all.

Fixing any single gap reduces risk incrementally. Fixing the flat network (GAP-001) and deploying a SIEM (GAP-003) together would transform the security posture from blind and permeable to monitored and segmented — the two highest-leverage investments MedDefense can make.
