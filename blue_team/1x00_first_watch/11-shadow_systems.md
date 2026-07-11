# 11. The Shadow Systems
## Shadow IT Risk Assessment & Response — MedDefense Health Systems

---

## Shadow System 1: Dr. Patel's Personal NAS (Cardiology)

### Risk Assessment

**What sensitive data might this system contain or provide access to?**

Dr. Patel is a cardiologist storing research data on a personal NAS. Given the context — a physician in a clinical department — this NAS likely contains:

- Patient-derived cardiology research data (ECG datasets, echocardiogram images, clinical observations tied to patient identifiers)
- Potentially copies of patient records exported from the EHR for research compilation
- Cardiac imaging studies possibly exported from PACS (DICOM files)
- Research correspondence, grant-related documents, or unpublished clinical findings
- Given that Dr. Patel cited the hospital shared drive being "too slow," he may also be storing working copies of active clinical documents, patient case studies, or referral letters

Even if Dr. Patel believes this is "just research data," any data derived from patient interactions — de-identified or not — carries HIPAA obligations. If patient identifiers are present (likely, given that research datasets often link back to patient records for longitudinal studies), this constitutes Restricted data stored on an unmanaged consumer device.

**What security controls from the official matrix (Task 10) do NOT cover this system?**

| Control | Coverage Status | Gap |
|---------|----------------|-----|
| C-001 (FortiGate Firewall) | ❌ No — NAS is behind the firewall on the internal network; no firewall rules protect it from lateral movement |
| C-004/C-005 (SSH Hardening) | ❌ No — personal NAS likely uses default or weak credentials; no SSH hardening |
| C-006 (AD Password Policy) | ❌ No — NAS authentication is local, not joined to Active Directory; no password complexity, rotation, or lockout enforcement |
| C-007 (Shared Account Management) | ❌ No — no oversight of who has access to the NAS |
| C-008 (Sophos Endpoint Protection) | ❌ No — NAS runs embedded Linux (Synology/QNAP/TerraMaster firmware); not a Sophos-supported platform |
| C-009 (Veeam Backup) | ❌ No — personal NAS is not in Veeam backup scope; no backup of research data exists |
| C-014 (Server Logging) | ❌ No — no centralized logging; NAS audit logs (if enabled) are local only and likely default |
| C-017 (NTFS Permissions) | ❌ No — NAS uses its own filesystem and permission model; no AD-integrated access control |
| C-018 (O365 Encryption) | ❌ No — data is on local hardware, not in Microsoft cloud |

**Every control in the matrix fails to cover this system.** The NAS is completely invisible to MedDefense's security infrastructure.

**Worst-case scenario if this system is compromised:**

An attacker who gains any foothold on the flat 10.10.0.0/16 network (e.g., through the currently compromised billing-srv-01) discovers the NAS via network scanning (as the Nmap scan already discovered similar devices). Consumer NAS devices (Synology, QNAP, TerraMaster) are notorious for unpatched firmware vulnerabilities — many have critical CVEs with public exploits. The attacker:

1. Exploits a known NAS firmware vulnerability to gain admin access
2. Exfiltrates all research data containing patient identifiers — a reportable HIPAA breach affecting an unknown number of patients
3. Uses the NAS as a persistent storage and staging point for attack tools, since it will never be audited or discovered by IT
4. Plants ransomware on the NAS, destroying irreplaceable research data with no backup
5. Uses the NAS as a pivot point to reach other systems on the cardiology department's network segment

Additionally, if the NAS is running services like SMB or NFS (typical for file sharing), it could be used to serve malicious payloads to other devices that mount its shares — turning a physician's personal storage into an attack distribution platform.

---

### Recommended Response: **Migrate**

**Justification:**

The legitimate business need is clear — Dr. Patel needs fast, accessible storage for large research datasets. The hospital's shared drive (file-srv-01, Windows Server 2016) is apparently too slow for his workflow, which suggests a performance issue that should be addressed through IT, not personal procurement.

**Migration plan:**

1. **Engage Dr. Patel diplomatically** — frame this as protecting his research, not punishing him. A physician who has invested personal funds in a NAS will resist being told to "just use the slow shared drive."
2. **Assess data sensitivity** — review what is stored on the NAS before migration. Determine if patient identifiers are present. If so, document the data types for HIPAA compliance.
3. **Provision high-performance storage** — allocate a dedicated high-speed share on file-srv-01 (or a new SSD-backed VM) specifically for Cardiology research. Alternatively, provision a departmental O365 SharePoint site with appropriate storage quotas.
4. **Migrate data** — copy all research data from the NAS to the approved system. Verify data integrity. Scan for malware during migration (since the NAS is untrusted).
5. **Secure-wipe and remove the NAS** — once data is verified on the approved system, securely wipe the NAS (multi-pass erase) and remove it from the network. Return it to Dr. Patel for personal use or repurpose it through IT.
6. **Apply controls** — the new storage location inherits all existing controls (NTFS permissions, Veeam backup, Sophos if on Windows, AD authentication, network monitoring).

This approach preserves the working relationship with Dr. Patel, addresses his performance concern, brings the data under governance, and eliminates the security risk without losing valuable research data.

---

### Asset Registry Update

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|--------------|-------------|-------------------|-----------------|--------|-------|
| A-038 | NAS-PATEL-01 | Data Store | Central, Cardiology Dept, Dr. Patel's office | Dr. Patel (Cardiology) | Unknown (personal consumer NAS) | Personal research data storage | 10.10.1.0/24 (workstations — assumed; IP not confirmed in scan) | Shadow IT | Purchased personally by Dr. Patel; plugged into wall port; stores research data (possible PHI); no IT oversight; no backup; default credentials likely; migration to approved storage recommended |

---

## Shadow System 2: Marketing Team's Shared Google Drive

### Risk Assessment

**What sensitive data might this system contain or provide access to?**

The marketing team's Google Drive, linked to a personal Gmail account, is used for "media files and press communications." While this sounds benign, healthcare marketing involves:

- Patient testimonials or case studies — potentially including patient names, photos, and medical conditions used with consent forms (the consent forms themselves are PHI)
- Press releases referencing hospital initiatives, partnerships, or clinical outcomes — premature disclosure could violate SEC regulations if MedDefense is considering any public offerings, or breach embargo agreements
- Internal strategic documents shared with marketing vendors — organizational plans, executive communications, vendor contracts
- Photographs of hospital facilities, staff, and possibly patients (if used in marketing materials) — identifiable images constitute PHI under HIPAA
- Communications with media outlets that may reference specific patient cases or clinical outcomes
- Crisis communication drafts — if a breach or incident occurs, pre-drafted communications may reference vulnerabilities or incident details

**Critical concern:** The Google Drive is linked to a **personal Gmail account**, not a managed O365 account. This means:

- There is no organizational password policy on the Gmail account
- There is no MFA enforcement (unless the individual personally enabled it)
- When the employee who owns the account leaves MedDefense, the organization loses access to all marketing assets
- Google's account recovery processes could grant access to someone who compromises the personal Gmail
- The personal Gmail may be used for other personal services, increasing the attack surface (password reuse, linked accounts, etc.)

**What security controls from the official matrix (Task 10) do NOT cover this system?**

| Control | Coverage Status | Gap |
|---------|----------------|-----|
| C-001 (FortiGate Firewall) | ❌ No — Google Drive is cloud-based; firewall does not inspect Google Drive traffic (no SSL inspection configured) |
| C-006 (AD Password Policy) | ❌ No — Gmail account uses Google's authentication, not Active Directory; no password complexity, rotation, or lockout |
| C-008 (Sophos Endpoint Protection) | ❌ No — cloud service; no endpoint control applicable |
| C-009 (Veeam Backup) | ❌ No — Google Drive data is not in Veeam scope; O365 backup is also absent but this data is in personal Google, not O365 |
| C-012 (Security Awareness Training) | ⚠️ Partial — marketing staff may have completed training, but training doesn't address cloud service governance |
| C-015 (MFA Recommendation) | ❌ No — MFA is "recommended" internally but this is an external personal account with no MedDefense control |
| C-018 (O365 Encryption) | ❌ No — data is in Google's cloud, not Microsoft's; MedDefense has no DLP or CASB to monitor cloud data egress |

**This system exists entirely outside MedDefense's security perimeter.** No technical or administrative control touches it.

**Worst-case scenario if this system is compromised:**

The personal Gmail account associated with the Google Drive is compromised through credential stuffing, phishing, or password reuse (common for personal accounts with no MFA). The attacker:

1. Gains access to all marketing materials, including patient testimonials with identifying information — a reportable HIPAA breach
2. Discovers internal strategic plans, executive communications, and vendor contracts — competitive intelligence that could be sold or leaked
3. Finds crisis communication drafts that may reference security vulnerabilities or incident details — providing an attacker with a roadmap of MedDefense's weaknesses
4. Modifies press materials or patient testimonials — inserting misinformation or damaging content that could be published before detection
5. Uses the compromised Gmail account to send phishing emails to other MedDefense staff that appear to come from a legitimate marketing contact — escalating the compromise inward
6. When the Gmail owner eventually leaves MedDefense, the account (and all its data) goes with them — organizational data is permanently lost or held hostage

---

### Recommended Response: **Migrate**

**Justification:**

Google Drive is a legitimate collaboration tool, but the issue is governance, not technology. The data and collaboration need to continue — but on a managed platform. MedDefense already pays $432,000/year for O365 E3 licenses, which include OneDrive and SharePoint — both are direct functional equivalents to Google Drive with organizational controls.

**Migration plan:**

1. **Identify the Gmail account owner** — likely a marketing team member. Engage Marketing leadership, not just the individual.
2. **Inventory all content** in the Google Drive — categorize by sensitivity (patient testimonials = Restricted, press releases = Internal/Public, strategic docs = Confidential).
3. **Create a managed SharePoint site** for Marketing under the O365 tenant — configure appropriate permissions, retention policies, and access reviews.
4. **Migrate all content** from Google Drive to SharePoint — verify file integrity and completeness. Scan for malicious content during migration.
5. **Transfer ownership** to a shared mailbox or distribution list, not an individual — so the data persists when team members change.
6. **Enable MFA** on the marketing team's O365 accounts (this should be done organization-wide but is especially critical here).
7. **Decommission the personal Google Drive** — secure-delete all MedDefense data from the personal account. Obtain written confirmation from the account owner that all organizational data has been transferred.
8. **Document the SharePoint site** in the asset registry as an approved application/data store.

This approach costs nothing in additional licensing (O365 is already purchased), leverages existing controls, and addresses the root cause: lack of a managed collaboration platform that marketing knew about and could use.

---

### Asset Registry Update

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|--------------|-------------|-------------------|-----------------|--------|-------|
| A-039 | GDRIVE-MKTG-01 | Application (Cloud) | Cloud (Google Workspace) | Marketing | Personal Gmail account | Marketing asset storage and collaboration | Internet (external) | Shadow IT | Linked to personal Gmail; contains media files, press communications, possibly patient testimonials (PHI); no MFA, no AD integration, no DLP/CASB monitoring; migration to O365 SharePoint recommended |

---

## Shadow System 3: Raspberry Pi Network Monitor (2nd Floor, Central)

### Risk Assessment

**What sensitive data might this system contain or provide access to?**

Marcus asked the previous intern to set up this Raspberry Pi as "some kind of network monitor." Depending on what software was deployed (likely tcpdump, Wireshark, Zeek/Bro, or similar), this device may have:

- **Packet captures of the entire flat network** — since it's on 10.10.1.0/24 (workstation subnet) with no segmentation, a network monitor in promiscuous mode can capture all traffic on the switch port it's connected to. Depending on switch configuration (port mirroring, or if the switch is flooding traffic), this could include:
  - EHR database queries (PostgreSQL on port 5432) passing between workstations and ehr-srv-01
  - DICOM imaging transfers between the MRI workstation and pacs-srv-01
  - SMB file share traffic containing HR documents and department files
  - LDAP/Kerberos authentication traffic to domain controllers
  - HTTP billing traffic (including credentials if billing uses basic auth)
  - Medical device telemetry (HL7, vital signs data)
- **Credential material** — if the Pi was configured with SSH keys for remote access, or if tcpdump captured authentication exchanges, credentials may be stored on the SD card
- **Network topology data** — captured traffic reveals the flat network architecture, device IPs, services running, and communication patterns — essentially a free reconnaissance report for any attacker
- **Marcus's configuration scripts** — may contain credentials for network devices, API keys, or other sensitive configuration data

**Critical concern:** Since both Marcus and the intern departed, **nobody knows the root password, what software is running, what services are exposed, or what data has been captured and stored.** The device has been running unattended for at least 3 months (intern vacancy duration) to 6 months (Marcus's departure). If it was accessible via SSH (typical for Raspberry Pi), and it was on the flat network, then anyone on 10.10.0.0/16 could potentially authenticate to it — and default Raspberry Pi credentials (pi/raspberry) are among the most commonly brute-forced credentials in existence.

**What security controls from the official matrix (Task 10) do NOT cover this system?**

| Control | Coverage Status | Gap |
|---------|----------------|-----|
| C-001 (FortiGate Firewall) | ❌ No — Pi is internal; no firewall rules protect it from lateral access |
| C-004/C-005 (SSH Hardening) | ❌ No — Marcus may have hardened it, but unknown; if default credentials remain, SSH is trivially exploitable |
| C-006 (AD Password Policy) | ❌ No — Pi uses local Linux authentication; not joined to AD |
| C-008 (Sophos Endpoint Protection) | ❌ No — Raspberry Pi runs Linux ARM; not covered by Sophos |
| C-009 (Veeam Backup) | ❌ No — Pi is not in Veeam scope; SD card is the only storage |
| C-014 (Server Logging) | ❌ No — Pi logs are local; no forwarding to central syslog |
| C-019 (Guest WiFi Isolation) | ❌ No — Pi is on the internal network, not guest |

**No control covers this device.** Additionally, because it was set up as a monitoring tool, it may have elevated network access (promiscuous mode, port mirroring) that gives it greater visibility than a standard endpoint.

**Worst-case scenario if this system is compromised:**

This device is, in some ways, the most dangerous shadow system of the three because it was **deliberately designed to capture network traffic.** If an attacker discovers it (and the Nmap scan may have already — the "UNKNOWN-01" at 10.10.2.99 with SSH and web services could potentially be this device, though the scan attributes that to the server subnet):

1. **Default credentials** (pi/raspberry) allow immediate SSH access if they were never changed
2. **Stored packet captures** are downloaded — providing the attacker with a complete map of network traffic patterns, including credentials, PHI, and internal service communications
3. **The Pi is used as a persistent foothold** — since nobody is monitoring it, the attacker can use it indefinitely as a staging point for attacks, a C2 relay, or a network sniffer capturing ongoing traffic
4. **Network configuration data** on the Pi (if Marcus stored notes, configs, or scripts) reveals switch credentials, firewall configurations, or other infrastructure details
5. **The Pi is used to inject traffic** — ARP spoofing, DNS hijacking, or man-in-the-middle attacks against clinical workstations on the same subnet
6. **The Pi is used to attack the flat network** — it has full access to 10.10.0.0/16 including servers, medical devices, and domain controllers

---

### Recommended Response: **Decommission**

**Justification:**

Unlike Dr. Patel's NAS (legitimate business need, poor implementation) or the Marketing Google Drive (legitimate collaboration, wrong platform), this Raspberry Pi was a **security tool** set up by a departed security analyst who can no longer explain its configuration, purpose, or security posture. It has no current owner, no documented purpose, and no maintenance plan.

**Decommissioning plan:**

1. **Physical discovery** — locate the Raspberry Pi on the 2nd floor. Document its physical state, what it's connected to (which wall port, any USB devices, SD card present).
2. **Capture forensic image** before powering off — if possible, image the SD card to preserve any captured traffic data, Marcus's scripts, and configuration files. This may contain evidence relevant to the billing-srv-01 investigation or reveal what Marcus was monitoring.
3. **Review stored data** — examine packet captures for exposed credentials (Kerberos tickets, LDAP binds, HTTP auth headers). If credentials are found in plaintext captures, those credentials must be rotated.
4. **Disconnect from network** — remove the Ethernet cable. Power off the device.
5. **Secure-wipe the SD card** — multi-pass erase to destroy any captured data.
6. **Document findings** — if the Pi was performing useful monitoring (e.g., capturing traffic that reveals security issues), note this as a capability gap. If centralized monitoring is needed (it is — see Gap G-004), it should be deployed as a managed SIEM/IDS solution, not a rogue Raspberry Pi.
7. **Do NOT repurpose the Pi** without a formal IT request, configuration standard, and assigned owner.

This approach eliminates the risk while preserving any forensic value the device may hold. If Marcus set it up to monitor for the very issues this assessment has uncovered, his instincts were right — but a single Raspberry Pi is not a sustainable security monitoring strategy. That capability belongs in a proper SIEM deployment.

---

### Asset Registry Update

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|----------|------|------|----------|--------------|-------------|-------------------|-----------------|--------|-------|
| A-040 | RPI-MONITOR-01 | Endpoint / Network Device | Central, 2nd Floor (location approximate) | Unknown (originally IT Security — Marcus Webb / former IT intern) | Raspberry Pi OS (Linux ARM) | Network traffic monitoring (purpose: tcpdump/Wireshark/Zeek — unconfirmed) | 10.10.1.0/24 (workstations — assumed) | Shadow IT | Set up by former intern at Marcus Webb's request; no current owner; credentials unknown; may contain captured network traffic (PHI, credentials); no backup, no monitoring, no patching; decommission recommended with forensic preservation |

---

## Shadow IT Cross-Reference with Network Scan

| Shadow System | Detected in Network Scan? | Matching Scan Entry? | Notes |
|---------------|---------------------------|---------------------|-------|
| Dr. Patel's NAS (A-038) | **Uncertain** | Possibly — if the NAS responds on standard ports, it may be among the ~290 unlisted workstations in 10.10.1.0/24. A consumer NAS typically shows ports 5000/5001 (Synology DSM), 139/445 (SMB), or 80/443. Cannot confirm without IP address. | Need to scan Dr. Patel's office port specifically or ask him for the IP |
| Marketing Google Drive (A-039) | **No** | N/A | Cloud-based external service; not visible on internal network scan. Would require CASB or SaaS discovery tooling to detect |
| Raspberry Pi (A-040) | **Possibly** | **10.10.2.99 (UNKNOWN-01)** — Linux 4.x, SSH + ports 8888/9090. However, scan places this in the SERVER subnet (10.10.2.0/24), not the 2nd-floor workstation subnet (10.10.1.0/24). Sarah noted: "Could be Marcus's or the intern's." The web services on 8888/9090 could be a monitoring dashboard (Grafana on 3000, Kibana on 5601, or Nagios on 8080 — 8888/9090 are less standard). | Alternatively, this could be the Westside mystery device (10.10.10.200) running on port 3000. Need physical verification of both locations |
| Westside mystery device (10.10.10.200, A-033) | **Yes** | Linux 5.x, ports 22/80/3000. Sarah: "Port 3000 is often Grafana or Node.js. Could be a monitoring tool someone set up unofficially." | This may be a SECOND Raspberry Pi or similar device at Westside, set up independently |

**Recommendation:** Physically locate the Raspberry Pi on the 2nd floor of Central and compare its MAC address and IP against the network scan results. If it matches 10.10.2.99, it may have been moved or connected to a different port than expected. If no match is found, it may have been powered off during the scan window or is using a different IP than recorded.

---

## Shadow IT Policy Recommendation

**The single most effective policy change to reduce future shadow IT at MedDefense is implementing a formal Technology Procurement and Approval Policy that requires all technology purchases — including personal devices brought into the workplace (BYOD) and cloud service subscriptions using organizational data — to be registered with IT before deployment, coupled with a fast-track approval process (72-hour SLA) so that legitimate needs like Dr. Patel's storage performance issue or the Marketing team's collaboration requirements can be met quickly through approved channels rather than driving staff to solve problems themselves with unvetted solutions.** The root cause of shadow IT at MedDefense is not malice or negligence — it is the absence of a responsive IT service request process. When Sarah Park's team takes weeks or months to provision storage, departments solve their own problems. A 72-hour approval SLA, with documented escalation paths to James Chen for security-sensitive requests, would address the velocity gap that drives shadow IT while giving the security team visibility into what enters the network before it becomes a risk.

---

## Summary: Shadow IT Risk Comparison

| Shadow System | Data Risk | Network Risk | Persistence Risk | Recommended Response | Priority |
|---------------|-----------|---------------|-----------------|---------------------|----------|
| Dr. Patel's NAS | High (potential PHI) | High (unpatched consumer device on flat network) | Medium (visible if scanned for) | Migrate to approved storage | **High** — address within 1 week |
| Marketing Google Drive | Medium-High (patient testimonials, strategic docs) | Low (cloud-based, no internal network exposure) | High (linked to personal Gmail, lost when employee departs) | Migrate to O365 SharePoint | **Medium** — address within 2 weeks |
| Raspberry Pi Monitor | Critical (may contain captured credentials and PHI) | Critical (unmanaged Linux on flat network with potential promiscuous access) | Critical (no owner, unknown credentials, running 3-6 months unattended) | Decommission with forensic preservation | **Critical** — address within 48 hours |

**Immediate Action Required:** The Raspberry Pi should be physically located and disconnected within 48 hours. Until it is located, it represents an unmanaged, credentialed Linux system on the flat network that may contain captured authentication data and PHI. It is also a potential pivot point for the currently active billing-srv-01 compromise — if the attacker on billing-srv-01 discovers the Pi, they gain a second persistent foothold with potential access to captured network traffic.
