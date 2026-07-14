# The Three Scenarios
## Integrated Threat Modeling for MedDefense Health Systems

**Date:** July 14, 2026  
**Classification:** CONFIDENTIAL – BOARD BRIEFING MATERIAL  
**References:** Task 2 BlackReef Profile, Task 3 Insider Analysis, Task 5 Supply Chain, Task 6 Threat Matrix, Task 7 Surface, Task 10 Kill Chains, Task 11 STRIDE, Task 13 ATT&CK  

---

## Scenario 1: External — "Operation Blackout"

**Title:** Operation Blackout  
**Threat Actor:** Organized Crime / RaaS Group (BlackReef Affiliate) — Task 6 Profile.  
**Motivation:** Financial Gain (Ransom Payment + PHI Data Sale).  
**Initial Vector:** Phishing / Spear Phishing (Human Surface + External Surface) — Task 7 Vector.  
**Attack Surface Exploited:** External (Web Server), Human (IT Admin), Internal (Flat Network).

### Attack Sequence
| Step | Action | ATT&CK Tactic / Technique |
|------|--------|---------------------------|
| **1** | Attacker sends spear phishing email to Sarah Park (IT Director) impersonating Fortinet Support. Link leads to malicious macro-enabled Word document. | **Initial Access** (T1566.001 — Spearphishing Attachment) |
| **2** | Macro executes PowerShell payload. Reverse shell connects to C2 server. Backdoor installed via Scheduled Task (disguised as Windows Update). | **Execution** (T1059.001 — PowerShell) + **Persistence** (T1053.005 — Scheduled Task) |
| **3** | Attacker runs `nltest` and `BloodHound` to map network. Identifies `ad-dc-01`, `ehr-db-01`, `NAS-01` on flat 10.10.0.0/16 subnet. | **Discovery** (T1046 — Network Service Discovery) |
| **4** | Attacker uses Mimikatz on Sarah's workstation to dump LSASS memory, capturing `svc_backup` Domain Admin hash. | **Credential Access** (T1003.001 — OS Credential Dumping) |
| **5** | Attacker performs Pass-the-Hash to `ad-dc-01`, gaining Domain Admin. Deploys GPO-based ransomware to all systems. Deletes backups on `NAS-01`. | **Lateral Movement** (T1550.002 — Pass the Hash) + **Impact** (T1486 — Data Encrypted for Impact) |

### STRIDE Categories Triggered
- **Spoofing:** Attacker spoofs identity of IT Admin and Backup Service.
- **Tampering:** Ransomware modifies files; GPO modifies system configurations.
- **Denial of Service:** EHR, billing, and clinical systems rendered unavailable.

### MedDefense Assets Impacted
- `ad-dc-01` / `ad-dc-02` (Active Directory)
- `ehr-srv-01` / `ehr-db-01` (Patient Data)
- `NAS-01` (Backup Storage)
- 2,000 Workstations (Clinical & Admin)

### Business Impact
- **Clinical:** Ambulance diversion, procedure cancellations, paper records for 14+ days.
- **Financial:** $2.7M–$5M recovery cost + lost revenue (per Task 0 industry benchmarks).
- **Regulatory:** HHS OCR investigation for HIPAA breach notification ($500K+ potential fine).
- **Reputational:** Public data leak, loss of patient trust, potential CEO turnover.

### Gaps Exploited
- **GAP-004 (No MFA):** Phishing credentials worked without second factor.
- **GAP-003 (No SIEM):** Malicious PowerShell, Mimikatz, and GPO changes went undetected.
- **GAP-001 (Flat Network):** Attacker moved from HR workstation to Domain Controller without restriction.
- **GAP-005 (Backup Co-location):** Backups deleted because they were on the same network as production.

### Detection Opportunities
1. **Step 1:** **Email Filtering / WAF.** (Missing Control). O365 ATP included in license but not configured.
2. **Step 2:** **Endpoint Detection (EDR).** (Gap: GAP-012). PowerShell logging would flag obfuscated commands.
3. **Step 4:** **SIEM Alerting.** (Gap: GAP-003). LSASS access triggers immediate alert (Wazuh).
4. **Step 5:** **Privileged Access Mgmt.** (Gap: GAP-004/GAP-017). MFA on Domain Admin prevents hash reuse.

---

## Scenario 2: Internal — "The Quiet Exit"

**Title:** The Quiet Exit  
**Threat Actor:** Malicious Insider (Terminating Employee — Billing Dept). Task 3 Profile.  
**Motivation:** Financial Gain (Selling PHI on Dark Web).  
**Initial Vector:** Legitimate Access Abused (Internal Surface + Human Surface) — Task 7 Vector.  
**Attack Surface Exploited:** Human (Employee), Internal (Workstation, Database).

### Attack Sequence
| Step | Action | ATT&CK Tactic / Technique |
|------|--------|---------------------------|
| **1** | Employee learns of impending layoff. Plans to exfiltrate patient data during final 3 weeks. | **Reconnaissance** (Pre-Attack Activity) |
| **2** | Employee accesses EHR read-only interface. Uses export function to download 200 records/day. Mixed with legitimate work. | **Collection** (T1005 — Data from Local System) |
| **3** | Employee transfers CSV files to personal USB drive. Copies database config file (plaintext credentials) to USB. | **Exfiltration** (T1048.002 — Exfil Over Physical Media) |
| **4** | Employee deletes local files to cover tracks. Relies on unreviewed audit logs for invisibility. | **Defense Evasion** (T1070.001 — Clear Event Logs) |
| **5** | Employee leaves. Account deactivated 5 days later due to manual ticket process. Connects via VPN post-departure using saved credentials. | **Persistence** (T1078 — Valid Accounts) |

### STRIDE Categories Triggered
- **Repudiation:** Insider denies access using shared accounts or lack of attribution in logs.
- **Information Disclosure:** 2,800+ patient records exposed.
- **Tampering:** Configuration files stolen could allow unauthorized DB access.

### MedDefense Assets Impacted
- `file-srv-01` (Workstation Storage)
- `ehr-db-01` (Patient Records)
- VPN Infrastructure
- 2,800 Patient Records (Exfiltrated)

### Business Impact
- **Clinical:** None directly (data theft, no alteration).
- **Financial:** ~$700K breach response cost (Task 13 Benchmark). Class action lawsuit.
- **Regulatory:** HHS OCR Breach Notification for 2,800+ individuals.
- **Reputational:** News leak, loss of competitive advantage in regional market.

### Gaps Exploited
- **GAP-016 (No DLP):** Bulk data export and USB copy not detected or blocked.
- **GAP-014 (Account Lifecycle):** Account remained active 5 days post-termination.
- **GAP-003 (No SIEM):** Unreviewed EHR audit logs meant high-volume access went unnoticed.
- **GAP-012 (No EDR):** USB storage and file deletion activities not monitored.

### Detection Opportunities
1. **Step 2:** **DLP Controls.** (Gap: GAP-016). Alert on >10 record exports per hour.
2. **Step 3:** **Removable Media Control.** (Gap: GAP-012). Disable USB via GPO.
3. **Step 5:** **Automated Offboarding.** (Gap: GAP-014). Sync HRIS to AD instantly.

---

## Scenario 3: Third Party — "Vendor Shadow"

**Title:** Vendor Shadow  
**Threat Actor:** Organized Crime (Compromising MedTech Solutions Vendor). Task 5 Profile.  
**Motivation:** Financial Gain (Espionage + Ransomware).  
**Initial Vector:** Supply Chain Compromise (Trusted Channel) — Task 7 Vector.  
**Attack Surface Exploited:** External (Vendor Network), Internal (Vendor Access Channel).

### Attack Sequence
| Step | Action | ATT&CK Tactic / Technique |
|------|--------|---------------------------|
| **1** | Attacker compromises MedTech Solutions internal workstation. Steals vendor RDP credentials used for EHR maintenance. | **Initial Access** (T1566 — Phishing at Vendor Side) |
| **2** | Attacker uses valid vendor credentials to RDP into `ehr-srv-01`. Access granted via "Trusted Vendor" rule in firewall. | **Resource Development** (T1586 — Acquire Access) |
| **3** | From `ehr-srv-01`, attacker pivots to `ad-dc-01` via flat network. Creates hidden backdoor admin account in Active Directory. | **Lateral Movement** (T1570 — Lateral Tool Transfer) |
| **4** | Attacker establishes persistent access via Scheduled Task on `ehr-srv-01`. Exfiltrates patient data slowly over 30 days. | **Persistence** (T1053.005 — Scheduled Task) + **Exfiltration** (T1567.001) |
| **5** | Attacker deploys ransomware via backdoor. Claims legitimate vendor maintenance caused the crash to delay suspicion. | **Impact** (T1486 — Data Encrypted) |

### STRIDE Categories Triggered
- **Spoofing:** Attacker pretends to be authorized vendor technician.
- **Info Disclosure:** PHI exfiltrated under guise of maintenance.
- **Repudiation:** Vendor blames MedDefense; MedDefense blames Vendor.

### MedDefense Assets Impacted
- `ehr-srv-01` (EHR Application)
- `ad-dc-01` (Domain Admin)
- `ehr-db-01` (Database)
- 50,000+ Patient Records (Long-term exposure)

### Business Impact
- **Clinical:** EHR downtime, potential data corruption.
- **Financial:** Vendor contract litigation ($145,000/year savings lost), remediation costs.
- **Regulatory:** Willful neglect penalties due to lack of vendor access controls.
- **Reputational:** Loss of trust in critical software partnership.

### Gaps Exploited
- **GAP-004 (No MFA on Vendor Access):** Stolen vendor password worked without 2nd factor.
- **GAP-001 (Flat Network):** Vendor access to EHR allowed pivot to Domain Controller.
- **GAP-017 (No Change Management):** Backdoor account created without review/approval.
- **GAP-003 (No SIEM):** Slow exfiltration blended with normal maintenance traffic.

### Detection Opportunities
1. **Step 2:** **Jump Host / Bastion.** (Gap: GAP-004). Force vendor access through MFA-enforced jump box.
2. **Step 3:** **Network Segmentation.** (Gap: GAP-001). Prevent EHR server from reaching Domain Controller.
3. **Step 4:** **Behavioral Analytics.** (Gap: GAP-003). Detect slow exfiltration patterns over time.

---

## Summary Comparison Table

| Feature | Scenario 1 (Ransomware) | Scenario 2 (Insider) | Scenario 3 (Supply Chain) |
|---------|-------------------------|----------------------|---------------------------|
| **Primary Risk** | Operational Shutdown | Data Privacy Breach | Long-term Compromise |
| **Most Critical Gap** | GAP-001 (Network) | GAP-014 (Lifecycle) | GAP-004 (MFA) |
| **Time to Impact** | Hours (Encryption) | Weeks (Accumulation) | Months (Stealth) |
| **Detection Feasibility** | High (if SIEM exists) | Medium (if DLP exists) | Low (if Trusted Channel) |
| **Board Priority** | **CRITICAL** (Survival) | **HIGH** (Liability) | **HIGH** (Trust) |

---

*Prepared by: Security Department*  
*References: Project 1x00 Gap Analysis, Task 2 BlackReef Profile, Task 3 Insider Analysis, Task 5 Supply Chain Assessment*
