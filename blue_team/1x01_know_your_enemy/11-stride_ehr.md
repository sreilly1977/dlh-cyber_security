# STRIDE Threat Model: MedDefense EHR System
## System Architecture: ehr-srv-01 + ehr-db-01 + Clinical Workstations + Network Paths

**Date:** July 14, 2026  
**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT  
**References:** Project 1x00 Asset Registry, Gap Analysis, Network Scan Summary  

---

## STRIDE Threat Inventory

### S – Spoofing (Identity Fraud)

| Threat ID | Description | Attack Vector | Impact | Existing Control | Gap |
|-----------|-------------|---------------|--------|------------------|-----|
| **EHR-S1** | **Clinician Credential Theft via Phishing**<br>Attacker steals nurse login credentials through spear phishing and logs into the EHR pretending to be an authorized staff member. | Vector: Phishing / Vishing (Task 4)<br>Surface: Human | Attacker views patient records without authorization, violating HIPAA privacy. If MFA existed, this would be blocked. | C-006 (Password Policy)<br>C-015 (Remote Access) | **GAP-004** (No MFA)<br>**GAP-003** (No Behavioral Monitoring) |
| **EHR-S2** | **Database Service Spoofing**<br>Attacker connects to `ehr-db-01` (port 5432) by spoofing a legitimate application server identity since no client certificates or IP whitelisting restrict access. | Vector: Open Service Ports (Task 8)<br>Surface: Internal | Unauthorized access to full patient database from any compromised workstation on the flat network. | C-001 (Network Firewall) | **GAP-001** (Flat Network)<br>**GAP-015** (DMZ Misconfiguration) |

### T – Tampering (Data Integrity)

| Threat ID | Description | Attack Vector | Impact | Existing Control | Gap |
|-----------|-------------|---------------|--------|------------------|-----|
| **EHR-T1** | **Patient Dosage Record Modification**<br>Attacker gains DB access and alters medication dosage values in the database before a nurse retrieves them at the bedside. | Vector: Default Credentials / SQL Injection (Task 8)<br>Surface: Internal | Direct patient harm from incorrect medication administration. FDA/HHS reporting required. | None | **GAP-007** (Medical Device Exposure)<br>**GAP-001** (Flat Network) |
| **EHR-T2** | **Ransomware Payload Injection**<br>Attacker exploits Apache RCE on `ehr-srv-01` to inject encrypted payload logic that renders the application unusable. | Vector: Vulnerable Software (Task 8)<br>Surface: External | Clinical operations halt immediately; doctors cannot prescribe or view orders. | C-001 (Firewall) | **GAP-008** (Apache RCE)<br>**GAP-010** (No Vuln Mgmt) |

### R – Repudiation (Denial of Action)

| Threat ID | Description | Attack Vector | Impact | Existing Control | Gap |
|-----------|-------------|---------------|--------|------------------|-----|
| **EHR-R1** | **Unauthorized Record Viewing Denial**<br>Malicious insider accesses celebrity/patient records but denies doing so because shared PACS/EHR logins make attribution impossible. | Vector: Shared Credentials (Task 3)<br>Surface: Human | HIPAA compliance failure; inability to prove accountability for privacy violations. | C-007 (Shared Account Mgmt) | **GAP-003** (No Centralized Log Mgmt)<br>**GAP-007** (Shared Credentials) |
| **EHR-R2** | **Configuration Change Concealment**<br>Admin disables security logging or alters firewall rules via CLI but claims it was a legitimate maintenance task with no documentation. | Vector: Physical Access / SSH (Task 3)<br>Surface: Internal | Security posture degrades without detection; incident investigation lacks evidence trail. | C-017 (Audit Logging) | **GAP-017** (No Change Management)<br>**GAP-003** (No Log Retention) |

### I – Information Disclosure (Privacy Breach)

| Threat ID | Description | Attack Vector | Impact | Existing Control | Gap |
|-----------|-------------|---------------|--------|------------------|-----|
| **EHR-I1** | **Database Dump via Port Exposure**<br>Attacker scans network for port 5432 and queries `ehr-db-01` directly, exfiltrating 50,000 patient records. | Vector: Open Service Ports (Task 8)<br>Surface: Internal | Massive HIPAA breach notification ($1.5M+ fine), class action lawsuits, dark web sales of PHI. | C-016 (DLP - Policy Only) | **GAP-001** (Flat Network)<br>**GAP-016** (No DLP) |
| **EHR-I2** | **Man-in-the-Middle Traffic Sniffing**<br>Attacker captures unencrypted EHR traffic on the flat network between workstations and `ehr-srv-01`. | Vector: Unsecure Networks (Task 8)<br>Surface: Internal | Credentials and PHI exposed in cleartext during transmission. | C-013 (Encryption in Transit) | **GAP-013** (Unencrypted Data) |

### D – Denial of Service (Availability Loss)

| Threat ID | Description | Attack Vector | Impact | Existing Control | Gap |
|-----------|-------------|---------------|--------|------------------|-----|
| **EHR-D1** | **Backup Deletion and Ransomware Encryption**<br>Attacker locates `NAS-01` on the flat network and deletes backups before encrypting production EHR servers. | Vector: Lateral Movement (Task 10)<br>Surface: Internal | Total operational shutdown with no recovery path; extended downtime (14+ days). | C-005 (Backup Policy) | **GAP-005** (Backup Co-location)<br>**GAP-001** (Flat Network) |
| **EHR-D2** | **Resource Exhaustion via Cryptojacking**<br>Attacker installs miners on `ehr-srv-01` or workstations to degrade system performance during peak clinical hours. | Vector: Compromised Workstations (Task 8)<br>Surface: Internal | Sluggish EHR response times causing delays in critical care decisions. | None | **GAP-012** (No EDR)<br>**GAP-003** (No Detection) |

### E – Elevation of Privilege (Access Escalation)

| Threat ID | Description | Attack Vector | Impact | Existing Control | Gap |
|-----------|-------------|---------------|--------|------------------|-----|
| **EHR-E1** | **User-to-Domain Admin Escalation**<br>Compromised nurse workstation scans flat network, finds vulnerable Domain Controller service, escalates to Domain Admin rights. | Vector: Open Service Ports / Vulnerable Software (Task 8)<br>Surface: Internal | Attacker gains full control over all systems, users, and policies across the entire organization. | C-014 (Least Privilege) | **GAP-001** (Flat Network)<br>**GAP-003** (No Monitoring) |
| **EHR-E2** | **Web Server Shell Escalation**<br>Attacker exploits Apache RCE on `ehr-srv-01` to gain root shell and install persistence mechanisms. | Vector: Vulnerable Software (Task 8)<br>Surface: External | Permanent foothold in core application layer; ability to intercept all EHR traffic. | C-001 (Firewall) | **GAP-008** (Apache RCE)<br>**GAP-003** (No WAF/IDS) |

---

## STRIDE Summary for EHR System

The **Information Disclosure** category represents the greatest overall risk for the MedDefense EHR system due to the convergence of extreme data value and complete architectural exposure. While Tampering carries the highest potential for physical harm (dosage alteration), Information Disclosure poses an existential financial and reputational threat because the flat network architecture (GAP-001) allows any single compromised endpoint to reach the database directly without passing through security controls, and the lack of DLP or monitoring (GAP-016, GAP-003) ensures exfiltration remains undetected for weeks. This danger is particularly acute in a healthcare context because patient records contain immutable identifiers (Social Security numbers, medical histories) that fuel long-term identity theft and insurance fraud, turning a single breach into decades of liability rather than a one-time financial hit. Consequently, prioritizing network segmentation and MFA not only mitigates Spoofing and Elevation of Privilege but fundamentally collapses the attack path for Information Disclosure, protecting both patient privacy and organizational solvency simultaneously.

---

*Prepared by: Security Department*  
*References: Project 1x00 Gap Analysis, Task 8 Vector Assessment, Task 10 Kill Chains*
