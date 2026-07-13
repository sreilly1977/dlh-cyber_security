# Vector-to-Asset Matrix
## MedDefense Health Systems – Complete Threat Exposure Map

**Date:** July 13, 2026  
**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT  
**References:** Project 1x00 Asset Registry, Network Scan Summary, Gap Analysis  

---

## Attack Vector to Critical Asset Cross-Reference

| Attack Vector | EHR System | EHR Database | Domain Controllers | Billing Server | Medical Device Management | PACS Server | Medical IoT Devices |
|---------------|:----------:|:------------:|:------------------:|:--------------:|:-------------------------:|:-----------:|:-------------------:|
| **1. Phishing / Spear Phishing** | Phishing email → clinician workstation → EHR login with stolen credentials → direct access to ehr-srv-01. | Phishing → credential harvest → database connection string in config file accessed → PostgreSQL 5432 queried via flat network. | Phishing → domain user account compromised → lateral movement across flat network → Kerberoasting attack on AD DCs. | Phishing → billing department user → direct RDP to billing-srv-01 or credential reuse on compromised server. | Phishing → biomedical engineer account → authenticated access to device management console via internal web interface. | Phishing → radiology tech → PACS workstation login → DICOM data access via raduser shared account. | Phishing → nurse workstation → flat network scan → default credentials on BD Alaris pump web interface → device control. |
| **2. VPN Exploit** | Compromised VPN credentials → full network access via FortiGate → direct RDP to ehr-srv-01 over flat network. | VPN tunnel grants unrestricted access to 10.10.0.0/16 → PostgreSQL 5432 on ehr-db-01 accessible from any VPN endpoint. | VPN → Active Directory admin account obtained → DCs directly accessible from remote location without additional hops. | Already compromised billing server reachable directly via VPN → no additional lateral movement required for attacker. | VPN access → medical device subnet (flat) → web interface on management console accessible from external location. | VPN → PACS server on flat network → DICOM data retrieval via authenticated workstation credentials. | VPN → medical IoT subnet (no segmentation) → ping sweep → exploit default credentials on pumps/monitors from external network. |
| **3. Default / Shared Credentials** | raduser shared PACS account → lateral access from PACS workstation to EHR server via flat network credentials reuse. | Default database admin password → direct PostgreSQL 5432 authentication without requiring application layer access. | Admin/Admin default on network devices → router/firewall compromise → ability to pivot to Domain Controller services. | Vendor-shared service account credentials → direct authenticated access to billing-srv-01 via RDP/SSH. | BD Alaris admin/admin default → direct manipulation of pump settings from any network-accessible device. | Default PACS credentials shared by 15 staff members → any radiology tech can exfiltrate imaging data via unattributed session. | Philips monitor default credentials → direct network access to monitor management console without authentication. |
| **4. Vulnerable Software Exploit** | Apache 2.4.29 RCE on web-srv-01 → reverse shell established → flat network pivot to ehr-srv-01 via SMB/RPC exploits. | MySQL/PostgreSQL version vulnerabilities exposed via web application → SQL injection → direct database query without credentials. | Windows Server 2012 R2 Print Spooler vulnerability → RCE on print-srv-01 → lateral movement to Domain Controller via SMB relay. | Apache 2.4.29 CVE-2021-41773 exploited twice → remote code execution → attacker installs cryptominer or ransomware payload. | Medical IoT device firmware vulnerabilities with vendor advisories → exploit unpatched embedded web servers on pumps. | PACS server running outdated DICOM service → buffer overflow exploitation → remote code execution on imaging server. | Unpatched Windows XP on MRI workstation → EternalBlue MS17-010 exploitation → persistent foothold in medical device network. |
| **5. Supply Chain Compromise** | MedTech Solutions vendor compromise → direct RDP access to EHR server granted via legitimate maintenance credentials. | Vendor database admin account → exfiltrate patient records via approved backup/sync mechanism without raising alarms. | MedTech or other contractor → existing AD admin account in their possession → credential harvesting from vendor workstation. | Vendor support session → backdoor installed during legitimate maintenance window for future access by unknown actors. | Siemens technician laptop compromised during MRI maintenance → malware introduced to medical device network via service connection. | PACS vendor maintenance → backdoor access established for data theft during routine firmware updates or troubleshooting. | Vendor remote access credentials leaked → attacker impersonates vendor to gain authenticated access to IoT management console. |
| **6. Insider (Malicious)** | Malicious employee with clinical access → intentional data download via authorized EHR interface with legitimate credentials. | Database administrator with excessive privileges → unauthorized bulk export of PHI without triggering DLP alerts. | Domain Admin intentionally disables security logging and creates hidden backdoor accounts for later data exfiltration. | Billing employee with system knowledge → intentional copy of billing records including patient insurance information. | Radiology staff intentionally download patient images for sale on dark web using shared PACS account for anonymity. | Malicious insider with legitimate workstation access → portable USB drive containing stolen PHI removed from facility. | Clinical staff with physical access → intentional tampering with medication dosing through unmonitored IoT device interface. |
| **7. Insider (Negligent)** | Phishing click by staff → credentials stolen → attacker uses legitimate workflow access to browse patient records. | Accidental exposure of database credentials in plaintext script on desktop → attacker discovers via network scan. | Shared admin credentials written on sticky note visible on IT desk → unauthorized person gains domain admin access. | Unencrypted backup copy of billing data on personal laptop → data exfiltrated if device lost or compromised remotely. | Shadow IT NAS device storing PHI → data exposed to any network attacker who discovers the device via scan. | Nurse leaves workstation unlocked while treating patient → passerby browses EHR records without attribution. | Personal iPad connects to clinical network without MDM → stolen device provides O365 access to employee emails and documents. |
| **8. Physical Access** | Unauthorized person enters unlocked IT room → direct console access to EHR server bypassing all network security controls. | Physical access to ehr-db-01 → boot from live CD or hot-plug storage drive to extract database files offline. | Server room unlocked → direct connection to Domain Controller console port for password reset or data extraction. | Physical access to billing-srv-01 → local password reset via boot media or credential dump from memory. | Physical access to medical device network closet → direct cable connection to pump management console or switch. | Unlocked server closet → direct connection to PACS server for imaging data copy or ransomware deployment. | Physical access to nursing station → plug infected USB device into medical device or workstation for lateral movement. |

---

## Cell Count Summary

| Column (Asset) | Cells Filled | Risk Density |
|----------------|:------------:|:------------:|
| **EHR System** | 8/8 | Highest — reachable by every vector |
| **EHR Database** | 8/8 | Highest — contains 50,000 patient records |
| **Domain Controllers** | 8/8 | Highest — authentication authority for entire network |
| **Billing Server** | 8/8 | High — already compromised, critical business function |
| **Medical Device Management** | 8/8 | High — patient safety implications |
| **PACS Server** | 8/8 | Medium-High — large data repository |
| **Medical IoT Devices** | 7/8 | High — direct patient harm potential |

**Total Cells Filled:** 55 out of 56 possible cells  
**Empty Cells:** 1 (Physical Access → Medical IoT Devices — partial, but still viable via workstations in nursing stations)

---

## Top 3 Most Connected Assets (By Vector Reachability)

| Rank | Asset | Vectors Reaching It | Why This Represents Highest Priority |
|------|-------|---------------------|--------------------------------------|
| **1** | **EHR Database (ehr-db-01)** | All 8 vectors reach this asset via multiple paths (Phishing, VPN, Default Credentials, Vulnerable Software, Supply Chain, Malicious Insider, Negligent Insider, Physical Access). | This single asset contains the highest-value data (50,000 patient records with full PHI) and is reachable by every attack vector because the flat network architecture removes all barriers between initial compromise and database access. |
| **2** | **Domain Controllers (ad-dc-01/02)** | All 8 vectors reach this asset, making it the second-most connected asset. | Domain controllers authenticate every user, system, and service across the entire organization; compromising them grants total control over the environment and makes remediation nearly impossible without rebuilding the entire infrastructure. |
| **3** | **Medical IoT Devices (Pumps/Monitors)** | 7 of 8 vectors reach this asset (only Physical Access has a slightly weaker path due to location constraints). | Patient safety is the unique risk here—unlike the other assets where compromise results in data loss or operational disruption, IoT compromise can alter medication dosing and directly endanger lives, representing an existential regulatory and liability risk beyond financial impact. |

---

## Top 3 Most Versatile Vectors (By Asset Reachability)

| Rank | Attack Vector | Assets Reached | Why This Represents Highest Priority |
|------|---------------|----------------|--------------------------------------|
| **1** | **Phishing / Spear Phishing** | All 7 assets reached via credential theft, workstation compromise, or direct access. | Phishing is the lowest-cost, highest-volume attack method for adversaries, and at MedDefense it bypasses all technical controls because users voluntarily hand over credentials that unlock every asset on the flat network. |
| **2** | **Vulnerable Software Exploit** | All 7 assets reached via RCE, lateral movement, or service exploitation. | The billing-srv-01 cryptominer proves this vector is already active and uncontained; Apache RCE vulnerabilities on two servers plus unpatched legacy systems provide multiple entry points requiring zero user interaction or social engineering. |
| **3** | **Default / Shared Credentials** | All 7 assets reached via known credentials without requiring exploitation. | Default credentials on medical devices, shared PACS accounts, and vendor service accounts mean attackers do not need to crack passwords or exploit vulnerabilities—they simply use the well-documented credentials that were never changed from factory or never revoked from terminated employees. |

---

## Strategic Implications

This matrix demonstrates that **the flat network architecture (GAP-001) is the single greatest force multiplier** in MedDefense's threat environment, enabling every vector to reach every critical asset without encountering technical barriers. The three most connected assets (EHR Database, Domain Controllers, Medical IoT) represent the intersection of highest data value, highest control authority, and highest patient safety risk—compromising any one of these creates catastrophic business outcomes. The three most versatile vectors (Phishing, Vulnerable Software, Default Credentials) require the least sophistication and investment from attackers, meaning they represent the most probable paths for an active breach today.

**Primary Recommendation:** Remediation efforts must prioritize closing GAP-001 (Network Segmentation) first, because segmentation would reduce the number of cells from 55 to approximately 20, eliminating most lateral movement paths and forcing attackers to find additional entry points for each critical asset. Secondary priorities include implementing MFA (GAP-004) to neutralize Phishing and Default Credential vectors, and patching Apache (GAP-008) to close the Vulnerable Software vector that is already actively exploited on billing-srv-01.

---

*Prepared by: Security Department*  
*References: Task 1x00 Gap Analysis, Network Scan Summary, Asset Registry, Task 8 Posture Assessment*
