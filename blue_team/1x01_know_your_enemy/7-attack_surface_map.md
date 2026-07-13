# MedDefense Attack Surface Map
## External, Internal, and Human Exposure Analysis

**Date:** July 13, 2026  
**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT  
**References:** Project 1x00 Asset Registry, Network Scan Summary, Control Matrix, Gap Analysis  

---

## Section 1: External Attack Surface (Internet-Accessible)

| Entry Point | Asset Behind It | Protection (1x00 Controls) | Gap Documented (1x00 Gap IDs) |
|-------------|-----------------|-----------------------------|-------------------------------|
| **Patient Portal (HTTPS)** | `web-srv-01` (Apache 2.4.29, Ubuntu 18.04) | C-002 (DMZ Segmentation), C-003 (FortiGate Firewall). TLS 1.2 enabled but TLS 1.0 fallback active. | **GAP-008** (Apache RCE — CVE-2021-41773/42013, already exploited twice on billing-srv-01). **GAP-013** (TLS 1.0 enabled — deprecated protocol). **GAP-015** (DMZ allows outbound to internal — misconfigured firewall rules). |
| **VPN Endpoint (FortiGate 100F)** | Full internal network via 10.10.0.0/16 | C-001 (Network Firewall), C-015 (Remote Access — "recommended" not required). FortiGate handles VPN termination. | **GAP-004** (No MFA on VPN — single-factor credentials). **GAP-001** (Flat network — VPN grants unrestricted access to entire broadcast domain). **GAP-010** (No patch management — FortiGate firmware patch status unknown). |
| **Email Infrastructure (O365)** | All organizational mailboxes, SharePoint, OneDrive | C-018 (O365 Environment). ATP included in E3 license but not confirmed as configured. | **GAP-004** (No MFA on O365 accounts — credential theft = email compromise). **GAP-016** (No DLP — email exfiltration of PHI undetected). |
| **Public Website** | `web-srv-01` (same host as patient portal) | C-002 (DMZ Segmentation). FortiGate NAT rules. | **GAP-008** (Apache vulnerability — same host as patient portal). **GAP-015** (DMZ misconfiguration — outbound to internal permitted). |
| **DNS** | External DNS hosting (registrar-managed). Internal DNS via AD DCs. | None documented. No DNSSEC or sinkholing configured. | **GAP-003** (No monitoring of DNS queries for malicious domains). **GAP-010** (No vulnerability management for DNS infrastructure). |
| **Billing Server (if internet-exposed)** | `billing-srv-01` (Apache 2.4.29, MySQL, Ubuntu 18.04) | C-002 (DMZ Segmentation — unclear if properly enforced for billing server). | **GAP-002** (Active compromise — cryptominer running 14+ days). **GAP-008** (Apache RCE — exploited twice). **GAP-001** (Flat network — billing server can reach EHR database directly). |

### External Surface Observations

The external attack surface presents **three confirmed exploitable entry points**: the patient portal (Apache RCE), the VPN (no MFA), and the billing server (already compromised). Each entry point connects directly to the flat internal network without segmentation, meaning a single external compromise provides unrestricted internal access. The DMZ configuration (GAP-015) further amplifies risk because a compromised DMZ host can initiate outbound connections to internal servers, effectively making the DMZ transparent to an attacker.

---

## Section 2: Internal Attack Surface (Accessible Once Inside the Network)

**Critical Context:** MedDefense operates a **flat 10.10.0.0/16 network** with no VLANs, no internal firewalls, and no zone separation. This means every service listed below is **reachable from any compromised device** on the network.

| Asset | Exposure (Port/Service) | Why This Matters in a Flat Network |
|-------|-------------------------|-----------------------------------|
| **`ehr-db-01` (EHR Database)** | PostgreSQL on port 5432, network-accessible | Any compromised workstation or server can directly query the patient database using stolen or brute-forced credentials. No network ACL restricts database access to the EHR application server only. |
| **`billing-srv-01` (Billing Server)** | MySQL on port 3306, Apache on 80/443, SSH on 22 | Already compromised with cryptominer. MySQL is network-accessible, meaning any attacker on the internal network can attempt database credential brute-force or exploit MySQL vulnerabilities. |
| **`ad-dc-01` / `ad-dc-02` (Domain Controllers)** | LDAP on 389, SMB on 445, Kerberos on 88, RPC on 135 | Domain controllers are the authentication authority. Any compromised system can query AD for user enumerations, attempt pass-the-hash attacks, or exploit SMB vulnerabilities (similar to EternalBlue propagation). Unrestricted network access to DCs is the prerequisite for total domain compromise. |
| **`NAS-01` (Backup Storage)** | SMB on 445, HTTP admin interface on 80 | Backup storage is on the same network as production servers. A ransomware actor can encrypt backups simultaneously with production systems. The HTTP admin interface may use default credentials. |
| **FortiGate 100F Admin Interface** | HTTPS admin on 443 (if configured for internal access) | If the firewall management interface is accessible from the general network, an attacker who obtains or brute-forces admin credentials can modify firewall rules, disable security policies, or create backdoor VPN accounts. |
| **Medical IoT: BD Alaris Pumps (120 units)** | Web management interfaces on HTTP (various ports) | Default credentials on management consoles. Any compromised workstation can access pump settings, potentially altering medication dosing. Vendor security bulletin recommends network isolation — not implemented. |
| **Medical IoT: Philips Monitors (80 units)** | Web management interfaces, DICOM on 104/11112 | Known firmware vulnerabilities with vendor-advised network isolation. On the flat network, these devices are directly accessible from any IT system. |
| **`print-srv-01` (Print Server)** | SMB on 445, RPC on 135, Spooler service | Windows Server 2012 R2 (EOL — no security patches since October 2023). Print Spooler vulnerabilities (PrintNightmare) allow remote code execution. Any internal system can exploit this. |
| **MRI Workstation** | Network-connected, Windows XP (EOL since 2014) | No security patches available for over a decade. SMB and RPC services exposed. Any attacker on the network can exploit hundreds of unpatched Windows XP vulnerabilities. Acts as a persistent foothold — once compromised, it cannot be patched. |
| **PACS Workstation (Radiology)** | DICOM on 104/11112, shared login ("raduser/radiology1") | Shared credentials eliminate individual accountability. Any attacker who obtains the shared credentials can access imaging data without attribution. The shared account is likely known by multiple people, increasing credential leak probability. |
| **Dr. Patel's Personal NAS** | SMB/AFP on internal network, unencrypted | Shadow IT device unknown to IT. Stores unencrypted PHI. Unmanaged, unpatched, and unprotected. Any network scan reveals this device, and its default credentials are likely unchanged. |
| **Westside Clinic Network** | Entire Westside subnet (10.10.10.0/24) connected via site-to-site VPN | Westside uses a consumer-grade Netgear Nighthawk router with no firewall rules. The VPN connects Westside to Central's flat network, meaning a compromise at Westside (via the consumer router) propagates directly to Central. |

### Internal Surface Observations

The internal attack surface is **effectively infinite** because the flat network makes every device reachable from every other device. An attacker who gains any foothold — through phishing, VPN compromise, or billing server exploitation — can reach all 12 servers, 200 medical devices, and 2,000 workstations without encountering a single network control. The presence of Windows XP (MRI workstation), Windows Server 2012 R2 (print server), and default credentials on medical devices creates persistent, unpatchable exploit targets within the network.

---

## Section 3: Human Attack Surface (People Who Can Be Targeted)

| Role | Access Level | Why They Are Targetable | Training/Control Gap (1x00) |
|------|--------------|------------------------|---------------------------|
| **Clinical Staff (Nurses, Physicians, Techs)** | Full EHR access, PACS access, patient portals. Broad access to PHI required for clinical care delivery. | Trained to be helpful and responsive, especially in urgent patient care situations. High stress and workload create susceptibility to urgency-based social engineering (vishing "emergency IT audit"). Handling sensitive data constantly creates desensitization to data protection protocols. | **GAP-003** (No monitoring of EHR access — snooping undetected). **GAP-004** (No MFA — single password between attacker and EHR). **GAP-007** (Shared PACS credentials — accountability eliminated). Security training completion is low per Task 9 data map. |
| **Reception / Registration Staff** | EHR registration module, patient scheduling, physical front-desk presence. First contact for patients and visitors. | Front desk staff are the human gateway to the facility. Vulnerable to physical social engineering (tailgating, impersonation). Handle patient check-ins requiring quick system access, creating password reuse and shared login temptations. | **GAP-011** (Physical security — no badge enforcement at entrances). **GAP-004** (No MFA on shared registration workstations). No documented security awareness training specific to front desk social engineering scenarios. |
| **IT Staff (Sarah Park, Marcus's Replacement, Helpdesk)** | Domain Admin equivalent privileges. Full access to all servers, network devices, backup infrastructure, AD, O365 tenant. Most powerful internal accounts. | Small team means fatigue and stress, leading to shortcuts (plaintext credential storage — Task 3, Scenario 5). Elevated privileges make them high-value targets for spear phishing and BEC. IT staff are also the target of vendor impersonation (Task 4, Scenario 1). | **GAP-004** (No MFA on admin accounts — Domain Admin credentials are single-factor). **GAP-017** (No change management — ad hoc script creation and sharing). **GAP-003** (No monitoring of privileged account activity). |
| **Executives (CEO, CFO, CTO)** | Strategic information access, financial authority, email accounts containing confidential discussions, budget data, merger/acquisition info. | Primary targets for Business Email Compromise (Task 4, Scenario 2). Authority gradient means their impersonation coerces subordinates into actions (wire transfers, data sharing). Executives often bypass security controls due to perceived importance. | **GAP-004** (No MFA on executive email). **GAP-016** (No DLP on email). No documented executive-specific security training. No wire transfer verification policy documented. |
| **External Contractors (MedTech Solutions, Siemens, Cleaning, Building Mgmt)** | Varies: MedTech has direct server access (RDP to EHR). Siemens has physical/network access to MRI. Building mgmt controls network infrastructure. | Contractors operate outside MedDefense's direct security oversight. Their credentials and devices are not subject to MedDefense's security policies. Contractor offboarding is manual and unreliable (Task 3, Scenario 2). | **GAP-014** (No automated account lifecycle — contractor accounts persist after contract end). **GAP-001** (Flat network — vendor access to one server grants access to all). No vendor security assessment or jump host requirement documented. |

### Human Surface Observations

The human attack surface spans from front desk staff to the C-suite, and every role presents exploitable psychological levers. The common denominator across all roles is the absence of MFA (GAP-004), which means a single compromised credential — whether through phishing, vishing, or credential reuse — grants the attacker the same system access as the legitimate user. IT staff represent the highest-impact human targets because their Domain Admin privileges provide total network control, and their fatigue-induced shortcuts (plaintext credentials, shared scripts) create additional exposure.

---

## Surface Assessment Summary

The **internal attack surface** represents the greatest risk for MedDefense today because it is effectively boundless. On a flat 10.10.0.0/16 network with no segmentation, no internal firewalls, and no monitoring, every device is reachable from every other device, meaning a single compromise at any point — whether the billing server, a phished nurse's workstation, or a vendor's remote session — instantly expands into unrestricted access to the EHR database, domain controllers, backup storage, and 200 life-critical medical devices. The external surface is dangerous but finite (six entry points, all documented), and the human surface is mitigable through training and MFA. However, the internal surface cannot be mitigated through awareness or patching alone; it requires architectural change. Until network segmentation (GAP-001) is implemented, every other security investment is a localized improvement within an environment where a single foothold equals total compromise. The flat network is not merely a gap; it is a force multiplier for every other vulnerability, making the internal surface the dominant risk dimension.
