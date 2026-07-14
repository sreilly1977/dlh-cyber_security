# STRIDE Across the Architecture
## Threat Triage for PACS, Active Directory, and Network Infrastructure

**Date:** July 14, 2026  
**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT  
**References:** Project 1x00 Asset Registry, Gap Analysis, Network Scan Summary  

---

## System 1: PACS / Medical Imaging

**Architecture Notes:** `pacs-srv-01` (Windows Server) stores all diagnostic imaging data and serves images to radiology workstations via DICOM protocol (port 104/11112). The MRI workstation runs Windows XP (EOL since April 2014) and is network-connected for image transfer. Radiology workstations use a shared account ("raduser/radiology1") for PACS access. All components reside on the flat 10.10.0.0/16 network with no segmentation. PACS backups are not included in the Veeam backup scope.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| **S** | Attacker uses the shared "raduser" credentials (known by 15+ staff members) to authenticate to PACS as a legitimate radiology technician. | Unauthorized access to all diagnostic images on the server. No individual attribution possible — attacker activity is indistinguishable from legitimate staff access. | High |
| **T** | Attacker compromises the Windows XP MRI workstation via EternalBlue (MS17-010) and modifies DICOM image headers or pixel data before transfer to PACS. | Corrupted diagnostic images lead to misdiagnosis, incorrect treatment plans, and potential patient harm. Integrity violation may not be detected until clinical decisions are made on altered images. | Critical |
| **R** | Staff member inappropriately accesses celebrity patient imaging data using shared "raduser" account, then denies the action when audited. | HIPAA violation with no ability to attribute the access to a specific individual. Violates 42 CFR § 164.312(b) audit control requirements. OCR investigation cannot determine responsible party. | High |
| **I** | Attacker on the flat network intercepts unencrypted DICOM traffic between MRI workstation and PACS server, capturing patient images and metadata in transit. | Diagnostic images containing patient name, medical record number, and clinical data exposed. PHI disclosure requires breach notification. Images may contain visually identifiable patient information (burns, tattoos, facial reconstructions). | High |
| **D** | Attacker encrypts `pacs-srv-01` via ransomware propagated through the flat network from a compromised workstation. | All diagnostic imaging becomes inaccessible. Physicians cannot review prior imaging for current patients. Emergency diagnoses requiring comparison studies are blocked. PACS is excluded from backup scope, so recovery requires manual reconstruction. | Critical |
| **E** | Attacker exploits an unpatched vulnerability on the Windows XP MRI workstation to gain SYSTEM-level access, then uses that foothold to enumerate the network and escalate to Domain Admin via Kerberoasting against `ad-dc-01`. | Full domain compromise originating from an unpatchable legacy system. The Windows XP workstation becomes a permanent pivot point that cannot be remediated through patching — only through network isolation. | Critical |

**Top Threat: Elevation of Privilege (E).** The Windows XP MRI workstation is the most dangerous component in this system because it cannot be patched and resides on the flat network. Once compromised, it provides a permanent, unremovable foothold for lateral movement and privilege escalation. Even if every other vulnerability were fixed, this single unpatchable system would remain a critical exposure. Network isolation (GAP-001/GAP-007 remediation) is the only viable mitigation.

---

## System 2: Active Directory

**Architecture Notes:** `ad-dc-01` and `ad-dc-02` (Windows Server) provide authentication, authorization, and directory services for all users, computers, and services across MedDefense. Both domain controllers are accessible from any device on the flat 10.10.0.0/16 network. Password policy enforces 8-character minimum with 90-day rotation. No MFA on any AD-authenticated system except one personal account. No centralized logging of AD events. Service accounts with excessive privileges exist throughout the environment.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| **S** | Attacker uses credentials harvested from phishing or purchased from an Initial Access Broker to authenticate to AD as a legitimate user, gaining access to all systems that user can reach. | Valid credentials bypass all perimeter controls. Attacker operates as a trusted insider with legitimate access patterns. No MFA exists to challenge the authentication. | Critical |
| **T** | Attacker with Domain Admin privileges modifies Group Policy Objects to disable antivirus, change firewall rules, or deploy ransomware across all Windows systems simultaneously. | Organization-wide configuration tampering. GPO modification enables simultaneous ransomware deployment to all Windows systems — the exact deployment method used in BlackReef Kill Chain #1 (Task 10). | Critical |
| **R** | Administrator creates a hidden backdoor service account in AD but no change management process exists to detect, review, or document the creation. | Persistent unauthorized access that persists indefinitely. No audit trail of account creation, modification, or use. Backdoor account remains active across password resets and policy changes. | High |
| **I** | Attacker performs LDAP enumeration against `ad-dc-01` from a compromised workstation, extracting the full user list, group memberships, and service account names for use in targeted attacks. | Attacker gains complete organizational directory structure including usernames, department assignments, and privileged group memberships. This information enables highly targeted spear phishing and identifies high-value accounts for credential attacks (Kerberoasting, AS-REP roasting). | High |
| **D** | Attacker floods `ad-dc-01` with authentication requests (Kerberoasting or password spraying), overwhelming the LSASS process and causing authentication timeouts across all MedDefense systems. | All systems that depend on AD authentication become unusable. Clinical staff cannot log into EHR, billing, or workstations. PACS cannot authenticate image requests. Complete operational paralysis without any data being encrypted. | Critical |
| **E** | Attacker compromises a standard user account via phishing, then uses BloodHound to identify a privilege escalation path through a misconfigured service account with Domain Admin delegation, escalating from standard user to Domain Admin. | Total environment compromise. Attacker controls all authentication, can reset any password, create any account, and modify any system configuration. This is the prerequisite for GPO-based ransomware deployment (Kill Chain #1 and #5). | Critical |

**Top Threat: Elevation of Privilege (E).** Active Directory is the authentication backbone for the entire organization. A standard user escalating to Domain Admin represents total compromise because Domain Admin credentials enable ransomware deployment via GPO, backdoor account creation, and security control disabling across all systems. The combination of no MFA (GAP-004), no SIEM monitoring of AD events (GAP-003), no change management (GAP-017), and flat network access to domain controllers (GAP-001) creates a clear and unobstructed path from any compromised user account to total environment control. This is the single most consequential escalation path in the entire MedDefense environment.

---

## System 3: Network Infrastructure

**Architecture Notes:** FortiGate 100F serves as the sole perimeter firewall and VPN concentrator at Central HQ. Core switches are unmanaged for VLAN purposes (flat network). Westside Clinic connects via site-to-site VPN through a consumer-grade Netgear Nighthawk router with no firewall rules. No internal segmentation, no IDS/IPS, no network monitoring. DNS provided internally by domain controllers. No network access control (NAC) on any switch port. Dr. Patel's personal NAS and other shadow IT devices are connected to clinical network ports.

| STRIDE | Threat | Impact | Severity |
|--------|--------|--------|----------|
| **S** | Attacker spoofs the FortiGate management interface IP address and presents a fake login portal to capture admin credentials when an IT staff member connects. | Attacker obtains FortiGate admin credentials, enabling them to modify firewall rules, disable VPN MFA (when implemented), create backdoor VPN accounts, or divert traffic through attacker-controlled infrastructure. | Critical |
| **T** | Attacker modifies routing tables or firewall rules on the consumer-grade Netgear router at Westside Clinic to redirect VPN traffic through an attacker-controlled middlebox. | All traffic between Westside and Central is intercepted and modified. Attacker can inject malicious payloads into clinical data streams or alter EHR synchronization data. Westside's consumer router has no tamper-resistant configuration management. | High |
| **R** | Network administrator changes FortiGate firewall rules to open additional ports or weaken VPN ACLs via CLI but no change management process documents or reviews the modification. | Security posture degrades without detection. If a breach occurs through the opened port, the administrator can plausibly deny the change since no audit trail links it to a specific person or approved change request. | Medium |
| **I** | Attacker connects a rogue device (laptop, Raspberry Pi, or packet capture appliance) to any wall jack in the building and captures all broadcast traffic on the flat network, including ARP requests, DHCP leases, and unencrypted protocol traffic. | Complete network visibility including IP addresses of all devices, MAC addresses (device identification), unencrypted credentials (LDAP, HTTP, SNMP), and internal service advertisements. Flat network means every jack sees every device's broadcast traffic. | Critical |
| **D** | Attacker overwhelms the FortiGate 100F with a volumetric DDoS attack against the public IP, or floods the VPN endpoint with authentication attempts, exhausting firewall session limits. | All external connectivity including VPN, patient portal, and email synchronization is disrupted. Remote staff lose access. Patient portal goes offline. FortiGate becomes a single point of failure for all external connectivity with no redundancy. | High |
| **E** | Attacker compromises the Westside consumer router (default or weak credentials on Netgear Nighthawk), establishes administrative access, then uses the site-to-site VPN tunnel as an authenticated internal connection to pivot into Central's flat network. | Attacker bypasses Central's FortiGate perimeter entirely by entering through the trusted Westside VPN tunnel. Once inside, the flat network provides unrestricted access to all Central systems including EHR, domain controllers, and medical devices. | Critical |

**Top Threat: Elevation of Privilege (E).** The Westside Clinic consumer router represents the most dangerous network infrastructure threat because it provides a trusted, authenticated path into Central's flat network that completely bypasses the FortiGate perimeter firewall. An attacker who compromises a $150 consumer router gains the same network access as a legitimate MedDefense VPN user. Because the internal network is flat, this access extends to every server, workstation, and medical device at Central HQ. The Netgear Nighthawk has known vulnerabilities, likely uses default credentials, and receives no security monitoring. It is the weakest link in the network perimeter, and its compromise is indistinguishable from legitimate VPN traffic to any monitoring system MedDefense might deploy.

---

## Cross-System STRIDE Comparison

| STRIDE Category | PACS Top Severity | AD Top Severity | Network Top Severity | Aggregate Risk |
|-----------------|-------------------|-----------------|----------------------|-----------------|
| **Spoofing** | High | Critical | Critical | Critical |
| **Tampering** | Critical | Critical | High | Critical |
| **Repudiation** | High | High | Medium | High |
| **Information Disclosure** | High | High | Critical | High |
| **Denial of Service** | Critical | Critical | High | Critical |
| **Elevation of Privilege** | Critical | Critical | Critical | Critical |

### Key Observation

Elevation of Privilege emerged as the top threat for all three systems, and this is not coincidence. In each case, the flat network architecture (GAP-001) creates an environment where any initial foothold can be parlayed into total environment control. For PACS, the Windows XP MRI workstation provides an unpatchable escalation point. For Active Directory, the combination of no MFA and flat network access to domain controllers creates a direct path from standard user to Domain Admin. For network infrastructure, the Westside consumer router provides an authenticated path that bypasses the perimeter entirely. In all three cases, network segmentation (GAP-001 remediation) is the single control that would break the escalation chain by denying attackers the unrestricted access needed to move from initial compromise to privileged control.

---

*Prepared by: Security Department*  
*References: Project 1x00 Gap Analysis, Task 8 Vector Assessment, Task 11 STRIDE on EHR, Task 10 Kill Chains*
