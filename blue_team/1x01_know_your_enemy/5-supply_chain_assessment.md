# Third-Party Risk Assessment
## MedDefense Health Systems – Supply Chain Analysis

---

## Vendor 1: MedTech Solutions

**Vendor:** MedTech Solutions  
**Service:** EHR System Maintenance and Support (Annual Contract $145,000).  
**Access Type:** Network / Application (Remote Administration).  
**Access Scope:** Direct RDP/VNC access to `ehr-srv-01` and `ehr-db-01`. Full administrative privileges on the EHR application layer and database layer.  
**Compromise Scenario:** If a MedTech analyst workstation is compromised (or they are bribed), attackers gain authenticated RDP access to the production EHR environment. Due to **GAP-001** (Flat Network), they can pivot immediately to other servers from the EHR server. Because there is no MFA (**GAP-004**), stolen vendor credentials grant instant access. Attackers can exfiltrate the entire patient database or deploy ransomware directly into the core clinical system.  
**Existing Controls:** Contractual SLA (4hr response). Shared administrative credentials used for maintenance (violates **C-007**). No dedicated jump host or bastion host documented in Task 10 matrix.  
**Risk Assessment:** **Critical**. This vendor holds the keys to the crown jewels (PHI + EHR uptime). Combined with MedDefense's lack of network segmentation and MFA, a vendor compromise equates to a total organizational compromise.

---

## Vendor 2: Microsoft

**Vendor:** Microsoft  
**Service:** O365 E3 (Email, SharePoint, OneDrive, Identity Management via Entra ID).  
**Access Type:** Cloud Application / Identity.  
**Access Scope:** All organizational email, file storage, and potentially on-premise identity sync (if hybrid AD used).  
**Compromise Scenario:** If the Microsoft tenant is breached (or the vendor's update mechanism is compromised), attackers could manipulate identity synchronization to create backdoor accounts. More realistically, phishing against the vendor's helpdesk could lead to token theft. Since MedDefense uses O365 for all identity, a Microsoft-side compromise bypasses on-premise firewalls entirely.  
**Existing Controls:** O365 E3 license includes Advanced Threat Protection and MFA capability (**C-015** potential), but these are largely unused due to **GAP-004** (No MFA). No conditional access policies defined.  
**Risk Assessment:** **High**. While Microsoft's security posture is stronger than typical vendors, the organization's reliance on them for identity makes it a high-value target. The risk is amplified by MedDefense's failure to enable available MFA features.

---

## Vendor 3: Sophos

**Vendor:** Sophos  
**Service:** Endpoint Protection and Antivirus.  
**Access Type:** Agent-Based / System Level.  
**Access Scope:** All managed endpoints (~2,000 workstations, 12 servers). Kernel-level access to file systems, memory, and network traffic on every device.  
**Compromise Scenario:** Similar to the SolarWinds attack, if Sophos update servers are compromised, a malicious update could be pushed to all agents simultaneously. The signed malware would bypass local AV checks (since it comes from the trusted vendor). Attackers gain kernel-level persistence on every device in the organization simultaneously.  
**Existing Controls:** Digital signature verification assumed (standard vendor practice). No network egress filtering specifically for update channels (**GAP-001** flat network allows any destination).  
**Risk Assessment:** **High**. The trust relationship is deep (kernel level). A supply chain compromise here neutralizes the only active detection control MedDefense has on endpoints (the agent itself).

---

## Vendor 4: Siemens

**Vendor:** Siemens (Medical Division)  
**Service:** MRI Scanner Maintenance and Firmware Updates.  
**Access Type:** Physical / Local Network.  
**Access Scope:** The MRI Workstation (`MRI-WORKSTATION`, Windows XP EOL). Potentially connected to the internal hospital network for data transfer to PACS.  
**Compromise Scenario:** A service technician connects a compromised maintenance laptop to the MRI workstation or local network. Due to **GAP-001** (Flat Network), malware introduced to the MRI machine spreads laterally to `pacs-srv-01` and the rest of the hospital. Additionally, the Windows XP OS contains known unpatched vulnerabilities that the vendor relies on for remote support tools.  
**Existing Controls:** None documented for vendor laptop screening. Physical access to the MRI room is restricted but monitored only loosely (**GAP-011**).  
**Risk Assessment:** **High**. While access frequency is low (periodic maintenance), the vulnerability of the target asset (Windows XP) and the network architecture (Flat) mean even temporary access creates a persistent foothold.

---

## Vendor 5: Greenfield Building Management

**Vendor:** Greenfield Building Management  
**Service:** Office Building Infrastructure and Network Services.  
**Access Type:** Network Layer.  
**Access Scope:** Building network backbone. MedDefense occupies a VLAN on Greenfield's network infrastructure.  
**Compromise Scenario:** If Greenfield's management network is compromised, attackers could perform lateral movement within the building's shared infrastructure. Depending on VLAN isolation configurations (or lack thereof per **GAP-015**), they could sniff traffic between MedDefense devices or route traffic through their own infrastructure for MITM attacks.  
**Existing Controls:** VLAN tagging implemented (partial segregation). Firewalls at the demarcation point (FortiGate 100F) but no inspection of inbound building traffic (**GAP-003** no monitoring).  
**Risk Assessment:** **Medium**. The attack surface is external to MedDefense's perimeter but shares the physical wiring. Risk is manageable if network isolation is enforced, but currently lacks monitoring.

---

## Supply Chain Risk Summary

**Worst-Case Vendor:** **MedTech Solutions** poses the single greatest risk to MedDefense. Unlike the other vendors who provide peripheral services or shared infrastructure, MedTech has direct administrative access to the EHR and patient database—the organization's highest-value assets. A compromise here bypasses all perimeter defenses because it originates from within the trusted zone, leveraging valid credentials that are not protected by MFA (**GAP-004**). Combined with the flat network architecture (**GAP-001**), a vendor breach grants immediate access to the entire environment, making recovery nearly impossible without rebuilding the core EHR infrastructure.

**Top Priority Control:** **Zero Trust / Just-In-Time Vendor Access.** MedDefense must immediately implement a bastion host or jump box for all vendor remote access. Vendors should never have standing, persistent access to production servers. Instead, they should request access via a ticket system that grants time-limited credentials (max 8 hours) to a specific IP address for a specific task. This satisfies the principle of least privilege, forces logging of all vendor activity into Wazuh (**GAP-003**), and reduces the window of opportunity for credential theft or misuse.
