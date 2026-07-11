# 6. The Legacy Dilemma: MRI Scanner Compensating Control Strategy

## Risk Analysis

This MRI workstation represents a critical security risk to the entire MedDefense network because Windows XP has not received security patches since April 2014, leaving it vulnerable to well-known, publicly exploitable vulnerabilities such as EternalBlue (MS17-010), which was leveraged in WannaCry and NotPetya ransomware campaigns. The workstation currently sits on the flat 10.10.0.0/16 broadcast domain alongside all clinical workstations, servers, and medical devices, meaning any compromise on one segment propagates freely to the MRI system. Once an attacker gains a foothold on the MRI, whether through the EHR application, the billing server, or a phishing email, they can pivot laterally to the MRI control system and potentially disrupt imaging services, falsify diagnostic results, or use the MRI workstation as a staging point to reach other critical systems like the EHR database or domain controllers. The combination of an unpatchable OS with no network isolation creates a persistent attack surface that cannot be eliminated through traditional vulnerability remediation.

---

## Compensating Control Strategy

---

### Control 1: Network Micro-Segmentation (VLAN Isolation)

**Description:** Create a dedicated VLAN (e.g., 10.10.3.X) exclusively for medical imaging devices, including the MRI scanner and PACS server. Configure the FortiGate 100F firewall to permit only specific traffic flows:
- TCP port 104 (DICOM) from MRI to PACS server only
- TCP port 443 (HTTPS) from MRI to authorized vendor remote support IP addresses (whitelisted)
- Block all other outbound and inbound traffic from the imaging VLAN to the rest of the hospital network

**Classification:** Technical / Preventive

**Risk Reduction Without OS Modification:** This control isolates the MRI at the network layer, preventing lateral movement from other compromised systems on the 10.10.0.0/16 range. Even if the Windows XP workstation has unpatched vulnerabilities, an attacker on the general workstation segment cannot reach the MRI without first breaching the firewall rules. DICOM communication remains functional while all unnecessary ports are blocked.

**Limitations and Residual Risk:** 
- If an attacker already compromises a device within the imaging VLAN (e.g., PACS server), the protection is bypassed
- Vendor remote support may require periodic port openings that introduce temporary windows of exposure
- Does not protect against physical attacks on the MRI workstation itself
- Requires careful testing to ensure DICOM image transfer is not disrupted
- Residual risk: Moderate — network isolation significantly reduces attack surface but does not eliminate it

---

### Control 2: Host-Based Firewall and Application Whitelisting on MRI Workstation

**Description:** Install and configure Windows Firewall on the MRI workstation to restrict all inbound connections except those required for DICOM (port 104) and necessary system functions. Enable strict application whitelisting (using native Windows XP capabilities or lightweight third-party tools compatible with XP) to prevent execution of any binary not explicitly authorized. Block PowerShell, Command Prompt, and scripting engines. Disable all unused services (Telnet, FTP, RPC if not required for DICOM).

**Classification:** Technical / Preventive

**Risk Reduction Without OS Modification:** This control provides defense-in-depth at the host level, ensuring that even if network traffic reaches the MRI workstation, only approved processes can execute and only authorized network ports respond. An attacker who successfully exploits an XSS or buffer overflow would be unable to spawn a reverse shell or run unauthorized tools if application whitelisting is enforced.

**Limitations and Residual Risk:**
- Windows XP has limited native application whitelisting capability; requires third-party solution that is compatible with XP (may be difficult to source and support)
- Must be carefully configured to avoid disrupting PACS imaging workflow or vendor-required applications
- If the attacker compromises an already-whitelisted process (DLL hijacking), protections can be circumvented
- Cannot be centrally managed easily; changes must be applied manually to the isolated workstation
- Residual risk: Moderate-High — effective but technically challenging to implement correctly on legacy OS

---

### Control 3: Enhanced Monitoring and Alerting for Imaging Segment

**Description:** Deploy a dedicated sensor (such as Wazuh agent, Suricata IDS, or passive network tap) on the imaging VLAN to monitor all traffic entering and exiting the MRI/PACS subnet. Configure alerts for:
- Any connection attempts from outside the imaging VLAN
- Known exploit signatures targeting Windows XP vulnerabilities (SMB, RDP, MS08-067, EternalBlue)
- Unusual outbound connections or DNS queries from the MRI workstation
- Process execution anomalies detected via host-based monitoring (if agent can be installed)

Configure these alerts to forward to a centralized SIEM or log aggregation system (even a basic Wazuh server on a separate Linux VM).

**Classification:** Technical / Detective

**Risk Reduction Without OS Modification:** This control enables rapid detection if an attacker breaches the network perimeter and reaches the imaging segment, allowing security teams to respond before significant damage occurs. Unlike the billing server cryptominer that ran for 14 days undetected, the MRI's activity would be visible through continuous monitoring and alerting. Early detection limits dwell time and data exfiltration potential.

**Limitations and Residual Risk:**
- Detection does not prevent the initial compromise; only enables faster response
- False positives may overwhelm staff if thresholds are not tuned carefully
- Requires staffing or automation to act on alerts; detection without response is incomplete
- Legacy OS may not support modern security agents; passive network monitoring is fallback option
- Residual risk: Medium — improves visibility but depends on operational follow-through

---

### Control 4: Administrative Access Control and Change Management Policy

**Description:** Create a formal policy governing access to the MRI workstation:
- Only named, vetted radiology staff with explicit authorization may physically access the MRI control console
- All configuration changes require documented approval from both IT Security and Radiology Department leadership
- No removable media (USB drives) may be connected to the MRI workstation without prior security review
- Quarterly reviews verify authorized users and remove access for departed employees
- Mandatory reporting of any unusual behavior (slow performance, unexpected popups, failed logins) by radiology staff

**Classification:** Administrative / Preventive

**Risk Reduction Without OS Modification:** This control reduces the likelihood of insider threats, accidental misconfiguration, or opportunistic malware introduction through removable media. It establishes clear ownership and accountability for the MRI system, making it less likely that changes go undocumented or that unauthorized individuals gain access.

**Limitations and Residual Risk:**
- Relies on human compliance; policies without enforcement often degrade over time
- Does not protect against external network-based attacks
- Staff turnover requires ongoing maintenance of access lists
- Requires security culture buy-in from Radiology department (historically resistant per Marcus's notes)
- Residual risk: Medium — valuable as part of a layered approach but insufficient alone

---

### Control 5: Physical Access Restriction to MRI Control Console

**Description:** Install a locked enclosure or badge-controlled access mechanism around the MRI control workstation. The control console should be in a restricted area accessible only to authorized radiology staff. Log badge access attempts. Place a camera monitoring the MRI room with 90-day retention (longer than the current 30-day standard for other cameras).

**Classification:** Physical / Preventive + Detective

**Risk Reduction Without OS Modification:** This control prevents unauthorized physical access to the MRI control console, eliminating opportunities for direct manipulation, USB malware injection, or local account brute force. A camera enables post-incident forensic review if suspicious activity is detected.

**Limitations and Residual Risk:**
- Authorized staff still have full physical access; insider threats not mitigated
- Does not protect against network-based attacks (primary vector)
- Additional cost and infrastructure (badging hardware, camera, DVR storage)
- May interfere with clinical workflow if access becomes too restrictive
- Residual risk: Low-Medium — effective for physical security but does not address the larger network threat

---

## Implementation Priority: Single Control Selection

**If MedDefense could only implement ONE control immediately, the network micro-segmentation (VLAN isolation) provides the greatest risk reduction.**

**Justification:** Network segmentation addresses the single most dangerous aspect of the current architecture: the flat 10.10.0.0/16 broadcast domain that allows unrestricted lateral movement across all systems. As demonstrated by the billing-srv-01 cryptominer incident, an attacker who gains initial access to one server can spread across the entire network. By placing the MRI on an isolated VLAN with strict firewall rules, the blast radius of any compromise is contained regardless of whether the MRI itself is breached or whether other systems are attacked first. This control is achievable within existing infrastructure (the FortiGate 100F already has VLAN capability; Marcus's network diagram shows segmentation is "planned for next fiscal year"), requires minimal operational disruption, and provides broad protective benefit beyond just the MRI (it would also protect other medical devices). Compared to application whitelisting (technically challenging on Windows XP), administrative policies (dependent on compliance), or physical controls (limited scope), VLAN isolation delivers the most significant risk reduction per euro spent and can be implemented within 1-2 weeks with proper testing.

**Residual Risk Acknowledgement:** Even with VLAN isolation, the MRI remains fundamentally vulnerable at the OS level. If an attacker somehow reaches the imaging VLAN (through a compromised PACS server or vendor access), exploitation is still possible. Therefore, micro-segmentation should be treated as a **temporary measure** with a formal exception for the Windows XP system, accompanied by a timeline for eventual replacement when budget allows. Documentation should clearly state the compensating control's limitations to satisfy HIPAA risk assessment requirements and inform the Board that this remains a high-risk asset requiring continued investment toward eventual decommissioning.
