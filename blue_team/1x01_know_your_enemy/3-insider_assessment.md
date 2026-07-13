# Insider Threat Analysis
## MedDefense Health Systems

---

## Scenario 1: The Shared Login

**Classification:** Negligent. The Radiology department's use of a shared account is not motivated by malice or financial gain. The technicians use shared credentials for workflow convenience ("we need fast access between patients"), not for unauthorized purposes. However, the practice eliminates individual accountability, violates HIPAA audit trail requirements, and creates a security blind spot where any misuse cannot be attributed to a specific person.

**Behavioral Indicators:**
- Single account continuously authenticated across multiple shifts without logout events corresponding to staff changes
- PACS access logs showing continuous sessions lasting 8+ hours with no individual user transitions
- Concurrent sessions from multiple PACS workstations under the same account simultaneously

**Existing Control:** C-007 (Shared Account Management) covers shared accounts. C-006 (Password Policy) mandates individual accountability. Both controls exist but are unenforced for the Radiology department due to operational pushback.

**Gap Exploited:** GAP-007 (Medical Device Network Exposure) references the shared PACS account as a contributing accountability factor. Additionally, the broader GAP-003 (No Centralized Log Management) means the shared account usage pattern would not trigger any alert because nobody is reviewing PACS access logs.

**Recommended Mitigation:** Implement proximity badge authentication (tap-in/tap-out) on PACS workstations using the existing employee badges. This eliminates the login friction that motivates shared credential use while restoring individual accountability for every access session. Badge readers cost approximately $200 per workstation, and integration with Active Directory creates automatic audit trails.

---

## Scenario 2: The Ghost Account

**Classification:** Negligent (organizational negligence). The classification is negligent because the contractor is not a MedDefense employee and may have legitimate reasons for checking system status post-contract, but the real failure is organizational: no automated offboarding process existed to deactivate the account. Whether the contractor's intent was malicious or merely curious is irrelevant because the control failure made the question moot. The organization negligently left an entry point open.

**Behavioral Indicators:**
- Account authentication events occurring exclusively during off-hours (10 PM to 2 AM) when the contractor had no legitimate business need
- Authentication from an IP address never previously associated with that user account
- Account showing activity after the contract end date in HR records

**Existing Control:** None. No control in the Task 10 matrix addresses account lifecycle management or automated offboarding. C-007 covers shared account management but not deprovisioning. This is a documented gap.

**Gap Exploited:** GAP-014 (No Automated Account Lifecycle Management). This scenario is the exact real-world parallel to Health Network Beta (Breach 2 from Task 13) where a former billing employee retained active VPN and EHR credentials for 47 days after termination and exfiltrated 3,211 patient records.

**Recommended Mitigation:** Implement automated account deactivation triggered by HR termination records. When HR marks an employee or contractor as terminated in the HRIS, a workflow automatically disables the AD account, revokes VPN access, and disables O365 login within 4 hours. This removes human dependency from the offboarding process entirely.

---

## Scenario 3: The Personal NAS

**Classification:** Negligent. Dr. Patel's actions are not malicious in intent. He connected the NAS for convenience and research efficiency, storing "convenience copies" of patient files he consults frequently. He likely does not understand the security implications of unencrypted PHI on an unmanaged network device. However, the outcome is severe: unencrypted patient data on a device IT cannot see, monitor, or protect.

**Behavioral Indicators:**
- New network device (NAS) appearing on the network with an unrecognized MAC address or hostname
- Unusual file transfer volume from EHR or PACS systems to an unknown internal IP address
- Network device responding on file-sharing protocols (SMB, AFP, NFS) from an office jack not registered in the asset inventory

**Existing Control:** C-002 (DMZ Segmentation) governs the network perimeter but does not address internal device management. C-001 (Network Firewall) is configured for north-south traffic only. No control addresses internal shadow IT detection.

**Gap Exploited:** GAP-009 (Shadow IT / Undocumented Devices). Dr. Patel's NAS is a shadow IT device that IT was unaware of. The broader GAP-001 (Flat Network Architecture) exacerbates the risk because the NAS is reachable from any compromised system on the network, making it a potential exfiltration target or lateral movement hop point.

**Recommended Mitigation:** Implement Network Access Control (NAC) on all network switches using 802.1X port authentication. Any device connecting to a network jack must authenticate against Active Directory before receiving network access. Unauthenticated devices are placed in a quarantine VLAN with no access to production systems. This prevents unauthorized devices like Dr. Patel's NAS from connecting to the clinical network without IT oversight.

---

## Scenario 4: The Curious Employee

**Classification:** Malicious. Despite the clerk's claim that she "just looked," accessing patient records without a treatment relationship is a federal crime under HIPAA (42 USC § 1320d-6). The subsequent disclosure of protected health information to a friend who posted it on social media constitutes a reportable HIPAA breach. The motivation may not be financial, but the act is deliberate: she knowingly accessed records she had no legitimate need to view, and she knowingly disclosed the information to an unauthorized person.

**Behavioral Indicators:**
- EHR access for a patient with whom the clerk has no treatment relationship (no appointment, no registration, no referral)
- Access occurring outside the clerk's normal workflow (viewing an inpatient record when her role only handles outpatient registration)
- Patient record accessed from a registration workstation outside of an active check-in transaction

**Existing Control:** C-006 (Password Policy) and C-007 (Account Management) provide individual authentication, ensuring the access is attributable to the clerk. However, C-006 covers authentication, not authorization monitoring. No control in the matrix addresses access monitoring or behavioral analytics on the EHR.

**Gap Exploited:** GAP-003 (No Centralized Log Management) and GAP-016 (No DLP Controls). EHR audit logs exist and would record the access, but nobody reviews them. Even if someone reviewed the logs, no DLP control would flag the access as anomalous because the clerk used legitimate credentials within her authorized access scope. The access was illegitimate in purpose but technically authorized in execution.

**Recommended Mitigation:** Implement EHR access auditing with automated behavioral analytics. The EHR system should automatically flag accesses where the user has no documented treatment relationship with the patient (no appointment, no referral, no care team assignment). These flags should feed into the Wazuh SIEM as alerts for daily review by the privacy officer. Additionally, implement a "break-the-glass" access model: the clerk can access any record in emergencies, but doing so triggers an immediate alert and requires post-access justification.

---

## Scenario 5: The Overworked Admin

**Classification:** Negligent. The sysadmin's intent is efficiency, not sabotage. He wrote a password reset script to handle ticket volume and shared it with a colleague to "help with the backlog." However, storing Active Directory admin credentials in plaintext on a desktop and emailing the script externally are severe security violations. The admin may not recognize the risk, but the outcome creates a credential exposure that any external attacker or internal threat actor could exploit with minimal effort.

**Behavioral Indicators:**
- Script files (.ps1, .bat, .sh) containing plaintext credential strings appearing on workstations or in email
- Email attachments containing executable scripts with embedded authentication tokens
- Multiple staff using a single administrative credential for password resets rather than individual delegated admin accounts

**Existing Control:** C-007 (Account Management) covers password management practices. C-015 (Remote Access Security) addresses authentication. However, no control addresses secure credential handling in scripts or administrative tooling.

**Gap Exproited:** GAP-017 (No Formal Change Management Process). The script was developed and shared without review, approval, or security assessment. Additionally, GAP-004 (No MFA on Any System) means the plaintext admin credentials, if obtained by an attacker, provide immediate access to Active Directory without a second authentication factor.

**Recommended Mitigation:** Replace the plaintext credential script with a delegated administration model using Just Enough Administration (JEA) for PowerShell. JEA allows specific users to run predefined PowerShell commands with elevated privileges without giving them full Domain Admin access. Credentials are handled by the system, never exposed to the admin. Additionally, implement a secure credential vault (e.g., Windows Credential Guard or a PAM solution) for any scripting requiring elevated credentials. Pair this with a change management policy requiring security review of all administrative scripts before deployment.

---

## Pattern Assessment

The systemic weakness that makes insider threats particularly dangerous at MedDefense is the complete absence of detective controls combined with broad, unaudited access to sensitive systems. GAP-003 (No Centralized Log Management) ensures that no insider behavior, whether negligent or malicious, generates alerts, is reviewed, or is correlated across systems. The shared radiology account (Scenario 1) persists because nobody reviews PACS access logs. The ghost VPN account (Scenario 2) went undiscovered because nobody monitors authentication patterns. Dr. Patel's NAS (Scenario 3) exists because nobody monitors the network for unauthorized devices. The curious clerk (Scenario 4) acted with impunity because nobody reviews EHR access against treatment relationships. The overworked admin's plaintext credentials (Scenario 5) circulate because nobody reviews email for sensitive data exposure. In every case, the individual behavior varied, but the systemic enabler was identical: MedDefense has no visibility into what happens inside its own network. Until Wazuh SIEM is deployed (GAP-003 remediation) and DLP controls are implemented (GAP-016), every insider, whether well-meaning or hostile, operates with the same invisibility that the external cryptominer enjoyed for 14+ days on billing-srv-01. The network sees nothing, and therefore the organization knows nothing.
