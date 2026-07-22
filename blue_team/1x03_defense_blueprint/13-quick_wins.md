# 13. The Quick Wins

## Goal

Identify and design 5 security improvements that can be implemented within 2 weeks at zero or minimal cost.

## Context

The full roadmap takes 6 months. The Board approved the budget last week. But James Chen has a more immediate concern: "What can we do THIS WEEK that makes us safer? Not the big purchases. Not the architecture changes. What can we do with what we already have?" Quick wins matter because they demonstrate momentum, reduce risk immediately, and build credibility with the Board before the big spending begins.

---

## Quick Win #1: Disable Public RDP Access on billing-srv-01

| Field | Value |
|---|---|
| **Risk Addressed** | RISK-009 (Ransomware via RDP on billing infrastructure) |
| **Action** | (1) Identify all public-facing RDP endpoints by reviewing firewall NAT rules and external port scans. (2) Modify the edge firewall to block inbound TCP 3389 from all external IP ranges. (3) Configure a temporary VPN profile for billing staff who require remote access to billing-srv-01. (4) Document the change in the change management system with emergency priority justification. (5) Notify billing department leadership that remote access now requires VPN connection. |
| **Owner** | CTO (network engineering team executes) |
| **Timeline** | 1 day |
| **Cost** | $0 — Uses existing firewall infrastructure and VPN concentrator already deployed but underutilized |
| **Risk Reduction** | Eliminates the primary kill chain entry point identified in 1x01 Kill Chain #2 where the cybercriminal group used brute-force RDP to gain initial access to billing-srv-01. By removing the internet-facing RDP port, the attacker cannot reach Step 1 (Initial Access) of that kill chain, disrupting the entire attack sequence before it begins. This is the single highest-impact free action available. |
| **Verification** | (1) Run external port scan against MedDefense's public IP range to confirm TCP 3389 is closed. (2) Have a billing staff member attempt remote access via RDP directly and confirm connection is refused. (3) Have the same staff member connect via VPN and confirm RDP works through the tunnel. (4) Review firewall logs to confirm no inbound 3389 traffic is passing. |

---

## Quick Win #2: Enforce Account Lockout Policy via Group Policy

| Field | Value |
|---|---|
| **Risk Addressed** | RISK-004 (Credential compromise via phishing) and RISK-009 (brute force on billing server) |
| **Action** | (1) Open Group Policy Management Console on the domain controller. (2) Create a new GPO named "SEC-AccountLockout-Policy." (3) Configure the following settings under Computer Configuration → Windows Settings → Security Settings → Account Policies → Account Lockout Policy: Account lockout threshold = 5 failed attempts, Account lockout duration = 30 minutes, Reset account lockout counter after = 30 minutes. (4) Link the GPO to the root domain OU so it applies to all user and computer accounts. (5) Run gpupdate /force on critical servers including billing-srv-01 and EHR application servers. (6) Document the policy change and notify helpdesk staff to expect lockout-related support calls. |
| **Owner** | CISO (system administration team executes) |
| **Timeline** | 2 days |
| **Cost** | $0 — Uses existing Active Directory infrastructure and Group Policy engine already in place |
| **Risk Reduction** | Disrupts the brute-force and credential stuffing attack paths referenced in 1x01 Kill Chain #2 (Step 2, Establish Foothold) where the attacker used automated password spraying against exposed services. With a 5-attempt lockout and 30-minute reset window, automated tools running thousands of attempts per minute are rendered ineffective against all domain-joined systems, forcing attackers to either abandon the approach or slow down to a rate that makes detection feasible even with current monitoring gaps. |
| **Verification** | (1) Attempt 5 failed logins on a test account and confirm the account locks. (2) Confirm the account unlocks after 30 minutes. (3) Run gpresult /r on billing-srv-01 and an EHR workstation to confirm the GPO is applied. (4) Check domain controller security event logs for Event ID 4740 (account locked) to confirm logging is capturing lockout events. |

---

## Quick Win #3: Enable Local Firewall on All Windows Servers

| Field | Value |
|---|---|
| **Risk Addressed** | RISK-002 (Third-party vendor breach lateral access) and RISK-001 (Ransomware lateral movement) |
| **Action** | (1) Inventory all Windows servers from the 1x00 asset registry to identify those with Windows Firewall disabled. (2) For each server, enable Windows Defender Firewall with the following profile configuration: Domain profile = On, Private profile = On, Public profile = On. (3) Set default inbound behavior to "Block" for all profiles. (4) Create inbound exceptions only for required services (e.g., SQL port 1433 for EHR database, RPC for Active Directory, HTTPS 443 for web applications). (5) Apply via GPO named "SEC-WindowsFirewall-Enable" linked to the Servers OU. (6) Test each critical application after deployment to confirm no service interruptions. (7) Rollback plan: disable the GPO and document for emergency reversal. |
| **Owner** | CTO (server administration team executes) |
| **Timeline** | 5 days (staged rollout: Day 1-2 non-critical servers, Day 3-4 EHR and billing, Day 5 validation) |
| **Cost** | $0 — Windows Defender Firewall is included in all Windows Server licenses MedDefense already owns |
| **Risk Reduction** | Creates a baseline host-level segmentation that disrupts the lateral movement steps in 1x01 Kill Chain #1 (Step 3, Lateral Movement/Escalation) and Kill Chain #2 (Step 3). The flat network architecture identified as GAP-003 means that once an attacker gains any foothold, they can reach any system. Enabling host firewalls on servers closes unnecessary ports that ransomware and attackers use for propagation (e.g., SMB on servers that do not need to share files, RDP between servers that do not administratively require it). This does not replace proper network segmentation but provides an immediate compensating control while the segmentation project is scoped. |
| **Verification** | (1) Run Get-NetFirewallProfile on each server via PowerShell remoting to confirm all three profiles are enabled. (2) Port scan each server from a workstation on a different subnet to confirm only intended ports are reachable. (3) Have EHR and billing application owners confirm their systems function normally. (4) Review GPO application status in Group Policy Results for any servers showing errors. |

---

## Quick Win #4: Disable USB Mass Storage on All Workstations via Group Policy

| Field | Value |
|---|---|
| **Risk Addressed** | RISK-001 (Ransomware initial infection vector) |
| **Action** | (1) Create a GPO named "SEC-USBStorage-Disable." (2) Navigate to Computer Configuration → Administrative Templates → System → Removable Storage Access. (3) Enable "All Removable Storage classes: Deny all access" for all removable storage device classes. (4) Optionally, create a security group called "USB-Exception-Approved" and configure the GPO to exempt members of this group for specific approved scenarios (e.g., imaging technicians transferring DICOM files). (5) Link the GPO to all workstation OUs. (6) Run gpupdate /force on a sample of workstations across clinical, administrative, and billing areas. (7) Notify department managers that USB drives will no longer function and provide approved alternatives (network file shares, approved encrypted USB drives via IT Security). |
| **Owner** | CISO (desktop administration team executes) |
| **Timeline** | 3 days |
| **Cost** | $0 — Uses existing Active Directory Group Policy infrastructure. If approved encrypted USB drives are purchased for exceptions, approximate cost is $300 for 10 drives. |
| **Risk Reduction** | Eliminates the USB-based malware introduction vector identified in 1x02 vulnerability scan findings (VULN-006) where uncontrolled USB ports were flagged as a high-risk entry point. In 1x01 Kill Chain #3 (Social Engineering Attack), the threat actor used a discarded USB drive in the parking lot as the initial access vector, relying on an employee plugging it into a workstation. By blocking all removable storage at the OS level, this kill chain is severed at Step 1 (Initial Access) regardless of user behavior. The control is especially valuable because it does not depend on user judgment or awareness training, closing the gap until DLP and endpoint controls are fully deployed. |
| **Verification** | (1) Insert a USB drive into a sample workstation in each department and confirm it is not accessible (Windows displays an access denied message). (2) Attempt the same on a member of the USB-Exception-Approved group and confirm access works. (3) Run gpresult /r on a sample workstation to confirm the GPO is applied. (4) Check Windows Event Viewer for Event ID 6551 (removable storage blocked) to confirm logging is functional. |

---

## Quick Win #5: Audit and Disable Inactive Active Directory Accounts

| Field | Value |
|---|---|
| **Risk Addressed** | RISK-003 (Insider threat exfiltrates PHI) and RISK-004 (Credential compromise via phishing) |
| **Action** | (1) Export all Active Directory user accounts using Get-ADUser with properties including LastLogonDate, Enabled, and MemberOf. (2) Identify accounts that have not logged in for 90+ days (excluding service accounts, which require separate review with application owners). (3) Sort accounts by privilege level, prioritizing domain admins, enterprise admins, and members of sensitive security groups. (4) For each inactive account: disable the account, move it to a quarantine OU named "Disabled-Accounts-Pending-Review," and document the action in a spreadsheet with account name, last logon date, manager, and disable date. (5) For accounts inactive 30-90 days, send an email to the employee's manager requesting confirmation of continued need. (6) Review all service accounts for unnecessary domain admin privileges and document recommendations for privilege reduction. (7) Schedule a recurring monthly review process and assign ownership to the IT Security team. |
| **Owner** | CISO (IT Security analyst executes, HR confirms employment status) |
| **Timeline** | 7 days (Day 1-2: Export and analysis, Day 3-4: Manager confirmations, Day 5-6: Disable inactive accounts, Day 7: Documentation and process handoff) |
| **Cost** | $0 — Uses existing Active Directory infrastructure, PowerShell (already installed), and staff time already allocated. |
| **Risk Reduction** | Shrinks the attack surface for both insider threat and credential compromise kill chains. In 1x01 Kill Chain #4 (Insider Threat Path), the disgruntled former employee used credentials from an account that had not been disabled after their departure. The account retained EHR access for 4 months post-departure, enabling PHI exfiltration via Step 1 (Initial Access using valid credentials). Similarly, in 1x01 Kill Chain #2 (Ransomware via RDP), dormant accounts with weak or unchanged passwords were identified as likely brute-force targets because attackers assume they are unmonitored. By disabling all inactive accounts, both kill chains lose their easiest entry points and the overall credential attack surface is reduced to only active, monitored users. |
| **Verification** | (1) Attempt to authenticate with a disabled account and confirm access is denied. (2) Run a PowerShell script counting enabled accounts versus disabled accounts and compare against the pre-audit baseline to confirm reduction. (3) Confirm all disabled accounts are in the Disabled-Accounts-Pending-Review OU via Active Directory Users and Computers console. (4) Review the service account privilege report and confirm that no non-essential service accounts retain domain admin membership. (5) Spot-check 5 disabled accounts against HR records to confirm the employees are no longer active or on extended leave without system need. |

---

## Why Quick Wins Matter Beyond Immediate Risk Reduction

Quick wins serve a critical organizational purpose in the first month of a security program that extends far beyond the technical risk reduction they provide. They demonstrate to the Board, to executive leadership, and to the broader workforce that the security program is not a paper exercise but an operational reality capable of producing tangible results quickly. When James Chen walks into the next Board meeting and reports that public RDP exposure has been eliminated, account lockout is enforced, host firewalls are active, USB ports are locked down, and dormant accounts have been purged, he is not just listing technical achievements. He is proving that the security investment is already producing returns, that the team he hired understands the environment, and that the organization's risk posture has measurably improved since the last meeting. This momentum builds trust, which translates into sustained budget support when the larger expenditures come before the Board. Equally important, quick wins shift the organizational culture. When employees see that security policies are being enforced through technical controls rather than just written in documents, the tone shifts from "security as paperwork" to "security as practice." The helpdesk learns to handle lockout calls, department managers learn that USB drives no longer work, and the IT team practices change management under security priorities. Each quick win is a small rehearsal for the larger transformation ahead, building muscle memory and organizational tolerance for the disruptions that a full security program rollout will inevitably bring. In this sense, quick wins are as much about organizational change management as they are about threat mitigation.
