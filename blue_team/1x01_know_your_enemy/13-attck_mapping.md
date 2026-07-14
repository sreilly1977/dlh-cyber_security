# ATT&CK Mapping: MedDefense Attack Scenarios

**Date:** July 14, 2026  
**Classification:** CONFIDENTIAL – SECURITY ASSESSMENT  
**Framework:** MITRE ATT&CK Enterprise (v14)  
**References:** Scenario Narratives, Project 1x00 Gap Analysis  

---

## Scenario Alpha: "Operation Flatline" (Ransomware Campaign)

**Step 1:** Affiliate purchases list of healthcare orgs with Fortinet VPN.
  **Tactic:** Resource Development
  **Technique:** Acquire Access (T1586)
  **MedDefense Factor:** Industry vulnerability databases (like Shodan/CISA) identify Fortinet exposure; MedDefense is on the list due to unpatched perimeter devices (GAP-010).

**Step 2:** Spear phishing email to Sarah Park, malicious macro document, PowerShell payload.
  **Tactic:** Initial Access
  **Technique:** Phishing: Spearphishing Attachment (T1566.001)
  **MedDefense Factor:** No MFA on O365 (GAP-004) means email is accessible; no advanced threat protection scanning macros (C-018 underutilized).

**Step 3:** Reverse shell connection, persistent backdoor via Scheduled Task (disguised as Windows Update).
  **Tactic:** Persistence
  **Technique:** Scheduled Task/Job: Scheduled Task (T1053.005)
  **MedDefense Factor:** No endpoint monitoring detects new tasks; no baseline deviation alerts (GAP-003).

**Step 4:** Network discovery commands (`nltest`, `net group`, `arp -a`) mapping entire 10.10.0.0/16.
  **Tactic:** Discovery
  **Technique:** Network Service Discovery (T1046) + Account Discovery (T1087)
  **MedDefense Factor:** Flat network architecture (GAP-001) allows full visibility from single workstation; no internal firewalls to block scanning traffic.

**Step 5:** Mimikatz credential dump, capture of svc_backup NTLM hash.
  **Tactic:** Credential Access
  **Technique:** OS Credential Dumping: LSASS Memory (T1003.001)
  **MedDefense Factor:** No EDR/AV detection of Mimikatz (GAP-012); Domain Admin credentials cached on workstation due to lack of Least Privilege.

**Step 6:** Pass-the-hash attack to `ad-dc-01`, gaining Domain Admin rights.
  **Tactic:** Lateral Movement
  **Technique:** Pass the Hash (T1550.002)
  **MedDefense Factor:** Flat network allows direct RPC/SMB traffic from workstation to DC (GAP-001); no MFA on admin accounts (GAP-004) enables reuse of hashes.

**Step 7:** Export patient database (pg_dump), compress data, exfiltrate via Rclone over HTTPS.
  **Tactic:** Exfiltration
  **Technique:** Exfiltration Over Web Service: Exfiltration to Cloud Storage (T1567.001)
  **MedDefense Factor:** Database port 5432 open network-wide (GAP-001); No DLP controls (GAP-016) to block bulk export.

**Step 8:** Delete NAS backups, delete Volume Shadow Copies (`vssadmin`).
  **Tactic:** Defense Evasion
  **Technique:** Disable Backup Services (T1485) / Disable Restore Points (T1490)
  **MedDefense Factor:** Backups co-located on same network (GAP-005) make them reachable and deletable by attacker.

**Step 9:** GPO deployment of ransomware, encryption of all Windows systems.
  **Tactic:** Impact
  **Technique:** Data Encrypted for Impact (T1486)
  **MedDefense Factor:** Domain Admin privileges allow Group Policy deployment to entire domain (GAP-004 failure).

---

## Scenario Beta: "The Quiet Departure" (Insider Data Theft)

**Step 1:** Employee learns of layoff, plans data theft.
  **Tactic:** Pre-Attack (Not mapped to Enterprise Matrix, but enables Persistence)
  **Technique:** N/A (Human Motivation)
  **MedDefense Factor:** No insider threat awareness program (Training Gap).

**Step 2:** Assessing data visibility through billing interface and EHR read-only access.
  **Tactic:** Discovery
  **Technique:** Application Window Discovery (T1010) / Data Discovery (T1082)
  **MedDefense Factor:** EHR lacks volume limits or behavior monitoring (GAP-003).

**Step 3:** Exporting 200 records/day via built-in export function, no alerts triggered.
  **Tactic:** Collection
  **Technique:** Data from Local System (T1005)
  **MedDefense Factor:** No DLP policy enforcing export limits (GAP-016); Audit logs exist but nobody reviews them (GAP-003).

**Step 4:** Transferring CSV files to personal USB drive.
  **Tactic:** Exfiltration
  **Technique:** Exfiltration Over Physical Media (T1048.002)
  **MedDefense Factor:** No Group Policy disabling USB storage (GAP-012); Unmanaged endpoints allow unrestricted removable media.

**Step 5:** Deleting CSV files and emptying recycle bin to cover tracks.
  **Tactic:** Defense Evasion
  **Technique:** Indicator Removal on Host: Clear Windows Event Logs (T1070.001)
  **MedDefense Factor:** Local logs are cleared; central logs (if they existed) might show deletion, but no SIEM (GAP-003) exists to correlate.

**Step 6:** Copying database credentials from config file on workstation to USB.
  **Tactic:** Credential Access
  **Technique:** Credentials from Password Stores (T1555)
  **MedDefense Factor:** Plaintext credentials stored in app config (Bad Practice); No PAM solution (GAP-004/GAP-017).

**Step 7:** Account remains active for 5 days post-departure (ticket sits in queue).
  **Tactic:** Persistence
  **Technique:** Valid Accounts (T1078)
  **MedDefense Factor:** No automated offboarding process (GAP-014); Manual ticket queue delays deactivation.

**Step 8:** Connecting via VPN post-departure, extracting 400 records via database credentials.
  **Tactic:** Exfiltration
  **Technique:** Data from Non-Standard Port (T1571) + Database T1005
  **MedDefense Factor:** VPN access still granted (GAP-014); Database port accessible from any network location including home IP (GAP-001).

---

## ATT&CK Coverage Assessment

Both attack scenarios converge heavily on three critical tactics: **Credential Access**, **Discovery**, and **Persistence**. In Alpha, attackers dumped LSASS memory and used pass-the-hash because Domain Admin credentials were cached on a workstation with no MFA (GAP-004) and no EDR (GAP-012). In Beta, the insider exploited stored plaintext credentials and valid accounts that persisted after termination (GAP-014). The **Discovery** tactic appears in both because the flat network (GAP-001) makes enumeration trivial for the external attacker and the EHR system makes data discovery trivial for the insider. The **Persistence** tactic differs (scheduled task vs. valid account) but shares the same root cause: lack of session monitoring and lifecycle management. This tells us that MedDefense needs detection capability most urgently in **Credential Access** (deploy Wazuh SIEM to flag Mimikatz/hash dumping patterns) and **Discovery** (monitor for network scanning tools like BloodHound/nmap). Furthermore, preventing **Persistence** requires MFA (GAP-004) to stop credential reuse and automated offboarding (GAP-014) to terminate valid accounts immediately. Without these three layers, any initial access—phishing or insider—leads inevitably to total compromise.

---

*Prepared by: Security Department*  
*References: Project 1x00 Gap Analysis, MITRE ATT&CK Framework v14*
