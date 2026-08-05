# 0. Domain Reconnaissance

Goal: Map the entire MedDefense Active Directory environment from a security perspective, establishing the Windows baseline equivalent of 2x00 Task 0.

Context: Before you harden a Windows domain, you need to understand what you are working with. How many users? What groups? What service accounts? What GPOs exist? What are the current password and audit policies? This is the Windows equivalent of the Lynis baseline from 2x00 Task 0.

Instructions: Write a PowerShell script 0-domain_baseline.ps1 that captures the complete security state of the MedDefense domain and produces a structured report:

- Domain information: domain name, forest level, domain controllers

- All user accounts: name, enabled/disabled, last logon, password last set, password never expires flag

- All groups and their members

- All service accounts (accounts with "svc" in the name or in the Service Accounts OU)

- All GPOs linked to the domain and OUs

- Current password policy: minimum length, complexity, history, max age

- Current account lockout policy (or "NOT CONFIGURED" if absent)

- Kerberos encryption types supported

- All users with Domain Admin or Enterprise Admin privileges

- Summary with security findings count

**Expected Output:**

```PS
PS> .\0-domain_baseline.ps1
Domain: meddefense.local
DC: DC01.meddefense.local
User Accounts: 14
  Password Never Expires: 6
Service Accounts: 3
  Unconstrained delegation: 3
GPOs: 2 (Default only)
Password Minimum Length: 7
Complexity: Disabled
Lockout Threshold: 0                      
Kerberos: DES, RC4, AES128, AES256
Domain Admins: Administrator, analyst
Findings: 9 (Critical: 3, High: 4, Medium: 2)
```

---

# 1. Domain Risk Findings Extractor

Goal: Produce the actionable findings inventory that drives the Windows hardening workflow.

Context: Task 0 maps the domain baseline, but baseline data alone is not enough. The security engineer needs a findings inventory that identifies exactly what must be remediated, which task remediates it, and how severe the risk is. This rebuilt task connects Active Directory weaknesses to password policy, audit policy, Kerberos hardening, service account control, GPO hardening, and stale object cleanup.

Instructions: Write 1-domain_findings.ps1.

The script must audit meddefense.local and generate domain_security_findings.json.

It must identify:

    Accounts with PasswordNeverExpires, including account name, enabled state, group memberships, password last set date, and whether it is a service account.
    Disabled accounts in privileged groups: Domain Admins, Enterprise Admins, and G_IT_Admins.
    Stale computer objects with no logon/authentication activity in 90+ days.
    Password and lockout policy gaps against the Windows Fortress target state: minimum length 14, complexity enabled, history 24, lockout threshold 5.
    Missing audit visibility for process creation, special logon, account management, object access, and PowerShell/Sysmon readiness.
    Service account risks: interactive logon allowed, unconstrained delegation, DES-only flag, privileged membership, stale password, or suspicious last logon.
    Weak GPO security posture: default-only GPOs, no MedDefense hardening GPOs, or GPOs without clear security purpose.

Each finding object must include id, severity, category, asset, evidence, risk, recommended_remediation, and mapped_task.

Expected Output:

```PS
PS> .\1-domain_findings.ps1
[CRITICAL] Password policy minimum length: 7
[CRITICAL] Account lockout: not configured
[CRITICAL] Kerberos DES/RC4 enabled
[HIGH] 6 accounts with PasswordNeverExpires
[HIGH] 3 service accounts with unconstrained delegation
[HIGH] Advanced Audit Policy: not configured
[MEDIUM] Stale computer objects: 2
[MEDIUM] No MedDefense hardening GPOs present

Findings: 9
Critical: 3
High: 4
Medium: 2
Report saved to: domain_security_findings.json
```

---

# 2. Windows Event Log Assessment

Goal: Assess the current event logging capability by checking which critical Event IDs the domain is actually generating and identifying the visibility gaps.

Context: You need to know what the domain is currently capable of seeing. If Event ID 4688 (process creation) is not being generated, then every process the attacker runs is invisible. If Event ID 4672 (special logon) is not logged, you cannot detect when someone uses admin privileges. This task quantifies the gap between what the domain sees now and what it needs to see.

Instructions: Write a PowerShell script 2-eventlog_assessment.ps1 that:

    Checks the current audit policy configuration using auditpol /get /category:*

    For each critical Event ID (4624, 4625, 4648, 4688, 4720, 4726, 4732, 4672, 1102), checks whether the required audit subcategory is enabled

    Queries the Security log to confirm which Event IDs have actually been generated in the last 24 hours

Expected Output:

```PS
PS> .\2-eventlog_assessment.ps1
Event ID  Description               Audit Subcategory     Status
--------  -----------               -----------------     ------
4624      Successful Logon          Logon                 [GENERATING]
4625      Failed Logon              Logon                 [GENERATING]
4648      Explicit Credentials      Logon                 [NOT CONFIGURED]
4688      Process Creation          Process Tracking      [NOT CONFIGURED]
4720      Account Created           Account Management    [NOT CONFIGURED]
4726      Account Deleted           Account Management    [NOT CONFIGURED]
4732      Member Added to Group     Account Management    [NOT CONFIGURED]
4672      Special Logon             Special Logon         [NOT CONFIGURED]
1102      Audit Log Cleared         System Integrity      [GENERATING]
```

---

# 3. Windows Telemetry Reference Builder

Goal: Build a machine-readable Windows event reference that connects security events to MedDefense detection use cases.

Context: The original task was too static. This rebuilt task creates an operational reference mapping Event IDs to log source, audit dependency, detection meaning, Crimson Tide phase, triage priority, and validation method. This becomes the bridge between audit policy configuration, Sysmon deployment, PowerShell logging, and Module 3 detection work.

Instructions: Write 3-telemetry_reference.ps1.

The script must generate windows_event_reference.json.

The reference must include:

Security log: 4624, 4625, 4648, 4672, 4688, 4720, 4726, 4732, 1102.

PowerShell log: 4103, 4104.

Sysmon log: 1, 3, 7, 11, 13, 22.

For each event include event_id, event_name, log_source, audit_or_sensor_dependency, security_meaning, normal_frequency, triage_priority, crimson_tide_phase, example_suspicious_pattern, and validation_method.

Expected Output:

```PS
PS> .\3-telemetry_reference.ps1
Security events mapped: 9
PowerShell events mapped: 2
Sysmon events mapped: 6
Total events documented: 17
Reference saved to: windows_event_reference.json
```

---

# 4. Password and Lockout Policy

Goal: Deploy a CIS-compliant password and account lockout policy via Group Policy, fixing the two most critical findings from your domain assessment.

Context: Finding password minimum length is 7, complexity disabled, no lockout. The Crimson Tide advisory documented that weak passwords and absent lockout enabled brute-force and credential harvesting in all 5 hospital breaches. This is the single highest-impact GPO you will create.

Instructions: Write a PowerShell script 4-password_policy.ps1 that:

    Creates a new GPO named "MedDefense - Password and Lockout Policy"

    Configures password settings:

        Minimum length: 14 characters

        Complexity: Enabled

        History: 24 passwords remembered

        Maximum age: 0

        Minimum age: 1 day

    Configures account lockout:

        Lockout threshold: 5 attempts

        Lockout duration: 15 minutes

        Reset counter: 15 minutes

    Links the GPO to the domain root

    Forces a group policy update

    Verifies the policy is applied by querying the effective policy

Expected Output:

```PS
PS> .\4-password_policy.ps1
[*] Creating GPO: "MedDefense - Password and Lockout Policy"... CREATED
[*] Configuring Password Policy...
    Minimum Length: 14            [SET]
    Complexity: Enabled           [SET]
    History: 24                   [SET]
    Maximum Age: 0                [SET]
    Minimum Age: 1 day            [SET]
[*] Configuring Account Lockout...
    Threshold: 5 attempts         [SET]
    Duration: 15 minutes          [SET]
    Reset Counter: 15 minutes     [SET]
[*] Linking GPO to domain root... LINKED
[*] Forcing Group Policy update... COMPLETE
```

---

# 5. Advanced Audit Policy

Goal: Configure Advanced Audit Policies via GPO to generate the security events needed for detection, closing the visibility gaps identified in Task 2.

Context: The default Windows audit policy logs almost nothing useful. Event ID 4688 (process creation) is not generated by default. Command-line logging in process events is disabled. Privilege use is not audited. This means that if an attacker runs PowerShell on a MedDefense workstation right now, there is zero evidence of what they executed. The Advanced Audit Policy replaces the basic policy with granular per-category configuration. This is what transforms Windows Event Logs from "noise" to "evidence."

Instructions: Write a PowerShell script 5-audit_policy.ps1 that:

    Creates a GPO named "MedDefense - Advanced Audit Policy"

    Configures the following audit categories (Success and Failure where applicable):

        Account Logon: Credential Validation (S/F), Kerberos Authentication (S/F)

        Logon/Logoff: Logon (S/F), Logoff (S), Special Logon (S)

        Account Management: User Account Management (S/F)

        Privilege Use: Sensitive Privilege Use (S/F)

        Object Access: File System (S/F), Registry (S/F)

        Process Tracking: Process Creation (S)

    Enables command-line logging in process creation events (adds full command line to Event ID 4688)

    Restricts Security log clearing to Domain Admins only

    Configures Security log size to 1 GB

    Links the GPO and forces an update

    Verifies with auditpol /get /category:*

Expected Output:

```PS
PS> .\5-audit_policy.ps1
[*] Creating GPO: "MedDefense - Advanced Audit Policy"... CREATED
[*] Configuring Audit Categories...
    Credential Validation:    Success, Failure   [SET]
    Kerberos Authentication:  Success, Failure   [SET]
    Logon:                    Success, Failure   [SET]
    Special Logon:            Success            [SET]
    User Account Management:  Success, Failure   [SET]
    Sensitive Privilege Use:  Success, Failure   [SET]
    Process Creation:         Success            [SET]
[*] Enabling command-line in process creation events...   [SET]
[*] Restricting Security log clearing...                  [SET]
[*] Setting Security log max size to 1 GB...              [SET]
[*] Linking GPO and forcing update... COMPLETE
```

---

# 6. PowerShell Security

Goal: Configure PowerShell logging and execution restrictions to ensure every PowerShell command executed on MedDefense systems is captured, neutralizing the attacker's most powerful post-exploitation tool.

Context: PowerShell is the most commonly abused legitimate tool in post-exploitation. The Crimson Tide advisory noted powershell.exe -enc [base64] in the process creation logs of compromised hospitals (Phase 3). Without Script Block Logging, encoded PowerShell commands are invisible. Without Module Logging, you cannot trace which capabilities the attacker loaded. Without Transcription, you have no complete record of the session.

Instructions: Write a PowerShell script 6-powershell_security.ps1 that:

    Creates a GPO named "MedDefense - PowerShell Security"

    Enables Script Block Logging (logs the decoded content of every PowerShell script, including encoded commands)

    Enables Module Logging for all modules

    Enables Transcription to C:\PSTranscripts\

    Verifies AMSI integration is active

    Tests by running an encoded PowerShell command and verifying it appears decoded in Event ID 4104

Expected Output:

```PS
PS> .\6-powershell_security.ps1
[*] Creating GPO: "MedDefense - PowerShell Security"... CREATED
[*] Configuring Script Block Logging...
    EnableScriptBlockLogging = 1           [SET]
    -> Event ID 4104 captures decoded scripts
[*] Configuring Module Logging...
    EnableModuleLogging = 1, ModuleNames = *  [SET]
    -> Event ID 4103 captures module invocations
[*] Configuring Transcription...
    OutputDirectory = C:\PSTranscripts     [SET]
[*] Verifying AMSI... AMSI DLL loaded     [OK]
[*] Linking GPO and forcing update... COMPLETE
[*] Testing encoded command...
    Input: powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABlAHMAdAAi
    Event ID 4104 found: "Write-Host 'Test'"  [VERIFIED]
```

---

# 7. Kerberos and Authentication Hardening

Goal: Disable weak Kerberos encryption types and harden authentication protocols to block Kerberoasting and credential theft attacks.

Context: Finding from 1x02: "Active Directory supports DES and RC4 Kerberos encryption types." The Crimson Tide advisory confirmed: "In 3 of 5 cases, the attacker exploited Kerberoasting (RC4-encrypted service tickets cracked offline)." RC4 tickets can be cracked in minutes with hashcat. AES-256 tickets take years. The fix is straightforward: disable DES and RC4, enforce AES-only. But if any legacy application authenticates using RC4, disabling it breaks that authentication.

Instructions: Write a PowerShell script 7-auth_hardening.ps1 that:

    Queries the current Kerberos encryption types supported by the domain

    Identifies any service accounts with the "Use DES encryption types" flag

    Checks each service account's SPN configuration

    Disables DES on all flagged accounts

    Configures the domain to support only AES128 and AES256 for Kerberos

    Disables NTLMv1 (allows only NTLMv2 as fallback)

    Configures Credential Guard awareness

    Verifies the new configuration

Expected Output:

```PS
PS> .\7-auth_hardening.ps1
[*] Current Kerberos types: DES, RC4, AES128, AES256
    [!] DES enabled - trivially breakable
    [!] RC4 enabled - Kerberoastable
[*] Accounts with DES flag...
    svc_sql: UseDESKeyOnly = True          [!]
[*] Service Principal Names...
    svc_backup: HTTP/backup.meddefense.local
    svc_ehr: HTTP/ehr.meddefense.local
    svc_sql: MSSQLSvc/sql.meddefense.local:1433
    [!] All 3 SPNs are Kerberoastable targets
[*] Remediating...
    svc_sql: Clearing DES flag              [DONE]
    Supported encryption: AES128 + AES256   [SET]
    NTLMv1: Refused (LmCompatibilityLevel=5) [SET]
[*] Verifying...
    Kerberos: AES128, AES256 only           [VERIFIED]
    NTLM: v2 only                           [VERIFIED]
```

---

# 8. SMB and Protocol Hardening

Goal: Disable SMBv1 and enforce SMB signing to eliminate one of the most commonly exploited lateral movement vectors in enterprise Windows environments.

Context: SMBv1 is the protocol behind EternalBlue (WannaCry, NotPetya). The Crimson Tide advisory did not use EternalBlue, but SMBv1 remains enabled on MedDefense's domain controller. Disabling it costs nothing and removes an entire class of attacks. SMB signing prevents relay attacks. SMB encryption prevents network sniffing of file transfers.

Instructions: Write a PowerShell script 8-smb_hardening.ps1 that:

    Checks current SMB configuration (v1 enabled, signing, encryption)

    Disables SMBv1 (client and server)

    Enables SMB signing (required, not just enabled)

    Enables SMB encryption where supported

    Disables legacy protocols: NetBIOS over TCP/IP, LLMNR

    Verifies each change with before/after comparison

Expected Output:

```PS
PS> .\8-smb_hardening.ps1
[*] Current SMB Configuration...
    SMBv1: Enabled                         [!]
    Signing Required: False                [!]
    Encryption: False                      [!]
[*] Disabling SMBv1 (server + client)...   [DONE]
[*] Enforcing SMB Signing...               [SET]
[*] Enabling SMB Encryption...             [SET]
[*] Disabling NetBIOS over TCP/IP...       [SET]
[*] Disabling LLMNR via GPO...             [SET]
[*] Verification...
    SMBv1: Disabled                        [VERIFIED]
    Signing: Required                      [VERIFIED]
    Encryption: Enabled                    [VERIFIED]
    LLMNR: Disabled                        [VERIFIED]
```

---

# 9. Sysmon Deployment

Goal: Install and configure Sysmon with a detection-optimized configuration, deploying the single most important endpoint detection tool on the Windows platform.

Context: Windows Event Logs capture authentication and process creation. Sysmon captures everything else: network connections, DNS queries, file creation timestamps, registry modifications, driver loads, WMI events, named pipe connections. Sysmon transforms a Windows endpoint from "I know who logged in" to "I know what they ran, what it connected to, what files it created, what registry keys it modified and what network connections it made." Without Sysmon, detecting the Crimson Tide attacker's lateral movement (PsExec, WMI), data exfiltration (Rclone) and ransomware deployment would be nearly impossible.

Instructions: Write a PowerShell script 9-sysmon_deploy.ps1 that:

    Downloads Sysmon from the Microsoft Sysinternals website

    Downloads the SwiftOnSecurity Sysmon configuration as a baseline

    Installs Sysmon with the configuration

    Verifies Sysmon is running, the driver is loaded and events are generating

    Tests by creating a file in C:\Windows\Temp\ and verifying a Sysmon Event ID 11 (FileCreate) appears

Produce the sysmonconfig.xml as a separate deliverable.

Expected Output:

```PS
PS> .\9-sysmon_deploy.ps1
[*] Downloading Sysmon... OK
[*] Downloading SwiftOnSecurity config... OK
[*] Installing Sysmon with config...
    Sysmon64.exe -accepteula -i sysmonconfig.xml
    Service: Sysmon64 - Running            [OK]
    Driver: SysmonDrv - Loaded             [OK]
[*] Verifying event generation...
    Events in last 60 seconds: 12          [OK]
[*] Testing FileCreate detection...
    Created: C:\Windows\Temp\sysmon_test.txt
    Event ID 11 captured                   [VERIFIED]
```

---

# 10. Sysmon Detection Tuning

Goal: Write custom Sysmon detection rules targeting MedDefense-specific threats, then validate each rule with a controlled trigger.

Context: The SwiftOnSecurity config is a solid baseline, but it is generic. MedDefense has specific threats: Crimson Tide uses Rclone for exfiltration (Phase 4), PsExec for lateral movement (Phase 3), and encoded PowerShell for execution (Phase 3). Custom rules that detect THESE tools are more valuable than generic coverage. Adding rules for process creation from unusual paths, network connections to external IPs from server processes, file creation in startup directories and registry modifications to persistence keys makes the instrumentation specific to the MedDefense threat model.

Instructions: Write a PowerShell script 10-sysmon_tune.ps1 that:

    Loads the current Sysmon configuration

    Adds 5 custom detection rules targeting MedDefense threats:

        Rule 1: Detect rclone.exe execution (exfiltration tool)

        Rule 2: Detect PsExec service installation (registry modification)

        Rule 3: Detect encoded PowerShell execution (-enc in command line)

        Rule 4: Detect vssadmin.exe delete shadows (ransomware pre-encryption)

        Rule 5: Detect new scheduled task creation (persistence)

    Updates the Sysmon configuration

    Trigger-and-verify each rule: execute a safe trigger, check the Sysmon log, report PASS/FAIL

Produce the updated sysmonconfig.xml as a deliverable.

Expected Output:

```PS
PS> .\10-sysmon_tune.ps1
[*] Loading Sysmon config... OK
[*] Adding custom rules...
    Rule 1: Rclone detection                [ADDED]
    Rule 2: PsExec service installation     [ADDED]
    Rule 3: Encoded PowerShell              [ADDED]
    Rule 4: Shadow deletion (vssadmin)      [ADDED]
    Rule 5: Scheduled task persistence      [ADDED]
[*] Updating Sysmon config... OK
[*] Trigger-and-Verify...
    Rule 1: rclone.exe detection            [PASS]
    Rule 2: PsExec registry key             [PASS]
    Rule 3: Encoded PowerShell              [PASS]
    Rule 4: vssadmin execution              [PASS]
    Rule 5: schtasks /create                [PASS]
Custom rules: 5 added | Tests: 5/5 PASS
```

---

# 11. Windows Firewall Lockdown

Goal: Configure Windows Firewall with a default-deny inbound policy and service-specific allow rules, implementing endpoint-level network segmentation.

Context: The domain reconnaissance found: Domain profile ON but permissive, Private and Public profiles OFF. This means any application can listen on any port with no restriction. The firewall should enforce the principle of least privilege at the network level: only the services that MUST be reachable are allowed inbound.

Instructions: Write a PowerShell script 11-firewall_hardening.ps1 that:

    Captures the current firewall state

    Enables ALL three profiles (Domain, Private, Public) with default-deny inbound

    Creates allow rules for required services only:

        RDP (TCP 3389) from management subnet only (10.10.3.0/24)

        DNS (TCP/UDP 53) for DC operation

        LDAP (TCP 389) for AD authentication

        Kerberos (TCP/UDP 88) for AD

        SMB (TCP 445) from server subnet only

        WinRM (TCP 5985/5986) from management subnet only

    Enables logging for dropped packets

    Disables legacy allow rules that conflict with the new policy

Expected Output:

```PS
PS> .\11-firewall_hardening.ps1
[*] Current Firewall State...
    Domain: ON, DefaultInbound: Allow       [!]
    Private: OFF                            [!]
    Public: OFF                             [!]
[*] Setting default-deny on all profiles... [SET]
[*] Creating allow rules...
    MedDef-RDP-Mgmt:  TCP 3389 from 10.10.3.0/24     [CREATED]
    MedDef-DNS:        TCP/UDP 53                    [CREATED]
    MedDef-LDAP:       TCP 389                       [CREATED]
    MedDef-Kerberos:   TCP/UDP 88                    [CREATED]
    MedDef-SMB:        TCP 445 from 10.10.1.0/24     [CREATED]
    MedDef-WinRM:      TCP 5985-5986 from 10.10.3.0/24 [CREATED]
[*] Enabling dropped packet logging...     [SET]
[*] Disabling 42 legacy allow rules...     [DONE]
[*] Verification...
    All 3 profiles: ON, DefaultInbound: Block  [VERIFIED]
    Custom rules: 6 active                     [VERIFIED]
```

---

# 12. AppLocker Policy

Goal: Deploy AppLocker application allow-listing to prevent unauthorized executables from running, blocking the ransomware deployment mechanism used by Crimson Tide.

Context: Crimson Tide deployed ransomware as an executable pushed via GPO. AppLocker would have blocked this: if only approved executables are allowed to run, a malicious payload dropped by GPO fails to execute. AppLocker is the control that would have stopped Phase 6 dead. But AppLocker has a clinical constraint: physicians use a medical imaging application (DicomViewer.exe) signed by a small medical software company. The policy must allow this while blocking everything else.

Instructions: Write a PowerShell script 12-applocker_config.ps1 that:

    Creates a GPO named "MedDefense - AppLocker Policy"

    Configures executable rules (.exe, .com):

        Allow: Windows system directories (C:\Windows\*)

        Allow: Program Files (C:\Program Files\*, C:\Program Files (x86)\*)

        Allow: MedDefense-approved applications (explicit path rule for DicomViewer)

        Deny: All other locations

    Configures script rules (.ps1, .bat, .cmd, .vbs):

        Allow: System scripts from C:\Windows\*

        Allow: Admin scripts from C:\MedDefense_Lab\Scripts\*

        Deny: All other locations

    Sets AppLocker to Audit Only mode (not Enforce, to avoid breaking applications during the testing period)

    Starts the Application Identity service

    Exports the AppLocker policy XML

Expected Output:

```PS
PS> .\12-applocker_config.ps1
[*] Creating GPO: "MedDefense - AppLocker Policy"... CREATED
[*] Starting AppIDSvc... Running           [OK]
[*] Configuring Executable Rules...
    Allow: C:\Windows\*                    [SET]
    Allow: C:\Program Files\*              [SET]
    Allow: C:\Program Files (x86)\*        [SET]
    Allow: DicomViewer.exe (MedImage Corp) [SET]
    Default: DENY                          [SET]
[*] Configuring Script Rules...
    Allow: C:\Windows\*                    [SET]
    Allow: C:\MedDefense_Lab\Scripts\*     [SET]
    Default: DENY                          [SET]
[*] Mode: AUDIT ONLY (not enforcing)
[*] Linking GPO... COMPLETE
[*] Testing...
    notepad.exe from C:\Windows: ALLOWED   [EXPECTED]
    calc.exe from C:\Temp: WOULD BLOCK     [EXPECTED]
Policy exported to: applocker_policy.xml
```

---

# 13. RDP and Remote Access Reduction

Goal: Secure Remote Desktop Protocol to prevent it from being a lateral movement entry point, restricting access to authorized administrators with strong session controls.

Context: RDP was used for lateral movement in the Crimson Tide attack (Phase 3). MedDefense currently allows RDP from any user, with no Network Level Authentication requirement, no session timeout and no restriction on source IP. Clipboard and drive redirection allow an attacker to exfiltrate data directly through the RDP session.

Instructions:

Write a PowerShell script 13-rdp_hardening.ps1 that:

    Enables Network Level Authentication (NLA)

    Restricts RDP access to GITAdmins group only

    Sets session idle timeout to 15 minutes, max session to 8 hours

    Enforces highest encryption level

    Disables clipboard and drive redirection (exfiltration risk)

    Disables Remote Assistance

    Verifies all settings

Expected Output:

```PS
PS> .\13-rdp_hardening.ps1
[*] Enabling NLA... UserAuthentication = 1       [SET]
[*] Restricting to G_IT_Admins...
    Removed: Domain Users from Remote Desktop Users
    Added: G_IT_Admins                           [SET]
[*] Session limits...
    Idle timeout: 15 min                         [SET]
    Max session: 8 hours                         [SET]
[*] Encryption: High/SSL                         [SET]
[*] Clipboard: Disabled                          [SET]
[*] Drive redirection: Disabled                  [SET]
[*] Remote Assistance: Disabled                  [SET]
[*] Verification...
    NLA: Required                                [VERIFIED]
    Access: G_IT_Admins only                     [VERIFIED]
```

---

# 
