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

# 
