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

