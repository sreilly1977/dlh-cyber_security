# Hardening Updates: IR-2026-0420-01

- author: Steve - Cybersecurity Engineer
- date: 2026-10-26
- change_window: staged over 14 days (audit phase 7 days, enforce phase 7 days)
- scope: MedDefense clinical workstations and servers, Site A and Main

## Gap register (derived from forensic_findings.md)

| Gap ID | Gap | Evidence |
|--------|-----|----------|
| GAP-001 | Macro execution unrestricted on clinical workstations. A downloaded .docm executed its macro with no block, and the resulting Office child process ran unhindered. | MEM-001, MEM-002, PRX-001, DISK-003 |
| GAP-002 | Credential material was reusable. A process opened lsass.exe with access mask 0x1010 and obtained hashes; SMB signing was not enforced, so the harvested credential worked for lateral movement across three hosts and a file server. | MEM-005, SYS-001 (EID 10, 0x1010), FS-002, SYS-001 |
| GAP-003 | No application control. An unsigned binary executed from a user-writable directory and registered itself as a service, giving the intruder 72 hours of persistence. | DISK-002, DISK-003, SYS-002 |

## Change 1: Restrict macro execution on non-developer workstations

- **Control:** Block macro execution in internet-origin Office files, and block
  Office applications from creating child processes and executable content.
  Developer and finance workstations retain macro capability through a
  separate policy group with compensating monitoring.
- **Gap closed:** GAP-001
- **Configuration — Group Policy (computer side):**
  `Computer Configuration > Policies > Administrative Templates > Windows
  Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard
  > Attack Surface Reduction > Configure Attack Surface Reduction rules`
  Set to Enabled, then add the following rule IDs with action `1` (Block):
  - `d4f940ab-401b-4efc-aadc-ad5f3c50688a` — Block all Office applications
    from creating child processes
  - `3b576869-a4ec-4529-8536-b80a7769e899` — Block Office applications from
    creating executable content
  - `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` — Block Office applications from
    injecting code into other processes
  - `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` — Block Win32 API calls from
    Office macros
  - `5beb7efe-fd9a-4556-801d-275e5ffc04cc` — Block execution of potentially
    obfuscated scripts
- **Configuration — Group Policy (user side), per Office application:**
  `User Configuration > Policies > Administrative Templates > Microsoft Word
  2016 > Word Options > Security > Trust Center > Block macros from running in
  Office files from the Internet` set to Enabled. Repeat the equivalent path
  for Excel 2016 and PowerPoint 2016.
- **Configuration — registry equivalent (deployed via preference item or
  Intune CSP `./Vendor/MSFT/Policy/Config/Defender/AttackSurfaceReductionRules_Ids`
  and `..._Actions`):**
  - `HKCU\Software\Policies\Microsoft\Office\16.0\word\security\blockcontentexecutionfrominternet`
    REG_DWORD = 1
  - `HKCU\Software\Policies\Microsoft\Office\16.0\word\security\vbawarnings`
    REG_DWORD = 4 (disable all macros without notification)
- **Validation test:**
  1. On a pilot non-developer workstation, download a macro-enabled test
     document through the browser so the Mark-of-the-Web zone identifier is
     applied, then open it. Expected: macro blocked, no prompt offering to
     enable content.
  2. Confirm no Office child process was created:
     `Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational'` filtered
     on Event ID 1 with `ParentImage` ending in `WINWORD.EXE`. Expected: zero
     events for the test window.
  3. Confirm the rule fired in the Defender operational log and, where
     Defender for Endpoint is licensed, in Advanced Hunting by action type
     `AsrOfficeChildProcessBlocked` (audit mode produces
     `AsrOfficeChildProcessAudited`).
  4. Confirm applied configuration:
     `Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,
     AttackSurfaceReductionRules_Actions`
- **Rollback:** Remove the rule IDs from the ASR policy, or set action to `2`
  (Audit) to observe without blocking. Macro policy rolls back by disabling the
  Trust Center setting.

## Change 2: Enforce SMB signing and protect credential material

- **Control:** Require SMB signing on all domain members and servers, restrict
  NTLM domain-wide, enable LSASS as a protected process, and enable Credential
  Guard. This combination removes both the harvest step and the reuse step that
  carried the intruder from one workstation to five systems.
- **Gap closed:** GAP-002
- **Configuration — Group Policy (SMB signing):**
  `Computer Configuration > Policies > Windows Settings > Security Settings >
  Local Policies > Security Options`
  - `Microsoft network server: Digitally sign communications (always)` =
    Enabled
  - `Microsoft network client: Digitally sign communications (always)` =
    Enabled
  - `Domain member: Digitally encrypt or sign secure channel data (always)` =
    Enabled
- **Configuration — registry equivalent:**
  - `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature`
    REG_DWORD = 1
  - `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature`
    REG_DWORD = 1
- **Configuration — Group Policy (credential protection):**
  - `Computer Configuration > Policies > Administrative Templates > System >
    Local Security Authority > Configure LSASS to run as a protected process`
    = Enabled (UEFI lock). Registry equivalent
    `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` REG_DWORD = 1,
    requires restart.
  - `Computer Configuration > Policies > Administrative Templates > System >
    Device Guard > Turn On Virtualization Based Security` = Enabled, with
    Secure Boot and Credential Guard set to Enabled with UEFI lock.
  - `Computer Configuration > Policies > Windows Settings > Security Settings >
    Local Policies > Security Options > Network security: Restrict NTLM: NTLM
    authentication in this domain` = Audit all for 14 days, then Deny all.
- **Validation test:**
  1. `Get-SmbServerConfiguration | Select-Object RequireSecuritySignature` and
     `Get-SmbClientConfiguration | Select-Object RequireSecuritySignature`
     both return `True` on a sample of workstations and on FILE-SVR-01.
  2. In an isolated lab segment, attempt a relay against a test file server
     using a standard relay toolset. Expected: authentication fails and no
     session is established.
  3. Attempt a credential read against lsass.exe in the lab. Expected: access
     denied, and any Sysmon Event ID 10 record shows the attempt without a
     successful `0x1010` grant.
  4. `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName
     Win32_DeviceGuard` shows Credential Guard in `SecurityServicesRunning`.
  5. NTLM audit phase: review 4776 and 8004 events to inventory remaining NTLM
     dependencies before switching to Deny all.
- **Risk note:** Legacy clinical peripherals, imaging modalities, and older
  scanners frequently lack SMB signing support. Inventory these before the
  enforce phase and place them on a segmented VLAN with compensating controls
  rather than granting a domain-wide exception.
- **Rollback:** Set `RequireSecuritySignature` back to 0 and refresh policy.
  Credential Guard and LSASS protection require a restart to disable.

## Change 3: Deny execution from user-writable directories

- **Control:** Application control denying executable launch from directories
  any interactive user or low-privilege process can write to, with publisher
  and hash allowlist exceptions for approved vendor updaters.
- **Gap closed:** GAP-003
- **Configuration — Group Policy (AppLocker):**
  `Computer Configuration > Policies > Windows Settings > Security Settings >
  Application Control Policies > AppLocker > Executable Rules`
  Create the default rules, then add Deny rules for the group `Everyone` using
  Path conditions:
  - `C:\ProgramData\*`
  - `C:\Users\*\AppData\Local\Temp\*`
  - `C:\Users\Public\*`
  - `C:\Windows\Temp\*`
  AppLocker deny rules take precedence over allow rules. Confirm the
  Application Identity service (`AppIDSvc`) is running and set to Automatic.
- **Configuration — alternative (App Control for Business / WDAC), preferred
  where already licensed:**
  `Computer Configuration > Policies > Windows Settings > Security Settings >
  Application Control Policies > App Control for Business`, or Intune
  `Endpoint security > App control for business`, deploying a policy that
  permits execution only from `%ProgramFiles%`, `%SystemRoot%`, and approved
  publisher rules, implicitly denying user-writable paths.
- **Validation test:**
  1. Copy a benign signed executable to `C:\ProgramData\Microsoft\` and
     execute it as a standard user. Expected: blocked.
  2. Confirm the block event in
     `Applications and Services Logs > Microsoft > Windows > AppLocker > EXE
     and DLL`, Event ID 8004 (prevented from running, enforce mode). During the
     audit phase, Event ID 8003 indicates the file would have been blocked.
  3. Confirm approved vendor updaters still launch from their permitted paths
     via publisher rules.
  4. Confirm no legitimate clinical application fails to start over a
     seven-day observation window before switching enforcement.
- **Risk note:** Many legitimate installers and updaters stage binaries in
  ProgramData. Deploy in audit mode for seven days, build the exception list
  from observed Event ID 8003 records, then enforce.
- **Rollback:** Set the AppLocker policy to Audit only, or delete the deny
  rules.

## Residual gaps not closed by this change set

- **GAP-004:** No egress policy or reputation enforcement. The beacon reached a
  single command-and-control endpoint for 72 hours while the proxy already
  carried the reputation tags `suspicious_cdn_lookalike` and
  `cobalt_strike_team_server_known` (PRX-002). Recommended follow-on: promote
  proxy reputation tags to automatic block plus priority alert, and enforce
  internal DNS resolution only. Tracked separately, not part of this
  three-change set.
