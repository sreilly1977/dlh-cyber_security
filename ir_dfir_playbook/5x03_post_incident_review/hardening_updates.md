<!-- Name: hardening_updates.md -->
<!-- Purpose: Translate IR-2026-0414-01 findings into specific, deployable -->
<!--          hardening changes, each linked to a Gap ID from Task 2 and -->
<!--          paired with a validation test that confirms enforcement. -->
<!-- Author: Steve - Cybersecurity Engineer -->
<!-- Date: 19 October 2026 -->

# Hardening Updates: IR-2026-0414-01

Each change below is justified by a confirmed forensic finding and closes a
specific gap from `gap_analysis.md`. Validation tests are observables: a
command output, an event log entry, or a blocked action that proves the
control is active rather than merely configured.

---

## HRD-001: PowerShell Constrained Language Mode

**Closes:** GAP-004, GAP-005

**Configuration:**
- Preferred path: enforce via WDAC or AppLocker in Enforce mode. When an
  application control policy is active, PowerShell automatically runs in
  Constrained Language Mode for users who are not exempt, with no separate
  registry edit required.
- Explicit path (where a policy-forced setting is needed):
  - GPO: `Computer Configuration > Preferences > Windows Settings > Registry`
  - Key: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
  - Value name: `__PSLockdownPolicy`
  - Value type: `REG_SZ`
  - Value data: `4`

**Effect:** Restricts PowerShell to Constrained Language Mode for standard
users. Blocks .NET type instantiation, COM object creation, and
`[System.Management.Automation.ScriptBlock]::Create` calls, which the
MSBuild inline-task loader depends on to stage its shellcode.

**Applies to:** Non-administrative accounts on all clinical and
administrative workstations (WST host class).

**Caveats:** Forcing `__PSLockdownPolicy=4` globally also constrains
administrator sessions and will break legitimate admin automation, which is
why the WDAC/AppLocker enforcement path is preferred: it applies CLM by
context. CLM is not a hard boundary against a determined attacker with
administrative rights, and it does not stop `powershell.exe -enc` from
launching; it stops the type loading that follows. It is a friction control
layered beneath the process creation detection rule, not a replacement.

**Validation:** Run `$ExecutionContext.SessionState.LanguageMode` in a
standard-user PowerShell session; expected output: `ConstrainedLanguage`.

---

## HRD-002: AppLocker or WDAC Rule Restricting MSBuild.exe

**Closes:** GAP-004, GAP-006

**Configuration (AppLocker, Exe rule collection, Enforce mode):**

```xml
<RuleCollection Type="Exe" EnforcementMode="Enabled">
  <FilePathRule Id="c9f1a4b2-3d68-4e71-9a05-7b2c8e6f1d34"
                Name="MSBuild.exe - Administrators and CI only"
                Description="Restrict MSBuild.exe to BUILTIN\Administrators and CI/CD service accounts"
                UserOrGroupSid="S-1-5-32-544"
                Action="Allow">
    <Conditions>
      <FilePathCondition Path="%OSDRIVE%\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" />
      <FilePathCondition Path="%OSDRIVE%\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe" />
    </Conditions>
  </FilePathRule>
  <FilePathRule Id="a4e7c1d9-8b25-4f30-b6c2-1e9d5a7f3b08"
                Name="MSBuild.exe - CI/CD service account"
                Description="Named build service account exemption"
                UserOrGroupSid="S-1-5-21-XXXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX-XXXX"
                Action="Allow">
    <Conditions>
      <FilePathCondition Path="%OSDRIVE%\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" />
    </Conditions>
  </FilePathRule>
</RuleCollection>
```

**Critical implementation note:** AppLocker Deny rules take precedence over
Allow rules, so the common instinct to "deny MSBuild for Everyone, allow for
admins" does not work, because the deny would also block the administrators.
The correct construction is to narrow the default AppLocker "Windows" allow
rule so it no longer blanket-permits `C:\Windows\Microsoft.NET\...`, then add
the scoped Allow rules above. Because AppLocker blocks anything with no
matching Allow rule, MSBuild then runs only for the SIDs listed. If your
estate already uses WDAC, implement the same restriction as a WDAC policy
with a scoped deny for the interactive user SIDs, which expresses this more
cleanly and also drives CLM from HRD-001.

**Effect:** Prevents a standard user (such as the compromised `dmarsh`
account) from executing `MSBuild.exe` at all, severing the proxy execution
stage that ART-002-M01 and ART-003-M01 both relied on.

**Applies to:** All WST-class workstations; CI/CD build agents retain access
under their dedicated service account SIDs.

**Validation:** As a standard user, run
`"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" -version`;
expected result: blocked with an AppLocker policy message, and Event ID
`8004` (EXE and DLL) logged in
`Applications and Services Logs > Microsoft > Windows > AppLocker`.

---

## HRD-003: Conditional Access for VPN Authentication from New Geographies

**Closes:** GAP-002, GAP-003

**Configuration (Microsoft Entra ID Conditional Access):**

1. **Named location.** Create `Trusted Countries - MedDefense` containing the
   countries of normal operation. This is the geographic baseline.
2. **Policy `CA-VPN-StepUp-NewGeo`:**
   - Assignments: All users; Cloud apps: the VPN enterprise application
     (and Exchange Online / SharePoint if the same session is reused).
   - Conditions > Locations: `Any location`, with `Trusted Countries -
     MedDefense` excluded.
   - Conditions > Sign-in risk: `Medium` and `High`.
   - Grant: `Require multifactor authentication` **and** `Require device to
     be marked as compliant`, with the toggle set to **Require all the
     selected controls**.
3. **Fix for the suppression observed in the incident.** The original policy
   let a compliant-device state satisfy the grant on its own, which cancelled
   the Azure AD risk signal. Setting the grant to require all selected
   controls means a compliant device is necessary but no longer sufficient;
   MFA is enforced independently whenever location or risk conditions match.

**On "new geography in the prior 30 days":** Entra ID has no native
per-account "country not seen in 30 days" condition. That behaviour is
delivered by the Identity Protection **unfamiliar sign-in properties**
detection, which raises sign-in risk when a user authenticates from a
location or with properties not seen recently. Routing that risk signal into
the policy above is the supported way to achieve the intended outcome.

**Effect:** The 2026-04-13T18:14:41Z session from `45.63.9.88` (RU) would
have matched the location condition and required an interactive MFA step the
attacker could not satisfy, stopping the intrusion before VPN access.

**Applies to:** All remote-access identities, with a documented break-glass
account excluded from the policy and monitored separately.

**Validation:** In the Entra portal, `Sign-in logs` for the test account
shows the policy name under `Conditional Access > Policies applied` with
result `Success` or `MFA required` for a sign-in from a non-trusted country.
Programmatically:
`Connect-MgGraph; Get-MgIdentityConditionalAccessPolicy | Where-Object DisplayName -eq 'CA-VPN-StepUp-NewGeo'`
returns the policy with state `enabled`.

---

## HRD-004: Windows Credential Guard (with RunAsPPL)

**Closes:** GAP-009, GAP-010

**Configuration:**
- GPO: `Computer Configuration > Administrative Templates > System > Device
  Guard > Turn On Virtualization Based Security` set to `Enabled with UEFI
  Lock`.
- Equivalent registry settings:
  - `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`
    - `EnableVirtualizationBasedSecurity` = `1` (DWORD)
    - `RequirePlatformSecurityFeatures` = `1` (Secure Boot) or `3` (Secure
      Boot and DMA)
  - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
    - `LsaCfgFlags` = `1` (Enabled with UEFI lock) or `2` (Enabled without
      lock)
    - `RunAsPPL` = `1` (DWORD), which runs LSASS as a protected process light
      and complements Credential Guard.

**Supported versions:** Windows 10 and Windows 11 Enterprise and Education,
plus Windows Server 2016 and later. Home and Pro editions do not support
Credential Guard, so a fleet audit is required before rollout. Hardware
prerequisites: virtualization extensions, UEFI Secure Boot (strongly
recommended), and TPM 2.0 where available.

**Effect:** Isolates NTLM hash and Kerberos-derived credential material in a
hypervisor-protected memory region, so the plaintext-equivalent NTLM material
observed in lsass at ART-002-M04 is no longer extractable by a user-mode
process. This removes the credential source that enabled the WST-WS-017
lateral movement.

**Scope honesty:** Credential Guard closes the LSASS memory-extraction path
(T1003.001). It does **not** mitigate Kerberoasting (T1558.003), which the
ATT&CK mapping also lists for this incident. Kerberoasting is addressed
separately by migrating service accounts to group Managed Service Accounts
(gMSA) with 240-character rotating passwords and enforcing AES-only Kerberos
encryption, which should be tracked as its own hardening item.

**Validation:**
`Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -ExpandProperty SecurityServicesRunning`
returns a list containing `1` (Credential Guard) and `2` (HVCI) where
applicable. `msinfo32` shows `Credential Guard` under
`Virtualization-based security Services Running`.

---

## HRD-005: Workstation Egress Enforcement Through the Secure Web Gateway

**Closes:** GAP-007, GAP-008

**Configuration:** Route all WST-class workstation egress through the secure
web gateway with a deny-by-default rule for connections to raw IP addresses
that have no preceding DNS resolution. Subscribe the gateway to the
`applied-privacy.net` Tor exit list and to an AbuseIPDB feed filtered at
confidence `>= 75`. Permit anonymizer traffic only from the sanctioned
research subnet. Enable flow-periodicity analytics (six-hour window, flag
destinations receiving 10 or more evenly spaced connections from a single
endpoint).

**Effect:** The ten-hour C2 channel to `185.220.101.47` (Tor exit) and
`91.234.99.107` (Cobalt Strike) would have been blocked at egress rather than
merely observed after the fact.

**Validation:** Attempt a raw-IP HTTPS connection from a test workstation with
no DNS lookup; expected result: blocked by the gateway, with a proxy log entry
showing the deny rule. Confirm the Tor exit feed is loaded via the gateway's
threat-feed status page.

---

## HRD-006: Clinical Segment Isolation and LIS Share ACL Tightening

**Closes:** GAP-011, GAP-012

**Configuration:** Place `LIS-WSIDE-01` and the LIS server segment behind a
firewall policy that permits SMB (TCP 445) only from the designated jump host,
not from general workstation VLANs. On the `LIS_REPORTS$` share, replace
broad domain-user read with explicit ACLs granting read to the LIS service
account and the authorised lab personnel group only. Enable Windows object
access auditing (success on Read) for the share and forward those events to
the SIEM.

**Effect:** Breaks the path that let a Kerberos-authenticated `dmarsh` session
read 14 PHI report PDFs from a compromised workstation (AD-LOG-01).

**Validation:** From a standard workstation, attempt
`dir \\LIS-WSIDE-01\LIS_REPORTS$`; expected result: access denied. Confirm the
audit subcategory `File System` is enabled via `auditpol /get /category:*`.

---

## HRD-007: Recursive DNS and Web Filtering with Community Blocklists

**Closes:** GAP-001

**Configuration:** Configure MedDefense recursive DNS resolvers and the secure
web gateway to consume Spamhaus DBL, SURBL, and URLhaus feeds on a 60-minute
refresh, with block-on-list enforcement for domains matching the corporate
brand-plus-verification pattern (keyword proximity of `ms0365`,
`login-verification`, and the `.click` TLD).

**Effect:** The phishing domain
`ms0365-support.login-verification.click` was listed on Spamhaus DBL and SURBL
from 2026-04-07, six days before the 2026-04-13 click; this control would have
blocked the credential submission at the first step.

**Validation:** Query a known-listed test domain from a workstation and confirm
an NXDOMAIN or block page response, plus a resolver log entry attributing the
block to the Spamhaus DBL feed.

---

## HRD-008: Sysmon Persistence Telemetry and Detection Configuration

**Closes:** GAP-013

**Configuration:** Deploy a Sysmon configuration to the WST host class
capturing Event ID 11 (file create), 12/13 (registry create/set), and 1
(process create), and load the Sigma persistence rule alerting on Run key
additions and scheduled task creation whose binary paths resolve to
user-writable directories.

**Effect:** The `WindowsUpdateSvc` Run key write at 02:46:55Z and the
scheduled task `{7B4F2D81-...}` would have generated alerts at the persistence
stage rather than being reconstructed forensically.

**Validation:** Confirm Sysmon service is running with the intended config
(`sysmon64 -c` prints the active configuration) and that a controlled test
registry write to a Run key produces Event ID 13 in the Sysmon operational log.

---

## Summary: Change-to-Gap Traceability

| Change | Closes | Validation observable |
|---|---|---|
| HRD-001 PowerShell CLM | GAP-004, GAP-005 | `LanguageMode` returns `ConstrainedLanguage` |
| HRD-002 AppLocker/WDAC MSBuild | GAP-004, GAP-006 | Standard-user MSBuild blocked, AppLocker Event 8004 |
| HRD-003 Conditional Access new-geo | GAP-002, GAP-003 | Sign-in log shows policy applied with MFA required |
| HRD-004 Credential Guard + RunAsPPL | GAP-009, GAP-010 | `Win32_DeviceGuard` lists service `1` running |
| HRD-005 Egress enforcement | GAP-007, GAP-008 | Raw-IP egress blocked, Tor feed loaded |
| HRD-006 LIS isolation and ACLs | GAP-011, GAP-012 | Share access denied from workstation VLAN |
| HRD-007 DNS/web blocklists | GAP-001 | Listed domain returns NXDOMAIN or block page |
| HRD-008 Sysmon persistence config | GAP-013 | Run key write generates Sysmon Event 13 |

Every change above traces to a Gap ID from Task 2 and a confirmed finding from
`forensic_findings_summary.md`. Items requiring fleet prerequisites before
rollout (HRD-004 edition support, HRD-002 default-rule rework) are flagged in
their sections rather than assumed.
