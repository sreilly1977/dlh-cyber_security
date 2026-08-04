# Locking the Gates

## System Hardening

**What a CIS Benchmark is, and applying it with judgment**
CIS Benchmarks are consensus-based, vendor-specific configuration guidelines organized into scored and non-scored recommendations that should be applied selectively based on threat model, environment context, and operational impact rather than blanket compliance.

**Hardening SSH for enterprise use**
Harden SSH by disabling protocol 1, enforcing public-key-only authentication with `PasswordAuthentication no` and `PubkeyAuthentication yes`, setting `PermitRootLogin no`, configuring `ClientAliveInterval`/`ClientAliveCountMax` for idle timeouts, restricting access with `AllowUsers`/`AllowGroups`, and binding `ListenAddress` to specific interfaces.

**Hardening the Linux kernel via sysctl**
Apply sysctl knobs such as `net.ipv4.tcp_syncookies=1`, `net.ipv4.conf.all.accept_redirects=0`, `net.ipv4.ip_forward=0`, `kernel.randomize_va_space=2` for ASLR, and `fs.suid_dumpable=0` to restrict core dumps and reduce the kernel's attack surface.

**Auditing and remediating filesystem permissions**
Audit SUID/SGID binaries with `find / -perm /6000 -type f`, identify world-writable files with `find / -perm -0002`, and enforce restrictive mount options (`noexec`, `nosuid`, `nodev`) on filesystems like `/tmp`, `/var`, and `/home` via `/etc/fstab`.

**Configuring AppArmor in enforce mode**
Build AppArmor profiles with `aa-genprof` against the target binary, validate rule coverage with `aa-logprof` against audit logs, and switch the profile from complain to enforce mode using `aa-enforce` so that violations are blocked rather than merely logged.

**Configuring PAM for password quality and login throttling**
Configure the `pam_pwquality` module in `/etc/security/pwquality.conf` with minimum length, complexity, and dictionary checks, and use `pam_faillock` in the PAM auth/account stacks to lock accounts after a configurable number of failed attempts for a defined duration.

**Deploying and configuring auditd**
Install `auditd`, define watch rules for sensitive files and directories using `auditctl` (e.g., `-w /etc/passwd -p wa -k identity`), set syscall-based rules for privilege escalation events, persist rules in `/etc/audit/rules.d/`, and restart the daemon so rules survive reboots.

**Configuring rsyslog and log rotation**
Forward structured logs to a central collector by configuring rsyslog templates with RFC 5424 formatting and remote forwarding via `*.* @@collector:6514` (TCP/TLS), and manage retention with `logrotate` policies specifying rotation frequency, count, compression, and post-rotation signal handling.

**Implementing a host firewall with default-deny posture**
Set the default policy for INPUT and FORWARD chains to DROP, allow only established connections and explicitly required inbound ports with `-m conntrack --ctstate ESTABLISHED,RELATED`, and permit loopback traffic, achieving a deny-by-default posture that requires explicit allowlisting for any service.

---

## Operational Skills

**Running a Lynis audit, parsing results, and measuring hardening delta**
Run `lynis audit system --pentest` to establish a baseline score, re-run after hardening, and parse the JSON or report output programmatically (via `--auditor` and scriptable parsing of `lynis.log`/`/var/log/lynis-report.dat`) to compute the score differential and quantify the hardening delta.

**Cross-referencing audit findings against CIS controls for gap analysis**
Map Lynis or auditd findings to CIS control identifiers by maintaining a crosswalk table that links each finding ID to its corresponding CIS benchmark section number, then produce a gap analysis report listing controls that are missing, partially implemented, or fully satisfied.

**Writing idempotent bash scripts for automated hardening with JSON output**
Write scripts that check current state before modifying (e.g., test `sysctl -n` values, grep config files) to ensure repeated executions produce no changes, and emit structured JSON summaries via functions that wrap each operation in a key-value report capturing status, changed state, and timestamp.

**Building a master hardening pipeline**
Orchestrate all hardening modules (sysctl, SSH, filesystem, AppArmor, PAM, auditd, rsyslog, firewall) in a single ordered pipeline script with dependency resolution, rollback on failure, idempotency checks, and a final validation pass that runs Lynis and outputs a before-and-after comparison report.

---

## Professional Judgment

**When to apply or skip a CIS recommendation with a compensating control**
Apply a CIS recommendation unless there is a documented, validated compensating control that achieves the same risk reduction—record the rationale, the control's mechanism, its residual risk assessment, and the approval authority in a deviation register for auditable traceability.

**Balancing security hardening against operational requirements**
Evaluate each hardening control against operational impact—such as service availability, performance overhead, and administrative friction—and adopt graduated or phased implementations that protect critical assets first while documenting accepted risks and timelines for controls deferred due to operational constraints.

---

# The Windows Fortress

## Active Directory Security

**How Active Directory structures authentication and authorization**
Active Directory uses Domain Controllers to authenticate users via Kerberos/NTLM, Organizational Units to logically group objects, Group Policy Objects to centrally configure security settings, and Security Groups to manage permissions through role-based access control.

**How Group Policy Objects are applied, diagnosing conflicts, and deploying security settings**
GPOs apply in LSDOU order (Local, Site, Domain, OU) where later applications override earlier ones, conflicts are diagnosed with `gpresult /h` or Group Policy Management Editor's Resultant Set of Policy, and security settings deploy by linking GPOs to target OUs with enforced inheritance when necessary.

**Critical Windows Event IDs for security monitoring**
Event ID 4624 indicates successful logons (attackers leave trails on lateral movement), 4625 shows failed logons (brute-force attempts), 4648 reveals explicit credential usage (pass-the-hash indicators), 4688 captures process creation (malware execution), 4720 signals new user creation (persistence), 4726 marks user deletion (cover tracks), 4732 records membership changes to privileged groups (privilege escalation), and 1102 denotes audit log clearing (attacker anti-forensics).

---

## Windows Hardening

**How to harden password policy, account lockout, and authentication protocols via GPO**
Deploy password complexity, minimum age/length, and history requirements through the Default Domain Policy GPO under Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies, while configuring Account Lockout Threshold and duration alongside enabling NTLM restrictions and Kerberos pre-authentication via GPO security options.

**How to configure Advanced Audit Policies for security-relevant event generation**
Replace legacy audit settings with Advanced Audit Policy Configuration under Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration to enable granular subcategories like Account Logon, Logon/Logoff, Privilege Use, and Process Tracking that generate the critical Event IDs needed for detection.

**How to deploy Sysmon with detection-optimized configuration and tuning**
Install Sysmon from Microsoft, import a community-maintained XML configuration (such as SwiftOnSecurity's or Olaf Hartong's), deploy via SCCM/GPO for centralized management, and iteratively tune rules by filtering out legitimate admin activities while preserving events tied to threat detection use cases.

**How to configure AppLocker for application allow-listing**
Create executable, script, and packaged app rules in AppLocker under Computer Configuration → Windows Settings → Security Settings → Application Control Policies, test rules in Enforce mode with the AppLocker Diagnostic log active, then deploy via GPO to restrict unsigned and unauthorized code execution.

**How to harden SMB, RDP, Windows Firewall, and service accounts**
Disable SMBv1 via Windows Features and registry, enforce Network Level Authentication for RDP while restricting RDP access via GPO, configure Windows Firewall with default-deny inbound rules allowing only explicitly required ports, and replace local service accounts with Managed Service Accounts or Group Managed Service Accounts for credential protection.

---

## Endpoint Detection

**How Sysmon works, critical Event IDs, and custom detection rules**
Sysmon operates as a kernel-mode driver writing system-level events to the Windows Event Log, where critical Event IDs include 1 (process creation), 3 (network connection), 7 (image loaded), 8 (create remote thread), 10 (process access), and 22 (DNS query), enabling custom detection rules that match IoCs, TTPs, and anomalous behavior patterns.

**How PowerShell Script Block Logging and Constrained Language Mode reduce the attacker's toolkit**
Enable Script Block Logging via GPO under Advanced Audit Policies to capture full command execution including obfuscated content, and activate Constrained Language Mode to prevent reflection-based attacks, memory injection, and dynamic code generation that attackers commonly leverage in living-off-the-land scenarios.

**How Windows Firewall rules enforce network segmentation at the endpoint level**
Deploy Windows Firewall with Advanced Security rules blocking unnecessary inbound/outbound traffic by port, protocol, and program, segment endpoints into security zones through firewall policy groups, and use connection security rules (IPsec) to enforce authenticated communication between trusted systems.
