# 0. The Baseline Snapshot

## Goal: 

Capture the complete security state of a system before any changes, establishing the measurement that every subsequent task will improve against.

# Context: 

You cannot prove hardening worked if you do not know where you started. This task captures the system as it is: unhardened, default configuration, every setting at its out-of-the-box value. Every number you record here is the number you will improve.

## Instructions: 

Write a script 0-baseline_snapshot.sh that captures the complete security baseline of a Linux system. The script must:

    Record system identification (hostname, OS, kernel version, uptime)

    List all running services and their state

    List all open ports and listening sockets

    List all SUID and SGID binaries

    List all world-writable files (excluding /proc, /sys, /dev)

    Capture current sysctl security-relevant parameters

    Capture current SSH configuration settings

    Record active user accounts and sudo group membership

**Expected Output:**

```bash
$ sudo ./0-baseline_snapshot.sh
Hostname: billing-srv-01
OS: Ubuntu 22.04.3 LTS
Running services: 24
Open ports: 11
SUID binaries: 23
SGID binaries: 12
World-writable files: 7
```

---

# 1. MedDefense CIS Control Profile

## Goal: 

Build a threat-driven CIS hardening profile for MedDefense Linux servers that becomes the input for later remediation tasks.

## Context: 

The original CIS priority task leaned too heavily toward manual benchmark interpretation. In this project, scripts are the primary deliverable. This rebuilt task turns CIS prioritization into a structured, reusable control profile that later scripts can consume.

MedDefense does not need a generic list of CIS recommendations. It needs a focused control profile for billing-srv-01, web-srv-01, and log-srv-01, tied to the project's actual risks: SSH lateral movement, weak authentication, unnecessary services, missing audit visibility, exposed database services, and insufficient kernel hardening.

## Instructions: 

Write 1-cis_profile.sh.

The script must generate cis_profile.json containing exactly 15 controls. Each control must include:

    control_id
    title
    cis_section
    severity (critical, high, or medium)
    asset_scope
    threat_mapping
    implementation_task
    verification_method
    justification

The selected controls must cover SSH, kernel/sysctl hardening, PAM, service minimization, filesystem permissions, audit logging, firewall exposure, and log retention.

**Expected Output:**

```bash
$ ./1-cis_profile.sh
Controls selected: 15
Critical: 5
High: 7
Medium: 3
CIS sections covered: 5
Mapped implementation tasks: 10
Report saved to: cis_profile.json
```

---

# 2. The Lynis Audit Parser

## Goal: 

Parse a report file and produce a machine-readable JSON summary of the most important audit results.

## Context: 

Lynis stores the most important audit data in a key-value report file, usually lynis-report.dat. This file is easier to parse than the terminal output or the verbose log file. Converting it into JSON makes the audit results easier to inspect, filter, and reuse in a security workflow.

## Instructions:

Run a full Lynis audit on the system. Then write a script 2-lynis_parse.sh that:

    accepts the path to a .dat report file as its first argument ("$1")

    extracts the Lynis hardening index

    extracts every warning[], suggestion[], and manual_check[] entry

    parses each finding into:

        severity

        test_id

        message

    produces a structured JSON report on standard output

**Hint: man jq**

## Expected Output:

```bash
$ ./2-lynis_parse.sh /var/log/lynis-report.dat | jq '.' > lynis_findings.json

$ cat lynis_findings.json
{
  "hardening_index": 62,
  "findings": [
    {
      "severity": "suggestion",
      "test_id": "LYNIS",
      "message": "This release is more than 4 months old. Check the website or GitHub to see if there is an update available."
    },
    {
      "severity": "suggestion",
      "test_id": "DEB-0280",
      "message": "Install libpam-tmpdir to set $TMP and $TMPDIR for PAM sessions"
    },
...
```

---

# 3. Evidence-Based Remediation Queue

## Goal: 

Convert the CIS control profile and Lynis findings into a prioritized, evidence-backed remediation queue.

## Context: 

This task becomes the decision engine that explains why Tasks 4–13 are performed and in what order. Every remediation item must be backed by evidence, mapped to a later hardening script, and ordered by risk.

## Instructions: 

Write 3-remediation_queue.sh.

The script must read cis_profile.json and lynis_findings.json, then produce gap_analysis.json and remediation_queue.json.

For each CIS control, determine one status: compliant, non_compliant, partially_compliant, or not_assessed.

For every non-compliant or partially compliant control, include:

    matching Lynis finding IDs or messages
    affected asset
    remediation script to run
    severity
    priority score from 1–100
    operational risk if left unresolved
    expected validation check

The queue must be sorted by priority score descending.

**Expected Output:**

```bash
$ ./3-remediation_queue.sh
Controls assessed: 15
Compliant: 2
Non-compliant: 10
Partially compliant: 2
Not assessed: 1
Remediation actions queued: 12
Report saved to: gap_analysis.json
Queue saved to: remediation_queue.json
```

---

# 4. The SSH Lockdown

##Goal: 

Harden SSH to eliminate password-based authentication and reduce the attack surface to the minimum required for MedDefense operations.

## Context: 

Finding 009 from your vulnerability assessment (1x02): "SSH on billing-srv-01 allows password-based authentication. Combined with no account lockout policy, this permits brute-force attacks." The Crimson Tide advisory confirmed: in 3 of 5 hospital breaches, the attacker used harvested credentials for SSH lateral movement (Phase 3). This is the first thing you fix.

## Instructions: 

Write a script 4-ssh_hardening.sh that:

    Backs up the current sshd_config to /etc/ssh/sshd_config.bak

    Applies the following SSH hardening settings (each with a comment referencing the threat it addresses):

        PermitRootLogin no

        PasswordAuthentication no

        PermitEmptyPasswords no

        X11Forwarding no

        MaxAuthTries 3

        ClientAliveInterval 300 and ClientAliveCountMax 2 (idle timeout: 10 min)

        AllowUsers medadmin sysadmin

        Protocol 2

        LoginGraceTime 60

        Banner /etc/issue.net

    Creates the /etc/issue.net banner file

    Validates the configuration syntax with sshd -t

    If validation passes, restarts SSH. If it fails, restores the backup.

**Expected Output:**

```bash
$ sudo ./4-ssh_hardening.sh
[*] Backing up /etc/ssh/sshd_config
[*] Applying SSH hardening settings...
    PermitRootLogin no
    PasswordAuthentication no
    PermitEmptyPasswords no
    X11Forwarding no
    MaxAuthTries 3
    ClientAliveInterval 300
    ClientAliveCountMax 2
    AllowUsers medadmin sysadmin
    Protocol 2
    LoginGraceTime 60
    Banner /etc/issue.net
[*] Validating SSH configuration...
    sshd -t: OK
[*] Restarting SSH service...
    ssh.service: active (running)
Settings applied: 11
```

---

# 5. The Kernel Shield

## Goal: 

Harden the Linux kernel network stack and memory protections via sysctl to prevent the server from being used as a pivot point or exploitation target.

## Context: 

In the Crimson Tide attack chain (Phase 3), the attacker moved laterally across the flat network. If a compromised Linux server has IP forwarding enabled, it becomes a router for the attacker. If ICMP redirects are accepted, the attacker can reroute traffic. If ASLR is disabled, memory corruption exploits become trivially reliable. These are default-off settings that should never be on a production server.

## Instructions: 

Write a script 5-sysctl_hardening.sh that:

    Backs up the current sysctl.conf

    Applies network stack hardening, IPv6 disabling and memory protection parameters

    Applies settings immediately with sysctl -p

    Verifies each setting was applied by reading back from /proc/sys/

    Prints a PASS/FAIL for each setting

**Expected Output:**

```bash
$ sudo ./5-sysctl_hardening.sh
[*] Backing up /etc/sysctl.conf
[*] Applying kernel hardening parameters...
net.ipv4.ip_forward = 0                    [PASS]
net.ipv4.conf.all.accept_redirects = 0     [PASS]
net.ipv4.conf.default.accept_redirects = 0 [PASS]
net.ipv4.conf.all.send_redirects = 0       [PASS]
net.ipv4.conf.all.accept_source_route = 0  [PASS]
net.ipv4.conf.all.log_martians = 1         [PASS]
net.ipv4.tcp_syncookies = 1                [PASS]
net.ipv4.icmp_echo_ignore_broadcasts = 1   [PASS]
net.ipv6.conf.all.disable_ipv6 = 1         [PASS]
net.ipv6.conf.default.disable_ipv6 = 1     [PASS]
kernel.randomize_va_space = 2              [PASS]
fs.suid_dumpable = 0                       [PASS]
kernel.dmesg_restrict = 1                  [PASS]
kernel.kptr_restrict = 2                   [PASS]
Parameters applied: 14
Verified PASS: 14
Verified FAIL: 0
```

---

# 6. The Permission Sweep

## Goal: 

Audit and remediate dangerous filesystem permissions that could enable privilege escalation.

## Context: 

SUID binaries are how an attacker with low-privilege shell access escalates to root. World-writable files are how an attacker modifies scripts that run as root. Both are classic privilege escalation vectors that the Crimson Tide affiliate would use after initial access (Phase 3). The baseline snapshot from Task 0 found 23 SUID binaries and 7 world-writable files. Not all of them are necessary.

## Instructions: 

Write a script 6-filesystem_hardening.sh that:

    Finds all SUID binaries, compares against a hardcoded whitelist of known-safe binaries for Ubuntu 22.04, removes SUID from unexpected binaries

    Does the same for SGID binaries

    Finds and remediates world-writable files (excluding /proc, /sys, /dev)

    Checks and configures mount options for /tmp, /var/tmp and /dev/shm (noexec, nosuid, nodev)

    Restricts cron access to authorized users

    Prints a full remediation summary

**Expected Output:**

```bash
$ sudo ./6-filesystem_hardening.sh
Found 23 SUID binaries
Whitelisted: 18
Non-whitelisted: 5
  /usr/local/bin/oldtool   [SUID REMOVED]
  /opt/legacy/setuid-app   [SUID REMOVED]
Found 12 SGID binaries
Whitelisted: 11
Non-whitelisted: 1
  /usr/local/bin/shared    [SGID REMOVED]
Found 7 world-writable files
  /tmp/debug.log           [FIXED]
  /var/www/html/uploads/   [FIXED]
/tmp:     noexec,nosuid,nodev  [OK]
/var/tmp: noexec,nosuid,nodev  [APPLIED]
/dev/shm: noexec,nosuid,nodev  [OK]
SUID remediated: 5 | SGID remediated: 1 | World-writable fixed: 7
```

---

# 7. The Service Minimizer

## Goal: 

Identify and disable unnecessary services to reduce the attack surface to only what MedDefense operations require.

## Context: 

CIS Benchmark Section 2 covers service configuration. The principle: every running service is a potential entry point. A billing server does not need avahi-daemon, cups or rpcbind. The 1x02 scan found billing-srv-01 with unnecessary services exposed network-wide (Finding 006: MySQL on 0.0.0.0). The baseline snapshot counted 24 enabled services. A production billing server needs fewer than 10.

## Instructions: 

Write a script 7-service_minimization.sh that:

    Lists all enabled services

    Compares against a whitelist of services required for MedDefense (defined as an array with comments explaining why each is needed)

    Stops and disables services not on the whitelist

    Verifies required services are running

    Reports the before/after count

**Expected Output:**

```bash
$ sudo ./7-service_minimization.sh
[*] Scanning enabled services...
    Enabled services found: 24
[*] Comparing against MedDefense whitelist (9 required services)...
  avahi-daemon.service     [STOPPED] [DISABLED]
  cups.service             [STOPPED] [DISABLED]
  ModemManager.service     [STOPPED] [DISABLED]
  bluetooth.service        [STOPPED] [DISABLED]
  ssh.service              [ACTIVE]
  apache2.service          [ACTIVE]
  mysql.service            [ACTIVE]
  ufw.service              [ACTIVE]
  auditd.service           [ACTIVE]
  apparmor.service         [ACTIVE]
  cron.service             [ACTIVE]
  rsyslog.service          [ACTIVE]
  systemd-timesyncd.service [ACTIVE]
Before: 24 | After: 9 | Disabled: 15
```

---

# 8. The PAM Fortress

## Goal: 

Configure PAM to enforce password quality requirements and lock accounts after failed authentication attempts.

## Context: 

The Crimson Tide advisory documented that in 3 of 5 breaches, the attacker used harvested credentials (Phase 2) and Kerberoasting (Phase 3) to move laterally. Weak passwords are the root cause. PAM is where Linux enforces password policy. Currently, MedDefense has no password complexity requirements, no account lockout and no password history enforcement on its Linux servers.

## Instructions: 

Write a script 8-pam_hardening.sh that:

    Installs libpam-pwquality if not present

    Configures password quality: minlen 14, complexity requirements, reject_username

    Configures account lockout with pam_faillock: 5 attempts, 900 second lockout

    Configures password history: remember 12 passwords

    Validates the PAM configuration by checking the relevant files

**Expected Output:**

```bash
$ sudo ./8-pam_hardening.sh
[*] Checking libpam-pwquality...
    Already installed: libpam-pwquality 1.4.2
[*] Configuring password quality (/etc/security/pwquality.conf)...
    minlen = 14                      [SET]
    dcredit = -1                     [SET]
    ucredit = -1                     [SET]
    lcredit = -1                     [SET]
    ocredit = -1                     [SET]
    maxrepeat = 3                    [SET]
    reject_username                  [SET]
[*] Configuring account lockout (pam_faillock)...
    deny = 5                         [SET]
    unlock_time = 900                [SET]
    fail_interval = 900              [SET]
[*] Configuring password history...
    remember = 12                    [SET]
Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12
```

---

# 9. The AppArmor Enforcer

## Goal: 

Deploy and configure AppArmor profiles in enforce mode for all network-exposed services, implementing mandatory access control that limits damage even if a service is compromised.

## Context: 

When the crypto-miner compromised billing-srv-01 through Apache (1x00 incident), it had full access to the filesystem as www-data. AppArmor would have confined the Apache process to only the directories it needs. AppArmor is the difference between "the attacker got a shell on our web server" and "the attacker got a shell that can only access /var/www." A custom profile for the MedDefense billing application ensures that even a zero-day in the application cannot reach patient data directories.

## Instructions: 

Write a script 9-apparmor_config.sh that:

    Verifies AppArmor is installed and running

    Lists all current profiles and their status

    Switches profiles for Apache and MySQL from complain to enforce mode

    Creates a custom AppArmor profile for a MedDefense application that restricts filesystem access to its required directories only

    Reports unconfined processes that should have profiles

    Prints a summary with enforce/complain/unconfined counts

**Expected Output:**

```bash
$ sudo ./9-apparmor_config.sh
[*] Checking AppArmor status...
    AppArmor module: loaded
    AppArmor service: active
[*] Profile enforcement:
    /usr/sbin/apache2        complain -> enforce  [ENFORCED]
    /usr/sbin/mysqld         complain -> enforce  [ENFORCED]
    /usr/sbin/sshd           enforce              [OK]
[*] Custom profile: /opt/meddefense/billing-app   [CREATED] [ENFORCED]
[*] Unconfined network-exposed processes:
    /usr/sbin/rsyslogd       [UNCONFINED - Profile recommended]
Profiles in enforce: 4 | Complain: 0 | Unconfined: 1
```

---

# 10. The Audit Engine

## Goal: 

Deploy and configure auditd to monitor security-critical events, creating the audit trail that feeds future telemetry export.

## Context: 

Marcus Webb's notes from the 1x00 incident: "No SIEM or IDS was deployed. Attacker moved undetected for 5 days." auditd is the Linux kernel audit framework. It records system calls, file accesses and authentication events at the kernel level. The logs it generates become the primary Linux data source for the analyst work in Module 3. The rules you write here determine what the SOC can see.

## Instructions: 

Write a script 10-auditd_config.sh that:

    Installs and enables auditd

    Deploys audit rules to /etc/audit/rules.d/meddefense.rules covering: identity files, privilege escalation, suspicious tool execution and MedDefense-specific file integrity

    Loads the rules and verifies they are active

    Tests by triggering an auditable event and checking the log

**Expected Output:**

```bash
$ sudo ./10-auditd_config.sh
[*] Enabling auditd service...
    auditd.service: active (running)
[*] Deploying MedDefense audit rules...
    -w /etc/passwd -p wa -k identity              [ADDED]
    -w /etc/shadow -p wa -k identity              [ADDED]
    -w /etc/group -p wa -k identity               [ADDED]
    -w /etc/pam.d/ -p wa -k pam_config            [ADDED]
    -w /etc/ssh/sshd_config -p wa -k sshd_config  [ADDED]
    -w /usr/bin/sudo -p x -k priv_esc             [ADDED]
    -w /usr/bin/su -p x -k priv_esc               [ADDED]
    -w /etc/sudoers -p wa -k sudoers              [ADDED]
    -w /usr/bin/wget -p x -k suspicious_download  [ADDED]
    -w /usr/bin/curl -p x -k suspicious_download  [ADDED]
    -w /usr/bin/nc -p x -k suspicious_netcat      [ADDED]
    -w /var/lib/mysql/ -p wa -k meddefense_db     [ADDED]
    -w /etc/apache2/ -p wa -k meddefense_web      [ADDED]
    -w /etc/init.d/ -p wa -k startup_scripts      [ADDED]
[*] Loading rules... augenrules --load: OK
[*] Verifying... auditctl -l: 14 rules loaded
[*] Test: reading /etc/shadow...
    ausearch -ts recent -k identity: 1 event found [PASS]
```

---

# 11. Audit Telemetry Coverage Test

## Goal: 

Prove that the audit rules deployed in Task 10 actually capture the security events MedDefense cares about.

## Context: 

The original audit validator encouraged risky system changes. This rebuilt version keeps the operational idea but makes the test safer, controlled, measurable, and usable as final compliance evidence.

## Instructions: 

Write 11-audit_coverage_test.sh.

The script must produce audit_validation.json and test at least six controlled events:

    privileged command execution through sudo
    attempted access to /etc/shadow
    execution of wget or curl
    read or metadata check of /etc/ssh/sshd_config
    controlled write to a temporary file under a monitored test path
    cron configuration inspection or controlled test cron file action

For each test, record test name, expected audit key, command executed, timestamp, capture status, and matching event count or excerpt.

The script must include cleanup logic and must not leave unsafe test accounts, files, or cron jobs behind.

**Expected Output:**

```bash
$ sudo ./11-audit_coverage_test.sh
[*] Running audit telemetry coverage tests...
[1/6] sudo execution                    [CAPTURED]
[2/6] shadow access                     [CAPTURED]
[3/6] suspicious download tool          [CAPTURED]
[4/6] sshd config read                  [CAPTURED]
[5/6] monitored test file write         [CAPTURED]
[6/6] cron configuration check          [CAPTURED]
[*] Cleaning test artifacts...
Tests executed: 6
Captured: 6
Missed: 0
Report saved to: audit_validation.json
```

---

# 12. The Log Architect

## Goal: 

Configure rsyslog for structured logging and set log rotation policies that ensure logs are preserved and exportable.

## Context: 

auditd handles kernel-level events, but authentication logs (auth.log), system logs (syslog) and service logs are handled by rsyslog. If rsyslog is misconfigured, SSH login attempts, PAM events and service failures disappear into /dev/null. If log rotation is too aggressive, evidence is destroyed before analysts can examine it. This task ensures that every log source on the hardened server is properly configured, retained and ready for the telemetry export you will build in 2x02.

## Instructions: 

Write a script 12-log_config.sh that:

    Configures rsyslog to write auth events to /var/log/auth.log with structured formatting

    Configures syslog facility routing for security-relevant sources

    Sets log rotation policies: auth.log retained 90 days, syslog retained 60 days, compressed after 7 days

    Verifies that auth.log and syslog are actively receiving events

    Ensures log file permissions restrict access to root only

**Expected Output:**

```bash
$ sudo ./12-log_config.sh
[*] Configuring rsyslog...
    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]
    *.info;auth.none -> /var/log/syslog      [CONFIGURED]
[*] Setting log rotation policies...
    /var/log/auth.log: rotate 90, compress after 7d  [SET]
    /var/log/syslog: rotate 60, compress after 7d    [SET]
[*] Verifying log activity...
    /var/log/auth.log: receiving events       [OK]
    /var/log/syslog: receiving events         [OK]
[*] Securing log file permissions...
    /var/log/auth.log: 640 root:adm          [OK]
    /var/log/syslog: 640 root:adm            [OK]
Log sources configured: 2 | Rotation policies: 2 | Permissions: secured
```

---

# 13. The Firewall Baseline

## Goal: 

Configure a host firewall with default-deny inbound policy, allowing only the services MedDefense requires.

## Context: 

The hardened services and the audit trail are useless if the server accepts connections on ports that no service is listening on. A default-deny firewall means the server only speaks when spoken to on approved channels. The 1x02 scan found billing-srv-01 with 11 open ports. After service minimization (Task 7), only 4 or 5 should be reachable. The firewall enforces this at the network layer, independent of the service configuration.

## Instructions: 

Write a script 13-firewall_baseline.sh that:

    Enables UFW (or configures nftables) with default-deny inbound, default-allow outbound

    Creates allow rules only for required services: SSH (port 22 from management network only), HTTP/HTTPS (ports 80/443), MySQL (port 3306 from application network only)

    Enables logging for denied connections

    Validates the rules by listing the active ruleset

**Expected Output:**

```bash
$ sudo ./13-firewall_baseline.sh
[*] Configuring UFW...
    Default incoming: deny
    Default outgoing: allow
[*] Adding allow rules...
    22/tcp from 10.10.1.0/24   [ADDED] SSH - management only
    80/tcp                     [ADDED] HTTP
    443/tcp                    [ADDED] HTTPS
    3306/tcp from 10.10.2.0/24 [ADDED] MySQL - app network only
[*] Enabling logging...
    Logging: on (low)
[*] Activating firewall...
    UFW: active
    Rules: 4 allow, default deny
```

---

# 14. Production Hardening Orchestrator

## Goal: 

Create a safe master script that runs the hardening workflow in dependency order and records the before/after security delta.

## Context: 

A production-style hardening script must not run blindly. It must check prerequisites, stop safely, record failures, and generate evidence.

## Instructions: 

Write 14-hardening_orchestrator.sh.

The script must run the hardening workflow in this order:

    0-baseline_snapshot.sh
    Lynis baseline capture or 2-lynis_parse.sh
    4-ssh_hardening.sh
    5-sysctl_hardening.sh
    6-filesystem_hardening.sh
    7-service_minimization.sh
    8-pam_hardening.sh
    9-apparmor_config.sh
    10-auditd_config.sh
    11-audit_coverage_test.sh
    12-log_config.sh
    13-firewall_baseline.sh
    15-validation.sh

The script must verify required scripts exist, stop immediately on failure, record timing and exit codes, capture pre/post Lynis scores, and write hardening_run.json plus hardening_improvement.json.

It must be idempotent.

**Expected Output:**

```bash
$ sudo ./14-hardening_orchestrator.sh
Pre-checks: PASS
Steps scheduled: 13
Steps completed: 13
Steps failed: 0
Before Lynis score: 52
After Lynis score: 84
Delta: +32
Run log saved to: hardening_run.json
Improvement saved to: hardening_improvement.json
```

---

# 15. The Post-Hardening Validator

## Goal: 

Write a read-only script that independently verifies every hardening control is in its expected state.

## Context: 

Hardening is not a one-time event. Configuration drift happens: an admin changes a sysctl setting for debugging and forgets to revert. A software update overwrites sshd_config. This script is the continuous validation tool James Chen runs every Monday morning. It makes no changes to the system. It only reads and reports.

## Instructions: 

Write a script 15-validation.sh that checks every hardening setting from Tasks 4-13 against its expected value. For each control:

    Read the actual system state

    Compare against the expected value

    Record PASS or FAIL

The script must exit with code 0 if all checks pass, code 1 if any check fails.

**Expected Output:**

```bash
$ sudo ./15-validation.sh
[PASS] PermitRootLogin = no
[PASS] PasswordAuthentication = no
[PASS] MaxAuthTries = 3
[PASS] net.ipv4.ip_forward = 0
[PASS] net.ipv4.tcp_syncookies = 1
[PASS] kernel.randomize_va_space = 2
[FAIL] net.ipv4.conf.all.log_martians = 0 (expected: 1)
[PASS] auditd.service = active
[PASS] apparmor.service = active
[PASS] UFW status = active
[PASS] Default incoming = deny
```

---

# 16. Lynis Improvement Diff

## Goal: 

Compare pre-hardening and post-hardening Lynis results and produce a structured improvement report.

## Context: 

Sarah Park needs a report that shows which findings disappeared, which remain, and whether hardening introduced new issues.

## Instructions: 

Write 16-lynis_diff.sh.

The script must read lynis_findings.json and lynis_post_findings.json or generate the post-hardening file by running Lynis and parsing it.

The script must write hardening_improvement.json with:

    before_score
    after_score
    delta
    resolved_findings
    remaining_findings
    new_findings
    resolved_count
    remaining_count
    new_count
    residual_risk_summary

**Expected Output:**

```bash
$ sudo ./16-lynis_diff.sh
Before: 52
After: 84
Delta: +32
Findings resolved: 41
Findings remaining: 22
New findings: 4
Report saved to: hardening_improvement.json
```

---

# 17. Machine-Readable Compliance Evidence Bundle

## Goal: 

Generate the final compliance artifact that proves what was selected, remediated, validated, and intentionally left unresolved.

## Context: 

This should not be a narrative report. It is an auditor-ready JSON artifact assembled from the outputs created throughout the project.

## Instructions: 

Write 17-compliance_bundle.sh.

The script must read:

    cis_profile.json
    gap_analysis.json
    remediation_queue.json
    audit_validation.json
    validation_results.json
    hardening_improvement.json

The script must produce compliance_report.json with system identity, hardening date, selected/remediated/verified/unresolved controls, deviations, compensating controls, residual Lynis findings, final compliance percentage, and evidence files used.

Every deviation must include control ID, reason, risk accepted, compensating control, and owner.

**Expected Output:**

```bash
$ ./17-compliance_bundle.sh
Evidence files loaded: 6
Controls selected: 15
Controls remediated: 13
Controls verified: 13
Deviations documented: 2
Overall compliance: 86.7%
Residual findings: 22
Report saved to: compliance_report.json
```

---
