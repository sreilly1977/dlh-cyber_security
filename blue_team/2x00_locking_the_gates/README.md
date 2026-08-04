0. The Baseline Snapshot

Goal: Capture the complete security state of a system before any changes, establishing the measurement that every subsequent task will improve against.

Context: You cannot prove hardening worked if you do not know where you started. This task captures the system as it is: unhardened, default configuration, every setting at its out-of-the-box value. Every number you record here is the number you will improve.

Instructions: Write a script 0-baseline_snapshot.sh that captures the complete security baseline of a Linux system. The script must:

    Record system identification (hostname, OS, kernel version, uptime)

    List all running services and their state

    List all open ports and listening sockets

    List all SUID and SGID binaries

    List all world-writable files (excluding /proc, /sys, /dev)

    Capture current sysctl security-relevant parameters

    Capture current SSH configuration settings

    Record active user accounts and sudo group membership

Expected Output:

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

1. MedDefense CIS Control Profile

Goal: Build a threat-driven CIS hardening profile for MedDefense Linux servers that becomes the input for later remediation tasks.

Context: The original CIS priority task leaned too heavily toward manual benchmark interpretation. In this project, scripts are the primary deliverable. This rebuilt task turns CIS prioritization into a structured, reusable control profile that later scripts can consume.

MedDefense does not need a generic list of CIS recommendations. It needs a focused control profile for billing-srv-01, web-srv-01, and log-srv-01, tied to the project's actual risks: SSH lateral movement, weak authentication, unnecessary services, missing audit visibility, exposed database services, and insufficient kernel hardening.

Instructions: Write 1-cis_profile.sh.

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

Expected Output:

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

2. The Lynis Audit Parser

Goal: Parse a report file and produce a machine-readable JSON summary of the most important audit results.

Context: Lynis stores the most important audit data in a key-value report file, usually lynis-report.dat. This file is easier to parse than the terminal output or the verbose log file. Converting it into JSON makes the audit results easier to inspect, filter, and reuse in a security workflow.

Instructions: Run a full Lynis audit on the system. Then write a script 2-lynis_parse.sh that:

    accepts the path to a .dat report file as its first argument ("$1")

    extracts the Lynis hardening index

    extracts every warning[], suggestion[], and manual_check[] entry

    parses each finding into:

        severity

        test_id

        message

    produces a structured JSON report on standard output

Hint: man jq

Expected Output:

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

3. Evidence-Based Remediation Queue

Goal: Convert the CIS control profile and Lynis findings into a prioritized, evidence-backed remediation queue.

Context: This task becomes the decision engine that explains why Tasks 4–13 are performed and in what order. Every remediation item must be backed by evidence, mapped to a later hardening script, and ordered by risk.

Instructions: Write 3-remediation_queue.sh.

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

Expected Output:

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

4. The SSH Lockdown

Goal: Harden SSH to eliminate password-based authentication and reduce the attack surface to the minimum required for MedDefense operations.

Context: Finding 009 from your vulnerability assessment (1x02): "SSH on billing-srv-01 allows password-based authentication. Combined with no account lockout policy, this permits brute-force attacks." The Crimson Tide advisory confirmed: in 3 of 5 hospital breaches, the attacker used harvested credentials for SSH lateral movement (Phase 3). This is the first thing you fix.

Instructions: Write a script 4-ssh_hardening.sh that:

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

Expected Output:

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


