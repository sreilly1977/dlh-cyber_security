# 8. The Self-Audit
## Security Audit with Lynis and MedDefense Projection

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 8)  

---

## Part 1: Install and Run

### Installation Command

    sudo apt update && sudo apt install lynis -y

### Audit Execution

    sudo lynis audit system

### System Information (From Provided Output)

| Parameter | Value |
|-----------|-------|
| **Lynis Version** | 3.1.7 |
| **Operating System** | CachyOS (Rolling release) |
| **Kernel Version** | 7.1.4 |
| **Hostname** | chloeravenloft |
| **Hardware Platform** | x86_64 |
| **Tests Performed** | 248 |
| **Plugins Enabled** | 0 |
| **Hardening Index** | 70 / 100 |
| **Warnings** | 0 (Lynis reports "Great, no warnings") |
| **Suggestions** | 28 |

---

## Part 2: Analyze Results

### Hardening Index

**Score:** 70 / 100 (Medium-High Security Posture)

**Interpretation:** A score of 70 indicates reasonable baseline security but significant room for improvement. According to Lynis documentation, scores below 50 indicate serious hardening deficiencies, 50-70 indicate moderate hardening gaps, and 70+ indicate good security posture. This system is in the upper range of acceptable but not production-hardened.

---

### Top 5 Warnings

Although Lynis formally reports zero warnings in the summary, the audit output contains several critical security findings flagged with concerning statuses (DISABLED, NOT FOUND, FILES FOUND, NONE, DIFFERENT). These represent real security gaps that Lynis identified during its 248 checks. The following 5 are the most critical:

**Warning 1: No Mandatory Access Control (MAC) Framework**

| Attribute | Value |
|-----------|-------|
| **Lynis Check** | Security frameworks section: Checking presence AppArmor [NOT FOUND], SELinux [NOT FOUND], TOMOYO [NOT FOUND], grsecurity [NOT FOUND], MAC framework [NONE] |
| **What Lynis Checks** | Whether any kernel-level mandatory access control system is installed and enforcing security policies on processes and files |
| **Why It Matters** | Without a MAC framework (AppArmor or SELinux), there is no kernel-enforced confinement of processes. A compromised service runs with the full permissions of its user account. MAC frameworks contain damage by restricting what a process can access even after compromise, limiting the blast radius of an exploit. |
| **Remediation** | Install and enable AppArmor: sudo apt install apparmor apparmor-utils, then enable in kernel boot parameters. Alternatively configure SELinux for stricter policy-based confinement. |

**Warning 2: Deleted Files Still in Use**

| Attribute | Value |
|-----------|-------|
| **Lynis Check** | Logging and files section: Checking deleted files in use [FILES FOUND] |
| **What Lynis Checks** | Whether any processes have open file handles to deleted files, which can indicate replaced system binaries still running in memory |
| **Why It Matters** | Deleted files in use is a classic indicator of compromise. Attackers replace system binaries (like ps, ls, or sshd) with trojaned versions, then delete the originals while the malicious version continues running in memory. While this can also occur from legitimate package updates that require a service restart, it must be investigated to rule out rootkit activity. |
| **Remediation** | Identify which processes hold deleted file handles using lsof +L1. If legitimate (post-update), restart the affected services. If suspicious, capture memory for forensic analysis and investigate potential rootkit installation. |

**Warning 3: Failed Login Attempt Logging Disabled**

| Attribute | Value |
|-----------|-------|
| **Lynis Check** | Users, Groups and Authentication section: Logging failed login attempts [DISABLED] |
| **What Lynis Checks** | Whether the system records authentication failures, enabling detection of brute-force password attacks |
| **Why It Matters** | Without failed login logging, brute-force attacks against local accounts are invisible. An attacker can attempt thousands of password guesses without leaving any trace in system logs. This is particularly dangerous for SSH-accessible systems where automated tools can run continuous credential stuffing campaigns. The inability to detect failed logins also prevents tools like fail2ban from blocking malicious IPs. |
| **Remediation** | Enable failed login logging in PAM configuration. Install fail2ban to automatically block IPs after repeated failures. Ensure rsyslog or journald captures auth.log entries. |

**Warning 4: Secure Boot Disabled**

| Attribute | Value |
|-----------|-------|
| **Lynis Check** | Boot and services section: Checking Secure Boot [DISABLED], Boot loader [NONE FOUND] |
| **What Lynis Checks** | Whether UEFI Secure Boot is enabled, which verifies cryptographic signatures on boot components before allowing execution |
| **Why It Matters** | Secure Boot prevents unauthorized bootloaders, kernel modules, and boot-level rootkits from loading during system startup. With Secure Boot disabled, an attacker with physical or remote root access can install a bootkit that survives OS reinstalls and operates below the operating system layer. This makes post-compromise detection extremely difficult because the rootkit controls what the OS can see. |
| **Remediation** | Enable Secure Boot in UEFI/BIOS firmware. Ensure the bootloader is properly signed. Register any custom kernel modules with MOK (Machine Owner Key) if using unsigned drivers. |

**Warning 5: No File Integrity Monitoring Tool Installed**

| Attribute | Value |
|-----------|-------|
| **Lynis Check** | Software: file integrity section: dm-integrity [DISABLED], dm-verity [DISABLED], Checking presence integrity tool [NOT FOUND] |
| **What Lynis Checks** | Whether any file integrity monitoring (FIM) tool such as AIDE, Tripwire, or OSSEC is installed to detect unauthorized changes to critical system files |
| **Why It Matters** | Without file integrity monitoring, an attacker can modify system binaries, configuration files, or cron jobs without detection. File integrity tools establish cryptographic baselines of critical files and alert when modifications occur. This is essential for detecting backdoors, rootkits, and persistence mechanisms after a compromise. The absence of FIM means the system cannot distinguish between legitimate administrative changes and attacker modifications. |
| **Remediation** | Install AIDE (Advanced Intrusion Detection Environment): sudo apt install aide, initialize the database with aideinit, and schedule regular checks via cron or systemd timer. Configure centralized alerting to forward integrity violations to a monitoring system. |

---

### Top 5 Suggestions

| Rank | Suggestion ID | Description | Security Improvement |
|------|---------------|-------------|---------------------|
| **1** | AUTH-9230 | Configure password hashing rounds in /etc/login.defs | Increase bcrypt/SHA rounds to resist offline cracking attacks. More hashing rounds mean each guess takes longer to compute, making stolen password hashes exponentially harder to crack. |
| **2** | AUTH-9262 | Install PAM module for password strength testing (pam_cracklib or pam_passwdqc) | Enforce minimum password complexity requirements at the PAM level so users cannot set weak passwords like "password123" or dictionary words. Prevents predictable credentials that enable brute-force success. |
| **3** | LOGG-2154 | Enable logging to an external logging host for archiving and additional protection | Forward logs to a remote syslog server or SIEM so that an attacker who gains root cannot erase their tracks by deleting local logs. Centralized logs survive host compromise and enable cross-system correlation. |
| **4** | FINT-4350 | Install a file integrity tool to monitor changes to critical and sensitive files | Deploy AIDE or Tripwire to establish cryptographic baselines of system binaries and configuration files. Alerts on unauthorized modifications that indicate backdoor installation, rootkit deployment, or configuration tampering. |
| **5** | KRNL-6000 | Adjust sysctl values to match recommended hardening profile | Several kernel parameters differ from Lynis recommended values: dev.tty.ldisc_autoload, fs.protected_fifos, fs.protected_regular, kernel.modules_disabled, kernel.sysrq, kernel.unprivileged_bpf_disabled, net.core.bpf_jit_harden, net.ipv4.conf.all.log_martians, and net.ipv4.conf.all.send_redirects. Correcting these prevents kernel module injection, symlink attacks, BPF abuse, and network-based reconnaissance. |

---

### Category Breakdown

| Category | Score Status | Findings | Interpretation |
|----------|--------------|----------|----------------|
| **Boot and Services** | Medium Risk | Secure Boot disabled, multiple UNSAFE/EXPOSED services via systemd-analyze security | Need systemd service hardening and Secure Boot enablement |
| **Users, Groups and Authentication** | Medium Risk | Password hashing OK, but PAM strength checking missing, password aging disabled, failed login logging disabled | Baseline secure but critical detective controls missing |
| **Networking** | Good | Firewall active, no promiscuous interfaces, redirect acceptance correct | Reasonably configured with no major concerns |
| **Logging** | Weak | Remote logging NOT ENABLED, auditd NOT FOUND, deleted files in use | Critical gap for incident response and forensic capability |
| **File Integrity** | Weak | No integrity tool installed, dm-integrity disabled | Cannot detect post-compromise changes |
| **Cryptographic** | Medium | LUKS encryption active, kernel entropy sufficient, but expired SSL certificates found | Proper disk encryption but certificate management gap |
| **Kernel Hardening** | Medium | Multiple sysctl values DIFFERENT from profile (9 parameters) | Needs tuning to hardened defaults |
| **Security Frameworks** | Weak | No AppArmor, SELinux, TOMOYO, or grsecurity | No kernel-level process confinement |
| **Software: Firewalls** | Good | Host firewall ACTIVE | Basic perimeter protection in place |
| **Malware Detection** | Medium | Rootkit scanner found but no active agent | Passive scanning only, no real-time protection |
| **USB Devices** | Medium | USB storage driver NOT DISABLED, USBGuard NOT FOUND | Removable media access unrestricted |

**Security Posture Assessment:**

This system demonstrates solid foundational security (disk encryption, active firewall, no formal warnings) but lacks defense-in-depth controls that enable threat detection and rapid response. The three most significant gaps are: no MAC framework (no kernel-level process containment), no file integrity monitoring (cannot detect post-compromise changes), and no remote logging (local logs are erasable by an attacker with root). These missing controls mean that while the system resists initial compromise reasonably well, it has virtually no ability to detect or respond to a successful breach. The hardening index of 70 accurately reflects this split: good preventive controls, weak detective controls.

---

## Part 3: MedDefense Projection

### Billing Server Context

| Parameter | Value |
|-----------|-------|
| **Host** | billing-srv-01 |
| **IP** | 10.10.2.15 |
| **OS** | Ubuntu 18.04.6 LTS (EOL June 2023) |
| **Services** | Apache 2.4.29, MySQL, SSH (password auth enabled) |
| **History** | Crypto-miner compromise for 14+ days (Finding 002) |
| **Network** | Flat 10.10.0.0/16, no segmentation |

### Projected Lynis Findings on billing-srv-01

| # | Expected Finding | Lynis Control ID | Severity | Reasoning |
|---|------------------|------------------|----------|-----------|
| **1** | OS End-of-Life (Ubuntu 18.04) | PKGS-7300 | Critical | Standard support ended June 2023 with ESM not enrolled (Finding 011). No security patches for 47 known kernel CVEs (Finding 026). Lynis will flag this as unpatchable vulnerability risk since the OS no longer receives security updates. |
| **2** | No File Integrity Monitoring | FINT-4350 | High | Scan report shows no AIDE/Tripwire/OSSEC deployment. Combined with cryptominer compromise history, system cannot detect post-breach changes. Lynis will recommend installing file integrity tool because the server was already compromised and persistence mechanisms may still exist. |
| **3** | Remote Logging Not Configured | LOGG-2154 | High | Findings 003 and 006 show centralized SIEM does not exist (GAP-003). Syslog logs on local disk only, allowing attacker to erase evidence. Lynis will flag remote logging as critical for forensic capability since the 14-day cryptominer dwell time proves local detection failed. |
| **4** | SSH Password Authentication Enabled | AUTH-9308 | High | Finding 009 explicitly states SSH allows password-based authentication without lockout policy. Lynis compares SSH config against hardened profile requiring PermitRootLogin no, PasswordAuthentication no, and key-only auth. The deviation will be flagged because the server is on a flat network reachable by any compromised host. |
| **5** | No MAC Framework (AppArmor/SELinux) | MACF-6230 | High | Ubuntu 18.04 ships with AppArmor available but it is likely not enforced given the inconsistent hardening documented in 1x00 T3 (SSH key-only on ehr-srv-01 but not billing-srv-01). Lynis will flag missing MAC framework because Apache RCE (CVE-2021-44790) would be contained by AppArmor profiles that restrict what the www-data user can access. |

### Comparative Analysis: Personal Machine vs. MedDefense billing-srv-01

| Metric | Personal Machine (CachyOS) | MedDefense billing-srv-01 | Risk Differential |
|--------|----------------------------|--------------------------|-------------------|
| **Hardening Index** | 70 | ~45 (projected) | 25-point gap |
| **OS Support Status** | Rolling (current) | EOL 3 years ago | Critical |
| **Logging Capability** | Local only, auditd missing | Local only, no SIEM | Equal weakness |
| **File Integrity** | Not installed | Not installed | Equal weakness |
| **MAC Framework** | None | Likely none | Equal weakness |
| **Service Hardening** | 5 UNSAFE services | 3+ vulnerable services with weaponized exploits | Higher risk (active exploits vs. theoretical) |
| **Attack History** | Clean | Crypto-miner compromise confirmed | MedDefense already breached |

### Why MedDefense Would Score Lower

The projected 45 hardening index for billing-srv-01 reflects systemic failure across all security domains:

1. **Patch Management Failure:** Ubuntu 18.04 EOL means no CVE fixes for kernel and base packages. This is not a configuration gap but an operational failure.

2. **Detection Failure:** No file integrity monitoring or centralized logging means compromise could go undetected for months (as demonstrated by the 14-day cryptominer dwell time).

3. **Authentication Weakness:** SSH password authentication enables brute-force attacks that key-only auth would prevent. Combined with flat network, any attacker with network access can attempt password guessing.

4. **Service Exposure:** Apache RCE (CVE-2021-44790) plus Privilege Escalation (CVE-2019-0211) mean the entire system is vulnerable through unauthenticated HTTP requests.

5. **Compromise History:** Previous crypto-miner infection indicates attacker already had successful foothold and persistence mechanisms established. This is not theoretical risk but proven breach capability.

### Conclusion: Security Maturity Gap

My personal system scores 70 because I actively maintain it with rolling updates, an enabled firewall, and no known compromises. MedDefense's billing server would score approximately 45 because it represents three distinct security maturity failures: preventive controls absent (no segmentation, EOL OS, vulnerable services), detective controls absent (no SIEM, no file integrity, no failed login logging), and corrective controls untested (backups on same network, no tested recovery). This comparison demonstrates why scan findings must be interpreted in context: the same Lynis suggestion about file integrity tools represents a recommendation on my system but represents critical missing detective capability on MedDefense's already-compromised billing server.

---

*Prepared by: Security Department*  
*References: Lynis 3.1.7 audit output, Project 1x02 Scan Report (Findings 001-031), CISA Hardening Guidance*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
