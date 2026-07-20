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
| **Warnings** | 0 (Great, no warnings) |
| **Suggestions** | 28 |

---

## Part 2: Analyze Results

### Hardening Index

**Score:** 70 / 100 (Medium-High Security Posture)

**Interpretation:** A score of 70 indicates reasonable baseline security but significant room for improvement. According to Lynis documentation, scores below 50 indicate serious hardening deficiencies, 50-70 indicate moderate hardening gaps, and 70+ indicate good security posture. This system is in the upper range of acceptable but not production-hardened.

---

### Top 5 Warnings (From Service Exposure Analysis)

Since there are technically 0 formal warnings, I am analyzing the highest-risk service exposures identified by systemd-analyze security:

| Rank | Service | Exposure Value | Risk Level | Concern |
|------|---------|----------------|------------|---------|
| **1** | alsa-state.service | 9.6 | UNSAFE | High exposure value indicates unnecessary capabilities that could be exploited if compromised |
| **2** | auditd.service | 9.4 | UNSAFE | Audit daemon should be protected; high exposure contradicts security monitoring purpose |
| **3** | Cups.service | 9.6 | UNSAFE | Print spooler is a known attack vector (PrintNightmare) and should be disabled if unused |
| **4** | libvirtd.service | 9.6 | UNSAFE | Virtualization daemon requires minimal privileges; high exposure increases blast radius |
| **5** | udisks2.service | 9.6 | UNSAFE | USB/device management should be restricted to prevent unauthorized storage access |

**Remediation Summary:**

| Service | Remediation Action |
|---------|-------------------|
| All UNSAFE services | Apply systemd service hardening: ProtectHome=yes, PrivateTmp=yes, NoNewPrivileges=yes |
| CUPS | Disable if printing not needed: systemctl disable --now cups.service |
| libvirtd | Restrict network bindings and apply SELinux/AppArmor profiles |
| auditd | Enable logging to external syslog server for tamper-proofing |

---

### Top 5 Suggestions (From Suggestions Section)

| Rank | Suggestion ID | Description | Security Improvement |
|------|---------------|-------------|---------------------|
| **1** | AUTH-9230 | Configure password hashing rounds in /etc/login.defs | Increase bcrypt/SHA rounds to resist offline cracking attacks |
| **2** | AUTH-9262 | Install PAM module for password strength testing (pam_cracklib) | Enforce minimum password complexity and prevent weak passwords |
| **3** | LOGG-2154 | Enable logging to external logging host | Prevent local log tampering and enable centralized SIEM integration |
| **4** | FINT-4350 | Install file integrity tool (AIDE/Tripwire) | Detect unauthorized file changes indicative of compromise or rootkit |
| **5** | KRNL-6000 | Adjust sysctl values to recommended hardening profile | Enable ASLR, disable IP forwarding, reject redirects, enable SYN cookies |

---

### Category Breakdown

| Category | Score Status | Findings | Interpretation |
|----------|--------------|----------|----------------|
| **Boot and Services** | Medium Risk | Multiple UNSAFE/EXPOSED services | Need systemd service hardening |
| **Authentication** | Good | Password hashing OK, but PAM suggestion exists | Baseline secure but can improve |
| **Networking** | Good | Firewall active, no promiscuous interfaces | Reasonably configured |
| **Logging** | Weak | Remote logging NOT ENABLED, auditd NOT FOUND | Critical gap for incident response |
| **File Integrity** | Weak | No integrity tool installed | Cannot detect post-compromise changes |
| **Cryptographic** | Good | LUKS encryption active, kernel entropy sufficient | Properly encrypted storage |
| **Kernel Hardening** | Medium | Multiple sysctl values differ from profile | Needs tuning to hardened defaults |
| **Software: Firewalls** | Good | Host firewall ACTIVE | Basic perimeter protection |
| **Malware Detection** | Weak | Rootkit scanner found but NOT ACTIVE | False sense of security without active scanning |

**Security Posture Assessment:**

This system demonstrates solid foundational security (encryption, firewall, no active malware) but lacks defense-in-depth controls that enable threat detection and rapid response. The missing file integrity monitoring and remote logging would significantly delay breach discovery. Service exposure levels indicate incomplete hardening that could allow privilege escalation if an attacker gains initial foothold.

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
| **1** | OS End-of-Life (Ubuntu 18.04) | PKGS-7300 | Critical | Standard support ended June 2023 with ESM not enrolled (Finding 011). No security patches for 47 known kernel CVEs (Finding 026). Lynis will flag this as unpatchable vulnerability risk. |
| **2** | No File Integrity Monitoring | FINT-4350 | High | Scan report shows no AIDE/Tripwire/OSSEC deployment. Combined with cryptominer compromise history, system cannot detect post-breach changes. Lynis will recommend installing file integrity tool. |
| **3** | Remote Logging Not Configured | LOGG-2154 | High | Findings 003 and 006 show centralized SIEM does not exist (GAP-003). Syslog logs on local disk only, allowing attacker to erase evidence. Lynis will flag remote logging as critical for forensic capability. |
| **4** | SSH Password Authentication Enabled | AUTH-9308 | High | Finding 009 explicitly states SSH allows password-based authentication without lockout policy. Lynis will compare against hardened profile requiring key-only auth and flag deviation. |
| **5** | Multiple Service Hardening Gaps | BOOT-5264 | Medium | Apache 2.4.29, MySQL 0.0.0.0 binding, and flat network access all violate systemd/operation hardening best practices. Lynis systemd-analyze comparison will show exposure values exceeding safe thresholds. |

### Comparative Analysis: Personal Machine vs. MedDefense billing-srv-01

| Metric | Personal Machine (CachyOS) | MedDefense billing-srv-01 | Risk Differential |
|--------|----------------------------|--------------------------|-------------------|
| **Hardening Index** | 70 | ~45 (projected) | 25-point gap |
| **OS Support Status** | Rolling (current) | EOL 3 years ago | Critical |
| **Logging Capability** | Local only, auditd missing | Local only, no SIEM | Equal weakness |
| **File Integrity** | Not installed | Not installed | Equal weakness |
| **Service Hardening** | 5 UNSAFE services | 3+ vulnerable services with exploits | Higher risk (active exploits vs. theoretical) |
| **Attack History** | Clean | Crypto-miner compromise confirmed | MedDefense already breached |

### Why MedDefense Would Score Lower

The projected 45 hardening index for billing-srv-01 reflects **systemic failure across all security domains**:

1. **Patch Management Failure:** Ubuntu 18.04 EOL means no CVE fixes for kernel and base packages. This is not a configuration gap but an operational failure.

2. **Detection Failure:** No file integrity monitoring or centralized logging means compromise could go undetected for months (as demonstrated by the 14-day cryptominer dwell time).

3. **Authentication Weakness:** SSH password authentication enables brute-force attacks that key-only auth would prevent. Combined with flat network, any attacker with network access can attempt password guessing.

4. **Service Exposure:** Apache RCE (CVE-2021-44790) + Privilege Escalation (CVE-2019-0211) mean the entire system is vulnerable through unauthenticated HTTP requests.

5. **Compromise History:** Previous crypto-miner infection indicates attacker already had successful foothold and persistence mechanisms established. This is not theoretical risk but proven breach capability.

### Conclusion: Security Maturity Gap

My personal system scores 70 because I actively maintain it (rolling updates, firewall enabled, no known compromises). MedDefense's billing-server would score 45 because it represents **three distinct security maturity failures**:

| Failure Type | My System | MedDefense billing-srv-01 |
|--------------|-----------|--------------------------|
| **Preventive Controls** | Firewall, updates, service hardening | No segmentation, EOL OS, vulnerable services |
| **Detective Controls** | Local logs, basic monitoring | No SIEM, no file integrity, no alerting |
| **Corrective Controls** | Backups, rollback capability | Backups on same network (encryptable), no tested recovery |

This comparison demonstrates why scan findings must be interpreted in context. The same Lynis suggestion about file integrity tools represents a recommendation on my system but represents **critical missing detective capability** on MedDefense's already-compromised billing server.

---

*Prepared by: Security Department*  
*References: Lynis 3.1.7 audit output, Project 1x02 Scan Report (Findings 001-031), CISA Hardening Guidance*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
