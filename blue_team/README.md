# Blue Team

Cybersecurity defensive operations and blue team study materials. Covers threat intelligence, vulnerability management, cryptography, security frameworks, regulatory compliance, and practical defense tooling through a scenario-driven case study approach centered on MedDefense, a fictional healthcare organization.

> **Parent repository:** [`dlh-cyber_security`](https://github.com/sreilly1977/dlh-cyber_security) · **This directory:** [`blue_team`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team)

---

## Repository Structure

### Scenario Modules

The curriculum follows a progressive learning path through ten modules across two series, each building on the previous:

#### Part 1 — Foundations (Modules 1–6)

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 1 | [`1x00_first_watch`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) | SOC fundamentals, incident classification, asset discovery, control gap analysis, and security posture assessment | 18 |
| 2 | [`1x01_know_your_enemy`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x01_know_your_enemy) | Threat intelligence, ransomware (RaaS) analysis, insider threats, social engineering, supply chain risks, and MITRE ATT&CK mapping | 19 |
| 3 | [`1x02_the_weak_links`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x02_the_weak_links) | Vulnerability management, CVE/CVSS/CWE analysis, exploit hunting, misconfiguration discovery, Lynis auditing, OSINT reconnaissance, and remediation prioritization | 24 |
| 4 | [`1x03_defense_blueprint`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x03_defense_blueprint) | Security architecture planning, defense-in-depth strategies, ALE/risk quantification, control evaluation, budget allocation, network segmentation design, and adversarial red-team validation | 11 |
| 5 | [`1x04_crypto_foundation`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x04_crypto_foundation) | Symmetric/asymmetric encryption (AES, RSA, ECC, ChaCha20-Poly1305), hashing, digital signatures, PKI/certificate management, TLS hardening, disk encryption (LUKS), steganography as a threat vector, and key management (TPM/HSM) | 14 |
| 6 | [`1x05_board_briefing`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x05_board_briefing) | Executive synthesis: Crimson Tide attack chain overlay, control interception mapping, gap analysis, crypto emergency assessment, budget ROI analysis, and technical proficiency demonstration | 6 |

#### Part 2 — Applied Hardening (Modules 7–10)

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 7 | [`2x00_locking_the_gates`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x00_locking_the_gates) | Linux infrastructure hardening: baseline security snapshots, CIS control profiling, Lynis audit integration, evidence-based remediation queuing, SSH hardening, PAM fortress configuration, auditd deployment, log management (rsyslog), and host firewall baselines | 14 |
| 8 | [`2x01_windows_fortress`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x01_windows_fortress) | Windows endpoint hardening: security posture assessment, domain reconnaissance, GPO deployment for password/lockout policies, advanced audit policy, PowerShell security logging, Kerberos/authentication hardening, Sysmon, AppLocker, Windows Firewall lockdown, RDP security, and service account control | 15 |
| 9 | [`2x02_eyes_on_endpoint`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x02_eyes_on_endpoint) | EDR deployment, Sysmon configuration and telemetry validation, ATT&CK coverage matrix, PowerShell logging validation, and auditd rule refinement | 16 |
| 10 | [`2x03_patch_equation`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x03_patch_equation) | Vulnerability management lifecycle, patch prioritization, deployment strategies, and compliance scanning | 16 |


### Course Materials

Reference documents supporting the scenario modules:

| Directory | Description | Contents |
|-----------|-------------|----------|
| [`CIS`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/CIS) | CIS Benchmarks for system hardening | CIS Microsoft Windows Server 2022 Benchmark v5.1.0, CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 |
| [`CISA`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/CISA) | CISA cybersecurity advisories and guidance | NSA and CISA Red and Blue Teams — Top Ten Cybersecurity Misconfigurations |
| [`Crypt101`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Crypt101) | Cryptography fundamentals reference | Crypto101 PDF |
| [`HIPAA`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/HIPAA) | HIPAA and healthcare regulatory compliance | HIPAA Main guide, NIPP Sector-Specific Plan for Healthcare and Public Health |
| [`Knowbe4`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Knowbe4) | Security awareness training resources | Social Engineering Red Flags reference |
| [`Microsoft`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Microsoft) | Microsoft security methodologies | STRIDE Threat Model guide |
| [`NIST_CSF`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_CSF) | NIST Cybersecurity Framework references | CIS Controls Guide v8.1.2, NIST CSWP.29 (CSF 2.0) |
| [`NIST_Special_Publications`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_Special_Publications) | NIST SP 800-series reference documents | SP 800-12 r1, SP 800-30 r1, SP 800-53 r5, SP 800-61 r2, CSWP.29 |
| [`SANS`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/SANS) | SANS Institute reading room materials | Additional security research papers and best practices |
| [`learning_objectives`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/learning_objectives) | Weekly learning objectives for the course | Week 10, Week 11 |

---

## Case Study: MedDefense

The scenario modules are built around MedDefense, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through incremental security incidents and defense implementations.

Supporting characters (e.g., James Chen, Marcus) and realistic artifacts (network scans, diagnostic outputs, breach summaries, CFO pushback documents) create an immersive, hands-on learning environment.

---

## Alignment with Certifications & Frameworks

This repository supports preparation for:

- **CompTIA Security+ (SY0-701)** — Core security fundamentals and defensive operations
- **CompTIA CySA+ (CS0-003)** — Threat detection, analysis, and response
- **NIST Cybersecurity Framework (CSF 2.0)** — Implementation and alignment guidance
- **HIPAA Security Rule** — Healthcare regulatory compliance fundamentals
- **CIS Controls v8** — Prioritized security best practices
- **MITRE ATT&CK Framework** — Adversary tactics, techniques, and procedures mapping

---

## Usage

Each module directory contains its own `README.md` with exercise instructions. Work through modules sequentially, as later exercises reference findings and decisions from earlier ones. Artifact files (`.txt`, `.pdf`) should be reviewed alongside their corresponding exercises.

### Getting Started

Begin with [`1x00_first_watch`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) — no prior modules are required.
