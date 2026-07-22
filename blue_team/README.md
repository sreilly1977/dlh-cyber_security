# Blue Team

Cybersecurity defensive operations and blue team study materials. Covers threat intelligence, vulnerability management, security frameworks, regulatory compliance, and practical defense tooling through a scenario-driven case study approach centered on **MedDefense**, a fictional healthcare organization.

---

## Repository Structure

### Scenario Modules

The curriculum follows a progressive learning path through four core modules, each building on the previous:

| Module | Directory | Focus | Exercises |
|--------|-----------|-------|-----------|
| 1 | [`1x00_first_watch`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x00_first_watch/README.md) | SOC fundamentals, incident classification, asset discovery, control gap analysis, and security posture assessment | 18 exercises |
| 2 | [`1x01_know_your_enemy`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/README.md) | Threat intelligence, ransomware (RaaS) analysis, insider threats, social engineering, supply chain risks, and MITRE ATT&CK mapping | 19 exercises |
| 3 | [`1x02_the_weak_links`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x02_the_weak_links/README.md) | Vulnerability management, CVE/CVSS/CWE analysis, exploit hunting, misconfiguration discovery, Lynis auditing, OSINT reconnaissance, and remediation prioritization | 24 exercises |
| 4 | [`1x03_defense_blueprint`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/README.md) | Security frameworks (NIST CSF, CIS Controls), governance architecture, risk quantification (ALE), cost-benefit analysis, budget allocation, and executive communication | 11 exercises |

Each module contains numbered exercise files (e.g., `0-first_impressions.md`, `1-cve_ecosystem.md`) accompanied by supporting artifact files such as scan outputs, threat intelligence dossiers, diagnostic snapshots, and briefing materials that simulate real-world evidence.

### Reference Libraries

| Directory | Description | Contents |
|-----------|-------------|----------|
| [`HIPA`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/HIPA) | HIPAA and healthcare regulatory compliance | HICP Main guide, NIPP Sector-Specific Plan for Healthcare and Public Health |
| [`Knowbe4`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Knowbe4) | Security awareness training resources | Social Engineering Red Flags reference |
| [`Microsoft`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Microsoft) | Microsoft security methodologies | STRIDE Threat Model guide |
| [`NIST_CSF`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_CSF) | NIST Cybersecurity Framework references | CIS Controls Guide v8.1.2, NIST CSWP.29 (CSF 2.0) |
| [`NIST_Special_Publications`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_Special_Publications) | NIST SP 800-series reference documents | SP 800-12 r1, SP 800-30 r1, SP 800-53 r5, SP 800-61 r2, CSWP.29 |

### Course Materials

| Directory | Description | Contents |
|-----------|-------------|----------|
| [`learning_objectives`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/learning_objectives) | Weekly learning objectives for the course | Week 10, Week 11 |

---

## Case Study: MedDefense

The scenario modules are built around **MedDefense**, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through:

- Incident response and root cause analysis on compromised systems
- Threat actor profiling and ransomware exposure assessment
- Vulnerability scanning, triage, and remediation planning
- Framework-aligned defense strategy and executive-level risk communication

Supporting characters (e.g., James Chen, Marcus) and realistic artifacts (network scans, diagnostic outputs, breach summaries, CFO pushback documents) create an immersive, hands-on learning environment.

---

## Alignment with Certifications & Frameworks

This repository supports preparation for:

- **CompTIA Security+** — threat types, vulnerability management, risk assessment, incident response, and security controls
- **NIST Cybersecurity Framework (CSF 2.0)** — Govern, Identify, Protect, Detect, Respond, Recover
- **CIS Controls v8** — Implementation Groups 1–3 safeguard mapping
- **MITRE ATT&CK** — Technique mapping and adversary emulation analysis
- **HIPAA / HICP** — Healthcare-specific regulatory and cybersecurity practices

---

## Usage

Each module directory contains its own `README.md` with exercise instructions. Work through modules sequentially, as later exercises reference findings and decisions from earlier ones. Artifact files (`.txt`, `.pdf`) should be reviewed alongside their corresponding exercises.

---
