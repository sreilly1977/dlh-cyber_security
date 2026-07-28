# Blue Team

Cybersecurity defensive operations and blue team study materials. Covers threat intelligence, vulnerability management, security frameworks, regulatory compliance, and practical defense tooling through a scenario-driven case study approach centered on MedDefense, a fictional healthcare organization.

## Repository Structure

### Scenario Modules

The curriculum follows a progressive learning path through six core modules, each building on the previous:

| Module | Directory | Focus | Exercises |
|--------|-----------|-------|-----------|
| 1 | [`1x00_first_watch`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) | SOC fundamentals, incident classification, asset discovery, control gap analysis, and security posture assessment | 18 exercises |
| 2 | [`1x01_know_your_enemy`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x01_know_your_enemy) | Threat intelligence, ransomware (RaaS) analysis, insider threats, social engineering, supply chain risks, and MITRE ATT&CK mapping | 19 exercises |
| 3 | [`1x02_the_weak_links`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x02_the_weak_links) | Vulnerability management, CVE/CVSS/CWE analysis, exploit hunting, misconfiguration discovery, Lynis auditing, OSINT reconnaissance, and remediation prioritization | 24 exercises |
| 4 | [`1x03_defense_blueprint`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x03_defense_blueprint) | Security architecture planning, defense-in-depth strategies, and control implementation roadmaps | TBD exercises |
| 5 | [`1x04_crypto_foundation`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x04_crypto_foundation) | Cryptographic principles, PKI, encryption standards, and cryptographic protocol analysis | TBD exercises |
| 6 | [`1x05_board_briefing`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x05_board_briefing) | Executive communication, risk reporting, and security governance presentations | TBD exercises |

### Reference Libraries

| Directory | Description | Contents |
|-----------|-------------|----------|
| [`HIPAA`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/HIPAA) | HIPAA and healthcare regulatory compliance | HIPAA Main guide, NIPP Sector-Specific Plan for Healthcare and Public Health |
| [`Knowbe4`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Knowbe4) | Security awareness training resources | Social Engineering Red Flags reference |
| [`Microsoft`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Microsoft) | Microsoft security methodologies | STRIDE Threat Model guide |
| [`NIST_CSF`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_CSF) | NIST Cybersecurity Framework references | CIS Controls Guide v8.1.2, NIST CSWP.29 (CSF 2.0) |
| [`NIST_Special_Publications`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_Special_Publications) | NIST SP 800-series reference documents | SP 800-12 r1, SP 800-30 r1, SP 800-53 r5, SP 800-61 r2, CSWP.29 |
| [`SANS`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/SANS) | SANS Institute reading room materials | Additional security research papers and best practices |
| [`Crypt101`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Crypt101) | Foundational cryptography concepts | Cryptographic algorithms, key management, and implementation guides |

### Course Materials

| Directory | Description | Contents |
|-----------|-------------|----------|
| [`learning_objectives`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/learning_objectives) | Weekly learning objectives for the course | Week 10, Week 11 |

## Case Study: MedDefense

The scenario modules are built around MedDefense, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through incremental security incidents and defense implementations.

Supporting characters (e.g., James Chen, Marcus) and realistic artifacts (network scans, diagnostic outputs, breach summaries, CFO pushback documents) create an immersive, hands-on learning environment.

## Alignment with Certifications & Frameworks

This repository supports preparation for:
- [CompTIA Security+ (SY0-701)](https://www.comptia.org/certifications/security) — Core security fundamentals and defensive operations
- [CompTIA CySA+ (CS0-003)](https://www.comptia.org/certifications/cybersecurity-analyst) — Threat detection, analysis, and response
- [NIST Cybersecurity Framework (CSF 2.0)](https://www.nist.gov/cyberframework) — Implementation and alignment guidance
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html) — Healthcare regulatory compliance fundamentals
- [CIS Controls v8](https://www.cisecurity.org/controls) — Prioritized security best practices
- [MITRE ATT&CK Framework](https://attack.mitre.org/) — Adversary tactics, techniques, and procedures mapping

## Usage

Each module directory contains its own `README.md` with exercise instructions. Work through modules sequentially, as later exercises reference findings and decisions from earlier ones. Artifact files (`.txt`, `.pdf`) should be reviewed alongside their corresponding exercises.

### Getting Started

1. Clone the repository
2. Begin with [`1x00_first_watch`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) for foundational SOC concepts
3. Review reference libraries as needed during exercises
4. Document your findings for cumulative learning objectives

---
