# DLH Cyber Security Academy Repository

<div align="center">

![Security+ Badge](https://img.shields.io/badge/CompTIA-Security%2B-yellow)
![Academy Badge](https://img.shields.io/badge/Luxembourg-CS_Academy-blue)

</div>

A comprehensive cybersecurity study repository structured around two primary learning tracks — foundational coursework and applied blue team operations — supplemented by a practical SOC notes collection. Content aligns with the CompTIA Security+ (SY0-701) certification exam domains and NIST/CIS security frameworks.

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [`blue_team/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team) | Applied defensive operations through a scenario-driven case study (MedDefense) |
| [`common_core/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core) | Foundational coursework covering all five Security+ domains |
| [`notes/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/notes) | Practical SOC references — Splunk/Wazuh queries, open-source security stack architecture, and project presentations |

---

## `blue_team/`

Applied defensive operations through a scenario-driven case study centered on MedDefense, a fictional healthcare organization. Thirteen modules build practical SOC analyst skills from incident classification through executive briefing.

### Part 1 — Foundations (Modules 1–6)

| Directory | Focus | Exercises |
|-----------|-------|-----------|
| [`1x00_first_watch/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) | SOC fundamentals, incident classification, asset discovery, control gap analysis, security posture assessment | 18 |
| [`1x01_know_your_enemy/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x01_know_your_enemy) | Threat intelligence, ransomware (RaaS) analysis, insider threats, social engineering, supply chain risks, MITRE ATT&CK mapping | 19 |
| [`1x02_the_weak_links/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x02_the_weak_links) | Vulnerability management, CVE/CVSS/CWE analysis, exploit hunting, Lynis auditing, OSINT, remediation prioritization | 24 |
| [`1x03_defense_blueprint/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x03_defense_blueprint) | NIST CSF and CIS Controls mapping, governance, risk quantification (ALE), cost-benefit analysis, budget allocation, executive briefings | 20 |
| [`1x04_crypto_foundation/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x04_crypto_foundation) | Cryptographic principles, PKI, encryption standards, cryptographic protocol analysis, cipher implementation | 24 |
| [`1x05_board_briefing/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x05_board_briefing) | Executive communication, risk reporting, security governance presentations, stakeholder management | 10 |

### Part 2 — Applied Hardening (Modules 7–12)

| Directory | Focus | Exercises |
|-----------|-------|-----------|
| [`2x00_locking_the_gates/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x00_locking_the_gates) | Network perimeter defenses, firewall rule management, access control lists, segmentation strategies | 18 |
| [`2x01_windows_fortress/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x01_windows_fortress) | Windows security hardening, Group Policy Objects, Active Directory security, privilege management | 17 |
| [`2x02_eyes_on_endpoint/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x02_eyes_on_endpoint) | Endpoint detection and response, EDR configuration, Sysmon deployment, host-based monitoring | 16 |
| [`2x03_patch_equation/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x03_patch_equation) | Vulnerability management lifecycle, patch prioritization, deployment strategies, compliance scanning | 16 |
| [`2x04_perimeter_defense/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x04_perimeter_defense) | Network defense control plane, nftables rule enforcement, protocol auditing, Suricata IDS analysis, PCAP investigation, DNS filtering | 16 |
| [`2x05_defensible_endpoint/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x05_defensible_endpoint) | Integrated endpoint hardening capstone, baseline snapshots, Linux/Windows hardening, telemetry deployment, compliance reporting, handoff packaging | 12 |

### Part 3 — Evidence Pipeline (Module 13)

| Directory | Focus | Exercises |
|-----------|-------|-----------|
| [`3x00_evidence_pipeline/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x00_evidence_pipeline) | Evidence pipeline construction, multi-format log parsing, data normalization, schema validation, event enrichment, timeline indexing | 16 |
[`3x01_reading_the_noise`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x01_reading_the_noise) | Behavioral baseline construction from enriched event data: format analysis, field indexing, query toolkit, event taxonomy, authentication/process/network/file baselines, temporal activity profiling, anomaly detection across auth/process/network sources, cross-source correlation, anomaly ranking, and self-contained baseline package assembly | 17 |

### Reference Libraries

| Directory | Description |
|-----------|-------------|
| [`Crypt101/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Crypt101) | Foundational cryptography concepts, algorithms, and implementation guides |
| [`HIPAA/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/HIPAA) | HIPAA and healthcare regulatory compliance references (HICP, NIPP Sector-Specific Plan) |
| [`Knowbe4/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Knowbe4) | Security awareness training resources and social engineering red flags |
| [`Microsoft/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/Microsoft) | Microsoft security methodologies (STRIDE Threat Model) |
| [`NIST_CSF/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_CSF) | NIST Cybersecurity Framework references (CIS Controls Guide v8.1.2, CSWP.29) |
| [`NIST_Special_Publications/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/NIST_Special_Publications) | NIST SP 800-series reference documents (SP 800-12, 800-30, 800-53, 800-61) |
| [`SANS/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/SANS) | SANS Institute reading room materials and security research papers |
| [`learning_objectives/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/learning_objectives) | Weekly learning objectives for the course (Weeks 10 & 11 ) |

---

## `common_core/`

Foundational coursework organized into sub-modules aligned with CompTIA Security+ (SY0-701) domains. Each sub-module builds theoretical knowledge with practical application examples.

| Directory | Description | Security+ Domain |
|-----------|-------------|------------------|
| [`cybersecurity_basics/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/cybersecurity_basics) | Foundational concepts, terminology, and core principles | Domain 1.0 |
| [`network_security/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/network_security) | Network protocols, segmentation, firewalls, and monitoring | Domains 1.0, 2.0 |
| [`linux_security/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/linux_security) | Linux system hardening, permissions, and secure administration | Domains 3.0, 4.0 |
| [`scripting_cyber/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/scripting_cyber) | Python automation scripts for security tasks and analysis | Domain 4.0 |
| [`security_policy_analysis/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/security_policy_analysis) | Policy frameworks, compliance requirements, and governance | Domain 5.0 |
| [`threat-modeling-fundamentals/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/threat-modeling-fundamentals) | Methodologies for identifying and assessing threats | Domain 1.0 |
| [`understanding_vulnerabilities/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/understanding_vulnerabilities) | CVE tracking, vulnerability scanning, and mitigation strategies | Domain 1.0 |
| [`web_application_security/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/web_application_security) | Web app vulnerabilities, OWASP Top 10, and secure coding practices | Domain 2.0 |

See the [`common_core/README.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/common_core/README.md) for the full curriculum map.

---

## `notes/`

Practical security operations references for SOC analysts and incident response teams. Includes detection query templates, architecture documentation, and presentation materials.

### Key Documents

| File | Description |
|------|-------------|
| [`Open-Source_Security_Stack.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Open-Source_Security_Stack.md) | Architecture blueprint for home lab security infrastructure |
| [`Top_25_SPL_Queries.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Top_25_SPL_Queries.md) | Commonly used Splunk SPL queries for threat detection |
| [`Top_25_Wazuh_Queries.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Top_25_Wazuh_Queries.md) | Wazuh rule queries and detection patterns |
| [`Flowchart.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Flowchart.md) | Incident response workflow diagrams |
| [`Security+ Security Architecture Domain Presentation.odp`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Security+%20Security%20Architecture%20Domain%20Presentation.odp) | Slide deck for Security+ Domain 3 coverage |
| [`Security Infra Project For CS Academy.odp`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Security%20Infra%20Project%20For%20CS%20Academy.odp) | Complete infrastructure project presentation |

See the [`notes/README.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/README.md) for full documentation including the open-source security stack architecture and detection query categories.

---

## Certification Alignment

This repository supports preparation for:

| Certification | Domain Coverage | Resources |
|---------------|-----------------|-----------|
| [CompTIA Security+ (SY0-701)](https://www.comptia.org/certifications/security) | All 5 domains | `common_core/` + `blue_team/` exercises |
| [CompTIA CySA+ (CS0-003)](https://www.comptia.org/certifications/cybersecurity-analyst) | Threat detection, analysis, response | `notes/` queries + `blue_team/` SOC modules |
| [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework) | Identify, Protect, Detect, Respond, Recover | `blue_team/NIST_CSF/` references |
| [CIS Controls v8](https://www.cisecurity.org/controls) | Prioritized security best practices | `blue_team/` exercise mappings |
| [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html) | Healthcare compliance fundamentals | `blue_team/HIPAA/` references |
| [MITRE ATT&CK Framework](https://attack.mitre.org/) | Adversary TTPs mapping | `blue_team/1x01_know_your_enemy/` exercises |

---

## Usage

Work through the tracks based on your learning goals:

### Learning Paths

| Path | Start Here | Best For |
|------|------------|----------|
| Foundation First | [`common_core/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core) | Security+ exam prep, new learners |
| Applied Defense | [`blue_team/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team) | SOC skills, hands-on practice |
| Quick References | [`notes/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/notes) | Working professionals, query lookups |

### Recommended Workflow

1. **New learners:** Begin with [`common_core/cybersecurity_basics/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core/cybersecurity_basics), then proceed sequentially through each domain module
2. **Security+ candidates:** Review [`common_core/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core) aligned with SY0-701 exam objectives, supplement with [`notes/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/notes) for practical context
3. **Blue team aspirants:** Follow [`blue_team/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team) modules in order, document findings cumulatively
4. **Working analysts:** Use [`notes/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/notes) query collections during incident response activities

### Cheat Sheets

Available in the [`notes/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/notes) directory:
- Splunk SPL quick reference
- Wazuh rule patterns
- Common port/protocol reference
- OWASP Top 10 summary

### Online Training Resources

- [TryHackMe](https://tryhackme.com) — Guided learning rooms
- [HackTheBox](https://www.hackthebox.com) — Hands-on labs
- [OverTheWire](https://overthewire.org) — Command line and security challenges

### Open Source Infrastructure

Setup guides and configuration files available in the repository for:
- Wazuh SIEM deployment
- Splunk Free instance
- Security Onion network monitoring
- Home lab architecture recommendations

### AuditD & SysMon Configs

Configuration templates for:
- Linux audit daemon rules
- Windows Sysmon Event ID filtering
- Log retention policies
- Compliance-aligned baselines

> **Note:** Remember to enable browser ad blockers when accessing public security resources, and configure local DNS exclusions for optimal log collection.
> wevtutil sl Microsoft-Windows-DNS-Client/Operational /enabled:true

---

## License

See [`LICENSE`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/LICENSE) for details.

---
