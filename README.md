# DLH Cyber Security Academy Repository

![Security+ Badge](https://img.shields.io/badge/Certification-CompTIA_Security%2B-blue)
![Academy Badge](https://img.shields.io/badge/Academy-Luxembourg_Academy_of_Cybersecurity-green)

A comprehensive cybersecurity study repository structured around two primary learning tracks — foundational coursework and applied blue team operations — supplemented by a practical SOC notes collection. Content aligns with the CompTIA Security+ (SY0-701) certification exam domains and NIST/CIS security frameworks.

---

## Repository Structure

| Directory | Description |
|-----------|-------------|
| [`blue_team/`](blue_team/README.md) | Applied defensive operations through a scenario-driven case study (MedDefense) |
| [`common_core/`](common_core/README.md) | Foundational coursework covering all five Security+ domains |
| [`notes/`](notes/) | Practical SOC references — Splunk/Wazuh queries, open-source security stack architecture, and project presentations |

---

## blue_team/

Scenario-based curriculum following **MedDefense**, a fictional healthcare organization. Learners progress through four modules as a security analyst handling incidents, threat intelligence, vulnerability management, and defense strategy.

| Directory | Focus | Exercises |
|-----------|-------|-----------|
| [`1x00_first_watch/`](blue_team/1x00_first_watch/README.md) | SOC fundamentals, incident classification, asset discovery, control gap analysis, security posture assessment | 18 |
| [`1x01_know_your_enemy/`](blue_team/1x01_know_your_enemy/README.md) | Threat intelligence, ransomware (RaaS) analysis, insider threats, social engineering, supply chain risks, MITRE ATT&CK mapping | 19 |
| [`1x02_the_weak_links/`](blue_team/1x02_the_weak_links/README.md) | Vulnerability management, CVE/CVSS/CWE analysis, exploit hunting, Lynis auditing, OSINT, remediation prioritization | 24 |
| [`1x03_defense_blueprint/`](blue_team/1x03_defense_blueprint/README.md) | NIST CSF and CIS Controls mapping, governance, risk quantification (ALE), cost-benefit analysis, budget allocation, executive briefings | 11 |
| [`HIPA/`](blue_team/HIPA/) | HIPAA and healthcare regulatory compliance references (HICP, NIPP Sector-Specific Plan) |
| [`Knowbe4/`](blue_team/Knowbe4/) | Security awareness training — Social Engineering Red Flags reference |
| [`Microsoft/`](blue_team/Microsoft/) | STRIDE Threat Model methodology guide |
| [`NIST_CSF/`](blue_team/NIST_CSF/) | NIST Cybersecurity Framework references (CIS Controls Guide v8.1.2, NIST CSWP.29) |
| [`NIST_Special_Publications/`](blue_team/NIST_Special_Publications/) | NIST SP 800-series documents (SP 800-12 r1, SP 800-30 r1, SP 800-53 r5, SP 800-61 r2) |
| [`learning_objectives/`](blue_team/learning_objectives/) | Weekly learning objectives for the blue team track |


---

## common_core/

Foundational coursework from the DLH Cyber Security Academy covering the core competencies required for the CompTIA Security+ (SY0-701) certification.

| Directory | Description | Security+ Domain |
|-----------|-------------|------------------|
| [`cybersecurity_basics/`](common_core/cybersecurity_basics/README.md) | Foundational concepts, terminology, and core principles | Domain 1.0 |
| [`network_security/`](common_core/network_security/README.md) | Network protocols, segmentation, firewalls, and monitoring | Domains 1.0, 2.0 |
| [`linux_security/`](common_core/linux_security/README.md) | Linux system hardening, permissions, and secure administration | Domains 3.0, 4.0 |
| [`scripting_cyber/`](common_core/scripting_cyber/README.md) | Python automation scripts for security tasks and analysis | Domain 4.0 |
| [`security_policy_analysis/`](common_core/security_policy_analysis/README.md) | Policy frameworks, compliance requirements, and governance | Domain 5.0 |
| [`threat-modeling-fundamentals/`](common_core/threat-modeling-fundamentals/README.md) | Methodologies for identifying and assessing threats | Domain 1.0 |
| [`understanding_vulnerabilities/`](common_core/understanding_vulnerabilities/README.md) | CVE tracking, vulnerability scanning, and mitigation strategies | Domain 1.0 |
| [`web_application_security/`](common_core/web_application_security/README.md) | OWASP Top 10, secure coding practices, and application defense | Domain 1.0 |
| [`learning_objectives/`](common_core/learning_objectives/) | Weekly learning objectives covering all five Security+ domains | Domains 1.0–5.0 |

See the [`common_core/README.md`](common_core/) for the full curriculum map.

---

## notes/

Practical security operations references for SOC analysts and incident response.

| File | Purpose | Platform |
|------|---------|----------|
| [`Open-Source_Security_Stack.md`](notes/Open-Source_Security_Stack.md) | Reference architecture for a complete open-source security platform (OPNsense, Security Onion, Shuffle, Eramba) | Infrastructure |
| [`Top_25_SPL_Queries.md`](notes/Top_25_SPL_Queries.md) | Essential Splunk search queries for threat detection | Splunk SIEM |
| [`Top_25_Wazuh_Queries.md`](notes/Top_25_Wazuh_Queries.md) | Core detection rules for security monitoring | Wazuh SIEM |
| [`Flowchart.md`](notes/Flowchart.md) | Process flowchart for incident response procedures | — |
| `Security+ Security Architecture Domain Presentation.odp` | Presentation deck for the Security Architecture domain | — |
| `Security Infra Project For CS Academy.odp` | Infrastructure project presentation | — |

See the [`notes/README.md`](notes/) for the full documentation including the open-source security stack architecture and detection query categories.

---

## Certification Alignment

This repository supports preparation for:

- **CompTIA Security+ (SY0-701)** — All five exam domains covered across both tracks
- **NIST Cybersecurity Framework (CSF 2.0)** — Govern, Identify, Protect, Detect, Respond, Recover
- **CIS Controls v8** — Implementation Groups 1–3 safeguard mapping
- **MITRE ATT&CK** — Technique mapping and adversary emulation analysis
- **HIPAA / HICP** — Healthcare-specific regulatory and cybersecurity practices

---

## Usage

1. Start with [`common_core/`](common_core/) for foundational concepts aligned to Security+ domains
2. Progress to [`blue_team/`](blue_team/) for applied scenario exercises
3. Reference [`notes/`](notes/) for practical SOC tooling, queries, and architecture guides
4. Within `blue_team/`, work modules sequentially (1x00 → 1x03) as later exercises build on earlier findings

---

### Cheat Sheets

- [Nishtman's Cyber Study Hub](https://niteshtiwari.github.io/)
- [SANS Cybersecurity Posters and Cheat Sheets](https://www.sans.org/posters/)
- [Python Security Cheat Sheet for Developers](https://python-security.readthedocs.io/)
- [Python Cheat Sheet for Ethical Hackers](https://github.com/The-Art-of-Hacking/h4cker)

### Online Training

- [Learn Cybersecurity Step by Step](https://learncybersecurity.stepbystep.com/)
- [HACKTHEBOX](https://www.hackthebox.com/)
- [LetsDefend](https://letsdefend.io/)
- [TryHackMe](https://tryhackme.com/)

### Open Source Infrastructure

- [OPNsense](https://opnsense.org/) — FW, IPS/IDS, Netflow, VPN, WAF
- [Security Onion](https://securityonionsolutions.com/) — NIDS/HIDS, Netflow, SIEM, XDR
- [Shuffle Automation](https://shuffler.io/) — SOAR
- [Eramba](https://www.eramba.org/) — GRC

### AuditD & SysMon Configs

- [AuditD Best Practices Config](https://github.com/Neo23x0/auditd)
- [SysMon for Windows](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SysMon for Linux](https://github.com/SysmonSystemMonitor/sysmon-for-linux)
- [SwiftOnSecurity SysMon config](https://github.com/SwiftOnSecurity/sysmon-config)
- Enable Windows Client DNS Logging: 

```cmd
wevtutil sl Microsoft-Windows-DNS-Client/Operational /enabled:true
```
*Remember to enable browser ad blockers, and exclude local/own DNS*

## About

DLH CS Academy Repo

## License

See [LICENSE](LICENSE) for details.
