# DLH Cyber Security Academy Repository

![Security+ Badge](https://img.shields.io/badge/Certification-CompTIA_Security%2B-blue)
![Academy Badge](https://img.shields.io/badge/Academy-Luxembourg_Academy_of_Cybersecurity-green)

## Overview

This repository serves as a centralized repo for Stephen Reilly, enrolled in the Luxembourg Academy of Cybersecurity. All content is curated and organized to support preparation for the CompTIA Security+ (SY0-701) certification examination.

Most of the scripts published in this repository are one-liners with little to no commenting or error handling, due to the automated checking of the VLE, and are written to showcase command and concept understanding.

The Security Policy Analysis, Threat Modeling, and Understanding Vulnerabilities sections are series' of blog posts in which I explore those respective topics. The Learning Objectives section consists of answers to questions, divided by subject, and condensed to one line, in preparation for that week's test.

The repository is organized into two primary tracks:

- **`common_core/`** — The DLH Cyber Security Common Core curriculum, covering foundational cybersecurity concepts, network and Linux security, scripting, web application security, threat modeling, and vulnerability management.
- **`blue_team/`** — Defensive operations and blue team study materials, covering threat intelligence, security frameworks, compliance, and practical defense tooling.

## Repository Structure

### [blue_team/](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team)

| Directory | Description | Security+ Domains Covered |
| --- | --- | --- |
| `1x00_first_watch/` | Introduction to blue team and SOC fundamentals | Domain 4.0: Operations and Incident Response |
| `1x01_know_your_enemy/` | Threat actor profiles and threat intelligence | Domain 1.0: Attacks, Threats, and Vulnerabilities |
| `HIPA/` | HIPAA regulatory compliance for healthcare security | Domain 5.0: Governance, Risk, and Compliance |
| `Knowbe4/` | Security awareness training via KnowBe4 platform | Domain 5.0: Governance, Risk, and Compliance |
| `Microsoft/` | Microsoft security tools and configurations | Domain 2.0: Technologies and Tools |
| `NIST_Special_Publications/` | Reference materials from NIST SP series | Domain 5.0: Governance, Risk, and Compliance |
| `learning_objectives/` | Blue team course and module learning objectives | Domains 1.0 - 5.0 |

### [common_core/](https://github.com/sreilly1977/dlh-cyber_security/tree/main/common_core)

| Directory | Description | Security+ Domains Covered |
| --- | --- | --- |
| `cybersecurity_basics/` | Foundational concepts, terminology, and core principles | Domain 1.0: Attacks, Threats, and Vulnerabilities |
| `learning_objectives/` | Weekly learning objectives for the DLH Cyber Security Common Core curriculum | Domains 1.0 - 5.0 |
| `linux_security/` | Linux system hardening, permissions, and secure administration | Domain 3.0: Architecture, Domain 4.0: Operations |
| `network_security/` | Network protocols, segmentation, firewalls, and monitoring | Domain 1.0, Domain 2.0: Technologies and Tools |
| `scripting_cyber/` | Automation scripts (Python) for security tasks and analysis | Domain 4.0: Operations and Incident Response |
| `threat-modeling-fundamentals/` | Methodologies for identifying and assessing threats | Domain 1.0: Attack Surface Analysis |
| `understanding_vulnerabilities/` | CVE tracking, vulnerability scanning, and mitigation strategies | Domain 1.0: Vulnerability Management |
| `web_application_security/` | OWASP Top 10, secure coding practices, and application defense | Domain 1.0: Application Security |

### notes/

| Directory | Description | Security+ Domains Covered |
| --- | --- | --- |
| `notes/` | A collection of notes outside the scope of the course | N/A |

## CompTIA Security+ Alignment

This curriculum maps directly to the CompTIA Security+ SY0-701 exam objectives:

| Exam Domain | Weight | Related Repositories |
| --- | --- | --- |
| General Security Concepts | 12% | `common_core/cybersecurity_basics`, `common_core/understanding_vulnerabilities` |
| Threats, Vulnerabilities, & Analytics | 22% | `common_core/threat-modeling-fundamentals`, `common_core/understanding_vulnerabilities`, `blue_team/1x01_know_your_enemy` |
| Architecture | 18% | `common_core/linux_security`, `common_core/network_security` |
| Operations & Incident Response | 28% | `common_core/scripting_cyber`, `common_core/network_security`, `common_core/linux_security`, `blue_team/1x00_first_watch` |
| Governance, Risk, & Compliance | 10% | `blue_team/NIST_Special_Publications`, `blue_team/HIPA` |

_Domain weights based on CompTIA Security+ SY0-701 official exam outline._

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
- [Enable Windows Client DNS Logging](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging)

## About

DLH CS Academy Repo

## License

See [LICENSE](LICENSE) for details.
