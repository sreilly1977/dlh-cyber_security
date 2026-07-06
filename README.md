# DLH Cyber Security Academy Repository

<div align="center">

![Security+ Badge](https://img.shields.io/badge/Certification-CompTIA_Security%2B-blue)
![Academy Badge](https://img.shields.io/badge/Academy-Luxembourg_Academy_of_Cybersecurity-green)

</div>

---

## Overview

This repository serves as a centralized repo for **Stephen Reilly**, enrolled in the **Luxembourg Academy of Cybersecurity**. All content is curated and organized to support preparation for the **CompTIA Security+ (SY0-701)** certification examination.

Most of the scripts published in this repository are one-liners with little to no commenting or error handling, due to the automated checking of the VLE, and are written to showcase command and concept understanding.

The [Security Policy Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/security_policy_analysis/README.md), [Threat Moddeling](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat-modeling-fundamentals/README.md), and [Understanding Vulnerabilities](https://github.com/sreilly1977/dlh-cyber_security/blob/main/understanding_vulnerabilities/README.md) sections are series' of blog posts in which I explore those respective topics. The [Learning Objectives](https://github.com/sreilly1977/dlh-cyber_security/tree/main/learning_objectives) section consists of answers to questions, divided into subject, and condensed to one line, in preparation for that week's test.

---

## Repository Structure

| Directory | Description | Security+ Domains Covered |
|-----------|-------------|--------------------------|
| [`cybersecurity_basics/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/cybersecurity_basics) | Foundational concepts, terminology, and core principles | Domain 1.0: Attacks, Threats, and Vulnerabilities |
| [`learning_objectives/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/learning_objectives) | Weekly learning objectives for the DLH Cyber Security Common Core curriculum | Domains 1.0 - 5.0 |
| [`linux_security/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/linux_security) | Linux system hardening, permissions, and secure administration | Domain 3.0: Architecture, Domain 4.0: Operations |
| [`network_security/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/network_security) | Network protocols, segmentation, firewalls, and monitoring | Domain 1.0, Domain 2.0: Technologies and Tools |
| [`notes/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/notes) | A collection of notes outside the scope of the course | N/A |
| [`scripting_cyber/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/scripting_cyber) | Automation scripts (Python) for security tasks and analysis | Domain 4.0: Operations and Incident Response |
| [`security_policy_analysis/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/security_policy_analysis) | Policy frameworks, compliance requirements, and governance | Domain 5.0: Governance, Risk, and Compliance |
| [`threat-modeling-fundamentals/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat-modeling-fundamentals) | Methodologies for identifying and assessing threats | Domain 1.0: Attack Surface Analysis |
| [`understanding_vulnerabilities/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/understanding_vulnerabilities) | CVE tracking, vulnerability scanning, and mitigation strategies | Domain 1.0: Vulnerability Management |
| [`web_application_security/`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/web_application_security) | OWASP Top 10, secure coding practices, and application defense | Domain 1.0: Application Security |

---

## CompTIA Security+ Alignment

This curriculum maps directly to the CompTIA Security+ SY0-701 exam objectives:

| Exam Domain | Weight | Related Repositories |
|-------------|--------|---------------------|
| **General Security Concepts** | 12% | `cybersecurity_basics`, `understanding_vulnerabilities` |
| **Threats, Vulnerabilities, & Analytics** | 22% | `threat-modeling-fundamentals`, `understanding_vulnerabilities` |
| **Architecture** | 18% | `linux_security`, `network_security` |
| **Operations & Incident Response** | 28% | `scripting_cyber`, `network_security`, `linux_security` |
| **Governance, Risk, & Compliance** | 10% | `security_policy_analysis` |

*Domain weights based on CompTIA Security+ SY0-701 official exam outline.*

---

### Setup Instructions

```bash
# Clone the repository
git clone https://github.com/sreilly1977/dlh-cyber_security.git

# Navigate into the directory
cd dlh-cyber_security

# Explore individual module documentation
ls -la
```

---

### Cheat Sheets
[Nishtman's Cyber Study Hub](https://nishtman-k.github.io/cyber-study-hub/)

[SANS Cybersecurity Posters and Cheat Sheets](https://www.sans.org/posters)

[Python Security Cheat Sheet for Developers](https://www.aptori.com/blog/python-security-cheat-sheet-for-developers)

[Python Cheat Sheet for Ethical Hackers](https://www.comparitech.com/net-admin/python-cheat-sheet-for-ethical-hackers/)

---

### Online Training
[Learn Cybersecurity Step by Step](https://cyber-stride-learn.vercel.app/)

[**HACK**THE**BOX**](https://www.hackthebox.com)

[LetsDefend](https://letsdefend.io/)

[TryHackMe](https://tryhackme.com/)

---

### Opensource Infrastructure
[OPNsense - FW, IPD/IDS, VPN, WAF](https://opnsense.org/)

[Security Onion - NIDS/HIDS. IDS/IPS, Netflow, SIEM, XDR](https://securityonionsolutions.com/)

[UTMStack - SIEM, XDR, SOAR, GRC](https://utmstack.com/)

[Eramba - GRC](https://www.eramba.org/)

### Windows Client Configs

[**Swift**On**Security** SysMon config](https://github.com/SwiftOnSecurity/sysmon-config/blob/master/sysmonconfig-export.xml)

Enable Windows Client DNS Logging:

```cmd
wevtutil sl Microsoft-Windows-DNS-Client/Operational /enabled:true
```
