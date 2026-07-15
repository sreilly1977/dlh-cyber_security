# Common Core Curriculum

Foundational coursework from the DLH Cyber Security Academy, covering the core competencies required for the CompTIA Security+ (SY0-701) certification examination.

## Contents

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

## Notes

Most scripts in this repository are one-liners with little to no commenting or error handling, due to the automated checking of the VLE. They are written to showcase command and concept understanding rather than production readiness.

The Threat Modeling Fundamentals and Understanding Vulnerabilities sections are series of blog posts exploring those respective topics. The Learning Objectives section consists of answers to questions, divided by subject, and condensed to one line, in preparation for that week's test.

## CompTIA Security+ Alignment

| Exam Domain | Weight | Related Directories |
| --- | --- | --- |
| General Security Concepts | 12% | `cybersecurity_basics`, `understanding_vulnerabilities` |
| Threats, Vulnerabilities, & Analytics | 22% | `threat-modeling-fundamentals`, `understanding_vulnerabilities` |
| Architecture | 18% | `linux_security`, `network_security` |
| Operations & Incident Response | 28% | `scripting_cyber`, `network_security`, `linux_security` |
| Governance, Risk, & Compliance | 10% | _See [`../blue_team`](../blue_team)_ |

_Domain weights based on CompTIA Security+ SY0-701 official exam outline._
