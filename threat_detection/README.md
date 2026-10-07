# Threat Detection

Cybersecurity threat detection and analysis study materials. Covers phishing dissection, network traffic analysis with Wireshark, behavioral baseline construction, and practical detection engineering through hands-on lab exercises.

## Case Study: MedDefense

The scenario modules are built around MedDefense, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through incremental security incidents and defense implementations.

Supporting characters (e.g., James Chen, Marcus) and realistic artifacts (network scans, diagnostic outputs, breach summaries, CFO pushback documents) create an immersive, hands-on learning environment.

## Total Exercise Count

The curriculum includes 88 hands-on exercises across six core modules.

## Modules

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 1 | [`4x00_phishing_dissection`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x00_phishing_dissection) | Phishing email forensics: header authentication (SPF/DKIM/DMARC), attachment metadata extraction, URL defanging, sandbox analysis, and IOC mapping to MITRE ATT&CK TTPs | 15 |
| 2 | [`4x01_wire_shark_territory`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory) | Network traffic analysis: packet capture filtering, protocol decoding, C2 traffic identification, data exfiltration patterns, and timeline reconstruction | 12 |
| 3 | [`4x02_intelligence_driven_defense`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x02_intelligence_driven_defense) | Threat intelligence integration: IOCs, TLP handling, feed aggregation, and mapping intelligence to defensive controls | 15 |
| 4 | [`4x03_malware_awareness`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x03_malware_awareness) | Malware fundamentals: static/dynamic analysis, PE headers, packers, sandbox execution, and behavioral indicators | 15 |
| 5 | [`4x04_threat_hunting`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x04_threat_hunting) | Proactive hunting: hypothesis-driven searches, log correlation, anomaly detection, and artifact triage | 15 |
| 6 | [`4x05_attack_reconstruction`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x05_attack_reconstruction) | Post-incident reconstruction: kill chain mapping, attacker TTP synthesis, and forensic timeline assembly | 16 |

## Learning Objectives

See the [`learning_objectives`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/learning_objectives) directory for module-specific competency mapping aligned with CompTIA Security+ and industry detection standards.

## Usage

Each module directory contains its own `README.md` with detailed exercise instructions. Work through modules sequentially, as later exercises often reference findings, artifacts, or detection rules developed in earlier ones.

### Getting Started

Begin with [`4x00_phishing_dissection`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x00_phishing_dissection) — no prior modules are required.

## Related Directories

| Directory | Description |
|-----------|-------------|
| [`blue_team`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team) | Defensive operations, vulnerability management, and security architecture planning |

## Footer

### Project Context

This repository supports your ongoing studies for the **CompTIA Security+** certification and real-world incident response workflows. All investigations are designed for local lab environments—never execute suspicious payloads or visit active malicious URLs on production systems.
