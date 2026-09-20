# Threat Detection

Cybersecurity threat detection and analysis study materials. Covers phishing dissection, network traffic analysis with Wireshark, behavioral baseline construction, and practical detection engineering through hands-on lab exercises.

## Case Study: MedDefense

The scenario modules are built around MedDefense, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through incremental security incidents and defense implementations.

Supporting characters (e.g., James Chen, Marcus) and realistic artifacts (network scans, diagnostic outputs, breach summaries, CFO pushback documents) create an immersive, hands-on learning environment.

## Total Exercise Count

**20 exercises** across **2 scenario modules**.

Those marked as advanced are not required to pass the course.

## Overview

This module focuses on identifying, analyzing, and responding to active threats in real-world scenarios. Unlike the defensive posture of the Blue Team modules, this track emphasizes offensive threat simulation, forensic investigation, and the construction of detection logic from enriched event data.

Key focus areas include:
- **Phishing Dissection**: Deep-dive analysis of malicious emails, header authentication, attachment sandboxing, and IOC extraction.
- **Network Traffic Analysis**: Packet-level inspection using Wireshark to identify command-and-control (C2) communications, data exfiltration, and protocol anomalies.
- **Detection Engineering**: Building signatures, anomaly baselines, and correlation rules from raw telemetry.

## Modules

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 1 | [`4x00_phishing_dissection`](4x00_phishing_dissection) | Phishing email forensics: header authentication (SPF/DKIM/DMARC), attachment metadata extraction, URL defanging, sandbox analysis, and IOC mapping to MITRE ATT&CK TTPs | 12 |
| 2 | [`4x01_wire_shark_territory`](4x01_wire_shark_territory) | Network traffic analysis: packet capture filtering, protocol decoding, C2 traffic identification, data exfiltration patterns, and timeline reconstruction | 8 |

### Additional Resources

| Directory | Description |
|-----------|-------------|
| [`learning_objectives`](learning_objectives) | Module-specific learning objectives and competency mapping aligned with CompTIA Security+ and industry detection standards |

## Usage

Each module directory contains its own `README.md` with detailed exercise instructions. Work through modules sequentially, as later exercises often reference findings, artifacts, or detection rules developed in earlier ones.

- **Safety First**: Never navigate directly to suspicious URLs or open attachments on your production workstation. Use defanged URLs, sandbox environments, and command-line tools for all investigations.
- **Documentation**: Every conclusion must be supported by specific evidence from email headers, authentication results, or OSINT findings.
- **Lab Environment**: Perform investigations in an isolated local lab environment. No centralized SIEM or preconfigured infrastructure is required.

### Getting Started

Begin with [`4x00_phishing_dissection`](4x00_phishing_dissection) — no prior modules are required.

[`4x00_phishing_dissection`]

## Related Directories

| Directory | Description |
|-----------|-------------|
| [`blue_team`](../blue_team) | Defensive operations, vulnerability management, and security architecture planning |

---
