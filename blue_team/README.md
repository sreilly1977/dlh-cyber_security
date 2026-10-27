# Blue Team

Cybersecurity defensive operations and blue team study materials. Covers threat intelligence, vulnerability management, cryptography, security frameworks, regulatory compliance, and practical defense tooling through a scenario-driven case study approach centered on MedDefense, a fictional healthcare organization.

Parent repository: [`dlh-cyber_security`](https://github.com/sreilly1977/dlh-cyber_security) · This directory: `blue_team`

---

## Case Study: MedDefense

The scenario modules are built around MedDefense, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through incremental security incidents and defense implementations.

Supporting characters (e.g., James Chen, Marcus) and realistic artifacts (network scans, diagnostic outputs, breach summaries, CFO pushback documents) create an immersive, hands-on learning environment.

## Total Exercise Count

**306 exercises** across all **18 scenario modules**.

Those marked as advanced are not required to pass the course.

---

## Repository Structure

### Scenario Modules

The curriculum follows a progressive learning path through twelve modules across three series, each building on the previous:

#### Part 1 — Foundations (Modules 1–6)

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 1 | [`1x00_first_watch`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) | SOC fundamentals, incident classification, asset discovery, control gap analysis, and security posture assessment | 18 |
| 2 | [`1x01_know_your_enemy`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x01_know_your_enemy) | Threat intelligence, ransomware (RaaS) analysis, insider threats, social engineering, supply chain risks, and MITRE ATT&CK mapping | 19 |
| 3 | [`1x02_the_weak_links`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x02_the_weak_links) | Vulnerability management, CVE/CVSS/CWE analysis, exploit hunting, misconfiguration discovery, Lynis auditing, OSINT reconnaissance, and remediation prioritization | 24 |
| 4 | [`1x03_defense_blueprint`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x03_defense_blueprint) | Security architecture planning, defense-in-depth strategies, ALE/risk quantification, control evaluation, budget allocation, network segmentation design, and adversarial red-team validation | 20 |
| 5 | [`1x04_crypto_foundation`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x04_crypto_foundation) | Symmetric/asymmetric encryption (AES, RSA, ECC, ChaCha20-Poly1305), hashing, digital signatures, PKI/certificate management, TLS hardening, disk encryption (LUKS), steganography as a threat vector, and key management (TPM/HSM) | 24 |
| 6 | [`1x05_board_briefing`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x05_board_briefing) | Executive synthesis: Crimson Tide attack chain overlay, control interception mapping, gap analysis, crypto emergency assessment, budget ROI analysis, and technical proficiency demonstration | 10 |

#### Part 2 — Applied Hardening (Modules 7–12)

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 7 | [`2x00_locking_the_gates`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x00_locking_the_gates) | Linux infrastructure hardening: baseline security snapshots, CIS control profiling, Lynis audit integration, evidence-based remediation queuing, SSH hardening, PAM fortress configuration, auditd deployment, log management (rsyslog), and host firewall baselines | 18 |
| 8 | [`2x01_windows_fortress`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x01_windows_fortress) | Windows endpoint hardening: security posture assessment, domain reconnaissance, GPO deployment for password/lockout policies, advanced audit policy, PowerShell security logging, Kerberos/authentication hardening, Sysmon, AppLocker, Windows Firewall lockdown, RDP security, and service account control | 17 |
| 9 | [`2x02_eyes_on_endpoint`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x02_eyes_on_endpoint) | Endpoint detection and response (EDR), behavioral monitoring, process tree analysis, memory forensics, and incident triage workflows | 16 |
| 10 | [`2x03_patch_equation`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x03_patch_equation) | Patch management lifecycle, vulnerability scanning automation, change control integration, zero-day response protocols, and patch testing methodologies | 16 |
| 11 | [`2x04_perimeter_defense`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x04_perimeter_defense) | Network perimeter security, IDS/IPS deployment, DMZ architecture, firewall rule optimization, traffic analysis, and boundary monitoring | 16 |
| 12 | [`2x05_defensible_endpoint`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/2x05_defensible_endpoint) | Advanced endpoint hardening, application whitelisting, USB device control, sandboxing strategies, and endpoint isolation techniques | 12 |

#### Part 3 — Detection & Response Operations (Modules 13-18)

| # | Directory | Focus | Exercises |
|---|-----------|-------|-----------|
| 13 | [`3x00_evidence_pipeline`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x00_evidence_pipeline) | Digital forensics fundamentals, chain of custody procedures, evidence acquisition, memory/disk imaging, artifact analysis, and reporting for legal proceedings | 16 |
| 14 | [`3x01_reading_the_noise`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x01_reading_the_noise) | Behavioral baseline construction from enriched event data: format analysis, field indexing, query toolkit, event taxonomy, authentication/process/network/file baselines, temporal activity profiling, anomaly detection across auth/process/network sources, cross-source correlation, anomaly ranking, and self-contained baseline package assembly | 17 |
| 15 | [`3x02_the_alert_factory`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x02_the_alert_factory) | Detection engineering with Sigma rules: detection matrix mapping, rule authoring across signature/correlation types, Sigma rule execution, correlation primitives, false-positive baseline measurement, rule tuning, attack coverage mapping, rule quality scoring and prioritization, alert generation, and detection catalog assembly | 17 |
| 16 | [`3x03_triage_shift`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift) | SOC triage operations: alert queue assessment, triaging true positives, false positives, benign, and ambiguous auth/process/network alerts with IOC context joins, cross-alert correlation, priority conflict resolution, FP tuning, incident assembly, shift metrics, and bounded shift handoff report writing | 15 |
| 17 | [`3x04_cross_platform_detection`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x04_cross_platform_detection) | Multi-platform and multi-interface detection evaluation: CLI vs Wazuh dashboard/export comparison, Sigma-to-native XML rule translation, cross-tool query language analysis (jq, Sigma, KQL, Lucene), workflow and tradeoff comparison, tool evaluation packaging, field name translation tables, and vendor brief assembly for stakeholder review | 16 |
| 18 | [`3x05_the_24_hour_watch`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch) | SOC Tier 1 capstone simulation: 24-hour watch operations for MedDefense Health Systems detecting HC-RED7 cluster, including enriched event pipeline ingestion, behavioral baseline construction, Sigma-based detection engineering, multi-alert triage and correlation, deep-dive incident investigation (Incidents A, B, C), containment strategy, IOC packaging, detection tuning recommendations, and formal shift handoff documentation | 15 |

### Additional Resources

| Directory | Description |
|-----------|-------------|
| [`learning_objectives`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/learning_objectives) | Module-specific learning objectives and competency mapping |

## Working Through the Modules

Each module directory contains its own `README.md` with detailed exercise instructions. Work through modules sequentially: later modules consume the artifacts, findings, and decisions produced in earlier ones. The hardening work in Part 2 assumes the risk register, kill chains, and remediation priorities built in Part 1; the detection and response work in Part 3 runs against the hardened environments and telemetry exported at the end of Part 2.

The storyline is continuous. Module 1 establishes the security baseline: incident classification and asset criticality (`1x00`), threat intelligence and ATT&CK kill chains (`1x01`), vulnerability analysis and remediation prioritization (`1x02`), risk quantification and architecture design (`1x03`), applied cryptography (`1x04`), and executive reporting (`1x05`). Module 2 implements defense: Linux and Windows hardening (`2x00`, `2x01`), endpoint telemetry and detection proof (`2x02`), patch lifecycle automation (`2x03`), and perimeter defense (`2x04`), culminating in the `2x05` capstone that exports a structured handoff and telemetry package. Module 3 operates on what you built: evidence pipeline and schema design (`3x00`), behavioral baselining (`3x01`), Sigma detection engineering (`3x02`), alert triage and false-positive tuning (`3x03`), cross-platform SIEM querying (`3x04`), and the 24-hour watch capstone (`3x05`).

Key cross-module dependencies to be aware of:

| From | Consumed by | What carries forward |
| --- | --- | --- |
| `1x00` | `1x01`, `1x02` | Incident log, asset registry, criticality ratings, control gaps |
| `1x01` | `1x02`, `1x03`, `1x05` | Kill chains, MITRE ATT&CK mapping, threat actor profiles |
| `1x02` | `1x03` | Scan findings, CVE/CVSS analysis, remediation priorities |
| `1x03` | `1x05`, `2x04` | ALE calculations, security strategy, network segmentation design |
| `1x04` | `1x05` | Crypto priority list, encryption decisions |
| `2x00`–`2x04` | `2x05` | Hardened hosts, validation scripts, zone model, telemetry |
| `2x02`, `2x05` | `3x00` | Sysmon, auditd, and PowerShell telemetry exports |
| `3x00` | `3x01`–`3x05` | Enriched events, unified schema, asset inventory |
| `3x01` | `3x02`, `3x03` | Behavioral baselines, event taxonomy, anomaly markers |

Recurring characters (James Chen, SOC Lead; Sarah Park, IT Director; Robert Kim, CFO; Dr. Patricia Morales) and realistic artifacts (incident logs, scan reports, threat dossiers, Sigma rules, structured JSON evidence packages) create an immersive, hands-on learning environment where every exercise is a task assigned on the job.

Artifact files (`.txt`, `.pdf`) shipped with each module should be reviewed alongside their corresponding exercises, as several exercises require extracting evidence directly from them.

---

## Usage

Each module directory contains its own `README.md` with exercise instructions. Work through modules sequentially, as later exercises reference findings and decisions from earlier ones. Artifact files (`.txt`, `.pdf`) should be reviewed alongside their corresponding exercises.

### Getting Started

Begin with [`1x00_first_watch`](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/1x00_first_watch) — no prior modules are required.
