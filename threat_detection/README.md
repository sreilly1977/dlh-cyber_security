# Threat Detection

Cybersecurity threat detection and analysis study materials. Covers phishing dissection, network traffic analysis with Wireshark, behavioral baseline construction, and practical detection engineering through hands-on lab exercises.

## Case Study: MedDefense

The scenario modules are built around MedDefense, a healthcare organization facing realistic security challenges. Learners take on the role of a security analyst working through incremental security incidents and defense implementations.

Supporting characters (James Chen, SOC Lead; Marcus; Dr. Patricia Morales; Robert Kim, CFO; Diane Marsh) and realistic artifacts (email evidence batches, PCAPs, HC3 advisories, sandbox behavioral reports, Wazuh and Sysmon SIEM exports, memory images) create an immersive, hands-on learning environment where the whole directory is one extended investigation told from six angles.

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

## Working Through the Modules

Each module directory contains its own `README.md` with detailed exercise instructions. Work through modules sequentially: this is a single, continuous investigation into the HEALTHBANE campaign, and every module consumes the evidence, IOCs, and conclusions produced by the ones before it. The phishing forensics in `4x00` identifies the initial access email; the packet analysis in `4x01` follows the attacker across the network; `4x02` turns scattered indicators into a campaign attribution; `4x03` confirms the malware stages the intelligence could only infer; `4x04` hunts the lateral movement the malware enabled; and `4x05` reconstructs the entire operation end to end. Skipping ahead means investigating an incident you have not yet understood.

The storyline is continuous. Module `4x00` begins with an evidence batch of suspicious emails: header and authentication analysis (SPF/DKIM/DMARC), social engineering breakdowns, URL and attachment autopsy, and a campaign assessment across E2, E5, and E7, anchored by Diane Marsh's click on E2. Module `4x01` picks up the network side: six PCAPs covering VPN authentication, RDP, SMB enumeration, C2 beaconing, and DNS tunneling exfiltration, ending in a full kill chain reconstruction and network IOC extraction. Module `4x02` builds the intelligence picture: feed evaluation, OSINT enrichment of raw IOCs, an actor capability and intent assessment, a deduplicated indicator database classified by attack phase, and the initial three-stage HEALTHBANE kill chain. Module `4x03` confirms what the intelligence inferred: static and dynamic analysis of the macro dropper, the custom RAT masquerading as svchost (mutex `Global\HealthSync_MTX`, C2 at healthbane-c2.net), and the PowerShell DNS-exfiltration script, then updates the `4x02` kill chain with observed Stage 2 and Stage 3 behavior. Module `4x04` turns to proactive defense: five ATT&CK-aligned hunt hypotheses (PsExec, LSASS, WMI, PSRemoting, service accounts) executed against 14 days of Wazuh and Sysmon SIEM exports, filtered against Robert Kim's admin baseline, correlated into the Stage 4 lateral movement chain to the database server. Module `4x05` closes the case: memory and disk forensics from WS-RECV-03, firewall session data, and IR artifacts are fused with findings from every prior module to rebuild all four stages, identify what the `4x04` hunt missed, pinpoint the containment moment, and answer Dr. Morales's board-level question: was patient data compromised?

Key cross-module dependencies to be aware of:

| From | Consumed by | What carries forward |
| --- | --- | --- |
| `4x00` | `4x01`, `4x02`, `4x05` | Email headers, authentication results, campaign assessment, Diane Marsh's click as temporal anchor |
| `4x01` | `4x02`, `4x05` | Network IOCs, C2 beaconing pattern, exfiltration timeline, packet-vs-log visibility limits |
| `4x02` | `4x03`, `4x04` | HEALTHBANE kill chain (Stages 1–3), actor profile, indicator database |
| `4x03` | `4x04`, `4x05` | Confirmed malware behaviors, ATT&CK technique mapping, campaign behavioral signature |
| `4x04` | `4x05` | Hunt findings, lateral movement chain, credential dumping evidence, containment moment |
| `4x05` | — | Final integrated reconstruction and data exposure assessment |

Key focus areas include:

- **Email forensics**: SMTP header chain analysis, SPF/DKIM/DMARC interpretation, social engineering analysis, attachment metadata extraction, and URL defanging (`4x00`)
- **Campaign assessment**: distinguishing targeted spearphishing from spam, linking lookalike domains and role-specific lures into a coordinated campaign, and assigning triage priority with evidence (`4x00`)
- **Network traffic analysis**: PCAP filtering and protocol decoding with tshark, C2 beacon interval extraction, lateral movement tracking (RDP, SMB), and DNS tunnel detection (`4x01`)
- **Kill chain reconstruction**: assembling packet evidence into a coherent attack timeline, separating packet evidence from log evidence, and identifying intervention points (`4x01`)
- **Threat intelligence**: evaluating source reliability, aggregating and deduplicating IOC feeds, TLP handling, and structuring an indicator database by attack phase and confidence (`4x02`)
- **Actor attribution**: capability assessment, intent and targeting analysis, and predictive assessment of what will change versus what will persist, with explicit limits on what can and cannot be proven (`4x02`)
- **Malware analysis**: static analysis of PE headers, imports, and strings; deobfuscation of encoded commands; sandbox detonation and behavioral indicator extraction (`4x03`)
- **Detection rule evaluation**: measuring detection rate, false positive rate, and precision against labeled samples, with tuning recommendations and DEPLOY/TUNE/MONITOR decisions (`4x02`, `4x03`)
- **Threat hunting**: hypothesis-driven searches structured as testable IF/THEN predictions, executed against SIEM exports and filtered against known-good admin baselines (`4x04`)
- **Attack reconstruction**: integrating memory, disk, firewall, and IR evidence across all campaign stages, and delivering a defensible data exposure assessment for leadership (`4x05`)

Operational rules throughout:

- **Evidence discipline**: every conclusion must be supported by specific evidence from headers, packet captures, sandbox reports, or forensic artifacts. What is confirmed and what is inferred are stated separately, and nothing is presented as fact that the evidence does not show.
- **Do not overclaim**: attribution assessments state what can be inferred and what cannot be proven; timelines do not invent events the evidence does not support, and analytical inference is labeled as such.
- **Never investigate hostile artifacts directly**: do not navigate to suspicious URLs; use defanging, sandbox services, and command-line tools for all URL investigation. Do not open attachments on your workstation; use metadata extraction tools and online sandboxes only.
- **Detonate only in sandbox environments**: all malware execution happens in controlled sandboxes, and analysis clearly separates static evidence from inferred capability.
- **Show your commands**: every scripted analysis must show the tshark commands, filters, or queries used, so a reviewer can reproduce the finding.
- **Behavioral evidence over signatures**: beacon timing, sequencing, and baseline deviation are argued as behavioral findings, with explicit reasoning about why they constitute evidence rather than a signature match.
- **Test before deployment**: detection rules are validated against labeled true-positive, true-negative, and known-variant samples before any DEPLOY recommendation is issued.
- **Lab environment**: perform all analysis in your own isolated local lab environment. No SIEM platform, collector, or live monitoring stack is required.

Evidence discipline applies throughout: never navigate directly to suspicious URLs, never open attachments outside a sandbox, and document every conclusion with specific evidence from headers, packet captures, or forensic artifacts. The campaign narrative deliberately includes unresolved questions and analytical inference clearly separated from confirmed evidence, mirroring real investigations.

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
