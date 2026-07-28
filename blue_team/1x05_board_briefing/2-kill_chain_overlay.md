# 2. The Kill Chain Overlay

## Goal

Overlay the Crimson Tide attack chain onto the kill chains built in 1x01, identifying where they converge and where MedDefense's planned controls would intercept.

## Context

Five kill chains were built for MedDefense in Project 1x01. Crimson Tide's attack chain is a real-world instance of those theoretical models. This overlay assesses how accurately the threat modeling predicted this attack, where the Crimson Tide chain matches the predicted kill chains, and where it diverges.

---

## Part 1 — The Overlay

### Kill Chain #1 (Ransomware) from 1x01 T10 vs. Crimson Tide 7-Phase Attack Chain

#### Phase 1: INITIAL ACCESS

| Dimension | Kill Chain #1 Prediction (1x01) | Crimson Tide Actual (CISA Advisory) |
|---|---|---|
| Vector | External attacker exploits unpatched VPN concentrator or phishing campaign targeting clinical staff | Exploitation of CVE-2023-27997 (FortiOS SSL-VPN heap-based buffer overflow) on FortiGate appliance |
| Predicted Accuracy | MATCH | The predicted vector (unpatched VPN concentrator) was precisely correct |
| Unanticipated Element | Did not predict the specific CVE or that the attacker would achieve full device takeover rather than credential theft alone | Crimson Tide gains root-level code execution on the FortiGate itself, turning the perimeter device into an attack platform rather than just an entry point |
| Attack Complexity | Predicted moderate complexity (social engineering or credential brute force) | Actually LOW complexity (single unauthenticated HTTP request, CVSS 9.8, AC:L) |
| Divergence Assessment | Prediction was directionally accurate but underestimated the speed and simplicity of exploitation. The model assumed phishing as a co-equal vector; Crimson Tide used only the VPN exploit, which was faster and more reliable |

#### Phase 2: INTERNAL RECONNAISSANCE

| Dimension | Kill Chain #1 Prediction (1x01) | Crimson Tide Actual (CISA Advisory) |
|---|---|---|
| Vector | Attacker performs network scanning (nmap), AD enumeration (BloodHound/SharpHound), and credential discovery via LSASS dumping | Attacker captures VPN credentials from FortiGate memory, dumps routing table to map internal subnets, uses captured credentials to authenticate to internal systems |
| Predicted Accuracy | PARTIAL MATCH | The model predicted network scanning and credential discovery, which aligns conceptually |
| Unanticipated Element | Did not predict that the compromised FortiGate itself would serve as the reconnaissance platform. The model assumed the attacker would pivot to a workstation first, then enumerate. Crimson Tide uses the FortiOS CLI directly, which is invisible to endpoint-based detection tools | 
| Divergence Assessment | The model predicted the WHAT (credential theft, subnet mapping) but not the HOW (FortiGate-native CLI reconnaissance, which bypasses all host-based controls). This is a significant gap because EDR and SIEM agents do not monitor FortiGate internal operations |

#### Phase 3: LATERAL MOVEMENT

| Dimension | Kill Chain #1 Prediction (1x01) | Crimson Tide Actual (CISA Advisory) |
|---|---|---|
| Vector | Attacker uses stolen credentials for RDP, SMB relay, and Pass-the-Hash to move between workstations and servers | Attacker uses RDP to Windows systems, SSH to Linux systems, WMI for remote command execution. Also exploits Kerberoasting (RC4 tickets cracked offline) and Mimikatz for cached credentials |
| Predicted Accuracy | STRONG MATCH | RDP and credential-based movement were correctly predicted |
| Unanticipated Element | Did not specifically predict Kerberoasting as a lateral movement technique, though the crypto assessment (1x04) did flag RC4 Kerberos as a weakness. Also did not predict that the flat network architecture would amplify lateral movement effectiveness this dramatically |
| Divergence Assessment | The model correctly predicted the techniques (RDP, stolen credentials). The Kerberoasting addition is a refinement, not a fundamental surprise. The critical unanticipated factor was the SPEED of movement on a flat network with no segmentation barriers between servers, workstations, and medical devices |

#### Phase 4: DATA EXFILTRATION

| Dimension | Kill Chain #1 Prediction (1x01) | Crimson Tide Actual (CISA Advisory) |
|---|---|---|
| Vector | Attacker exfiltrates patient databases via encrypted tunnel or cloud storage service. Predicted target: EHR database and patient PII | Attacker copies patient databases, financial/billing records, employee PII, insurance claim data. Exfiltration via Rclone to attacker-controlled cloud storage (mega.nz). Volume: 15-65 GB per incident |
| Predicted Accuracy | STRONG MATCH | Target data (EHR, billing, PII) and exfiltration method (cloud storage) were correctly predicted |
| Unanticipated Element | Did not predict that databases would be UNENCRYPTED AT REST, allowing the attacker to copy raw database files from the filesystem without database credentials. The model assumed the attacker would need SQL access or a database dump tool. Also did not predict Rclone as the specific exfiltration tool |
| Divergence Assessment | The model correctly predicted what would be stolen and roughly how. The critical surprise is the EASE of theft: unencrypted database files mean the attacker copies files directly from the filesystem, no database expertise required. This reduces the attack complexity below what the model anticipated |

#### Phase 5: BACKUP DESTRUCTION

| Dimension | Kill Chain #1 Prediction (1x01) | Crimson Tide Actual (CISA Advisory) |
|---|---|---|
| Vector | Attacker targets backup systems to prevent recovery. Predicted methods: deleting VSS snapshots, corrupting backup catalogs, targeting NAS devices | Attacker targets NAS/SAN devices on same network, deletes Volume Shadow Copies (vssadmin delete shadows), destroys backup software catalogs (Veeam, Commvault) |
| Predicted Accuracy | EXACT MATCH | All three predicted destruction methods were used by Crimson Tide |
| Unanticipated Element | Did not predict that backups would be UNENCRYPTED, allowing the attacker to verify backup contents before destroying them. Also did not predict that backup infrastructure would be on the SAME NETWORK as production systems with no isolation |
| Divergence Assessment | The model perfectly predicted the WHAT of backup destruction. The unanticipated element is the complete absence of backup isolation, which makes the destruction trivial rather than requiring lateral movement to a separate backup network |

#### Phase 6: RANSOMWARE DEPLOYMENT

| Dimension | Kill Chain #1 Prediction (1x01) | Crimson Tide Actual (CISA Advisory) |
|---|---|---|
| Vector | Attacker deploys ransomware via PsExec, GPO, or SCCM. Encryption target: all Windows systems. Predicted encryption algorithm: AES or ChaCha20 | Attacker deploys via GPO pushed from compromised Domain Controller. Payload: modified BlackSuit variant. Encryption: AES-256-CBC with RSA-2048 wrapped key. Targets: all Windows systems + Linux servers via SSH |
| Predicted Accuracy | STRONG MATCH | GPO deployment and AES encryption were correctly predicted |
| Unanticipated Element | Did not predict the specific ransomware family (BlackSuit/Conti lineage). Did not predict that Linux servers would be targeted SEPARATELY via SSH (model focused on Windows-centric deployment). Also did not predict that medical devices would intentionally NOT be encrypted but would become non-functional due to backend server unavailability |
| Divergence Assessment | The deployment method (GPO from DC) was exactly as predicted. The Linux SSH targeting is a refinement that the model missed. The cascading impact on medical devices through backend dependency (rather than direct encryption) is a nuanced attack impact the model did not capture |

#### Phase 7: EXTORTION

| Dimension | Kill Chain #1 Prediction (1x01) | Crimson Tide Actual (CISA Advisory) |
|---|---|---|
| Vector | Attacker demands ransom via ransom note on encrypted systems. Threatens to publish patient data if ransom not paid within deadline | Dual pressure: ransom for decryption key + threat to publish patient data on Tor leak site. Hospitals contacted via ransom note, direct email to CEO/CFO, and phone calls to hospital main line |
| Predicted Accuracy | MATCH | Double extortion (encryption + data publication threat) was correctly predicted |
| Unanticipated Element | Did not predict the phone calls to hospital main line as a pressure tactic. Did not predict that attacker would harvest CEO/CFO email addresses from email system or HR records during exfiltration phase for targeted extortion contact |
| Divergence Assessment | The model correctly predicted the core extortion mechanism. The direct executive targeting (email + phone) is an escalation tactic the model did not anticipate, but it represents a psychological warfare refinement rather than a fundamentally new attack vector |

### Overlay Summary

| Phase | Prediction Accuracy | Key Unanticipated Element |
|---|---|---|
| 1. Initial Access | MATCH | FortiGate device takeover (not just credential theft) |
| 2. Reconnaissance | PARTIAL MATCH | FortiGate CLI as recon platform (invisible to EDR) |
| 3. Lateral Movement | STRONG MATCH | Kerberoasting via RC4 tickets (speed amplified by flat network) |
| 4. Data Exfiltration | STRONG MATCH | Raw database file copying (no SQL access needed due to unencrypted at rest) |
| 5. Backup Destruction | EXACT MATCH | Backups unencrypted and on same network (trivial to verify and destroy) |
| 6. Ransomware Deployment | STRONG MATCH | Linux servers targeted separately via SSH (model was Windows-focused) |
| 7. Extortion | MATCH | Direct executive contact via phone and email (psychological escalation) |

**Overall Threat Model Accuracy: 5/7 phases strongly matched or exactly matched. 2/7 partially matched. 0/7 completely missed.**

The kill chain model from 1x01 correctly predicted the overall attack progression, techniques, and objectives. The gaps are in tactical details (specific tools, Linux targeting, executive phone calls) and in underestimating how architectural weaknesses (flat network, unencrypted databases) would dramatically lower the skill barrier for each phase.

---

## Part 2 — Control Interception Map

From the Security Strategy (1x03), the following planned controls are mapped against each Crimson Tide phase. Status reflects whether the control is funded and deployed, funded but not yet deployed, or not funded.

| Phase | Planned Control (from 1x03) | Status | Would It Stop This Phase? |
|---|---|---|---|
| **1. Initial Access** | FortiGate firmware patching and vulnerability management program (STRAT-CTRL-01: Network Infrastructure Patch Management) | Not Deployed (process designed, not implemented; support contract expired) | **YES** — Patching FortiOS to 7.2.5+ would eliminate CVE-2023-27997 exploitation path entirely. This is the single most effective control in the entire strategy |
| **1. Initial Access** | VPN MFA enforcement (STRAT-CTRL-02: Multi-Factor Authentication for Remote Access) | Not Deployed (licensed, pilot not started) | **PARTIALLY** — MFA would not prevent the buffer overflow exploit itself, but would prevent use of captured VPN credentials in subsequent phases. Attacker gains device control but cannot easily pivot using stolen credentials if MFA challenges are required |
| **1. Initial Access** | Network segmentation (STRAT-CTRL-03: VLAN Segmentation between server, workstation, medical device, and management zones) | Not Deployed (designed in 1x03, implementation not started) | **NO** — Segmentation does not block initial access. It would, however, limit the blast radius after compromise (see Phase 3) |
| **2. Internal Reconnaissance** | SIEM with FortiGate log ingestion (STRAT-CTRL-04: Centralized Logging and SIEM) | Funded, Partially Deployed (SIEM collector running, FortiGate logs not ingested) | **PARTIALLY** — If FortiGate logs were ingested and correlated, unusual CLI commands and routing table dumps would trigger alerts. Currently, FortiGate activity is NOT monitored by the SIEM, so reconnaissance from the device itself is invisible |
| **2. Internal Reconnaissance** | EDR on all endpoints (STRAT-CTRL-05: Endpoint Detection and Response) | Not Deployed (budget approved, vendor selection pending) | **NO** — EDR monitors endpoints, not network devices. FortiGate CLI reconnaissance would not be detected by EDR. However, EDR would detect Mimikatz and BloodHound on workstations during later reconnaissance |
| **3. Lateral Movement** | Network segmentation (STRAT-CTRL-03) | Not Deployed | **YES** — Proper VLAN segmentation would prevent an attacker on a compromised FortiGate from reaching database servers, backup NAS, and Domain Controllers directly. Each zone would require separate compromise, slowing the attacker and triggering alerts |
| **3. Lateral Movement** | Disable RC4 in Active Directory Kerberos (STRAT-CTRL-06: Kerberos Hardening) | Not Deployed (identified in 1x04 as CRYPTO-004, remediation planned but not executed) | **YES** — Disabling RC4 would eliminate Kerberoasting as a lateral movement technique. Attackers would need to find alternative credential theft methods, increasing dwell time and detection likelihood |
| **3. Lateral Movement** | Service account privilege review (STRAT-CTRL-07: Least Privilege Enforcement for Service Accounts) | Not Deployed (assessment complete, remediation not started) | **PARTIALLY** — Reducing service account privileges would limit the scope of lateral movement. An attacker with a low-privilege service account cannot RDP to Domain Controllers or access database servers. However, if domain admin credentials are captured via Mimikatz, least privilege alone would not block movement |
| **3. Lateral Movement** | EDR on all endpoints (STRAT-CTRL-05) | Not Deployed | **PARTIALLY** — EDR would detect Mimikatz execution, suspicious RDP sessions, and WMI abuse. Would generate alerts but may not BLOCK the activity without active response policies configured |
| **4. Data Exfiltration** | Database encryption at rest — PostgreSQL TDE (CRYPTO-001 remediation) | Not Deployed (Action #1 in Implementation Playbook, scheduled for this weekend) | **YES** — If PostgreSQL TDE were active, the attacker could not copy raw database files from the filesystem. They would need database credentials to read decrypted data, adding a significant barrier. This single control would disrupt the exfiltration phase |
| **4. Data Exfiltration** | Database encryption at rest — MySQL TDE (CRYPTO-003 remediation) | Not Deployed (Action #2 in Implementation Playbook, scheduled for this weekend) | **YES** — Same rationale as above. Billing database files would be unreadable without database-level access |
| **4. Data Exfiltration** | Database TLS enforcement (CRYPTO-005 remediation) | Not Deployed (Action #3 in Implementation Playbook) | **NO** — TLS protects data in transit between application and database, but does not protect data files on disk. Exfiltration via filesystem copy would not be affected by TLS enforcement |
| **4. Data Exfiltration** | EDR with network traffic analysis (STRAT-CTRL-05) | Not Deployed | **PARTIALLY** — Advanced EDR with network monitoring could detect large outbound transfers to cloud storage services (Rclone to mega.nz). Would generate alerts, but may not automatically block the transfer |
| **4. Data Exfiltration** | DLP (Data Loss Prevention) for outbound traffic (STRAT-CTRL-08: DLP Gateway) | Not Funded | **YES** — A properly configured DLP gateway would detect and block large outbound transfers of structured data (database files, CSV exports). This is a control gap that the strategy identified but was not budgeted |
| **5. Backup Destruction** | Backup network isolation (STRAT-CTRL-09: Air-Gapped or Network-Isolated Backups) | Not Deployed (identified as GAP-008 in 1x00, design complete, implementation not started) | **YES** — If NAS-01 were on a separate VLAN or physically disconnected from the production network, the attacker could not reach it from compromised database servers. This would preserve backup integrity and enable recovery without paying ransom |
| **5. Backup Destruction** | Backup encryption (CRYPTO-002 remediation) | Not Deployed (scheduled in Implementation Playbook) | **PARTIALLY** — Encrypted backups prevent the attacker from verifying backup contents before destruction. However, encrypted backups can still be deleted if the attacker has filesystem access. Encryption protects confidentiality of backed-up data but not availability of the backups themselves |
| **5. Backup Destruction** | Immutable backup storage (STRAT-CTRL-10: WORM Backup Architecture) | Not Funded | **YES** — Write-Once-Read-Many storage physically prevents deletion of backup data, even by an attacker with full administrative access. This is the only control that guarantees backup survivability against ransomware-induced destruction |
| **6. Ransomware Deployment** | EDR with behavioral detection (STRAT-CTRL-05) | Not Deployed | **PARTIALLY** — Modern EDR can detect ransomware behavior patterns (mass file encryption, shadow copy deletion) and automatically isolate affected hosts. Would reduce the scope of encryption but may not prevent initial deployment entirely if the payload uses novel techniques |
| **6. Ransomware Deployment** | Application whitelisting / AppLocker (STRAT-CTRL-11: Application Whitelisting on Servers) | Not Funded | **YES** — If only approved executables can run on Windows servers, the ransomware payload (an untrusted binary) would be blocked from executing. This is a strong preventive control but is operationally challenging in healthcare environments with diverse clinical applications |
| **6. Ransomware Deployment** | GPO change monitoring (STRAT-CTRL-12: Active Directory Change Monitoring) | Not Deployed (partially covered by SIEM, alerting rules not configured) | **PARTIALLY** — Would alert on new GPO creation outside change windows, allowing rapid response before ransomware deploys. But alerting alone does not prevent deployment if response is slow |
| **6. Ransomware Deployment** | Network segmentation (STRAT-CTRL-03) | Not Deployed | **PARTIALLY** — Segmentation would limit ransomware spread to the compromised zone. If the Domain Controller is in a management zone separated from clinical workstations, GPO-pushed ransomware may not reach all endpoints |
| **7. Extortion** | Executive email protection (STRAT-CTRL-13: Executive Email Security Enhancement) | Not Funded | **NO** — Does not prevent extortion if data has already been exfiltrated. However, would reduce the attacker's ability to harvest executive contact information from email systems during Phase 4 |
| **7. Extortion** | Incident response retainer (STRAT-CTRL-14: IR Retainer Contract) | Not Funded | **NO** — Does not prevent extortion. Would improve response quality and speed, potentially reducing ransom negotiations and recovery time |
| **7. Extortion** | Cyber insurance (STRAT-CTRL-15: Cyber Liability Insurance) | Funded, Active | **NO** — Does not prevent extortion. Would cover ransom payment, forensic costs, legal fees, and breach notification expenses if extortion occurs. Reduces financial impact but does not block the attack phase |

---

## Part 3 — The Gap Between Plan and Reality

If MedDefense had fully implemented the Security Strategy from 1x03, 4 of the 7 Crimson Tide phases would have been blocked outright: Phase 1 (Initial Access) would be blocked by FortiGate firmware patching (STRAT-CTRL-01), eliminating the entry point entirely. Phase 3 (Lateral Movement) would be severely impeded by network segmentation (STRAT-CTRL-03) and Kerberos hardening (STRAT-CTRL-06), forcing the attacker to compromise each zone separately and eliminating Kerberoasting. Phase 4 (Data Exfiltration) would be blocked by database TDE (CRYPTO-001, CRYPTO-003) because raw database files would be unreadable without database credentials, and partially mitigated by DLP (STRAT-CTRL-08) detecting large outbound transfers. Phase 5 (Backup Destruction) would be blocked by backup network isolation (STRAT-CTRL-09) and immutable storage (STRAT-CTRL-10), preserving recovery options. However, 3 of the 7 phases would still likely succeed: Phase 2 (Internal Reconnaissance) would partially succeed because FortiGate CLI reconnaissance is invisible to endpoint controls even with full SIEM ingestion, as the FortiGate operates outside the EDR visibility envelope. Phase 6 (Ransomware Deployment) would still succeed on at least the compromised zone, because EDR detects but may not fully prevent novel ransomware execution, and GPO-based deployment from a compromised Domain Controller remains viable if the DC is in the same zone as endpoints. Phase 7 (Extortion) is unblockable once data has been exfiltrated, because the attacker retains possession of stolen data regardless of subsequent defensive actions. The critical insight is this: even with FULL strategy implementation, MedDefense would retain a residual risk of 3/7 phases succeeding (43% phase success rate), which means the strategy is necessary but not sufficient. The gap between plan and reality is not in what was planned, but in what was not yet deployed. The strategy correctly identified the controls needed to block 4 of 7 phases, but the 3 remaining phases reveal architectural blind spots that no amount of tooling fully addresses: network device introspection (FortiGate CLI activity cannot be monitored by endpoint agents), zone-contained ransomware propagation (segmentation limits but does not eliminate spread), and the irreversibility of data theft (once exfiltrated, data cannot be un-stolen). This tells us that the Security Strategy must be supplemented with network-level telemetry (NetFlow analysis, network traffic analysis on the FortiGate itself), aggressive zone-based ransomware containment playbooks (auto-isolation of compromised zones), and a proactive data minimization posture (reduce the volume of data that COULD be exfiltrated by archiving or purging old PHI that is no longer clinically needed). The residual risk after full implementation is not a failure of planning, it is the inherent residual risk of operating a healthcare network that must, by clinical necessity, allow broad access to patient data across interconnected systems.

---

## Appendix — Kill Chain Convergence Matrix

| Crimson Tide Phase | Kill Chain #1 (Ransomware) | Kill Chain #2 (Insider Data Theft) | Kill Chain #3 (Supply Chain Compromise) | Kill Chain #4 (Medical Device Tampering) | Kill Chain #5 (Credential Stuffing) |
|---|---|---|---|---|---|
| 1. Initial Access | CONVERGES (VPN exploit predicted) | DIVERGES (insider already inside) | DIVERGES (supply chain, not perimeter) | DIVERGES (medical device vector) | PARTIAL CONVERGE (credential-based, not exploit-based) |
| 2. Reconnaissance | PARTIAL CONVERGE (CLI vs workstation) | DIVERGES (insider has legitimate access) | DIVERGES (vendor access differs) | DIVERGES (device-specific recon) | DIVERGES (automated, not interactive) |
| 3. Lateral Movement | CONVERGES (RDP, credential theft) | DIVERGES (insider does not need lateral movement) | PARTIAL CONVERGE (vendor credentials used similarly) | DIVERGES (device network pivot) | DIVERGES (lateral movement not typical) |
| 4. Data Exfiltration | CONVERGES (database copying, cloud storage) | CONVERGES (same data targets, same exfil method) | PARTIAL CONVERGE (vendor access to same data) | DIVERGES (device data, not central database) | PARTIAL CONVERGE (API-based exfil possible) |
| 5. Backup Destruction | CONVERGES (same techniques observed) | DIVERGES (insider typically does not destroy backups) | DIVERGES (supply chain actor focuses on persistence, not destruction) | DIVERGES (not applicable) | DIVERGES (not applicable) |
| 6. Ransomware Deployment | CONVERGES (GPO-based deployment predicted) | DIVERGES (insider theft does not deploy ransomware) | DIVERGES (supply chain focuses on persistence and espionage) | DIVERGES (medical devices not targeted by ransomware) | DIVERGES (credential stuffing does not lead to ransomware in this model) |
| 7. Extortion | CONVERGES (double extortion predicted) | DIVERGES (insider theft may involve extortion but typically sale-based) | DIVERGES (supply chain compromises are typically espionage, not extortion) | DIVERGES (device tampering is sabotage, not extortion) | DIVERGES (credential stuffing leads to account takeover, not extortion) |

**Convergence Summary:**
- Kill Chain #1 (Ransomware): 6/7 phases converge with Crimson Tide — strongest predictive model
- Kill Chain #2 (Insider Data Theft): 2/7 phases converge — data targets overlap, methods diverge
- Kill Chain #3 (Supply Chain): 3/7 phases partially converge — credential use overlaps, objectives differ
- Kill Chain #4 (Medical Device Tampering): 0/7 phases converge — completely different attack paradigm
- Kill Chain #5 (Credential Stuffing): 1/7 phase partially converges — entry method differs, no downstream overlap

The threat modeling in 1x01 Kill Chain #1 was the most accurate predictor of the Crimson Tide campaign. This validates the risk-based prioritization approach: the highest-risk kill chain identified in the assessment IS the one materializing in the real world. The investment in analyzing Kill Chain #1 in detail (techniques, tools, mitigations) provides direct actionable intelligence for the current crisis.

---

## Final Assessment

**Threat Model Accuracy Score: 71% Strong Match or Better (5/7 phases)**

The kill chain modeling exercise in 1x01 was directionally correct and operationally useful. The Crimson Tide attack chain validates the predictive methodology used. The two partial matches (Phases 2 and 3) reveal gaps not in the attack progression model but in the environmental awareness of how architectural weaknesses (flat network, unencrypted databases, FortiGate as single point of failure) would amplify each phase's effectiveness.

The most important lesson: threat modeling correctly predicted WHAT the attacker would do, but underestimated how EASY it would be due to environmental factors. Future threat modeling exercises should include an "attack friction assessment" that evaluates how much resistance the current environment provides against each predicted technique, not just whether the technique is possible.

-- Steve, Security Engineer
July 28, 2026, 09:00 EST
