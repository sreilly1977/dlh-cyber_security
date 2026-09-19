# Network Forensics Investigation Report

**Incident:** MedDefense Campaign 2026-04-14 (4x01 Wire-Shark Territory)
**Date Generated:** 2026-09-19 21:25:34 UTC
**Classification:** CONFIDENTIAL — Internal Investigation
**Prepared By:** Steve Reilly, Cybersecurity Engineer
**Related Analysis:** 4x00 Phishing Dissection (email-layer investigation, sibling repository)

---

## Executive Summary

On April 14, 2026, MedDefense staff received targeted credential-phishing emails from attacker-registered lookalike domains, and clinical staff member dmarsh clicked a harvesting link served from 91[.]234[.]99[.]107. Following the click, the victim workstation established periodic command-and-control beacons to that same address, and an external attacker initiated a VPN session using harvested credentials from Nigerian consumer LTE space (AS37340). The attacker moved laterally from the nursing workstation to the billing server over RDP, then exfiltrated approximately 6 KB of data through a covert DNS TXT tunnel to a dedicated attacker subdomain. Gateway micro-segmentation blocked the attacker from reaching the restricted 10.10.4.x clinical subnet, containing the intrusion before the highest-sensitivity systems were touched.

---

## Investigation Scope

### PCAPs Analyzed

| Capture File | Purpose | Time Window | SHA-256 |
|--------------|---------|-------------|---------|
| full_timeline.pcap | End-to-end campaign timeline, correlation anchor | 2026-04-14 08:00–18:00 UTC | 56cc866cf302ca1bad0e4885ea7f37f7d211d084553278f5d3a65bf330b77d22 |
| phishing_click.pcap | Victim click, TLS session to harvesting site (47.2s) | 2026-04-14 09:23–09:25 UTC | ecc9d24abc892883bda52919995e626e39829633d5601f9810fb710012f7cd61 |
| c2_beaconing.pcap | Command-and-control channel to 91.234.99.107 | 2026-04-14 10:15–16:30 UTC | d8c3d1b88a88e1d27d39f44127ae8024c53db6c9f6b6eb27951bfb7db6f33a95 |
| dns_exfil.pcap | DNS TXT tunnel to data-sync[.]meddefense-portal[.]com | 2026-04-14 14:45–15:10 UTC | 447cb45b498a03e77283e10ccbade38733df3d1210faef2d3995d04dd97faa32 |
| lateral_movement.pcap | Cross-subnet RDP/SMB flows | 2026-04-14 15:30–15:45 UTC | 7ae0cd46df2b82af6fa83db95560a78d3b582ef56cd56438bc5ff43545320586 |
| vpn_pivot.pcap | Inbound external VPN session | 2026-04-14 (window in vpn_pivot_evidence.json) | NOT ANALYZED AS SEPARATE CAPTURE |

Time period: April 14, 2026, covering initial click through exfiltration completion. Exact per-capture windows are documented in each task's JSON artifact.

### Tools Used

- **tshark** — packet filtering, protocol dissection, field extraction (Tasks 0–6)
- **python3** — embedded JSON parsing, statistical calculations (beacon intervals, entropy, rates)
- **jq** — ad-hoc artifact inspection
- **shellcheck** — static analysis of all bash scripts

### Evidence Sources Not Used

- Endpoint Detection and Response (EDR) logs — unavailable in lab environment; limits persistence and credential-use confirmation
- Active Directory authentication logs — no visibility into account activity during VPN pivot
- Email gateway logs — covered by the 4x00 investigation, not re-analyzed here
- Decrypted TLS payloads — keylog files unavailable; JA3 and certificate subject NOT CAPTURED

---

## Methodology

### 1. Baseline Establishment (Task 0)

Established clinical VLAN baseline:
- Normal DNS TXT query rate: 0.2336 queries/min
- Standard label length: 15–25 characters
- Baseline duration and external IP population recorded in baseline_clinical.json

### 2. Known-IOC Search (Task 1)

Searched PCAPs for indicators from the 4x00 email analysis:
- Lookalike domains matched in DNS queries
- Sending IPs observed in session metadata
- Per-victim harvesting URL confirmed via TLS SNI inspection (47.2s session)

### 3. DNS Analysis (Task 3)

Identified anomalies in DNS query patterns:
- 120 anomalous TXT queries to data-sync[.]meddefense-portal[.]com
- Left-most label lengths: 44–60 characters (baseline max: 25)
- Average entropy: 4.5 bits/char (baseline: 2.1)
- Query rate: 4.85/min vs baseline 0.2336/min (~20.8x multiplier)

### 4. TLS Metadata Analysis

Examined Server Name Indication (SNI) fields without decryption:
- Phishing click: SNI=meddefense-portal[.]com (harvest session)
- C2 beaconing: direct IP 91[.]234[.]99[.]107, no SNI observed
- VPN pivot: SNI=vpn[.]meddefense[.]com from external source 154[.]118[.]42[.]89

### 5. Timing Analysis (Task 2)

Computed beaconing intervals and regularity:
- Mean interval: 299.8 seconds (~5 minutes)
- Regularity coefficient of variation: 1.81% (highly periodic)
- Session count: 24 distinct beacons

### 6. Behavioral Analysis (Tasks 4–5)

Correlated cross-PCAP activities into kill-chain phases:
- Click -> C2 establish -> Lateral movement -> VPN pivot -> Exfiltration
- Timeline coherence verified via timestamp alignment across captures

### 7. Cross-PCAP Correlation

Linked discrete captures through shared identifiers:
- Victim IP (10.10.2.15) appears in phishing and lateral movement captures
- C2 IP (91[.]234[.]99[.]107) appears in phishing click AND beaconing captures
- Exfil subdomain appears in DNS capture and kill-chain evidence

---

## Findings by Attack Phase

### Phase 1: Initial Access — Phishing Click

**Narrative:** Clinical staff member dmarsh clicked a credential-harvesting link in a targeted phishing email. The workstation established a TLS session to the attacker's harvesting site and remained connected for 47.2 seconds, consistent with a form submission.

**Evidence:**
- phishing_click.pcap — TLS session to 91[.]234[.]99[.]107, SNI=meddefense-portal[.]com
- phishing_click_evidence.json — victim IP, phishing IP, session duration
- 4x00 — harvesting URL hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1

**MITRE ATT&CK:** T1566.002 (Phishing: Spearphishing Link), T1650 (Hardware Additions — N/A, listed for completeness of matrix review)

**Confidence:** CONFIRMED — direct packet capture of click and session. Credential *submission* itself is encrypted and unproven (Task 8 verdict: STRONG INFERENCE).

**What the packet evidence proves:** the click occurred, the session lasted 47.2s, and the same IP later served C2. It does not prove what was typed into the form.

---

### Phase 2: Command-and-Control

**Narrative:** The victim workstation initiated periodic HTTPS beacons to 91[.]234[.]99[.]107 at approximately five-minute intervals with near-perfect regularity.

**Evidence:**
- c2_beaconing.pcap — 24 sessions, 299.8s average interval, CV 1.81%
- c2_beacon_evidence.json — per-IP beacon statistics keyed by C2 address

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols), T1571 (Non-Standard Port — via direct-IP connection on 443 bypassing domain controls)

**Confidence:** CONFIRMED — quantifiable timing signatures in packet capture.

**What the packet evidence proves:** automated, scheduled communication to attacker infrastructure from the victim host. Payload content is encrypted.

---

### Phase 3: Lateral Movement

**Narrative:** The attacker pivoted from the clinical workstation (10.10.2.15) to the billing server (10.10.1.10) over RDP, exchanged approximately 265 KB, then originated SMB connections to four server-subnet peers. Attempts into the 10.10.4.x restricted subnet were blocked at the gateway.

**Evidence:**
- lateral_movement.pcap — RDP flow 10.10.2.15 -> 10.10.1.10:3389, 265723 bytes, clean FIN
- lateral_movement_evidence.json — connections list, blocked attempts
- Gateway TCP RSTs against 10.10.4.x targets

**MITRE ATT&CK:** T1021.001 (Remote Services: RDP), T1021.002 (Remote Services: SMB/Windows Admin Shares), T1046 (Network Service Discovery)

**Confidence:** CONFIRMED — direct capture of cross-subnet flows with byte counts.

**What the packet evidence proves:** interactive pivot from clinical to server subnet in violation of role topology. Which credentials authenticated the RDP session is not visible at the network layer.

---

### Phase 4: VPN Pivot

**Narrative:** An external session initiated a TLS connection to the VPN endpoint (SNI vpn[.]meddefense[.]com) from 154[.]118[.]42[.]89, Nigerian dynamic LTE space (AS37340 Spectranet).

**Evidence:**
- vpn_pivot_evidence.json — source IP, ASN, org, TLS SNI, geolocation
- Timing correlation with the credential-harvest window

**MITRE ATT&CK:** T1133 (External Remote Services), T1078 (Valid Accounts)

**Confidence:** STRONG INFERENCE — session origin and timing are confirmed; the credential used was harvested per the Task 8 correlation chain, but credential use itself is encrypted.

**What the packet evidence proves:** an anomalous foreign-origin VPN session occurred in the exploitation window. It does not capture the authentication exchange.

---

### Phase 5: Exfiltration

**Narrative:** Data was exfiltrated via DNS TXT queries to data-sync[.]meddefense-portal[.]com, with encoded subdomain labels 44–60 characters long at high entropy, sustained over approximately 25 minutes.

**Evidence:**
- dns_exfil.pcap — 120 anomalous TXT queries
- dns_tunnel_evidence.json — rate 4.85/min vs 0.2336/min baseline (~20.8x), entropy 4.5 bits/char, sample decodes
- Estimated volume: ~6 KB (50 bytes/query assumption)

**MITRE ATT&CK:** T1048.003 (Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol)

**Confidence:** CONFIRMED — direct capture of encoded DNS queries; sample decodes indicate patient/billing data patterns.

**What the packet evidence proves:** exfiltration channel, volume estimate, and rate. Exact record counts require full payload decode (NOT YET PERFORMED).

---

## Network-Level IOC Table

Combined indicators from 4x00 (email) + 4x01 (packets) = 39 total (27 + 12 + 2 enrichments). Full machine-readable package: campaign_iocs.json (Task 9).

### BLOCK (Campaign-Specific, Low Collateral Risk)

| Type | Value | Source | Confidence |
|------|-------|--------|------------|
| domain | meddefense-portal[.]com | 4x00+4x01 | HIGH |
| url | hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 | 4x00 | HIGH |
| ip | 91[.]234[.]99[.]107 | 4x00+4x01 | HIGH |
| email | noreply@meddefense-portal[.]com | 4x00 | HIGH |
| domain | outlook-protection[.]com | 4x00 | HIGH |
| url | hxxps://outlook-protection[.]com/verify | 4x00 | HIGH |
| ip | 51[.]38[.]42[.]17 | 4x00 | HIGH |
| email | security@outlook-protection[.]com | 4x00 | HIGH |
| domain | medequip-supplies[.]net | 4x00 | HIGH |
| url | hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 | 4x00 | HIGH |
| url | hxxps://medequip-supplies[.]net/portal/login | 4x00 | HIGH |
| ip | 185[.]176[.]43[.]22 | 4x00 | HIGH |
| email | invoices@medequip-supplies[.]net | 4x00 | HIGH |
| file_hash | 2f4a6c8e...e7b9d1f (SHA-256, MONITOR — in-object label, unverified) | 4x00 | MEDIUM |
| filename | INV-2026-04891[.]pdf | 4x00 | HIGH |
| domain | meddefense-benefits[.]org | 4x00 | HIGH |
| url | hxxps://meddefense-benefits[.]org/enroll | 4x00 | HIGH |
| ip | 164[.]90[.]218[.]73 | 4x00 | HIGH |
| email | hr-notifications@meddefense-benefits[.]org | 4x00 | HIGH |
| subdomain | data-sync[.]meddefense-portal[.]com | 4x01 | HIGH |

### DETECT (Alert + Review)

| Type | Value | Source | Confidence |
|------|-------|--------|------------|
| ip | 154[.]118[.]42[.]89 | 4x01 | HIGH (session) / MEDIUM (shared-infra risk) |
| tls_sni | vpn[.]meddefense[.]com (alert on EXTERNAL-source sessions only) | 4x01 | MEDIUM |
| dns_pattern | TXT queries, left-most labels 44-60 chars, entropy 4.5 bits/char | 4x01 | HIGH |

### HUNT (Threat-Hunting Queries)

| Type | Value | Source | Confidence |
|------|-------|--------|------------|
| beacon_signature | 24 sessions, 299.8s avg interval, CV 1.81% | 4x01 | HIGH |
| rate_signature | 4.85 TXT/min vs 0.2336/min baseline (~20.8x) | 4x01 | HIGH |
| flow_signature | RDP 10.10.2.15 -> 10.10.1.10:3389, 265723 B, clean FIN | 4x01 | HIGH |

### CONTEXT / MONITOR

| Type | Value | Source | Confidence |
|------|-------|--------|------------|
| asn | AS37340 (Spectranet-INET-LTE_DYN_ALLOC) | 4x01 | MEDIUM (shared carrier) |
| host_context | 10.10.1.10 (billing-srv-01) — exfil source, SMB origin | 4x01 | HIGH |
| account_context | dmarsh — token attribution, harvest-to-VPN correlation | 4x00+4x01 | HIGH (correlated; chain partly INFERENCE) |
| tool | wkhtmltopdf 0.12.6 | 4x00 | MEDIUM |
| infra_note | newly-registered domains (<30d), portal/benefits/supplies/login keywords | 4x00 | MEDIUM |

### WHITELIST / EXCLUDED

| Type | Value | Action |
|------|-------|--------|
| email | HC3@hhs[.]gov | DO NOT BLOCK — legitimate sector alert sender |
| victim_identity | internal-only (dmarsh) | EXCLUDED from external sharing |

---

## Impact Assessment

### Data Exfiltration

| Metric | Value | Confidence |
|--------|-------|------------|
| Anomalous DNS queries | 120 | CONFIRMED |
| Estimated volume | ~6 KB (50 bytes/query assumption) | ESTIMATE |
| Data types suggested | Patient records, billing metadata (per sample decodes) | STRONG INFERENCE |
| Exfiltration window | ~25 minutes | CONFIRMED |
| Rate vs baseline | ~20.8x | CONFIRMED |

### Systems Involved

| System | Address | Access Level | Confidence |
|--------|---------|--------------|------------|
| WS-NURSE-04 (workstation) | 10.10.2.15 | Initial click host, lateral pivot origin | CONFIRMED |
| billing-srv-01 | 10.10.1.10 | RDP target, exfil source, SMB origin to 4 peers | CONFIRMED |
| C2 server (external) | 91[.]234[.]99[.]107 | Command-and-control channel | CONFIRMED |
| DNS exfil resolver (external) | data-sync[.]meddefense-portal[.]com | DNS TXT tunnel endpoint | CONFIRMED |
| External VPN initiator | 154[.]118[.]42[.]89 | Authenticated VPN session (SNI vpn.meddefense.com) | CONFIRMED (session); credential use INFERRED |

### Systems Protected or Not Reached

| System | Address | Attempt | Response | Confidence |
|--------|---------|---------|----------|------------|
| Restricted clinical subnet | 10.10.4.x | Lateral movement via SMB | Blocked at gateway (TCP RST) | CONFIRMED |

### Credential Exposure

| Account | Status | Basis |
|---------|--------|-------|
| dmarsh | Strongly inferred (likely harvested) | Token ID correlation + harvest-session timing + VPN pivot timing; TLS prevents plaintext capture |

**Blast radius if valid:** clinical workstation access, EHR frontend, authenticated sessions without additional foothold.

### Regulatory and Business Concern

HIPAA Breach Notification Rule likely triggered: healthcare sector, PHI exposure likelihood HIGH (sample decodes show patient/billing patterns), exfil source confirmed as billing-srv-01. Escalation: Privacy Officer (1 business day), Legal Counsel (notification obligations), Forensics Lead (evidence preservation). Unconfirmed: exact patient count, credential submission, full lateral scope — all require endpoint/database logs beyond PCAP visibility.

---

## Detection Gap Analysis

### What Could Have Detected Earlier

| Activity | Detectable Signal | Earliest Possible Detection |
|----------|-------------------|------------------------------|
| C2 beaconing | Inter-arrival CV < 5% over 10+ sessions | Within first hour |
| DNS exfiltration | Label length >40 chars, entropy >3.5, rate >5x baseline | Within minutes |
| VPN pivot | Foreign dynamic-LTE ASN, impossible-travel timing | At authentication |
| Lateral movement | Clinical->server VLAN RDP role violation | At first flow |
| Phishing click | Domain age <30d, lookalike heuristics at gateway | At delivery |

### Gap 1: Behavioral Detection

No real-time alerting existed for any phase. The 20.8x DNS rate multiplier and 1.81% beacon CV were textbook anomaly signals; a host-relative baseline monitor would have fired within minutes.

### Gap 2: DNS Tunneling Detection

Resolver logs did not alert on label length, entropy, or TXT concentration. All three thresholds were exceeded for the entire 25-minute window without detection.

### Gap 3: VPN Anomaly Detection

The foreign dynamic-LTE source authenticated without geographic scoring or step-up authentication. Impossible-travel logic would have flagged a Nigeria-origin session against expected user geography.

### Gap 4: Lateral Movement Detection

Gateway segmentation enforced policy (RST) but generated no analyst-facing alert. Enforcement without monitoring allowed the successful RDP/SMB pivot to billing-srv-01 to proceed undetected even where controls worked.

---

## Detection Rules Recommended

| Rule | Data Source | Phase Detected | Condition | False Positive Considerations |
|------|-------------|-----------------|------------|-------------------------------|
| DNS_TXT_Exfil_Anomaly (DET-001) | Resolver logs (TXT) | Exfiltration | Rate >2x host baseline, OR label >40 chars, OR entropy >3.5 bits/char | Cloud health checks, zone transfers — whitelist known-good domains |
| C2_Beacon_Regularity (DET-002) | NetFlow/session logs | C2 | CV <5% over >=10 sessions to same destination | Backup jobs, update checks — whitelist scheduled destinations |
| RDP_CrossSubnet_RoleViolation (DET-003) | Firewall/flow logs | Lateral Movement | Clinical->server VLAN RDP, >100KB transferred | Maintenance windows — require ticket correlation |
| VPN_Foreign_Source_Alert (DET-004) | VPN gateway auth + GeoIP | Initial Access/Persistence | Source ASN = dynamic LTE/hosting, or non-employee-country origin | Authorized travel — pre-registration whitelist |
| Newly_Registered_Domain_Alert (DET-005) | Gateway DNS feed | Delivery | Domain age <30d with portal/benefits/supplies/login keywords | Legitimate new vendors — vendor onboarding verification |

---

## Recommendations

### Immediate (Next 24 Hours)

1. **Isolate Involved Systems**
   - WS-NURSE-04 (10.10.2.15) — initial click host, potential persistence
   - billing-srv-01 (10.10.1.10) — confirmed exfil source, SMB pivot point
   - All hosts in 10.10.1.x, 10.10.2.x — lateral movement domain
2. **Reset Involved Credentials**
   - dmarsh — immediate disable pending forensic clearance
   - Service accounts accessing billing-srv-01 — rotate secrets
   - Audit MFA device registrations for the account
3. **Block Attacker Infrastructure**
   - Domains and IPs per the BLOCK section above; full package in campaign_iocs.json (39 indicators)
4. **Preserve Evidence**
   - All PCAPs hashed and stored in immutable audit repository; retain minimum 7 years (HIPAA)

### Short-Term (Next 7 Days)

1. **Deploy Behavioral Detection Logic** — DET-001 through DET-005, integrated with alerting pipeline
2. **Review VPN Access** — geo-scoring at authentication gate, step-up MFA for foreign origins, block dynamic-LTE ASN abuse
3. **Review DNS Egress Visibility** — ensure resolver logs capture TXT metadata (label length, entropy)
4. **Search for Additional Affected Hosts** — hunt for other 4x00 recipients, beacon-like traffic to the C2 IP, DNS TXT anomalies on other hosts

### Medium-Term (Next 30 Days)

1. **Enforce Stronger Email Authentication Policy** — DMARC p=reject on organizational domains; the 4x00 attacker-set SPF/DKIM/DMARC pass should drive policy review
2. **Improve DNS Anomaly Detection** — resolver-level label/entropy alerting, per-host baselines, UEBA integration
3. **Implement Role-Based RDP Restrictions** — clinical VLAN RDP restricted to approved windows, JIT elevation, alert on all role-violating sessions
4. **Conduct Healthcare Data Exposure Review** — full tunnel payload decode for exact patient count, HIPAA notification determination with Privacy Officer and Legal Counsel

---

## Evidence Chain

| Filename | Purpose | Time Window | Storage Location | SHA-256 |
|----------|---------|-------------|------------------|---------|
| full_timeline.pcap | Complete campaign timeline | 2026-04-14 08:00–18:00 UTC | /data/evidence/forensic/pcap/ | 56cc866cf302ca1bad0e4885ea7f37f7d211d084553278f5d3a65bf330b77d22 |
| phishing_click.pcap | Victim click, harvesting session | 2026-04-14 09:23–09:25 UTC | /data/evidence/forensic/pcap/ | ecc9d24abc892883bda52919995e626e39829633d5601f9810fb710012f7cd61 |
| c2_beaconing.pcap | C2 channel | 2026-04-14 10:15–16:30 UTC | /data/evidence/forensic/pcap/ | d8c3d1b88a88e1d27d39f44127ae8024c53db6c9f6b6eb27951bfb7db6f33a95 |
| dns_exfil.pcap | DNS tunnel exfiltration | 2026-04-14 14:45–15:10 UTC | /data/evidence/forensic/pcap/ | 447cb45b498a03e77283e10ccbade38733df3d1210faef2d3995d04dd97faa32 |
| lateral_movement.pcap | Internal pivot traffic | 2026-04-14 15:30–15:45 UTC | /data/evidence/forensic/pcap/ | 7ae0cd46df2b82af6fa83db95560a78d3b582ef56cd56438bc5ff43545320586 |

**Handling Notes:**
- Hashes computed at report generation; if "NOT COMPUTED" appears, the PCAP was absent from the working directory — recompute with sha256sum before relying on this table for chain of custody
- Storage in write-protected directory, chain-of-custody log maintained separately
- Retention: minimum 7 years (HIPAA)
- Access: incident response team only, audit-logged

---

## Continuity with 4x00

| Finding | 4x00 Status | 4x01 Update |
|---------|-------------|-------------|
| Credential exposure | Likely (harvesting URL) | **Strongly Supported** — token + timing correlation with VPN pivot (Task 8: STRONG INFERENCE) |
| Attack timeline | Pre-click only | **Documented end-to-end** — click through exfiltration completion |
| Campaign infrastructure | 4 domains, 4 sending IPs | **Linked to post-click** — 91[.]234[.]99[.]107 confirmed dual-role (mail sender + C2 platform) |
| Impact scope | Credential theft only | **Expanded** — DNS exfiltration (~6 KB) adds HIPAA-relevant data loss |
| Behavioral signatures | None | **Added** — beacon CV, DNS rate multiplier, RDP flow signature survive infrastructure rotation |

**Key advancement:** email analysis produced 27 atomic IOCs that decay when infrastructure rotates; packet analysis added 12 behavioral IOCs (beacon interval, tunnel pattern, exfil rate, flow signature) that persist across infrastructure changes — the most durable hunting material. 2 existing 4x00 values were enriched with packet-layer confirmation.

---

Report generated by 11-network_forensics_report.sh
Evidence: /home/steve/projects/dlh/threat_detection/4x01_wire_shark_territory
Contact: security@meddefense.com

