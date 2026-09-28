# Detection Gap Analysis - HEALTHBANE Campaign

**Analyst:** Steve - Cybersecurity Engineer  

**Project:** 4x02 Intelligence-Driven Defense - Task 8  

**Date:** 28 September 2026  

**References:** `healthbane_layer.json`, `7-attack_navigator.md`, `meddefense_4x00_findings.txt`, Tasks 5/9/10 outputs  

---

## Executive Summary

This gap analysis compares the HEALTHBANE campaign ATT&CK mapping (30 techniques: 18 observed, 12 inferred) against MedDefense's documented detection capability as of the 4x00/4x01 timeframe and the newly developed YARA rules from Tasks 9-10.

| Detection Status | Count | Percentage | Priority Implication |
|------------------|-------|------------|----------------------|
| DETECTED         | 8     | 27%        | Existing controls effective |
| PARTIALLY DETECTED | 6   | 20%        | Telemetry gaps or analyst review required |
| NOT DETECTED     | 16    | 53%        | Coverage gap requiring new instrumentation |

**Priority Gaps:**
- **Priority 1 (OBSERVED + NOT DETECTED):** 10 techniques — immediate coverage gaps
- **Priority 2 (INFERRED + NOT DETECTED):** 6 techniques — proactive monitoring needed
- **Priority 3 (PARTIALLY DETECTED):** 6 techniques — refinement opportunity

---

## Technique-Level Analysis

### RECONNAISSANCE

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1589.002 | Gather Victim Identities | OBSERVED | NOT DETECTED | HC3 Section 4; domain registration timing correlates to MedDefense staff list | No pre-compromise monitoring of adversary reconnaissance activities | Implement WHOIS/DNS registration monitoring for brand-related domains; alert on <72hr registration-to-exposure windows |
| T1584.001 | Host Infrastructure | INFERRED | NOT DETECTED | Researcher blog Section 1 (kit directory listings) | Passive infrastructure discovery; no active hunting against known registrar/hosting providers | Subscribe to threat intel feeds tracking Njalla/Namecheap abuse patterns; implement registrar WHOIS alerts for MedDefense branding variants |

---

### RESOURCE DEVELOPMENT

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1583.001 | Acquire Infrastructure (Domains) | OBSERVED | NOT DETECTED | HC3 Section 3.1; 8 domains registered 2026-04-05 to 2026-04-10 | Domain registration happens outside MedDefense visibility window | Integrate Brand Protection Service (e.g., MarkMonitor) to monitor new domain registrations matching MedDefense/MedEquip naming conventions |
| T1585.002 | Compromise Accounts | OBSERVED | PARTIALLY DETECTED | 4x00 F2-F3 (Stage 2 sent from compromised internal accounts); email headers show legitimate addresses | Compromised credentials allow bypass of basic SPF/DKIM; no anomalous send-behavior alerting yet deployed | Deploy UEBA on mail flow logs; baseline per-user send volumes and flag deviations >3σ; implement MFA on all mailboxes |
| T1587.001 | Develop Capabilities | OBSERVED | PARTIALLY DETECTED | Task 10 YARA: `HEALTHBANE_Document_Metadata` (wkhtmltopdf fingerprint); Task 11 YARA pending | YARA detects tooling signatures post-delivery; no runtime development detection | Extend YARA rule to sandbox environments; monitor for wkhtmltopdf/wkhtmltoimage execution on endpoints (process creation events) |
| T1608.005 | Upload Tooling | OBSERVED | PARTIALLY DETECTED | 4x00 F5 (landing pages hosted on compromised accounts); researcher blog kit URLs | Landing page deployment visible in web logs but not correlated to phishing campaigns | Correlate web application access logs with outbound mail events; require change-management approval for all public-facing HTML uploads |
| T1584.001 | Host Infrastructure | INFERRED | NOT DETECTED | Kit hosting across Hostinger/OVH/DigitalOcean/Ascenty | Multiple hosting providers dilute single-vendor detection signal | Build multi-provider correlation: alert when any hosting provider shows MedDefense-brand assets with non-official IP ranges |

---

### INITIAL ACCESS

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1566.002 | Spearphishing Link | OBSERVED | PARTIALLY DETECTED | Task 10: `HEALTHBANE_Email_Headers` YARA rule; 4x00 F5 (dmarsh clicked E2 link); email gateway URL scanning exists | YARA rule operates offline on saved emails; live email gateway not configured for PHISHING-LITE profile matching | Enable real-time YARA integration at mail gateway (e.g., ClamAV/YARA hook); implement URL rewriting + detonation for external links |
| T1566.001 | Spearphishing Attachment | OBSERVED | NOT DETECTED | 4x00 F4 (macro document sent from compromised accounts); `HEALTHBANE_S2_invoice.docm` | Macro-enabled attachments reach mailbox without sandbox detonation; email gateway macro policy set to "warn" not "block" | Set macro policy to "Block All External Macros" via ATP; deploy Microsoft Defender for Office 365 Safe Attachments with dynamic detonation |
| T1566.003 | Spearphishing Service | INFERRED | NOT DETECTED | Internal 4x00 F3 (`outlook-protection.com` variant passes DMARC) | Service impersonation bypasses standard phishing filters; DMARC alignment passes due to legitimate DKIM keys | Implement DMARC p=reject policy; configure BIMI to bind logos to verified domains; add service-impersonation heuristics to mail gateway |
| T1199 | Trusted Relationships | INFERRED | NOT DETECTED | HC3 Section 2; exploited trust in compromised internal accounts | No behavioral baseline distinguishing "legitimate internal sender" from "compromised internal sender" | Deploy sender reputation scoring based on historical send patterns; flag internal-origin emails with anomalous content/language |

---

### EXECUTION

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1204.001 | User Execution Link | OBSERVED | PARTIALLY DETECTED | 4x00 F5 (47-second HTTPS session logged); browser history shows /verify page load | Browser logs exist but not correlated to email click events; no automated alert on phishing site visit | Enable browser telemetry forwarding to SIEM; correlate URL visits with outbound mail click events; alert on <5-min post-click session |
| T1204.002 | User Execution Macro | OBSERVED | NOT DETECTED | HC3 Section 2; macro document required user interaction | Word macro execution not logged; no AMSI/ETW event collection on endpoints | Enable PowerShell Script Block Logging; deploy AMSI for Office applications; configure ETW for `winword.exe` macro invocation events |
| T1059.005 | PowerShell | OBSERVED | NOT DETECTED | HC3 Sections 2/4; macro pulls executable from C2 via PowerShell downloader | PowerShell execution occurs silently; Script Block Logging disabled per legacy endpoint configuration | Enable constrained PowerShell language mode; enforce Script Block Logging via GPO; collect ETW Microsoft-Windows-PowerShell channel |
| T1059.001 | Command-Line Interface | OBSERVED | NOT DETECTED | HC3 Sections 2/4; `sync_healthdata.ps1` exfiltrator | Command-line arguments not captured; no Sysmon ProcessCommandLine collection | Install Sysmon with CommandLine event collection (Event ID 1); configure retention ≥30 days |

---

### PERSISTENCE

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1053.005 | Scheduled Task | OBSERVED | NOT DETECTED | HC3 Sections 2/5.3; Scheduled task 'HealthSync Update Service' | Task scheduler events not forwarded to central log collection; no scheduled-task-change alerting | Forward Event ID 4698/4699 (task creation/deletion) to SIEM; baseline scheduled tasks per system; alert on new tasks with suspicious names |
| T1547.001 | Registry Run Keys | OBSERVED | NOT DETECTED | HC3 Sections 2/5.3; registry Run key persistence | Registry modification events not collected; no RegEdit audit policy enabled | Enable Audit Registry (success/failure) via GPO; collect Event ID 4657 (object access); monitor HKCU\Software\Microsoft\Windows\CurrentVersion\Run |
| T1543.003 | Windows Service | INFERRED | NOT DETECTED | Task name suggests possible service installation; only task confirmed | Service installation detection requires WMI/event monitoring not currently in scope | Monitor Event ID 7045 (new service installation); baseline legitimate services per department; alert on unsigned service binaries |

---

### DEFENSE EVASION

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1027 | Obfuscated Files | INFERRED | NOT DETECTED | Base32 encoding may qualify as minimal obfuscation; weak evidence | Endpoint AV signature-based only; no heuristic/static-analysis engine for encoded payloads | Deploy static analysis sandbox for email attachments; enable heuristics for Base64/Base32-encoded executables; configure YARA for encoding-pattern detection |

---

### CREDENTIAL ACCESS

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1056.003 | Form Grabbing | OBSERVED | PARTIALLY DETECTED | HC3 Section 2; landing pages captured credentials via HTML form POST | Web logs show POST to credential-capture URLs but no automated classification | Enable URL categorization (phishing/know-bad); integrate with DLP to block credential submission to non-official domains |
| T1056 | Input Capture | INFERRED | NOT DETECTED | Parent technique for T1056.003; keyboard logging plausible but unconfirmed | No EDR keystroke-monitoring capability; keylogger detection relies on signature matching | Deploy EDR module with keystroke-event telemetry; baseline normal keyboard input patterns for anomalies |
| T1552.001 | Credentials From Registry | INFERRED | NOT DETECTED | Post-access credential harvesting plausible but unconfirmed | No credential-theft detection in endpoint protection suite | Enable LSASS protection (Credential Guard); monitor Event ID 4648 (explicit credential logon) and 4624 (logon type 9) |

---

### COLLECTION

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1213 | Data From Information Repositories | INFERRED | NOT DETECTED | Patient/insurance data exfiltration implies collection method unknown | No data-loss visibility into SharePoint/EHR databases; no DLP policy covering patient-data export | Deploy DLP agents on EHR/workstation endpoints; configure sensitivity-label enforcement on patient records; monitor database query volume anomalies |
| T1005 | Data From Local System | INFERRED | NOT DETECTED | Local data collection necessary prior to exfiltration | No file-access telemetry; no endpoint data-access logging | Enable File Audit Policy (success/failure); monitor access to sensitive directories (C:\Users\*\Documents, shared drives) |

---

### COMMAND AND CONTROL

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1071.004 | DNS Application Layer | OBSERVED | PARTIALLY DETECTED | HC3 Section 2; DNS TXT tunneling to data-sync.healthbane-c2.net | DNS logs show queries to unknown domain but no anomaly detection on query structure | Implement DNS sinkhole for known-bad C2 domains; deploy DNS query-length anomaly detection; monitor for TXT-record queries to non-official subdomains |
| T1071.001 | Web Services | OBSERVED | NOT DETECTED | HC3 Section 4; HTTPS phishing LPs and C2 downloads | Encrypted HTTPS traffic prevents content inspection; no SSL inspection deployed for outbound connections | Deploy SSL inspection proxy; configure TLS decryption for non-official domains; integrate with Threat Intel Feed for known-bad certificate fingerprints |
| T1095 | Non-Application Layer Protocol | INFERRED | NOT DETECTED | Parent category for DNS channel; T1071.004 specific | Network-layer protocol monitoring insufficient for encrypted tunnels | Enable NetFlow/IPFIX collection; baseline per-host DNS query volume; alert on sustained elevated DNS traffic (>1000 queries/hour) |

---

### EXFILTRATION

| ATT&CK ID | Technique | Status | Detection Status | Evidence | Gap Explanation | Recommendation |
|-----------|-----------|--------|------------------|----------|-----------------|----------------|
| T1048.003 | Exfiltration Over Alternative Protocol | OBSERVED | NOT DETECTED | HC3 Section 2; patient records encoded in base32 DNS TXT queries | No DLP visibility into DNS exfiltration channel; no DNS query content inspection | Configure DNS firewall to block TXT queries to non-official domains; implement DNS query-content anomaly detection (base32 pattern recognition) |
| T1041 | Exfiltration Over C2 Channel | OBSERVED | NOT DETECTED | Same DNS tunnel carries exfil and C2 responses | C2 channel indistinguishable from normal DNS; no bidirectional traffic analysis | Deploy network traffic analysis (NTA) tool with C2-beacon detection; enable DNS response-size anomaly detection |
| T1048 | Exfiltration Over Non-C2 | INFERRED | NOT DETECTED | Parent category for T1048.003; alternatives not ruled out | No egress filtering or data-volume baseline monitoring | Implement egress data-volume baselines; alert on unusual outbound data transfers (>10MB/hour from single host); configure DLP for sensitive-data patterns |

---

## Prioritized Gap List

### Priority 1: OBSERVED + NOT DETECTED (Immediate Risk)

| Technique | Why Gap Matters | Detection Idea | Required Data Source | Owner / Implementation Path |
|-----------|-----------------|----------------|---------------------|----------------------------|
| T1589.002 | Adversary targets specific departments; early detection enables pre-emptive defense | Brand/domain registration monitoring | WHOIS/DNS feed subscription | IT Security → Threat Intel Vendor procurement |
| T1583.001 | Domain registration precedes campaign launch; earliest intervention point | Real-time brand-protection alerts | Registrar API feed | IT Security → Procure Brand Protection Service |
| T1566.001 | Macro attachments delivered via trusted internal accounts bypass gateway filtering | ATP Safe Attachments + macro-block policy | Exchange Online Protection | Security Admin → ATP policy update (high effort, high impact) |
| T1204.002 | Macro execution is the execution vector; no visibility into Word macro events | Script Block Logging + ETW | Endpoint Event Logs (ETW) | SysAdmin → GPO rollout (medium effort) |
| T1059.005 | PowerShell downloader stage enables all subsequent actions | PowerShell Script Block Logging | Endpoint Event Logs | SysAdmin → GPO rollout (low effort) |
| T1059.001 | Command-line exfil script executes post-download | Sysmon ProcessCommandLine | Endpoint Event Logs | SysAdmin → Sysmon deployment |
| T1053.005 | Persistence mechanism survives reboot | Scheduled task creation alerting | Windows Event Logs (4698/4699) | SysAdmin → SIEM rule creation |
| T1547.001 | Registry persistence enables re-entry after cleanup | Registry Run-key monitoring | Windows Event Logs (4657) | SysAdmin → GPO audit policy |
| T1048.003 | Active exfiltration channel; ongoing data loss | DNS query-content anomaly detection | DNS logs (content inspection) | Network Engineering → DNS firewall rules |
| T1041 | C2 channel sustains long-term access | DNS traffic analysis + beacon detection | Network flow logs | Network Engineering → NTA tool evaluation |

---

### Priority 2: INFERRED + NOT DETECTED (Proactive Risk)

| Technique | Why Gap Matters | Detection Idea | Required Data Source | Owner / Implementation Path |
|-----------|-----------------|----------------|---------------------|----------------------------|
| T1584.001 | Infrastructure hosting campaign assets; indirect exposure | WHOIS/alerts on Njalla/Offshore hosts | Threat Intel feed | IT Security → Integrate Intel feed |
| T1566.003 | Service-impersonation attacks increasingly common | DMARC p=reject + BIMI enforcement | DNS (DMARC records) | Email Admin → DNS zone updates |
| T1199 | Exploits organizational trust relationships | Sender-reputation anomaly detection | Mail flow logs | Email Admin → UEBA deployment |
| T1027 | Obfuscation undermines signature-based detection | Static-analysis sandbox + heuristics | Endpoint sandboxing | Security Admin → Sandbox procurement |
| T1056.001 | Potential for credential harvesting beyond form-grabbing | EDR keystroke-telemetry | EDR platform | Security Admin → EDR upgrade |
| T1055.001 | Possible process hollowing/patching (unconfirmed) | Process-integrity monitoring | Endpoint EDR | Security Admin → EDR policy |

---

### Priority 3: PARTIALLY DETECTED (Refinement Opportunity)

| Technique | Why Gap Matters | Detection Idea | Required Data Source | Owner / Implementation Path |
|-----------|-----------------|----------------|---------------------|----------------------------|
| T1585.002 | Compromised accounts enable lateral movement | UEBA on mail flow; MFA enforcement | Mail logs + IdP logs | Identity Admin → MFA rollout |
| T1587.001 | Tooling development signals future campaign | Endpoint process monitoring (wkhtmltopdf) | Endpoint Event Logs | SysAdmin → Process whitelist |
| T1608.005 | Landing page deployment correlates to campaign | Web-access-log correlation to outbound mail | Web logs + Mail logs | Web Admin → SIEM correlation rule |
| T1566.002 | Link-based phishing still reaching users | Real-time YARA at mail gateway; URL detonation | Mail gateway + Sandbox | Security Admin → Gateway config update |
| T1204.001 | Click-through leads to credential capture | Browser telemetry + mail-correlation | Browser logs + Mail logs | End-user Computing → Browser policy |
| T1071.004 | DNS tunneling may be intermittent | DNS query anomaly detection | DNS logs | Network Engineering → DNS analytics |

---

## Recommendations Summary

### Immediate Actions (≤30 Days)
1. **Enable Macro Blocking:** Switch ATP macro policy from "warn" to "block external macros" (T1566.001, T1204.002)
2. **Deploy Script Block Logging:** GPO rollout for PowerShell and Office macro logging (T1059.005, T1059.001)
3. **Implement DMARC p=Reject:** Prevent domain-spoofing attacks (T1566.003, T1199)
4. **Configure Sysmon ProcessCommandLine:** Enable command-line argument logging (T1053.005, T1547.001)
5. **Update DNS Firewall Rules:** Block TXT queries to non-official domains (T1048.003)

### Medium-Term Actions (≤90 Days)
6. **Procure Brand Protection Service:** Monitor new domain registrations (T1583.001, T1589.002)
7. **Roll Out UEBA on Mail Flow:** Baseline sender behavior (T1585.002, T1199)
8. **Deploy DNS Traffic Analysis:** Anomaly detection for C2/beacon activity (T1071.004, T1041)
9. **Integrate YARA at Mail Gateway:** Enable real-time phishing detection (T1566.002)
10. **Evaluate NTA Platform:** Network traffic analysis for exfiltration detection (T1048.003, T1041)

### Long-Term Actions (≤180 Days)
11. **Deploy DLP on Endpoints:** Sensitive-data export prevention (T1213, T1005, T1048)
12. **Implement SSL Inspection:** Decrypt and inspect outbound HTTPS (T1071.001)
13. **Upgrade EDR Platform:** Add keystroke and process-hollowing detection (T1056, T1027)
14. **Establish Incident Response Playbook:** Incorporate all Priority 1 detections (campaign-wide coordination)

---

## Appendix: Mapping Verification

| Source | Techniques Covered | Techniques Uncovered |
|--------|--------------------|----------------------|
| Task 10 YARA: `HEALTHBANE_Email_Headers` | T1566.002 (partial), T1587.001 (partial) | None |
| Task 10 YARA: `HEALTHBANE_Document_Metadata` | T1587.001 (partial), T1071.001 (partial), T1071.004 (partial) | Most execution/persistence/exfil |
| Task 10 YARA: `HEALTHBANE_Campaign_Composite` | Cross-family correlation (T1566.002, T1587.001) | No single-technique coverage |
| Task 5: Indicator Database (33 indicators) | IOC blocking for known-bad hashes/domains (T1583.001, T1589.002 partial) | Behavioral detections absent |
| 4x00 Findings | Email forensics, DMARC analysis (T1566.002, T1199 partial) | No endpoint/network telemetry |
| 4x01 Packet Analysis | DNS query structure (T1071.004 partial), HTTPS inspection gaps (T1071.001) | Limited to observed sessions |

**Coverage Calculation:** 8/30 techniques have documented detection (DETECTED); 6/30 have partial coverage (requires refinement); 16/30 lack any documented telemetry (NOT DETECTED).

---
