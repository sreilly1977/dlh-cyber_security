# 3. The Gap-to-Framework Bridge
## Connecting Gaps, Vulnerabilities, Threats, and Framework Controls

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 3)  
**Reference:** 1x00 Gap Analysis (GAP-001 through GAP-008), 1x01 Threat Landscape, 1x02 Vulnerability Assessment

---

## High-Priority Gap Traceability Chains

### Gap 1: GAP-001 — Flat Network Architecture (No Segmentation)

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-001 (from 1x00 Task 4 Gap Analysis) |
| **Description** | Internal network uses single broadcast domain (10.10.0.0/16) with no VLAN segmentation between departments or device types |
| **Vulnerability Evidence** | Finding 003 (PostgreSQL Unrestricted Access), Finding 004 (BlueKeep/EternalBlue on MRI), Finding 010 (BD Alaris Default Credentials), Finding 007 (LDAP Signing Not Required) |
| **Threat Context** | Organized Crime / RaaS (Kill Chain #1 — Ransomware), Nation-State (Kill Chain #2 — EHR Exfiltration), Opportunistic (Kill Chain #3 — Medical Device) |
| **NIST CSF Function** | Protect (PR.IR — Technology Infrastructure Resilience) |
| **CIS Control** | CIS Control 12 (Network Infrastructure Management) — IG1 Safeguard 12.2, IG2 Safeguard 12.3 |
| **Recommended Action** | Deploy VLAN segmentation separating Clinical IoT, Medical Imaging, Administrative Computing, and Management networks with inter-VLAN firewall rules |

---

### Gap 2: GAP-003 — Zero Monitoring Capability (No SIEM/IDS)

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-003 (from 1x00 Task 4 Gap Analysis) |
| **Description** | No centralized logging, no SIEM, no IDS/IPS, no network anomaly detection; Marcus's notes confirm "zero monitoring capability" |
| **Vulnerability Evidence** | Finding 021 (Windows Event Log Forwarding Not Configured), billing-srv-01 cryptominer undetected for 14+ days (1x02 Task 4) |
| **Threat Context** | All threat actors benefit (Organized Crime, Nation-State, Insider) — no ability to detect Kill Chain #1, #2, #3, #4, or #5 |
| **NIST CSF Function** | Detect (DE.CM — Continuous Monitoring, DE.AE — Adverse Event Analysis) |
| **CIS Control** | CIS Control 8 (Audit Log Management) — IG1 Safeguards 8.1-8.3; CIS Control 13 (Network Monitoring) — IG2 Safeguards 13.1, 13.3 |
| **Recommended Action** | Deploy centralized syslog collector with Windows Event Log forwarding from all critical servers, configure Zeek network sensor on Medical Device VLAN |

---

### Gap 3: GAP-002 — No MFA Deployment

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-002 (from 1x00 Task 4 Gap Analysis) |
| **Description** | No multi-factor authentication deployed on O365, VPN, administrative access, or any externally-exposed applications |
| **Vulnerability Evidence** | Finding 009 (SSH Password Auth Enabled), Finding 007 (LDAP Signing Not Required), Finding 010 (BD Alaris Default Credentials admin/admin) |
| **Threat Context** | Opportunistic (Kill Chain #4 — Credential Theft), Organized Crime (Kill Chain #1 — Ransomware entry via stolen credentials) |
| **NIST CSF Function** | Protect (PR.AA — Identity Management, Authentication, and Access Control) |
| **CIS Control** | CIS Control 6 (Access Control Management) — IG1 Safeguards 6.3, 6.4, 6.5 |
| **Recommended Action** | Deploy MFA on all externally-exposed applications (O365, VPN), administrative access (SSH, RDP), and privileged accounts |

---

### Gap 4: GAP-006 — No Vulnerability Management Program

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-006 (from 1x00 Task 4 Gap Analysis) |
| **Description** | No recurring vulnerability scanning, no remediation SLA, no patch management process; assessment was one-time effort by SecurePoint |
| **Vulnerability Evidence** | Finding 001 (Apache mod_lua RCE unpatched for 1+ year), Finding 011 (Ubuntu 18.04 EOL without ESM), Finding 026 (Kernel CVEs on billing-srv-01) |
| **Threat Context** | Organized Crime (Kill Chain #1 — Ransomware), Nation-State (Kill Chain #2 — Data Exfiltration) exploiting known CVEs |
| **NIST CSF Function** | Identify (ID.RA — Risk Assessment), Protect (PR.PS — Platform Security) |
| **CIS Control** | CIS Control 7 (Continuous Vulnerability Management) — IG1 Safeguards 7.1, 7.2, 7.3, 7.4 |
| **Recommended Action** | Establish weekly vulnerability scan schedule for critical assets with documented remediation SLA (24 hours Critical, 7 days High, 30 days Medium) |

---

### Gap 5: GAP-004 — No Incident Response Plan

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-004 (from 1x00 Task 4 Gap Analysis) |
| **Description** | No documented incident response plan, no designated IR personnel, no breach notification process for HHS OCR |
| **Vulnerability Evidence** | Active billing-srv-01 compromise (1x02 Task 19) with no IR activation, no forensic preservation, no containment actions taken |
| **Threat Context** | Organized Crime (Kill Chain #1 — Ransomware) requiring coordinated response; HIPAA breach notification required within 60 days |
| **NIST CSF Function** | Respond (RS.MA — Incident Management, RS.CO — Incident Reporting) |
| **CIS Control** | CIS Control 17 (Incident Response Management) — IG1 Safeguards 17.1, 17.2, 17.3 |
| **Recommended Action** | Develop incident response plan with defined roles, escalation procedures, forensics procedures, and HHS OCR breach notification workflow |

---

### Gap 6: GAP-005 — EOL Systems Running Without Replacement

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-005 (from 1x00 Task 4 Gap Analysis) |
| **Description** | Three end-of-life systems operational: Windows XP MRI workstation, Server 2012 R2 Print Server, Ubuntu 18.04 Billing Server |
| **Vulnerability Evidence** | Finding 004 (BlueKeep/EternalBlue on Windows XP, unpatchable), Finding 011 (Ubuntu 18.04 EOL without ESM), Finding 008 (PrintNightmare on Server 2012 R2) |
| **Threat Context** | Organized Crime (Kill Chain #1 — Ransomware propagating via wormable vulnerabilities), Opportunistic (script kiddies using historical exploits) |
| **NIST CSF Function** | Identify (ID.RA — Risk Assessment), Protect (PR.PS — Platform Security) |
| **CIS Control** | CIS Control 7 (Continuous Vulnerability Management) — IG1 Safeguard 7.3 (OS patching); CIS Control 4 (Secure Configuration) — IG1 Safeguard 4.1 |
| **Recommended Action** | Complete OS migration for billing-srv-01 within 90 days, deploy compensating network isolation for MRI workstation and print server pending replacement |

---

### Gap 7: GAP-007 — Medical IoT on General Network

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-007 (from 1x00 Task 4 Gap Analysis) |
| **Description** | Seven BD Alaris infusion pumps and approximately 15 Philips patient monitors operate on flat network alongside general computing infrastructure |
| **Vulnerability Evidence** | Finding 010 (BD Alaris Default Credentials admin/admin), Finding 016 (Philips Monitors Unauthenticated Web Interface), WS-RAD-01 (MRI) accessible from any host |
| **Threat Context** | Nation-State (Kill Chain #3 — Medical Device Manipulation), Opportunistic (Kill Chain #3 — Device compromise for lateral movement), Insider Threat |
| **NIST CSF Function** | Protect (PR.IR — Technology Infrastructure Resilience), Identify (ID.AM — Asset Management) |
| **CIS Control** | CIS Control 12 (Network Infrastructure Management) — IG1 Safeguard 12.2, IG2 Safeguard 12.3; CIS Control 6 (Access Control) — IG1 Safeguard 6.5 |
| **Recommended Action** | Create dedicated Medical Device VLAN with strict ACLs restricting access to authorized clinical workstations only, disable unnecessary web interfaces |

---

### Gap 8: GAP-008 — No Security Awareness Training

| Attribute | Value |
|-----------|-------|
| **Gap Reference** | GAP-008 (from 1x00 Task 4 Gap Analysis) |
| **Description** | No structured security awareness training program; Acceptable Use Policy exists but no phishing training, incident reporting training, or data handling training |
| **Vulnerability Evidence** | No direct vulnerability evidence, but 1x01 Threat Landscape identifies social engineering as primary initial access method for Organized Crime and Insider Threat actors |
| **Threat Context** | Organized Crime (Kill Chain #1 — Ransomware via phishing email), Insider Threat (malicious or compromised credentials), Nation-State (targeted spearphishing) |
| **NIST CSF Function** | Protect (PR.AT — Awareness and Training) |
| **CIS Control** | CIS Control 14 (Security Awareness and Skills Training) — IG1 Safeguards 14.1-14.6 |
| **Recommended Action** | Launch security awareness training covering phishing recognition, authentication best practices, data handling, and incident reporting with quarterly phishing simulations |

---

## Traceability Summary Table

| Gap ID | Gap Description | Vulnerability Evidence | Threat Context | NIST CSF Function | CIS Control | Recommended Action |
|--------|-----------------|----------------------|----------------|-------------------|-------------|-------------------|
| **GAP-001** | Flat Network (No Segmentation) | Finding 003, 004, 007, 010 | Organized Crime (Ransomware), Nation-State (Exfil) | Protect (PR.IR) | CIS Control 12 | Deploy VLAN segmentation with inter-VLAN firewall rules |
| **GAP-003** | Zero Monitoring (No SIEM/IDS) | Finding 021, Undetected Cryptominer | All threat actors (Detection Failure) | Detect (DE.CM, DE.AE) | CIS Control 8, 13 | Deploy centralized logging with Zeek network sensor |
| **GAP-002** | No MFA Deployment | Finding 007, 009, 010 | Opportunistic (Credential Theft), Organized Crime | Protect (PR.AA) | CIS Control 6 | Deploy MFA on O365, VPN, administrative access |
| **GAP-006** | No Vulnerability Management | Finding 001, 011, 026 | Organized Crime (Exploit Known CVEs) | Identify (ID.RA), Protect (PR.PS) | CIS Control 7 | Weekly scans with 24-hour Critical remediation SLA |
| **GAP-004** | No Incident Response Plan | Active billing-srv-01 Compromise | Organized Crime (Ransomware) | Respond (RS.MA, RS.CO) | CIS Control 17 | Develop IR plan with roles, procedures, breach notification |
| **GAP-005** | EOL Systems Running | Finding 004, 008, 011 | Organized Crime (Wormable Propagation) | Identify (ID.RA), Protect (PR.PS) | CIS Control 7 | Complete OS migration for billing-srv-01; isolate others |
| **GAP-007** | Medical IoT on General Network | Finding 010, 016, WS-RAD-01 | Nation-State (Device Manipulation), Insider | Protect (PR.IR), Identify (ID.AM) | CIS Control 12, 6 | Create Medical Device VLAN with strict ACLs |
| **GAP-008** | No Security Awareness Training | None (Human Factor) | Organized Crime (Phishing), Insider | Protect (PR.AT) | CIS Control 14 | Launch security awareness training with phishing simulations |

---

## Strategic Implications

The traceability chain above demonstrates that MedDefense's eight highest-priority gaps are not isolated issues but interconnected vulnerabilities enabling multiple threat kill chains. Closing these gaps produces compounding security benefits:

1. **Network Segmentation (GAP-001)** reduces risk amplification by 6.6x to 12.0x across all other vulnerabilities, making it the single highest-leverage investment.

2. **Monitoring Capability (GAP-003)** transforms reactive breach response to proactive detection, reducing dwell time from 14+ days to hours and enabling timely incident response.

3. **MFA Deployment (GAP-002)** breaks the most common attack path for Organized Crime and Insider Threat actors, addressing the credential-based kill chains identified in 1x01.

4. **Vulnerability Management (GAP-006)** prevents known CVEs from becoming exploitation vectors, closing the gap between disclosure and patching that threat actors exploit.

5. **Incident Response (GAP-004)** ensures that when prevention fails, response minimizes impact and satisfies HIPAA regulatory requirements.

6. **EOL System Replacement (GAP-005)** eliminates permanent vulnerabilities that cannot be patched, removing the most persistent risk factor in the environment.

7. **Medical Device Isolation (GAP-007)** protects patient safety from direct manipulation and limits lateral movement from compromised clinical devices.

8. **Security Awareness (GAP-008)** addresses the human element that remains the weakest link regardless of technical controls.

Each gap maps to specific NIST CSF functions and CIS Controls, enabling the Board to understand the strategic rationale for each recommendation beyond "best practice" language. The framework alignment also provides the audit trail required for HIPAA compliance demonstrations and insurance underwriting requirements.

---

*Prepared by: Security Department*  
*References: 1x00 Gap Analysis (GAP-001 through GAP-008), 1x01 Threat Landscape (Kill Chains #1-#5), 1x02 Vulnerability Assessment (Findings 001, 003, 004, 007, 008, 010, 011, 016, 021, 026), NIST CSF 2.0, CIS Controls v8*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
