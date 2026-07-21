# 10. The Risk Register

## Goal

Build the formal Risk Register that will serve as the operational backbone of MedDefense's security program.

## Context

Every deliverable produced so far, the gap analysis, the threat landscape, the vulnerability assessment, the ALE calculations, feeds into one master document: the Risk Register. This is not a summary. It is the living governance instrument that tracks every identified risk through its lifecycle: identification, scoring, treatment, monitoring and review.

---

## MedDefense Health Systems Risk Register, Top 10 Risks

---

### RISK-001

| Field | Description |
|---|---|
| **Risk ID** | RISK-001 |
| **Risk Description** | Ransomware encrypts EHR system causing clinical operations shutdown |
| **Risk Category** | Operational |
| **Threat Source** | Cybercriminal Group (financially motivated) |
| **Vulnerability** | VULN-001: Unpatched Windows servers with known SMB exploits |
| **Affected Asset(s)** | EHR System, Patient Records Database |
| **Likelihood** | 4 — Multiple active ransomware campaigns targeting healthcare in current threat landscape |
| **Impact** | 5 — Complete loss of clinical operations, patient safety risk, regulatory reporting mandatory |
| **Inherent Risk Score** | 20 (Critical) |
| **ALE** | $2,100,000/year |
| **Risk Owner** | CISO |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Clinical continuity is non-negotiable and ransom payment does not guarantee data recovery. |
| **Planned Control(s)** | Endpoint Detection and Response (EDR), offline immutable backups tested quarterly, network segmentation isolating EHR, mandatory MFA on all EHR access paths, patch management SLA of 7 days for critical CVEs |
| **Residual Risk** | Low (3) — Residual likelihood reduced to 1, impact remains 3 due to irreparable clinical disruption potential |
| **KRI** | Number of critical patches unapplied beyond 7-day SLA; failed backup restoration tests |
| **Review Date** | Monthly |

---

### RISK-002

| Field | Description |
|---|---|
| **Risk ID** | RISK-002 |
| **Risk Description** | Third-party vendor breach provides lateral access to MedDefense core systems |
| **Risk Category** | Operational |
| **Threat Source** | Supply Chain Attacker |
| **Vulnerability** | GAP-003: Flat network architecture with insufficient segmentation between vendor access zones and internal systems |
| **Affected Asset(s)** | Billing System, EHR, Medical Devices (MRI) |
| **Likelihood** | 3 — Healthcare supply chain attacks increasing but still require specific vendor targeting |
| **Impact** | 5 — Vendor access to multiple critical systems creates cascading failure across clinical and financial operations |
| **Inherent Risk Score** | 15 (High) |
| **ALE** | $1,800,000/year |
| **Risk Owner** | CIO |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Vendor compromises are escalating in the healthcare sector and flat network architecture amplifies blast radius. |
| **Planned Control(s)** | Network segmentation into access zones, vendor access reviews quarterly, API gateway with rate limiting and anomaly detection, vendor security questionnaire renewal annually, jump box architecture for all vendor remote sessions |
| **Residual Risk** | Medium (6) — Likelihood reduced to 2, impact reduced to 3 through segmentation containing blast radius |
| **KRI** | Number of vendor accounts with privileged access; unauthorized lateral movement attempts detected by network monitoring |
| **Review Date** | Monthly |

---

### RISK-003

| Field | Description |
|---|---|
| **Risk ID** | RISK-003 |
| **Risk Description** | Insider threat exfiltrates PHI for identity theft or sale on dark web markets |
| **Risk Category** | Operational / Compliance |
| **Threat Source** | Disgruntled Employee / External Collusion |
| **Vulnerability** | VULN-008: Lack of user behavior analytics and data loss prevention controls |
| **Affected Asset(s)** | Patient Records Database, Email System |
| **Likelihood** | 3 — Healthcare insider incidents represent approximately 18% of all breaches in sector data |
| **Impact** | 4 — Large-scale PHI exposure triggering HIPAA breach notification, patient trust erosion, potential class action |
| **Inherent Risk Score** | 12 (High) |
| **ALE** | $950,000/year |
| **Risk Owner** | HR Director (jointly with CISO) |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Insider incidents in healthcare average 24 months to detect, early detection dramatically reduces exposure scope. |
| **Planned Control(s)** | Data Loss Prevention (DLP) deployment across email and endpoints, User and Entity Behavior Analytics (UEBA), privileged access management with session recording, mandatory security awareness training with insider threat module |
| **Residual Risk** | Medium (6) — Likelihood reduced to 2, impact remains 3 as exfiltration risk cannot be fully eliminated |
| **KRI** | Anomalous data access patterns flagged by UEBA; large file transfers outside business hours |
| **Review Date** | Monthly |

---

### RISK-004

| Field | Description |
|---|---|
| **Risk ID** | RISK-004 |
| **Risk Description** | Credential compromise via phishing leads to administrative account takeover |
| **Risk Category** | Operational |
| **Threat Source** | Social Engineering Attacker |
| **Vulnerability** | VULN-003: No MFA on email or administrative portals |
| **Affected Asset(s)** | Admin Workstations, Email Gateway, Active Directory |
| **Likelihood** | 5 — Phishing remains the primary initial access vector with highest success rate in healthcare |
| **Impact** | 4 — Administrative credential compromise enables full domain control and lateral movement |
| **Inherent Risk Score** | 20 (Critical) |
| **ALE** | $1,500,000/year |
| **Risk Owner** | CISO |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Phishing is the most common attack vector in healthcare and MFA eliminates the vast majority of credential abuse. |
| **Planned Control(s)** | Mandatory MFA across all systems (phishing-resistant FIDO2 for admin accounts), simulated phishing campaigns quarterly with remedial training for failures, email security gateway with sandbox detonation, banner warnings on external emails |
| **Residual Risk** | Low (4) — Likelihood reduced to 1, impact remains 4 as admin compromise is always severe |
| **KRI** | Failed authentication attempts across admin accounts; successful credential stuffing attempts detected by SIEM |
| **Review Date** | Weekly |

---

### RISK-005

| Field | Description |
|---|---|
| **Risk ID** | RISK-005 |
| **Risk Description** | HIPAA violation due to unprotected PHI transmission results in regulatory penalty |
| **Risk Category** | Compliance |
| **Threat Source** | Opportunistic Attacker / Internal Negligence |
| **Vulnerability** | GAP-001: Legacy systems without encryption at rest or in transit |
| **Affected Asset(s)** | Patient Records Database, Billing System, Fax Machines |
| **Likelihood** | 4 — Legacy infrastructure and manual processes create consistent exposure windows |
| **Impact** | 4 — HHS OCR penalties range from $100 to $50,000 per record, plus mandatory breach notification |
| **Inherent Risk Score** | 16 (Critical) |
| **ALE** | $2,800,000/year |
| **Risk Owner** | Compliance Officer |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | HHS OCR enforcement actions have intensified and penalties scale with perceived negligence. |
| **Planned Control(s)** | TLS 1.3 enforcement across all systems, full-disk encryption on all endpoints, encrypted fax replacement solution, PHI discovery and classification engine, annual HIPAA Security Rule audit |
| **Residual Risk** | Medium (8) — Likelihood reduced to 2, impact remains 4 as regulatory penalties are statutory |
| **KRI** | Number of unencrypted PHI transmissions detected by DLP; audit log gaps on PHI access |
| **Review Date** | Monthly |

---

### RISK-006

| Field | Description |
|---|---|
| **Risk ID** | RISK-006 |
| **Risk Description** | Medical device compromise (MRI, infusion pumps) disrupts patient care |
| **Risk Category** | Operational |
| **Threat Source** | Hacktivist / Cybercriminal |
| **Vulnerability** | VULN-005: IoT medical devices with default credentials and no patching lifecycle |
| **Affected Asset(s)** | MRI Machine, Infusion Pumps, Patient Monitoring Equipment |
| **Likelihood** | 2 — Medical device targeting is growing but still less frequent than general IT attacks |
| **Impact** | 5 — Direct patient safety risk including potential loss of life |
| **Inherent Risk Score** | 10 (Medium) |
| **ALE** | $1,200,000/year |
| **Risk Owner** | Chief Medical Officer (jointly with CIO) |
| **Treatment Decision** | Transfer |
| **Treatment Justification** | Medical device vendor liability agreements should cover cyber incident costs and MedDefense lacks direct firmware control. |
| **Planned Control(s)** | Comprehensive medical device inventory with criticality scoring, network microsegmentation for all medical device VLANs, vendor SLA revisions requiring cybersecurity clauses and patch commitments, clinical engineering cybersecurity training program |
| **Residual Risk** | Low (4) — Likelihood reduced to 1, impact remains 4 as patient safety risk persists regardless of controls |
| **KRI** | Unauthorized connections to medical device VLAN; device firmware age exceeding 2 years without update |
| **Review Date** | Quarterly |

---

### RISK-007

| Field | Description |
|---|---|
| **Risk ID** | RISK-007 |
| **Risk Description** | Business email compromise (BEC) results in fraudulent wire transfer |
| **Risk Category** | Financial |
| **Threat Source** | Organized Crime |
| **Vulnerability** | VULN-004: Insufficient transaction verification procedures |
| **Affected Asset(s)** | Finance System, Email Gateway, Accounting Workstations |
| **Likelihood** | 4 — BEC attacks targeting healthcare finance departments are highly prevalent |
| **Impact** | 3 — Financial loss is significant but contained to fraud amount and does not directly impact patient care |
| **Inherent Risk Score** | 12 (High) |
| **ALE** | $750,000/year |
| **Risk Owner** | CFO |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | BEC losses in healthcare exceeded $1.2 billion in 2023 and verification gaps are easily exploitable. |
| **Planned Control(s)** | Dual authorization for all payments exceeding $10,000, domain-based message authentication (DMARC) enforcement, payment verification call-back procedure using known phone numbers, financial staff BEC awareness training |
| **Residual Risk** | Low (3) — Likelihood reduced to 1, impact remains 3 as fraud amount is bounded by transaction limits |
| **KRI** | Outbound email from compromised finance accounts; payment requests containing urgency or secrecy language |
| **Review Date** | Weekly |

---

### RISK-008

| Field | Description |
|---|---|
| **Risk ID** | RISK-008 |
| **Risk Description** | Cloud misconfiguration exposes patient data publicly |
| **Risk Category** | Operational / Compliance |
| **Threat Source** | Automated Scanner / Opportunistic Attacker |
| **Vulnerability** | VULN-007: Cloud storage buckets with public read permissions |
| **Affected Asset(s)** | Cloud Storage, Backup Repository, Development Environment |
| **Likelihood** | 3 — Cloud misconfigurations are common but MedDefense has limited cloud footprint currently |
| **Impact** | 4 — Public PHI exposure triggers mandatory breach notification and significant reputational damage |
| **Inherent Risk Score** | 12 (High) |
| **ALE** | $890,000/year |
| **Risk Owner** | Cloud Architect |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Cloud exposure incidents have tripled and automated scanners discover misconfigurations within hours. |
| **Planned Control(s)** | Cloud Security Posture Management (CSPM) tool with real-time alerting, Infrastructure as Code security scanning in CI/CD pipeline, quarterly cloud access reviews, default-deny IAM policies with explicit grant exceptions |
| **Residual Risk** | Low (3) — Likelihood reduced to 1, impact remains 3 as any public PHI exposure is serious |
| **KRI** | Public-facing storage bucket discoveries by CSPM; IAM permission escalation attempts |
| **Review Date** | Monthly |

---

### RISK-009

| Field | Description |
|---|---|
| **Risk ID** | RISK-009 |
| **Risk Description** | Ransomware via Remote Desktop Protocol (RDP) attack on billing infrastructure |
| **Risk Category** | Operational |
| **Threat Source** | Cybercriminal Group |
| **Vulnerability** | VULN-002: RDP exposed to internet with weak password policy on billing server |
| **Affected Asset(s)** | Billing Server (billing-srv-01), Payment Gateway |
| **Likelihood** | 4 — RDP remains a top ransomware entry point and billing-srv-01 is directly exposed |
| **Impact** | 4 — Billing system downtime directly halts revenue cycle and cash flow |
| **Inherent Risk Score** | 16 (Critical) |
| **ALE** | $1,100,000/year |
| **Risk Owner** | CTO |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | RDP is the number one ransomware entry vector and direct internet exposure is indefensible. |
| **Planned Control(s)** | Remove RDP from public internet entirely, deploy jump box architecture with MFA, conditional access policies restricting RDP to managed devices only, account lockout policy enforcement |
| **Residual Risk** | Medium (6) — Likelihood reduced to 2, impact remains 3 as billing downtime always affects revenue |
| **KRI** | RDP connection attempts from geolocations outside normal patterns; brute force attempts detected by SIEM |
| **Review Date** | Weekly |

---

### RISK-010

| Field | Description |
|---|---|
| **Risk ID** | RISK-010 |
| **Risk Description** | Failure to meet SOC 2 Type II requirements causes loss of key enterprise customer contracts |
| **Risk Category** | Strategic / Compliance |
| **Threat Source** | Market / Customer Requirements |
| **Vulnerability** | GAP-005: Insufficient logging and audit trail capabilities to satisfy SOC 2 control criteria |
| **Affected Asset(s)** | Log Servers, SIEM Platform, Compliance Documentation |
| **Likelihood** | 3 — Contract renewals occur annually and customer security questionnaires are becoming more stringent |
| **Impact** | 4 — Loss of enterprise contracts representing approximately 35% of total revenue |
| **Inherent Risk Score** | 12 (High) |
| **ALE** | $2,500,000/year |
| **Risk Owner** | CISO |
| **Treatment Decision** | Mitigate |
| **Treatment Justification** | Enterprise customers increasingly mandate SOC 2 compliance and contract renewals are at risk annually. |
| **Planned Control(s)** | SIEM platform expansion to cover all in-scope systems, centralized log retention policy (7 years minimum), automated control evidence collection, annual third-party SOC 2 Type II audit |
| **Residual Risk** | Medium (6) — Likelihood reduced to 2, impact remains 3 as contract loss is binary and severe |
| **KRI** | Days since last successful SOC 2 control testing; audit finding resolution time exceeding 30 days |
| **Review Date** | Quarterly |

---

## Risk Register Governance Note

This Risk Register is maintained by the **CISO Office** with input from all designated risk owners. The register undergoes **monthly review** by the Security Steering Committee, consisting of the CISO, CIO, CFO, Compliance Officer, and Chief Medical Officer. **Out-of-cycle reviews** are triggered when: (1) a new CVE with active exploit code emerges affecting MedDefense assets, (2) a KRI breaches its established threshold, (3) significant organizational changes occur such as mergers, acquisitions, or new technology deployments, or (4) a security incident reveals previously unknown risk exposure. When a **KRI threshold is breached**, the corresponding risk owner must initiate a risk reassessment within 72 hours, implement emergency controls if warranted, and report to the CISO within 5 business days with a documented corrective action plan. The register serves as the primary briefing document for Board security reviews conducted quarterly, and all treatment decisions must be documented with approval signatures before implementation begins.
