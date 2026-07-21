# 6. The ALE Workshop
## Quantitative Risk Analysis and Control Investment Strategy

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 6)  
**Reference:** 1x00 Gap Analysis, 1x01 Threat Landscape, 1x02 Vulnerability Assessment, Task 5 ALE Exercises

---

## Risk 1: Ransomware Encryption via Perimeter Breach

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **Risk** | Ransomware encrypts critical infrastructure via compromised VPN endpoint |
| **Source** | GAP-002 (No MFA) + Finding 001 (Apache RCE) + Threat Actor: Organized Crime (1x01 T4) |
| **Asset** | Enterprise Infrastructure (Billing + EHR + Backups) |
| **Asset Value (AV)** | **$4,500,000** <br> *Revenue Loss ($16K/day × 18 days = $288K) + Recovery ($85K) + Data Restoration ($1M) + Downtime Operations ($3M aggregate impact)* |
| **Exposure Factor (EF)** | **65%** <br> *Reasoning: Not all systems may be encrypted simultaneously; backups allow partial recovery, but 18 days of downtime represents significant operational loss.* |
| **SLE** | **$2,925,000** (AV $4.5M × EF 65%) |
| **ARO** | **0.30** <br> *Reasoning: Based on 1x01 intelligence showing VPN compromise is #1 initial access vector (38% of attacks). Flat network amplifies success rate.* |
| **ALE** | **$877,500** (SLE $2.925M × ARO 0.30) |
| **Proposed Control** | Multi-Factor Authentication (MFA) on all external access + Network Segmentation |
| **Control Annual Cost** | **$60,000** (vCISO oversight + Identity provider + Segmentation labor) |
| **Estimated ALE After** | **$146,250** (Reduces ARO to 0.05 due to MFA blocking credential theft) |
| **Net Benefit** | **$671,250** ($877,500 - $146,250 - $60,000) |

---

## Risk 2: Patient Data Exfiltration

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **Risk** | Bulk exfiltration of Protected Health Information (PHI) leading to regulatory breach |
| **Source** | GAP-001 (Flat Network) + Finding 031 (Ghostcat) + Threat Actor: Nation-State (1x01 T2) |
| **Asset** | EHR System (ehr-srv-01 + ehr-db-01) |
| **Asset Value (AV)** | **$9,075,000** <br> *Notification/Credit Monitoring ($25K) + Litigation ($200K) + Reputation Loss ($600K) + Record Cost (50K records × $165 = $8.25M)* |
| **Exposure Factor (EF)** | **100%** <br> *Reasoning: Once exfiltrated, all data is considered compromised; full breach notification cycle triggers.* |
| **SLE** | **$9,075,000** |
| **ARO** | **0.33** <br> *Reasoning: 1 in 3 years based on sector data for unsegmented hospitals with unpatched web servers.* |
| **ALE** | **$2,994,750** (SLE $9.075M × ARO 0.33) |
| **Proposed Control** | Network Segmentation (EHR VLAN) + DLP Deployment |
| **Control Annual Cost** | **$120,000** (Switches/Firewall rules + DLP licensing) |
| **Estimated ALE After** | **$900,000** (Reduces EF to ~30% via DLP blocking bulk transfer; reduces ARO to 0.10) |
| **Net Benefit** | **$1,974,750** ($2.99M - $900K - $120K) |

---

## Risk 3: Negligent Insider Incident

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **Risk** | Employee accidentally exposes PHI via unsecured USB or phishing click |
| **Source** | GAP-008 (No Awareness Training) + Finding 021 (No Logging) + Threat Actor: Insider (1x01 T3) |
| **Asset** | Clinical Workstations + Data |
| **Asset Value (AV)** | **$120,000** <br> *Average cost per incident (Investigation $30K + Containment $25K + Remediation $40K + Reporting $25K).* |
| **Exposure Factor (EF)** | **100%** <br> *Reasoning: Cost is incurred once the incident is confirmed.* |
| **SLE** | **$120,000** |
| **ARO** | **2.50** <br> *Reasoning: With 2,000 staff and no training/no DLP, sector averages suggest 2-3 incidents/year.* |
| **ALE** | **$300,000** (SLE $120K × ARO 2.50) |
| **Proposed Control** | Security Awareness Training + Endpoint DLP Policy |
| **Control Annual Cost** | **$35,000** (Training platform + DLP policy enforcement labor) |
| **Estimated ALE After** | **$120,000** (Reduces ARO to 1.0 via reduced user error) |
| **Net Benefit** | **$145,000** ($300K - $120K - $35K) |

---

## Risk 4: Medical Device Safety Compromise

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **Risk** | Infusion pump compromise leads to operational disruption or patient safety event |
| **Source** | GAP-007 (IoT on General Network) + Finding 010 (Default Credentials) + Threat Actor: Opportunistic (1x01 T5) |
| **Asset** | BD Alaris Infusion Pumps (7 units) |
| **Asset Value (AV)** | **$355,000** <br> *Replacement ($105K) + FDA Investigation ($150K) + Ops Disruption ($20K/day × 5 days = $100K).* |
| **Exposure Factor (EF)** | **100%** <br> *Reasoning: A quarantine event triggers all associated costs immediately.* |
| **SLE** | **$355,000** |
| **ARO** | **0.10** <br> *Reasoning: 1 in 10 years for DoS event based on flat network exposure.* |
| **ALE** | **$35,500** (SLE $355K × ARO 0.10) |
| **Proposed Control** | Dedicated Medical IoT VLAN + Switch Port ACLs |
| **Control Annual Cost** | **$15,000** (Configuration labor + Maintenance) |
| **Estimated ALE After** | **$7,100** (Reduces ARO to 0.02 via network isolation) |
| **Net Benefit** | **$13,400** ($35.5K - $7.1K - $15K) |

---

## Risk 5: Regulatory Non-Compliance (HIPAA)

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **Risk** | OCR audit findings result in civil monetary penalties due to lack of documentation |
| **Source** | GAP-004 (No IR Plan) + GAP-006 (No Vuln Management) + Threat: Regulatory (HHS OCR) |
| **Asset** | Organizational License / Standing |
| **Asset Value (AV)** | **$250,000** <br> *Estimated penalty tier for moderate negligence ($50K-$250K) + Legal defense costs.* |
| **Exposure Factor (EF)** | **100%** <br> *Reasoning: Penalty is a fixed financial liability upon audit finding.* |
| **SLE** | **$250,000** |
| **ARO** | **1.00** <br> *Reasoning: Annual compliance risk due to lack of governance framework (NIST CSF).* |
| **ALE** | **$250,000** (SLE $250K × ARO 1.00) |
| **Proposed Control** | vCISO Program + NIST CSF Implementation |
| **Control Annual Cost** | **$80,000** (vCISO Retainer + Documentation support) |
| **Estimated ALE After** | **$100,000** (Reduces likelihood of severe penalty to minor findings) |
| **Net Benefit** | **$70,000** ($250K - $100K - $80K) |

---

## Risk Prioritization by ALE

The following table ranks the identified risks by their Annualized Loss Expectancy (ALE). This ranking drives the strategic roadmap presented in Task 8 (The Defense Blueprint).

| Rank | Risk Description | ALE (Before Control) | Proposed Control Cost | Net Benefit | Priority |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | Patient Data Exfiltration | $2,994,750 | $120,000 | $1,974,750 | **Critical** |
| **2** | Ransomware Encryption | $877,500 | $60,000 | $671,250 | **Critical** |
| **3** | Regulatory Non-Compliance | $250,000 | $80,000 | $70,000 | **High** |
| **4** | Negligent Insider | $300,000 | $35,000 | $145,000 | **High** |
| **5** | Medical Device Safety | $35,500 | $15,000 | $13,400 | **Medium** |
| **Total** | **Combined ALE Exposure** | **$4,457,750** | **$310,000** | **$2,874,400** | |

### Investment Justification

The total Annualized Loss Expectancy across these five top risks is **$4.46 million**. The proposed controls require an annual investment of **$310,000**. This yields a projected net benefit (risk reduction minus cost) of **$2.87 million** in the first year alone.

While the $310,000 investment exceeds the current security budget of **$120,000**, the cost of inaction ($4.46 million ALE) creates an existential financial threat to MedDefense. Specifically:
1.  **Data Exfiltration ($2.99M ALE):** A single breach would wipe out several years of operating profit.
2.  **Ransomware ($877K ALE):** Operational paralysis poses an immediate survival risk.

Prioritizing controls based on ALE ensures that capital is directed toward risks with the highest potential financial impact rather than simply addressing "vulnerabilities" without business context. The 1x03 roadmap will sequence these investments over 12 months to align with cash flow, starting with MFA and Segmentation (highest leverage) before expanding to DLP and vCISO services.

---

*Prepared by: Security Department*  
*References: Task 5 Risk Scenarios, 1x00 Asset Registry, 1x01 Threat Intelligence Dossier, 1x02 Vulnerability Findings, Ponemon Institute Reports, CISA Ransomware Guidance*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
