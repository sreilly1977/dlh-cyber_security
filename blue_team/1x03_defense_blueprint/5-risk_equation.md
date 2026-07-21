# 5. The Risk Equation
## Quantitative Risk Analysis for MedDefense Health Systems

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 5)  
**Reference:** Provided Risk Scenarios File, 1x01 Threat Landscape

---

## Methodology Note
For quantitative analysis, the formula **SLE = AV × EF** represents the financial impact of a single event. **ALE = SLE × ARO** represents the expected annual cost of that risk. In these calculations, "Asset Value" (AV) refers to the business value at risk during the incident (not just hardware replacement cost), ensuring the loss reflects operational impact.

---

## Scenario 1: Ransomware Attack on Billing Server

| Parameter | Value | Reasoning |
|-----------|-------|-----------|
| **Asset Value (AV)** | $4,200,000 | Based on annual revenue processed by the billing server. This represents the maximum operational exposure if the revenue stream were halted for a full year, providing the base against which partial losses are calculated. |
| **Exposure Factor (EF)** | 11.26% | The incident does not destroy the server permanently but causes temporary loss. EF is calculated as Total Estimated Loss ($473,000) ÷ Annual Revenue ($4.2M). The loss components are: 18 days downtime @ $16K/day ($288K) + Recovery ($85K) + HIPAA Penalty ($100K). |
| **Single Loss Expectancy (SLE)** | **$473,000** | Derived from sum of direct loss components: Downtime ($288,000) + Recovery ($85,000) + Penalty ($100,000). |
| **Annualized Rate of Occurrence (ARO)** | 0.25 | Sector intelligence (1x01) indicates approximately 1 attack every 3-4 years for similar-profile hospitals. Conservative estimate uses 1 in 4 years. |
| **Annualized Loss Expectancy (ALE)** | **$118,250** | SLE ($473,000) × ARO (0.25). |
| **Confidence Level** | **Medium** | High confidence in downtime/recovery costs (industry averages). Lower confidence in exact timing of next attack (ARO), as a flat network increases this frequency beyond sector averages. |

---

## Scenario 2: Patient Data Breach via EHR System

| Parameter | Value | Reasoning |
|-----------|-------|-----------|
| **Asset Value (AV)** | $9,075,000 | Total value of the EHR dataset at risk. Includes 50,000 records × $165/record ($8.25M) + Fixed Breach Costs ($25K notification + $200K litigation + $600K reputation = $825K). |
| **Exposure Factor (EF)** | 100% | A successful exfiltration via Kill Chain #2 exposes the entire database. Unlike ransomware where recovery is possible, data exfiltration triggers full breach costs immediately. |
| **Single Loss Expectancy (SLE)** | **$9,075,000** | AV × EF = $9,075,000 × 100%. |
| **Annualized Rate of Occurrence (ARO)** | 0.33 | Probabilistic estimate based on HHS breach data and MedDefense's lack of controls (no SIEM, flat network). 1 in 3 years is a reasonable upper-bound expectation given the vulnerability posture. |
| **Annualized Loss Expectancy (ALE)** | **$3,004,875** | SLE ($9,075,000) × ARO (0.33). |
| **Confidence Level** | **Low** | Highly sensitive to ARO estimation. If MedDefense implements the proposed segmentation and SIEM (GAP-001, GAP-003), ARO drops significantly. The $600K reputational figure is subjective and difficult to model precisely. |

---

## Scenario 3: Insider Data Theft (Negligent)

| Parameter | Value | Reasoning |
|-----------|-------|-----------|
| **Asset Value (AV)** | $120,000 | Defined as the "Cost per Incident." In insider threat scenarios, the "Asset" is the cumulative cost of investigation, containment, remediation, and reporting. |
| **Exposure Factor (EF)** | 100% | The incident cost is incurred once the negligence is discovered. EF is 100% because the SLE represents the total financial fallout of the event. |
| **Single Loss Expectancy (SLE)** | **$120,000** | Based on Ponemon Insider Threat Report averages for healthcare negligent insiders. |
| **Annualized Rate of Occurrence (ARO)** | 2.5 | With 2,000 staff, no DLP, no USB restrictions, and no security training, sector averages suggest 2-3 incidents per year. Conservative estimate uses 2.5. |
| **Annualized Loss Expectancy (ALE)** | **$300,000** | SLE ($120,000) × ARO (2.5). |
| **Confidence Level** | **Medium** | ARO is driven by human behavior which is hard to predict, but the lack of controls (no training, no DLP) strongly correlates with higher incident frequency observed in similar environments. |

---

## Scenario 4: Medical Device Compromise

This scenario is split into two distinct risk vectors: Denial of Service (DoS) and Patient Safety Liability.

### Vector A: Denial of Service (Operational Disruption)

| Parameter | Value | Reasoning |
|-----------|-------|-----------|
| **Asset Value (AV)** | $355,000 | Replacement cost ($105K for 7 pumps) + FDA investigation ($150K) + Ops disruption ($20K/day × 5 days = $100K). |
| **Exposure Factor (EF)** | 100% | A compromise leading to quarantine results in total loss of these costs for the affected unit. |
| **Single Loss Expectancy (SLE)** | **$355,000** | Sum of direct costs associated with the DoS event. |
| **Annualized Rate of Occurrence (ARO)** | 0.1 | Opportunistic attack is plausible due to default credentials (Finding 010) but targeted DoS is rare. Estimate 1 in 10 years. |
| **Annualized Loss Expectancy (ALE)** | **$35,500** | SLE ($355,000) × ARO (0.1). |

### Vector B: Patient Safety Liability (Direct Harm)

| Parameter | Value | Reasoning |
|-----------|-------|-----------|
| **Asset Value (AV)** | $3,000,000 | Mid-range patient liability ($500K-$5M) + FDA costs ($150K) + Ops disruption ($100K). Used mid-range liability for calculation. |
| **Exposure Factor (EF)** | 100% | Liability is realized upon a patient safety event. |
| **Single Loss Expectancy (SLE)** | **$3,000,000** | Catastrophic impact scenario. |
| **Annualized Rate of Occurrence (ARO)** | 0.02 | Patient harm via hacked infusion pump is statistically rare. Estimate 1 in 50 years. |
| **Annualized Loss Expectancy (ALE)** | **$60,000** | SLE ($3,000,000) × ARO (0.02). |

| **Combined ALE (Vector A + B)** | **$95,500** | Sum of both vectors. |
| **Confidence Level** | **Low** | Liability estimates are highly speculative. However, the existence of default credentials makes the lower-frequency, high-impact risk credible enough to justify mitigation spending. |

---

## Scenario 5: VPN Compromise Leading to Full Network Access

| Parameter | Value | Reasoning |
|-----------|-------|-----------|
| **Asset Value (AV)** | $9,548,000 | Aggregate worst-case impact of Scenarios 1 + 2. Ransomware SLE ($473,000) + Data Breach SLE ($9,075,000). This assumes a VPN breach allows an adversary to execute both a ransomware attack and a data exfiltration campaign sequentially. |
| **Exposure Factor (EF)** | 100% | A VPN compromise grants full access to the flat network. EF is 100% of the aggregated enterprise risk. |
| **Single Loss Expectancy (SLE)** | **$9,548,000** | Represents the maximum foreseeable loss from a perimeter breach. |
| **Annualized Rate of Occurrence (ARO)** | 0.3 | Based on 1x01 intelligence showing VPN as the #1 initial access vector (38% of healthcare ransomware attacks). ARO 0.3 equates to roughly once every 3 years. |
| **Annualized Loss Expectancy (ALE)** | **$2,864,400** | SLE ($9,548,000) × ARO (0.3). |
| **Confidence Level** | **Medium** | The ALE is dominated by the Breach SLE component. While the probability of a simultaneous Ransomware + Breach event might be slightly lower than the individual probabilities, treating the VPN as a "Master Key" justifies aggregating the downstream risks for strategic planning. |

---

## Summary of Quantitative Risk Posture

| Scenario | Risk Type | SLE (Single Loss) | ARO (Annual Rate) | ALE (Annual Loss) | Priority Ranking |
|----------|-----------|-------------------|-------------------|-------------------|------------------|
| **Scenario 1** | Ransomware | $473,000 | 0.25 | $118,250 | Medium |
| **Scenario 2** | Data Breach | $9,075,000 | 0.33 | $3,004,875 | High |
| **Scenario 3** | Insider Negligence | $120,000 | 2.50 | $300,000 | Medium-High |
| **Scenario 4** | Medical Device | $3,355,000 | 0.12 | $95,500 | Low-Medium |
| **Scenario 5** | VPN Perimeter | $9,548,000 | 0.30 | $2,864,400 | Critical |
| **Total ALE** | | | | **$6,383,025** | |

### Strategic Interpretation

The quantitative analysis reveals a total expected annual loss exposure of **$6.38 million** for MedDefense. This figure dwarfs the current security budget of **$120,000**, demonstrating a funding gap ratio of **53:1**. 

The highest cost driver is the Data Breach (Scenario 2) followed closely by the VPN Perimeter Breach (Scenario 5), which acts as the gateway for the other scenarios. Investing in network segmentation (GAP-001) and SIEM deployment (GAP-003) directly addresses the root cause of the highest ALE figures. A conservative 50% reduction in ARO for these top scenarios would save MedDefense approximately **$3 million annually**, yielding an ROI that justifies significant capital expenditure despite the current budget deficit.

---

*Prepared by: Security Department*  
*References: Provided Risk Scenarios File, 1x01 Threat Landscape (T14 Kill Chains), 1x02 Vulnerability Assessment (Findings 001-031), Ponemon Institute Reports, CISA Data, HHS Breach Portal Statistics*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
