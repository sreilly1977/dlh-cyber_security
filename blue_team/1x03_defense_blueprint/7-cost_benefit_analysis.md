# 7. The Cost-Benefit Analysis
## Financial Justification for Proposed Security Controls

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 7)  
**Reference:** Task 6 ALE Calculations, 1x02 Vulnerability Assessment, 1x01 Threat Landscape

---

## Control Evaluation

### Control 1: Network Segmentation (VLAN Implementation)

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 12 (Network Infrastructure Management) |
| **Annual Cost** | **$95,000** <br> *Switch hardware ($60K one-time amortized at $20K/year) + Firewall rules ($15K/year labor) + Ongoing maintenance ($60K/year)* |
| **Risk(s) Addressed** | Ransomware ($877.5K ALE), Data Exfiltration ($2.99M ALE), Medical Device Safety ($35.5K ALE) |
| **ALE Reduction** | **$2,400,000** <br> *Reduces ARO across all three scenarios by 70% (prevents lateral movement on flat network)* |
| **Net Value** | **$2,305,000** ($2.4M - $95K) |
| **Verdict** | **Justified** |
| **Recommendation** | **Implement Immediately** - Single highest-impact control; addresses root cause (flat network) amplifying all other vulnerabilities by 6.6x to 12.0x. |

---

### Control 2: MFA Deployment on VPN and Administrative Accounts

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 6 (Access Control Management) |
| **Annual Cost** | **$18,000** <br> *License ($5K/year - already owned in O365 E3) + Implementation labor ($10K one-time, amortized) + Maintenance ($3K/year)* |
| **Risk(s) Addressed** | Ransomware ($877.5K ALE via VPN entry point), Data Exfiltration (credential theft component) |
| **ALE Reduction** | **$585,000** <br> *Reduces ARO from 0.30 to 0.05 for credential-based attacks (90% reduction per Verizon DBIR data)* |
| **Net Value** | **$567,000** ($585K - $18K) |
| **Verdict** | **Justified** |
| **Recommendation** | **Implement Immediately** - Highest ROI control available; leverages existing O365 licenses with minimal marginal cost. |

---

### Control 3: Enterprise SIEM Deployment (Wazuh Open-Source)

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 8 (Audit Log Management), Control 13 (Network Monitoring) |
| **Annual Cost** | **$75,000** <br> *Labor only (Security Analyst time + SysAdmin support) = $75K/year. No software license cost.* |
| **Risk(s) Addressed** | Ransomware (improves detection time), Regulatory Compliance ($250K ALE) |
| **ALE Reduction** | **$350,000** <br> *Reduces dwell time from 14 days to 2 hours, lowering ransomware impact by 80%. Reduces regulatory penalty severity.* |
| **Net Value** | **$275,000** ($350K - $75K) |
| **Verdict** | **Justified** |
| **Recommendation** | **Implement Within 90 Days** - Open-source option avoids $200K+ commercial SIEM costs while delivering critical detection capability. |

---

### Control 4: Offsite Backup Replication (AWS S3 Glacier Immutable Storage)

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 11 (Data Recovery) |
| **Annual Cost** | **$25,000** <br> *Cloud storage ($18K/year for 15TB) + Egress fees ($3K/year) + Monitoring ($4K/year)* |
| **Risk(s) Addressed** | Ransomware (backup encryption scenario) |
| **ALE Reduction** | **$150,000** <br> *Enables rapid recovery without paying ransom; reduces recovery time from 18 days to 3 days.* |
| **Net Value** | **$125,000** ($150K - $25K) |
| **Verdict** | **Justified** |
| **Recommendation** | **Implement Within 60 Days** - Critical for ransomware resilience; low cost relative to business continuity value. |

---

### Control 5: Endpoint Detection and Response Upgrade (Sophos Intercept X)

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 10 (Malware Defenses) |
| **Annual Cost** | **$65,000** <br> *License for 300 endpoints + servers ($55K/year) + Administration ($10K/year)* |
| **Risk(s) Addressed** | Ransomware (endpoint malware), Negligent Insider ($300K ALE) |
| **ALE Reduction** | **$220,000** <br> *Improves malware detection rate from 60% to 95%, reducing successful infections by 70%.* |
| **Net Value** | **$155,000** ($220K - $65K) |
| **Verdict** | **Justified** |
| **Recommendation** | **Implement Within 90 Days** - Addresses the cryptominer that went undetected for 14+ days; complements segmentation. |

---

### Control 6: Dedicated Firewall for Westside Clinic

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 12 (Network Infrastructure Management) |
| **Annual Cost** | **$12,000** <br> *Hardware ($8K one-time, amortized at $2.7K/year) + Managed firewall service ($9K/year) + Support ($300/year)* |
| **Risk(s) Addressed** | Ransomware (entry via weak perimeter at branch site) |
| **ALE Reduction** | **$88,000** <br> *Reduces ARO for VPN compromise by 20% (eliminates weakest link in perimeter).* |
| **Net Value** | **$76,000** ($88K - $12K) |
| **Verdict** | **Justified** |
| **Recommendation** | **Implement Within 30 Days** - Fixes consumer-grade router (ASUS) serving as gateway for 3-site network; low cost, meaningful perimeter hardening. |

---

### Control 7: 24/7 Security Operations Center Staffing (Outsourced Managed SOC)

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 8 (Audit Log Management), Control 13 (Network Monitoring) |
| **Annual Cost** | **$280,000** <br> *Managed SOC service for mid-sized organization ($280K/year based on vendor quotes)* |
| **Risk(s) Addressed** | Ransomware (detection), Data Exfiltration (detection), Regulatory Compliance ($250K ALE) |
| **ALE Reduction** | **$180,000** <br> *Improves detection speed but does not address root cause (flat network). Diminishing returns compared to building internal SIEM capability.* |
| **Net Value** | **-$100,000** ($180K - $280K) |
| **Verdict** | **Not Justified** |
| **Recommendation** | **Reject** - Costs exceed risk reduction; use open-source Wazuh SIEM with internal analyst coverage instead. SOC can be added later at 2x budget. |

---

### Control 8: Full Medical Device Network Isolation with Dedicated Monitoring

| Parameter | Value / Reasoning |
|-----------|-------------------|
| **CIS Control Reference** | Control 12 (Network Infrastructure Management) |
| **Annual Cost** | **$85,000** <br> *Dedicated monitoring appliance ($40K/year) + VLAN isolation labor ($35K/year) + Biomed coordination ($10K/year)* |
| **Risk(s) Addressed** | Medical Device Safety ($35.5K ALE) |
| **ALE Reduction** | **$28,000** <br> *Reduces ARO from 0.10 to 0.02 for DoS events; negligible impact on patient safety liability (low-probability event).* |
| **Net Value** | **-$57,000** ($28K - $85K) |
| **Verdict** | **Not Justified** |
| **Recommendation** | **Defer** - ALE reduction ($28K) does not justify cost ($85K). Implement basic ACL-based isolation from Control 1 instead; full monitoring deferred until budget permits. |

---

## Cost-Benefit Summary Table

Ranked by Net Value (highest first):

| Rank | Control | Annual Cost | ALE Reduction | Net Value | Verdict | Fit in $120K Budget? |
|------|---------|-------------|---------------|-----------|---------|----------------------|
| **1** | Network Segmentation | $95,000 | $2,400,000 | $2,305,000 | Justified | **Yes** |
| **2** | MFA Deployment | $18,000 | $585,000 | $567,000 | Justified | **Yes** |
| **3** | Enterprise SIEM (Wazuh) | $75,000 | $350,000 | $275,000 | Justified | **Yes** |
| **4** | EDR Upgrade | $65,000 | $220,000 | $155,000 | Justified | **Yes** |
| **5** | Offsite Backup Replication | $25,000 | $150,000 | $125,000 | Justified | **Yes** |
| **6** | Westside Clinic Firewall | $12,000 | $88,000 | $76,000 | Justified | **Yes** |
| **7** | 24/7 SOC (Managed) | $280,000 | $180,000 | -$100,000 | Not Justified | **No** |
| **8** | Medical Device Isolation | $85,000 | $28,000 | -$57,000 | Not Justified | **No** |

### Budget Feasibility Analysis

**Top 6 Justified Controls Total Cost:** $290,000

**Current Annual Security Budget:** $120,000

**Budget Gap:** $170,000

**Implementation Priority Within Current Budget:**

Given the $120,000 budget constraint, MedDefense should prioritize controls in this order to maximize net value while respecting cash flow:

| Phase | Controls | Cumulative Cost | Remaining Budget |
|-------|----------|-----------------|------------------|
| **Phase 1 (Months 1-2)** | MFA ($18K) + Westside Firewall ($12K) | $30,000 | $90,000 |
| **Phase 2 (Months 3-6)** | Network Segmentation ($95K, staged) | $125,000 | -$5,000 (overshoot) |
| **Alternative Phase 2** | SIEM ($75K) + Backup ($25K) + EDR ($65K reduced scope) | $165,000 | Requires funding raise |

**Recommended Path:** Execute Phase 1 (MFA + Westside Firewall) within current budget using existing funds. Request Board approval for **additional $170,000 capital allocation** to fund Phase 2 controls. The ROI justification ($3.5M annual risk reduction for $290K investment) supports this request compellingly.

---

## Strategic Decision Matrix

| Decision | Recommendation | Rationale |
|----------|----------------|-----------|
| **Network Segmentation** | Proceed to Phase 1 procurement | Highest net value; addresses root cause of all amplified risks |
| **MFA Deployment** | Proceed immediately | Leverages existing O365 licenses; 32x ROI |
| **SIEM (Open-Source)** | Proceed within 90 days | Cost-effective detection vs. expensive commercial alternatives |
| **EDR Upgrade** | Proceed within 90 days | Addresses cryptominer detection failure; strong ROI |
| **Offsite Backup** | Proceed within 60 days | Business continuity essential; low cost |
| **Westside Firewall** | Proceed within 30 days | Eliminates weakest perimeter link; lowest cost |
| **24/7 SOC** | Reject | Overpriced for MedDefense maturity level; defer until budget doubles |
| **Medical Device Monitoring** | Defer | Does not pass cost-benefit test; implement basic ACLs from Control 1 instead |

---

*Prepared by: Security Department*  
*References: Task 6 ALE Workshop, 1x02 Vulnerability Assessment (Findings 001-031), 1x01 Threat Intelligence, CIS Controls v8, Verizon DBIR 2024, Ponemon Institute Reports*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
