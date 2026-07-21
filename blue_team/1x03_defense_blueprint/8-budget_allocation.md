# 8. The Budget Game
## Resource Allocation Under Budget Constraints

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 8)  
**Reference:** Task 7 Cost-Benefit Analysis, Task 6 ALE Workshop

---

## Part 1 — The Selection

### Funded Controls

| Control | Annual Cost | ALE Reduction | Net Value |
|---------|-------------|---------------|-----------|
| **MFA Deployment** (O365 E3, VPN, admin accounts) | $18,000 | $585,000 | $567,000 |
| **Westside Clinic Firewall** (enterprise-grade replacement) | $12,000 | $88,000 | $76,000 |
| **Offsite Backup Replication** (AWS S3 Glacier immutable) | $25,000 | $150,000 | $125,000 |
| **Network Segmentation** (core VLAN implementation, phased scope) | $65,000 | $1,200,000 | $1,135,000 |
| **Total Spend** | **$120,000** | **$2,023,000** | **$1,903,000** |

### Budget Ledger

| Line Item | Amount |
|-----------|--------|
| Annual Security Budget | 120000 |
| Total Spend | 120000 |
| Budget Remaining | 0 |
| Budget Utilization | 100% |

### Funded Controls: Justification Summary

**MFA Deployment ($18K):** Selected first because it leverages existing O365 E3 licenses, producing the highest ROI of any control ($567K net value). Addresses the number one initial access vector (credential theft via VPN) identified in 1x01. Eliminates the authentication weakness exploited in Kill Chain #1 and Kill Chain #4. Implementable within 30 days with minimal infrastructure changes.

**Westside Clinic Firewall ($12K):** Selected second because it eliminates the consumer-grade ASUS router (1x02 Finding 014) that represents the weakest perimeter link across all three sites. Low absolute cost ($12K) relative to risk reduction ($88K). Without this control, the Westside Clinic remains a viable entry point for adversaries bypassing the FortiGate 100F at Central Hospital. Implementable within 30 days.

**Offsite Backup Replication ($25K):** Selected third because it provides ransomware resilience at low cost. The current backup infrastructure (Synology NAS) is on the flat network and vulnerable to CVE-2023-1383 (1x02 Finding 015). Immutable cloud backups ensure recovery capability even if the primary NAS is encrypted. Without this control, a ransomware event could result in permanent data loss. Implementable within 60 days.

**Network Segmentation, Phased ($65K):** Selected fourth with a reduced scope from the $95K full implementation. The $65K phased approach funds core VLAN creation (Server, Medical Device, and Management zones) with inter-VLAN ACLs but defers the Guest WiFi isolation and workstation micro-segmentation to the next fiscal year. This partial implementation still breaks the flat network's 6.6x to 12.0x risk amplification by isolating the highest-value assets (EHR, billing, medical devices) from general computing infrastructure. Implementable within 90-120 days.

### Deferred Controls

| Control | Reason for Deferral |
|---------|---------------------|
| **Enterprise SIEM (Wazuh)** ($75K) | Deferred due to budget exhaustion after funding the four controls above. The SIEM addresses the Detect function (rated Not Implemented in Task 1 NIST CSF Profile), which is critical for reducing dwell time and enabling incident response. However, the four funded controls reduce the likelihood and impact of incidents reaching the network in the first place, making detection a second-wave priority. Targeted for next fiscal year budget or grant funding. |
| **EDR Upgrade** ($65K) | Deferred because the existing Sophos deployment provides baseline endpoint protection, albeit insufficient for advanced threats. The cryptominer detection failure (1x02 Task 4) demonstrates the gap, but network segmentation reduces the blast radius of endpoint compromise by isolating affected systems. The EDR upgrade addresses the same risk vector as segmentation but at a higher cost per dollar of ALE reduction. Targeted for next fiscal year. |

### Rejected Controls

| Control | Reason for Rejection |
|---------|----------------------|
| **24/7 Managed SOC** ($280K) | Rejected because the annual cost ($280K) exceeds the total security budget ($120K) by 133%. Even if the entire budget were allocated to SOC, it would leave no funds for preventive controls. Furthermore, the ALE reduction ($180K) is less than the control cost ($280K), producing a negative net value of -$100K. The SOC also requires a functioning SIEM as a prerequisite, which is also deferred. The combination of both controls ($355K) would consume nearly triple the budget while providing diminishing returns on detection without addressing root causes. Replaced by interim measure: Security Analyst reviews Wazuh alerts (once deployed) during business hours and configures email alerts for critical events after hours. |
| **Full Medical Device Isolation with Dedicated Monitoring** ($85K) | Rejected because the ALE reduction ($28K) does not justify the cost ($85K), producing a negative net value of -$57K. The basic network isolation (switch port ACLs) is already covered under the funded Network Segmentation control ($65K phased). Full monitoring with a dedicated appliance adds incremental value but at a cost disproportionate to the risk. Replaced by interim measure: ACL-based network isolation funded under Control 1 (Network Segmentation) restricts access to medical devices without the dedicated monitoring infrastructure. |

---

## Part 2 — The Opportunity Cost

For each deferred control, the opportunity cost represents the ALE that remains unaddressed because the control was not funded this fiscal year. This is the residual risk the Board must knowingly accept.

| Deferred Control | Unaddressed ALE | Opportunity Cost Statement |
|------------------|-----------------|---------------------------|
| **Enterprise SIEM (Wazuh)** | $350,000 | By deferring the SIEM deployment, MedDefense accepts an estimated $350,000 in annual risk exposure related to undetected intrusions, extended dwell time, and inability to investigate incidents. The cryptominer on billing-srv-01 went undetected for 14+ days because no centralized logging or monitoring existed; this gap persists. |
| **EDR Upgrade** | $220,000 | By deferring the EDR upgrade, MedDefense accepts an estimated $220,000 in annual risk exposure related to endpoint malware evading Sophos baseline protection. The probability of a future cryptominer or ransomware variant bypassing current endpoint defenses remains elevated. |
| **Total Opportunity Cost** | **$570,000** | By deferring these two controls, MedDefense accepts an estimated $570,000 in annual risk exposure that could be addressed with $140,000 in additional funding. |

### Rejected Controls: Opportunity Cost

Rejected controls also carry opportunity cost, but the cost-benefit analysis demonstrated that the control costs more than the risk it mitigates. The Board accepts this residual risk not because it is ideal but because the mathematical alternative (paying more to mitigate less) is irrational.

| Rejected Control | Unaddressed ALE | Opportunity Cost Statement |
|------------------|-----------------|---------------------------|
| **24/7 Managed SOC** | $180,000 | By rejecting the managed SOC, MedDefense accepts an estimated $180,000 in annual risk exposure related to after-hours detection gaps. However, funding this control would require $280,000, which exceeds the entire budget and produces a negative ROI. Interim monitoring via business-hours alert review partially addresses this gap. |
| **Medical Device Monitoring** | $28,000 | By rejecting full medical device monitoring, MedDefense accepts an estimated $28,000 in annual risk exposure related to undetected medical device compromise. Basic ACL-based isolation (funded under Network Segmentation) reduces the likelihood but does not provide detection capability. |

---

## Part 3 — The Alternative

### Alternative Allocation: Detection-First Strategy

An alternative budget allocation prioritizes detection and response over prevention, accepting that MedDefense cannot prevent all incidents and must therefore detect and respond quickly.

| Control | Annual Cost | ALE Reduction | Net Value |
|---------|-------------|---------------|-----------|
| MFA Deployment | $18,000 | $585,000 | $567,000 |
| Westside Clinic Firewall | $12,000 | $88,000 | $76,000 |
| Enterprise SIEM (Wazuh) | $75,000 | $350,000 | $275,000 |
| EDR Upgrade (reduced scope: servers only) | $35,000 | $140,000 | $105,000 |
| **Total Spend** | **$140,000** | **$1,163,000** | **$1,023,000** |

**Problem:** This combination exceeds the budget of 120000 by $20K and achieves only $1.16M in ALE reduction compared to the primary recommendation's $2.02M. The detection-first strategy leaves the flat network unsegmented, meaning every detected incident has maximum blast radius.

### Comparison

| Metric | Primary Recommendation | Alternative (Detection-First) |
|--------|------------------------|-------------------------------|
| Total Spend | 120000 | 140000 (over budget) |
| ALE Reduction | $2,023,000 | $1,163,000 |
| Net Value | $1,903,000 | $1,023,000 |
| Flat Network Addressed | Yes (phased segmentation) | No (deferred) |
| Detection Capability | No (SIEM deferred) | Yes (SIEM funded) |
| Backup Resilience | Yes (immutable backups) | No (deferred) |
| Endpoint Protection | Baseline (existing Sophos) | Upgraded (Intercept X on servers) |
| Risk Amplification Reduction | 6.6x-12.0x eliminated | Unchanged (flat network persists) |

### Conclusion

The primary recommendation (Prevention-First with Phased Segmentation) is superior because it achieves **74% more ALE reduction** ($2.02M vs $1.16M) at **$20K less cost** ($120K vs $140K). The fundamental insight is that network segmentation is a force multiplier: it reduces the impact of every other vulnerability simultaneously, whereas detection-only strategies reduce dwell time but do not limit blast radius. On a flat network, faster detection of a ransomware outbreak that can propagate to all 280+ systems in minutes provides marginal benefit. Preventing lateral movement through segmentation fundamentally changes the risk equation.

The alternative does highlight a legitimate gap: the primary recommendation defers all detection capability, leaving MedDefense blind to incidents that bypass preventive controls. The recommended mitigation is to use the Security Analyst's existing skills to deploy a **minimal Wazuh agent** on billing-srv-01 and ehr-srv-01 at zero software cost during the first 90 days, providing basic log aggregation for the two highest-risk servers while full SIEM deployment awaits next fiscal year funding.

---

*Prepared by: Security Department*  
*References: Task 7 Cost-Benefit Analysis, Task 6 ALE Workshop, 1x02 Task 20 Priority Matrix, 1x01 Threat Intelligence*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
