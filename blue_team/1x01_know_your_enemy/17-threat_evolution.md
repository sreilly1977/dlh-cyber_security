# The What-If
## Threat Landscape Dynamics Under Business Change Scenarios

**Date:** July 14, 2026  
**Classification:** CONFIDENTIAL – STRATEGIC ANALYSIS  
**References:** Task 6 Actor Matrix, Task 16 Threat Priority, Task 5 Supply Chain Assessment  

---

## Scenario A: Clinical Trial Partnership Launch

**Context:** Partnership with a university for an experimental cardiac treatment (500 patients, proprietary protocols, 3 international research institutions). Dedicated new server at MedDefense Central.

| Analysis Area | Impact Assessment |
|:---|:---|
| **New Threat Actors** | **Nation-State (Medium Likelihood):** Previously "Low" in Task 6. Proprietary cardiac research and biometric data now attracts espionage groups seeking medical IP. <br>**Competitor Espionage:** Commercial entities may target the data for market advantage. |
| **Changed Vectors** | **Supply Chain (Increased):** 3 international institutions introduce new trust boundaries and access points (Task 5). <br>**Data Exfiltration (Increased):** Research data is high-value, making insider/negotiated exfiltration more lucrative (Task 14 Scenario 2). <br>**Lateral Movement (Increased):** New server adds another asset to compromise within the flat network (Task 7). |
| **Shifted Priorities** | **Ransomware (Stays #1):** Remains existential threat. <br>**Supply Chain Attack (Moves #2 → #1):** Vendor/Partner access now touches high-value IP. <br>**Insider Data Theft (Moves #5 → #3):** More staff/external partners accessing sensitive research data. |
| **New Gaps** | **GAP-018 (Research Data Classification):** No policy exists for classifying IP vs. PHI vs. Shared Research data. <br>**GAP-019 (International Partner Risk):** No process for vetting security posture of international research institutions. <br>**GAP-001 (Segmentation):** New server must be isolated from EHR/Production (currently flat network risks cross-contamination). |
| **Net Assessment** | **Overall threat exposure increases significantly.** The organization transitions from a regional hospital target to a strategic IP asset, attracting higher-capability adversaries while simultaneously expanding the attack surface through international trust relationships that are outside MedDefense's direct security control. |

---

## Scenario B: EHR Migration to Cloud-Hosted SaaS

**Context:** Migrate `ehr-srv-01` / `ehr-db-01` to MedTech Solutions cloud. Decommission on-prem servers. All access via cloud interface.

| Analysis Area | Impact Assessment |
|:---|:---|
| **New Threat Actors** | **Identity-Focused Crime (Increased):** Attackers shift focus from network infiltration to credential harvesting (Task 16 Vector #2). <br>**Cloud-Native Ransomware (Emerging):** Groups specializing in SaaS account takeover (e.g., SharePoint/EHR admin abuse). |
| **Changed Vectors** | **Network Scanning (Decreased):** No local EHR server means no direct database port attacks (GAP-001/008 impact reduced). <br>**Identity/Access (Increased):** Authentication becomes the new perimeter; MFA (GAP-004) becomes the single most critical control. <br>**API Security (New):** All EHR interactions move to API endpoints, introducing injection/abuse risks. |
| **Shifted Priorities** | **Ransomware (Moves #1 → #2):** Still possible via identity, but local encryption risk drops. <br>**Identity Compromise (Moves #2 → #1):** Becomes the primary attack vector (if you own the credentials, you own the EHR). <br>**Supply Chain Risk (Moves #4 → #1):** Dependency on MedTech Solutions deepens (Task 5 analysis confirms this vendor is high risk). |
| **New Gaps** | **GAP-020 (Vendor SLA Security):** Current contract lacks strict security response time/data ownership clauses. <br>**GAP-021 (API Security Monitoring):** No visibility into API traffic anomalies now that DB logs are gone. <br>**GAP-004 (MFA):** If not enabled, SaaS migration is a single point of failure. |
| **Net Assessment** | **Overall threat exposure shifts rather than decreases.** While the internal attack surface shrinks by removing physical servers, the dependency risk on MedTech Solutions skyrockets (Task 5), and the organization becomes equally vulnerable if their identity controls (GAP-004) are not hardened immediately to compensate for the loss of network segmentation. |

---

## Scenario C: Public Ransomware Revelation (Media Exposure)

**Context:** National media reports January ransomware attack on billing-srv-01. Former patients express concern. Story gains traction.

| Analysis Area | Impact Assessment |
|:---|:---|
| **New Threat Actors** | **Hacktivists (Medium Likelihood):** Previously "Low" in Task 6. Now a potential target for public shaming/Denial of Service. <br>**Targeted Organized Crime (Increased):** Ransomware groups now know MedDefense is a viable, "soft" target that responds publicly. |
| **Changed Vectors** | **Phishing/Social Engineering (Increased):** Employees are primed for scams ("We need to fix this now") due to news coverage (Task 4). <br>**DDoS (New):** Hacktivist groups may target patient portal availability to amplify the scandal. <br>**Credential Stuffing (Increased):** Known breach encourages attackers to try reused passwords on patient/staff accounts. |
| **Shifted Priorities** | **Ransomware (Stays #1):** Now confirmed as an active target. <br>**Reputation/Crisis Comms (New Priority #4):** Managing patient trust becomes a security function. <br>**DDoS Protection (New Priority #5):** Portal availability becomes critical to prevent secondary reputational damage. |
| **New Gaps** | **GAP-022 (Crisis Communication Protocol):** No process for coordinating security/legal/media responses during active incidents. <br>**GAP-003 (Log Review):** Need to prove what happened in Jan to answer regulators/journalists (currently unreviewed logs). <br>**GAP-016 (Customer Notification):** Unclear process for notifying affected patients transparently. |
| **Net Assessment** | **Overall threat exposure increases due to target profiling.** Being publicly identified as a victim removes the benefit of obscurity, inviting opportunistic attacks and raising the probability of targeted follow-up attacks by actors who see the organization as both vulnerable and high-profile. |

---

## Summary of Strategic Implications

| Scenario | Primary Driver | Immediate Action Required |
|----------|---------------|---------------------------|
| **A (Clinical Trial)** | **Intellectual Property Value** | Implement Research VLAN isolation (GAP-001 extension) + International Partner Vetting (GAP-019). |
| **B (EHR Cloud)** | **Identity Dependency** | Enforce MFA on all vendor accounts immediately (GAP-004) + Update Vendor SLA (GAP-020). |
| **C (Media Exposure)** | **Visibility Targeting** | Activate Incident Response Plan (GAP-006) + DDoS mitigation prep (Gateway security). |

**Final Verdict:** None of these scenarios eliminate the foundational vulnerabilities (GAP-001, GAP-003, GAP-004) identified in Task 16. Scenario B reduces *some* technical surface but increases *vendor* risk. Scenario A increases *target value*. Scenario C increases *likelihood*. In all three cases, closing the Critical Three (Segmentation, SIEM, MFA) remains the prerequisite for safe evolution.

---

*Prepared by: Security Department*  
*References: Task 16 Threat Priority, Task 5 Supply Chain, Task 6 Actor Matrix*
