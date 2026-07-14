# The Gap-Threat Correlation
## Threat-Informed Prioritization for MedDefense Health Systems

**Date:** July 14, 2026  
**Classification:** CONFIDENTIAL – BOARD BRIEFING MATERIAL  
**References:** Project 1x00 Gap Analysis (Task 12), Task 13 Reality Check, Task 10 Kill Chains, Task 14 Scenarios  

---

## Gap-Threat Correlation Matrix

| Gap ID | Gap Description | Original Risk | Threat Actors | Kill Chains | Scenarios | Updated Risk | Justification |
|--------|-----------------|---------------|---------------|-------------|-----------|--------------|---------------|
| **GAP-001** | Flat Network Architecture | Critical | All (Ransom, Insider, Vendor, Opportunistic) | #1, #2, #3, #4, #5 | #1, #2, #3 | **Critical** | Appears in **every** kill chain and scenario. Enables lateral movement for every actor type. Highest leverage control. |
| **GAP-002** | Active Compromise (Billing-SRV) | Critical | Ransomware, Opportunistic | #1, #5 | #1, #3 | **Critical** | Already exploited; immediate containment required. Threat evidence confirms active attacker presence. |
| **GAP-003** | No SIEM / Detection | Critical | All (especially Ransom, Insider) | #1, #2, #3, #4, #5 | #1, #2, #3 | **Critical** | No detection in any chain. Attackers operate undetected for days/weeks. Essential for all kill chain interruption. |
| **GAP-004** | No MFA | Critical | All (Ransom, Insider, Vendor) | #1, #2, #3, #4, #5 | #1, #2, #3 | **Critical** | Enabling credential reuse in all scenarios. Blocks 90% of initial access vectors without segmentation. |
| **GAP-005** | Backup Co-location | Critical | Ransomware | #1, #5 | #1 | **Critical** | Critical for Ransomware survivability. Not in Insider/Vendor chains, but catastrophic for Ransomware recovery. |
| **GAP-006** | No IR/DR/BCP | Critical | Ransomware, Insider | #1, #5 | #1, #2 | **Critical** | Amplifies impact of all successful attacks. Delays containment and recovery significantly. |
| **GAP-007** | Medical Device Exposure | Critical | Ransomware, Opportunistic | #3 | #1 (secondary) | **Critical** | Unique risk of patient harm (not just data). Specific vector for IoT manipulation chain. |
| **GAP-008** | Apache RCE Vulnerability | Critical | Ransomware, Opportunistic | #1 | #1 | **Critical** | Proven active vector (billing-srv-01). Primary entry for Kill Chain #1. |
| **GAP-009** | Shadow IT (Westside) | High | Ransomware, Opportunistic | #1, #3 | #1, #3 | **High** | Provides alternate entry point. Less frequent than primary gaps but critical for perimeter bypass. |
| **GAP-010** | No Vuln Management | Critical | Ransomware, Opportunistic | #1, #5 | #1 | **Critical** | Root cause of GAP-008. Systemic failure ensuring repeat exploitation. |
| **GAP-011** | Physical Security | High | Insider, Opportunistic | #5 | #2 (secondary) | **Medium** | Lower priority. Digital vectors are more prevalent per threat data. Physical access is harder to achieve remotely. |
| **GAP-012** | Endpoint Protection Gaps | High | Ransomware, Insider | #1, #2, #5 | #1, #2 | **High** | Helps detect post-compromise (EDR). Critical for stopping lateral movement but secondary to network controls. |
| **GAP-013** | Unencrypted Data in Transit | High | Ransomware, Vendor | #1, #4 | #1, #3 | **High** | Facilitates credential interception. Important but less urgent than authentication/network segmentation. |
| **GAP-014** | No Account Lifecycle | Critical | Insider, Vendor | #4, #5 | #2, #3 | **Critical** | Directly enables Scenario 2 and 3. Post-departure access is a high-probability vector per threat intel. |
| **GAP-015** | DMZ Misconfiguration | High | Ransomware, Opportunistic | #1, #4 | #1, #3 | **High** | Allows pivot from web server to internal network. Critical for Kill Chain #1 initial phase. |
| **GAP-016** | No DLP Controls | High | Insider, Vendor | #2, #4 | #2, #3 | **High** (Upgraded) | Primary enabler for data theft scenarios. Often underestimated until exfiltration occurs. |
| **GAP-017** | No Change Management | Medium | Vendor, Insider | #4, #5 | #3 | **High** (Upgraded) | Enabled hidden backdoors in Scenario 3. Critical for supply chain integrity. |

---

## Re-Prioritized Gap List (Threat-Informed)

| Rank | Gap ID | Gap Title | Updated Risk | Priority Rationale |
|------|--------|-----------|--------------|--------------------|
| **1** | **GAP-001** | Flat Network Architecture | **Critical++** | Enables every attack path identified. Highest leverage for disruption. |
| **2** | **GAP-003** | No SIEM / Detection | **Critical++** | Without visibility, no chain can be broken mid-flight. |
| **3** | **GAP-004** | No MFA | **Critical++** | Neutralizes credential-based access used in 100% of chains. |
| **4** | **GAP-008** | Apache RCE Vulnerability | **Critical** | Active exploitation confirmed. Immediate containment required. |
| **5** | **GAP-005** | Backup Co-location | **Critical** | Determines survivability of ransomware attack. |
| **6** | **GAP-014** | No Account Lifecycle | **Critical** | Direct enabler of insider/vendor persistence scenarios. |
| **7** | **GAP-010** | No Vulnerability Management | **Critical** | Systemic root cause of unpatched entry points. |
| **8** | **GAP-002** | Active Compromise (Billing) | **Critical** | Ongoing breach requiring immediate remediation. |
| **9** | **GAP-007** | Medical Device Exposure | **Critical** | Unique patient safety risk requiring isolation. |
| **10** | **GAP-006** | No IR/DR/BCP | **Critical** | Limits recovery capability. |
| **11** | **GAP-016** | No DLP Controls | **High** | Primary enabler for data theft scenarios (beta/3). |
| **12** | **GAP-015** | DMZ Misconfiguration | **High** | Key pivot point for web-to-internal attacks. |
| **13** | **GAP-012** | Endpoint Protection Gaps | **High** | Necessary for post-compromise detection. |
| **14** | **GAP-009** | Shadow IT (Westside) | **High** | Alternate entry point. |
| **15** | **GAP-013** | Unencrypted Data in Transit | **High** | Credential interception risk. |
| **16** | **GAP-017** | No Change Management | **High** | Supply chain/backdoor risk. |
| **17** | **GAP-011** | Physical Security | **Medium** | Lower priority compared to digital vectors. |

---

## The Critical Three

The three gaps whose closure would disrupt the greatest number of attack paths are:

1.  **GAP-001 (Flat Network Architecture):** Disrupts **100%** of kill chains. If segmented, Kill Chain #1 (Ransomware) cannot pivot from web to DC. Kill Chain #2 (Exfil) cannot reach DB from workstation. Kill Chain #3 (IoT) cannot be reached from VPN. It is the single force multiplier.
2.  **GAP-003 (No SIEM / Detection):** Disrupts **100%** of kill chains. Even with segmentation, attackers will probe. With SIEM, Kill Chain #2 (Exfil) is flagged during bulk export. Kill Chain #4 (Vendor) is flagged by off-hours login. Without detection, we only know when we are hit.
3.  **GAP-004 (No MFA):** Disrupts **~80%** of kill chains. Blocks Kill Chains #2, #3, #4, and #5 entirely at the authentication step. Kill Chain #1 (Apache RCE) bypasses MFA via exploit, but MFA blocks credential stuffing/phishing which are more common entry vectors.

**Strategic Implication:** Investing $24,000 in these three controls ($8K Segmentation, $10K SIEM, $6K MFA) neutralizes the majority of risk in the first year, before full infrastructure overhaul.

---

## The Surprise

**Gap:** **GAP-017 (No Change Management Process)**  
**Original Rating:** Medium (Task 12/13)  
**Updated Rating:** **High** (Threat-Informed)

**What Changed:** Initially, I viewed Change Management as an administrative hygiene issue—a "nice to have" for operational stability. However, **Scenario 3 (Vendor Shadow)** and **Kill Chain #5 (Insider Negligence)** revealed it is a critical security control.
-   In **Scenario 3**, the attacker installed a hidden backdoor account that persisted indefinitely because there was no change management review to detect unauthorized account creation.
-   In **Kill Chain #5**, the overworked admin wrote a script with plaintext credentials because no process required security review of administrative tooling.

**Conclusion:** In a supply chain environment, vendor actions are indistinguishable from internal actions without a formal review process. Without Change Management, supply chain compromise (Task 5) is functionally permanent. This moves it from "Operational Best Practice" to "Security Control."

---

*Prepared by: Security Department*  
*References: Project 1x00 Gap Analysis, Task 6 Threat Actor Matrix, Task 10 Kill Chains, Task 14 Scenarios*
