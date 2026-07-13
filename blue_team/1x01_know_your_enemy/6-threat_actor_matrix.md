# MedDefense Threat Actor Matrix
## Consolidated Threat Prioritization Reference

**Date:** July 13, 2026  
**Classification:** CONFIDENTIAL – EXECUTIVE REVIEW  
**Prepared For:** Board of Directors, MedDefense Health Systems  

---

## Threat Actor Matrix

| Actor Type | Likelihood | Capability | Primary Motivation | Preferred Vector | Primary Target | MedDefense Exposure (Gap IDs) |
|------------|------------|------------|--------------------|------------------|----------------|-------------------------------|
| **Ransomware Groups (Organized Crime)** | **Critical** | High (RaaS infrastructure, custom malware, affiliate networks) | Financial Gain (Ransom + Data Sale) | Phishing, Exploiting Public-Facing Apps (CVEs) | EHR System (`ehr-srv-01`), Domain Controllers | GAP-001 (Flat Network), GAP-003 (No SIEM), GAP-004 (No MFA), GAP-005 (Backup Isolation), GAP-008 (Apache RCE) |
| **Nation-State APT** | **Low** | Very High (Zero-day exploitation, custom stealth tools, long dwell) | Espionage, Intellectual Property Theft, Geopolitical Advantage | Spear Phishing, Supply Chain Compromise, Zero-Day Exploits | R&D Data (None), EHR (Secondary) | GAP-003 (No SIEM), GAP-004 (No MFA). Low exposure as MedDefense has no high-value IP. |
| **Insider (Malicious)** | **Medium** | Low/Medium (Knowledge of systems, valid credentials) | Revenge, Financial Gain (Data Sale), Sabotage | Credential Abuse, Data Exfiltration, Privilege Abuse | Patient Records (PHI), Financial Data | GAP-014 (Account Lifecycle), GAP-016 (No DLP), GAP-003 (No Behavioral Monitoring) |
| **Insider (Negligent)** | **High** | Low (Human error, workflow shortcuts, lack of training) | Convenience, Carelessness, Workflow Efficiency | Phishing Clicks, Shared Credentials, Shadow IT, Lost Devices | Any Asset (EHR, Email, Mobile Devices) | GAP-007 (Shared Logins), GAP-009 (Shadow IT), GAP-004 (No MFA), GAP-017 (Change Mgmt) |
| **Hacktivist** | **Low** | Low/Medium (DDoS scripts, website defacement tools) | Ideological Protest, Political Messaging, Disruption | DDoS, Website Defacement, Social Media Campaigns | Patient Portal (`web-srv-01`), Public Website | GAP-008 (Apache RCE), GAP-013 (Encryption Gaps). Low interest as MedDefense is not politically controversial. |
| **Unskilled/Opportunistic Attacker** | **High** | Low (Automated scripts, public exploits, credential stuffing) | Financial Gain (Crypto Mining, Bulk Data Theft), Chaos | Automated Vulnerability Scanning, Credential Stuffing, Default Credentials | Public-Facing Servers (`web-srv-01`, `billing-srv-01`) | GAP-008 (Apache RCE), GAP-001 (Flat Network), GAP-014 (Default/Vendor Passwords) |

---

## Top 3 Priority Ranking

### 1. Ransomware Groups (Organized Crime)
**Ranking Justification:** Ransomware poses an **Existential Risk** to MedDefense, warranting the #1 priority. Sector data (Task 0 & 2) confirms healthcare is the #1 target sector for ransomware (25% of all critical infrastructure incidents), with a **Critical** likelihood rating specific to our profile (mid-size hospital, cyber insurance, clinical urgency). The potential impact is catastrophic: three comparable regional hospitals were hit within 200 miles in 8 months. A successful attack would result in immediate operational paralysis (averaging 18 days downtime per industry benchmark), potential regulatory fines exceeding $1M, and reputational damage that could permanently impair patient trust. Our current exposure (GAP-001, 003, 005, 008) provides a direct, unblocked path for this threat to achieve its goals. Mitigation of this vector is not optional; it is survival.

### 2. Insider Threat (Negligent)
**Ranking Justification:** Insider negligence represents the **highest frequency risk** (Task 0 cites 35% of healthcare breaches involve insiders, split 60/40 negligent/malicious). While the individual impact per event is lower than ransomware, the cumulative frequency creates constant attrition. Common scenarios include phishing clicks (unlocking ransomware), shared credentials (eliminating accountability), and shadow IT (creating unmanaged data stores). Because clinical workflows require broad access to sensitive data, the balance between usability and security is precarious. Our lack of behavioral monitoring (GAP-003) and DLP controls (GAP-016) means these incidents are invisible until after damage is done. Addressing this requires continuous training and technical controls (MFA, DLP) rather than one-time fixes, making it a sustained management priority.

### 3. Unskilled/Opportunistic Attacker
**Ranking Justification:** This actor type warrants #3 priority because they serve as the **primary delivery mechanism** for the #1 threat (Ransomware). Proof of existence is already present in our environment: the `billing-srv-01` cryptominer was installed via automated scanning of unpatched vulnerabilities (Task 1). These actors do not need to target MedDefense specifically; they scan the entire internet for known CVEs (like our Apache vulnerability in GAP-008) and deploy exploits indiscriminately. Their capability is low, but their volume is infinite. If left unchecked, they act as the "front door" for more sophisticated actors (like RaaS affiliates) to purchase initial access from brokers. Fixing this is technically straightforward (patching, segmentation) but critically important to harden the perimeter before the next automated scan finds us.

---

**Strategic Implication:** The Board must prioritize funding that directly reduces exposure to these top three actors. Specifically, closing GAP-001 (Segmentation), GAP-003 (SIEM), GAP-004 (MFA), and GAP-008 (Patch Management) simultaneously addresses the primary vectors for all three prioritized threats. This is not a menu of options; it is a cohesive defense stack.

---

*Prepared by: Security Department*  
*References: Task 0 (Threat Intel), Task 1 (Taxonomy), Task 2 (Ransomware), Task 16 (Posture Assessment)*
