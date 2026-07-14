# The Threat Priority Assessment
## Definitive Ranking of Threats Against MedDefense Health Systems

**Date:** July 14, 2026  
**Classification:** CONFIDENTIAL – EXECUTIVE VERDICT  
**References:** Task 6 Actor Matrix, Task 10 Kill Chains, Task 14 Scenarios, Task 15 Gap Correlation  

---

## Top 5 Prioritized Threats

| Rank | Threat Description | Actor Type | Primary Vector | Primary Target | Likelihood | Impact | Overall Priority | Key Gap | Recommended Action |
|:----:|--------------------|------------|----------------|----------------|------------|--------|------------------|---------|--------------------|
| **1** | **Ransomware Deployment via Unpatched Entry & Lateral Movement** | Organized Crime (RaaS/BlackReef) | Exploitation of Public-Facing App (Apache RCE) + Phishing | EHR System (`ehr-srv-01`) + Domain Controllers (`ad-dc-01`) | **Critical**<br>Sector data: Healthcare is #1 target (Task 0). MedDefense has active vulnerability (billing-srv-01 exploit) + flat network (Task 15). | **Critical**<br>Asset: Core Clinical Ops.<br>Consequence: 14+ day downtime, $5M cost, patient safety risk (Task 14 Scenario 1). | **Critical++** | **GAP-001** (Flat Network)<br>*Enables lateral movement for every attack path.* | **Implement Network Segmentation**<br>(Short-term: Month 1-2).<br>Cost: ~$8K. Separates servers/workstations/IoT. Stops pivot to EHR. |
| **2** | **Mass PHI Data Exfiltration via Stolen Credentials** | Organized Crime / Insider Hybrid | Phishing (Credential Harvesting) or Abused Insider Access | EHR Database (`ehr-db-01`) | **High**<br>Sector data: 73% ransomware uses double extortion (Task 2). Insider threat: 35% of breaches (Task 0). | **Critical**<br>Asset: Patient Records (50k).<br>Consequence: HHS OCR Fine ($1.5M), Class Action ($890K) (Task 13 Benchmark). | **Critical** | **GAP-004** (No MFA)<br>*Neutralizes 90% of credential-based access.* | **Deploy Multi-Factor Authentication**<br>(Quick Win: Month 1).<br>Cost: ~$6K. Covers O365, VPN, Admin accounts. Blocks credential reuse. |
| **3** | **Medical IoT Device Manipulation (Patient Harm)** | Organized Crime / Opportunistic | Default Credentials + Flat Network Access | BD Alaris Pumps / Philips Monitors | **Medium**<br>Likelihood: Lower than ransomware. But exposure: 200 devices, known CVEs, unisolated (Task 7). | **Critical**<br>Asset: Life-Critical Systems.<br>Consequence: FDA Notification, Civil Liability, Loss of Life (Task 10 Kill Chain #3). | **High** | **GAP-007** (Medical Device Exposure)<br>*Requires isolation to mitigate patient safety risk.* | **Isolate Medical IoT VLAN**<br>(Short-term: Month 2).<br>Cost: ~$3.5K. ACLs prevent IT network reaching pumps. |
| **4** | **Supply Chain Backdoor via Vendor Access** | Organized Crime (Targeting Vendor) | Compromised Vendor Credentials (MedTech Solutions) | EHR Application Server (`ehr-srv-01`) | **Medium**<br>Trend: Increasing (SolarWinds precedent). MedTech access: Direct RDP to EHR (Task 5). | **High**<br>Asset: Core Application.<br>Consequence: Persistent backdoor, long-term exfil, contract litigation (Task 14 Scenario 3). | **High** | **GAP-014** (Account Lifecycle)<br>*Ensures vendor access is controlled and timed.* | **Implement Vendor Jump Host + MFA**<br>(Short-term: Month 2-3).<br>Cost: ~$10K. Forces vendor auth through secured gateway. |
| **5** | **Uncontrolled Data Export by Malicious/Negligent Insider** | Malicious Insider / Negligent Employee | Legitimate Access Abuse (EHR Export + USB) | Billing Data / Patient Records | **High**<br>Frequency: Highest. Negligence: 60% of insider incidents (Task 0). | **High**<br>Asset: Data Integrity/Confidentiality.<br>Consequence: Breach Notification, Reputation Damage (Task 14 Scenario 2). | **High** | **GAP-016** (No DLP)<br>*Detects bulk export and physical exfiltration.* | **Enable DLP Controls**<br>(Short-term: Month 3).<br>Cost: ~$15K (O365 included feature activation). Blocks bulk exports/USB. |

---

## Strategic Recommendation

If MedDefense could only fund **two** defensive initiatives in the next quarter, they must be **Network Segmentation (GAP-001)** and **Multi-Factor Authentication (GAP-004)**. Network segmentation is the single highest-leverage control because it physically breaks the kill chain for Ransomware, Insider, and Supply Chain attacks; even if an attacker penetrates the perimeter, they cannot reach the EHR database or Domain Controller without crossing an air-gap enforced by the firewall. Multi-Factor Authentication neutralizes the most common entry vector (credential theft via phishing, vishing, and password stuffing) which enables both External (Task 14 Scenario 1) and Internal (Task 14 Scenario 2) threats. While SIEM (GAP-003) is essential for detection, prevention via Segmentation and MFA stops the attack before it becomes a crisis, transforming a potential $5M catastrophe into a manageable security incident. Investing in these two controls first ensures that when the inevitable breach occurs, it remains contained rather than catastrophic.

---

*Prepared by: Security Department*  
*References: Task 15 Gap-Threat Correlation, Task 14 Threat Scenarios, Task 6 Actor Matrix, Task 2 BlackReef Profile*
