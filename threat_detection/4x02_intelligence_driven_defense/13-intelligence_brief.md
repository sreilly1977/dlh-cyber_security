# Intelligence Brief - HEALTHBANE Campaign

**To:** Dr. Patricia Morales (CISO), MedDefense Leadership Board  

**Cc:** James Chen (SOC Lead), HC3 Sector Partners  

**From:** Steve - Cybersecurity Engineer, Threat Detection Team  

**Date:** 28 September 2026  

**Subject:** HEALTHBANE Campaign Assessment and Remediation Roadmap  

**Classification:** INTERNAL (MedDefense) / TLP:CLEAR (Sector Share)  

**Reference:** HC3-2026-HEALTHBANE-001, MD-2026-IR-0414-001  

---

## 1. Executive Summary

HEALTHBANE is a coordinated, multi-stage cyber campaign targeting US healthcare providers, characterized by credential harvesting, macro-enabled malware delivery, and data exfiltration via DNS tunneling. MedDefense experienced initial compromise during the first stage, with one employee likely submitting credentials to a fraudulent portal, though no follow-on exploitation has been confirmed. Peer organizations in the Midwest ISAC region faced more severe outcomes, with two entities sustaining full compromise including patient data theft via DNS tunneling. Our current detection posture relies heavily on indicator-based blocking and four newly developed YARA rules targeting operational signatures. However, significant behavioral detection gaps remain, particularly regarding macro execution and encrypted command-and-control channels. We assess the operator as a financially motivated mid-tier cybercrime group, distinct from state-sponsored APTs despite conflicting industry labels. Immediate action is required to block identified infrastructure, enforce macro policies, and enable multi-factor authentication across all endpoints. This brief details the adversary profile, technical breakdown, and prioritized recommendations to mitigate ongoing risk and close visibility gaps.

---

## 2. Adversary Profile

**Working Designation:** HEALTHBANE Campaign Operator  
**Aliases:** VITALSCORE (Commercial Cluster), APT-MEDAGENT (Researcher Hypothesis)  
**Motivation:** Financial Gain (Financially motivated mid-tier cybercrime)  
**Confidence:** MODERATE (Per HC3 Advisory §1.5)

| Attribute | Assessment | Rationale |
|-----------|------------|-----------|
| **Sophistication** | Mid-tier | Competent multi-stage pipeline but uses commodity tooling (PHPMailer, wkhtmltopdf); exposes kit via directory misconfiguration. |
| **Resources** | Modest | Operates on disposable VPS infrastructure; no evidence of zero-days or supply-chain access. |
| **Target Sector** | Healthcare | Hospital systems, billing services, insurance administrators (US focus, Midwest heavy). |
| **Persistence** | Operational Signatures | Tooling fingerprints and naming patterns persist longer than individual domains. |

**Critical Attribution Note:** The "APT" prefix in the researcher alias (APT-MEDAGENT) does not reflect evidence of state sponsorship found in this analysis. HC3 explicitly assesses the actor as financially motivated cybercrime. Industry clusters (VITALSCORE) indicate overlapping activity but do not confirm actor identity.

---

## 3. Campaign Analysis

The HEALTHBANE campaign operates through three distinct stages designed to escalate from credential theft to data exfiltration. MedDefense successfully intercepted the campaign after Stage 1, preventing Stage 2 and 3 progression within our environment.

| Stage | Activity | Status at MedDefense | Status at Sector Peers | Confidence |
|-------|----------|----------------------|------------------------|------------|
| **Stage 1: Credential Harvesting** | Spearphishing via lookalike domains; form-post capture of usernames/passwords. | **Likely Exposure** (dmarsh clicked, credentials likely submitted). | **Active** (100% of visible orgs affected). | HIGH |
| **Stage 2: Malware Delivery** | Compromised accounts sent macro documents (.docm) dropping executables. | **None Detected** | **Partial Success** (2 of 6 orgs compromised). | HIGH |
| **Stage 3: Data Exfiltration** | DNS TXT tunneling of patient/insurance records. | **Not Observed** | **Confirmed** (2 of 6 orgs exfiltrated). | HIGH |

**Timeline:**
*   **2026-04-05 – 2026-04-10:** Lure domain registration (Namecheap).
*   **2026-04-14 – 2026-04-16:** Primary phishing wave (MedDefense incident window).
*   **2026-04-16 – 2026-04-22:** Stage 2 deployment at peer orgs.
*   **2026-04-23 – 2026-04-26:** Stage 3 exfiltration at peer orgs.
*   **2026-04-25:** HC3 Sector Advisory published.
*   **2026-09-28:** Intelligence Brief delivered.

---

## 4. ATT&CK Mapping

Analysis of the campaign yields 30 mapped techniques, divided into directly observed evidence and inferred necessity based on the kill chain.

**Total Techniques:** 30  
**Observed (Direct Evidence):** 18 (60%)  
**Inferred (Logical Necessity):** 12 (40%)

**Key Observable Techniques:**
*   **Initial Access:** T1566.002 (Spearphishing Link), T1566.001 (Spearphishing Attachment).
*   **Execution:** T1059.005 (PowerShell/Script), T1204.001 (User Execution).
*   **Command & Control:** T1071.004 (DNS Application Layer), T1071.001 (Web Protocols).
*   **Exfiltration:** T1048.003 (Exfil Over Alternative Protocol).

**Detection Relevance:**
*   Observed techniques inform current IOC blocking and YARA rule development (Tasks 9-10).
*   Inferred techniques (Collection, Persistence, Lateral Movement) highlight where visibility is missing and guide gap closure priorities.

---

## 5. Detection Gap Assessment

Current defenses are heavily weighted toward signature-based IOCs. Behavioral gaps leave the organization vulnerable to variants that rotate infrastructure but maintain tactics.

**Gap Summary:** 53% of mapped techniques lack documented detection coverage (16 of 30 techniques).

| Priority | Gap Description | Impact | Mitigation Strategy |
|----------|-----------------|--------|---------------------|
| **Priority 1 (Observed + Not Detected)** | Macro Execution (T1059.005), Scheduled Task Persistence (T1053.005) | Attacker gains foothold and hides presence. | Enable PowerShell Script Block Logging; Alert on Task Creation. |
| **Priority 1 (Observed + Not Detected)** | DNS Exfiltration (T1048.003) | Ongoing data loss via covert channel. | DNS query-length anomaly detection; block TXT to unknown domains. |
| **Priority 2 (Inferred + Not Detected)** | Lateral Movement (T1021), Valid Accounts (T1078) | Attacker moves freely post-compromise. | UEBA on authentication logs; enforce MFA everywhere. |
| **Priority 3 (Partially Detected)** | Phishing Links (T1566.002) | High volume alerts; alert fatigue possible. | Integrate YARA rules at mail gateway; enable URL detonation. |

---

## 6. Indicator of Compromise Table

**Total Vetted Indicators:** 33 (Actionable + Contextual).  
**Noise Filtered:** 15 (CDN/Shared IPs excluded per Task 1 triage).

| Phase | Type | Indicator | Confidence | Recommended Action |
|-------|------|-----------|------------|--------------------|
| **Stage 1** | Domain | `meddefense-portal.com`, `medequip-supplies.net`, `meddefense-benefits.org` | HIGH | BLOCK |
| **Stage 1** | Domain | `outlook-protection.com`, `healthbane-c2.net` | HIGH | BLOCK |
| **Stage 1** | IP | `91.234.99.107`, `185.176.43.22`, `164.90.218.73` | HIGH | BLOCK |
| **Stage 2** | File Hash | `a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456` (.docm) | HIGH | BLOCK |
| **Stage 2** | File Hash | `b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654` (.exe) | HIGH | BLOCK |
| **Stage 3** | Domain | `data-sync.healthbane-c2.net` | HIGH | BLOCK + SINKHOLE |
| **Stage 3** | IP | `51.38.42.191` (C2/Exfil Node) | HIGH | BLOCK |
| **Rotation** | Domain | `portal-secure-meddefense.com` | MEDIUM | MONITOR (Staged rotation domain) |

*Full indicator list maintained in `indicator_database.json`.*

---

## 7. YARA Rule Summary

Four operational rules have been developed and validated against the sample corpus. All rules achieved 100% true positive and 0% false positive rates in testing.

| Rule Name | Target Artifact | Test Result | Deployment Status |
|-----------|-----------------|-------------|-------------------|
| `HEALTHBANE_Phishing_PDF` | PDF Lure Documents | 100% Accuracy | **DEPLOY** |
| `HEALTHBANE_Email_Headers` | EML Email Headers | 100% Accuracy | **DEPLOY** |
| `HEALTHBANE_Document_Metadata` | PDF Metadata/Tooling | 100% Accuracy | **DEPLOY** |
| `HEALTHBANE_Campaign_Composite` | Cross-Family Correlation | 100% Accuracy | **DEPLOY** (High Severity) |

**Validation Note:** Rules include logic to survive common infrastructure rotation (tooling fingerprints vs. static URLs). False negatives from Task 11 were resolved by addressing separator tolerance in regexes and correcting PDF magic-byte checks.

---

## 8. Recommendations

### Immediate (≤48 Hours)
1.  **Block Identified Infrastructure:** Update perimeter firewalls and mail gateways to block the 8 HC3 domains and 6 IPs listed in Section 6.
2.  **Force Password Reset:** Reset credentials for `dmarsh` and all users who received campaign emails; invalidate active sessions.
3.  **Macro Policy Hardening:** Set Office macro policy to "Block All External Macros" via ATP policy.
4.  **DNS Firewall Rules:** Block DNS resolution for `*.healthbane-c2.net` and subdomain lengths >40 chars to DNS TXT.

### Short-Term (≤2 Weeks)
5.  **Deploy YARA Rules:** Integrate the four validated YARA rules into email gateway scanning (ClamAV hook) and endpoint scanning (scheduled task).
6.  **Enable Script Logging:** Roll out Group Policy for PowerShell Script Block Logging and Office Macro Event Logging.
7.  **MFA Enforcement:** Verify MFA enforcement on all remote-access entry points and mailboxes.

### Medium-Term (≤30 Days)
8.  **Behavioral Detection:** Implement SIEM rules for DNS tunneling anomalies and scheduled task creation ("Sync", "Update").
9.  **Threat Hunting:** Execute hunts for `HealthSync Update Service` tasks and registry Run key modifications.
10. **Brand Monitoring:** Procure service to monitor new domain registrations containing "MedDefense" or "MedEquip".

---

## 9. Intelligence Gaps and Collection Priorities

Despite high-confidence technical data, strategic gaps remain regarding the operator's ultimate reach and identity.

| Gap | Question | Priority | Owner/Data Source |
|-----|----------|----------|-------------------|
| **Operator Identity** | Who runs the operation beyond the pseudonym? | Low | Law Enforcement/Intel Partner |
| **Monetization Channel** | How is stolen data monetized? | Medium | Dark Web Monitoring |
| **Full Scope** | How many additional victims exist beyond the 14 reported? | High | Sector-wide Survey (HC3 coordination) |
| **Prior Activity** | Is the RXBRIDGE/CLAIMBRIDGE continuity hypothesis correct? | Medium | Threat Intel Vendor Query |
| **Internal Exposure** | Were credentials actually submitted, or just viewed? | High | PCAP Analysis (4x01 handoff) |

---
