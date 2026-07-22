# 15. Red Team Your Blueprint

## Goal

Attack your own security strategy to find its weaknesses before an adversary does.

## Context

Every plan has blind spots. The best way to find them is to think like the attacker. In this task, you switch sides: you are no longer the security architect defending MedDefense. You are the BlackReef ransomware affiliate (from 1x01) who has read your Security Strategy Document and needs to find a way in despite the new controls.

---

## PART 1 - THE ATTACKER'S PERSPECTIVE

### Assumption: All Budget-Allocated Controls Are Fully Implemented

| Control Category | Status |
|------------------|--------|
| EDR/MDR Platform | Operational |
| SIEM Platform | Operational |
| MFA Everywhere | Enforced |
| Network Segmentation | 5 zones active |
| USB Blocked | GPO deployed |
| Account Lockout | Active |
| Host Firewalls | Servers protected |
| Immutable Backups | Tested quarterly |
| DLP Suite | Deployed |

Despite these investments, I as BlackReef affiliate still see openings. Here's why.

---

### Which of My 5 Kill Chains Is STILL Viable Despite New Controls?

**Kill Chain #4 (Insider Threat Exfiltration) remains HIGHLY VIABLE at 85% effectiveness.**

**Why?**

Segmentation, MFA, and EDR all protect against external attackers. They do nothing to stop a legitimate user with valid credentials accessing data they are authorized to see. The insider already has clearance. The EHR database knows they belong. The DLP rules trigger on volume but not on gradual exfiltration by authorized staff. The segmentation allows clinical access to patient records—which IS their job. This attack path exploits the gap between "authorized activity" and "malicious intent," a distinction technology alone cannot make reliably.

**Supporting Factors:**

- User Behavior Analytics (UEBA) is a Year 2 purchase, not included in Year 1 budget
- Data classification tagging is incomplete; DLP cannot block what it cannot identify
- Insider threat detection requires correlating HR termination data with access logs—a manual process we haven't automated
- A determined insider can exfiltrate over 6 months at 50 records per day, staying below alert thresholds

**Secondary Viable Kill Chain: #3 (Social Engineering USB Attack)**

Even with USB blocked at the OS level, the attack adapts:
- Print-to-file or screenshot exfiltration via legitimate clinical workflow
- Use of approved encrypted USB drives (exception group members) for staged transfers
- Photographing screens with personal phones (shadow IT, impossible to technically prevent)

This kill chain remains at **60% viability**.

**Least Viable Kill Chains:**
- #1 (Phishing → Ransomware): Reduced to 20% viability with MFA + EDR + segmentation
- #2 (RDP Brute Force): Reduced to 10% viability with public RDP removed + lockout policy
- #5 (Supply Chain Vendor): Reduced to 35% viability with segmentation + jump box

---

### Alternative Attack Path: Exploiting Deferred Controls

My recommended approach bypasses every implemented control by targeting the gaps I know you deferred to Year 2:

**Operation Silent Night – 5-Step Attack Sequence**

| Step | Action | ATT&CK Tactic | Why It Works Against Your Defenses |
|------|--------|---------------|-------------------------------------|
| **Step 1: Initial Access – Compromise Vendor Portal** | Target Greenfield Building Management (from 1x00 T8 third-party assessment). Their portal uses single-factor authentication. No MFA enforced. Phish their billing manager. | T1566 – Phishing; T1078 – Valid Accounts | Your controls protect MedDefense systems, not vendor infrastructure. Once I have vendor credentials, I enter through their authorized integration point into MedDefense. The vendor portal connection terminates in the Guest/IoT Zone, which then connects to Management Zone jump box for vendor maintenance. |
| **Step 2: Establish Foothold – Compromise Vendor Jump Box Session** | Wait for scheduled maintenance window. Vendor technician connects via approved portal. I intercept the session through their compromised credentials and maintain persistence on the jump box. | T1133 – External Remote Services; T1059 – Command Scripting | Your jump box architecture is sound, but you trust the vendor to manage their side of the handshake. I am now the vendor technician. Session recording captures everything, but you won't review it until AFTER the incident. |
| **Step 3: Lateral Movement – Escalate Through Management Zone** | From the jump box, pivot to PAM vault using credentials cached from previous sessions. Extract service account credentials used for EHR database maintenance. | T1528 – Steal Application Access Tokens; T1552 – Unsecured Credentials | The PAM vault stores service accounts with elevated privileges. Your Year 1 budget did not include PAM credential rotation automation. These credentials have not changed in 18 months. |
| **Step 4: Objective Execution – Deploy Ransomware via Scheduled Task** | Use service account to create a scheduled task on EHR database server that runs at midnight. Payload is signed with stolen developer certificate from your cloud dev environment (another deferred control gap). | T1053 – Scheduled Task; T1105 – Ingress Tool Transfer | The task runs with SYSTEM privileges. Your host firewall allows database traffic but blocks malicious executables only on known signatures. This payload is unsigned at deployment time, evading EDR until execution. |
| **Step 5: Impact – Encrypt Patient Records + Demand $2.5M** | Execute ransomware at 2 AM when backups run. Your immutable backup is offline and air-gapped, but the malware infects the backup server itself before the snapshot completes. Then delete shadow copies. | T1486 – Data Encrypted for Impact; T1490 – Inhibit System Recovery | You assumed offline backups were invulnerable. They are only invulnerable if disconnected BEFORE infection. My service account had access to the backup scheduling system because it was part of the original PAM vault extraction. |

**Total Viability Rating: 75%**

This attack works because it exploits trust relationships you designed but did not adequately monitor:
- Vendor trust → Jump box trust → Service account trust → Backup system trust

Each link is individually secure. The chain of trust is your vulnerability.

---

### Insider Threat Scenario That Remains Dangerous

**Scenario: "The Quiet Departure"**

A senior database administrator (DBA) with EHR system privileges decides to leave MedDefense for a competitor. They have 90 days notice before termination. During this period, they systematically extract patient records in batches that appear normal within their job scope.

**Why Existing Controls Fail:**

| Control | Intended Function | Why It Doesn't Stop This |
|---------|------------------|--------------------------|
| **MFA** | Prevents credential theft | DBA has legitimate credentials. MFA verifies the correct person is logging in. |
| **Segmentation** | Limits lateral movement | DBA access to EHR database is authorized. Segmentation permits this traffic. |
| **DLP** | Blocks bulk data exfiltration | DBA exports 20-30 patient records per day over 90 days = 2,700 total. Below alert threshold. |
| **Audit Logging** | Records access events | Logs show normal query patterns. No obvious anomaly without UEBA baseline comparison. |
| **SIEM** | Aggregates and correlates logs | No rule exists for "cumulative record access over 90-day period exceeds 2,000." |
| **PAM** | Restricts privileged access | DBA account has documented privilege elevation for database maintenance. PAM validates the role. |

**Exploitation Details:**

1. DBA creates custom SQL queries that look like routine health checks
2. Queries execute during business hours from their normal workstation in Clinical Workstation Zone
3. Results are saved to "temporary analysis" folder that gets auto-deleted weekly
4. Actual data is copied to encrypted local drive using BitLocker (allowed by policy)
5. Before resignation, drive is wiped and replaced with fresh hardware
6. No DLP alerts trigger because data never leaves approved channels
7. No EDR alerts because SQL queries are signed and trusted applications

**Timeline to Complete Exfiltration:**
- Days 1-30: Reconnaissance – understand data volume and query patterns
- Days 31-60: Slow exfiltration – 15-20 records/day, varying query times
- Days 61-90: Acceleration – 30-35 records/day, preparing to exit
- Total extracted: 2,100-2,400 patient records, including SSNs and financial data

**Estimated Financial Damage:**
- Regulatory penalty: $150-500K depending on breach notification
- Class action settlement: $2-5M estimated
- Reputational damage: 20-40% patient attrition in affected communities
- Contract losses: 2-3 enterprise customers require PHI audit after news breaks

---

## PART 2 - THE HONEST ASSESSMENT

### Overall Residual Risk Rating: HIGH

**Justification:**

I rate residual risk as HIGH rather than Medium because the implemented controls significantly reduce external attack surface but leave critical vulnerabilities exposed that sophisticated adversaries can exploit. The segmentation architecture, MFA enforcement, and EDR deployment collectively eliminate approximately 60% of external threat vectors. However, three gaps remain unaddressed:

1. **Insider Threat Detection Gap:** No automated UEBA, no cumulative access monitoring, no integration between HR and IT security. An insider with legitimate access remains 85% viable.

2. **Vendor Trust Chain Gap:** Vendor access flows through jump boxes but relies on vendor-side security posture and manual session review. A compromised vendor becomes a compromised entry point.

3. **Credential Rotation Gap:** Service account passwords are not rotated automatically. Stolen credentials have indefinite validity unless manually discovered and changed.

If I multiply the probability of successful insider threat (estimated 15% annually based on healthcare industry benchmarks) by the impact of 2,000+ patient records exposed ($5M+), I get an expected loss of $750K/year. Combined with the 35% viable supply chain attack path ($1.8M ALE from RISK-002), the total residual annualized loss expectation is approximately $1.1M.

This falls squarely in the HIGH category (>$500K annualized exposure) according to NIST SP 800-30 risk guidance.

---

### Single Biggest Remaining Gap

**Missing Automated User and Entity Behavior Analytics (UEBA) Integrated with HR Termination Workflows**

Without UEBA, you cannot:
- Detect abnormal access patterns for individual users (e.g., "Sarah normally accesses 50 records/day, suddenly 200")
- Correlate access spikes with business context (e.g., "Is this normal for month-end billing?")
- Automatically revoke access upon HR-confirmed termination in under 15 minutes
- Identify credential sharing (same user logged in from two geographic locations simultaneously)
- Flag accumulation of sensitive data access that stays below daily thresholds but exceeds monthly limits

The gap is particularly severe because:
1. It costs $30,000/year (included in Year 1 budget but deprioritized)
2. It takes 90 days to tune effectively once deployed
3. It requires log ingestion from Active Directory, EHR, DLP, PAM, and SIEM—all available but not correlated
4. It prevents the exact insider scenario described above where 2,400 records were exfiltrated undetected

This is the single investment that would convert HIGH residual risk to MEDIUM by closing the insider threat blind spot.

---

### #1 Priority for Next Year's Budget

**Investment: UEBA Platform with HR Integration ($35,000 initial + $30,000/year)**

**Justification:**

Next year's budget must prioritize closing the insider threat detection gap before any other expenditure. The rationale:

1. **Risk Reduction ROI:** At $750K expected loss from insider scenarios, a $35K investment provides 2,000% return on risk-reduction dollars invested.

2. **Compounding Benefits:** UEBA also detects compromised external accounts (phishing victims), identifies rogue administrator activity, flags credential sharing, and surfaces anomalous data access patterns. One tool addresses multiple risks simultaneously.

3. **Regulatory Defense:** HIPAA Security Rule §164.308(a)(1)(ii)(D) requires "information system activity review" including audit log review, alerts, and incident response mechanisms. UEBA satisfies this control more effectively than manual log review.

4. **Board-Level Narrative:** When James Chen presents to the Board next year, he can demonstrate measurable reduction in insider threat risk exposure from HIGH to MEDIUM with a specific dollar investment tied to quantifiable risk reduction.

5. **Implementation Readiness:** All prerequisite infrastructure (SIEM, AD logging, EHR audit trails, DLP alerts) is already in place from Year 1 spend. UEBA is purely an integration and analytics layer—no new hardware, no infrastructure overhaul.

**Alternative Consideration:**

If UEBA cannot be funded for any reason, the second-highest priority is **automated credential rotation for service accounts** ($15,000 platform + $5,000 labor). This eliminates the infinite-validity vulnerability exploited in Operation Silent Night and reduces supply chain attack viability from 35% to 15%. However, UEBA remains the superior choice because it addresses both insider AND external account compromise, while credential rotation only mitigates one vector.

---

### Final Recommendation to CISO Office

**Do not wait for perfect security.** The Year 1 controls have reduced external attack surface by approximately 60%. That is meaningful progress. However, the remaining 40% gap concentrates risk in three areas: insider threat, vendor trust, and stale credentials. Of these, insider threat represents the highest probability × highest impact combination.

Approve UEBA procurement in Q2 of Year 2. Begin vendor security posture assessments in parallel (Q3). Automate service account rotation by end of Year 2.

If an attacker reads this document, they will know the same thing: your strongest defenses are in place, but your weakest link is human behavior, not technical controls. The attacker who succeeds will be the one who exploits the people gap, not the firewall gap.

Make sure that gap closes before anyone else finds it first.
