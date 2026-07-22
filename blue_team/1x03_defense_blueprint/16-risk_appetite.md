# 16. The Risk Appetite Debate

## Goal

Define MedDefense's risk appetite and demonstrate that risk acceptance is a legitimate, documented governance decision.

## Context

Not every risk is worth mitigating. Some risks cost more to fix than they cost if they happen. Some risks require accepting for operational reasons: the Windows XP MRI workstation cannot be replaced until the $2.1M scanner lease expires in 18 months. Accepting risk is not negligence. It is a governance decision made by an authorized person, documented, monitored and reviewed.

---

## PART 1 - RISK APPETITE STATEMENT

MedDefense Health Systems accepts that the delivery of healthcare inherently involves information security risk, and the Board authorizes operating within a residual risk tolerance of MEDIUM (inherent risk score of 12 or lower) for operational and financial risks where the annualized cost of mitigation exceeds the annualized loss expectancy. Risks to patient safety, including any scenario where a cybersecurity event could directly cause physical harm or death, represent an absolute limit: these risks must be mitigated to LOW regardless of cost, and acceptance is never permitted. Risks scoring 16 or higher (HIGH/CRITICAL) in any category require explicit CISO and CFO joint approval for acceptance, risks scoring 12-15 require CISO approval, and risks scoring 8-11 may be accepted by department directors with documented justification. All accepted risks are reviewed quarterly, and any KRI threshold breach on an accepted risk triggers immediate reassessment with Board notification.

---

## PART 2 - THE THREE DECISIONS

### Decision 1: Windows XP MRI Workstation

| Field | Value |
|---|---|
| **Risk** | RISK-006 (Medical device compromise disrupts patient care) |
| **Treatment Decision** | Accept |
| **Authority** | Chief Medical Officer with CISO concurrence. The CMO holds authority because the risk directly intersects patient care delivery and clinical equipment lifecycle management. The CISO concurs because the technical mitigation options are constrained by vendor support limitations and the segmentation architecture provides compensating controls. |
| **Justification** | The MRI scanner lease runs for another 18 months at a cost of $117,000/month ($2.1M total remaining). Replacement of the Windows XP workstation controlling the scanner requires vendor engineering, proprietary software redevelopment, and FDA recertification, with an estimated cost of $340,000. The ALE for medical device compromise is $1,200,000/year, but the realistic probability of targeted attack on this specific device is low (likelihood = 2) and the segmentation architecture isolates the device in the Medical Device Zone with no internet access and no path to clinical systems. The cost of mitigation ($340K) exceeds the residual ALE after segmentation ($240K calculated as likelihood 2 × impact 3 × ARO 0.4), making acceptance the rational economic decision for the remaining lease period. |
| **Compensating Measure** | Medical Device Zone isolation prevents lateral movement. No inbound connections from any zone except Management Zone via time-limited, CISO-approved vendor sessions. SIEM collects firewall logs for the medical device VLAN with alerting on any unexpected outbound traffic attempt. Vendor remote access is restricted to pre-scheduled maintenance windows with session recording. Monthly device inventory verification confirms no new devices added to the VLAN. |
| **Review Trigger** | (1) Discovery of active exploit code targeting this specific MRI model or Windows XP embedded systems in healthcare. (2) KRI breach: unauthorized connection attempt to or from the MRI workstation. (3) Lease expiration approaching within 6 months, triggering replacement planning cycle. (4) Any security incident on the Medical Device Zone, regardless of whether the MRI workstation is involved. |

---

### Decision 2: Accept Residual Risk of Cloud Misconfiguration Detection Latency

| Field | Value |
|---|---|
| **Risk** | RISK-008 (Cloud misconfiguration exposes patient data) |
| **Treatment Decision** | Accept (residual risk after CSPM deployment) |
| **Authority** | CISO. The CISO holds authority because this is a residual technical risk within the security program's architecture. The CFO was consulted and confirmed the cost of real-time remediation automation exceeds the remaining ALE. |
| **Justification** | The CSPM platform provides near-real-time detection of cloud misconfigurations (average alert time: 4 minutes). However, the planned automated remediation playbooks (auto-remediation of public storage buckets, auto-quarantine of over-permissioned IAM roles) require an additional $22,000 investment in workflow orchestration tooling and 3 months of development time. The residual ALE after manual remediation (average response time: 2 hours from alert to fix) is $89,000/year, compared to $15,000/year with automated remediation. The delta of $74,000 in ALE reduction does not justify the $22,000 tooling cost plus $15,000 development labor ($37,000 total) in Year 1, given competing budget priorities. Manual remediation with a 2-hour SLA from the security operations team represents acceptable residual risk. |
| **Compensating Measure** | CSPM alerts are routed to the SIEM with critical priority. Security operations team has a documented 2-hour response SLA for public storage bucket exposures. Default-deny IAM policies mean that even if a misconfiguration occurs, the default posture denies access. Quarterly cloud access reviews provide a backstop for configuration drift. IaC scanning in the CI/CD pipeline prevents most misconfigurations from reaching production in the first place. |
| **Review Trigger** | (1) Any cloud misconfiguration that goes undetected for more than 4 hours. (2) A publicly exposed storage bucket containing PHI, regardless of duration. (3) CSPM platform misses a misconfiguration that is later discovered through external reporting or breach notification. (4) Annual budget cycle when automation tooling costs can be reassessed. |

---

### Decision 3: Accept Risk of Legacy Fax Machine PHI Exposure

| Field | Value |
|---|---|
| **Risk** | RISK-005 (HIPAA violation due to unprotected PHI transmission) |
| **Treatment Decision** | Accept (partial: fax machine component only) |
| **Authority** | Compliance Officer with CMO concurrence. The Compliance Officer holds authority because this is a regulatory compliance decision with clinical workflow implications. The CMO concurs because fax machines remain operationally necessary for inter-facility patient transfers where the receiving facility lacks compatible electronic systems. |
| **Justification** | MedDefense operates 12 fax machines across three facilities, primarily used for urgent inter-facility patient transfers, prescription orders to external pharmacies, and insurance pre-authorizations. Replacing all fax machines with encrypted electronic fax solutions costs $48,000 (software licensing, hardware, integration, training) plus $12,000/year ongoing. The exposure factor for fax-based PHI breach is limited: faxes go to known medical facilities with dedicated fax lines, transmission is point-to-point over telephone lines (not internet-routed), and physical access to receiving machines is controlled. The estimated SLE for a fax-related breach is $40,000 (limited records, contained exposure) with an ARO of 0.3, yielding an ALE of $12,000/year. Mitigation cost ($48K upfront + $12K/year) exceeds ALE by 4x in Year 1 and equals ALE in subsequent years, making acceptance rational until natural workflow migration eliminates fax dependency. |
| **Compensating Measure** | All fax machines are located in secured areas with badge access logging. Fax confirmation receipts are retained for 6 years per HIPAA documentation requirements. A fax cover sheet with HIPAA confidentiality notice is mandatory on all transmissions. Fax numbers are verified against a maintained directory before sending. Monthly audit of fax usage logs identifies any anomalous transmission patterns. Encrypted electronic fax replacement is piloted in the billing department (highest fax volume) as a phased migration path. |
| **Review Trigger** | (1) Any fax-based PHI breach, regardless of scope. (2) HHS OCR announces enforcement action specifically targeting fax-based PHI transmission. (3) Inter-facility electronic health information exchange (HIE) integration reaches 80% of referral partners, eliminating the operational justification for fax. (4) Annual compliance audit identifies fax as a trending deficiency. |

---

## PART 3 - THE DEBATE

### James Chen, CISO — Argument for Mitigation

"The Windows XP MRI workstation is a ticking time bomb. We have active exploit frameworks publicly available for Windows XP that require minimal skill to deploy, and the healthcare sector is the most targeted vertical for medical device attacks. Segmentation reduces lateral movement risk but does nothing to prevent direct compromise of the device itself—if an attacker gains access through a vendor session or a USB drop by a social engineer, that device is instantly owned. The $340,000 mitigation cost sounds steep, but it pales against the $4.5 million average cost of a healthcare breach, the potential loss of life if diagnostic imaging goes down during an emergency, and the board liability if we knowingly operated an unsupported, unpatchable operating system on critical medical equipment. Accepting this risk sets a precedent that operational convenience overrides security fundamentals, and that is not a precedent I am comfortable setting."

### Robert Kim, CFO — Argument for Acceptance

"I am not suggesting we ignore the risk, I am suggesting we quantify it honestly. The MRI scanner lease costs $117,000 per month, and we cannot break that lease without a $630,000 early termination penalty, so the hardware is staying for 18 months regardless of what we do. The $340,000 mitigation cost James proposes is for vendor engineering and FDA recertification of a workstation that will be replaced when the lease expires anyway—that is sunk cost with zero residual value. Our segmentation architecture isolates this device completely: no internet access, no inbound connections, vendor access only through time-limited jump box sessions with recording. The realistic probability of targeted attack on this specific isolated device is negligible. Spending $340,000 to mitigate a $240,000 residual ALE is not responsible fiscal stewardship, it is security theater driven by fear rather than math."

### Verdict

Robert Kim's reasoning is more compelling on this specific issue, though James Chen raises legitimate concerns about precedent and worst-case scenarios. The economics are clear: spending $340,000 to mitigate a $240,000 residual ALE is not defensible, particularly when the asset has a hard 18-month retirement date and the segmentation architecture provides meaningful compensating controls. However, the acceptance must be conditional and time-boxed: the 18-month clock starts now, KRIs are monitored monthly, and the moment active exploit code targeting this specific device class emerges, the decision is revisited immediately. The CMO's authority to accept this risk is appropriate because it balances clinical operational reality with documented risk management. James Chen's concern about precedent is addressed by requiring that every future risk acceptance follows the same rigorous documentation, authority verification, and review trigger framework—ensuring that acceptance remains a governed decision, not a default position.
