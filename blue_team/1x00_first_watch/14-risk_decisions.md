# 14. The Risk Decisions
## Risk Treatment Strategy & Budget Allocation — MedDefense Health Systems

---

## Selected Gaps for Treatment (Top 7 by Priority)

| Gap ID | Title | Risk Level |
|--------|-------|------------|
| GAP-001 | Flat Network Architecture — No Segmentation | Critical |
| GAP-002 | Active Compromise on billing-srv-01 — Uncontained 14+ Days | Critical |
| GAP-003 | No Centralized Log Management or SIEM | Critical |
| GAP-004 | No MFA on Any System Except One Personal Account | Critical |
| GAP-005 | Backup Infrastructure — Single Point of Failure, No Offsite | Critical |
| GAP-007 | Medical Device Network Exposure — No Isolation for Life-Critical IoT | Critical |
| GAP-008 | Apache 2.4.29 Vulnerability — Known RCE, Exploited Twice | Critical |

---

## Risk Treatment Decisions

---

### GAP-001: Flat Network Architecture — No Segmentation

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Network segmentation is the single highest-leverage control MedDefense can implement. It directly constrains every other gap's blast radius — the billing-srv-01 compromise, the medical device exposure, the lateral movement risk — all are amplified by the flat network and all would be partially contained by segmentation. The FortiGate 100F already supports VLANs; this is primarily a configuration and switch-management effort, not a capital expenditure.

**Proposed Control(s):**
- Technical / Preventive (Compensating): VLAN segmentation on FortiGate 100F dividing 10.10.0.0/16 into isolated zones:
  - Server VLAN (10.10.2.0/24) — restricted inter-VLAN access
  - Medical Device VLAN (10.10.3.0/24) — strict ACLs, DICOM-only to PACS
  - Workstation VLAN (10.10.1.0/24) — restricted access to server VLAN
  - Management VLAN — IT admin systems only
  - Westside VPN VLAN — restricted to specific services
- Technical / Preventive: Inter-VLAN firewall rules on FortiGate permitting only required traffic flows (e.g., workstation VLAN to EHR on port 443 only; no direct workstation-to-database access)
- Technical / Preventive: Database access rules restricting PostgreSQL (5432) to ehr-srv-01 only and MySQL (3306) to billing application server only

**Estimated Cost:** $5,000–$10,000 (external network consultant for design + validation, internal IT labor for implementation, minor switch configuration changes)

**Implementation Effort:** Short-term (< 1 month) — requires coordinated change windows, testing of clinical application connectivity (especially DICOM, HL7, EHR), and careful validation that no clinical workflows break

**Expected Risk Reduction:** Significant. Segmentation converts a single-compromise-equals-total-compromise environment into compartmentalized zones. An attacker who breaches billing-srv-01 can no longer directly query ehr-db-01 or reach infusion pumps. Medical devices become isolated from general IT traffic. The billing-srv-01 attacker's blast radius shrinks from "entire network" to "server VLAN only." Estimated 60-70% reduction in lateral movement risk.

**Trade-offs:** Risk of disrupting clinical workflows if VLAN rules are too restrictive (e.g., blocking a required DICOM or HL7 connection). Requires careful testing and potentially a phased rollout. Some legacy applications may depend on flat-network connectivity that is not documented. Sarah Park's team will need to participate — coordination between security and IT operations is required despite the documented authority gap.

---

### GAP-002: Active Compromise on billing-srv-01 — Uncontained 14+ Days

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** This is not a future risk — it is an active, ongoing breach. No treatment strategy other than mitigation is appropriate for a confirmed, uncontained compromise. The attacker currently has unrestricted network access from a compromised server. Every day of delay increases the probability of lateral movement, data exfiltration, or escalation to ransomware.

**Proposed Control(s):**
- Administrative / Corrective: Execute incident response procedure (Task 2, IR Playbook): contain (isolate from network), investigate (forensic image, memory dump, Apache log review), eradicate (rebuild from known-good image), remediate (patch Apache to current version), recover (restore verified data), document (formal incident report)
- Technical / Preventive: Patch Apache to version 2.4.58+ on rebuilt server (also addresses GAP-008 for this server)
- Technical / Preventive: Disable SSH password authentication, migrate to key-based auth (extend Marcus's migration to billing-srv-01)
- Technical / Preventive: Restrict MySQL (port 3306) to localhost or application server IP only
- Technical / Preventive: Enable Apache mod_security with base rule set as compensating WAF
- Administrative / Corrective: Implement mandatory security review checklist for all server rebuilds (verify OS patched, application patched, SSH hardened, unnecessary services disabled before returning to production)

**Estimated Cost:** $2,000–$5,000 (internal labor for rebuild, forensic capture, reconfiguration; no hardware cost — existing VM infrastructure)

**Implementation Effort:** Quick Win (< 1 week) — must be executed immediately; billing downtime can be scheduled for overnight/weekend window with finance team coordination

**Expected Risk Reduction:** Eliminates the active compromise. Removes attacker foothold. Closes the Apache RCE entry point. Prevents further data exfiltration from billing server. Combined with GAP-001 segmentation, reduces future re-exploitation risk to near-zero for this vector.

**Trade-offs:** Billing system downtime during rebuild (estimated 4-8 hours). Finance team must coordinate claims batch processing around the maintenance window. Forensic investigation may reveal additional compromise scope requiring further remediation. If the attacker has already established persistence on other systems (unknown without investigation), rebuilding billing-srv-01 alone may not fully eradicate the threat.

---

### GAP-003: No Centralized Log Management or SIEM

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Without detection capability, MedDefense cannot identify breaches — as demonstrated by the 14-day cryptominer and the three real-world breaches (3 hours to 23 days of undetected dwell time). An enterprise SIEM at $80,000/year is not feasible within the $120,000 budget, but open-source Wazuh (which Marcus researched) provides SIEM and XDR capabilities at zero software cost, requiring only infrastructure to host it.

**Proposed Control(s):**
- Technical / Detective: Deploy Wazuh SIEM on a dedicated Linux VM (existing VMware cluster at Central) with the following log sources integrated:
  - FortiGate firewall logs (syslog forwarding)
  - Windows Server event logs (Wazuh agent on ad-dc-01, ad-dc-02, file-srv-01, pacs-srv-01, print-srv-01)
  - Linux server syslog (Wazuh agent on ehr-srv-01, ehr-db-01, billing-srv-01, backup-srv-01, web-srv-01)
  - Apache access/error logs on web-srv-01 and billing-srv-01
  - Active Directory change monitoring (new accounts, group membership changes, privilege escalations)
  - Sophos Central API integration for endpoint alerts
- Technical / Detective: Configure alerting rules for:
  - Outbound connections to known-bad IP ranges (mining pools, Tor exits, C2 infrastructure)
  - Failed login spikes (password spraying detection)
  - Off-hours access to EHR (behavioral anomaly)
  - New account creation in AD (especially privileged groups)
  - Process execution anomalies on Linux servers (masquerading detection)
  - Firewall configuration changes
- Administrative / Detective: Establish daily log review process (15-minute morning review by security analyst) for top alerts; weekly trend review

**Estimated Cost:** $5,000–$12,000 (dedicated VM storage allocation, Wazuh configuration consulting if needed, internal labor for deployment and tuning)

**Implementation Effort:** Short-term (< 1 month) — Wazuh can be deployed in 2-3 days; log source integration and alert tuning takes 2-3 weeks. Prioritized in phases: firewall + Linux servers first (highest risk), then Windows servers, then workstations.

**Expected Risk Reduction:** Transformative. Moves MedDefense from zero detection capability to centralized monitoring with automated alerting. Would have detected the billing-srv-01 cryptominer within hours (outbound connection to known mining pool IP + process anomaly). Enables proactive threat hunting and post-incident forensics with correlated timelines.

**Trade-offs:** Requires ongoing maintenance (alert tuning, false positive management). Wazuh requires Linux expertise to manage — Sarah's team has Linux skills (they manage 5 Ubuntu servers). Open-source SIEM lacks vendor support — issues must be resolved through community resources or internal expertise. Alert fatigue risk if rules are not properly tuned during initial deployment.

---

### GAP-004: No MFA on Any System Except One Personal Account

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** MFA is one of the highest ROI security controls available — it neutralizes credential theft, phishing, and password spraying attacks. MedDefense already pays $432,000/year for O365 E3, which includes Microsoft's built-in MFA (Azure AD Conditional Access) at no additional license cost. For VPN, Cisco Duo (now Cisco Secure Access by Duo) offers a free tier for up to 10 users and affordable pricing for larger deployments. Starting with privileged users and remote access provides maximum risk reduction per dollar.

**Proposed Control(s):**
- Technical / Preventive: Enable Azure AD Conditional Access MFA for all O365 accounts (included in existing E3 license). Phase 1: all IT staff, executives, and clinical department directors (~50 users). Phase 2: all staff (~2,000 users).
- Technical / Preventive: Deploy Duo MFA for VPN access (FortiGate supports Duo integration via RADIUS). Start with all VPN users (~220 HQ staff + remote-capable laptop users).
- Technical / Preventive: Enable MFA for FortiGate admin access (local administrator accounts)
- Administrative / Preventive: Update password policy (C-006) to mandate MFA for all remote access and privileged accounts. Update C-015 from "recommended" to "required."
- Administrative / Preventive: Communicate MFA rollout to staff with 2-week notice, provide setup instructions, set 14-day enrollment window with grace period.

**Estimated Cost:** $5,000–$8,000 (Duo licensing for ~250 VPN users at ~$3/user/month for 12 months = ~$9,000; Azure AD MFA is $0 with existing E3 license. Can reduce cost by using Microsoft Authenticator for both O365 and VPN via Azure AD NPS extension, eliminating Duo licensing entirely.)

**Implementation Effort:** Quick Win to Short-term (< 1 month) — Azure AD MFA can be enabled in 1 day for pilot group. VPN MFA requires FortiGate RADIUS configuration (2-3 days). Full org rollout with support takes 2-4 weeks.

**Expected Risk Reduction:** High. MFA would have prevented Breach 2 (Health Network Beta) entirely — the former employee's credentials would have been useless without the second factor. Neutralizes credential stuffing on patient portal (GAP-008 adjacent risk). Reduces phishing effectiveness — a stolen password alone no longer provides access. Estimated 80-90% reduction in credential-based attack success rate.

**Trade-offs:** User friction — staff must install authenticator app or use SMS (less secure). Clinical staff resistance likely (similar to "don't log out between shifts" culture). IT helpdesk will see increased password/MFA reset tickets during rollout. Some clinical workstations may lack smartphones for authenticator app — consider hardware tokens for key clinical roles (additional cost). SMS-based MFA is vulnerable to SIM swapping; authenticator app preferred.

---

### GAP-005: Backup Infrastructure — Single Point of Failure, No Offsite

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** The existing $14,400/year AWS S3 cloud replication quote (denied by CFO) represents the single most cost-effective insurance policy MedDefense can purchase. Breach 1 (Regional Hospital Alpha) demonstrated that co-located backups are destroyed alongside production in ransomware attacks — resulting in 11 days of downtime and $5M in total costs. The $14,400/year investment is 0.3% of the $5M Alpha lost. Additionally, a disaster recovery test must be performed to validate recoverability — untested backups are untrustworthy backups.

**Proposed Control(s):**
- Technical / Corrective: Implement Veeam cloud backup replication to AWS S3 (or Wasabi — S3-compatible, 80% cheaper) for all currently backed-up VMs. Configure immutable storage bucket (S3 Object Lock) to prevent ransomware from deleting/encrypting cloud backups.
- Technical / Corrective: Add pacs-srv-01, ad-dc-02, and ws-srv-01 to Veeam backup scope (currently excluded). PACS storage may require additional cloud storage capacity.
- Technical / Corrective: Conduct full disaster recovery test — restore each critical server from backup to isolated test environment, validate data integrity, document recovery time for each system. Establish RTO/RPO metrics for Board reporting.
- Administrative / Corrective: Draft disaster recovery plan documenting recovery procedures, prioritization order (EHR first, then AD, then billing, then file shares, then web), and assigned responsibilities.
- Administrative / Corrective: Establish quarterly backup verification testing schedule.

**Estimated Cost:** $14,400–$20,000/year (cloud storage replication: $14,400 for AWS S3 or ~$3,600 for Wasabi equivalent; additional storage for PACS backups: variable depending on image volume, estimate $5,000/year). One-time DR test labor: internal, no additional cost.

**Implementation Effort:** Short-term (< 1 month) — Veeam cloud replication can be configured in 1-2 days once cloud storage is provisioned. Adding servers to backup scope requires storage planning. DR test requires coordinated maintenance window (weekend).

**Expected Risk Reduction:** Eliminates the correlated failure scenario where ransomware destroys both production and backup simultaneously. Immutable cloud storage is not accessible to ransomware on the internal network. Provides a guaranteed recovery path even in worst-case ransomware scenario. DR test validates that backups actually work — converting "we hope they work" to "we know they work."

**Trade-offs:** Ongoing annual cost ($14-20K/year reduces available budget for other initiatives). Cloud restore speed depends on bandwidth — restoring terabytes of PACS data from cloud could take days without a direct-connect circuit. PACS backup may require significant additional storage capacity (images are large). DR test will require weekend downtime for IT staff and potentially for clinical systems (if testing restoration to production).

---

### GAP-007: Medical Device Network Exposure — No Isolation for Life-Critical IoT

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Medical devices represent the most direct path from cyber compromise to patient harm. Breach 3 (Community Hospital Gamma) demonstrated that attackers can reach infusion pump management consoles with default credentials, accessing patient names and medication data. The BD Alaris vendor security bulletin (18 months old) explicitly recommends network isolation as the primary mitigation. This is not a MedDefense invention — it is vendor-prescribed guidance being followed 18 months late. Much of the implementation overlaps with GAP-001 (VLAN segmentation), making this a marginal additional cost.

**Proposed Control(s):**
- Technical / Preventive (Compensating): Implement medical device VLAN (10.10.3.0/24) with strict ACLs as part of GAP-001 segmentation effort:
  - Permit DICOM (port 104/11112) from MRI/CT to PACS only
  - Permit HL7 from monitors/nurse call to EHR interface only
  - Block all inbound connections from workstation and server VLANs to medical devices
  - Block all outbound connections from medical devices except to PACS/EHR
- Technical / Preventive: Audit and change default credentials on all BD Alaris pump management consoles and Philips monitor interfaces (coordinate with biomedical engineering department)
- Technical / Detective: Deploy Wazuh agent or passive network sensor on medical device VLAN (part of GAP-003 SIEM deployment) monitoring for:
  - Unauthorized inbound connections
  - Default credential login attempts
  - Firmware version changes
- Administrative / Preventive: Establish medical device security policy requiring:
  - Vendor security bulletins reviewed within 30 days of publication
  - Network isolation documented for all new medical device deployments
  - Biomedical engineering included in security assessment for all medical device procurement
  - Annual medical device inventory reconciliation

**Estimated Cost:** $2,000–$5,000 (incremental to GAP-001 — additional ACL configuration, credential audit labor, policy drafting. Biomedical engineering time for credential changes is internal.)

**Implementation Effort:** Short-term (< 1 month) — VLAN creation is part of GAP-001. Credential audit requires coordination with biomedical engineering and may require vendor support for some devices. Policy drafting can be done in parallel.

**Expected Risk Reduction:** Critical. Eliminates the direct attack path from any compromised system to 120 infusion pumps and 80 patient monitors. Follows vendor-recommended mitigation for known CVEs. Addresses Breach 3's exact attack vector (medical device default credentials + network accessibility). Protects against the most severe potential outcome in the entire assessment: patient harm through medication dosage alteration.

**Trade-offs:** Some medical device management workflows may break if ACLs are too restrictive — vendor remote support sessions may require temporary firewall rule additions. Credential changes on medical devices may require vendor involvement (potential service fees). Biomedical engineering team may not have security expertise — requires training and collaboration. Some devices may not support credential changes at all (hardcoded credentials — would require network isolation as the only mitigation).

---

### GAP-008: Apache 2.4.29 Vulnerability — Known RCE, Exploited Twice

**Risk Level:** Critical

**Treatment Strategy:** Mitigate

**Justification:** Apache 2.4.29 has known RCE vulnerabilities (CVE-2021-41773, CVE-2021-42013) that have already been exploited twice on billing-srv-01. web-srv-01 runs the same version and is publicly accessible. Patching is free — the cost is purely labor. This is among the simplest, cheapest, highest-impact fixes available.

**Proposed Control(s):**
- Technical / Preventive: Patch Apache to version 2.4.58+ (or latest stable) on billing-srv-01 (during rebuild from GAP-002) and web-srv-01
- Technical / Preventive: Upgrade Ubuntu 18.04 on billing-srv-01 to Ubuntu 22.04 LTS or 24.04 LTS during rebuild (addresses OS EOL as well)
- Technical / Preventive: Enable mod_security with OWASP Core Rule Set on both web servers as compensating WAF control
- Technical / Detective: Add Apache log monitoring to Wazuh SIEM (part of GAP-003) with alerts for path traversal attempts and exploit signatures
- Administrative / Preventive: Implement monthly patch review schedule for all internet-facing systems; document patch SLA (critical patches within 7 days of release)

**Estimated Cost:** $1,000–$3,000 (internal labor for Apache patch, Ubuntu upgrade, mod_security configuration. No license or hardware cost.)

**Implementation Effort:** Quick Win (< 1 week) — Apache patch can be applied in a 2-hour maintenance window. billing-srv-01 Apache is upgraded during the rebuild (GAP-002). web-srv-01 patch is a standalone 2-4 hour window.

**Expected Risk Reduction:** Eliminates the specific vulnerability that has been exploited twice. Closes the entry point for both the January ransomware and the current cryptominer. Prevents web-srv-01 from becoming the next compromised server. mod_security provides defense-in-depth against future web application vulnerabilities.

**Trade-offs:** Apache upgrade may require application compatibility testing (billing application may not be compatible with newer Apache modules). mod_security may generate false positives that block legitimate billing traffic — requires tuning. Ubuntu OS upgrade on billing-srv-01 requires application reinstall/reconfiguration. Web-srv-01 patch may require coordination with marketing team (website downtime).

---

## Budget Summary

| Gap ID | Treatment | Estimated Cost (Year 1) | Implementation Window |
|--------|-----------|------------------------|----------------------|
| GAP-001 | Mitigate (Network Segmentation) | $8,000 | Month 1–2 |
| GAP-002 | Mitigate (Contain, Rebuild, Harden) | $3,500 | Week 1 (immediate) |
| GAP-003 | Mitigate (Wazuh SIEM) | $10,000 | Month 1–2 |
| GAP-004 | Mitigate (MFA — O365 + VPN) | $6,000 | Month 1–3 |
| GAP-005 | Mitigate (Cloud Backup + DR Test) | $17,000 | Month 1–2 (recurring $14K/year) |
| GAP-007 | Mitigate (Medical Device Isolation) | $3,500 | Month 2 (after GAP-001) |
| GAP-008 | Mitigate (Apache Patch + mod_security) | $2,000 | Week 1–2 (concurrent with GAP-002) |
| **Subtotal — Direct Mitigation** | | **$50,000** | |
| Contingency (15%) | | $7,500 | |
| **Total Year 1 Spend** | | **$57,500** | |
| **Remaining Budget** | | **$62,500** | |

---

## Deferred Items (Year 2 or as Budget Allows)

| Deferred Item | Estimated Cost | Rationale for Deferral |
|---------------|---------------|----------------------|
| **Enterprise Vulnerability Scanner** (GAP-010 — Nessus/Qualys) | $8,000–$15,000/year | Wazuh provides basic vulnerability detection in Year 1; dedicated scanner is valuable but not as urgent as containment and segmentation |
| **Server Endpoint Protection License** (GAP-012 — Sophos server tier or alternative EDR) | $3,000–$6,000/year | Wazuh agent provides process monitoring and FIM on Linux servers as interim detective control; dedicated EDR is the next enhancement |
| **iPad MDM Solution** (GAP-012 — Intune or Jamf) | $6,000–$12,000/year | Lower risk than unpatched servers; can be addressed in Year 2. Mitigated partially by MFA on O365 access |
| **Physical Security Upgrades** (GAP-011 — server room badge, cameras, locks) | $10,000–$25,000 | Network segmentation reduces the impact of physical access (attacker can't pivot from server room console as easily), buying time for physical upgrades |
| **Automated Account Lifecycle** (GAP-014 — HR/AD integration) | $5,000–$10,000 (development/integration) | Can be partially mitigated by manual monthly access review process using Wazuh AD monitoring alerts as a compensating detective control |
| **Penetration Testing** (validates control effectiveness post-implementation) | $15,000–$25,000 (one-time engagement) | Should be scheduled 3-6 months after mitigation implementation to validate effectiveness |
| **DLP Solution** (Data Loss Prevention for PHI export monitoring) | $15,000–$30,000/year | Higher cost; Wazuh file integrity monitoring and access logging provide partial detective capability in Year 1 |
| **Remaining Budget Available for Deferrals** | **$62,500** | |

---

## Recommended Allocation of Remaining $62,500

| Priority | Item | Cost | Justification |
|----------|------|------|----------------|
| 1 | Physical security: server room badge reader + lock + 2 cameras | $15,000 | Highest-risk physical gap; directly protects all critical servers |
| 2 | Enterprise vulnerability scanner (Nessus or Greenbone) | $10,000 | Validates that Apache-type vulnerabilities don't recur; systematic versus reactive |
| 3 | Server endpoint protection (Sophos server tier or alternative) | $6,000 | Detects malware on Linux servers that Wazuh may miss; would have caught the cryptominer |
| 4 | Penetration test (post-implementation, month 4-6) | $20,000 | Validates that the $50K investment actually reduced risk; provides Board assurance |
| 5 | Reserve / contingency | $11,500 | Unforeseen implementation costs, emergency remediation, or scope expansion |
| **Total Year 1 Allocation** | | **$120,000** | |

---

## Final Budget Summary

| Category | Amount | Percentage |
|----------|--------|------------|
| Immediate Containment & Remediation (GAP-002, GAP-008) | $5,500 | 4.6% |
| Network Segmentation & Medical Device Isolation (GAP-001, GAP-007) | $11,500 | 9.6% |
| Detection & Monitoring (GAP-003) | $10,000 | 8.3% |
| Authentication Hardening (GAP-004) | $6,000 | 5.0% |
| Backup & Recovery (GAP-005) | $17,000 | 14.2% |
| Physical Security (GAP-011 — partial) | $15,000 | 12.5% |
| Vulnerability Management (GAP-010 — partial) | $10,000 | 8.3% |
| Server Endpoint Protection (GAP-012 — partial) | $6,000 | 5.0% |
| Post-Implementation Validation (Pen Test) | $20,000 | 16.7% |
| Contingency Reserve | $11,500 | 9.6% |
| **Not Allocated / Deferred to Year 2** | $7,500 (from contingency rounding) | 6.3% |
| **Total** | **$120,000** | **100%** |

---

## Implementation Sequencing

| Phase | Timeline | Actions | Dependencies |
|-------|----------|---------|--------------|
| **Phase 1: Stop the Bleeding** | Week 1 | Isolate billing-srv-01 (GAP-002); patch Apache on web-srv-01 (GAP-008); enable Azure AD MFA for IT staff (GAP-004 pilot) | None — immediate |
| **Phase 2: Build the Foundation** | Weeks 2–4 | Deploy Wazuh SIEM with firewall + Linux server logs (GAP-003); rebuild billing-srv-01 from clean image with patches and hardening (GAP-002 completion); begin VLAN design (GAP-001) | Phase 1 complete |
| **Phase 3: Segment & Isolate** | Weeks 4–8 | Implement VLAN segmentation on FortiGate (GAP-001); configure medical device isolation ACLs (GAP-007); audit/change medical device default credentials | Phase 2 complete (Wazuh monitoring in place to detect segmentation issues) |
| **Phase 4: Protect & Recover** | Weeks 8–12 | Implement cloud backup replication to immutable storage (GAP-005); roll out MFA to all staff (GAP-004 completion); conduct DR test (GAP-005 completion) | Phase 3 complete (segmentation ensures backup traffic isolation) |
| **Phase 5: Validate & Harden** | Months 4–6 | Deploy vulnerability scanner (GAP-010); install server endpoint protection (GAP-012); implement physical security upgrades (GAP-011); commission penetration test | All prior phases complete |

---

## Risk Treatment Decision Summary

| Gap ID | Strategy | Cost | Timeline | Risk Reduction |
|--------|----------|------|----------|----------------|
| GAP-001 | Mitigate | $8,000 | Weeks 4–8 | 60–70% lateral movement risk reduction |
| GAP-002 | Mitigate | $3,500 | Week 1 | Eliminates active compromise |
| GAP-003 | Mitigate | $10,000 | Weeks 2–4 | Transforms from zero detection to centralized alerting |
| GAP-004 | Mitigate | $6,000 | Weeks 1–12 | 80–90% credential attack risk reduction |
| GAP-005 | Mitigate | $17,000 | Weeks 8–12 | Eliminates correlated backup failure; enables tested recovery |
| GAP-007 | Mitigate | $3,500 | Weeks 4–8 | Eliminates medical device attack path; follows vendor guidance |
| GAP-008 | Mitigate | $2,000 | Week 1–2 | Eliminates exploited vulnerability on two servers |

**Total Investment:** $50,000 of $120,000 budget allocated to direct gap mitigation. Remaining $70,000 allocated to complementary controls (physical security, vulnerability scanning, endpoint protection), post-implementation validation (penetration test), and contingency reserve.

**Strategic Principle:** Every dollar spent addresses a gap validated by real-world healthcare breach data (Task 13). The four highest-leverage investments — segmentation ($8K), SIEM ($10K), MFA ($6K), and offsite backups ($17K) — totaling $41,000, would have prevented or mitigated all three real-world breaches analyzed. The remaining $79,000 provides defense-in-depth, validation, and operational resilience.
