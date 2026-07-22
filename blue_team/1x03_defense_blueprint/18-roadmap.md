# 18. The Roadmap

## Goal

Transform the strategy into a visual, dependency-aware implementation timeline.

## Context

A strategy document says "what." A roadmap says "when." The IT Director, Sarah Park, needs a document she can pin to the wall and track weekly: what happens first, what depends on what, who owns each milestone, and how she knows each phase is complete.

---

## MONTH-BY-MONTH BREAKDOWN

### Month 1: Quick Wins and Procurement

| Action | Responsible Owner | Dependencies | Completion Criteria |
|--------|-------------------|--------------|---------------------|
| Disable public RDP on billing-srv-01 | CTO (Network Engineering) | None — first action in the program | External port scan confirms TCP 3389 closed; billing staff validated on VPN access |
| Enforce account lockout policy via GPO | CISO (System Administration) | None | Test account locks after 5 failed attempts; gpresult confirms GPO applied on all critical servers |
| Enable Windows Firewall on all servers | CTO (Server Administration) | Asset inventory from 1x00 T7 | Get-NetFirewallProfile shows all 3 profiles enabled on 100% of servers; application owners confirm no service interruptions |
| Disable USB mass storage via GPO | CISO (Desktop Administration) | None | USB drive insertion blocked on sample workstations across all 3 sites; exception group functional for approved users |
| Audit and disable inactive AD accounts | CISO (IT Security Analyst) | HR confirms employment status for flagged accounts | All accounts inactive 90+ days disabled; service accounts reviewed and documented; monthly recurrence scheduled |
| Place procurement orders (EDR, SIEM, MFA, email gateway, CSPM) | CISO + CTO | Board budget approval signed | Purchase orders issued to all vendors; delivery dates confirmed in writing; vendor onboarding sessions scheduled |

### Month 2: Core Detection and Access Controls

| Action | Responsible Owner | Dependencies | Completion Criteria |
|--------|-------------------|--------------|---------------------|
| Deploy EDR agents across all endpoints | CISO (Security Operations) | EDR procurement delivered (Month 1) | Agent installed on ≥95% of endpoints per deployment report; console shows all agents checking in |
| Expand SIEM platform and configure log forwarders | CISO (Security Operations) | SIEM procurement delivered (Month 1) | SIEM ingesting logs from ≥10 sources (AD, firewalls, EDR, email, DNS, DHCP, servers, cloud, VPN, AV); 7-day stability test with no data gaps |
| Configure SIEM correlation rules and alert tuning | CISO (Security Operations) | SIEM log ingestion operational | 10 baseline correlation rules deployed; false positive rate <15% after 2-week tuning window |
| Begin MFA enrollment for all users | CISO (Identity Management) | MFA procurement delivered (Month 1); identity provider configured | 50% of users enrolled by end of Month 2; admin accounts 100% enrolled with FIDO2 tokens |

### Month 3: Access Hardening and Segmentation Preparation

| Action | Responsible Owner | Dependencies | Completion Criteria |
|--------|-------------------|--------------|---------------------|
| Complete MFA deployment across all systems | CISO (Identity Management) | 50% enrollment from Month 2 | 100% of users enrolled; MFA enforced on email, VPN, EHR, and all admin portals; access revoked for non-enrolled users past deadline |
| Activate email security gateway | CTO (Network Engineering) | Email gateway procurement delivered | Gateway processing all inbound/outbound email; DMARC reject policy enforced; sandbox detonation active; external email banners displayed |
| Finalize network segmentation design and order hardware | CTO (Network Engineering) | Segmentation design from T14 approved by CISO | Detailed VLAN and firewall rule documentation signed off; firewall hardware delivered and racked; cutover plan with rollback documented |
| Deploy DLP suite across email and endpoints | CISO (Security Operations) | DLP procurement delivered; PHI discovery scan complete (from RISK-005 C3) | DLP policies active on email gateway and ≥90% of endpoints; PHI content rules tuned; first week of alerts triaged and documented |

### Month 4: Segmentation Implementation, Phase 1

| Action | Responsible Owner | Dependencies | Completion Criteria |
|--------|-------------------|--------------|---------------------|
| Deploy perimeter firewall and configure VLANs | CTO (Network Engineering) | Firewall hardware delivered (Month 3); segmentation design approved | 5 VLANs active on core switches; inter-zone firewall rules loaded; existing connectivity maintained with no user-reported outages |
| Migrate billing-srv-01 to Server Zone | CTO (Server Administration) | Perimeter firewall operational; VLANs configured | billing-srv-01 reachable from Clinical WS Zone on approved ports only; no inbound from Guest/IoT Zone; billing application functional |
| Deploy jump box architecture in Management Zone | CISO (Security Operations) | Management Zone VLAN configured; MFA infrastructure operational | Jump boxes accessible only via VPN + MFA; session recording active; all admin access routes through jump boxes with PAM logging |
| Deploy immutable backup solution | CTO (Server Administration) | Backup hardware procured (Month 1) | Air-gapped backups configured for EHR and critical databases; first quarterly restoration test completed successfully within 4-hour RTO |

### Month 5: Segmentation Implementation, Phase 2

| Action | Responsible Owner | Dependencies | Completion Criteria |
|--------|-------------------|--------------|---------------------|
| Relocate clinical workstations to Clinical WS Zone | CTO (Network Engineering) | Server Zone migration complete (Month 4); firewall rules validated | All clinical workstations on 10.10.2.0/24; EHR access confirmed from nurse stations and physician desktops; no unauthorized inter-zone traffic in firewall logs |
| Isolate medical devices to Medical Device Zone | CTO + Chief Medical Officer | Clinical WS Zone operational; medical device inventory verified | All medical devices on 10.10.3.0/24; PACS DICOM traffic flowing to Server Zone only; no outbound internet from medical devices; MRI and infusion pumps operational with no clinical complaints |
| Deploy PAM with session recording | CISO (Security Operations) | Jump box architecture operational (Month 4); AD integration complete | All privileged accounts vaulted; just-in-time elevation functional; session recordings captured for 100% of admin sessions; credential rotation policy documented |
| Deploy CSPM platform across cloud subscriptions | CISO (Cloud Security) | Cloud admin access configured; API integrations complete | CSPM scanning all cloud resources; baseline configuration assessment complete; first remediation tickets generated for any findings |

### Month 6: Validation and Optimization

| Action | Responsible Owner | Dependencies | Completion Criteria |
|--------|-------------------|--------------|---------------------|
| Activate Guest/IoT Zone and migrate vendor access | CTO (Network Engineering) | All other zones operational; vendor access portal configured | Guest WiFi isolated; contractor laptops on Guest VLAN; vendor access through jump box only; no inbound traffic from Guest/IoT to any corporate zone in 7-day log review |
| Conduct third-party penetration test | CISO (External Vendor) | All segmentation zones active; all core controls deployed | Pen test report delivered; ≥70% of lateral movement attempts blocked; no critical findings open without remediation plan |
| False positive tuning on EDR and SIEM | CISO (Security Operations) | 30+ days of operational alert data | False positive rate reduced to <10%; alert-to-action time <15 minutes for critical alerts; tuning documentation complete |
| SOC 2 control validation audit | Compliance Officer | Evidence collection platform operational; all controls documented | Audit completed; zero critical findings; any minor findings have 30-day remediation plan; Type II audit scheduled for following year |
| Quarterly Board risk posture presentation | CISO | Risk register updated with residual scores; pen test results available | Board presentation delivered; risk register shows ≥50% inherent risk reduction; Year 2 priorities (UEBA, credential rotation) presented for preliminary budget discussion |

---

## DEPENDENCY CHAIN

The following three dependencies represent the most critical sequencing constraints. Failure to respect these dependencies will cause cascading delays across the entire roadmap.

### Dependency 1: SIEM Deployment → EDR Correlation → Alert Monitoring

SIEM platform expansion (Month 2) must be operational before EDR correlation rules can forward high-fidelity alerts (Month 2-3). EDR without SIEM correlation generates isolated alerts with no context. SIEM without EDR lacks endpoint telemetry. Both must be deployed and integrated before the security operations team can begin meaningful 24/7 monitoring in Month 3. If SIEM deployment slips beyond Month 2, EDR value is reduced by approximately 60% because analysts lack the cross-system correlation needed to distinguish true positives from noise.

### Dependency 2: Network Segmentation → Medical Device Isolation → Vendor Access Migration

Network segmentation (Month 4) must be completed before medical devices can be isolated to the Medical Device Zone (Month 5). The Medical Device Zone requires the Server Zone and Clinical WS Zone to be active first, because medical devices push DICOM images to PACS in the Server Zone and respond to queries from Clinical WS Zone workstations. If the Server Zone is not properly configured with the DICOM port 104 firewall rule, migrating medical devices will break imaging workflows. Similarly, vendor access migration to the Guest/IoT Zone (Month 6) requires the Management Zone jump box architecture (Month 4) to be functional, because vendors must access target systems through the jump box rather than direct network access.

### Dependency 3: MFA Infrastructure → Jump Box Architecture → PAM Session Recording

MFA deployment (Month 3) must be complete before jump box architecture (Month 4) can go live, because jump boxes require MFA authentication for all administrative sessions. PAM with session recording (Month 5) depends on the jump box being operational because PAM integrates with the jump box to capture privileged session video and keystroke logs. If MFA is delayed, jump box deployment is blocked, which blocks PAM, which leaves privileged access unrecorded through Months 4-5. This creates a window where administrators may be using direct access without session auditing, increasing insider threat exposure (RISK-003) precisely when the organization is most vulnerable during transition.

---

## MILESTONES

### Milestone 1: Quick Wins Complete

| Field | Value |
|-------|-------|
| **Target Date** | End of Month 1 (Week 4) |
| **Accomplished** | All 5 zero-cost security improvements implemented: public RDP disabled, account lockout enforced, server firewalls enabled, USB storage blocked, inactive AD accounts disabled. All procurement orders placed for core technology controls. |
| **Measurable Indicator** | 5/5 quick wins verified through technical testing (port scans, GPO application reports, USB insertion tests, AD account audits). All purchase orders confirmed with vendor delivery dates. Security Steering Committee receives first weekly status report showing green status on all quick win items. |
| **Significance** | Demonstrates immediate momentum to the Board before any capital expenditure. Reduces RISK-009 by 90%, RISK-004 by 40%, and RISK-001 by 25% at zero cost. Builds organizational confidence that the security program produces results, not just documents. |

### Milestone 2: Core Controls Operational

| Field | Value |
|-------|-------|
| **Target Date** | End of Month 3 |
| **Accomplished** | EDR deployed across ≥95% of endpoints. SIEM ingesting logs from ≥10 sources with correlation rules tuned. MFA enforced for 100% of users including FIDO2 for admins. Email security gateway active with DMARC enforcement. DLP policies deployed across email and endpoints. Network segmentation design finalized with hardware on site. |
| **Measurable Indicator** | EDR console shows agent check-in rate ≥95%. SIEM dashboard displays real-time log ingestion with <5% data gaps over 7-day window. MFA enrollment report shows 100% compliance, zero access exceptions. Email gateway reports phishing catch rate ≥90%. DLP alert queue triaged with <15% false positive rate. Penetration test of pre-segmentation environment completed as baseline. |
| **Significance** | The organization transitions from reactive to proactive detection capability. External attack surface for phishing and ransomware (RISK-001, RISK-004) reduced by approximately 60%. The security operations team has visibility into endpoint, network, email, and identity events for the first time. |

### Milestone 3: Segmentation Architecture Live

| Field | Value |
|-------|-------|
| **Target Date** | End of Month 5 |
| **Accomplished** | Five-zone network segmentation fully operational: Server Zone, Clinical WS Zone, Medical Device Zone, Management Zone, Guest/IoT Zone. All critical systems migrated to appropriate zones. Jump box architecture and PAM deployed. Immutable backups tested. CSPM monitoring cloud environment. |
| **Measurable Indicator** | Firewall logs show zero unauthorized inter-zone traffic over 14-day monitoring window. Medical devices operational with no clinical workflow complaints. PAM recording 100% of privileged sessions. Backup restoration test completed within 4-hour RTO. CSPM baseline scan complete with all critical findings remediated. |
| **Significance** | The flat network vulnerability (GAP-003) that amplified every kill chain in 1x01 is resolved. Lateral movement capability reduced by 72% across top 5 attack scenarios. Medical devices isolated from clinical and administrative networks. Vendor access fully controlled through jump box architecture. This is the single largest architectural risk reduction in the program. |

### Milestone 4: Validation and Board Reporting

| Field | Value |
|-------|-------|
| **Target Date** | End of Month 6 |
| **Accomplished** | Third-party penetration test confirms segmentation effectiveness. EDR and SIEM false positive rates below 10%. SOC 2 control validation audit completed. Risk register updated with residual scores. Board presentation delivered with measurable risk reduction metrics. |
| **Measurable Indicator** | Pen test report shows ≥70% of lateral movement attempts blocked. Zero critical pen test findings open without remediation plan. SOC 2 audit completed with zero critical findings. Risk register demonstrates ≥50% inherent risk reduction across top 10 risks. Board approves Year 2 budget priorities (UEBA, credential rotation, vendor assessments). |
| **Significance** | The security program has moved from strategy to verified implementation. Independent third-party validation confirms the controls work as designed. The Board has quantitative evidence that the $732,000 investment produced measurable risk reduction. Year 2 priorities are positioned for approval with clear justification from red team findings. |

---

## RISKS TO TIMELINE

### Risk 1: Procurement Delays from Vendor Lead Times

**Likelihood:** Medium-High  
**Description:** Enterprise security tools (EDR, SIEM, PAM, CSPM) typically have 2-6 week lead times from purchase order to delivery, plus additional time for vendor onboarding and licensing activation. If the Board delays budget approval beyond Week 1 of Month 1, or if vendors experience supply chain delays, procurement may slip past Week 4, pushing EDR and SIEM deployment from Month 2 into Month 3. This cascades into compressed tuning time, delayed segmentation (Month 4), and a rushed validation phase (Month 6).

**Contingency Plan:**
- Submit procurement requisitions during Week 1 of Month 1, before Board formal sign-off, using the CISO's emergency procurement authority for items under $50,000 (per existing delegation of authority). Large purchases (> $50K) require Board approval but can be pre-staged with vendors using letter of intent.
- If any vendor delivery slips beyond Week 2 of Month 2, implement a 30-day bridge using free or open-source alternatives: Wazuh (open-source SIEM/XDR) as interim detection, osquery for endpoint visibility, and ClamAV for basic malware defense. These are not permanent replacements but maintain detection capability during the delay.
- Compress the tuning window in Month 3 from 4 weeks to 2 weeks by dedicating 2 additional analysts to the effort, accepting a temporarily higher false positive rate (<25% vs target <15%) that is documented and communicated to the Security Steering Committee.
- If total delay exceeds 4 weeks, extend the roadmap by 1 month and notify the Board with revised milestone dates and an updated risk posture assessment showing the temporary exposure during the extended timeline.

### Risk 2: Segmentation Causing Clinical Service Interruption

**Likelihood:** Medium  
**Description:** Moving clinical workstations and medical devices to segmented VLANs carries the highest operational risk in the roadmap. If firewall rules block legitimate clinical traffic (e.g., EHR application using a non-standard port not identified during design, or PACS DICOM communication failing due to network path change), nurses and physicians lose access to patient records and imaging during active patient care. A clinical outage of even 30 minutes during peak hours could trigger patient safety incidents, executive escalation, and loss of confidence in the security program that jeopardizes the entire segmentation initiative.

**Contingency Plan:**
- Implement segmentation in a staged rollback-ready manner: migrate non-critical systems first (billing, administration) in Month 4, validate for 1 week, then migrate clinical systems in Month 5 with a clinical freeze window (weekend, low census period).
- Pre-stage rollback capability: firewall rules are deployed with an emergency disable switch (single CLI command or GPO disable) that restores flat network connectivity within 5 minutes. This switch is tested before clinical migration and documented in the runbook.
- Station a network engineer and application specialist at each site during clinical cutover with direct phone access to the CTO and CMO. If any clinical application fails, the rollback switch is executed immediately without requiring change management approval (emergency override pre-authorized by CMO).
- Conduct a full tabletop simulation of the cutover in Month 3 using the test environment, inviting clinical champions from nursing, radiology, and pharmacy to identify workflow dependencies that may not appear in technical documentation.
- If rollback is required, reschedule the clinical migration for 2 weeks later with corrected firewall rules. Do not attempt the same migration twice in the same week. Communicate transparently with clinical leadership about what failed and what was corrected.
