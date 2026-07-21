# 1. The NIST CSF Mapping
## Current Profile Assessment for MedDefense Health Systems

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 1)  
**Reference:** NIST CSF 2.0 (February 2024), NIST CSF Reference Summary (provided)

---

## Executive Summary

This document defines MedDefense's **Current Profile** against the NIST CSF 2.0 six core functions. This profile is derived from empirical evidence collected across Projects 1x00 (Security Posture), 1x01 (Threat Landscape), and 1x02 (Vulnerability Assessment). It serves as the baseline for measuring progress and defining the Target Profile for the 6-month roadmap.

No function achieves "Managed" or higher. Five of six functions are rated "Partial," reflecting informal, inconsistent, or incomplete activity. The Detect function is rated "Not Implemented" due to the total absence of monitoring and alerting capability confirmed by Marcus's onboarding notes and the undetected cryptominer on billing-srv-01.

---

## Function 1: Govern (GV)

**Function Description:** Establish, communicate, and monitor the organization's cybersecurity risk management strategy, expectations, and policy.

| Attribute | Assessment |
|-----------|------------|
| **Current Level** | **Partial** |
| **Evidence** | 1x00 Task 0 established the first formal security budget ($120K) based on threat landscape analysis, demonstrating leadership awareness. 1x01 Threat Landscape Report was briefed to the Board, indicating engagement. However, no formal cybersecurity strategy document existed prior to this project. Roles are informally assigned (Sarah Park as Deputy CISO, one security analyst). No formal Risk Appetite Statement. No supply chain risk management process. Policy exists only as fragments (AUP from HR, partial password policy from IT). No scheduled Board security reporting cadence. |
| **Key Gaps** | No documented cybersecurity strategy or charter. No formal risk register. No defined risk appetite or tolerance levels. Cybersecurity supply chain risk management is absent (vendor security not assessed during Westside Clinic router procurement or BD Alaris pump purchase). No oversight cycle for reviewing and updating security activities. |
| **Target Level (6 Months)** | **Managed**. Within 6 months MedDefense should have a written cybersecurity charter approved by the Board, a formal risk register maintained by the Security Department, quarterly Board reporting on CSF maturity, and documented role assignments for all security functions. Supply chain risk assessment should be incorporated into vendor procurement for Tier 1 assets. |

---

## Function 2: Identify (ID)

**Function Description:** Understand the organization's current cybersecurity risks.

| Attribute | Assessment |
|-----------|------------|
| **Current Level** | **Partial** |
| **Evidence** | 1x00 Task 2 Asset Registry was created *during* this project, meaning no comprehensive asset inventory existed before arrival. The registry covered 47 scanned hosts but excluded approximately 280 clinical workstations and an unknown number of medical IoT devices. 1x02 Task 16 identified Shadow IT device at 10.10.2.99 running undocumented Grafana instance, proving asset discovery is incomplete. 1x02 Task 15 Medical IoT Assessment could only estimate the number of Philips monitors (~15) rather than confirm exact count. No software license inventory exists. No data flow mapping has been completed. Risk assessment was performed as part of 1x00 (criticality matrix) and 1x02 (vulnerability assessment) but no ongoing risk assessment process exists. |
| **Key Gaps** | No continuous asset discovery mechanism. Medical IoT inventory incomplete. No software asset inventory or license tracking. No data flow mapping. No third-party or vendor risk inventory. No formal risk assessment cycle (the 1x00-1x02 assessments were one-time efforts, not recurring). Lessons learned from the billing-srv-01 cryptominer incident have not been formally documented. |
| **Target Level (6 Months)** | **Managed**. Within 6 months MedDefense should have a complete asset inventory including all medical IoT, automated discovery tooling deployed, data flow maps for critical systems, and a quarterly risk assessment cycle tied to the vulnerability management process from 1x02 Task 23. |

---

## Function 3: Protect (PR)

**Function Description:** Use safeguards to manage cybersecurity risks.

| Attribute | Assessment |
|-----------|------------|
| **Current Level** | **Partial** |
| **Evidence** | 1x02 Task 20 Priority Matrix shows 9 critical vulnerabilities unpatched including CVSS 9.8 RCE on billing-srv-01. 1x00 GAP-001 confirms flat network architecture with no segmentation. 1x02 Task 12 confirms 3 EOL systems (Windows XP MRI, Server 2012 R2 print server, Ubuntu 18.04 billing server) running without patches. 1x02 Task 15 confirms BD Alaris pumps using default credentials (admin/admin). 1x02 Task 10 confirms no MFA deployed anywhere. 1x02 Finding 009 confirms SSH password authentication on billing-srv-01. 1x02 Finding 007 confirms LDAP signing not required. Basic antivirus (Sophos) deployed but failed to detect active cryptominer. No secure configuration baselines applied. No network segmentation between medical devices and general computing infrastructure. No data encryption at rest on NAS or database servers. No formal security awareness training program. |
| **Key Gaps** | Network segmentation is the single most critical protective gap (GAP-001), amplifying every vulnerability by 6.6x to 12.0x per 1x02 Task 14. No patch management process. No MFA. No secure configuration baselines. No data encryption. No medical device hardening. No access control hardening (SSH, LDAP, database bindings). No security awareness training. |
| **Target Level (6 Months)** | **Managed**. Within 6 months MedDefense should have completed the Immediate and Short-Term remediations from 1x02 Task 20 (9 critical and 6 standard findings patched), deployed network segmentation for medical devices (Medical Device VLAN), enabled MFA on all O365 and VPN access, applied CIS Benchmark Level 1 baselines to critical servers, and launched a security awareness training program for all staff. |

---

## Function 4: Detect (DE)

**Function Description:** Find and analyze possible cybersecurity attacks and compromises.

| Attribute | Assessment |
|-----------|------------|
| **Current Level** | **Not Implemented** |
| **Evidence** | Marcus's onboarding notes explicitly state "zero monitoring capability." 1x00 GAP-003 confirms no SIEM, no centralized logging, no network anomaly detection, no endpoint detection and response. 1x02 Task 1 confirms active cryptominer on billing-srv-01 went undetected for 14+ days, proving that no detection controls functioned. 1x02 Task 4 confirms no IPS/IDS to detect exploitation of Apache RCE or Ghostcat. No Windows Event Log forwarding configured (Finding 021). No file integrity monitoring on any server. No database activity monitoring on ehr-db-01. No network traffic analysis on the flat network. No 24/7 monitoring capability. No alerting infrastructure. No incident detection playbooks. |
| **Key Gaps** | Complete absence of detection capability. This is the most severe function-level deficiency in the organization. No SIEM means no log correlation. No IDS means no network-level detection. No EDR means no endpoint-level detection. No file integrity monitoring means no detection of configuration changes or rootkit installation. The cryptominer compromise proves that active attacks succeed without detection indefinitely. |
| **Target Level (6 Months)** | **Partial**. Within 6 months MedDefense should deploy a centralized syslog collector for all critical server logs (open-source syslog-ng as interim SIEM), deploy Zeek network sensor on Medical Device VLAN, configure Windows Event Log forwarding from domain controllers, and deploy AIDE file integrity monitoring on billing-srv-01. Full SIEM with 24/7 monitoring is a 12-18 month goal exceeding the 6-month window given staffing constraints. |

---

## Function 5: Respond (RS)

**Function Description:** Take action regarding detected cybersecurity incidents.

| Attribute | Assessment |
|-----------|------------|
| **Current Level** | **Not Implemented** |
| **Evidence** | No incident response plan exists. 1x02 Task 19 identifies an active compromise on billing-srv-01 but no formal IR activation has occurred. No documented incident response procedures. No defined roles for incident triage, escalation, or resolution. No forensic analysis capability (Marcus noted no forensic tools or training). No communication procedures for breach notification to HHS OCR under the HIPAA Breach Notification Rule. No tabletop exercise has been conducted. No retainer with an incident response firm. The active cryptominer on billing-srv-01 demonstrates the response gap: the compromise was discovered during a vulnerability scan, not through incident response processes, and no containment actions have been taken. |
| **Key Gaps** | No incident response plan. No defined incident severity levels or escalation procedures. No forensic capability. No breach notification process. No IR firm retainer. No tabletop exercise history. The organization cannot respond to an incident because no response framework exists. The billing-srv-01 compromise is a live demonstration of this gap: the incident was detected (during scanning) but has not been responded to (no containment, no forensic preservation, no eradication). |
| **Target Level (6 Months)** | **Partial**. Within 6 months MedDefense should have a documented incident response plan aligned to NIST SP 800-61, defined incident severity levels and escalation matrix, a retainer with a third-party IR firm for surge capacity, at least one tabletop exercise completed with clinical operations participation, and a documented breach notification process for HHS OCR compliance. |

---

## Function 6: Recover (RC)

**Function Description:** Restore assets and operations affected by cybersecurity incidents.

| Attribute | Assessment |
|-----------|------------|
| **Current Level** | **Partial** |
| **Evidence** | Backups exist on NAS-01 (Synology DSM 7) containing server backups, database dumps, and configuration archives. However, 1x02 Task 9 OSINT Hunt identified CVE-2023-1383 (CVSS 9.8) on the NAS, meaning the backup infrastructure itself is vulnerable to compromise. 1x02 Task 15 confirms NAS is on the flat network, meaning ransomware could reach and encrypt backups. No documented recovery procedures. No backup testing or restoration verification. No business continuity plan. No defined RTOs or RPOs for critical systems. No isolated backup network. The presence of backups indicates awareness of recovery need, but the lack of testing, isolation, and documentation makes recovery capability unverified. |
| **Key Gaps** | Backup infrastructure is vulnerable (CVE-2023-1383 on NAS). Backups are not isolated from production network (flat network). No backup restoration testing. No business continuity plan. No disaster recovery plan. No defined RTO/RPO for EHR, billing, or critical clinical systems. No alternative processing site. No communication plan for recovery activities. |
| **Target Level (6 Months)** | **Managed**. Within 6 months MedDefense should have isolated the NAS on a backup VLAN, upgraded DSM to patched version, completed at least one full backup restoration test for EHR and billing systems, documented recovery procedures for Tier 1 assets, and defined RTO/RPO targets for critical clinical systems. A business continuity plan should be drafted and reviewed with Clinical Operations. |

---

## Current Profile Summary

| Function | Current Level | Target Level (6 mo) | Gap Size |
|----------|--------------|---------------------|----------|
| **Govern (GV)** | Partial | Managed | 1 level |
| **Identify (ID)** | Partial | Managed | 1 level |
| **Protect (PR)** | Partial | Managed | 1 level |
| **Detect (DE)** | Not Implemented | Partial | 1 level |
| **Respond (RS)** | Not Implemented | Partial | 1 level |
| **Recover (RC)** | Partial | Managed | 1 level |

### Key Observations

1. **No function achieves Managed or higher.** MedDefense's entire security program operates at Partial or below, meaning security activities are informal, inconsistent, or incomplete across all six functions.

2. **Detect and Respond are the most critical gaps.** Both are rated Not Implemented, meaning MedDefense cannot detect attacks when they happen and cannot respond when they are detected. The billing-srv-01 cryptominer (undetected for 14+ days with no response action taken) is concrete proof of both deficiencies.

3. **The Protect function has the most documented evidence.** Projects 1x00 through 1x02 produced extensive documentation of protective control failures (flat network, unpatched CVEs, default credentials, EOL systems), making this the most actionable area for immediate improvement.

4. **The Recover function has a foundation to build on.** Backups exist, which is more than can be said for Detect and Respond. However, the backup infrastructure itself is vulnerable and untested, meaning recovery capability is assumed but not verified.

5. **Six-month targets are deliberately realistic.** Moving from Partial to Managed and from Not Implemented to Partial within 6 months requires focused effort but does not require unrealistic resource expansion. Full optimization across all functions is a multi-year journey.

---

*Prepared by: Security Department*  
*References: NIST CSF 2.0 Reference Summary, Project 1x00 (Posture Assessment, Asset Registry, Gap Analysis), Project 1x01 (Threat Landscape, Kill Chains, Scenarios), Project 1x02 (Vulnerability Assessment, Task 4 Exploit Hunt, Task 10 Critical CVEs, Task 12 Legacy Systems, Task 14 Network Posture, Task 15 Medical IoT, Task 16 Noise Filter, Task 19 Remediation Map, Task 20 Priority Matrix)*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
