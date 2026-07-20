# 0. The Scan Report: First Impressions Summary

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 0)  

---

## Scan Metadata

| Field | Value |
|-------|-------|
| **Scanner Platform** | OpenVAS 22.x (Greenbone Community Edition) |
| **Scan Execution** | Approximately July 15, 2026 (5 days prior to report date) |
| **Scan Target Range** | 10.10.0.0/16 (all internal subnets) |
| **Scan Policy** | Full and Deep (authenticated where credentials available) |
| **Requestor** | James Chen, Deputy CISO |
| **Executor** | SecurePoint Consulting (third-party) |
| **Total Hosts Scanned** | 47 responsive hosts |
| **Scan Timing** | Off-peak hours (02:00-06:00) to minimize clinical impact |

### What Was NOT Scanned
Per Methodology Notes (page 13):
- **Cloud Services:** O365 environment excluded entirely
- **Mobile Devices:** iPads and other mobile endpoints not covered
- **Offline Assets:** Any system powered down during the 02:00-06:00 window
- **Physical Security:** No assessment of physical access controls
- **Active Exploitation:** Scanner confirmed no exploitation attempted (passive only)

---

## Finding Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| **Critical** | 4 | 12.9% |
| **High** | 8 (includes Finding 031 manual addition) | 25.8% |
| **Medium** | 10 | 32.3% |
| **Low** | 5 | 16.1% |
| **Informational** | 4 | 12.9% |
| **TOTAL** | **31** | **100%** |

**Observation:** Medium severity contains the most findings (10), but the Critical and High categories (12 combined findings) represent the immediate remediation priority.

---

## Asset Heat Map

| Rank | Host | IP Address | Finding Count | Role (from 1x00 T7 Asset Registry) |
|------|------|------------|---------------|-----------------------------------|
| **1** | **billing-srv-01** | 10.10.2.15 | **6** | Billing application server (Linux/Ubuntu) |
| **2** | **web-srv-01** | 10.10.2.50 | **4** | Patient Portal web server |
| **3** | **ad-dc-01** | 10.10.2.20 | **3** | Active Directory Domain Controller |
| **4** | **ehr-srv-01** | 10.10.2.10 | **3** | EHR application server (Linux) |
| **5** | **Medical Device Fleet** | 10.10.3.x | **3** (grouped) | BD Alaris pumps (7 devices) + Philips IntelliVue monitors (13 devices) |

### Additional Notable Hosts (Single Findings)
- **WS-RAD-01** (10.10.1.70): Windows XP MRI workstation — Critical EOL finding
- **NAS-01** (10.10.2.41): Backup storage server
- **print-srv-01** (10.10.2.31): Print server (Windows Server 2012 R2 EOL)
- **Westside Netgear Router** (10.10.10.1): Consumer-grade perimeter device
- **Unknown devices** (10.10.2.99, 10.10.10.200): Shadow IT systems detected

---

## First Observations

**Pattern 1: Critical Findings Concentrated on Single Asset**  
Three of the four Critical findings (001, 002, 031) are concentrated on **two systems**: billing-srv-01 (2 Critical) and ehr-srv-01 (1 Critical + Ghostcat manual verification). This signals that billing-srv-01 is the single highest-risk asset in the environment.

**Pattern 2: Exploitable Vulnerability Chains Exist**  
Multiple findings represent chained exploits:
- **Findings 001 + 002:** Apache RCE (CVE-2021-44790) followed by Privilege Escalation (CVE-2019-0211) on billing-srv-01 enables full root compromise
- **Finding 017 + 031:** Tomcat info disclosure led to manual verification that AJP connector is active (Ghostcat, CVE-2020-1938 CVSS 9.8) on EHR server

**Pattern 3: Flat Network Amplifies Every Finding**  
Nearly all network-accessible findings (PostgreSQL unrestricted access Finding 003, MySQL binding Finding 006, LDAP relay Finding 007) cite the flat network topology (GAP-001) as an enabling condition. A single compromise provides unrestricted reachability to all vulnerable services.

**Pattern 4: Legacy Systems Create Permanent Risk**  
Two systems run End-of-Life operating systems with unpatchable vulnerabilities:
- **WS-RAD-01:** Windows XP (EOL April 2014) — Finding 004 confirms 3 weaponized CVEs including BlueKeep (CVSS 9.8)
- **print-srv-01:** Windows Server 2012 R2 (EOL October 2023) — Finding 008 cites PrintNightmare (CVE-2021-34527)

**Pattern 5: Medical Devices Have Default Credentials**  
Finding 010 explicitly states all 7 BD Alaris infusion pumps use unchanged default credentials (admin/admin) with vulnerable firmware. This is a "known known" with direct patient harm potential.

**Surprise:** Finding 020 (OpenSSH CVE-2023-38408 on backup server) includes a manual false positive warning from SecurePoint, acknowledging scanner limitations and the need for human verification before remediation prioritization.

---

## Scan Limitations

| Limitation | Impact |
|-----------|--------|
| **No Cloud Coverage** | O365, SharePoint, Teams security posture unknown — could contain 500+ mailboxes vulnerable to phishing |
| **No Mobile Coverage** | 200+ clinical iPads not scanned — potential exfiltration vector (USB restriction Finding 023 applies to workstations, but tablets differ) |
| **Passive Scanning Only** | Scanner confirms version presence but does not verify if vulnerabilities are actually exploitable in this environment |
| **Shadow IT Blindness** | Finding 028 and 029 reveal unknown Linux hosts — scanner found them, but cannot assess if they are authorized or compromised |
| **Authentication Gaps** | Some findings (medical devices) scanned unauthenticated — configuration analysis may be incomplete |
| **False Positive Risk** | SecurePoint notes 5-10% false positive rate; Finding 020 explicitly flagged for manual verification |
| **Temporal Snapshot** | Scan represents one moment in time; new vulnerabilities discovered post-scan not reflected |

---

## Summary Assessment

This scan report confirms **billing-srv-01 is the critical focal point** for immediate remediation—it hosts 6 findings including 2 Critical and represents the primary entry point identified in Kill Chain #1 (Apache RCE → Ransomware). The **flat network topology** functions as a force multiplier, ensuring that any single compromise provides unrestricted access to all vulnerable systems including Domain Controllers, EHR database, and backup infrastructure. The scan limitations mean we still lack visibility into cloud, mobile, and physical security layers—which could account for additional attack paths not visible in this dataset.

**Next Step:** Proceed to individual finding investigation (Task 1) starting with the 4 Critical findings, prioritizing billing-srv-01 (001/002) before exploring the EHR Ghostcat finding (031).

---

*Prepared by: Security Department*  
*References: Project 1x00 Asset Registry (Task 7), Project 1x01 Threat Landscape Report (Kill Chain #1)*  
*Distribution: James Chen (Deputy CISO), SecurePoint Consulting (vendor)*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
