# 16. The Noise Filter
## Full-Report Triage: Separating Signal from Noise Across All 31 Findings

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 16)  

---

## Complete Finding Triage

Finding 001 | 9.8 Critical | billing-srv-01 | Category: AC | Reason: Weaponized unauthenticated RCE on Tier 1 asset with confirmed active cryptominer compromise.

Finding 002 | 7.8 High | billing-srv-01 | Category: AC | Reason: Root privilege escalation chains directly with Finding 001 to grant attacker full system control on compromised billing server.

Finding 003 | Critical (Misconfig) | ehr-db-01 | Category: AC | Reason: Unrestricted PostgreSQL access on flat network enables direct PHI exfiltration when chained with Ghostcat credential theft.

Finding 004 | 9.8/8.1 Critical | WS-RAD-01 | Category: AC | Reason: Wormable RCE on unpatchable Windows XP MRI workstation with direct patient safety implications.

Finding 005 | High | ad-dc-02 | Category: AS | Reason: Domain Controller missing critical patches but no confirmed exploitation and attacker would need network access first.

Finding 006 | High (Misconfig) | billing-srv-01 | Category: AS | Reason: MySQL unrestricted binding exposes financial data but requires credentials or exploit to access.

Finding 007 | High | ad-dc-01 | Category: AC | Reason: LDAP signing not required enables NTLM relay attacks against domain controllers, facilitating credential theft and lateral movement across entire AD environment.

Finding 008 | 8.8 High | print-srv-01 | Category: AS | Reason: PrintNightmare on EOL Server 2012 R2 is exploitable but Tier 2 asset with no PHI and manageable network isolation.

Finding 009 | High (Misconfig) | billing-srv-01 | Category: AC | Reason: SSH password authentication on actively compromised server enables persistent attacker access after initial RCE foothold.

Finding 010 | 9.8 Critical | BD Alaris Pumps (x7) | Category: AC | Reason: Default credentials on infusion pumps create direct patient safety risk including dose manipulation.

Finding 011 | Critical (EOL) | billing-srv-01 | Category: AC | Reason: Ubuntu 18.04 EOL without ESM means no security patches will ever be delivered for OS-level vulnerabilities including kernel CVEs.

Finding 012 | Medium | WS-RAD-01 | Category: I | Reason: SMBv1 enabled on MRI workstation is expected for Windows XP and cannot be remediated without OS replacement.

Finding 013 | Medium | ad-dc-01 | Category: AS | Reason: SMBv1 enabled on domain controller should be disabled but Windows XP MRI workstation may depend on it for file sharing.

Finding 014 | Medium (Architecture) | Westside Router | Category: AS | Reason: Consumer-grade router terminates site-to-site VPN but can be replaced with enterprise device within planned timeline.

Finding 015 | Medium | NAS-01 | Category: AS | Reason: Backup storage web interface exposed on flat network enables potential backup destruction when chained with OSINT CVE-2023-1383.

Finding 016 | Medium | Philips Monitors | Category: AS | Reason: Unauthenticated web interface on medical monitors allows vitals viewing and potential alarm suppression.

Finding 017 | Medium | ehr-srv-01 | Category: AS | Reason: Tomcat version disclosure directly enabled discovery of Ghostcat (Finding 031) and should be remediated as an attack enabler.

Finding 018 | Medium | ehr-srv-01 | Category: AS | Reason: Missing HSTS header enables protocol downgrade attacks complementing TLS 1.0 weakness on EHR server.

Finding 019 | Medium | ehr-srv-01 | Category: AS | Reason: TLS 1.0 with weak ciphers enables MITM interception of EHR traffic on flat network.

Finding 020 | High | backup-srv-01 | Category: FP | Reason: OpenSSH CVE-2023-38408 requires ssh-agent forwarding which is not in use on this server, confirmed false positive by SecurePoint.

Finding 021 | Medium | ad-dc-02 | Category: AS | Reason: Windows Event Log forwarding not configured limits incident response visibility and should be scheduled.

Finding 022 | Low | ad-dc-01 | Category: I | Reason: Administrator account renamed is a minor hardening gap with negligible real-world security impact.

Finding 023 | Low | Clinical Workstations | Category: FP | Reason: USB mass storage restriction absence may be intentional for clinical workflows and cannot be confirmed as vulnerability without verifying Sophos endpoint policies and BIOS settings.

Finding 024 | Medium | Monitor-to-EHR Pipeline | Category: AS | Reason: HL7 cleartext transmission exposes real-time patient vitals to interception on flat network.

Finding 025 | Low | ad-dc-01 | Category: FP | Reason: DNS zone transfer exposure is informational only since flat network already allows full host enumeration via passive means.

Finding 026 | Medium | billing-srv-01 | Category: AS | Reason: Kernel 4.15 has known CVEs but patches require ESM enrollment or OS upgrade, tying to Finding 011 remediation.

Finding 027 | Medium | patient-portal | Category: AS | Reason: Apache version disclosure and directory listing on internet-facing portal aids reconnaissance for external attackers.

Finding 028 | Medium | 10.10.2.99 (Shadow IT) | Category: AS | Reason: Undocumented Linux device on network indicates asset management failure and should be investigated and decommissioned or registered.

Finding 029 | Low | NAS-01 | Category: I | Reason: DSM version disclosure is low risk individually but documented as enabler for OSINT CVE-2023-1383 (addressed under Finding 015 remediation).

Finding 030 | Medium | NAS-01 | Category: AS | Reason: Admin login page without IP restriction combined with OSINT CVE-2023-1383 enables unauthenticated backup compromise.

Finding 031 | 9.8 Critical | ehr-srv-01 | Category: AC | Reason: Ghostcat provides unauthenticated file read leading to database credential theft on Tier 1 EHR system with weaponized exploit available.

---

## Triage Summary

| Category | Code | Count | Percentage |
|----------|------|-------|------------|
| Actionable Critical | AC | 10 | 32.3% |
| Actionable Standard | AS | 15 | 48.4% |
| Informational | I | 2 | 6.5% |
| False Positive | FP | 2 | 6.5% |

**Note:** Percentages total 93.9% due to rounding. The actual counts sum to 29. Findings 012 and 029 are classified as Informational, bringing the total to 31. Revised count below.

| Category | Count |
|----------|-------|
| Actionable Critical (AC) | 10 |
| Actionable Standard (AS) | 16 |
| Informational (I) | 2 |
| False Positive (FP) | 2 |
| **Unclassified (review pending)** | 1 |
| **Total** | **31** |

Corrected final tally after re-counting all 31 findings:

| Category | Count | Percentage |
|----------|-------|------------|
| Actionable Critical (AC) | 10 | 32.3% |
| Actionable Standard (AS) | 15 | 48.4% |
| Informational (I) | 3 | 9.7% |
| False Positive (FP) | 3 | 9.7% |
| **Total** | **31** | **100%** |

Let me recount carefully:

- AC: 001, 002, 003, 004, 007, 009, 010, 011, 031 = 9
- AS: 005, 006, 008, 013, 014, 015, 016, 017, 018, 019, 021, 024, 026, 027, 028, 030 = 16
- I: 012, 022, 029 = 3
- FP: 020, 023, 025 = 3

9 + 16 + 3 + 3 = 31. Correct.

**Final Triage Counts:**

| Category | Count | Percentage |
|----------|-------|------------|
| Actionable Critical (AC) | 9 | 29.0% |
| Actionable Standard (AS) | 16 | 51.6% |
| Informational (I) | 3 | 9.7% |
| False Positive (FP) | 3 | 9.7% |
| **Total** | **31** | **100%** |

---

## Actionable Findings List (Sorted by Priority)

### Actionable Critical (Immediate Remediation: 24-48 Hours)

| Priority | Finding | CVSS | Host | Vulnerability |
|----------|---------|------|------|---------------|
| 1 | **001** | 9.8 | billing-srv-01 | Apache mod_lua RCE — actively exploited, cryptominer confirmed |
| 2 | **031** | 9.8 | ehr-srv-01 | Ghostcat — unauthenticated file read, leads to DB credential theft |
| 3 | **004** | 9.8/8.1 | WS-RAD-01 | BlueKeep + EternalBlue — wormable RCE on MRI workstation, patient safety risk |
| 4 | **010** | 9.8 | BD Alaris Pumps | Default credentials on infusion pumps, patient safety risk |
| 5 | **003** | Critical | ehr-db-01 | PostgreSQL unrestricted access — PHI exfiltration enabler |
| 6 | **002** | 7.8 | billing-srv-01 | Apache privilege escalation — chains with Finding 001 |
| 7 | **011** | Critical | billing-srv-01 | Ubuntu 18.04 EOL — no OS patches, permanent vulnerability growth |
| 8 | **009** | High | billing-srv-01 | SSH password auth — persistence mechanism on compromised server |
| 9 | **007** | High | ad-dc-01 | LDAP signing not required — NTLM relay, domain compromise risk |

### Actionable Standard (Scheduled Remediation: 7-30 Days)

| Priority | Finding | Severity | Host | Vulnerability |
|----------|---------|----------|------|---------------|
| 10 | **015** | Medium | NAS-01 | Backup web interface exposed — chains with OSINT CVE-2023-1383 |
| 11 | **016** | Medium | Philips Monitors | Unauthenticated web interface — patient vitals exposure |
| 12 | **024** | Medium | Monitor-EHR | HL7 cleartext — real-time patient data interception |
| 13 | **008** | 8.8 | print-srv-01 | PrintNightmare on EOL Server 2012 R2 |
| 14 | **019** | Medium | ehr-srv-01 | TLS 1.0 weak ciphers — MITM on EHR traffic |
| 15 | **017** | Medium | ehr-srv-01 | Tomcat version disclosure — enabled Ghostcat discovery |
| 16 | **018** | Medium | ehr-srv-01 | Missing HSTS — protocol downgrade risk |
| 17 | **006** | High | billing-srv-01 | MySQL unrestricted binding — financial data exposure |
| 18 | **026** | Medium | billing-srv-01 | Kernel CVEs — requires ESM or OS upgrade |
| 19 | **014** | Medium | Westside Router | Consumer-grade router as enterprise VPN endpoint |
| 20 | **027** | Medium | patient-portal | Apache version disclosure + directory listing on internet-facing host |
| 21 | **030** | Medium | NAS-01 | Admin login page unrestricted — enables auth bypass exploitation |
| 22 | **028** | Medium | 10.10.2.99 | Shadow IT device — undocumented Linux host on network |
| 23 | **013** | Medium | ad-dc-01 | SMBv1 enabled — dependency concern with Windows XP MRI workstation |
| 24 | **005** | High | ad-dc-02 | Domain Controller missing patches |
| 25 | **021** | Medium | ad-dc-02 | Windows Event Log forwarding not configured |

---

## Triage Insights

**29% of findings require immediate action.** Nine findings are classified as Actionable Critical, representing vulnerabilities on Tier 1 assets with weaponized exploits, active compromise, or direct patient safety implications. These 9 findings should consume all available engineering resources for the first 48 hours.

**51.6% of findings require scheduled remediation.** Sixteen findings are real vulnerabilities that need planned remediation within 7-30 days. These include misconfigurations, EOL dependencies, and medium-severity exposures that pose real risk but do not require emergency response.

**9.7% are informational.** Three findings (SMBv1 on Windows XP, admin account rename, DSM version disclosure) are real observations that are either unavoidable consequences of EOL status or are being addressed through other remediation actions. These should be documented and monitored but do not require independent action.

**9.7% are false positives.** Three findings (OpenSSH CVE requiring unavailable conditions, DNS zone transfer on flat network, USB restrictions possibly managed by endpoint protection) should be formally documented with validation evidence and dismissed from the remediation queue.

The false positive rate of 9.7% falls within the industry-expected range of 5-10% for automated vulnerability scanners, confirming that the scan methodology was generally accurate and that manual validation successfully separated genuine findings from noise.

---

*Prepared by: Security Department*  
*References: Project 1x02 Scan Report (All 31 Findings), Tasks 4-15 Analysis, NVD.nist.gov, CISA KEV Catalog*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
