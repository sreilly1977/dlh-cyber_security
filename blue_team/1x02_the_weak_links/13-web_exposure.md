# 13. The Web Exposure
## Internet-Facing vs Internal Web Vulnerability Analysis

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 13)  

---

## Web-Related Findings Inventory

The scan report contains **9 web-related findings** across three hosts. These were identified by reviewing all 31 findings for web-specific characteristics: HTTP security headers, TLS/SSL configuration, information disclosure, application-layer vulnerabilities, and web server misconfigurations.

| Host | IP Address | Exposure Type | Web Findings Count | Highest Severity |
|------|------------|---------------|-------------------|------------------|
| **ehr-srv-01** | 10.10.2.10 | Internal (Flat Network) | 4 | Critical |
| **patient-portal.meddefense.local** | Public DMZ | Internet-Facing | 3 | Medium |
| **NAS-01** | 10.10.2.41 | Internal (Flat Network) | 2 | Medium |

---

## Host 1: EHR Application Server (ehr-srv-01)

| Field | Value |
|-------|-------|
| **Host** | ehr-srv-01 (10.10.2.10) |
| **Exposure** | Internal-only, but on flat 10.10.0.0/16 network — accessible from any compromised host |
| **Role** | EHR Application Server serving patient records to clinical workstations |

### Findings

| Finding ID | Finding | Severity | Category |
|------------|---------|----------|----------|
| **017** | Tomcat version disclosure via HTTP Server header | Medium | Information Disclosure |
| **018** | Missing HSTS header | Medium | Security Headers |
| **019** | TLS 1.0 enabled with weak cipher suites (CBC, 3DES) | Medium | TLS Configuration |
| **031** | Ghostcat — CVE-2020-1938 (Tomcat AJP path traversal) | Critical | Application Vulnerability |

### Combined Risk: **CRITICAL**

Four web findings on the EHR application server aggregate to a far greater risk than any individual finding suggests. The combined risk is **critical** because these findings form a chained attack path:

1. Finding 017 discloses the exact Tomcat version (9.0.30) to any attacker on the flat network.
2. Finding 019 (TLS 1.0) enables MITM downgrade attacks, allowing an attacker positioned on the flat network to intercept EHR traffic between workstations and the server.
3. Finding 031 (Ghostcat) becomes trivially targetable once the attacker knows the Tomcat version from Finding 017.
4. Finding 018 (missing HSTS) removes browser-level protection against protocol downgrades, complementing the TLS 1.0 weakness.

Together, these findings create both a passive intelligence path (version disclosure + TLS interception) and an active exploitation path (Ghostcat file read → database credential theft → PostgreSQL data exfiltration via Finding 003).

### Attack Scenario

This chain appears in **Kill Chain #2 (Phishing → EHR Exfiltration)** from 1x01 Task 10:

| Step | Action | Finding Used |
|------|--------|--------------|
| 1 | Attacker compromises a clinical workstation via phishing email | N/A (Initial Access) |
| 2 | Attacker scans flat network for web services, finds ehr-srv-01:80 | Network access (GAP-001) |
| 3 | Tomcat version banner reveals 9.0.30 — known vulnerable to Ghostcat | **Finding 017** |
| 4 | Attacker crafts Ghostcat exploit targeting AJP port 8009 | **Finding 031** |
| 5 | Ghostcat reads Tomcat configuration file (server.xml, context.xml) | **Finding 031** |
| 6 | Extracts PostgreSQL database credentials from configuration | **Finding 031 → Finding 003** |
| 7 | Attacker connects directly to ehr-db-01:5432 using stolen credentials | **Finding 003** |
| 8 | TLS 1.0 enabled allows MITM to capture session tokens if needed | **Finding 019** |
| 9 | Data exfiltrated without triggering any security alert | GAP-003 (No SIEM) |

**Time to compromise:** Estimated 30 minutes from initial workstation foothold to database access. Ghostcat exploit (Exploit-DB 48185) executes in under 10 seconds.

### Priority: **1 of 3** — Fix First

ehr-srv-01 should be remediated first among the three web-exposed hosts. Despite being internal-only, it sits on the flat network, holds the most findings (4 of 9), includes a CVSS 9.8 critical vulnerability, and protects 50,000+ patient records. The information disclosure finding (017) directly enables exploitation of the critical finding (031), making rapid remediation essential.

---

## Host 2: Patient Portal (patient-portal.meddefense.local)

| Field | Value |
|-------|-------|
| **Host** | patient-portal.meddefense.local (public IP via DMZ) |
| **Exposure** | Internet-facing — accessible from any external IP address |
| **Role** | External patient appointment scheduling and records access portal |

### Findings

| Finding ID | Finding | Severity | Category |
|------------|---------|----------|----------|
| **015** | Outdated TLS certificate (expired July 2023) | Medium | TLS Configuration |
| **016** | Missing X-Frame-Options and CSP headers | Medium | Security Headers |
| **027** | Apache version 2.4.41 with directory listing enabled | Medium | Information Disclosure |

### Combined Risk: **HIGH**

Three medium-severity findings on an internet-facing host aggregate to a **high** combined risk. While none of the individual findings is critical, the internet exposure multiplies the risk:

- An expired TLS certificate (Finding 015) means browsers display security warnings, training users to ignore certificate errors. This creates a population of patients accustomed to clicking through certificate warnings, making them vulnerable to spoofed login pages for credential harvesting.
- Missing X-Frame-Options (Finding 016) enables clickjacking attacks where the patient portal login form is embedded in an invisible iframe on an attacker-controlled site. Patients enter credentials believing they are logging into the legitimate portal.
- Directory listing enabled (Finding 027) allows attackers to enumerate files in directories without index pages, potentially discovering backup files, configuration files, or old application versions.
- Apache version disclosure (within Finding 027) tells attackers exactly which CVEs to target.

### Attack Scenario

This chain does not directly match a 1x01 kill chain, but it supports **Kill Chain #1 (Apache RCE → Ransomware)** as an initial access vector:

| Step | Action | Finding Used |
|------|--------|--------------|
| 1 | Attacker identifies patient portal as internet-facing Apache 2.4.41 | **Finding 027** |
| 2 | Attacker creates a spoofed patient portal login page mimicking the expired-cert warning | **Finding 015** |
| 3 | Patients trained to ignore cert warnings enter credentials on the spoofed page | **Finding 015** (behavioral) |
| 4 | Alternatively, attacker embeds legitimate login form in clickjacking iframe | **Finding 016** |
| 5 | Captured patient credentials may be reused for EHR access if patients use same credentials | Credential reuse |
| 6 | Alternatively, Apache 2.4.41 has known CVEs; attacker attempts RCE | **Finding 027** (version disclosure) |
| 7 | If RCE succeeds, attacker pivots from DMZ to internal network through flat architecture | Network access (GAP-001) |

**Time to compromise:** Variable. Credential harvesting is slow (days to weeks). If Apache 2.4.41 CVEs are exploited, potentially minutes.

### Priority: **2 of 3** — Fix Second

The patient portal is the only internet-facing web host and therefore represents the broadest attack surface. However, it ranks below ehr-srv-01 because its findings are all Medium severity (vs. one Critical on EHR), the portal does not store the full EHR database (limited patient-facing data subset), and the Apache 2.4.41 version, while outdated, does not have a confirmed critical CVE in the scan report. Remediation should focus on renewing the TLS certificate immediately and adding security headers within one week.

---

## Host 3: Synology NAS (NAS-01)

| Field | Value |
|-------|-------|
| **Host** | NAS-01 (10.10.2.41) |
| **Exposure** | Internal-only, but on flat 10.10.0.0/16 network — web management interface on ports 5000/5001 accessible from any host |
| **Role** | Backup storage — contains all server backups, database dumps, and configuration archives |

### Findings

| Finding ID | Finding | Severity | Category |
|------------|---------|----------|----------|
| **029** | DSM web interface exposes version information via HTTP headers | Low | Information Disclosure |
| **030** | Admin login page accessible without IP restriction | Medium | Access Control Misconfiguration |

### Combined Risk: **HIGH**

While only two web-related findings affect NAS-01, the combined risk escalates to **high** when contextual factors are considered:

- Finding 029 discloses the DSM version, allowing attackers to target known DSM CVEs (such as CVE-2023-1383 identified in Task 9 OSINT Hunt) with precision.
- Finding 030 exposes the admin login page to the entire flat network. Combined with the OSINT-discovered CVE-2023-1383 (authentication bypass, CVSS 9.8), an attacker can exploit the version identified via Finding 029 to bypass authentication entirely.
- The NAS holds all server backups. Compromise means loss of recovery capability — the final safety net against ransomware.

### Attack Scenario

This chain supports **Kill Chain #1 (Apache RCE → Ransomware)** at the final stage:

| Step | Action | Finding Used |
|------|--------|--------------|
| 1 | Attacker compromises billing-srv-01 via Apache RCE | **Finding 001** |
| 2 | Attacker performs lateral movement across flat network | Network access (GAP-001) |
| 3 | Attacker scans for web services, finds NAS-01:5000 | Network access |
| 4 | DSM version header reveals running version | **Finding 029** |
| 5 | Attacker confirms DSM version is vulnerable to CVE-2023-1383 | **Finding 029 + OSINT (Task 9)** |
| 6 | Attacker exploits CVE-2023-1383 (auth bypass, CVSS 9.8) via DSM web console | OSINT Finding |
| 7 | Attacker gains root access to backup storage | OSINT Finding |
| 8 | Attacker deletes or encrypts all backup sets | Impact |
| 9 | Attacker deploys ransomware on billing-srv-01 and spreads across flat network | Kill Chain #1 completion |
| 10 | No backups remain for recovery; ransom negotiation leverage lost | Impact |

**Time to compromise:** Approximately 10 minutes from billing-srv-01 compromise to NAS root access.

### Priority: **3 of 3** — Fix Third

NAS-01 ranks third among web-exposed hosts because it has only 2 web findings (both Low/Medium) and the critical CVE-2023-1383 was discovered through OSINT (Task 9), not the scan report itself. However, the consequence of compromise (backup destruction) is existential to MedDefense. Remediation should focus on restricting management interface access via IP whitelist and verifying DSM version immediately. Full remediation overlaps with Task 9 recommendations.

---

## Combined Web Exposure Summary

| Host | Exposure | Findings | Highest Severity | Combined Risk | Priority |
|------|----------|----------|------------------|---------------|----------|
| **ehr-srv-01** | Internal (flat network) | 4 | Critical (Ghostcat) | **Critical** | **1 — Fix First** |
| **patient-portal** | Internet-facing | 3 | Medium | **High** | **2 — Fix Second** |
| **NAS-01** | Internal (flat network) | 2 | Medium | **High** | **3 — Fix Third** |

---

## Analysis: The Value of Investigating Medium Findings

### The Finding 017 → Finding 031 Pipeline

The scan report narrative documents a critical analytical sequence:

1. **Finding 017 (Medium):** The scanner detected that Tomcat was exposing its exact version number (9.0.30) through the HTTP `Server` header. This is rated Medium severity — it discloses information but does not itself enable exploitation.
2. **Manual investigation:** SecurePoint analysts saw the Tomcat version, cross-referenced it against known Tomcat CVEs, and discovered that version 9.0.30 is vulnerable to CVE-2020-1938 (Ghostcat, CVSS 9.8).
3. **Finding 031 (Critical):** SecurePoint manually verified the AJP connector on port 8009 and confirmed Ghostcat was exploitable. This finding was elevated to Critical and added to the report as a manually discovered finding.

### What This Tells Us

This sequence illustrates three essential principles of vulnerability management:

**1. Medium findings are not "low priority" findings.**

Finding 017 is rated Medium because version disclosure alone has limited impact. But version disclosure is an **enabler** — it tells the attacker exactly which exploit to use. Without Finding 017, an attacker would need to probe the AJP port blindly, potentially triggering detection. With Finding 017, the attacker knows the exact Tomcat version and can select a guaranteed-working exploit. Medium findings that reveal version information are **force multipliers** for attackers.

**2. Automated scanners miss context chains.**

The scanner flagged Finding 017 and moved on. It did not connect "Tomcat 9.0.30 is exposed" to "CVE-2020-1938 affects Tomcat 9.0.30." A human analyst made that connection. Automated scanners evaluate findings in isolation; they cannot reason about how Finding A enables exploitation of Finding B. Manual investigation of Medium findings is where the most valuable threat intelligence is generated.

**3. Information disclosure findings are reconnaissance shortcuts.**

When a scanner reports information disclosure (version numbers, directory listings, error messages), it is handing the attacker a reconnaissance result for free. In a well-defended environment, an attacker must spend time and risk detection to fingerprint services. When the server hands out its version number in every HTTP response, the attacker skips straight to exploitation. Every information disclosure finding should be investigated as a potential gateway to a higher-severity vulnerability.

### Practical Recommendation for MedDefense

| Rule | Action |
|------|--------|
| **Rule 1** | Never dismiss a Medium information disclosure finding without checking if the disclosed version has known critical CVEs |
| **Rule 2** | Treat version disclosure as an enabler — if the version is vulnerable to a critical CVE, elevate the combined finding to Critical |
| **Tomcat Rule** | Remove the `Server` header in Tomcat by setting `server.xml` to remove version info and set `xpoweredBy="false"` |
| **General Rule** | Apply this logic to all information disclosure findings — Apache version, PHP version, OpenSSH banner, DSM version |

---

*Prepared by: Security Department*  
*References: Project 1x02 Scan Report (Findings 015-019, 027, 029-031), Project 1x01 Kill Chain Analysis, NVD.nist.gov, OWASP Secure Headers Project*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
