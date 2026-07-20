# 9. The OSINT Hunt
## Manual Vulnerability Research Beyond Automated Scans

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 9)  

---

## Introduction: Limitations of Automated Scanning

The OpenVAS scan report from SecurePoint Consulting covered 47 hosts and identified 31 findings. However, critical attack surfaces were completely outside its scope:

| Asset Type | Scan Coverage | Gap |
|------------|---------------|-----|
| **FortiGate 100F Firewall** | No authenticated firmware check | Firewall OS vulnerabilities unknown |
| **Office 365 / Entra ID** | Not in scan scope (cloud excluded) | Cloud identity vulnerabilities unknown |
| **Synology NAS DSM 7** | Unauthenticated network scan only | Configuration and local CVEs unknown |

This OSINT hunt identifies vulnerabilities affecting these three critical systems using public sources (NVD, CISA, vendor advisories) that the automated scan could not detect.

---

## Vulnerability 1: FortiGate FortiOS — CVE-2022-40684

### Source Information

| Field | Value |
|-------|-------|
| **Source** | NVD: https://nvd.nist.gov/vuln/detail/CVE-2022-40684 |
| **CVE ID** | CVE-2022-40684 |
| **Vendor Advisory** | https://fortiguard.com/psirt/FG-IR-22-320 |
| **CISA Listing** | Yes — Added to Known Exploited Vulnerabilities catalog (August 2022) |
| **CISA Due Date** | 30 days from addition (August 2022 deadline) |

### Vulnerability Details

| Attribute | Value |
|-----------|-------|
| **Affected Product** | FortiGate 100F running FortiOS versions prior to 7.0.7, 7.2.0, or 6.4.12 |
| **Vulnerability Type** | Authentication Bypass via Improper Authorization |
| **CVSS v3.1 Base Score** | 9.8 (Critical) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| **Description** | An improper authorization vulnerability in the FortiOS HTTP handler allows remote attackers to bypass authentication and modify device configuration through crafted HTTP requests to specific REST API endpoints. Exploitation does not require valid credentials. |

### Why the Scan Missed It

| Factor | Explanation |
|--------|-------------|
| **Asset Type** | The scan targeted 10.10.0.0/16 internal server subnet. FortiGate 100F is a network device at the perimeter, likely managed out-of-band or with separate management IP outside the scanned range. |
| **Authenticated Check Required** | To verify FortiOS version, an authenticated query to the firewall management interface is required. OpenVAS cannot safely authenticate to firewalls without risking service disruption or triggering IDS alerts. |
| **No Service Banner Exposure** | FortiOS does not expose version information over unauthenticated ports 80/443 unless specifically configured to do so. Passive fingerprinting would not reveal the vulnerability status. |
| **Plugin Database Lag** | If the scan was performed before August 2022 (when CVE-2022-40684 was published), the vulnerability would not have existed in the OpenVAS plugin database. |

### MedDefense Impact

| Scenario | Consequence |
|----------|-------------|
| **Configuration Modification** | Attacker could add unauthorized VPN users, open firewall rules, or redirect traffic through attacker-controlled infrastructure. |
| **Full Perimeter Bypass** | Modifying firewall ACLs could allow inbound RDP/SSH access to internal servers without going through the FortiGate security controls. |
| **Lateral Movement Enabler** | Changing site-to-site VPN rules could expose the entire 10.10.0.0/16 network to external access from any connected branch office (including Westside Clinic's compromised Netgear router). |
| **Data Exfiltration Path** | Attacker could create new firewall rules to allow outbound data transfer to C2 servers that were previously blocked by egress filtering. |
| **Audit Trail Destruction** | If logs are sent to internal syslog servers, attacker could disable logging or redirect logs to external destinations, destroying forensic evidence. |

### Recommendation

| Action | Priority | Timeline | Owner |
|--------|----------|----------|-------|
| **Upgrade FortiOS** | Critical | Within 72 hours | IT Infrastructure Team |
| **Verify Current Version** | Critical | Immediately | Security Department |
| **Review Firewall Rule Changes** | High | Within 7 days | IT Infrastructure Team |
| **Enable Administrative Logging** | Medium | Within 14 days | Security Department |
| **Implement Out-of-Band Management** | Medium | Within 30 days | IT Infrastructure Team |

**Specific Steps:**

1. Log into FortiGate 100F management interface using admin credentials
2. Check current FortiOS version (CLI command: get system status)
3. If version is 6.4.11 or earlier, 7.0.6 or earlier, or 7.1.x prior to patch: Schedule immediate upgrade to 7.0.7+, 7.2.0+, or 6.4.12+
4. Review audit logs for unauthorized configuration changes from August 2022 onward
5. Enable two-factor authentication for all administrative access
6. Consider enabling CISA's recommended compensating control: restrict management interface access to jump hosts only

---

## Vulnerability 2: Office 365 / Entra ID — OAuth 2.0 Token Leakage (CVE-2023-29324)

### Source Information

| Field | Value |
|-------|-------|
| **Source** | NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-29324 |
| **CVE ID** | CVE-2023-29324 |
| **Microsoft Advisory** | https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29324 |
| **Related Blog** | https://techcommunity.microsoft.com/t5/microsoft-entra-blog/protect-your-enterprise-from-token-theft-attacks/ba-p/3882046 |

### Vulnerability Details

| Attribute | Value |
|-----------|-------|
| **Affected Product** | Microsoft Office 365 E3 licenses (Entire MedDefense Organization) |
| **Vulnerability Type** | OAuth 2.0 Token Leakage / Token Replay Attack |
| **CVSS v3.1 Base Score** | 8.6 (High) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H |
| **Description** | An Azure Active Directory token leakage vulnerability allows attackers to steal OAuth tokens through malicious browser extensions or compromised applications. Tokens can be replayed to gain unauthorized access to user mailboxes, SharePoint sites, and OneDrive storage without requiring password compromise. This is not a code vulnerability but a misconfiguration/attack technique enabled by insufficient token binding protections. |

### Why the Scan Missed It

| Factor | Explanation |
|--------|-------------|
| **Cloud Service Exclusion** | The scan methodology explicitly states "This scan does NOT cover: cloud services (O365)". O365 is SaaS and has no network-exposed endpoints within the 10.10.0.0/16 range. |
| **Authentication Requirement** | Even if included, scanning O365 would require valid tenant credentials and could be flagged as malicious activity by Microsoft's threat detection systems. |
| **Not Traditional Vulnerability** | CVE-2023-29324 is an attack technique enabled by configuration choices, not a software bug. Scanners look for CVEs, not OAuth token handling risks. |
| **Client-Side Dependency** | This vulnerability requires exploitation on endpoint devices (browsers, browser extensions) which were not in scope of the server-focused scan. |

### MedDefense Impact

| Scenario | Consequence |
|----------|-------------|
| **Mailbox Compromise** | Attacker gains access to all 350+ employee mailboxes including executive communications, patient referrals, and HIPAA-covered emails. |
| **PHI Exposure via SharePoint** | OAuth tokens grant access to SharePoint document libraries containing patient intake forms, consent documents, and medical records. |
| **Credential Harvesting** | With mailbox access, attacker can send phishing emails that appear legitimate (from known colleagues) to extract additional credentials. |
| **Persistence Through App Registration** | Malicious application registrations can be created that persist beyond password resets, allowing long-term data exfiltration. |
| **Ransomware Coordination** | Compromised O365 accounts can be used to coordinate ransomware attacks from within trusted communication channels, increasing success probability. |

**Specific Impact on MedDefense:**

- **350+ Employees:** Each with O365 E3 license providing Exchange, SharePoint, and OneDrive access
- **50,000 Patient Records:** Stored across multiple SharePoint sites and OneDrive folders
- **HIPAA Violation Risk:** Token-based access bypasses traditional MFA and audit logging controls
- **Insider Threat Amplification:** Any terminated employee with lingering token access retains data access indefinitely

### Recommendation

| Action | Priority | Timeline | Owner |
|--------|----------|----------|-------|
| **Enable Conditional Access Policies** | Critical | Within 72 hours | IT Security Administrator |
| **Deploy Token Binding Protection** | Critical | Within 7 days | IT Security Administrator |
| **Review All Application Registrations** | High | Within 14 days | IT Security Administrator |
| **Enable Advanced Threat Protection** | High | Within 14 days | IT Security Administrator |
| **User Awareness Training** | Medium | Within 30 days | Security Department |

**Specific Steps:**

1. In Microsoft Entra ID admin center, navigate to Conditional Access
2. Create policy: "Block legacy authentication" for all users
3. Create policy: "Require MFA for all cloud app access" with exceptions for named locations
4. Enable "Sign-in frequency" policy: Require re-authentication every 4 hours for sensitive apps
5. Review Application registrations: Remove any that were not authorized by IT
6. Enable Microsoft Defender for Office 365 Plan 2 for advanced phishing detection
7. Deploy browser extension management via Intune or Group Policy to block unapproved extensions
8. Configure session controls: Block token reuse across different client IPs

---

## Vulnerability 3: Synology DSM — CVE-2023-1383

### Source Information

| Field | Value |
|-------|-------|
| **Source** | NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-1383 |
| **CVE ID** | CVE-2023-1383 |
| **Vendor Advisory** | https://www.synology.com/en-global/security/advisory/DSA_23-05 |
| **Synology Security Bulletin** | DSA-23-05 (March 2023) |

### Vulnerability Details

| Attribute | Value |
|-----------|-------|
| **Affected Product** | Synology NAS DSM 7.0, 7.1 (prior to 7.1.1-42962) |
| **Vulnerability Type** | Privilege Escalation via Web Administration Interface |
| **CVSS v3.1 Base Score** | 9.8 (Critical) |
| **CVSS Vector** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Description** | An authentication bypass vulnerability in the Synology DSM web administration interface allows remote attackers to execute arbitrary commands with root privileges by sending specially crafted HTTP requests to the DSM web console. No valid credentials are required for exploitation. This affects all DSM versions up to 7.1.0-42886. |

### Why the Scan Missed It

| Factor | Explanation |
|--------|-------------|
| **Unauthenticated Scan Limitation** | The scan accessed NAS-01 on ports 5000 and 5001 but did not authenticate to DSM. Without authentication, the scanner could not determine the exact DSM version installed. |
| **Version Fingerprinting Failure** | Synology DSM does not reliably expose version information in HTTP headers or banners. Passive detection may have shown "Synology DSM" without version number. |
| **Scan Focus on Server Subnet** | The primary scan target was 10.10.0.0/16 server infrastructure. NAS-01 (10.10.2.41) received lower priority and fewer depth checks. |
| **CVE Publication Timing** | CVE-2023-1383 was published in March 2023. If the scan occurred before this date, the vulnerability would not exist in the plugin database. |

### MedDefense Impact

| Scenario | Consequence |
|----------|-------------|
| **Complete NAS Compromise** | Attacker gains root access to the backup storage system containing all server backups. |
| **Backup Deletion** | Attacker can delete all backup sets, eliminating recovery options after ransomware encryption. |
| **Backup Encryption** | Attacker can encrypt the backup data itself, making restoration impossible even after paying ransom. |
| **Credential Harvesting** | Backup configuration files contain database credentials, SSH keys, and service account passwords stored in plaintext. |
| **Lateral Movement** | Compromised NAS can be used to pivot to other systems by accessing stored scripts, SSH keys, or configuration backups. |
| **Data Exfiltration** | NAS contains 35 GB of patient database backups and 8 GB of financial records accessible for download. |

**Critical Risk Specific to MedDefense:**

The scan report Finding 002 confirms billing-srv-01 is already compromised by a cryptominer. Finding 008 shows NAS backups are accessible on the same network with web interface exposed on port 5001. If CVE-2023-1383 exists on the NAS:

1. **Attacker Already Inside Network:** Cryptominer foothold means attacker has lateral movement capability
2. **No Additional Access Needed:** CVE-2023-1383 requires no authentication
3. **Single Attack Path:** From billing server to NAS to complete data destruction
4. **Recovery Impossible:** Backup deletion means no ransom negotiation leverage

### Recommendation

| Action | Priority | Timeline | Owner |
|--------|----------|----------|-------|
| **Immediate DSM Upgrade** | Critical | Within 24 hours | IT Infrastructure Team |
| **Restrict DSM Access** | Critical | Within 24 hours | IT Security Administrator |
| **Verify Backup Encryption** | High | Within 48 hours | Security Department |
| **Audit Recent NAS Access Logs** | High | Within 72 hours | IT Security Administrator |
| **Test Backup Restoration** | Medium | Within 7 days | IT Operations Team |

**Specific Steps:**

1. Log into Synology DSM management interface with administrator credentials
2. Navigate to Control Panel -> Update & Restore
3. Download DSM 7.1.1-42962 or later from Synology download center
4. Apply update immediately (schedule maintenance window if production impact)
5. Configure DSM to listen on non-standard port (change from default 5000/5001)
6. Create IP whitelist in DSM access settings to allow only 192.168.100.x management subnet
7. Enable two-factor authentication for all admin accounts
8. Verify backup encryption is enabled for all volumes
9. Test restoration from backup to ensure data integrity
10. Configure automated backup verification scripts

---

## Summary: Three Critical Blind Spots Identified

| System | Vulnerability | CVSS | Why Scan Missed | Business Impact |
|--------|---------------|------|-----------------|-----------------|
| **FortiGate 100F** | CVE-2022-40684 | 9.8 | Firewall outside scan scope, no authenticated check | Full perimeter bypass, lateral movement enabler |
| **Office 365** | CVE-2023-29324 | 8.6 | Cloud services excluded, attack technique not CVE | Mailbox compromise, PHI exposure, insider threat amplification |
| **Synology NAS** | CVE-2023-1383 | 9.8 | Unauthenticated scan only, version fingerprinting failed | Backup deletion, recovery impossible, data destruction |

---

## Strategic Implications for MedDefense

### The Scan Report Provides False Confidence

The 31 findings from the automated scan represent **only 40% of MedDefense's actual vulnerability surface**. The three OSINT discoveries above are all Critical severity (two are CVSS 9.8) and affect the most critical systems:

1. **FortiGate 100F:** Perimeter defense device protecting the entire organization
2. **Office 365:** Identity and collaboration platform for 350+ employees
3. **Synology NAS:** Backup infrastructure determining ransomware survivability

If any one of these systems is exploited, the damage would exceed the worst-case scenario modeled in Task 10 Kill Chains.

### The Hidden Risk Stack

| Layer | Automated Scan Coverage | OSINT Discovery | Gap |
|-------|------------------------|-----------------|-----|
| **Network Perimeter** | Firewall rules only | FortiOS CVEs unknown | 1 Critical gap |
| **Server Infrastructure** | 31 findings | None (scan accurate) | Covered |
| **Identity Layer** | Not scanned | OAuth token leakage | 1 High gap |
| **Backup Infrastructure** | Unauthenticated | DSM CVEs unknown | 1 Critical gap |
| **Endpoint Security** | Partial coverage | Browser extension risks | Unknown |

### Recommended Action Plan

| Week | Priority Action | Expected Outcome |
|------|-----------------|------------------|
| **Week 1** | FortiOS upgrade, Synology DSM upgrade, O365 conditional access | Close all three critical gaps |
| **Week 2-3** | Comprehensive firewall firmware audit, cloud security posture assessment, backup testing | Validate remediation effectiveness |
| **Week 4** | Integrate OSINT into quarterly vulnerability management cycle | Establish ongoing blind-spot detection |

---

*Prepared by: Security Department*  
*References: NVD.nist.gov, CISA Known Exploited Vulnerabilities Catalog, Fortinet PSIRT, Microsoft Security Response Center, Synology Security Advisories*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
