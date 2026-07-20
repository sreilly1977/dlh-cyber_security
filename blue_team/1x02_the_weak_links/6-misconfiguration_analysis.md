# 6. The Misconfiguration Findings
## Non-CVE Vulnerabilities and Their Real-World Risk

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 6)  

---

## 6 Misconfiguration Findings Analysis

### Finding 003: PostgreSQL Unrestricted Network Access

| Field | Value |
|-------|-------|
| **Finding ID** | 003 |
| **Host** | ehr-db-01 (10.10.2.11) |
| **Misconfiguration** | PostgreSQL pg_hba.conf allows connections from entire 10.10.0.0/16 network (host all all 10.10.0.0/16 md5). Database containing protected health information is accessible from any compromised host without additional firewall or network ACL restrictions. |
| **Why No CVE** | This is a configuration error in pg_hba.conf, not a bug in PostgreSQL code. The software works exactly as configured. The vulnerability exists because someone set overly permissive network access rules. |
| **Severity Assessment** | **Critical** | Justification: Direct database access from flat network means any single compromise (workstation, billing server, web server) can query, exfiltrate, or destroy all patient records. Combined with finding 001 (Apache RCE on billing-srv-01), this enables complete data breach without needing additional exploits. |
| **Cross-Reference 1x00** | Matches GAP-001 (Flat Network Architecture) from 1x00 T5. Also corresponds to Network Scan Finding in 1x00 T7 where PostgreSQL port 5432 was observed listening across internal subnet with no segmentation. |
| **Comparable CVE Risk** | **CVE-2021-44790** (Apache mod_lua RCE, CVSS 9.8). Both provide complete system compromise through their respective vectors. The PostgreSQL misconfiguration requires no exploit development—just network connectivity—making it potentially easier to exploit than the CVE which requires crafting a specific HTTP request body. |

---

### Finding 006: MySQL Unrestricted Network Binding

| Field | Value |
|-------|-------|
| **Finding ID** | 006 |
| **Host** | billing-srv-01 (10.10.2.15) |
| **Misconfiguration** | MySQL bind-address set to 0.0.0.0 in /etc/mysql/mysql.conf.d/mysqld.cnf. Accepts connections from any IP on the internal network. Confirmed by authenticated scan that database contains financial records and billing data. |
| **Why No CVE** | MySQL is functioning as designed when bound to all interfaces. This is an operational configuration decision, not a software defect. The application developer chose to expose the database externally rather than binding to localhost. |
| **Severity Assessment** | **High** | Justification: Combined with flat network and finding 009 (SSH password auth enabled), attackers can attempt brute-force attacks against financial data. While not directly exposing PHI like the PostgreSQL finding, financial records enable insurance fraud and are valuable on dark web markets. |
| **Cross-Reference 1x00** | Maps to GAP-013 (Unencrypted Data in Transit) from 1x00 T5. Also relates to 1x00 T7 Control Matrix observation that billing-srv-01 had no database connection restrictions documented in firewall rules. |
| **Comparable CVE Risk** | **CVE-2020-1938** (Ghostcat, CVSS 9.8). Both allow unauthorized file/database access through misconfigured services. The MySQL finding exposes financial records directly, while Ghostcat exposes configuration files. Both are equally damaging depending on what data is accessed. |

---

### Finding 007: LDAP Signing Not Required

| Field | Value |
|-------|-------|
| **Finding ID** | 007 |
| **Host** | ad-dc-01 (10.10.2.20) |
| **Misconfiguration** | Active Directory domain controller does not require LDAP signing. SMBv1 is also enabled. This allows attackers to perform LDAP relay attacks and potentially modify directory objects. |
| **Why No CVE** | LDAP signing is a Microsoft security best practice configuration option, not a software bug. SMBv1 is deprecated but still functions when enabled. The vulnerability stems from administrators leaving insecure settings at their default values. |
| **Severity Assessment** | **High** | Justification: LDAP relay attacks allow attackers to authenticate as themselves to the domain controller and execute commands with their own permissions. Combined with flat network access (finding 007 notes any host can reach the domain controller), this enables privilege escalation without credentials. SMBv1 adds vulnerability to EternalBlue exploits if Windows XP is ever isolated. |
| **Cross-Reference 1x00** | Corresponds to GAP-004 (No MFA on Admin Access) from 1x00 T5. Also relates to 1x00 T7 Network Scan Finding where domain controllers were directly accessible from all subnets with no internal firewall. |
| **Comparable CVE Risk** | **CVE-2017-0144** (EternalBlue/MS17-010, CVSS 8.1). Both enable lateral movement and privilege escalation across the network. LDAP relay provides authenticated access through relayed credentials, while EternalBlue provides unauthenticated RCE. Both ultimately lead to domain controller compromise. |

---

### Finding 009: SSH Password Authentication Enabled

| Field | Value |
|-------|-------|
| **Finding ID** | 009 |
| **Host** | billing-srv-01 (10.10.2.15) |
| **Misconfiguration** | SSH daemon allows password-based authentication. Combined with no account lockout policy on the Linux system, this permits brute-force attacks against user accounts. ehr-srv-01 has SSH key-only auth properly configured, but billing-srv-01 does not. |
| **Why No CVE** | OpenSSH is functioning as configured. Password authentication is a valid SSH feature that was left enabled. This is an administrative decision, not a software defect or buffer overflow. |
| **Severity Assessment** | **High** | Justification: Combined with finding 001 (Apache RCE providing initial foothold), attackers can maintain persistence using SSH with brute-forced passwords. Without account lockout, unlimited password guessing attempts are possible. This finding directly contradicts 1x00 T7 observation that Linux servers had inconsistent hardening configurations. |
| **Cross-Reference 1x00** | Matches GAP-012 (Endpoint Protection Gaps) from 1x00 T5. Also appears in 1x00 T3 Walk-through observation that "SSH configuration was inconsistent between servers." |
| **Comparable CVE Risk** | **CVE-2023-38408** (OpenSSH 8.9 PKCS#11 vulnerability, CVSS 9.8). Both affect the same service (OpenSSH on Ubuntu 18.04). The misconfiguration provides broader attack surface (brute-force vs. specific exploitation conditions) but both enable unauthorized remote access. |

---

### Finding 014: Consumer-Grade Router Perimeter Device

| Field | Value |
|-------|-------|
| **Finding ID** | 014 |
| **Host** | 10.10.10.1 (Westside Clinic -- Netgear Nighthawk) |
| **Misconfiguration** | Westside Clinic perimeter device is a consumer-grade Netgear Nighthawk router. Administration interface is accessible from internal network. Lacks enterprise logging, IDS/IPS capability, granular ACL management, and VPN scalability. Terminates site-to-site IPSec VPN to MedDefense Central. |
| **Why No CVE** | The router hardware and firmware are functioning as designed for consumer use. The vulnerability arises from deploying inappropriate equipment for enterprise healthcare environment. This is an architectural and procurement decision, not a software bug. |
| **Severity Assessment** | **Critical** | Justification: Compromise of this router provides a direct authenticated tunnel into MedDefense's Central server network, bypassing the FortiGate perimeter entirely. As noted in 1x01 Task 14 Scenario 3 (Vendor Shadow), supply chain compromise through trusted channels is a primary attack vector. If an attacker compromises this router, they have the same network access as a legitimate MedDefense VPN user. |
| **Cross-Reference 1x00** | Maps to GAP-009 (Shadow IT / Westside Clinic) from 1x00 T5. Also corresponds to 1x00 T7 Network Diagram showing unmanaged network segment at Westside with no firewall rules documented. |
| **Comparable CVE Risk** | **CVE-2021-44790** (Apache RCE, CVSS 9.8). Both provide remote code execution pathways into critical infrastructure. The router misconfiguration provides permanent access via VPN tunnel, while Apache RCE provides initial foothold. Both lead to the same destination: Domain Controller access via flat network. |

---

### Finding 023: USB Mass Storage Not Restricted

| Field | Value |
|-------|-------|
| **Finding ID** | 023 |
| **Host** | Multiple (approximately 280 clinical workstations) |
| **Misconfiguration** | Group Policy does not restrict USB mass storage devices on clinical endpoints. Users can connect USB drives without restriction, creating a data exfiltration vector and potential malware entry point. |
| **Why No CVE** | This is a Windows Group Policy configuration decision, not a vulnerability in Windows itself. USB ports function exactly as Microsoft designed. The risk comes from failing to deploy security controls via GPO. |
| **Severity Assessment** | **High** | Justification: Unrestricted USB access enables insider data theft (1x01 Task 14 Scenario 2: "The Quiet Exit"). Combined with flat network access to databases, employees with legitimate workstation access can copy patient records to removable media without detection. No logging or DLP controls monitor USB transfers. |
| **Cross-Reference 1x00** | Matches GAP-016 (No DLP Controls) from 1x00 T5. Also corresponds to 1x00 T3 Walk-through observation that "no physical security controls on workstations for removable media." |
| **Comparable CVE Risk** | **CVE-2020-1938** (Ghostcat, CVSS 9.8). Both enable unauthorized data access and exfiltration. The USB misconfiguration requires insider access while Ghostcat requires remote exploitation, but both provide pathways to extract sensitive data (PHI/financial records) without triggering alarms. |

---

## Comparative Analysis Summary

| Finding | CVE Equivalent | Why Misconfiguration Can Be Worse |
|---------|---------------|-----------------------------------|
| PostgreSQL Unrestricted (003) | CVE-2021-44790 | No exploit code needed—any network connectivity provides database access |
| Consumer Router (014) | CVE-2021-44790 | Permanent backdoor access via trusted VPN tunnel, indistinguishable from legitimate traffic |
| LDAP Signing Disabled (007) | CVE-2017-0144 | Requires no code execution—just relays credentials across flat network |
| SSH Password Auth (009) | CVE-2023-38408 | Broader attack surface (brute-force vs. specific vulnerability conditions) |
| USB Unrestricted (023) | CVE-2020-1938 | Works with insider threat—no remote exploit needed at all |
| MySQL Unrestricted (006) | CVE-2020-1938 | Same as PostgreSQL—exposes data without requiring CVE exploitation |

---

## Final Question Answer

**Why does the statement "Our CVE scan shows nothing critical, we are secure" provide dangerous false assurance?**

Because **misconfigurations account for a significant percentage of real-world breaches** and have zero CVE scores. The MongoDB Ransomware Wave of 2017 affected 28,000 databases—all misconfigured, none with CVEs. The Capital One breach exposed 100 million records through a misconfigured AWS WAF rule, not a software vulnerability. At MedDefense, six critical misconfigurations exist (PostgreSQL unrestricted access, consumer router perimeter, LDAP signing disabled, SSH password auth, USB unrestricted, MySQL unrestricted binding) that collectively pose equal or greater risk than the highest-scoring CVEs. An attacker exploiting CVE-2021-44790 must craft a specific HTTP request; an attacker exploiting the PostgreSQL misconfiguration simply needs to connect from any compromised host. **CVE scans measure software defects but miss configuration errors, network architecture flaws, and human decisions**—the very categories that enable most breaches. Therefore, declaring security based solely on CVE results ignores the entire class of vulnerabilities that have no code to patch and no NVD page to reference, creating a false sense of security while critical attack paths remain fully open.

---

*Prepared by: Security Department*  
*References: Project 1x00 Security Posture Assessment, Project 1x01 Threat Landscape Report, MongoDB Ransomware 2017 Case Study, Capital One Breach 2019 Investigation*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
