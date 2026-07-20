# 12. The Legacy Systems
## End-of-Life Risk Assessment for Permanent Vulnerability Exposure

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 12)  

---

## System 1: Windows XP SP3 (MRI Workstation)

### System Profile

| Field | Value |
|-------|-------|
| **Hostname** | WS-RAD-01 |
| **IP Address** | 10.10.1.70 |
| **OS Version** | Windows XP SP3 |
| **Role** | MRI Scanner Control Workstation |
| **Asset Criticality (1x00)** | Tier 1 — Integrity Critical, Availability Critical (patient safety) |
| **EOL Date** | April 8, 2014 (12+ years past end of support) |

### EOL Research

NVD search criteria: Windows XP, critical CVEs published since July 2024. Because NVD organizes CVEs by product rather than OS, the search was scoped to Microsoft Security Bulletins and CISA advisories covering Windows XP-post-EOL vulnerabilities.

**Results:**

- **Total CVEs disclosed post-EOL affecting Windows XP:** Hundreds. Since Microsoft stopped patching in 2014, every Windows CVE that shares code with XP (SMB, RDP, kernel) remains permanently exploitable.
- **2 Most Critical (from scan report Finding 004):**

| CVE | CVSS | Description | Published |
|-----|------|-------------|-----------|
| CVE-2019-0708 (BlueKeep) | 9.8 | RDP RCE, wormable, no authentication required | May 2019 (5 years post-EOL) |
| CVE-2017-0144 (EternalBlue/MS17-010) | 8.1 | SMB RCE, wormable, used in WannaCry | March 2017 (3 years post-EOL) |
| CVE-2008-4250 (MS08-067) | 10.0 | Server Service RCE, weaponized, used in Conficker | October 2008 (6 years pre-EOL, never patched) |

**Observation:** Windows XP has accumulated critical vulnerabilities across multiple protocols (SMB, RDP, Server Service) from both before and after EOL. Each year adds new permanent vulnerabilities as new CVEs are discovered in shared Windows code.

### Permanent Exposure

Windows XP is categorically different from "unpatched" because the vendor has permanently discontinued security patch development for this operating system. An unpatched system can eventually be fixed by applying the available patch; an EOL system cannot. Every new CVE discovered in Windows code that shares lineage with XP—from kernel subsystems to SMB and RDP protocols—becomes a permanent vulnerability that will never be remediated through patching. The risk surface grows monotonically over time; it never shrinks.

### Scan Findings Affecting This System

| Finding | Description | Exploitable Because EOL? |
|---------|-------------|--------------------------|
| **004** | BlueKeep (CVE-2019-0708) + EternalBlue (CVE-2017-0144) + MS08-067 (CVE-2008-4250) | **Yes.** All three CVEs have patches available for supported Windows versions. XP cannot receive them. BlueKeep was disclosed 5 years after XP EOL; the patch was never created for XP. |

### Compensating Controls

**Controls Proposed in 1x00 (Task 6 for Medical IoT / MRI Workstation):**
- Network isolation via dedicated VLAN (GAP-007 remediation)
- Access restricted to PACS server and authorized radiology workstations only

**Adequacy Assessment:**

| Control | Adequate? | Gap |
|---------|-----------|-----|
| VLAN isolation | Partially | Stops lateral movement but does not protect against attacks from authorized devices on same VLAN (e.g., compromised PACS server reaching MRI workstation) |
| Access restriction to PACS only | Partially | Does not address the MRI workstation accessing the network (outbound SMB/RDP scanning from compromised device) |
| Application whitelisting | Not proposed | Would prevent malware execution if workstation is compromised |
| Port-level ACLs | Not proposed | Should restrict port 3389 (RDP) and 445 (SMB) at the switch port level |

**Additional Recommended Controls:**

| Control | Purpose | Implementation |
|---------|---------|---------------|
| **Switch port ACL** | Block inbound RDP/SMB to WS-RAD-01 | Cisco: `mac access-list extended MRI-BLOCK` + `deny any any` on ports 445/3389 |
| **Application whitelisting** | Prevent malware execution | Deploy AppLocker or third-party whitelisting (SRP cannot run on XP) |
| **Network Behavior Anomaly Detection (NBAD)** | Detect unusual traffic patterns from MRI workstation | Deploy Zeek on the medical device VLAN to alert on unexpected connections |
| **Physical port lockdown** | Prevent unauthorized USB or network cable insertion | Use Kensington locks on network ports; seal unused USB ports |

### Business Decision: Migration Priority

**Priority Rank: #2 of 3** (behind billing-srv-01, ahead of print-srv-01)

**Justification:**

The MRI workstation presents a unique patient safety risk that no other system at MedDefense matches—if it is compromised, diagnostic images could be manipulated leading to incorrect medical decisions. However, it serves a single, specialized function with limited user interaction. Network isolation (VLAN + ACLs) can contain the risk while replacement is planned. The system does not store large volumes of PHI locally (images are transferred to PACS), reducing data exfiltration risk. Migration requires vendor coordination (Siemens MRI scanner software compatibility) which extends timelines beyond a single quarter. Isolate now, replace within 6-12 months.

---

## System 2: Windows Server 2012 R2 (Print Server)

### System Profile

| Field | Value |
|-------|-----------|
| **Hostname** | print-srv-01 |
| **IP Address** | 10.10.2.31 |
| **OS Version** | Windows Server 2012 R2 |
| **Role** | Print Server |
| **Asset Criticality (1x00)** | Tier 2 — Availability Medium (clinical printing) |
| **EOL Date** | October 10, 2023 (3 years past end of support) |

### EOL Research

NVD search criteria: Windows Server 2012 R2, critical CVEs published since July 2024.

**Results:**

- **Total CVEs disclosed post-EOL affecting Windows Server 2012 R2:** Dozens. Any CVE affecting the Windows kernel, SMB stack, Print Spooler, or RDP service in supported Windows versions that shares code lineage with 2012 R2 remains permanently exploitable.
- **2 Most Critical (from scan report Finding 008 and NVD research):**

| CVE | CVSS | Description | Published |
|-----|------|-------------|-----------|
| CVE-2021-34527 (PrintNightmare) | 8.8 | Print Spooler RCE/LPE, weaponized, PoC widely available | June 2021 |
| CVE-2024-38077 (Remote Desktop Licensing Service RCE) | 9.8 | Unauthenticated RCE via RDP licensing service | July 2024 (1 year post-EOL) |

**Observation:** CVE-2024-38077 is particularly alarming because it was disclosed in July 2024—nearly a full year after 2012 R2 EOL. It proves the permanent exposure thesis: even years after EOL, new critical CVEs continue to surface for this OS.

### Permanent Exposure

Windows Server 2012 R2 is categorically different from "unpatched" because Microsoft permanently discontinued security patch development. While an unpatched system on a supported OS has a remediation path (apply the pending patch), an EOL system has no path. CVE-2024-38077, disclosed in July 2024, demonstrates this: the vulnerability was found after EOL, so no Server 2012 R2 patch was ever created. The system permanently carries a 9.8 CVSS vulnerability that will never be fixed through patching.

### Scan Findings Affecting This System

| Finding | Description | Exploitable Because EOL? |
|---------|-------------|--------------------------|
| **008** | Windows Server 2012 R2 EOL detection; CVE-2021-34527 (PrintNightmare) confirmed present with Print Spooler service running | **Yes.** PrintNightmare patches were released for supported Windows versions but not for EOL 2012 R2. The Print Spooler service cannot be disabled because the system is a print server. |

### Compensating Controls

**Controls Proposed in 1x00 (Task 6):**
- No specific compensating controls were proposed for print-srv-01 in 1x00. The posture assessment focused on Tier 1 assets (EHR, Domain Controllers, MRI workstation) and did not address Tier 2 infrastructure servers in detail.

**Adequacy Assessment:**

No compensating controls were proposed because print-srv-01 was not individually assessed in 1x00. This is itself a gap—Tier 2 systems on the flat network can serve as lateral movement pivot points even if they don't hold PHI directly.

**Additional Recommended Controls:**

| Control | Purpose | Implementation |
|---------|---------|---------------|
| **Disable Print Spooler service** | Eliminate PrintNightmare attack surface | Not feasible—system is a print server; would break clinical printing |
| **Network isolation** | Prevent lateral movement from/to print server | Deploy print server on isolated VLAN with ACLs restricting access to clinical workstations only |
| **Inbound port filtering** | Block SMB (445) and RDP (3389) to print server | Apply port-based ACL on switch; only allow print traffic (9100, 631, 515) |
| **Endpoint Detection and Response** | Detect exploitation attempts | Deploy EDR agent compatible with 2012 R2 (e.g., CrowdStrike Falcon for legacy Windows) |
| **Replace print service** | Eliminate EOL dependency entirely | Migrate print services to Windows Server 2022 or cloud-based print management |

### Business Decision: Migration Priority

**Priority Rank: #3 of 3** (lowest priority for migration)

**Justification:**

print-srv-01 is a Tier 2 asset with medium availability criticality. While PrintNightmare is a serious vulnerability (CVSS 8.8), the print server does not store PHI, does not process financial transactions, and does not authenticate users to core systems. Compromise would disrupt clinical printing but would not directly impact patient data or medical decisions. Network isolation can contain the risk effectively because print traffic is well-defined (ports 9100, 631, 515) and can be ACL'd without disrupting clinical workflows. Migration to Windows Server 2022 is straightforward (no vendor dependency, no specialized hardware). Budget should be allocated to Tier 1 system replacement first.

---

## System 4: Ubuntu 18.04 LTS (Billing Server)

### System Profile

| Field | Value |
|-------|-------|
| **Hostname** | billing-srv-01 |
| | 10.10.2.15 |
| | Ubuntu 18.04.6 LTS |
| **Role** | Billing Application Server (Apache, MySQL, SSH) |
| **Asset Criticality (1x00)** | Tier 1 — Confidentiality High, Integrity High, Availability High |
| **EOL Date** | June 2023 (3 years past standard support) |

### EOL Research

NVD search criteria: Ubuntu 18.04, critical CVEs published since July 2024.

**Results:}

- **Total CVEs disclosed post-EOL affecting Ubuntu 18.04:** Hundreds. Ubuntu 18.04 uses kernel 4.15 which has accumulated numerous CVEs. Without Extended Security Maintenance (ESM) enrollment, none of these are patched.
- **2 Most Critical (from scan report Findings 001, 002, 026 and NVD research):**

| CVE | CVSS | Description | Published |
|-----|------|-------------|-----------|
| CVE-2021-44790 (Apache mod_lua) | 9.8 | Buffer overflow RCE, weaponized, CISA KEV listed | December 2021 |
| CVE-2024-1086 | 7.8 | Linux kernel netfilter use-after-free, local privilege escalation | January 2024 (8 months post-EOL) |

**Observation:** CVE-2024-1086 is a kernel-level LPE disclosed in January 2024, 7 months after Ubuntu 18.04 EOL. No patch will ever be delivered without ESM enrollment. This CVE specifically enables escalation from www-data (Apache user) to root—directly chaining with Finding 001.

### Permanent Exposure

Ubuntu 18.04 is categorically different from "unpatched" because Canonical has discontinued standard security patch development. While an unpatched system on a supported OS has a remediation path (apply the pending patch), an EOL system without ESM has no path. CVE-2024-1086, disclosed in January 2024, demonstrates this: the vulnerability was found after EOL, so no standard Ubuntu 18.04 patch was ever created. The system permanently carries a kernel-level privilege escalation vulnerability that will never be fixed through standard patching. The only remediation paths are ESM enrollment or OS migration.

### Scan Findings Affecting This System

| Finding | Description | Exploitable Because EOL? |
|---------|-------------|--------------------------|
| **001** | Apache mod_lua buffer overflow (CVE-2021-44790) | Partially. Patch exists for Apache on supported OS, but Ubuntu 18.04 without ESM may not deliver the Apache patch through standard repositories. |
| **002** | Apache privilege escalation (CVE-2019-0211) | Partially. Same as above—patch exists but delivery depends on OS support status. |
| **006** | MySQL unrestricted network binding | No—this is a misconfiguration, not EOL-dependent. |
| **009** | SSH password authentication enabled | No—this is a misconfiguration, misconfiguration. |
| **011** | Ubuntu 18.04 EOL without ESM enrollment | **Yes.** No OS-level security patches for 47 kernel CVEs. |
| **026** | Kernel 4.15.0-213 has 4.7 known CVEs with available patches | **Yes.** Patches exist but cannot be applied without ESM or OS upgrade. |

### Compensating Controls

**Controls Proposed in 1x00:**
- No specific compensating controls were proposed for billing-srv-01. The posture assessment identified it as Tier 1 critical but did not propose specific hardening measures beyond general recommendations for Linux server hardening.

**Aadequacy Assessment:**

No compensating controls were proposed because 1x00 did not focus on billing-srv-01 hardening. This is a significant gap, given that the system is already compromised (crypto-miner active for 14+ days) and hosts 6 of the 31 scan findings.

**Additional Recommended Controls:**

| Control | Purpose | Implementation |
|---------|---------|---------------|
| **Immediate incident response** | Contain active cryptominer compromise | Isolate server, preserve forensic evidence, rebuild from known-good baseline |
| **OS migration to Ubuntu 22.04 LTS or 24.04 LTS** | Eliminate EOL kernel and package vulnerabilities | Backup application data, deploy fresh Ubuntu 24.04, restore application |
| **Apache upgrade** | Eliminate CVE-2021-44790 and CVE-2019-0211 | Upgrade to Apache 2.4.52+ on new OS |
| **MySQL binding restriction** | Eliminate Finding 006 | Set `bind-address = 127.0.0.1` in mysqld.cnf |
| **SSH key-only authentication** | Eliminate SSH password auth and unlock | Set `PasswordAuthentication no` in sshd_config |
| **File integrity monitoring** | Detect future compromise | Deploy AIDE with daily baseline checks |
| **Centralized logging** | Enable forensic visibility | Configure rsyslog to forward to SIEM |
| **Waf / reverse proxy** | Add defense-in-depth for Apache RCE | Deploy ModSecurity WAF in front of Apache |

### Business Decision: Migration Priority

**Priority Rank: #1 of 3** (highest priority for migration)

**Justification:**

billing-srv-01 is the **most critical EOL system at MedDefense** and must be migrated first for the following reasons:

1. **Already compromised.** Unlike the MRI workstation and print server, billing-srv-01 has an active crypto-miner (Finding 002). This is not theoretical risk; it is an ongoing breach. The attacker may have established persistence mechanisms that patching alone cannot remediate. System rebuild is required.
2. **Highest threat exposure.** Kill Chain #1 (Apache RCE → Ransomware) from 1x01 Task 10 originates on this server. The Apache RCE vulnerability (CVE-2021-44790, CVSS 9. compromise could begin with a single unauthenticated HTTP request.
3. **6 of 31 findings.** billing-srv-01 hosts 6 findings (001, 002,  heat map showed this server as the most vulnerable host in the environment.
6. **Active exploitation confirmed.** CISA KEV lists CVE-2021-44790 as actively exploited. Combined with the existing cryptominer compromise, this server is a live battlefield.
5. **Chains with flat network.** Compromise of billing-srv-01 provides foothold for lateral movement to ehr-db-01 (Finding 003), ad-dc-01 (Finding 007), and NAS-01 (Finding 015).
6. **Financial data + PHI exposure.** The server contains billing records, insurance claims, and potentially payment card data. A breach triggers PCI DSS and HIPAA obligations simultaneously.
7. **Migration is feasible.** Unlike the MRI workstation (vendor-dependent) or print server (clinical workflow disruption), migrating billing application to a supported OS is a standard IT operation. No specialized hardware or vendor dependencies.

---

## Summary: EOL System Comparison

| System | OS | EOL Date | Years Past EOL | Asset Tier | Active Compromise? | Kill Chain Origin? | Migration Priority |
|--------|----|----------|----------------|------------|---------------------|-------------------|-------------------|
| **billing-srv-01** | Ubuntu 18.04 | June 2023 | 3 | Tier 1 | **Yes** (cryptominer) | **Yes** (Kill Chain #1) | **#1 — Immediate** |
| **WS-RAD-01** | Windows XP | April 2014 | 12 | Tier 1 | No | Yes (Kill Chain #3) | **#2 — Isolate then replace** |
| **print-srv-01** | Windows Server 2012 R2 | Oct 2023 | 3 | Tier 2 | No | No (pivot point only) | **#3 — Isolate then migrate** |

---

## Strategic Insight: The EOL Risk Formula

The risk of an EOL system is not just the number of CVEs it has today. It is the number of CVEs it has today PLUS the CVEs that will be discovered tomorrow. That number grows every month. Every security researcher who finds a Windows kernel bug in 2024 or 2025 is adding a permanent vulnerability to WS-RAD-01. Every Linux kernel CVE discovered in 2026 adds a permanent vulnerability to billing-srv-01. The EOL risk formula is:

**Risk = Current CVEs + Future CVEs (growth rate × time remaining on EOL)**

MedDefense cannot reduce the "Current CVEs" term through patching. They can only reduce "Future CVEs × time" by migrating to supported operating systems. The longer they wait, the larger the permanent vulnerability surface becomes.

---

*Prepared by: Security Department*  
*References: NVD.nist.gov, CISA Advisories, Project 1x00 Security Posture Assessment, Project 1x01 Threat Landscape Report, Project 1x02 Scan Report*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
