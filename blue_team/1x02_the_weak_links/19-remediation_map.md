# 19. The Remediation Map
## Specific Remediation Actions with Operational Constraints and Risk Assessment

**Date:** July 21, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 19)  

---

## Remediation Strategy Overview

Each of the 8 prioritized findings from Task 17 receives a tailored remediation plan addressing the operational realities of a healthcare environment. Remediation is not simply applying patches. Each action includes prerequisites, rollback planning, operational risk assessment, and clinical coordination to ensure that the cure does not cause more harm than the vulnerability.

| Metric | Value |
|--------|-------|
| Findings Addressed | 8 (All AC priority) |
| Response Types | 4 (Patch, Config, Control, Exception) |
| Immediate Actions | 5 (Within 24-48 hours) |
| Estimated Total Cost | $50K+ (Capital + labor + vendor) |

---

## Finding 001: CVE-2021-44790 (Apache mod_lua Buffer Overflow)

Response Type: Patch

If Patch:
  Patch Source: Apache HTTP Server 2.4.51+ security release (https://httpd.apache.org/security/vulnerabilities_24.html). Specific patch addresses CVE-2021-44790 buffer overflow in mod_lua r:parsebody function. For Ubuntu 18.04, the package is apache2 2.4.52-1ubuntu1.1 or later from Ubuntu security repositories or ESM archive.
  Prerequisites: (1) Snapshot VM or bare-metal backup of billing-srv-01 before patching. (2) Test Apache upgrade in staging environment with billing application to verify compatibility. (3) Coordinate maintenance window with billing department for off-hours deployment (recommended Saturday 02:00-06:00). (4) Notify Finance Director and Billing Manager of planned downtime. (5) Prepare rollback backup of current Apache configuration files (httpd.conf, mod_lua configuration, virtual host configs).
  Rollback Plan: (1) If billing application fails to load after Apache upgrade, execute VM snapshot rollback or restore Apache 2.4.41 from backup package. (2) Revert httpd.conf and virtual host configurations from pre-patch backup. (3) Restart Apache service: systemctl restart apache2. (4) Verify billing application functionality with billing department test user. (5) If rollback fails, engage Apache troubleshooting: check error logs at /var/log/apache2/error.log, verify module loading with apache2ctl -M, validate mod_lua configuration syntax.
  Operational Risk: (1) Apache 2.4.51+ may require updated PHP modules if billing application uses PHP, creating dependency chain. (2) mod_lua configuration syntax may have changed between versions, requiring configuration file updates. (3) SSL/TLS configuration may need regeneration if Apache 2.4.51+ enforces stricter default cipher policies. (4) Billing application vendor may not certify compatibility with Apache 2.4.51+, requiring vendor engagement. (5) Server restart may disrupt active billing batch processes running overnight. (6) On Ubuntu 18.04 EOL, the patched Apache package may not be available in standard repositories without ESM enrollment (ties to Finding 011 remediation).

Timeline: Immediate (within 24 hours)  
Owner: IT Infrastructure Team (execution), Security Department (validation), Billing Department (user acceptance testing)  
Cost Estimate: $1-10K (engineering time, potential vendor consultation)

---

## Finding 031: CVE-2020-1938 (Ghostcat)

Response Type: Configuration Change

If Configuration Change:
  Change Description: Disable or restrict the Apache Tomcat AJP connector on ehr-srv-01. Three options in priority order: (1) Preferred: Comment out or remove the AJP Connector element in server.xml located at /opt/tomcat/conf/server.xml. Locate the Connector port="8009" protocol="AJP/1.3" element and comment out with XML comment tags. (2) Alternative if AJP is required for EHR application: Restrict AJP listener to localhost only by adding address="127.0.0.1" attribute to the Connector element. (3) If EHR application requires remote AJP: Add secret and secretRequired="true" attributes to enforce AJP authentication (requires Tomcat 9.0.31+ behavior verification).
  Impact Assessment: (1) Removing AJP connector will break any EHR application component that relies on AJP for Tomcat-to-Apache communication or load balancing. Must verify with EHR vendor whether AJP is used for application functionality. (2) Restricting to localhost only affects any reverse proxy or load balancer connecting via AJP from another host. (3) Adding secret attribute requires updating all AJP clients with the shared secret. (4) Tomcat restart required: systemctl restart tomcat (approximately 2-3 minutes of EHR application downtime). (5) Clinical staff will be unable to access patient records during restart window. Coordinate with Nursing Supervisor and Chief Medical Officer for maintenance window (recommended Sunday 04:00-06:00).

Timeline: Immediate (within 24 hours)  
Owner: IT Infrastructure Team (execution), EHR Vendor Support (compatibility verification), Clinical Operations (downtime coordination)  
Cost Estimate: $1-10K (engineering time, potential vendor consultation)

---

## Finding 004: CVE-2019-0708 (BlueKeep) and CVE-2017-0144 (EternalBlue) on Windows XP MRI Workstation

Response Type: Compensating Control

If Compensating Control:
  Control Description: Network isolation of WS-RAD-01 via switch port ACL and dedicated medical device VLAN. Specific actions: (1) Configure Cisco switch port connected to WS-RAD-01 with port-based ACL blocking inbound traffic on TCP port 3389 (RDP) and TCP port 445 (SMB) from all sources except authorized PACS server IP (10.10.2.20). (2) Move WS-RAD-01 to dedicated VLAN 30 (Medical Device VLAN, 10.10.30.x) with inter-VLAN routing denied by default. (3) Configure firewall rule on core switch permitting only required traffic: DICOM (TCP 104) to PACS server, DNS (UDP 53) to ad-dc-01, and NTP (UDP 123) to time server. (4) Deploy Zeek network sensor on Medical Device VLAN for traffic anomaly detection. (5) Install physical USB port locks on WS-RAD-01 to prevent unauthorized device insertion.
  Residual Risk: (1) Wormable malware already present on another host in the same broadcast domain could still reach WS-RAD-01 if VLAN migration is not completed before ACL deployment. (2) An authorized PACS server compromised via another vulnerability could still reach WS-RAD-01 through the permitted DICOM traffic. (3) Physical access to the workstation bypasses network controls entirely. (4) Windows XP retains all unpatched CVEs (hundreds) and will accumulate more over time. (5) The MRI workstation vendor (Siemens) may require SMB access for vendor maintenance, requiring temporary ACL rule additions that create scheduling-dependent security gaps. Network isolation reduces risk by an estimated 90% but does not eliminate it. The only complete remediation is OS replacement, which requires vendor-compatible hardware and software upgrade (scheduled for 6-12 month timeline under capital budget).

Timeline: Immediate (within 24 hours for ACL deployment), 30 days (full VLAN migration)  
Owner: Network Engineering (switch configuration), Security Operations (Zeek deployment), Biomedical Engineering (physical port locks), Siemens Vendor (long-term OS replacement consultation)  
Cost Estimate: $10-50K (Zeek sensor hardware, network reconfiguration labor, physical port locks, Siemens consultation)

---

## Finding 010: BD Alaris Default Credentials

Response Type: Compensating Control

If Compensating Control:
  Control Description: Immediate network isolation of all 7 BD Alaris infusion pumps via switch port ACLs and medical device VLAN migration. Specific actions: (1) Identify switch ports for all 7 infusion pumps via MAC address table lookup. (2) Apply port-based ACLs blocking all inbound traffic to pump IP addresses except nursing station traffic on TCP 80 (web interface) from authorized nursing subnet only, and HL7 traffic (TCP 2575) to EHR system. (3) Migrate all pumps to VLAN 30 (Medical Device VLAN) with inter-VLAN routing denied. (4) Deploy network anomaly detection sensors on pump network segment. (5) File emergency support ticket with BD to expedite firmware upgrade to version 12.1.5 or later. (6) Contact BD biomedical liaison to schedule on-site firmware upgrade sessions coordinated with clinical operations.
  Residual Risk: (1) Infusion pumps remain accessible from authorized nursing stations, and a compromised nursing station could still reach the pumps. (2) Default credentials remain active until firmware upgrade is completed, meaning any attacker who bypasses the ACL can authenticate with admin/admin. (3) HL7 traffic path to EHR system could be leveraged for lateral movement if EHR is compromised. (4) Firmware upgrade requires taking each pump offline, disrupting active infusions and requiring loaner pumps. (5) BD firmware upgrade timeline is estimated at 6-12 months, during which compensating controls are the only protection. Network isolation reduces risk by approximately 85% but the credential vulnerability persists until firmware is updated.

Timeline: Immediate (within 24 hours for ACL deployment), 30 days (VLAN migration), 90 days (firmware upgrade scheduling)  
Owner: Network Engineering (switch configuration), Biomedical Engineering (BD liaison and firmware coordination), Clinical Operations (pump downtime scheduling), Security Operations (anomaly detection)  
Cost Estimate: $10-50K (network reconfiguration, loaner pump rental during firmware upgrades, BD technician visit fees)

---

## Finding 003: PostgreSQL Unrestricted Network Access

Response Type: Configuration Change

If Configuration Change:
  Change Description: Modify PostgreSQL pg_hba.conf on ehr-db-01 to restrict database connections to authorized hosts only. Replace current rule "host all all 10.10.0.0/16 md5" with "host all all 10.10.2.10/32 md5" (restricting to ehr-srv-01 only). Additionally, configure iptables or UFW firewall rule to drop all inbound traffic on TCP port 5432 except from source IP 10.10.2.10 (ehr-srv-01). Finally, set listen_addresses = '10.10.2.11' in postgresql.conf to bind only to the database server interface rather than all interfaces.
  Impact Assessment: (1) EHR application server (ehr-srv-01) is the only authorized database client, so restricting to 10.10.2.10/32 should not disrupt normal EHR operations. (2) Any administrative tools or reporting systems that connect directly to PostgreSQL from other hosts will be blocked. Must identify all current database clients before applying the change: run PostgreSQL log analysis to identify all source IPs that have connected in the past 30 days. (3) Database administrator access from IT workstations will be blocked; must configure a jump host or VPN-based access for DBA activities. (4) PostgreSQL reload (not full restart) required: systemctl reload postgresql (no downtime, active connections preserved). (5) If any undocumented application relies on direct database access, it will fail immediately upon rule change. Have rollback procedure ready: restore previous pg_hba.conf and reload.

Timeline: Immediate (within 48 hours)  
Owner: IT Infrastructure Team / Database Administrator (execution), Security Department (validation), EHR Vendor Support (client identification)  
Cost Estimate: $0-1K (configuration change only, no hardware or software procurement)

---

## Finding 002: CVE-2019-0211 (Apache Privilege Escalation)

Response Type: Patch

If Patch:
  Patch Source: Apache HTTP Server 2.4.52+ addresses CVE-2019-0211 (CAROOT privilege escalation). Same patch package as Finding 001 (Apache upgrade to 2.4.51+). The Ubuntu package apache2 2.4.52-1ubuntu1.1 or later includes fixes for both CVE-2021-44790 and CVE-2019-0211. This remediation is executed concurrently with Finding 001 patch deployment.
  Prerequisites: (1) Same prerequisites as Finding 001 (VM snapshot, staging test, maintenance window, billing department notification). (2) Additionally, verify that the Apache binary setuid behavior is resolved after patching: run httpd -V and check that MPM prefork is used (required for CVE-2019-0211 to function; patch eliminates the vulnerability regardless of MPM). (3) Document current Apache process ownership model for post-patch comparison.
  Rollback Plan: (1) Same rollback plan as Finding 001 (VM snapshot rollback or package downgrade). (2) If privilege escalation fix breaks Apache startup (unlikely but possible if custom setuid scripts exist), restore previous Apache binary from backup and verify service startup. (3) Verify all Apache child processes are running as www-data after rollback to confirm previous state restored.
  Operational Risk: (1) CVE-2019-0211 patch modifies Apache master process privilege handling, which could affect custom startup scripts or init.d configurations. (2) If billing application uses any Apache modules that rely on setuid behavior (extremely rare), those modules may fail after patching. (3) Combined patching of CVE-2021-44790 and CVE-2019-0211 in single maintenance window increases change scope and risk of unforeseen interaction. (4) Since server is already compromised with active cryptominer, patching alone does not remove attacker persistence. Full incident response and system rebuild is required (see Finding 011 remediation).

Timeline: Immediate (within 24 hours, concurrent with Finding 001)  
Owner: IT Infrastructure Team (execution), Security Department (incident response and forensic verification)  
Cost Estimate: $1-10K (combined with Finding 001, incremental cost is minimal)

---

## Finding 011: Ubuntu 18.04 EOL Without ESM

Response Type: Exception (Short-Term) transitioning to Patch (Long-Term)

If Exception:
  Justification: Immediate OS migration for billing-srv-01 is not feasible within the 24-48 hour remediation window. The billing application must be tested for compatibility with Ubuntu 22.04 LTS or 24.04 LTS before migration. The server is already compromised with an active cryptominer, so the incident response plan takes precedence over OS migration. The short-term exception allows the server to be rebuilt on a supported OS as part of the incident response process rather than attempting an in-place upgrade on a compromised system.
  Review Date: 30 days from report date (August 20, 2026). OS migration must be completed or actively in progress by this date.
  Monitoring: (1) Deploy AIDE (Advanced Intrusion Detection Environment) file integrity monitoring on billing-srv-01 to detect unauthorized file changes. (2) Configure rsyslog to forward all auth.log and syslog entries to a centralized log collector (even a temporary SIEM or syslog server). (3) Deploy Osquery for real-time process and file monitoring. (4) Schedule daily cron job to check for new cron entries (common persistence mechanism for cryptominers). (5) Run daily chkrootkit and rkhunter scans. (6) Monitor network traffic from billing-srv-01 for C2 beaconing patterns using Zeek or tcpdump capture analysis.

If Patch (Long-Term):
  Patch Source: Ubuntu 22.04 LTS or 24.04 LTS installation media (https://releases.ubuntu.com/). Full system rebuild, not in-place upgrade, due to active compromise. New server deployment with fresh OS install, followed by billing application redeployment from known-good source code and configuration.
  Prerequisites: (1) Procure or allocate new VM or physical server hardware. (2) Install Ubuntu 22.04 LTS or 24.04 LTS with full disk encryption. (3) Harden OS per CIS Benchmark Level 1. (4) Install and configure Apache 2.4.52+, MySQL 8.0+, OpenSSH 9.0+, and all billing application dependencies. (5) Migrate billing application data from backup (not from compromised server filesystem). (6) Validate billing application functionality in staging. (7) Coordinate cutover with billing department during maintenance window.
  Rollback Plan: (1) Retain compromised billing-srv-01 powered off but preserved for forensic analysis. (2) If new server deployment fails, restore billing application to a secondary VM running the previous application stack (Apache 2.4.41 on supported OS with patches applied as interim measure). (3) Engage billing application vendor for emergency support if migration fails.
  Operational Risk: (1) Billing application may have undocumented dependencies on Ubuntu 18.04 specific library versions. (2) Data migration from compromised server risks transferring backdoor or malware with application data. Must use sanitized database export (SQL dump) rather than filesystem copy. (3) DNS and application configuration changes required to point users to new server IP. (4) Extended downtime during cutover may impact billing operations (estimated 4-8 hours). (5) IP address change may require firewall rule updates and application configuration changes across multiple systems.

Timeline: 30 days (exception with monitoring), 90 days (full OS migration and rebuild)  
Owner: IT Infrastructure Team (OS deployment), Billing Application Vendor (application migration), Security Department (incident response and forensic preservation), Billing Department (user acceptance testing)  
Cost Estimate: $10-50K (new server hardware or VM provisioning, vendor consultation, engineering time, potential data migration services)

---

## Finding 007: LDAP Signing Not Required

Response Type: Configuration Change

If Configuration Change:
  Change Description: Enforce LDAP signing and channel binding on ad-dc-01 and ad-dc-02 via Group Policy. Specific actions: (1) Open Group Policy Management Console on ad-dc-01. (2) Create new GPO named "LDAP Security Hardening" linked to the Domain Controllers OU. (3) Configure Computer Configuration - Administrative Templates - System - Domain Controller - LDAP server signing requirements: Set to "Require signing". (4) Configure Computer Configuration - Administrative Templates - System - LDAP Client - LDAP client signing requirements: Set to "Require signing". (5) Configure Domain Controller: LDAP channel binding enforcement: Set to "Enabled" initially (Phase 1), then "Strict" after 30-day validation period (Phase 2). (6) Enable SMB signing via GPO: Microsoft Network Client - Digitally sign communications (always): Enabled. (7) Apply GPO to Domain Controllers OU first, then deploy to all workstations via Default Domain Policy after testing.
  Impact Assessment: (1) Phase 1 (LDAP signing required): Legacy applications that perform unsigned LDAP queries will fail. Must identify all applications using LDAP for authentication. Common candidates: legacy billing application, HVAC management system, badge access system, and any application using LDAP without StartTLS. Run AD audit log analysis for unsigned LDAP binds before enforcing. (2) Phase 2 (Channel binding strict): Additional applications may fail if they do not support channel binding. This includes older Java applications and some third-party identity management tools. (3) SMB signing enforcement may cause performance degradation on file shares (approximately 10-15% throughput reduction on SMB transfers). (4) Windows XP MRI workstation (WS-RAD-01) may not support LDAP channel binding. Must verify if WS-RAD-01 performs LDAP queries to domain controllers and exempt if necessary using separate GPO. (5) GPO application does not require server reboot but may require gpupdate /force on target systems. (6) Application of SMB signing GPO to all workstations should be staged in pilot groups to identify affected applications before organization-wide deployment.

Timeline: 7 days (Phase 1 signing enforcement on DCs), 30 days (Phase 2 channel binding), 90 days (organization-wide GPO rollout)  
Owner: IT Infrastructure Team (GPO creation and deployment), Security Department (audit log analysis and validation), Application Owners (legacy application compatibility testing)  
Cost Estimate: $1-10K (engineering time, potential legacy application vendor consultation for compatibility fixes)

---

## Remediation Summary Matrix

| Finding | Response Type | Timeline | Owner | Cost Estimate | Clinical Impact |
|---------|--------------|----------|-------|----------------|-----------------|
| 001 | Patch | Immediate (24h) | IT Infrastructure | $1-10K | Billing downtime 2-4h |
| 031 | Configuration Change | Immediate (24h) | IT Infrastructure | $1-10K | EHR downtime 2-3m |
| 004 | Compensating Control | Immediate (24h) / 30 days | Network Engineering | $10-50K | No clinical impact (ACL only) |
| 010 | Compensating Control | Immediate (24h) / 90 days | Biomedical Engineering | $10-50K | Pump downtime for firmware |
| 003 | Configuration Change | Immediate (48h) | Database Administrator | $0-1K | No downtime (reload) |
| 002 | Patch | Immediate (24h) | IT Infrastructure | $1-10K | Combined with Finding 001 |
| 011 | Exception then Patch | 30 days / 90 days | IT Infrastructure | $10-50K | Billing downtime 4-8h |
| 007 | Configuration Change | 7 days / 90 days | IT Infrastructure | $1-10K | Legacy app failure risk |

---

## Remediation Sequencing and Dependencies

### Phase 1: Immediate Actions (0-48 Hours)

| Sequence | Action | Dependency | Rationale |
|----------|--------|------------|-----------|
| 1 | Isolate billing-srv-01 from network (except SSH from jump host) | None | Stop active cryptominer C2 communication and prevent lateral movement |
| 2 | Apply Apache patch (Findings 001 and 002) | Sequence 1 (network isolation allows controlled patching) | Eliminate RCE and privilege escalation on compromised server |
| 3 | Restrict AJP connector on ehr-srv-01 (Finding 031) | None (independent of billing server) | Eliminate Ghostcat exploitation path to EHR credentials |
| 4 | Restrict PostgreSQL access on ehr-db-01 (Finding 003) | Sequence 3 (must ensure EHR app still connects) | Break data exfiltration kill chain |
| 5 | Deploy switch port ACLs on WS-RAD-01 (Finding 004) | None | Block wormable exploitation of MRI workstation |
| 6 | Deploy switch port ACLs on BD Alaris pumps (Finding 010) | None | Block default credential access to infusion pumps |

### Phase 2: Short-Term Remediation (7-30 Days)

| Sequence | Action | Dependency | Rationale |
|----------|--------|------------|-----------|
| 7 | Deploy AIDE file integrity monitoring on billing-srv-01 (Finding 011 exception) | Phase 1 complete | Detect further compromise while OS migration is planned |
| 8 | Enforce LDAP signing on domain controllers (Finding 007 Phase 1) | AD audit log analysis | Eliminate NTLM relay against domain controllers |
| 9 | Begin VLAN migration for medical devices (Findings 004 and 010) | Switch configuration planning | Long-term isolation of medical IoT |
| 10 | Begin OS migration planning for billing-srv-01 (Finding 011 patch) | Vendor consultation | Replace EOL system with supported OS |

### Phase 3: Long-Term Remediation (90 Days)

| Sequence | Action | Dependency | Rationale |
|----------|--------|------------|-----------|
| 11 | Complete billing-srv-01 OS migration and application redeployment | Phase 2 planning | Eliminate EOL system permanently |
| 12 | Deploy LDAP channel binding strict mode (Finding 007 Phase 2) | Phase 2 Phase 1 validated | Full LDAP relay protection |
| 13 | Complete BD Alaris firmware upgrades (Finding 010) | BD technician scheduling | Eliminate default credential vulnerability |
| 14 | Initiate Windows XP MRI workstation replacement planning (Finding 004) | Siemens vendor consultation | Long-term elimination of EOL medical device risk |

---

## Key Operational Considerations

### Incident Response Takes Precedence Over Patching

billing-srv-01 is actively compromised with a cryptominer (Finding 002). Standard patching procedures assume a clean system. Patching a compromised system without first performing incident response may leave attacker persistence mechanisms (cron jobs, SSH keys, rootkits) active after the patch is applied. The recommended sequence is: (1) isolate the server from the network, (2) preserve forensic evidence (memory dump, disk image), (3) attempt patching if the system must remain online, (4) schedule full OS rebuild as soon as possible. The incident response plan should be activated in parallel with the remediation plan.

### Clinical Coordination Is Non-Negotiable

Any change affecting EHR availability (Finding 031 Tomcat restart) or medical device connectivity (Findings 004 and 010 ACL deployment) must be coordinated with Clinical Operations. The Chief Medical Officer and Nursing Supervisor must approve maintenance windows. Downtime procedures (paper charting fallback) must be prepared and communicated to clinical staff before any change that could affect EHR access. Medical device changes must be scheduled during shift changes when pump inventories allow for loaner deployment.

### Rollback Plans Must Be Tested

Every remediation action includes a rollback plan, but rollback plans are only effective if they are tested. Before applying any patch or configuration change in production, the rollback procedure must be validated in a staging environment. An untested rollback plan provides false confidence and may extend downtime if the remediation fails and the rollback also fails. For critical changes (Findings 001, 031, 011), rollback testing is mandatory before production deployment.

---

*Prepared by: Security Department*  
*References: Project 1x02 Task 17 CVSS Contextualizer, Project 1x00 Control Matrix, Project 1x01 Kill Chain Analysis, Apache Security Advisories, BD Security Bulletin, Microsoft Security Baselines*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
