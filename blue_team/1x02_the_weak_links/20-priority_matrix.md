# 20. The Priority Matrix
## Definitive Vulnerability Remediation Timeline

**Date:** July 21, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 20)  

---

## Priority Matrix Overview

This document consolidates all 25 Actionable findings (9 Actionable Critical and 16 Actionable Standard from Task 16 triage) into a time-boxed remediation plan. Entries are sorted within each horizon by priority. Every entry includes a one-line description, a one-line remediation action, a designated owner, and an estimated cost.

---

## Horizon 1: Immediate (24-48 Hours)

Criteria: Weaponized exploit available AND critical asset affected AND active threat or confirmed compromise.

| Seq | Finding | Description | Remediation Action | Owner | Est. Cost |
|-----|---------|-------------|--------------------|-------|-----------|
| 1 | 001 | Apache mod_lua RCE (CVSS 9.8) on actively compromised billing server | Upgrade Apache to 2.4.51+ and activate incident response for cryptominer | IT Infrastructure + Security | $1-10K |
| 2 | 002 | Apache privilege escalation (CVSS 7.8→8.1) chaining with Finding 001 for root access | Apply same Apache upgrade as Finding 001, concurrent deployment | IT Infrastructure + Security | Included in #1 |
| 3 | 011 | Ubuntu 18.04 EOL without ESM, accumulating permanent kernel and package CVEs | Deploy AIDE file integrity monitoring as exception control, plan OS rebuild | IT Infrastructure + Security | $1-10K |
| 4 | 031 | Ghostcat (CVSS 9.8) on EHR server, unauthenticated file read via AJP port 8009 | Disable or restrict AJP connector in Tomcat server.xml, restart service | IT Infrastructure | $1-10K |
| 5 | 003 | PostgreSQL unrestricted network access on EHR database (50,000+ patient records) | Modify pg_hba.conf to restrict to ehr-srv-01 only, add firewall rule on port 5432 | Database Administrator | $0-1K |
| 6 | 004 | BlueKeep and EternalBlue on Windows XP MRI workstation, wormable RCE | Deploy switch port ACL blocking ports 3389 and 445 inbound to WS-RAD-01 | Network Engineering | $1-10K |
| 7 | 010 | BD Alaris infusion pumps with default credentials (admin/admin), patient safety risk | Deploy switch port ACLs on all 7 pump ports, restrict access to nursing subnet only | Network Engineering + Biomedical | $1-10K |
| 8 | 007 | LDAP signing not required on domain controller, enabling NTLM relay | Enable LDAP signing requirement GPO on Domain Controllers OU (Phase 1) | IT Infrastructure | $1-10K |
| 9 | 009 | SSH password authentication enabled on compromised billing server | Disable SSH password auth, enforce key-based auth only, revoke known compromised keys | IT Infrastructure | $0-1K |

Immediate Horizon Subtotal: $7-61K (midpoint ~$34K)

---

## Horizon 2: Short-Term (7 Days)

Criteria: Critical or High CVE with public PoC available AND important asset affected.

| Seq | Finding | Description | Remediation Action | Owner | Est. Cost |
|-----|---------|-------------|--------------------|-------|-----------|
| 10 | 008 | PrintNightmare (CVSS 8.8) on EOL Windows Server 2012 R2 print server | Disable Print Spooler where possible or deploy Microsoft out-of-band patch if available, restrict inbound SMB | IT Infrastructure | $1-10K |
| 11 | 017 | Tomcat version disclosure on EHR server enabling Ghostcat exploitation | Remove Server header from Tomcat response, set xpoweredBy=false | IT Infrastructure | $0-1K |
| 12 | 019 | TLS 1.0 enabled with weak cipher suites on EHR server | Disable TLS 1.0/1.1, enable TLS 1.2+ only, remove CBC and 3DES ciphers | IT Infrastructure | $0-1K |
| 13 | 018 | Missing HSTS header on EHR server | Add Strict-Transport-Security header to Tomcat/Apache configuration | IT Infrastructure | $0-1K |
| 14 | 015 | Backup NAS web interface exposed on flat network, chains with OSINT CVE-2023-1383 | Restrict DSM management interface to management subnet via IP whitelist | IT Infrastructure | $0-1K |
| 15 | 030 | NAS admin login page accessible without IP restriction | Apply IP whitelist to NAS admin interface, change default DSM port | IT Infrastructure | $0-1K |

Short-Term Horizon Subtotal: $1-15K (midpoint ~$8K)

---

## Horizon 3: Medium-Term (30 Days)

Criteria: High or Medium CVE, significant misconfiguration, or systematic configuration issue.

| Seq | Finding | Description | Remediation Action | Owner | Est. Cost |
|-----|---------|-------------|--------------------|-------|-----------|
| 16 | 006 | MySQL unrestricted network binding on billing server | Set bind-address to 127.0.0.1 in mysqld.cnf, verify billing app connectivity | IT Infrastructure | $0-1K |
| 17 | 026 | Kernel 4.15 with known CVEs on billing-srv-01 (EOL dependency) | Enroll in Ubuntu ESM as interim or begin OS migration (ties to Finding 011) | IT Infrastructure | $1-10K |
| 18 | 016 | Philips IntelliVue monitors expose unauthenticated web interface on port 80 | Configure monitors to restrict web interface to PACS VLAN only, disable if unused | Biomedical Engineering | $1-10K |
| 19 | 024 | HL7 messaging between monitors and EHR transmitted in cleartext | Deploy TLS overlay for HL7 traffic or implement network-level encryption between VLANs | Network Engineering + Biomedical | $10-50K |
| 20 | 027 | Apache version disclosure and directory listing on internet-facing patient portal | Disable directory listing (Options -Indexes), remove Server header, upgrade Apache | IT Infrastructure | $0-1K |
| 21 | 014 | Consumer-grade Netgear router as Westside Clinic VPN endpoint | Replace with enterprise firewall (FortiGate 40F or equivalent), migrate VPN tunnel | Network Engineering | $10-50K |
| 22 | 028 | Shadow IT device (10.10.2.99) running undocumented Linux with Grafana 8.2.0 | Identify device owner, decommission or register, update or remove Grafana | IT Infrastructure | $0-1K |
| 23 | 013 | SMBv1 enabled on domain controller ad-dc-01 | Disable SMBv1 via GPO, verify WS-RAD-01 connectivity impact (may require exemption) | IT Infrastructure | $0-1K |
| 24 | 005 | Domain controller ad-dc-02 missing critical Windows patches | Apply latest cumulative update during maintenance window | IT Infrastructure | $0-1K |
| 25 | 021 | Windows Event Log forwarding not configured on ad-dc-02 | Configure WEF subscription to central log collector or SIEM | IT Infrastructure | $1-10K |

Medium-Term Horizon Subtotal: $13-125K (midpoint ~$69K)

---

## Horizon 4: Long-Term (90 Days)

Criteria: Architecture changes, EOL migrations, systemic fixes requiring vendor coordination or capital expenditure.

| Seq | Finding | Description | Remediation Action | Owner | Est. Cost |
|-----|---------|-------------|--------------------|-------|-----------|
| 26 | 011 (cont.) | Ubuntu 18.04 EOL: full OS migration for billing-srv-01 | Deploy new server on Ubuntu 22.04/24.04 LTS, migrate billing application from sanitized SQL dump, retire compromised server | IT Infrastructure + Vendor | $10-50K |
| 27 | 007 (cont.) | LDAP signing Phase 2: enforce strict channel binding organization-wide | Deploy channel binding strict mode via GPO to all workstations after application compatibility testing | IT Infrastructure | $1-10K |
| 28 | 004 (cont.) | Windows XP MRI workstation: VLAN migration and Zeek deployment | Complete Medical Device VLAN migration, deploy Zeek sensor, engage Siemens for OS replacement planning | Network Engineering + Biomedical + Vendor | $10-50K |
| 29 | 010 (cont.) | BD Alaris firmware upgrade to 12.1.5+ across all 7 pumps | Coordinate with BD technician for on-site firmware upgrades, schedule loaner pumps | Biomedical Engineering + Vendor | $10-50K |

Long-Term Horizon Subtotal: $31-160K (midpoint ~$96K)

---

## Consolidated Remediation Summary

| Horizon | Timeline | Finding Count | Cost Range | Cost Midpoint |
|---------|----------|---------------|------------|---------------|
| Immediate | 24-48 hours | 9 | $7-61K | $34K |
| Short-Term | 7 days | 6 | $1-15K | $8K |
| Medium-Term | 30 days | 10 | $13-125K | $69K |
| Long-Term | 90 days | 4 | $31-160K | $96K |
| **Total** | | **29** | **$52-361K** | **$207K** |

Note: Finding counts in Long-Term horizon are continuations of findings also listed in earlier horizons. Total unique findings addressed: 25 Actionable findings from T16.

---

## Budget Summary

### Total Estimated Remediation Cost vs. Annual Security Budget

| Item | Amount |
|------|--------|
| Immediate Horizon (24-48h) | $7-61K |
| Short-Term Horizon (7 days) | $1-15K |
| Medium-Term Horizon (30 days) | $13-125K |
| Long-Term Horizon (90 days) | $31-160K |
| **Total Remediation Cost Range** | **$52K - $361K** |
| **Total Remediation Cost (Midpoint)** | **$207K** |
| MedDefense Annual Security Budget (from 1x00) | $120K |
| **Budget Deficit (Midpoint)** | **$87K** |
| **Budget Surplus (Best Case)** | **$68K** |

### Budget Analysis

At the midpoint estimate of $207K, MedDefense faces an $87K shortfall against its $120K annual security budget. Even at the most optimistic estimate ($52K), the remediation consumes 43% of the annual budget, leaving no room for ongoing operations, tooling, or unplanned security incidents. At the pessimistic estimate ($361K), the remediation exceeds the annual budget by 201%.

The realistic scenario falls between midpoint and pessimistic because several cost drivers are not negotiable: the Westside Clinic router replacement ($10-50K), the billing server OS migration ($10-50K), the Zeek sensor deployment for medical device VLAN ($10-50K), and the BD Alaris firmware upgrade coordination ($10-50K) are all capital-intensive projects with vendor dependencies that limit cost optimization.

### What Must Be Deferred and Why

Given the $120K budget constraint, the following remediation actions must be deferred beyond the 90-day horizon:

| Deferred Action | Finding | Estimated Cost | Reason for Deferral |
|------------------|---------|----------------|---------------------|
| Siemens MRI workstation OS replacement | 004 | $50K+ | Requires vendor-compatible hardware and software certification. Capital expenditure requires board approval and cannot be completed within fiscal year. Compensating controls (VLAN + ACL + Zeek) provide interim protection. |
| HL7 TLS encryption overlay | 024 | $10-50K | Requires medical device vendor validation of TLS implementation. May require firmware updates on Philips monitors. Can be deferred if Medical Device VLAN segmentation is completed, isolating HL7 traffic from the flat network. |
| Full SIEM deployment for WEF forwarding | 021 | $10-50K | Commercial SIEM platforms exceed available budget. Defer to next fiscal year. Interim: deploy open-source syslog-ng central collector for basic log aggregation. |
| LDAP channel binding strict mode rollout | 007 | $1-10K | Not deferring the Phase 1 (signing) but deferring Phase 2 (strict channel binding) due to application compatibility testing requirements that extend beyond 90 days. |

### Budget Allocation Recommendation

| Allocation | Amount | Percentage |
|------------|--------|------------|
| Immediate Actions (Horizon 1) | $34K | 28% |
| Short-Term Actions (Horizon 2) | $8K | 7% |
| Medium-Term Actions (Horizon 3) | $69K | 58% |
| Reserve for Unplanned Incidents | $9K | 7% |
| **Total Budget** | **$120K** | **100%** |

This allocation prioritizes all Immediate and Short-Term actions (consuming 35% of budget), funds the most critical Medium-Term actions including the Westside router replacement and billing server OS migration (58%), and retains a 7% reserve for unplanned security incidents or cost overruns. Long-Term actions are deferred to the next fiscal year's capital budget, with compensating controls deployed as interim protection.

The deferral of the Siemens MRI workstation replacement and the HL7 encryption overlay represents accepted residual risk. Both deferrals are mitigated by network segmentation (Medical Device VLAN) deployed as an Immediate compensating control. The segmentation reduces the risk of these deferred items from catastrophic to moderate by isolating the medical devices from the flat network where most vulnerabilities reside.

---

*Prepared by: Security Department*  
*References: Project 1x02 Task 16 Triage, Task 17 CVSS Contextualizer, Task 19 Remediation Map, Project 1x00 Security Budget Allocation*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
