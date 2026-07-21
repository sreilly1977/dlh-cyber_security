# 2. The CIS Controls Audit
## Security Maturity Assessment Against CIS Controls v8

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 2)  
**Reference:** CIS Controls v8 Summary (provided)

---

## Control Assessments

### CIS Control 1: Inventory and Control of Enterprise Assets
**Score:** Partial  
**Evidence:** 1x00 Task 2 Asset Registry was created during the project and covers 47 scanned hosts, but approximately 280 clinical workstations and an unknown number of medical IoT devices remain uninventoried, and shadow IT was discovered at 10.10.2.99.

### CIS Control 2: Inventory and Control of Software Assets
**Score:** Not Implemented  
**Evidence:** 1x00 did not produce a software inventory, 1x02 Task 3 identified unsupported Apache versions and an undisclosed Cryptominer binary on billing-srv-01, and no license or software asset management process exists.

### CIS Control 3: Data Protection
**Score:** Not Implemented  
**Evidence:** 1x02 Task 10 identified no data encryption at rest on NAS or database servers, 1x02 Task 9 identified HL7 traffic transmitting in cleartext, and 1x00 Task 4 Gap Analysis confirms no data classification or DLP controls exist.

### CIS Control 4: Secure Configuration of Enterprise Assets and Software
**Score:** Partial  
**Evidence:** 1x02 Task 20 identified 14 misconfigurations (45.2% of all findings) including PostgreSQL unrestricted access (Finding 003), LDAP signing disabled (Finding 007), SSH password auth (Finding 009), and TLS 1.0 with weak ciphers (Finding 019), but Sophos endpoint protection is deployed indicating some baseline configuration management.

### CIS Control 5: Account Management
**Score:** Partial  
**Evidence:** 1x00 confirms Active Directory exists on ad-dc-01 for central account management, but no account inventory has been produced, dormant account review has not been performed, and no separation of administrative privileges into dedicated accounts is documented.

### CIS Control 6: Access Control Management
**Score:** Not Implemented  
**Evidence:** 1x02 Finding 010 confirms BD Alaris infusion pumps use default credentials (admin/admin), 1x02 Finding 009 confirms SSH password authentication on billing-srv-01, and no MFA is deployed on any system including O365 or VPN.

### CIS Control 7: Continuous Vulnerability Management
**Score:** Not Implemented  
**Evidence:** 1x02 Task 20 identified 9 critical vulnerabilities remaining unpatched across Tier 1 assets, 1x02 Task 23 confirms no recurring scan schedule exists, and no remediation SLA or patch management process is documented despite billing-srv-01 being actively compromised with a cryptominer for 14+ days.

### CIS Control 8: Audit Log Management
**Score:** Not Implemented  
**Evidence:** 1x00 GAP-003 confirms no SIEM or centralized logging exists, 1x02 Finding 021 confirms Windows Event Log forwarding is not configured, and the cryptominer on billing-srv-01 operated undetected for 14+ days demonstrating complete absence of log collection and analysis.

### CIS Control 9: Email and Web Browser Protections
**Score:** Partial  
**Evidence:** 1x00 confirms O365 is deployed with standard Exchange Online Protection, but no DNS filtering service is documented, no browser hardening GPO is deployed, and no email security gateway or advanced phishing protection is configured beyond O365 defaults.

### CIS Control 10: Malware Defenses
**Score:** Partial  
**Evidence:** 1x00 Task 0 confirms Sophos Intercept X is deployed as endpoint protection across servers and clinical workstations, but 1x02 Task 4 confirms it failed to detect the active cryptominer on billing-srv-01 for 14+ days, and no autorun/autoplay restrictions are documented.

### CIS Control 11: Data Recovery
**Score:** Not Implemented  
**Evidence:** 1x02 Task 9 identified CVE-2023-1383 (CVSS 9.8) on the Synology NAS holding all backups, the NAS resides on the flat network exposing backups to ransomware, no backup restoration testing has been performed, and no isolated backup instance exists.

### CIS Control 12: Network Infrastructure Management
**Score:** Partial  
**Evidence:** A FortiGate 100F firewall exists at the perimeter (1x00 Task 0), but 1x00 GAP-001 confirms the internal network is flat 10.10.0.0/16 with no VLAN segmentation, 1x02 Task 14 confirms medical devices share the broadcast domain with general computing, and a consumer-grade ASUS router serves as the Westside Clinic gateway.

### CIS Control 13: Network Monitoring and Defense
**Score:** Not Implemented  
**Evidence:** 1x00 GAP-003 confirms no IDS/IPS exists, Marcus's notes confirm zero network monitoring capability, no network traffic analysis tools are deployed, and the undetected cryptominer on billing-srv-01 proves no network-level detection is functioning.

### CIS Control 14: Security Awareness and Skills Training
**Score:** Not Implemented  
**Evidence:** 1x00 did not identify any security awareness training program, and an AUP from HR does not constitute structured security awareness training covering phishing, data handling, authentication best practices, or incident reporting.

### CIS Control 15: Service Provider Management
**Score:** Partial  
**Evidence:** 1x00 confirms contracts exist with SecurePoint (security scanning), AT&T (connectivity), and BD (infusion pumps), but no vendor security assessment was performed during BD Alaris procurement, no service provider inventory with security posture documentation exists, and the Synology NAS was procured without security review.

### CIS Control 16: Application Software Security
**Score:** Not Implemented  
**Evidence:** 1x00 did not identify any secure SDLC process, no code review practices, no vulnerability scanning of internally developed or customized applications, and the EHR platform on ehr-srv-01 runs default Tomcat configuration with version disclosure enabled (1x02 Finding 017).

### CIS Control 17: Incident Response Management
**Score:** Not Implemented  
**Evidence:** 1x02 Task 19 identifies an active compromise on billing-srv-01 but no incident response plan exists, no IR personnel are designated, and no breach notification process for HHS OCR under the HIPAA Breach Notification Rule is documented.

### CIS Control 18: Penetration Testing
**Score:** Not Implemented  
**Evidence:** 1x00 confirms no penetration testing program exists and no external penetration test has been performed; the current assessment is a vulnerability scan by SecurePoint, not a penetration test.

---

## Scorecard Summary

**Implemented:** 0 controls (0.0%)  
**Partial:** 7 controls (38.9%)  
**Not Implemented:** 11 controls (61.1%)  
**Total:** 18 controls

---

## Top 5 Priority Controls

These five controls, if implemented, would produce the greatest reduction in MedDefense's risk exposure. Selection is based on the number of critical findings they address, their impact on active kill chains identified in 1x01, and their foundational necessity for subsequent controls.

### Priority 1: CIS Control 6 — Access Control Management
**Justification:** Implementing MFA on all externally-exposed applications and remote access, enforcing unique credentials on medical devices, and disabling password-based SSH would simultaneously remediate Finding 010 (BD Alaris default credentials), Finding 009 (SSH password auth), and break Kill Chain entry points across all threat actor profiles identified in 1x01.

### Priority 2: CIS Control 7 — Continuous Vulnerability Management
**Justification:** Establishing a recurring vulnerability scan schedule with documented remediation SLAs would have caught the Apache mod_lua RCE (Finding 001) before exploitation, prevented the 14-day cryptominer dwell time, and addresses the systemic absence of patch management that leaves 9 critical vulnerabilities unpatched on Tier 1 assets.

### Priority 3: CIS Control 12 — Network Infrastructure Management
**Justification:** Implementing VLAN segmentation would reduce risk amplification by 6.6x to 12.0x per 1x02 Task 14, isolate medical devices from general computing infrastructure, protect backup infrastructure from ransomware propagation, and eliminate the flat network as a force multiplier for all 25 actionable findings in Task 20.

### Priority 4: CIS Control 8 — Audit Log Management
**Justification:** Deploying centralized log collection and establishing log review procedures would have detected the billing-srv-01 cryptominer within hours rather than 14 days, provides evidence for incident investigation required under HIPAA Security Rule, and establishes the visibility foundation required for all Detect function activities in NIST CSF.

### Priority 5: CIS Control 17 — Incident Response Management
**Justification:** Developing an incident response plan with defined roles, escalation procedures, and breach notification processes is legally required for HIPAA compliance, would ensure proper containment of the current billing-srv-01 compromise, and enables coordinated communication with HHS OCR and affected patients in the event of a data breach.

---

*Prepared by: Security Department*  
*References: CIS Controls v8 Summary, Project 1x00 (Posture Assessment, Asset Registry, Gap Analysis), Project 1x01 (Threat Landscape, Kill Chains, Scenarios), Project 1x02 (Vulnerability Assessment, Tasks 0-23)*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
