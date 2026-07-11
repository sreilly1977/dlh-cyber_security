# Security Control Gaps Analysis: MedDefense Health Systems
## The Missing Pieces

---

## Gap Registry

---

### Gap ID: G-001

**Gap Description:** No Administrative Detective controls exist. There are no scheduled access reviews, periodic permission audits, compliance attestations, or any administrative process designed to discover security issues after they occur. All detective activities are technical (logging, cameras) with no corresponding administrative oversight or review procedures.

**Category x Function Missing:** Administrative / Detective

**Affected Asset(s) or Zone:** Organization-wide — all systems, users, permissions, and access rights

**Risk if Unaddressed:** Permission creep, orphaned accounts, unauthorized access, and policy violations accumulate undetected. A former employee whose access wasn't revoked could exfiltrate PHI months after departure, or an insider could escalate privileges gradually without triggering any detection. Both **Confidentiality** and **Integrity** risks increase over time through undetected drift.

**Evidence:** Control Summary Matrix shows empty cell for Administrative/Detective. Artifact 7 shows training completion rates are tracked but no mechanism exists to review who has access to what systems. Artifact 4 notes 15 devices are "offline >30 days" and IT has not reconciled them with the asset list.

---

### Gap ID: G-002

**Gap Description:** No Administrative Corrective controls exist. There is no documented incident response plan, no disaster recovery plan, no business continuity plan, no formal post-incident review process, and no structured corrective procedure for responding to security events.

**Category x Function Missing:** Administrative / Corrective

**Affected Asset(s) or Zone:** Organization-wide — all assets during and after security incidents

**Risk if Unaddressed:** When incidents occur (and they have — January ransomware, current cryptominer), response is improvised with no structured approach. This leads to longer recovery times, incomplete remediation, evidence destruction, repeated vulnerabilities, and inability to learn from incidents. The January ransomware required 4 days to recover because no tested restoration procedure existed. This directly impacts **Availability** (slow recovery) and **Integrity** (incomplete remediation allows recurrence).

**Evidence:** Control Summary Matrix shows empty cell for Administrative/Corrective. Artifact 5 states "Full DR test: Never performed." Artifact 8 states logs are checked "manually if something breaks" with no alerting. Marcus's notes document "No formal incident response plan exists."

---

### Gap ID: G-003

**Gap Description:** Linux servers have no endpoint protection. Sophos Endpoint Protection is deployed on 387 Windows workstations (88.1% coverage) but explicitly does not cover Linux servers. The cryptominer on billing-srv-01 ran for 14 days undetected because there was no antivirus signature matching it on that platform.

**Category x Function Missing:** Technical Preventive (endpoint protection specifically)

**Affected Asset(s) or Zone:** All Linux servers — billing-srv-01, ehr-srv-01, ehr-db-01, backup-srv-01, web-srv-01 (Ubuntu-based systems documented in Artifact 2)

**Risk if Unaddressed:** Malware, ransomware, cryptominers, and attackers operating on Linux systems go undetected in real-time. The current cryptominer compromise demonstrates this gap directly — it consumed 96% CPU for two weeks before manual discovery. This enables prolonged **Confidentiality** exposure (attacker foothold), **Integrity** compromise (malicious code execution), and **Availability** degradation (resource exhaustion).

**Evidence:** Artifact 4 explicitly states "Linux servers: 0 (NOT covered -- not supported by current Sophos tier)." Artifact from billing-srv-01 diagnostics shows cryptominer running for 14 days before detection by sysadmin noticing performance issues, not by antivirus.

---

### Gap ID: G-004

**Gap Description:** No centralized log management or SIEM exists. Each system (firewall, Windows servers, Linux servers, Apache, EHR) stores logs locally with varying retention periods. There is no aggregation, no correlation, no automated alerting, and no SIEM (Marcus researched Wazuh but never installed it).

**Category x Function Missing:** Technical Detective (centralized monitoring)

**Affected Asset(s) or Zone:** All systems — firewall, servers, applications, network devices

**Risk if Unaddressed:** Security events remain siloed and invisible until manually discovered after significant damage. The cryptominer made 3 outbound connections to mining pools that appeared in netstat but weren't flagged by any system. An attacker moving laterally across the flat network could establish multiple footholds across servers without triggering any centralized alert. This severely impairs timely detection, increasing dwell time and the magnitude of **Confidentiality**, **Integrity**, and **Availability** impacts.

**Evidence:** Artifact 8 states "No centralized log management system exists. No automated alerting on security events." Marcus's notes mention SIEM research but confirm it was never implemented. Firewall logs stay on the FortiGate for 30 days; Apache logs rotate weekly; Linux logs are in /var/log with no forwarding.

---

### Gap ID: G-005

**Gap Description:** No compensating controls exist for legacy/unpatchable systems. The MRI scanner runs Windows XP (EOL since 2014), the print server runs Windows Server 2012 R2 (EOL October 2023), and billing-srv-01 runs Ubuntu 18.04 (approaching EOL). These systems are not segmented, isolated, or protected by compensating controls such as network micro-segmentation, application whitelisting, or enhanced monitoring.

**Category x Function Missing:** Technical Compensating

**Affected Asset(s) or Zone:** MRI scanner (siemens MAGNETOM), print-srv-01, billing-srv-01, any other legacy/medical devices that cannot be patched

**Risk if Unaddressed:** Known vulnerabilities in unpatchable systems remain fully exploitable indefinitely. The MRI scanner's Windows XP could be targeted by EternalBlue-style exploits. Print Server 2012 R2 has numerous CVEs with known exploits. Without compensating controls (like VLAN isolation), these systems are sitting targets. This creates critical **Integrity** risk (system compromise), **Availability** risk (disruption of critical clinical equipment), and **Confidentiality** risk (potential PHI access through compromised medical devices).

**Evidence:** Control Summary Matrix shows empty cell for Technical/Compensating. Artifact 2 shows Ubuntu 18.04 "approaching EOL." Artifact from onboarding packet states MRI "runs Windows XP" and print-srv-01 "End of support was Oct 2023." Marcus's notes document flat network with medical devices "on the same broadcast domain as all systems."

---

### Gap ID: G-006

**Gap Description:** No central backup verification or offsite replication. Veeam backs up 6 servers to a local NAS in the same server room, same rack row. PACS imaging, ad-dc-02, print-srv-01, Westside's server, O365 data, and medical device configurations are not backed up. Recovery testing occurred only once, 8 months ago, for a single server, and took 6 hours. No full DR test has been performed. Cloud/offsite replication was quoted at $14,400/year but budget was denied.

**Category x Function Missing:** Technical Corrective (adequate backup coverage and validation)

**Affected Asset(s) or Zone:** PACS imaging, secondary domain controller, Westside Clinic server, O365 data, medical device configurations, and all backed-up servers without validated recovery procedures

**Risk if Unaddressed:** Single-point-of-failure in backup infrastructure. If the server room suffers ransomware, fire, or hardware failure, both production and backup data are lost simultaneously. Unbacked-up systems (PACS, O365, medical devices) would have no recovery path. Untested restores mean even backed-up data may be corrupted or incompatible when needed. The January ransomware recovered from a 3-week-old backup because the current one was misconfigured. This creates catastrophic **Availability** risk and potential permanent **Confidentiality** loss (if data is unrecoverable and leaked).

**Evidence:** Artifact 5 states NAS is "in the server room at Central, same rack row" with no offsite backup. "Full DR test: Never performed." Unbacked-up systems explicitly listed. "Quote received: $14,400/year. Budget denied by CFO." Onboarding packet shows billing server backup was "3 weeks old due to misconfigured cron job."

---

### Gap ID: G-007

**Gap Description:** No physical security detective controls in critical areas. The server room, network closets, and administrative wing have no cameras. Westside's server closet has no lock and no alternative monitoring. Only 4 cameras cover main entrance, ER entrance, and parking garage — none near IT infrastructure.

**Category x Function Missing:** Physical Detective

**Affected Asset(s) or Zone:** Server room (ground floor), network closets (including 2nd-floor unlocked closet), administrative wing, Westside server closet

**Risk if Unaddressed:** Physical intrusions, unauthorized device installation, credential theft, or equipment tampering occur without detection or audit trail. An attacker entering the server room via tailgating or stolen badge can install a rogue device, clone drives, or modify configurations with zero surveillance. The 2nd-floor network closet with credentials taped to the wall is already exposed to any passerby, and there is no way to retroactively determine who accessed it. This enables undetectable **Integrity** attacks (physical tampering), **Confidentiality** breaches (drive cloning, credential theft), and **Availability** disruption (equipment sabotage).

**Evidence:** Artifact 6 states "No cameras in server room area, network closets or administrative wing." Onboarding packet walk-through observation 1 documents server room has "no camera covering the door." Observation 2 describes network closet with "no lock" and credentials "taped to the wall."

---

## Gap Analysis Summary

| Gap ID | Category x Function Missing | Affected Area | Risk Severity |
|--------|----------------------------|---------------|---------------|
| G-001 | Administrative / Detective | Organization-wide | High |
| G-002 | Administrative / Corrective | Organization-wide | Critical |
| G-003 | Technical Preventive (endpoint) | Linux servers | Critical |
| G-004 | Technical Detective (SIEM/logging) | All systems | Critical |
| G-005 | Technical Compensating | Legacy/unpatchable systems | Critical |
| G-006 | Technical Corrective (backup) | Critical infrastructure | Critical |
| G-007 | Physical Detective | Server room/network closets | Critical |

---

## Pattern Analysis

Looking at these gaps as a whole, MedDefense's security posture is overwhelmingly **prevention-oriented** with critically weak detection and corrective capabilities. Seven of the eight empty cells in the Control Summary Matrix represent detective, corrective, or compensating functions, and the gaps confirm this bias. The organization invests in locks, firewalls, and policies to stop incidents, but has virtually no ability to detect when those preventive controls fail (no SIEM, no centralized logging, no administrative oversight) and almost no capacity to recover when failures occur (untested backups, no IR/DR plans, no compensating controls for legacy systems).

This implies that **when preventive controls are bypassed** — which happens constantly, as evidenced by the January ransomware, the current cryptominer, the compromised billing server, and the five physical security observations — MedDefense is essentially flying blind. Incidents linger undetected for weeks (14-day cryptominer run-time), recovery takes days instead of hours (January ransomware), and the same vulnerabilities allow repeat compromises (billing server hit twice through the same Apache vulnerability). The organization operates in a state of **reactive crisis** rather than proactive security management, relying on luck and heroic individual effort (James Chen, Marcus Webb) rather than systemic resilience.
