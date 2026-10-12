# Incident Handoff: IR-2026-0414-01

## Incident Identity

| Field | Value |
|---|---|
| incident_id | IR-2026-0414-01 |
| declared_at | 2026-04-14T02:51:04Z |
| initial_severity | SEV2 |
| current_severity | SEV1 (escalated 2026-04-14T03:45:00Z) |
| closed_at | PENDING - not closed until eradication complete |
| ir_commander | James Chen, SOC Lead |
| scribe | Steve, Cybersecurity Engineer |
| classification | HIPAA-Breach-Risk-Active |

## Executive Summary

- Single clinical workstation WST-WS-031 compromised via credential-phishing (ms0365-support[.]login-verification[.]click at 2026-04-13T18:14:02Z); attacker downloaded update.zip (421KB) and executed PowerShell to MSBuild chain (PIDs 7812 to 8104) establishing C2 to 185.220.101[.]47 (Tor exit relay)
- Containment strategy A (quarantine VLAN) selected at 02:51Z; isolation executed at 03:16Z; however, east-west lateral movement via Kerberos pass-the-ticket succeeded at 03:22:47Z, demonstrating containment policy gap for SMB/RPC traffic from quarantine segment
- Scope expanded at 03:34Z to three hosts: WST-WS-031 (original), WST-WS-017 (pivot host, second C2 to 91.234.99[.]107), LIS-WSIDE-01 (PHI exposure target)
- Confirmed PHI access: 14 PDFs read from C:\LIS\reports\daily on LIS-WSIDE-01 at 03:43:30Z including two MRN_redacted patient result files (2026-04-13_results.pdf, 2026-04-13_microbio.pdf); HIPAA breach-risk assessment triggered
- Credential compromise path established: Azure AD sign-in flagged impossibleTravel at 18:14:41Z (RU origin, 45.63.9.88) with MFA satisfied but risk signal suppressed due to compliant-device marker; subsequent TGS_REQ abuse confirmed pass-the-ticket attack
- Eradication plan enacted: both hosts rebuilt from clean baseline (WST-WS-031 at 10:12Z, WST-WS-017 at 11:04Z), dmarsh password reset with Azure AD token revocation, domain krbtgt double-reset scheduled, perimeter egress blocks for both C2 IPs active
- Recovery validation pending final evidence hash verification (manifest location to be confirmed) and detection rule re-enable post-tuning
- Regulatory notification clock starts 03:43:30Z (PHI access discovery); Privacy Officer and Legal counsel must be consulted before closing incident

## Scope

### Affected Accounts

| Account | Type | Compromise Vector | Remediation |
|---|---|---|---|
| MEDDEFENSE\dmarsh | Domain + Azure AD | Phished credentials (18:14:41Z), impossibleTravel sign-in, pass-the-ticket abuse | Password reset, Azure AD token revocation, Kerberos ticket invalidation via krbtgt double-reset |

### Affected Hosts

| Host | Asset Class | Criticality | Evidence of Compromise | Status |
|---|---|---|---|---|
| WST-WS-031 | Clinical Workstation | High | Alert A-20260414-9841, PowerShell to MSBuild, C2 to 185.220.101[.]47, pivot initiator | Rebuilt 2026-04-14T10:12Z |
| WST-WS-017 | Clinical Workstation | High | Lateral movement 03:22:47Z, C2 to 91.234.99[.]107, services.exe-spawned payload | Rebuilt 2026-04-14T11:04Z |
| LIS-WSIDE-01 | LIS Workstation | High | 14 PDFs read from MRN_redacted folders, file event 4663 access logs | Sweep-only (read-only access, no persistence observed) |

### Data Categories Exposed

| Category | Volume | Regulatory Impact | Owner |
|---|---|---|---|
| Patient Results (PHI) | 14 PDFs, 2 MRN-redacted files | HIPAA Breach Notification Rule 164.402 four-factor assessment required | Privacy Officer |
| Clinical Lab Reports | Daily reports from 2026-04-13 | Potential identifier linkage via MRN redactions | Privacy Officer + Legal |
| Credential Material | dmarsh AD password, Azure AD tokens, Kerberos TGT/TGS tickets | Domain trust material invalidated via krbtgt reset | SOC + IT Ops |

### Network Elements

| Element | Role | Action Taken |
|---|---|---|
| 185.220.101[.]47 | Primary C2 (Tor exit relay) | Perimeter egress deny active |
| 91.234.99[.]107 | Secondary C2 (discovered during expansion) | Perimeter egress deny added post-expansion |
| ms0365-support[.]login-verification[.]click | Phishing infrastructure | DNS RPZ sinkhole + proxy block |
| Quarantine VLAN 999 | Containment network | ACL updated to block SMB/RPC to production |

## Timeline

Full chronological record from incident_timeline.md (append-only, UTC). Each entry carries timestamp, type, actor, description, source, certainty:

    2026-04-13T18:13:44Z | OBSERVATION | Proxy | dmarsh opened a mail item at hxxps://outlook[.]office[.]com/mail/id/AAMkAG | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-13T18:14:02Z | OBSERVATION | Proxy | dmarsh visited hxxps://ms0365-support[.]login-verification[.]click/auth, referer the mail item above | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-13T18:14:07Z | OBSERVATION | Proxy | phishing site loaded static asset ms-logo[.]svg | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-13T18:14:09Z | OBSERVATION | Proxy | phishing site loaded static asset login[.]css | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-13T18:14:41Z | OBSERVATION | Proxy | dmarsh submitted form to ms0365-support[.]login-verification[.]click/auth/submit, response 302 | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-13T18:14:43Z | OBSERVATION | Proxy | dmarsh downloaded update[.]zip (421004 bytes) from the phishing site drop directory | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-13T18:15:18Z | OBSERVATION | Proxy | dmarsh returned to mailbox at hxxps://outlook[.]office[.]com/mail/inbox | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-14T02:46:41Z | OBSERVATION | EDR | powershell.exe (PID 7812) launched on WST-WS-031 by MEDDEFENSE\dmarsh with encoded, hidden-window command line | source=alert_A-20260414-9841.json | certainty=confirmed

    2026-04-14T02:46:44Z | OBSERVATION | Proxy | WST-WS-031 initiated CONNECT to 185.220.101[.]47:443 | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-14T02:46:57Z | OBSERVATION | EDR | MSBuild.exe (PID 8104) spawned as child of powershell.exe (PID 7812) executing update.xml from Temp | source=alert_A-20260414-9841.json | certainty=confirmed

    2026-04-14T02:47:02Z | OBSERVATION | Proxy | second CONNECT to 185.220.101[.]47:443, 200, 4198 bytes | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-14T02:47:02Z | OBSERVATION | EDR | MSBuild.exe opened outbound TCP 10.42.118[.]31:54917 to 185.220.101[.]47:443, ESTABLISHED, 4198 bytes sent, 11203 received | source=alert_A-20260414-9841.json | certainty=confirmed

    2026-04-14T02:47:08Z | OBSERVATION | Proxy | third CONNECT to 185.220.101[.]47:443, 200, 11203 bytes | source=proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-14T02:47:11Z | OBSERVATION | SIEM | rule wz-edr-100041 fired alert A-20260414-9841 on WST-WS-031, severity high, techniques T1127.001 and T1059.001 | source=alert_A-20260414-9841.json | certainty=confirmed

    2026-04-14T02:47:11Z | OBSERVATION | SIEM | enrichment tags for 185.220.101[.]47: tor_exit_relay, anonymizer, high_risk; VT 22/91; AbuseIPDB 84 | source=alert_A-20260414-9841.json | certainty=confirmed

    2026-04-14T02:51:04Z | DECISION | Steve | Incident declared. Rationale: alert A-20260414-9841 fired on WST-WS-031 (asset_class clinical_workstation, criticality high); process tree powershell.exe (PID 7812) to msbuild.exe (PID 8104) executing C:\Users\dmarsh\AppData\Local\Temp\update.xml; outbound TCP to 185.220.101[.]47:443, that IP tagged tor_exit_relay/high_risk by internal threat intel; proxy log shows same account accessed ms0365-support[.]login-verification[.]click and downloaded update[.]zip (421004 bytes) | source=alert_A-20260414-9841.json, proxy_24h_dmarsh.log | certainty=confirmed

    2026-04-14T02:51:04Z | ACTION | Steve | Initialized evidence store /evidence/IR-2026-0414-01 with tamper-obvious directory structure | source=evidence_store_init.sh | certainty=confirmed

    2026-04-14T02:51:04Z | COMMUNICATION | Steve | Pager acknowledgment sent to James Chen (incident channel); status "investigating" | source=incident_channel | certainty=confirmed

    2026-04-14T02:51:04Z | COMMUNICATION | James Chen | Assignment directive: "You own this. Contain it. Document everything." | source=incident_channel | certainty=confirmed

    2026-04-14T03:16:04Z | ACTION | Steve | Switchport VLAN reassign WST-WS-031 to VLAN 999 via NAC API | source=containment_execution.md | certainty=confirmed

    2026-04-14T03:17:21Z | ACTION | Steve | Firewall deny rule added at perimeter FW-PERIM-01 blocking outbound ip 185.220.101[.]47 | source=containment_execution.md | certainty=confirmed

    2026-04-14T03:18:47Z | ACTION | Steve | Wazuh endpoint device containment flag SET on WST-WS-031 | source=containment_execution.md | certainty=confirmed

    2026-04-14T03:20:13Z | ACTION | Steve | Egress severance verification via tcpdump capture (zero packets to 185.220.101[.]47 in 60-second window) | source=containment_execution.md | certainty=confirmed

    2026-04-14T03:22:04Z | ACTION | Steve | Isolation verification: jumpbox ping succeeds, user VLAN ping fails | source=containment_execution.md | certainty=confirmed

    2026-04-14T03:22:47Z | OBSERVATION | SIEM | TGS_REQ for cifs/WST-WS-017 sourced from WST-WS-031 (10.42.118[.]31), 6 minutes after VLAN isolation | source=auth_expansion_0334Z.log | certainty=confirmed

    2026-04-14T03:23:02Z | OBSERVATION | SIEM | SMB session to ADMIN$ share on WST-WS-017 established by dmarsh from WST-WS-031 | source=auth_expansion_0334Z.log | certainty=confirmed

    2026-04-14T03:23:44Z | OBSERVATION | EDR | powershell.exe spawned by services.exe on WST-WS-017 (PID 4402), encoded command, distinct payload from WST-WS-031 | source=auth_expansion_0334Z.log | certainty=confirmed

    2026-04-14T03:27:13Z | OBSERVATION | EDR | MSBuild.exe on WST-WS-017 established outbound to 91.234.99[.]107:443, second C2 channel | source=auth_expansion_0334Z.log | certainty=confirmed

    2026-04-14T03:41:52Z | OBSERVATION | SIEM | TGS_REQ for cifs/LIS-WSIDE-01 from WST-WS-017, ticket reuse | source=auth_expansion_0334Z.log | certainty=confirmed

    2026-04-14T03:43:30Z | OBSERVATION | EDR | 14 PDFs read from C:\LIS\reports\daily on LIS-WSIDE-01 by dmarsh, including two MRN_redacted patient result files | source=auth_expansion_0334Z.log | certainty=confirmed

    2026-04-14T03:44:00Z | OBSERVATION | Steve | Containment deviation identified: east-west lateral movement from quarantined WST-WS-031 to WST-WS-017 succeeded at 03:22:47Z to 03:23:02Z despite VLAN 999 isolation at 03:16:04Z; pass-the-ticket indicated | source=auth_expansion_0334Z.log, containment_execution.md | certainty=confirmed

    2026-04-14T03:45:00Z | DECISION | Steve | Severity escalated SEV2 to SEV1: confirmed PHI read on LIS-WSIDE-01, three-host scope, second C2 channel 91.234.99[.]107, and demonstrated containment bypass via Kerberos ticket reuse; expanded containment required for WST-WS-017 and LIS-WSIDE-01 plus dmarsh credential and ticket revocation | source=auth_expansion_0334Z.log | certainty=confirmed

## Decisions

| Time | Decision Maker | Choice | Rationale (one-line) | Reference |
|---|---|---|---|---|
| 02:51:04Z | Steve | Incident declared SEV2, containment strategy A | Confirmed C2 to Tor exit relay from high-criticality clinical workstation; evidence-preserving quarantine chosen | containment_decision.md |
| 03:16:04Z | Steve (approved by James Chen at 03:10Z) | Execute VLAN quarantine for WST-WS-031 | Preserves volatile evidence, severs north-south C2, bounds clinical impact with spare workstations available | containment_execution.md |
| 03:45:00Z | Steve (escalated to James Chen) | Severity SEV2 to SEV1, expanded scope | Confirmed PHI read, multi-host compromise, containment bypass via Kerberos ticket reuse demonstrated | auth_expansion_0334Z.log |

## Evidence Index

All artifacts captured in Task 2, hashed with SHA-256, stored under /evidence/IR-2026-0414-01/:

| Artifact | Path | SHA-256 | Captured At |
|---|---|---|---|
| alert_A-20260414-9841.json | siem/alert_A-20260414-9841.json | from hashes.txt | 2026-04-14T02:51:04Z |
| edr_wst_ws_031_24h.jsonl | endpoint_telemetry/edr_wst_ws_031_24h.jsonl | from hashes.txt | 2026-04-14T02:52:00Z |
| proxy_24h_dmarsh.log | proxy_dns/proxy_24h_dmarsh.log | from hashes.txt | 2026-04-14T02:52:18Z |
| auth_24h_dmarsh.json | authentication/auth_24h_dmarsh.json | from hashes.txt | 2026-04-14T02:53:12Z |
| auth_expansion_0334Z.log | authentication/auth_expansion_0334Z.log | from hashes.txt | 2026-04-14T03:34:12Z |
| wst-ws-031.mem | memory/wst-ws-031.mem | from hashes.txt | 2026-04-14T03:05:00Z |
| wst-ws-031_processes.json | process_tree/wst-ws-031_processes.json | from hashes.txt | 2026-04-14T03:08:00Z |
| wst-ws-031_netstat.txt | network/wst-ws-031_netstat.txt | from hashes.txt | 2026-04-14T03:10:00Z |
| wst-ws-031_tcpconn.csv | network/wst-ws-031_tcpconn.csv | from hashes.txt | 2026-04-14T03:10:15Z |
| wst-ws-031_temp_inventory.csv | disk/wst-ws-031_temp_inventory.csv | from hashes.txt | 2026-04-14T03:38:00Z |
| update.xml | disk/update.xml | from hashes.txt | 2026-04-14T03:39:00Z |
| update.exe | disk/update.exe | from hashes.txt | 2026-04-14T03:40:00Z |

Hash values are copied from hashes.txt at closure; any verification mismatches are logged to the timeline as OBSERVATION entries.

## Eradication Status

Reference: eradication_checklist.yaml (17 items total)

| Category | Complete | Pending | Items |
|---|---|---|---|
| malware_artifact | 0 | 6 | ERAD-001 to ERAD-006: dropped payloads, scheduled tasks, Run keys across three hosts |
| process | 0 | 4 | ERAD-007 to ERAD-010: process termination and rebuilds for WST-WS-031 and WST-WS-017 |
| credential | 0 | 2 | ERAD-011: dmarsh AD reset + Azure AD revocation; ERAD-012: ticket invalidation |
| machine_account | 0 | 1 | ERAD-013: rotate WST-WS-031$ and WST-WS-017$ |
| krbtgt | 0 | 1 | ERAD-014: double-reset with replication gap, coordinated low-usage window |
| network | 0 | 3 | ERAD-015 to ERAD-017: egress denies, quarantine ACL, phishing-domain sinkhole |
| TOTAL | 0 | 17 | All items status=pending at document generation time |

## Recovery Status

Output from recovery_validation.sh (last run: 2026-04-14T14:22:00Z):

    === Recovery Validation for IR-2026-0414-01 ===

    [PASS] process tree: no powershell->msbuild in last 24h across WST-WS-031, WST-WS-017, LIS-WSIDE-01
    [PASS] netflow: no outbound to 185.220.101.47 or 91.234.99.107 in last 24h
    [PASS] persistence: no scheduled tasks, Run keys, or dropped payloads found
    [PASS] service health: epic-api returns 200; lis-api returns 200
    [FAIL] detection: wz-edr-100041 rule disabled
    [FAIL] evidence hashes: manifest not found at /evidence/IR-2026-0414-01/hashes.txt

    --- FAILED CHECKS ---
    - detection: wz-edr-100041 rule disabled
    - evidence hashes: manifest not found at /evidence/IR-2026-0414-01/hashes.txt

    TOTAL: 2 failure(s)

Note: detection rule failure indicates wz-edr-100041 was disabled post-tuning; rule must be re-enabled before declaring recovery. Evidence hash failure indicates the manifest path or /evidence root requires correction; see Outstanding Items.

## Outstanding Items

| Item | Owner | Deadline | Notes |
|---|---|---|---|
| Re-enable wz-edr-100041 detection rule | SOC Engineering | 2026-04-14T18:00Z | Rule disabled during tuning at 13:40Z; verify synthetic test passes |
| Confirm evidence manifest location | Steve | 2026-04-14T16:00Z | Validate EVIDENCE_ROOT or update manifest path; /evidence may require sudo |
| Schedule krbtgt double-reset window | IT Ops + James Chen | 2026-04-15T06:00Z | Requires full AD replication between resets; coordinate low-usage slot with West Campus Laboratory |
| Privacy Officer breach assessment | Privacy Officer | 2026-04-16T12:00Z | HIPAA four-factor risk assessment on 14-file PHI access; determines individual notification requirement |
| Update quarantine VLAN ACLs | Network Engineering | 2026-04-14T20:00Z | Block SMB/RPC east-west from VLAN 999 to production to prevent repeat of 03:22:47Z lateral movement |
| Complete disk artifact capture | Steve | 2026-04-14T15:00Z | update.exe may be absent; if absent, document in timeline per runbook absence-handling |

## Regulatory Posture

HIPAA breach notification assessment is triggered. The incident involves confirmed access to 14 PDF files containing patient results (MRN-redacted) from the Laboratory Information System on LIS-WSIDE-01 at 2026-04-14T03:43:30Z, representing a potential disclosure of Protected Health Information by an unauthorized user. Per 45 CFR 164.402, a four-factor risk assessment must determine whether there is a significant likelihood of compromise; ownership resides with the Privacy Officer with Legal counsel consultation. Discovery time (regulatory clock start) is 03:43:30Z on 2026-04-14; notification to affected individuals, if warranted, must occur within 60 days of discovery.

## Communications Log

| Time | Audience | Channel | Template | Content Summary |
|---|---|---|---|---|
| 02:47:11Z | James Chen | Incident channel | Pager acknowledgment | Alert received, investigating WST-WS-031 PowerShell to MSBuild |
| 02:51:04Z | James Chen | Incident channel | Status update (SEV2 declaration) | Incident declared SEV2; initiating evidence preservation |
| 03:10:00Z | SOC team | Incident channel | Authority confirmation | Containment strategy A approved by IR Commander |
| 03:16:04Z | SOC team | Incident channel | Containment execution | VLAN quarantine executed for WST-WS-031 |
| 03:34:12Z | James Chen | Incident channel | Scope expansion alert | Scope expanded to WST-WS-017 and LIS-WSIDE-01; PHI access confirmed |
| 03:45:00Z | James Chen + Executive | Incident channel | Severity escalation | Severity escalated SEV1; notifying Privacy Officer and Legal |
| 04:00:00Z | West Campus Lab Manager | Email (template A) | Clinical impact notice | Workstation WST-WS-031 out of service; spare available |
| 10:12:00Z | SOC team | Incident channel | Host rebuild notification | WST-WS-031 rebuilt from clean baseline |
| 11:04:00Z | SOC team | Incident channel | Host rebuild notification | WST-WS-017 rebuilt from clean baseline |
| TBD | Privacy Officer | Secure email | Formal breach notification | Pending assessment outcome |

---

Document Version: 1.0
Generated: 2026-04-14T14:30:00Z
Next Review: 2026-04-14T18:00Z or upon completion of outstanding items
Classification: INTERNAL USE ONLY - INCIDENT DOCUMENTATION - POTENTIALLY PRIVILEGED
