# Incident Timeline: IR-2026-0414-01

## Header

- incident_id: IR-2026-0414-01
- declared_at: 2026-04-14T02:51:04Z
- declared_by: Steve, on-call SOC
- initial_severity: SEV2
- current_severity: SEV2
- ir_commander: James Chen, SOC Lead
- scribe: Steve

## Legend

- OBSERVATION: raw fact from an alert, log, or artifact
- DECISION: a choice made by an authorized actor, with rationale
- ACTION: an operation executed against an asset, with owner
- COMMUNICATION: a message sent or received, with audience
- EVIDENCE: a preserved artifact with hash and storage path

## Entries

- 2026-04-13T18:14:02Z | OBSERVATION | Proxy | User dmarsh visited https://ms0365-support.login-verification.click/auth (200 OK) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:41Z | OBSERVATION | Proxy | POST to https://ms0365-support.login-verification.click/auth/submit (302 redirect) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:43Z | OBSERVATION | Proxy | Downloaded update.zip (421KB) from https://ms0365-support.login-verification.click/auth/drop/update.zip | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:44Z | OBSERVATION | Proxy | Initial TCP CONNECT to 185.220.101.47:443 (Tor exit relay) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:41Z | OBSERVATION | EDR | powershell.exe launched with encoded command on WST-WS-031 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:46:57Z | OBSERVATION | EDR | msbuild.exe spawned as child of powershell.exe, cmdline: msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | EDR Network | Outbound ESTABLISHED connection from MSBuild.exe (PID 8104) to 185.220.101.47:443, bytes_sent=4198, bytes_received=11203 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | Alert fired: Suspicious process tree PowerShell->MSBuild on WST-WS-031, MITRE ATT&CK T1127.001, T1059.001 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:11Z | EVIDENCE | SOC Evidence Collector | alert_A-20260414-9841.json preserved to /evidence/IR-2026-0414-01/endpoint_telemetry/ | source=soc-evidence-collector v2.1 | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | Steve, on-call SOC | Incident declared SEV2: Confirmed beaconing from high-criticality clinical workstation to known Tor exit relay; credential theft suspected via phishing; data exposure scope pending verification | source=alert_A-20260414-9841.json, proxy_24h_dmarsh.log, playbook PB-CRED-001 | certainty=confirmed

- 2026-04-14T02:51:04Z | ACTION | Steve, on-call SOC | Initialized evidence store /evidence/IR-2026-0414-01 with tamper-obvious directory structure | source=evidence_store_init.sh | certainty=confirmed

- 2026-04-14T02:51:04Z | COMMUNICATION | Steve, on-call SOC | Pager acknowledgment sent to James Chen (incident channel); status "investigating" | source=incident_channel | certainty=confirmed

- 2026-04-14T02:51:04Z | COMMUNICATION | James Chen, SOC Lead | Assignment directive: "You own this. Contain it. Document everything." | source=incident_channel | certainty=confirmed

- 2026-04-14T02:52:18Z | EVIDENCE | SOC Evidence Collector | proxy_24h_dmarsh.log preserved to /evidence/IR-2026-0414-01/proxy_dns/ | source=soc-evidence-collector v2.1 | certainty=confirmed
