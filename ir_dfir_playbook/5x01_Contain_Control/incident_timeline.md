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

- 2026-04-13T18:13:44Z | OBSERVATION | Proxy | GET hxxps://outlook[.]office[.]com/mail/id/AAMkAG (200) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:02Z | OBSERVATION | Proxy | GET hxxps://ms0365-support[.]login-verification[.]click/auth (200), referer hxxps://outlook[.]office[.]com/mail/id/AAMkAG | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:07Z | OBSERVATION | Proxy | GET ms0365-support[.]login-verification[.]click/auth/static/ms-logo[.]svg (200) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:09Z | OBSERVATION | Proxy | GET ms0365-support[.]login-verification[.]click/auth/static/login[.]css (200) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:41Z | OBSERVATION | Proxy | POST ms0365-support[.]login-verification[.]click/auth/submit (302, 418 bytes) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:43Z | OBSERVATION | Proxy | GET ms0365-support[.]login-verification[.]click/auth/drop/update[.]zip (200, 421004 bytes) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:15:18Z | OBSERVATION | Proxy | GET hxxps://outlook[.]office[.]com/mail/inbox (200) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:41Z | OBSERVATION | EDR | powershell.exe (PID 7812) started on WST-WS-031, cmdline powershell.exe -ep bypass -w hidden -enc <base64>, sha256 6f5902ac237024bdd0c176cb93063dc4e2a5e89d4aad51b3b3e4f7b72bce7e5e, user MEDDEFENSE\dmarsh, signed Microsoft Corporation | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:46:44Z | OBSERVATION | Proxy | CONNECT 185.220.101[.]47:443 (no status, no bytes) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:57Z | OBSERVATION | EDR | MSBuild.exe (PID 8104, parent PID 7812) started on WST-WS-031, cmdline msbuild.exe C:\Users\dmarsh\AppData\Local\Temp\update.xml, sha256 b2f5b7a7d2b0ec7cc8e4e5a03c6f72d4b1e53d1c4c4fcb9bba9c8a9aa9bba3f1, working directory C:\Users\dmarsh\AppData\Local\Temp | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | Proxy | CONNECT 185.220.101[.]47:443 (200, 4198 bytes) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | EDR Network | MSBuild.exe (PID 8104) outbound TCP from 10.42.118[.]31:54917 to 185.220.101[.]47:443, state ESTABLISHED, bytes_sent 4198, bytes_received 11203 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:08Z | OBSERVATION | Proxy | CONNECT 185.220.101[.]47:443 (200, 11203 bytes) | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM rule wz-edr-100041 | Alert A-20260414-9841 fired: Suspicious process tree PowerShell -> MSBuild on WST-WS-031, severity high, MITRE T1127.001, T1059.001, queue on_call_tier2, correlated events 3 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | Alert enrichment | Remote IP 185.220.101[.]47 tagged tor_exit_relay, anonymizer, high_risk by internal_threat_intel; VirusTotal 22/91 malicious; AbuseIPDB confidence 84; geoip DE, AS208294, Foundation for Applied Privacy | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | Steve, on-call SOC | Incident declared. Rationale: alert A-20260414-9841 fired on WST-WS-031 (asset_class clinical_workstation, criticality high); process tree powershell.exe (PID 7812) -> msbuild.exe (PID 8104) executing C:\Users\dmarsh\AppData\Local\Temp\update.xml; outbound TCP to 185.220.101[.]47:443, that IP tagged tor_exit_relay/high_risk by internal threat intel; proxy log shows same account accessed ms0365-support[.]login-verification[.]click and downloaded update[.]zip (421004 bytes) | source=alert_A-20260414-9841.json, proxy_24h_dmarsh.log | certainty=confirmed
