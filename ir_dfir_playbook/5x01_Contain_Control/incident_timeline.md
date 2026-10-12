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

## Entry schema

- timestamp (UTC, ISO 8601) | TYPE | actor | one-line description | source | certainty
- Actors are drawn from a fixed set: Proxy, EDR, SIEM, Steve, James Chen.

## Entries

- 2026-04-13T18:13:44Z | OBSERVATION | Proxy | dmarsh opened a mail item at hxxps://outlook[.]office[.]com/mail/id/AAMkAG | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:02Z | OBSERVATION | Proxy | dmarsh visited hxxps://ms0365-support[.]login-verification[.]click/auth, referer the mail item above | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:07Z | OBSERVATION | Proxy | phishing site loaded static asset ms-logo[.]svg | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:09Z | OBSERVATION | Proxy | phishing site loaded static asset login[.]css | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:41Z | OBSERVATION | Proxy | dmarsh submitted form to ms0365-support[.]login-verification[.]click/auth/submit, response 302 | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:14:43Z | OBSERVATION | Proxy | dmarsh downloaded update[.]zip (421004 bytes) from the phishing site drop directory | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-13T18:15:18Z | OBSERVATION | Proxy | dmarsh returned to mailbox at hxxps://outlook[.]office[.]com/mail/inbox | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:41Z | OBSERVATION | EDR | powershell.exe (PID 7812) launched on WST-WS-031 by MEDDEFENSE\dmarsh with encoded, hidden-window command line | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:46:44Z | OBSERVATION | Proxy | WST-WS-031 initiated CONNECT to 185.220.101[.]47:443 | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:46:57Z | OBSERVATION | EDR | MSBuild.exe (PID 8104) spawned as child of powershell.exe (PID 7812) executing update.xml from Temp | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | Proxy | second CONNECT to 185.220.101[.]47:443, 200, 4198 bytes | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:47:02Z | OBSERVATION | EDR | MSBuild.exe opened outbound TCP 10.42.118[.]31:54917 to 185.220.101[.]47:443, ESTABLISHED, 4198 bytes sent, 11203 received | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:08Z | OBSERVATION | Proxy | third CONNECT to 185.220.101[.]47:443, 200, 11203 bytes | source=proxy_24h_dmarsh.log | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM | rule wz-edr-100041 fired alert A-20260414-9841 on WST-WS-031, severity high, techniques T1127.001 and T1059.001 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:47:11Z | OBSERVATION | SIEM | enrichment tags for 185.220.101[.]47: tor_exit_relay, anonymizer, high_risk; VT 22/91; AbuseIPDB 84 | source=alert_A-20260414-9841.json | certainty=confirmed

- 2026-04-14T02:51:04Z | DECISION | Steve | Incident IR-2026-0414-01 declared at SEV2: high-severity alert on a high-criticality clinical workstation with confirmed malicious process chain and Tor-relay contact; exposure scope unknown | source=alert_A-20260414-9841.json, proxy_24h_dmarsh.log | certainty=confirmed
