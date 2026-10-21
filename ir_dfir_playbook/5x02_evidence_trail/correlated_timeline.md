# Correlated Incident Timeline: LH-2026-0414-01

**Case:** LH-2026-0414-01 / IR-2026-0414-01
**Analyst:** Steve — Cybersecurity Engineer
**Correlated sources:** ART-001 disk findings (Tasks 3–4), ART-002 memory findings (Task 5),
`proxy_log.jsonl`, `ad_auth_log.jsonl`, `siem_alert_export.json`, chain-of-custody records.

**Legend:** Each entry cites the controlling evidence (log line or artifact finding ID).
Where a forensic finding is cited, the underlying artifact retains its own hash-verified
integrity per the chain of custody. Approximate times are marked `~` and occur where
precise MAC/registry timestamps await lab-run completion.

## Timeline

| Timestamp (UTC) | Source | Event | ATT&CK | Certainty | Evidence Ref |
|---|---|---|---|---|---|
| 2026-04-13T03:10:22Z | ad_auth_log | Normal-hours Kerberos AS-REQ and interactive logon (type 2) for dmarsh on WST-WS-031 — establishes baseline working pattern | — | confirmed | ad_auth_log.jsonl lines 1–2 |
| 2026-04-13T18:13:44Z | proxy_log | dmarsh opens a message in Outlook web mail (msg-AAMkAG) — the phishing email | T1566.002 | confirmed | proxy_log.jsonl line 6; referred_by_email tag line 7 |
| 2026-04-13T18:14:02Z | proxy_log | Link clicked in phishing message; GET to typosquat `ms0365-support[.]login-verification[.]click/auth`, flagged `suspicious_typosquat`, referrer the Outlook message | T1566.002 | confirmed | proxy_log.jsonl line 7 |
| 2026-04-13T18:14:07Z | proxy_log | Phishing kit assets fetched (ms-logo.svg, login.css) — fake Microsoft login page rendered | T1566.002 | confirmed | proxy_log.jsonl lines 8–9 |
| 2026-04-13T18:14:41Z | proxy_log | Form POST to `/auth/submit` — dmarsh submits credentials to typosquat domain (HTTP 302 redirect) | T1566.002 | confirmed | proxy_log.jsonl line 10 |
| 2026-04-13T18:14:41Z | ad_auth_log | Azure AD sign-in to Office 365 Portal as dmarsh from RU (45.63.9.88), same second as credential submission — impossible-travel risk `medium` suppressed by CA `compliant_device` | T1078 | confirmed | ad_auth_log.jsonl line 3; SIEM `correlated_events[0]` |
| 2026-04-13T18:14:43Z | proxy_log + ART-001 | Payload download: GET `/auth/drop/update.zip`, 421,004 bytes; file created in `C:\Users\dmarsh\Downloads\` at the same timestamp on disk | T1566.002 / T1105 | confirmed | proxy_log.jsonl line 11; ART-001-F01 |
| 2026-04-13T19:02:11Z | ad_auth_log | dmarsh interactive logoff on WST-WS-031 — attacker holds credentials; user departs | — | confirmed | ad_auth_log.jsonl line 4 |
| 2026-04-14T02:44:02Z | ad_auth_log | Off-hours Kerberos AS-REQ and interactive logon (type 2) for dmarsh on WST-WS-031 (`unusual_hour_for_user`); source is the internal workstation | T1078 | probable (attribution of who sat at the console not established) | ad_auth_log.jsonl lines 5–6 |
| 2026-04-14T02:44:17Z | ad_auth_log (vpn) | VPN logon as dmarsh from external RU IP 45.63.9.88; conditional access passed despite foreign IP — attacker remote entry into the estate | T1078 / T1133 | confirmed | ad_auth_log.jsonl line 7 |
| 2026-04-14T02:46:41Z | SIEM (edr) | `powershell.exe` PID 7812 created with `-ep bypass -w hidden -enc` encoded payload; parent `update.exe` from Temp | T1059.001 | confirmed | siem_alert_export.json `correlated_events[1]`; ART-002-M01 |
| ~2026-04-14T02:46Z | ART-001 | `update.xml` (MSBuild inline-task payload) staged in `C:\Users\dmarsh\AppData\Local\Temp\` (exact seconds pending lab MAC times) | T1127.001 / T1027 | confirmed (presence) | ART-001-F02 |
| 2026-04-14T02:46:57Z | SIEM (edr) | `MSBuild.exe` PID 8104 created, PPID 7812 — LOLBin execution of `Temp\update.xml` | T1127.001 | confirmed | siem_alert_export.json `correlated_events[2]`; ART-002-M01 |
| 2026-04-14T02:46:58Z | proxy_log | C2 beacon begins: CONNECT 185.220.101.47:443 (Tor exit relay) by MSBuild.exe PID 8104; further CONNECTs at 02:47:02Z and 02:47:30Z | T1071.001 / T1090.003 | confirmed | proxy_log.jsonl lines 12–14; ART-002-M02 (ESTABLISHED at capture) |
| 2026-04-14T02:47:11Z | SIEM | Rule wz-edr-100041 fires: "Suspicious process tree: PowerShell -> MSBuild", severity high, alert A-20260414-9841; `analyst_assigned: null`, disposition open — detective control fired but was not actioned | — | confirmed | siem_alert_export.json `alert.fired_at` |
| ~2026-04-14T02:46–03:02Z | ART-001 | Persistence installed: HKCU Run key and scheduled task, both `MsUpdateCheck`, chaining PowerShell + MSBuild at logon (registry last-write timestamps pending lab run) | T1547.001 / T1053.005 | confirmed (presence) | ART-001-R01, ART-001-R03 |
| ~2026-04-14T02:46–03:02Z | ART-002 | NTLM hash and Kerberos ticket material for dmarsh resident in lsass.exe during the attack window — accessible to the attacker (Hashdump output pending) | T1003.001 | possible (pending ART-002-M07) | ART-002-M06/M07 |
| 2026-04-14T03:02:00Z | CoC | ART-002 memory capture from live, still-beaconing WST-WS-031 (pre-isolation) — establishes C2 channel state at this instant | — | confirmed | chain-of-custody ART-002 entry; ART-002-M02 |
| 2026-04-14T03:22:47Z | ad_auth_log | Kerberos TGS-REQ for `cifs/WST-WS-017` from WST-WS-031 (10.42.118.31) — reconnaissance/lateral preparation against second host | T1558.003 / T1021.002 | confirmed | ad_auth_log.jsonl line 8 |
| 2026-04-14T03:22:48Z | ad_auth_log | Kerberos TGS-REQ for `host/WST-WS-017` — service enumeration continues | T1021 | confirmed | ad_auth_log.jsonl line 9 |
| 2026-04-14T03:23:01Z | ad_auth_log | Network logon (type 3, Kerberos) to WST-WS-017 from WST-WS-031 — lateral movement accomplished via dmarsh's Kerberos ticket | T1550.003 / T1021.002 | confirmed | ad_auth_log.jsonl line 10 |
| ~2026-04-14T03:23–03:27Z | ART-003 / logs | PowerShell + MSBuild chain replicated on WST-WS-017 (process detail awaits ART-003 Volatility run) | T1059.001 / T1127.001 | probable | proxy process tags line 15; ART-003 (pending) |
| 2026-04-14T03:27:13Z | proxy_log | Second C2 beacon: CONNECT 91.234.99.107:443 (`c2_infrastructure`) by MSBuild.exe PID 5108 on WST-WS-017 (10.42.118.17); second CONNECT at 03:27:45Z | T1071.001 | confirmed | proxy_log.jsonl lines 15–16 |
| 2026-04-14T03:38:00Z | CoC | ART-003 memory capture from live WST-WS-017 (pre-isolation) | — | confirmed | chain-of-custody ART-003 entry |
| 2026-04-14T03:40:18Z | ad_auth_log | Kerberos TGS-REQ for `cifs/LIS-WSIDE-01` from WST-WS-017 — pivot toward lab results server | T1558.003 / T1021.002 | confirmed | ad_auth_log.jsonl line 11 |
| 2026-04-14T03:41:52Z | ad_auth_log | Second TGS-REQ for `cifs/LIS-WSIDE-01`, noted `ticket_reuse` — service ticket replay | T1550.003 | confirmed | ad_auth_log.jsonl line 12 |
| 2026-04-14T03:42:08Z | ad_auth_log | Network logon (type 3, Kerberos) to LIS-WSIDE-01 from WST-WS-017 | T1021.002 | confirmed | ad_auth_log.jsonl line 13 |
| 2026-04-14T03:43:30Z | ad_auth_log (fileserver_audit) | 14 patient lab report PDFs opened via share `LIS_REPORTS$` (`C:\LIS\reports\daily\*.pdf`) as dmarsh — PHI access, the breach-scope centerpiece | T1083 / T1005 | confirmed | ad_auth_log.jsonl line 14 |
| 2026-04-14T~04:00Z | CoC | Hosts isolated to VLAN 999 by James Chen; ART-001 disk image acquired thereafter (completed 06:14Z) | — | confirmed (sequence) | chain-of-custody ART-001 entry |

## Correlation notes

1. **Same-second credential theft and replay (18:14:41Z).** The proxy POST to the typosquat
   submit endpoint and the Azure AD sign-in from RU carry the same timestamp — the phishing
   kit harvested and replayed the credential within the same second. This is the tightest
   single-source-pair correlation in the case and pins Initial Access + T1078 precisely.
2. **SIEM fired and was ignored.** Alert A-20260414-9841 fired at 02:47:11Z, four seconds
   after the first C2 CONNECT, with `analyst_assigned: null`. The detective control worked;
   the response process did not. Dwell time from first execution to PHI access: 56 minutes
   and 49 seconds (02:46:41Z → 03:43:30Z).
3. **Two C2 channels, two infrastructure classes.** WST-WS-031 beaconed via a Tor exit
   relay (anonymizer) while WST-WS-017 beaconed direct to `c2_infrastructure` tagged
   91.234.99.107 — distinct IOC classes requiring separate perimeter blocking actions.
4. **Ticket reuse flags the lateral method.** The `ticket_reuse` note on the 03:41:52Z TGS
   request plus type-3 Kerberos logons from each preceding host corroborate Pass-the-Ticket
   style movement (T1550.003) rather than fresh credential authentication at each hop.
5. **Pending items carried forward:** exact MAC seconds and registry last-write times
   (ART-001 lab run), ART-003 Volatility output (second-host process tree), and ART-002
   Hashdump confirmation of LSASS credential material — the single `possible` entry above.
   These refine timestamps but do not alter the sequence, which is anchored by the three
   corroborating log sources.
