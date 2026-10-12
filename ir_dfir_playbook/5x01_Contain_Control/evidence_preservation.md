# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: /evidence/IR-2026-0414-01/
Hash algorithm: SHA-256
Command format: certutil -hashfile <artifact_path> SHA256 | find /v "Hash"

## 1. Volatile memory, WST-WS-031

- what: Full physical memory dump capturing active processes, network sockets, encryption keys, and in-memory payloads
- how: winpmem_3.3.rc3.exe -o \\evidence\IR-2026-0414-01\memory\wst-ws-031.mem --memdump
- where: /evidence/IR-2026-0414-01/memory/wst-ws-031.mem
- hash cmd: certutil -hashfile wst-ws-031.mem SHA256
- ordering: MUST precede ANY containment action (process kill, network isolation, credential rotation). Power cycle or aggressive containment will destroy memory-resident artifacts including decrypted malware stages and injected code.
- verification: Append `<hash_value>  memory/wst-ws-031.mem` to /evidence/IR-2026-0414-01/hashes.txt

## 2. Running process list with PIDs, command lines, parent PIDs

- what: Complete snapshot of active processes including hidden/injected threads via EDR or native tools
- how: Get-WmiObject Win32_Process | Select-Object ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate | ConvertTo-Json > \\evidence\IR-YYYY-MMDD-01\process_tree\wst-ws-031_processes.json
- where: /evidence/IR-2026-0414-01/process_tree/wst-ws-031_processes.json
- hash cmd: certutil -hashfile wst-ws-031_processes.json SHA256
- ordering: Must precede process termination or host reboot. Kill actions modify this state immediately.
- verification: Append to hashes.txt

## 3. Active network connections

- what: All established, listening, and TIME_WAIT TCP/UDP connections with owning PIDs and remote endpoints
- how: netstat -ano | findstr /C:"ESTABLISHED" /C:"LISTENING" /C:"TIME_WAIT" > \\evidence\IR-YYYY-MMDD-01\network\wst-ws-031_connections.txt; Get-NetTCPConnection | Export-Csv -Path \\evidence\IR-YYYY-MMDD-01\network\wst-ws-031_network.csv
- where: /evidence/IR-2026-0414-01/network/wst-ws-031_connections.txt and /evidence/IR-2026-0414-01/network/wst-ws-031_network.csv
- hash cmd: certutil -hashfile wst-ws-031_connections.txt SHA256; certutil -hashfile wst-ws-031_network.csv SHA256
- ordering: Must precede network isolation/firewall rule application. Containment will close active sockets.
- verification: Append to hashes.txt

## 4. Full endpoint telemetry export for WST-WS-031 (24h pre-alert)

- what: Wazuh EDR JSONL export covering 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z including process execution, file creation/modification, and network connections
- how: curl -s -X GET 'https://wazuh-api.meddefense.local/api/alerts?host=WST-WS-031&from=2026-04-13T02:47:00Z&to=2026-04-14T02:47:00Z' -H 'Authorization: Bearer $API_TOKEN' > \\evidence\IR-YYYY-MMDD-01\endpoint_telemetry\edr_wst_ws_031_24h.jsonl
- where: /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl
- hash cmd: certutil -hashfile edr_wst_ws_031_24h.jsonl SHA256
- ordering: Telemetry APIs may prune or aggregate after 24-48 hours. Capture early to ensure completeness. Independent of containment actions but time-sensitive.
- verification: Append to hashes.txt

## 5. SIEM alert record

- what: Alert A-20260414-9841 JSON payload with full enrichment including MITRE ATT&CK mappings, threat intel tags, and correlated event count
- how: curl -s -X GET 'https://spluk.meddefense.local/services/alerts/export?id=A-20260414-9841' -H 'Authorization: Bearer $SPLUNK_TOKEN' > \\evidence\IR-YYYY-MMDD-01\siem\alert_A-20260414-9841.json
- where: /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json
- hash cmd: certutil -hashfile alert_A-20260414-9841.json SHA256
- ordering: Alerts may be modified by downstream triage or suppression rules. Capture immediately upon declaration.
- verification: Append to hashes.txt

## 6. Proxy and DNS logs for dmarsh (24h pre-alert)

- what: HTTP/HTTPS request logs showing URL access patterns, referrers, status codes, byte counts, and DNS resolution events for user MEDDEFENSE\dmarsh
- how: Export from proxy gateway: query user=dmarsh AND timestamp >= 2026-04-13T02:47:00Z AND timestamp < 2026-04-14T02:47:00Z; export proxy_24h_dmarsh.log to \\evidence\IR-YYYY-MMDD-01\proxy_dns\proxy_24h_dmarsh.log
- where: /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log
- hash cmd: certutil -hashfile proxy_24h_dmarsh.log SHA256
- ordering: Proxy retention policies vary; capture before log rotation. Critical for establishing initial access vector (phishing domain visit, malware download).
- verification: Append to hashes.txt

## 7. Authentication events for dmarsh (24h pre-alert)

- what: Kerberos ticket grants (TGT/TGS), interactive logons (Event ID 4624), Azure AD sign-ins including MFA method, risk level, and conditional access results for MEDDEFENSE\dmarsh
- how: From AD DC01/DC02: Get-EventLog -LogName Security -InstanceId 4624,4634,4728,4729,4740 -ComputerName ms-dc01,ms-dc02 | Where-Object {$_.TimeGenerated -ge '2026-04-13T02:47:00Z' -and $_.TimeGenerated -lt '2026-04-14T02:47:00Z' -and $_.Message -match 'dmarsh'} | Export-Csv -Path \\evidence\IR-YYYY-MMDD-01\authentication\ad_auth_24h_dmarsh.csv; From Azure AD: auditlogs/?$filter=userPrincipalName eq 'dmarsh@meddefense.local' and activityDateTime ge 2026-04-13T02:47:00Z and activityDateTime lt 2026-04-14T02:47:00Z > \\evidence\IR-YYYY-MMDD-01\authentication\auth_24h_dmarsh.json
- where: /evidence/IR-2026-0414-01/authentication/ad_auth_24h_dmarsh.csv and /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json
- hash cmd: certutil -hashfile ad_auth_24h_dmarsh.csv SHA256; certutil -hashfile auth_24h_dmarsh.json SHA256
- ordering: AD and Azure AD audit logs are immutable once committed but may expire per retention policy. Capture before credential rotation invalidates session tokens and obscures compromise timeline.
- verification: Append to hashes.txt

## 8. Disk artifacts (post-volatile but pre-reboot)

- what: Suspicious file extracts including C:\Users\dmarsh\AppData\Local\Temp\update.xml and any dropped executables
- how: Copy with hash preservation: robocopy /NFL /NDL /NJH /NJS /NP /W:5 /R:3 C:\Users\dmarsh\AppData\Local\Temp C:\evidence\IR-YYYY-MMDD-01\disk\tmp_extract /XF *.tmp | Select-String -Pattern "update.xml|update.exe"; Get-ChildItem -Recurse -File -Path C:\Users\dmarsh\AppData\Local\Temp | Where-Object {$_.LastWriteTime -ge '2026-04-13T18:00:00Z'} | Export-Csv -Path \\evidence\IR-YYYY-MMDD-01\disk\suspicious_files_inventory.csv
- where: /evidence/IR-2026-0414-01/disk/tmp_extract/ and /evidence/IR-2026-0414-01/disk/suspicious_files_inventory.csv
- hash cmd: For each extracted file: certutil -hashfile <file> SHA256
- ordering: Files may be deleted by EDR cleanup or attacker post-exploitation scripts. Capture before remediation steps.
- verification: Append to hashes.txt

## 9. Verification

- Execute verification script: ./evidence_verify.sh /evidence/IR-2026-0414-01/hashes.txt
- Script re-computes SHA-256 for all artifacts listed in hashes.txt
- Compare computed values against original captured hashes
- Any mismatches logged as OBSERVATION entry in incident_timeline.md with source=evidence_verification, certainty=confirmed
- On success, add final verification timestamp line to hashes.txt: # Verified: YYYY-MM-DDTHH:MM:SSZ by <analyst_name>

## Order Summary (Execution Sequence)

1. Memory capture (Step 1) — destroys on power-off
2. Process list + network connections (Steps 2-3) — changes on process kill/isolation
3. Endpoint telemetry + SIEM alert (Steps 4-5) — time-sensitive API retention
4. Proxy/DNS logs (Step 6) — retention-limited
5. Authentication events (Step 7) — credential rotation impact
6. Disk artifacts (Step 8) — deletion risk

Failure to follow this order risks irreversible loss of volatile forensic artifacts.
