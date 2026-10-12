# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: /evidence/IR-2026-0414-01/

Hash algorithm: SHA-256

Hash manifest: /evidence/IR-2026-0414-01/hashes.txt (format: <sha256>  <relative_path>)

All destinations below are given as relative paths under /evidence/IR-2026-0414-01/. Where a host-local command writes to the evidence store, it targets the mapped share \\\\evidence\\IR-2026-0414-01\\ (same store, Windows UNC view of the same directory).

## 1. Volatile memory, WST-WS-031

- what: Full physical memory dump of WST-WS-031
- how: winpmem_3.3.rc3.exe -o \\\\evidence\\IR-2026-0414-01\\memory\\wst-ws-031.mem
- where: memory/wst-ws-031.mem
- hash cmd: sha256sum /evidence/IR-2026-0414-01/memory/wst-ws-031.mem >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: MUST be the first acquisition. Memory state is destroyed by reboot, power-off, and process termination. Nothing in Sections 2 through 8 may run on the host before this completes, because every tool launch modifies memory.
- verification: hash line present in hashes.txt

## 2. Running process list, WST-WS-031

- what: Snapshot of all processes with ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate, confirming the PID 7812 -> PID 8104 lineage
- how: powershell.exe -Command "Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json | Out-File -Encoding utf8 \\\\evidence\\IR-2026-0414-01\\\\process_tree\\\\wst-ws-031_processes.json"
- where: process_tree/wst-ws-031_processes.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/process_tree/wst-ws-031_processes.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Must run after Section 1 and before any process termination, EDR quarantine action, or host isolation. Those actions alter the process table and destroy the parent-child relationship evidence.
- verification: hash line present in hashes.txt

## 3. Active network connections, WST-WS-031

- what: All TCP/UDP connections with owning PID and remote endpoint, including the ESTABLISHED session 10.42.118[.]31:54917 -> 185.220.101[.]47:443 held by MSBuild.exe (PID 8104)
- how: netstat -ano > \\\\evidence\\IR-2026-0414-01\\network\\wst-ws-031_netstat.txt
- how: powershell.exe -Command "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv -NoTypeInformation \\\\evidence\\IR-2026-0414-01\\\\network\\\\wst-ws-031_tcpconn.csv"
- where: network/wst-ws-031_netstat.txt
- where: network/wst-ws-031_tcpconn.csv
- hash cmd: sha256sum /evidence/IR-2026-0414-01/network/wst-ws-031_netstat.txt >> /evidence/IR-2026-0414-01/hashes.txt
- hash cmd: sha256sum /evidence/IR-2026-0414-01/network/wst-ws-031_tcpconn.csv >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Must run after Section 1 and before network isolation of WST-WS-031, which closes the C2 socket. Executed in the same console session as Section 2; both are read-only queries that do not affect each other.
- verification: both hash lines present in hashes.txt

## 4. Endpoint telemetry export, WST-WS-031, 24h pre-alert

- what: Wazuh EDR event stream for WST-WS-031 covering 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z (process creations, file creations, network connections), source file edr_wst_ws_031_24h.jsonl
- how: cp $LAB_MATERIALS/5x01/edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl
- where: endpoint_telemetry/edr_wst_ws_031_24h.jsonl
- hash cmd: sha256sum /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Time-sensitive, not volatile-sensitive: SIEM index retention and rollover can drop the 24h window, and containment-generated event floods can push these events out of the hot window. Captured after host-local volatile sections (1-3) because it does not depend on the host remaining untouched.
- verification: hash line present in hashes.txt

## 5. SIEM alert record, A-20260414-9841

- what: Full JSON alert record for rule wz-edr-100041 (process tree, network connection, enrichment, SIEM context)
- how: cp $LAB_MATERIALS/5x01/alert_A-20260414-9841.json /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json
- where: siem/alert_A-20260414-9841.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: The alert record shows analyst_assigned: null; capture before any SOC queue action (assignment, annotation, severity override) mutates the record. Collected in the same batch as Section 4.
- verification: hash line present in hashes.txt

## 6. Proxy logs, dmarsh, 24h pre-alert

- what: HTTP/HTTPS request log for MEDDEFENSE\dmarsh, 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z, source file proxy_24h_dmarsh.log, containing the 18:14Z phishing sequence and the 02:46:44Z-02:47:08Z CONNECT series to 185.220.101[.]47
- how: cp $LAB_MATERIALS/5x01/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log
- where: proxy_dns/proxy_24h_dmarsh.log
- hash cmd: sha256sum /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: The export is a 24h rolling window; the 18:14Z initial-access evidence ages out within hours regardless of containment state. Capture immediately after the host-local volatile sections, before any waiting.
- verification: hash line present in hashes.txt

## 6b. DNS logs, dmarsh, 24h pre-alert

- what: DNS query log for MEDDEFENSE\dmarsh (source IP 10.42.118[.]31 / host WST-WS-031), 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z, capturing all hostname resolutions including dns for ms0365-support.login-verification.click and 185.220.101.47
- how: Query DNS server: query user=dmarsh OR client_ip=10.42.118.31 AND timestamp >= 2026-04-13T02:47:00Z AND timestamp < 2026-04-14T02:47:00Z; export to \\evidence\IR-2026-0414-01\proxy_dns\dns_24h_dmarsh.log
- how: cp $LAB_MATERIALS/5x01/dns_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/dns_24h_dmarsh.log
- where: proxy_dns/dns_24h_dmarsh.log
- hash cmd: sha256sum /evidence/IR-2026-0414-01/proxy_dns/dns_24h_dmarsh.log >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Paired with proxy logs, same 24h rolling window constraint. DNS queries for the malicious domain must be captured before log rotation truncates them. Captured alongside Section 6 (proxy) in the same batch.
- verification: hash line present in hashes.txt

## 7. Authentication events, dmarsh, 24h pre-alert

- what: AD (ms-dc01, ms-dc02) and Azure AD authentication events for MEDDEFENSE\dmarsh, 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z, source file auth_24h_dmarsh.json, covering sessions 0x1c8a4f and 0x3a71c2 and the Azure AD impossibleTravel sign-in at 18:14:41Z
- how: cp $LAB_MATERIALS/5x01/auth_24h_dmarsh.json /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json
- where: authentication/auth_24h_dmarsh.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Must be captured before any credential reset or account disable on dmarsh. Those actions generate new authentication events and alter the context of the 02:44:02Z unusual-hour logon that must be interpreted against a frozen window.
- verification: hash line present in hashes.txt

## 8. Disk artifacts, WST-WS-031, Temp directory

- what: Artifact 1, Temp directory inventory: full recursive listing of C:\Users\dmarsh\AppData\Local\Temp with FullName, Length, CreationTime, LastWriteTime, LastAccessTime
- how: powershell.exe -Command "Get-ChildItem -Recurse -File C:\Users\dmarsh\AppData\Local\Temp | Select-Object FullName,Length,CreationTime,LastWriteTime,LastAccessTime | Export-Csv -NoTypeInformation \\\\evidence\\IR-2026-0414-01\\\\disk\\\\wst-ws-031_temp_inventory.csv"
- where: disk/wst-ws-031_temp_inventory.csv
- hash cmd: sha256sum /evidence/IR-2026-0414-01/disk/wst-ws-031_temp_inventory.csv >> /evidence/IR-2026-0414-01/hashes.txt

- what: Artifact 2, dropped payload update.xml, referenced in the alert process tree as C:\Users\dmarsh\AppData\Local\Temp\update.xml
- how: copy C:\Users\dmarsh\AppData\Local\Temp\update.xml \\\\evidence\\IR-2026-0414-01\\disk\\update.xml
- where: disk/update.xml
- hash cmd: sha256sum /evidence/IR-2026-0414-01/disk/update.xml >> /evidence/IR-2026-0414-01/hashes.txt
- cross-check: certutil -hashfile C:\Users\dmarsh\AppData\Local\Temp\update.xml SHA256 computed on the host before copying; value must equal the stored hash (transfer integrity check)

- what: Artifact 3, dropped payload update.exe, the executable stage implied by the update.zip download; expected at C:\Users\dmarsh\AppData\Local\Temp\update.exe. If absent at capture time, record absence in the inventory (Artifact 1) and note in the incident timeline as an OBSERVATION; do not substitute or skip the hash step for files that do exist
- how: copy C:\Users\dmarsh\AppData\Local\Temp\update.exe \\\\evidence\\IR-2026-0414-01\\disk\\update.exe
- where: disk/update.exe
- hash cmd: sha256sum /evidence/IR-2026-0414-01/disk/update.exe >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Last host-local capture, after Sections 1-3. Disk files survive memory acquisition but are mutable: attacker cleanup, EDR quarantine, and any later rebuild destroy them. Captured before eradication begins.
- verification: one hash line per captured artifact present in hashes.txt

## 9. Verification (final step)

- Re-hash the entire store and compare against the manifest: while read -r expected relpath; do actual=$(sha256sum "/evidence/IR-2026-0414-01/$relpath" | awk '{print $1}'); [[ "$expected" == "$actual" ]] && echo "MATCH $relpath" || echo "MISMATCH $relpath expected=$expected actual=$actual"; done < /evidence/IR-2026-0414-01/hashes.txt
- Every mismatch is appended to incident_timeline.md as an OBSERVATION entry with source=evidence_verification, certainty=confirmed, and halts reliance on the affected artifact pending re-acquisition
- On full match, append the closing line to hashes.txt: # Verified: YYYY-MM-DDTHH:MM:SSZ by Steve

## Execution Order Summary

1. Section 1, memory: destroyed by reboot or process termination
2. Sections 2-3, process table and sockets: modified by kill, quarantine, or isolation
3. Sections 4-5, EDR telemetry and SIEM alert: retention and queue-mutation risk
4. Section 6, proxy log + Section 6b, DNS log: 24h rolling window actively aging out
5. Section 7, auth export: must freeze before any credential reset
6. Section 8, disk artifacts: vulnerable to cleanup, quarantine, and rebuild
7. Section 9, verification of the complete store

No containment action executes until Sections 1 through 8 are complete and hashed.
