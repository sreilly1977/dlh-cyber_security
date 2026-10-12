# Evidence Preservation Runbook: IR-2026-0414-01

Evidence store: /evidence/IR-2026-0414-01/

Hash algorithm: SHA-256

Hash manifest: /evidence/IR-2026-0414-01/hashes.txt (format: <sha256>  <relative_path>)

Convention: each section below documents exactly one artifact. `where` is a relative path under /evidence/IR-2026-0414-01/. Host-local Windows commands write to the UNC share \\\\evidence\\IR-2026-0414-01\\, the same store viewed from WST-WS-031.

## Artifact 1. Volatile memory, WST-WS-031

- what: Full physical memory dump of WST-WS-031, including resident memory of powershell.exe (PID 7812) and MSBuild.exe (PID 8104)
- how: winpmem_3.3.rc3.exe -o \\\\evidence\\IR-2026-0414-01\\memory\\wst-ws-031.mem
- where: memory/wst-ws-031.mem
- hash cmd: sha256sum /evidence/IR-2026-0414-01/memory/wst-ws-031.mem >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: First acquisition of the incident, before every other step. This artifact is destroyed by reboot, power-off, and process termination, and degraded by any additional tool execution on the host. It therefore precedes Artifacts 2 through 4 (which require launching tools on the host) and precedes all containment, none of which may begin until this hash is written.
- verification: hash line present in hashes.txt

## Artifact 2. Running process list, WST-WS-031

- what: JSON snapshot of all processes with ProcessId, ParentProcessId, ExecutablePath, CommandLine, CreationDate, preserving the PID 7812 -> PID 8104 lineage
- how: powershell.exe -Command "Get-WmiObject Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate | ConvertTo-Json | Out-File -Encoding utf8 \\\\evidence\\IR-2026-0414-01\\\\process_tree\\\\wst-ws-031_processes.json"
- where: process_tree/wst-ws-031_processes.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/process_tree/wst-ws-031_processes.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Second acquisition. Runs immediately after memory capture because the process table changes the instant a process is terminated, EDR quarantines powershell.exe or MSBuild.exe, or the host is isolated. Its own capture (a WMI enumeration) is read-only and does not invalidate Artifact 3, so the two may share a console session.
- verification: hash line present in hashes.txt

## Artifact 3. Network connections (netstat), WST-WS-031

- what: Plain-text netstat -ano output listing every TCP/UDP connection with owning PID, including the ESTABLISHED session 10.42.118[.]31:54917 -> 185.220.101[.]47:443 owned by PID 8104
- how: netstat -ano > \\\\evidence\\IR-2026-0414-01\\network\\wst-ws-031_netstat.txt
- where: network/wst-ws-031_netstat.txt
- hash cmd: sha256sum /evidence/IR-2026-0414-01/network/wst-ws-031_netstat.txt >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Captured in the same console session as Artifact 2, after Artifact 1. Must precede network isolation of WST-WS-031, because applying the isolation firewall rule closes the live C2 socket and this artifact exists precisely to prove that socket existed, with its PID, at capture time.
- verification: hash line present in hashes.txt

## Artifact 4. Network connections (structured), WST-WS-031

- what: CSV export of all TCP connections with LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess for cross-referencing against Artifacts 2 and 3
- how: powershell.exe -Command "Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | Export-Csv -NoTypeInformation \\\\evidence\\IR-2026-0414-01\\\\network\\\\wst-ws-031_tcpconn.csv"
- where: network/wst-ws-031_tcpconn.csv
- hash cmd: sha256sum /evidence/IR-2026-0414-01/network/wst-ws-031_tcpconn.csv >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Captured immediately after Artifact 3, same constraints: after memory (Artifact 1) and before network isolation, which terminates the sessions this CSV records. Sequenced with Artifacts 2-3 as a single read-only host-local batch with no interdependency.
- verification: hash line present in hashes.txt

## Artifact 5. Endpoint telemetry export, WST-WS-031, 24h pre-alert

- what: Wazuh EDR event stream for WST-WS-031, 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z, covering process creations, file creations, and network connections, source file edr_wst_ws_031_24h.jsonl
- how: cp $LAB_MATERIALS/5x01/edr_wst_ws_031_24h.jsonl /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl
- where: endpoint_telemetry/edr_wst_ws_031_24h.jsonl
- hash cmd: sha256sum /evidence/IR-2026-0414-01/endpoint_telemetry/edr_wst_ws_031_24h.jsonl >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: First SIEM-side artifact, taken only after the host-local volatile batch (Artifacts 1-4) completes, because it is not volatile-sensitive and the volatile batch must not be delayed. Its urgency driver is index retention and rollover: containment generates a flood of EDR events that pushes the 24h pre-alert window out of the hot tier.
- verification: hash line present in hashes.txt

## Artifact 6. SIEM alert record, A-20260414-9841

- what: Full JSON alert record for rule wz-edr-100041, alert A-20260414-9841, including process tree, network connection, threat-intel enrichment, and SIEM context
- how: cp $LAB_MATERIALS/5x01/alert_A-20260414-9841.json /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json
- where: siem/alert_A-20260414-9841.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/siem/alert_A-20260414-9841.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Captured with Artifact 5 as the second SIEM-side pull. Must be captured before any SOC queue action, specifically before assigning the alert (it currently shows analyst_assigned: null), annotating, or overriding severity, because any of those mutations would leave a manifest whose content differs from the record as it existed at declaration time.
- verification: hash line present in hashes.txt

## Artifact 7. Proxy log, dmarsh, 24h pre-alert

- what: HTTP/HTTPS transaction log for MEDDEFENSE\dmarsh, 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z, source file proxy_24h_dmarsh.log, containing the 18:14:02Z-18:14:43Z phishing sequence on ms0365-support[.]login-verification[.]click and the 02:46:44Z-02:47:08Z CONNECT series to 185.220.101[.]47
- how: cp $LAB_MATERIALS/5x01/proxy_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log
- where: proxy_dns/proxy_24h_dmarsh.log
- hash cmd: sha256sum /evidence/IR-2026-0414-01/proxy_dns/proxy_24h_dmarsh.log >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Third batch, after the SIEM pulls. The window is a 24h rolling export; the 18:14Z initial-access entries, which anchor the phishing attribution for the entire incident, age out of the window within hours of wall-clock time regardless of any containment action. Delay, not intervention, is what destroys this artifact.
- verification: hash line present in hashes.txt

## Artifact 8. DNS log, dmarsh / WST-WS-031, 24h pre-alert

- what: DNS query log for client 10.42.118[.]31 and user MEDDEFENSE\dmarsh, 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z, capturing resolution events for ms0365-support[.]login-verification[.]click and related lookups, exported from the recursive resolver to source file dns_24h_dmarsh.log
- how: cp $LAB_MATERIALS/5x01/dns_24h_dmarsh.log /evidence/IR-2026-0414-01/proxy_dns/dns_24h_dmarsh.log
- where: proxy_dns/dns_24h_dmarsh.log
- hash cmd: sha256sum /evidence/IR-2026-0414-01/proxy_dns/dns_24h_dmarsh.log >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Captured in the same batch as Artifact 7, immediately after it. DNS logs share the same rolling-retention decay as proxy logs, and the DNS record for the phishing domain is the corroborating evidence that ties the domain in Artifact 7 to an actual resolution from WST-WS-031. Isolating the host stops new queries but does not recover entries already rotated out.
- verification: hash line present in hashes.txt

## Artifact 9. Authentication events, dmarsh, 24h pre-alert

- what: Combined AD (ms-dc01, ms-dc02) and Azure AD authentication export for MEDDEFENSE\dmarsh, 2026-04-13T02:47:00Z to 2026-04-14T02:47:00Z, source file auth_24h_dmarsh.json, covering session 0x1c8a4f, the 18:14:41Z Azure AD impossibleTravel sign-in, and the 02:44:02Z unusual-hour logon (session 0x3a71c2)
- how: cp $LAB_MATERIALS/5x01/auth_24h_dmarsh.json /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json
- where: authentication/auth_24h_dmarsh.json
- hash cmd: sha256sum /evidence/IR-2026-0414-01/authentication/auth_24h_dmarsh.json >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: Captured last of the log-store batch and before any credential action on dmarsh. This artifact is the trigger gate for credential rotation: rotating or disabling dmarsh creates new auth events, collapses the Azure AD risk signals for the compromised session, and means the scoping analysis of the 02:44:02Z logon would run against a mutated dataset instead of the frozen window ending 02:47:00Z.
- verification: hash line present in hashes.txt

## Artifact 10. Temp directory inventory, WST-WS-031

- what: Recursive CSV inventory of C:\Users\dmarsh\AppData\Local\Temp with FullName, Length, CreationTime, LastWriteTime, LastAccessTime for every file present at capture time
- how: powershell.exe -Command "Get-ChildItem -Recurse -File C:\Users\dmarsh\AppData\Local\Temp | Select-Object FullName,Length,CreationTime,LastWriteTime,LastAccessTime | Export-Csv -NoTypeInformation \\\\evidence\\IR-2026-0414-01\\\\disk\\\\wst-ws-031_temp_inventory.csv"
- where: disk/wst-ws-031_temp_inventory.csv
- hash cmd: sha256sum /evidence/IR-2026-0414-01/disk/wst-ws-031_temp_inventory.csv >> /evidence/IR-2026-0414-01/hashes.txt
- ordering: First host-local disk capture, taken after the volatile batch (Artifacts 1-4) and before file collection (Artifacts 11-12), because the copy operations of Artifacts 11-12 update LastAccessTime metadata and would falsify this inventory. Recorded before attacker cleanup or EDR quarantine can delete files.
- verification: hash line present in hashes.txt

## Artifact 11. Dropped payload update.xml, WST-WS-031

- what: The MSBuild project file executed by MSBuild.exe (PID 8104) per alert A-20260414-9841, source path C:\Users\dmarsh\AppData\Local\Temp\update.xml
- how: copy C:\Users\dmarsh\AppData\Local\Temp\update.xml \\\\evidence\\IR-2026-0414-01\\disk\\update.xml
- where: disk/update.xml
- hash cmd: sha256sum /evidence/IR-2026-0414-01/disk/update.xml >> /evidence/IR-2026-0414-01/hashes.txt
- cross-check: certutil -hashfile C:\Users\dmarsh\AppData\Local\Temp\update.xml SHA256 computed on the host before copying; the value must equal the evidence-store hash, proving transfer integrity
- ordering: Captured immediately after the inventory (Artifact 10) and before any containment. This file is the primary malicious-logic sample for the incident, and it is the first target of attacker cleanup: the running MSBuild.exe process can delete it, and EDR quarantine or a later rebuild removes it permanently. Killing PID 8104 or isolating the host before this copy forfeits the payload.
- verification: hash line present in hashes.txt

## Artifact 12. Dropped payload update.exe, WST-WS-031

- what: The executable stage delivered by update[.]zip (downloaded 2026-04-13T18:14:43Z per proxy_24h_dmarsh.log), expected at C:\Users\dmarsh\AppData\Local\Temp\update.exe; capture is attempted unconditionally as part of the runbook
- how: copy C:\Users\dmarsh\AppData\Local\Temp\update.exe \\\\evidence\\IR-2026-0414-01\\disk\\update.exe
- where: disk/update.exe
- hash cmd: sha256sum /evidence/IR-2026-0414-01/disk/update.exe >> /evidence/IR-2026-0414-01/hashes.txt
- absence handling: if update.exe is not present at the source path, the copy fails, the failed attempt is appended to incident_timeline.md as an OBSERVATION entry (actor=Steve, source=wst-ws-031_temp_inventory.csv, certainty=confirmed, description=update.exe absent at capture time), and the absence is cross-checked against the Artifact 10 inventory. Absence is a finding, not an omission from the runbook
- ordering: Final host-local capture, executed immediately after Artifact 11 in the same session. Same destruction profile as update.xml: attacker cleanup, EDR quarantine, or a rebuild destroy it, so it is copied before any containment or eradication step runs.
- verification: hash line present in hashes.txt, or documented absence OBSERVATION in incident_timeline.md

## Step 13. Verification of the complete evidence store

- Re-hash every artifact in the manifest and compare against the recorded capture-time values: while read -r expected relpath; do actual=$(sha256sum "/evidence/IR-2026-0414-01/$relpath" | awk '{print $1}'); [[ "$expected" == "$actual" ]] && echo "MATCH $relpath" || echo "MISMATCH $relpath expected=$expected actual=$actual"; done < /evidence/IR-2026-0414-01/hashes.txt
- Every MISMATCH is appended to incident_timeline.md as an OBSERVATION entry with source=evidence_verification, certainty=confirmed, and halts reliance on the affected artifact pending re-acquisition
- On full match, append the closing line to hashes.txt: # Verified: YYYY-MM-DDTHH:MM:SSZ by Steve

## Execution Order Summary

| Order | Artifact | Destruction driver if late |
|---|---|---|
| 1 | 1, memory | reboot, power-off, process termination |
| 2 | 2, process list | kill, quarantine, isolation |
| 3 | 3, netstat | isolation closes sockets |
| 4 | 4, TCP CSV | isolation closes sockets |
| 5 | 5, EDR telemetry | index retention, containment event flood |
| 6 | 6, SIEM alert | queue assignment mutates record |
| 7 | 7, proxy log | 24h rolling window expiry |
| 8 | 8, DNS log | rolling retention expiry |
| 9 | 9, auth export | credential reset mutates dataset |
| 10 | 10, Temp inventory | copy operations alter timestamps |
| 11 | 11, update.xml | attacker cleanup, quarantine, rebuild |
| 12 | 12, update.exe | attacker cleanup, quarantine, rebuild |
| 13 | 13, verification | n/a, terminal step |

No containment action executes until Artifacts 1 through 12 are captured and hashed.
