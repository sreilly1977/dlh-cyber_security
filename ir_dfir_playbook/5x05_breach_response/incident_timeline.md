# Incident Timeline — IR-2026-0420-01

Append-only. Entries are never edited or deleted; corrections are made by
appending a new entry referencing the corrected entry ID. All times UTC.

Format: timestamp | type | actor | description | source | certainty

| # | Timestamp | Type | Actor | Description | Source | Certainty |
|---|-----------|------|-------|-------------|--------|-----------|
| 1 | 2026-04-20T19:43:22Z | OBSERVATION | On-call nurse, Main ED (via Torres) | User report: CS-WS-101 "crawling," files on desktop "look different," some filenames changed. Workstation is the clinical coordinator station at the ED charge desk. Nurse had paged Torres directly after failing to reach SOC line. | torres_call_transcript.md, 19:43:22Z | HIGH — direct user report relayed in real time; filename changes not yet verified by staff login |
| 2 | 2026-04-20T19:44:20Z | OBSERVATION | Mike Torres, Network Engineer | SIEM service-installation alert (rule wz-edr-200214) fired on three clinical workstations at Main — CS-WS-104, CS-WS-107, CS-WS-112 — within the same twelve-minute window that afternoon. Service name WinHealthSvc, image path C:\ProgramData\Microsoft\svchost32.exe (not a Microsoft path or naming convention). Concurrently, SCHED-SVR-01 exhibiting pinned CPU and extreme disk queue for ~90 minutes. Also noted: memory capture of CS-WS-101 taken at 19:38Z with WinPmem, host not isolated. | torres_call_transcript.md, 19:43:50Z–19:44:48Z | HIGH — SIEM alert and Torres observations directly reported; SCHED-SVR-01 cause not yet diagnosed |
| 3 | 2026-04-20T19:52Z | DECISION | Steve, on-call IR | Incident IR-2026-0420-01 declared SEV1. Reasoning: suspected ransomware in progress (user-reported filename changes + disk saturation on SCHED-SVR-01), confirmed unauthorized multi-host persistence on three clinical workstations, direct patient-care impact potential. 5x01 Contain & Control playbook activated with 5x02 evidence-handling procedures. Torres confirmed on bridge as evidence acquirer; James paged 19:54Z; SOC bridge opened 19:56Z. Pre-existing memory capture cs-ws-101.mem (19:38Z, no hash computed at acquisition — known gap, flagged by Torres) acknowledged as evidence item. | ir_activation.md; torres_call_transcript.md handoff notes 19:52Z | HIGH — declaration is a matter of record |
| 4 | 2026-04-20T21:00Z | ACTION | Steve | Pre-execution gate: verified all acquisitions (ART-001–ART-010) complete and hash-verified in evidence_preservation.md before first containment action | evidence_preservation.md chain-of-custody table | HIGH |
| 5 | 2026-04-20T21:05Z | ACTION | Torres | CS-WS-101 (10.30.12.101) network-quarantined via switch-port ACL; host left powered on | containment_execution.md STEP-01 | HIGH |
| 6 | 2026-04-20T21:12Z | ACTION | Torres | CS-WS-104 (10.30.12.104) network-quarantined; loaner workstation deployed | containment_execution.md STEP-02 | HIGH |
| 7 | 2026-04-20T21:19Z | ACTION | Torres | CS-WS-107 (10.30.12.107) network-quarantined | containment_execution.md STEP-03 | HIGH |
| 8 | 2026-04-20T21:26Z | ACTION | Torres | CS-WS-112 (10.30.12.112) network-quarantined | containment_execution.md STEP-04 | HIGH |
| 9 | 2026-04-20T21:35Z | ACTION | Torres | FILE-SVR-01 (10.30.10.20) network-quarantined to management VLAN only; clinical downtime procedures activated. 4-min deviation for charge-nurse notification accepted by IC | containment_execution.md STEP-05 | HIGH |
| 10 | 2026-04-20T21:45Z | ACTION | Torres | SCHED-SVR-01 network-quarantined (watch-item escalation, svchost32.exe PID 5920 active since 18:02:18Z) | containment_execution.md STEP-06 | HIGH |
| 11 | 2026-04-20T21:50Z | ACTION | Torres | Perimeter firewall deny+alert rule applied: staging.office365-cdn.net and 45.152.66.114 TCP/443 bidirectional, both interfaces | containment_execution.md STEP-07 | HIGH |
| 12 | 2026-04-20T22:00Z | ACTION | Steve | Credential revocation: jdoe password reset, all sessions/logon IDs (incl. 0xAF12C4B8) terminated | containment_execution.md STEP-08a | HIGH |
| 13 | 2026-04-20T22:10Z | ACTION | Steve | krbtgt password rotated (rotation 1 of 2) | containment_execution.md STEP-08b | HIGH |
| 14 | 2026-04-20T22:20Z | ACTION | Steve | Credential scope closed: jdoe confirmed sole compromised user principal in dwell-window evidence; local admin rotations performed as precaution | containment_execution.md STEP-08c | HIGH |
| 15 | 2026-04-20T23:30Z | OBSERVATION | Steve | C2 severance proven: zero successful connections to C2 infrastructure post-block across 60-min observation; firewall deny counter incrementing on attempted beacons; no new EID 3 external connections; no new wz-edr-200214 alerts | containment_execution.md STEP-09 | HIGH |
