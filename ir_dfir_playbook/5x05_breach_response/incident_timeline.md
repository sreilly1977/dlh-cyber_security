# Incident Timeline — IR-2026-0420-01

Append-only. Entries are never edited or deleted; corrections are made by
appending a new entry referencing the corrected entry ID. All times UTC.

Format: timestamp | type | actor | description | source | certainty

| # | Timestamp | Type | Actor | Description | Source | Certainty |
|---|-----------|------|-------|-------------|--------|-----------|
| 1 | 2026-04-20T19:43:22Z | OBSERVATION | On-call nurse, Main ED (via Torres) | User report: CS-WS-101 "crawling," files on desktop "look different," some filenames changed. Workstation is the clinical coordinator station at the ED charge desk. Nurse had paged Torres directly after failing to reach SOC line. | torres_call_transcript.md, 19:43:22Z | HIGH — direct user report relayed in real time; filename changes not yet verified by staff login |
| 2 | 2026-04-20T19:44:20Z | OBSERVATION | Mike Torres, Network Engineer | SIEM service-installation alert (rule wz-edr-200214) fired on three clinical workstations at Main — CS-WS-104, CS-WS-107, CS-WS-112 — within the same twelve-minute window that afternoon. Service name WinHealthSvc, image path C:\ProgramData\Microsoft\svchost32.exe (not a Microsoft path or naming convention). Concurrently, SCHED-SVR-01 exhibiting pinned CPU and extreme disk queue for ~90 minutes. Also noted: memory capture of CS-WS-101 taken at 19:38Z with WinPmem, host not isolated. | torres_call_transcript.md, 19:43:50Z–19:44:48Z | HIGH — SIEM alert and Torres observations directly reported; SCHED-SVR-01 cause not yet diagnosed |
| 3 | 2026-04-20T19:52Z | DECISION | Steve Reilly, on-call IR | Incident IR-2026-0420-01 declared SEV1. Reasoning: suspected ransomware in progress (user-reported filename changes + disk saturation on SCHED-SVR-01), confirmed unauthorized multi-host persistence on three clinical workstations, direct patient-care impact potential. 5x01 Contain & Control playbook activated with 5x02 evidence-handling procedures. Torres confirmed on bridge as evidence acquirer; James paged 19:54Z; SOC bridge opened 19:56Z. Pre-existing memory capture cs-ws-101.mem (19:38Z, no hash computed at acquisition — known gap, flagged by Torres) acknowledged as evidence item. | ir_activation.md; torres_call_transcript.md handoff notes 19:52Z | HIGH — declaration is a matter of record |
