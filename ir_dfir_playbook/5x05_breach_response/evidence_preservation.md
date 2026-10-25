# Evidence Preservation: IR-2026-0420-01

- incident: IR-2026-0420-01
- prepared_by: Steve, on-call IR
- prepared_at: 2026-04-20T20:05Z
- evidence_acquirer (hands-on): Mike Torres, Network Engineer (on bridge, confirmed at
  declaration — transcript handoff notes)
- storage_root: \\evidence\share\IR-2026-0420-01\
- rule: No containment action (isolation, service kill, credential reset) is taken on
  any host before its scheduled acquisitions for that host complete, EXCEPT where the
  5x01 containment decision tree declares imminent-execution override. As of writing,
  ransomware staging scripts exist on WS-101/104/107/112 (Sysmon event_id 11,
  2026-04-20T14:23–14:26Z) but have NOT executed; monitor for trigger indicators
  (svchost32.exe spawning powershell/cmd children) and escalate to emergency
  isolation if observed.

## Operational context from the Torres call (torres_call_transcript.md)

- 19:38Z — Torres ran WinPmem on CS-WS-101 and produced cs-ws-101.mem. He did this
  BEFORE calling the on-call IR. Host was NOT isolated.
- 19:41Z — dump written to \\evidence\share\IR-2026-0420-01\cs-ws-101.mem.
- NO hash was computed at acquisition. Torres flagged this himself; repeat of the
  IR-2026-0414-01 chain-of-custody gap.
- On-call nurse instructed to stop touching CS-WS-101 and leave the console
  unattended — limits post-capture contamination of the live host, but does not
  stop the running svchost32.exe (PID 7318) from altering in-memory state.
- Torres remained on the bridge and continues as evidence acquirer for all
  additional captures. All remote acquisitions below are executed by Torres under
  IR direction and logged here.

## Priority order rationale

Priority is driven by volatility and destruction risk, in this order: (a) running
process/C2 state that network isolation or a service kill destroys instantly,
(b) disk state that ransomware execution destroys irreversibly, (c) log and audit
records that survive but must be collected before rotation or tampering.

| Prio | Host | Justification |
|------|------|---------------|
| 1 | WS-101 | Memory already volatile-captured (ART-001). Remaining risk: svchost32.exe (PID 7318) is live, beaconing as recently as 19:32:04Z (Sysmon event_id 3), and holds encryption_staging.ps1 on disk (dropped 14:23:18Z). Disk must be imaged before ANY containment action touches this host — isolation or service termination changes disk state (pagefile, USN journal, $MFT, prefetch). |
| 2 | WS-104 | Active C2 participant. Beacon established 00:04:12Z 2026-04-19 (Sysmon event_id 3 to 45.152.66.114:443); malicious service created via cmd.exe child of services.exe (00:03:44Z); staging script dropped 14:25:02Z 2026-04-20. Memory MUST be captured before network isolation removes C2 telemetry and session/key material. |
| 3 | WS-107 | Same profile as WS-104: beacon at 00:12:44Z 2026-04-19, staging script dropped 14:25:42Z 2026-04-20. Ordered immediately behind WS-104 so both active-beacon hosts are volatile-captured before any isolation begins. |
| 4 | FILE-SVR-01 | No beaconing since 02:41:09Z 2026-04-19 (last proxy CONNECT) — C2 process may be dormant, so volatility risk is lower than WS-104/107. However it holds the entire PHI access record (1,847 Event 4663 rows, 02:14:01–02:41:12Z window) AND showed a 2.4 MB egress at 02:14:22Z. Disk image is time-critical for the breach assessment and must precede any rebuild or cleanup. Memory capture included opportunistically ahead of disk. |
| 5 | WS-112 | Lateral-movement host: service beacon event at 00:18:02Z 2026-04-19 and staging drop at 14:26:14Z, but no subsequent beacon or observed activity in the dwell window. Lowest volatility risk; captured last so hands stay on the higher-risk hosts. |

Sequencing note: WS-101 disk (P1) and WS-104/107 memory (P2/P3) can run in PARALLEL
if two operators are available; with Torres alone, execute strictly in the order
above. WS-112 is never allowed to delay the other four.

SCOPE FLAG (for the timeline): SCHED-SVR-01 shows svchost32.exe spawned by
services.exe at 2026-04-20T18:02:18Z (Sysmon) and Torres reported disk saturation
for ~90 minutes pre-call. SCHED-SVR-01 is NOT in the five-host scope of this
document
