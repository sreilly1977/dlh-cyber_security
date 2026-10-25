# Containment Decision: IR-2026-0420-01

- decision_by: Steve, on-call IR (proposed) 
- authorized_by: James, Security Lead / Incident Commander
- clinical downtime authority: Dr. Morales (Executive)
- decided_at: 2026-04-20T20:20Z
- scope: CS-WS-101, CS-WS-104, CS-WS-107, CS-WS-112, FILE-SVR-01
- watch item: SCHED-SVR-01 (malicious svchost32.exe PID 5920 running, spawned 18:02:18Z;
  held under the same isolation sequence and escalated to in-scope)

## Situation (basis for decision)

Four workstations run an active Cobalt Strike beacon to 45.152.66.114:443
(staging.office365-cdn.net), cycle ~60 s sleep with 10% jitter (proxy_72h). NTLM
credential material was extracted (LSASS handle 0x1010 on WS-101, 2026-04-17T14:25:02Z,
Sysmon EID 10) and reused for lateral movement as MEDDEFENSE\jdoe. Ransomware staging
scripts (encryption_staging.ps1) sit on WS-101/104/107/112, dropped 14:23–14:26Z on
2026-04-20, NOT yet executed. 1,847 patient files were read on FILE-SVR-01 and a
2.4 MB egress occurred (02:14:22Z, 2026-04-19). The site is operational with the
ED charge desk affected.

## Options considered

| # | Strategy | Attacker effect | Patient care effect | Evidence effect | Time | Reversible |
|---|----------|-----------------|--------------------|-----------------|------|------------|
| A | Immediate full isolation of all five hosts NOW (switch-port shutdown) | Kills all C2 instantly; denies lateral movement | Immediate loss of ED charge-desk station, three clinical workstations, and the clinical documentation file server; paper downtime required | Destroys live C2 session state and beacon config in memory of WS-104/107/112 before capture (only WS-101 memory exists); disk evidence retained | Minutes | Yes (ports re-enabled), but clinical trust cost is high |
| B | Perimeter egress block only (deny staging.office365-cdn.net / 45.152.66.114), hosts stay online | Severs C2; attacker may detect the block and detonate staged ransomware manually or pivot to a backup channel | Zero downtime initially; but compromised hosts remain in production, so patient-facing risk persists | Preserves memory on all hosts (best telemetry); block itself is visible to the operator if they probe | Minutes | Trivially reversible |
| C | Staged isolation: per-host memory capture, then immediate network isolation, executed in evidence-priority order (WS-101 → WS-104 → WS-107 → FILE-SVR-01 → WS-112), followed by the perimeter egress block and credential revocation | Same end state as A; attacker retains C2 slightly longer (~1 hour) during volatile capture | Staged downtime: ED charge desk lost first (~21:10Z), file server later; clinical ops prepared in advance | Maximum: all memory captured with live beacon state before isolation; disk state unchanged by containment | ~60–75 min | Yes, ports re-enableable; credential resets only via password change |

## Declared strategy: C (staged isolation with evidence-first ordering)

We accept roughly one additional hour of known C2 exposure (supervised by the beacon-integrity
monitor: no new connections other than the established 60 s cycle, no process spawns from
svchost32.exe, no new file drops) in exchange for capturing volatile evidence on the four
workstations before isolation destroys it, because this compromise ends in either prosecution
or a regulatory filing, and both hinge on the beacon configuration, session keys, and process
state only memory holds. The clinical stakes cut the same way: the ED charge desk workstation
goes down first, which is painful but survivable with downtime procedures, whereas losing the
forensic record or allowing a later dispute over what the attacker did on FILE-SVR-01 would
outlast the incident by years. Strategy A was rejected because it permanently forfeits memory
evidence on three hosts; Strategy B alone was rejected because it leaves four compromised
clinical workstations in production with staged ransomware on disk and only assumes the
operator will not react to a dead C2 channel. Emergency override: any indication of
encryption activity, svchost32.exe spawning cmd/powershell, or mass file I/O triggers
immediate full isolation (Strategy A) on the affected host without further authorization.

- rollback_trigger: Beacon-integrity monitor observes ANY of: (a) encrypted/renamed files,
  (b) svchost32.exe child processes, (c) C2 destination change or outbound spike on any
  in-scope host, (d) new service installations (wz-edr-200214 recurrences).
- rollback_action: Immediate switch-port shutdown on affected host(s); escalate to Strategy A
  fleet-wide if more than one host trips.
