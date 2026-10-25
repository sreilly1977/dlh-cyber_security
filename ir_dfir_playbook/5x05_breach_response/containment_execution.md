# Containment Execution Record: IR-2026-0420-01

Append-only. Steps are executed by Mike Torres (hands-on, on bridge) under IR direction
by Steve. Observed outcomes recorded at execution; deviations logged inline, never
overwritten. Emergency override condition remains armed throughout (see
containment_decision.md, rollback_trigger).

## Pre-execution gate

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T21:00Z | Steve | Verified completion of all scheduled acquisitions in evidence_preservation.md (ART-001 through ART-010) against the chain-of-custody table | All five hosts have memory + disk captured and hashes verified | ✔ All acquisitions verified; hashes matched | None |

STEP-01 — Isolate CS-WS-101 (ED charge desk)

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-21T21:05Z* | Torres | Switch-port ACL quarantine on switch port for CS-WS-101 (10.30.12.101): deny all in/out, host left POWERED ON (memory + disk already imaged; power state preserved to avoid triggering staged payloads on shutdown hooks) | Host unreachable from network; no new connections to 45.152.66.114 from 10.30.12.101 | ✔ Port quarantined; ping/probe tests failed as expected; last known beacon was 19:32:04Z (Sysmon EID 3) | None |

STEP-02 — Isolate CS-WS-104

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T21:12Z* | Torres | Switch-port ACL quarantine on CS-WS-104 (10.30.12.104), same method as STEP-01 | Host unreachable; beacon from 10.30.12.104 ceases | ✔ Quarantined successfully | Clinical owner notified; workstation at ED nurses' station replaced with loaner from clean spare pool |

STEP-03 — Isolate CS-WS-107

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T21:19Z* | Torres | Switch-port ACL quarantine on CS-WS-107 (10.30.12.107) | Host unreachable; beacon from 10.30.12.107 ceases | ✔ Quarantined successfully | None |

STEP-04 — Isolate CS-WS-112

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T21:26Z* | Torres | Switch-port ACL quarantine on CS-WS-112 (10.30.12.112) | Host unreachable; beacon from 10.30.12.112 ceases | ✔ Quarantined successfully | Lowest-activity host isolated last per plan; no beacon observed since 00:18:02Z 2026-04-19 |

STEP-05 — Isolate FILE-SVR-01

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T21:35Z* | Torres | Switch-port ACL quarantine on FILE-SVR-01 (10.30.10.20), host left powered on; server reachable only to the IR jumpbox via a management VLAN exception | Clinical documentation share unavailable to clinicians; paper downtime procedures activate; no beacon (last C2 02:41:09Z 2026-04-19) | ✔ Server quarantined; clinical supervisor confirmed downtime forms in use at Main | DEVIATION: full isolation delayed 4 min to allow Torres to notify the charge nurse of the documentation outage. Deviation accepted by IC (James) — no security impact; no network egress from server during the delay |

STEP-06 — Watch item SCHED-SVR-01

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T21:45Z* | Torres | Switch-port ACL quarantine on SCHED-SVR-01 (per containment_decision.md watch item; svchost32.exe PID 5920 active since 18:02:18Z, disk saturation ongoing) | Server unreachable except management VLAN; disk saturation activity halts at next C2 poll attempt | ✔ Quarantined; escalation to in-scope host logged in timeline | Scheduling downtime absorbed by charge-desk downtime procedures already active |

STEP-07 — Firewall egress block (severs C2 domain-wide)

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T21:50Z* | Torres | Perimeter firewall deny + alert rule: destinations staging.office365-cdn.net (FQDN object) and 45.152.66.114 (IP object), TCP/443 both directions, log-on-match, applied inbound and outbound on all interfaces | Any future beacon attempt from any MedDefense host reaches firewall counter and alarm, not the C2; existing sessions dropped | ✔ Rules committed; firewall log shows SYN attempts from quarantined segment being denied (deny hits incrementing) | Domain/IP objects retained as tripwire — intentionally NOT blocked silently from monitoring perspective |

STEP-08 — Credential revocation sequence

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T22:00Z* | Steve (via Torres/IT) | Reset MEDDEFENSE\jdoe password; disable all active sessions (logon IDs from 4624 events, incl. 0xAF12C4B8); revoke Kerberos tickets by forced logoff where supported | Lateral movement via stolen jdoe NTLM hash fails; no new type-3 logons under jdoe | ✔ Password reset; sessions cleared | jdoe was the subject user on ALL lateral movement and file access events (fileserver_access.sample.json, sysmon_multihost.sample.jsonl) |
| 2026-04-20T22:10Z* | Steve (via Torres/IT) | Reset krbtgt account password ONCE (first of two mandatory rotations, second scheduled post-incident after TGT lifetime expiry) | Any Golden Ticket forged from dumped KRBTGT hash invalidated at next rotation boundary | ✔ First rotation complete | LSASS handle 0x1010 on WS-101 (14:25:02Z, 2026-04-17) presumes full credential access, so krbtgt rotation is precautionary standard practice |
| 2026-04-20T22:20Z* | Steve (via Torres/IT) | Enumerated all accounts with sessions on in-scope hosts during dwell (per Sysmon "user" field: only MEDDEFENSE\jdoe observed); no additional user accounts implicated in the evidence | Credential scope closes with jdoe + krbtgt | ✔ Confirmed jdoe sole compromised user principal; SYSTEM-context actions attributed to the malware itself | LOCAL administrator credentials on the five hosts also rotated as a precaution (out-of-band, standard) |

STEP-09 — Proof of C2 severance

| ts_utc | actor | action | expected_outcome | observed_outcome | deviation_notes |
|--------|-------|--------|------------------|------------------|-----------------|
| 2026-04-20T22:30Z | Steve | Collected proxy log tail + firewall deny counters covering 21:50–22:30Z; queried for ANY traffic to staging.office365-cdn.net or 45.152.66.114 from any host | Zero successful (status 200) CONNECTs to C2 post-block; only firewall deny hits | ✔ RESULT RECORDED BELOW | — |
| 2026-04-20T23:30Z | Steve | Extended observation window: re-ran the same query at T+60 min post-block; cross-checked Sysmon EID 3 events across all hosts | Still zero C2 connections; no new EID 3 to any external destination from in-scope hosts; no new service installs (wz-edr-200214) | ✔ Beacon confirmed severed | Continued monitoring cadence: hourly through 06:00Z board brief |

## Proof of C2 severance (consolidated)

1. Firewall deny counter for 45.152.66.114:443 increments (attempted beacons hitting the block) — count recorded: ______ (lab fill-in)
2. Proxy logs 21:50Z onward: zero status-200 CONNECT records to staging.office365-cdn.net — confirmed over 60-minute observation window
3. Sysmon EID 3 on all in-scope hosts: no outbound connections post-isolation timestamps
4. Last confirmed successful beacon remains 2026-04-20T19:32:04Z from CS-WS-101 (pre-containment, consistent with memory capture at 19:38Z)
5. No recurrence during sustained observation through 2026-04-20T23:30Z

## Integrity monitoring during execution

Emergency override condition monitored throughout at 5-minute intervals via SIEM watch:
zero svchost32.exe child processes, zero new wz-edr-200214 alerts, zero mass file-write
patterns observed on any in-scope host. Condition never tripped. Recorded here as
a standing check, entries logged only on deviation.

* Timestamps marked with * are executed-at values from the lab run; confirm and adjust
  to your actual execution log before submitting. All other values are evidence-derived.
