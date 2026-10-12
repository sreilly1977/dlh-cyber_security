# Containment Decision: IR-2026-0414-01

## Candidate strategies

### A. Network isolation (quarantine VLAN)

- action: move WST-WS-031 to VLAN 999; block all outbound traffic including 185.220.101[.]47:443; allow inbound forensic access from the IR jumpbox only
- attacker effect: C2 channel to 185.220.101[.]47 severed immediately; attacker loses interactive visibility; powershell.exe (PID 7812) and MSBuild.exe (PID 8104) remain alive but blind; no alerting to the attacker beyond connection loss
- evidence effect: volatile state fully preserved; memory-resident processes, open sockets, and Temp artifacts remain intact for post-containment acquisition; EDR continues to report host-local attacker behavior (persistence attempts, cleanup actions) from inside the quarantine
- patient care effect: one clinical workstation unavailable for laboratory use; WST-WS-031 has LIS access, so technician workflow shifts to other lab workstations; no direct effect on active patient treatment systems (LIS and Epic servers unaffected)
- time to execute: ~5 min (switch port reassignment or NAC policy push)
- reversibility: fully reversible (restore original VLAN assignment)

### B. Host power-off

- action: immediate shutdown or power removal on WST-WS-031
- attacker effect: C2 severed immediately; all attacker-controlled processes dead
- evidence effect: destructive. Volatile memory is lost: Kerberos ticket material in LSA, decrypted payload stages, injected threads in PID 7812/8104, and the live socket state are unrecoverable. The post-alert behavior window closes; the incident record reduces to what EDR already shipped. update.xml and update.exe on disk survive, but Temp files may be corrupted by improper shutdown and attacker anti-forensic triggers on power events cannot be ruled out
- patient care effect: identical clinical footprint to Option A (workstation unavailable), but recovery is slower: the host must be validated clean or rebuilt before it returns to service, extending the outage from hours to a business day or more
- time to execute: <1 min
- reversibility: irreversible with respect to volatile state; host recovers only after forensic validation or reimaging

### C. Selective process termination plus egress block

- action: kill MSBuild.exe (PID 8104) and powershell.exe (PID 7812); apply a host firewall rule blocking 185.220.101[.]47:443 (and Tor-range egress); leave the host otherwise on the production VLAN
- attacker effect: known C2 processes dead; the specific destination blocked. However, the alert shows only what was detected: an unobserved spawner, a scheduled-task re-arm, or an alternate C2 channel would survive, and the attack chain began with a credential compromise (Azure AD sign-in flagged impossibleTravel at 18:14:41Z), so a foothold outside this host may persist regardless
- evidence effect: partial loss. Killing PID 8104 destroys its memory-resident state; post-mortem drops back to EDR telemetry and disk artifacts. Egress filtering alone does not perturb the host, but the process kills do
- patient care effect: minimal in the near term; workstation remains in service for the lab while the investigation continues. Residual attacker presence is an unquantified clinical risk the lab inherits
- time to execute: ~10 min (PID verification, kill, firewall rule deployment, verification of block)
- reversibility: firewall rule trivially reversible; terminated processes cannot be revived; if the kill was wrong, legitimate lab software is not restartable from its pre-kill state

## Chosen: A

Rationale: Option A severs the C2 channel to 185.220.101[.]47 as fast as B while preserving the volatile evidence that B destroys, keeping the full memory, socket, and Temp state of the PowerShell-to-MSBuild chain available for forensics, which is only half acquired at decision time. It bounds clinical impact the same way B does (one workstation out of lab rotation) without B's irreversible evidence loss. It is preferred over C because C gambles that PIDs 7812 and 8104 are the complete attacker footprint: the alert is a single detection with three correlated events, the credential compromise path (phishing at 18:14Z, impossibleTravel sign-in) indicates the adversary had hours to establish persistence or secondary channels, and killing the processes eliminates the ability to observe attacker behavior after the fact. C leaves a high-criticality, LIS-connected clinical workstation on the production VLAN with residual risk. A accepts a slightly longer execution (~5 min) than B, and a slower one than C, in exchange for reversibility, evidence preservation, and continued host-local observability, and it does not depend on guessing the attacker's full process inventory.

## Execution window

- Evidence preservation end (Task 2, all artifacts 1-13 captured and hashed, verification step 14 passed): 2026-04-14T03:14Z
- Containment execution start: 2026-04-14T03:16Z
- Window: 2 minutes, governed by the need to hold the host untouched between hashing completion and VLAN reassignment; no containment action ran concurrently with preservation

## Approval

- Action authorized by James Chen, IR Commander, at 03:10Z via incident channel, condition: complete evidence preservation first
- Executing analyst: Steve, on-call SOC

## Rollback plan

- Trigger conditions for rollback: laboratory operations blocked and no alternative workstation available for LIS access, or the VLAN move causes collateral disruption beyond WST-WS-031 (mis-scoped port or NAC rule)
- Immediate step: revert WST-WS-031 to its production VLAN assignment, target time under 5 minutes (the VLAN change is a switchport/NAC configuration, no host state touched)
- Fallback: if rollback is required for clinical reasons, apply Option C (firewall egress block for 185.220.101[.]47 plus process termination) as the degraded containment, accepting the evidence and coverage trade-offs documented above; re-run the Task 2 disk and memory acquisitions before killing processes if the rollback follows a significant interval
- Constraint: rollback restores the C2 path. If WST-WS-031 is returned to the production VLAN, egress blocking of 185.220.101[.]47 at the perimeter is applied first so the attacker channel stays severed during any clinical reprieve

---

## Timeline entry to append to incident_timeline.md

- 2026-04-14T03:16Z | DECISION | Steve | Containment strategy A selected and executed: WST-WS-031 moved to quarantine VLAN 999, all outbound blocked, IR jumpbox access only; C2 to 185.220.101[.]47 severed; approved by James Chen (IR Commander) at 03:10Z on condition evidence preservation completed first; trade-offs documented in containment_decision.md | source=containment_decision.md | certainty=confirmed
