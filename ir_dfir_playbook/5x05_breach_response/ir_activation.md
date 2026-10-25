# IR Activation: IR-2026-0420-01

- incident_id: IR-2026-0420-01
- declared_at: 2026-04-20T19:52Z
- declared_by: Steve Reilly, on-call IR
- initial_severity: SEV1

## Reasoning

At the moment of declaration, the observable facts supporting SEV1 are:

1. **Suspected ransomware in progress.** The on-call nurse at Main reported that
   CS-WS-101 is "crawling" and that files on her desktop "look different," with
   some filenames changed (Torres call transcript, 19:43:22Z). Simultaneously,
   SCHED-SVR-01 has been hammering its disk with CPU pinned and disk queue
   "through the roof" for approximately 90 minutes (19:43:50Z) — a classic
   mass-file-access/encryption-staging signature. Both symptoms together
   indicate probable ransomware preparation, not routine failure.
2. **Confirmed unauthorized persistence across multiple clinical hosts.** SIEM
   rule `wz-edr-200214` fired a service installation alert on three previously
   clean clinical workstations — CS-WS-104, CS-WS-107, CS-WS-112 — within the
   same twelve-minute window this afternoon (19:44:20Z). The installed service
   `WinHealthSvc` runs from `C:\ProgramData\Microsoft\svchost32.exe`, which is
   neither a Microsoft-signed path nor a Microsoft convention (Torres, 19:44:48Z).
   Three-host scope at declaration means this is an intrusion, not a single
   endpoint event.
3. **Clinical operations impact.** Affected systems are ED charge-desk and
   clinical workstations at Main. Patient care delivery is directly in the blast
   radius. Under the organizational severity matrix, any incident with confirmed
   or probable impact to clinical systems qualifies as SEV1 regardless of
   additional criteria.
4. **Aggregation.** Multi-host compromise + suspected ransomware + clinical
   impact + unknown dwell time triggers the highest-severity classification
   under the matrix. Severity will be re-evaluated as scoping evidence arrives;
   it is easier to downgrade than to recover lost containment time.

No further severity factor was assumed beyond what is stated above; suspected
PHI exposure has not yet been confirmed at declaration and does not form part
of this initial reasoning. It will be validated during investigation.

## Playbook Activated

**Ransomware / Multi-Host Intrusion Breach Response — 5x01 Contain & Control**,
with 5x02 Evidence Trail procedures attached for acquisition handling and
5x03 Post-Incident Review reserved for closure.

Why: observed indicators (multi-host suspicious service installation with a
non-Microsoft binary path, degraded host performance, altered filenames, disk
saturation on a server) match the ransomware-precondition branch of the
containment decision tree. 5x01 mandates immediate isolation of affected hosts
ahead of eradication, which is the required tempo given the patient-care
context. Evidence handling (memory capture already taken at 19:38Z, disk image
available) routes through 5x02 chain-of-custody requirements.

## Notifications (first 15 minutes)

- 19:52Z: **Mike Torres, Network Engineer** — already on the bridge; confirmed
  as evidence acquirer and engineering hands for isolation actions. Instructed
  to make no further changes to affected hosts without IR direction.
- 19:54Z: **James [Security Lead]** — paged per activation protocol; Torres had
  deliberately not called him ahead of the IR declaration (transcript, 19:45:12Z).
  Provided incident ID, SEV1 classification, and bridge number.
- 19:56Z: **SOC on-call line** — opened the incident bridge formally, logged the
  initial indicator set (rule `wz-edr-200214`, service `WinHealthSvc`,
  image path `C:\ProgramData\Microsoft\svchost32.exe`, hosts CS-WS-101/104/107/112,
  SCHED-SVR-01, FILE-SVR-01 pending scope) into the tracking system.

## First Communication

Executive status update sent to Dr. Morales at 20:05Z, per the 5x00
communication template (executive audience, plain language, no technical
jargon, next-update commitment):

> "Dr. Morales — At approximately 19:43 this evening we identified an active
> cybersecurity incident affecting several clinical workstations at the Main
> site, including the ED charge desk. Based on the evidence available, we
> believe an unauthorized party has been inside our systems for a period of
> days and may be preparing a ransomware attack. We have declared this a
> Severity 1 incident, the highest level, and have activated our full incident
> response process. Our immediate priorities are to prevent any disruption to
> patient care and to preserve the evidence needed to understand exactly what
> happened, including whether any patient information was involved. Clinical
> leadership should expect possible workstation outages at the Main ED tonight
> as we deliberately take affected machines offline; downtime procedures should
> be on standby. We have the situation contained within our response team,
> and I will provide you with a full status update, including any confirmed
> patient-data impact, no later than 06:00 tomorrow ahead of the board briefing.
> If anything material changes before then, you will hear from me immediately."

## Evidence Basis

All statements above derive from:
- `torres_call_transcript.md` (call at 2026-04-20T19:43:18Z, signed off by Torres 21:10Z)
- SIEM alert `wz-edr-200214` as reported in that transcript
- User report from on-call nurse, Main ED, relayed via Torres

No conclusions beyond these sources are asserted at declaration.
