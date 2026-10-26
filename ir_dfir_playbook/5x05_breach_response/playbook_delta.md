# Playbook Delta: Credential Exposure Playbook

- author: Steve - Cybersecurity Engineer
- date: 2026-10-26
- source incident: IR-2026-0420-01
- scope: two changes only, both to the Credential Exposure Playbook

## DELTA-01

**Section changed:** Section 3 — Trigger Conditions / Activation Criteria

**Before (abbreviated):**
> Activate credential exposure procedures once the compromised account has
> been confirmed through host scoping and account review, and revoke
> credentials as part of the containment phase.

**After:**
> Activate immediately, in parallel with scoping and never gated by it, on any
> one of the following trigger conditions:
>
> (a) Sysmon Event ID 10 where `TargetImage` ends with `\lsass.exe` and
> `GrantedAccess` contains `0x1010` or `0x1410`;
> (b) any Event ID 4624 with `logon_type` 3 originating from a host that has a
> confirmed beacon or a confirmed malicious service installation;
> (c) any Event ID 4624 paired with Event ID 4663 where the subject user holds
> no role-based entitlement to the accessed share, per the role-to-ACL
> mapping;
> (d) any Event ID 4672 (special privileges assigned) for a non-administrative
> service account.
>
> Revocation SLA: 30 minutes from trigger to password reset and termination of
> every active session for that principal. Scoping continues concurrently and
> is recorded as a separate workstream. Scope determination must enumerate
> distinct `subject_user` values from process creation and logon events on all
> in-scope hosts rather than relying on HR or role records, because a
> compromised credential will appear against shares the account holder has no
> business reason to touch.

**Justification:** SYS-001 records svchost32.exe opening lsass.exe with
`granted_access: 0x1010` at 2026-04-17T14:25:02Z, and MEM-005 confirms hash
material was resident and recoverable. The first lateral movement did not
occur until 2026-04-19T00:03:44Z — roughly 34 hours later. Under the previous
wording, revocation waited on scoping; under the new trigger, condition (a)
fires at the moment of the LSASS access and closes that window. Condition (c)
exists because FS-002 shows the intruder authenticating as a scheduling
coordinator against clinical shares, a pattern that role-based scoping alone
would not have surfaced.

## DELTA-02

**Section changed:** Section 7 — Recovery Gate / Case Closure Criteria

**Before (abbreviated):**
> Close the credential exposure case once the compromised account password has
> been reset and the affected hosts have been rebuilt.

**After:**
> The case cannot advance to Post-Incident Review until all five conditions
> are evidenced in the incident timeline:
>
> (a) compromised principal password reset and every active session for that
> principal terminated;
> (b) krbtgt account rotated twice, with the second rotation occurring no
> sooner than 10 hours after the first (equal to the maximum Kerberos ticket
> lifetime). This rotation is MANDATORY whenever any in-scope host shows LSASS
> access with `0x1010` or `0x1410`, regardless of whether a golden ticket has
> been observed;
> (c) validation query returning zero successful type-3 logons for the retired
> principal after the reset timestamp;
> (d) local administrator credentials rotated on every in-scope host,
> including hosts where no beacon was observed;
> (e) evidence that no Event ID 4768 or 4769 ticket request was issued to the
> retired principal after the second krbtgt rotation.
>
> Decision node: if condition (b) cannot be completed within the incident
> window, the case moves to Post-Incident Review with an explicit open action
> and a named owner, not as a closed case.

**Justification:** containment_execution.md STEP-08b performed a first krbtgt
rotation at 2026-04-20T22:10Z with the second deferred, which was sound but
improvised rather than prescribed. MEM-005 establishes that hash material was
recoverable from memory, and FS-002 shows the intruder authenticating to the
file server with a Kerberos ticket for the compromised principal from the
patient-zero workstation — meaning ticket-granting material was in play, not
just the password. Making the double rotation and the post-reset validation
query mandatory closure conditions converts an ad hoc decision into a
repeatable gate.
