# MedDefense IAM Audit Report

**Classification:** Confidential
**Audit date:** 08 November 2026
**Prepared by:** Steve, Cybersecurity Engineer
**Reviewed by:** James Chen, SOC Lead
**Approved by:** _________________________ Date: _________

## Executive Summary

MedDefense's identity layer currently permits the same class of compromise
that enabled the prior Cobalt Strike intrusion to succeed. A full audit of
the privileged Active Directory account inventory (20 accounts, every
account holding any privileged group membership) produced 22 findings:
5 Critical, 9 High, 3 Medium and 5 Low. Six accounts, including four
privileged service accounts, currently hold standing Domain Admin
credentials that no business function justifies. Three privileged user
accounts lack MFA, and one account belonging to a contractor whose
engagement ended in September 2025 remains enabled with Domain Admin
rights. Identity controls, not perimeter controls, are the organization's
weakest layer.

The single most urgent finding is `svc_epic_int` (IAM-003, IAM-004): a
service account holding Domain Admins membership, dormant for 1,156 days,
described in its own inventory record as having "no current function
identified". Together with `svc_helpdesk` (IAM-005) and `svc_backup`
(IAM-002), this means three of the most powerful credentials in the
organization belong to automation accounts whose privilege exceeds their
documented function. If any of these credentials were exposed, an
attacker would hold full domain control, and because they are static
passwords with no rotation history, nothing about their exposure would be
detectable from the directory itself.

The findings recreate the exact lateral movement path of the prior
incident: a compromised endpoint yields a credential from memory, and that
credential belongs to a privileged service account that grants Domain
Admin. `svc_epic_int`, `svc_helpdesk`, `svc_backup`, `t.morrison`,
`admin.legacy` and `j.yamamoto` are not hypothetical risks; they are the
current-state equivalent of the account that was abused before. This audit
changes the situation in two ways: it gives the organization a complete,
evidence-backed answer to Dr. Morales's question of how many accounts hold
more access than they need, and it provides a prioritized, traceable
remediation path (Section: Remediation Roadmap) so the gap is closed
deliberately rather than discovered during the next incident.

## Audit Scope and Methodology

In scope: the full privileged account inventory exported from Active
Directory as `accounts.csv` (20 accounts), covering every user and service
account with membership in any privileged group, including Domain Admins,
Server Admins and Workstation Admins, plus adjacent offboarding-relevant
accounts surfaced by the export. For each account the audit evaluated:
enabled state, last authentication age, MFA enrollment, privileged group
membership, account type and free-text description.

Out of scope: non-privileged clinical user accounts, the AWS cloud IAM
posture (covered by the separate cloud security assessment and CIS AWS
review), application-level entitlements inside Epic and PACS, and network
or endpoint controls. Those domains require separate evidence collection.

Method: the inventory was processed by `audit_iam.py`, a version-controlled
Python script applying six named checks (`check_dormant_privileged`,
`check_mfa_coverage`, `check_service_account_overpriv`,
`check_departed_or_transferred`, `check_disabled_with_groups`,
`check_no_mfa_high_risk`) to every row. The same logic is applied to every
account, so the audit is reproducible and defensible. Raw output is
preserved in `iam_findings.json`; every finding in this report cites the
finding ID from that file, which in turn traces to one inventory row and
one named check. Severity was assigned per `severity_model.md`:
Critical for direct domain takeover, broad ePHI access, privileged
persistence or repeat of the prior incident path; High for strong attack
paths needing one additional condition; Medium for meaningful exposure or
detection weakness; Low for hygiene issues unlikely to independently
enable a major incident.

## Findings Summary Table

| Finding ID | Account | Category | Severity | Status |
|---|---|---|---|---|
| IAM-001 | t.morrison | Departed/contractor with privileged access | Critical | Open |
| IAM-002 | svc_backup | Service account over-privilege | Critical | Open |
| IAM-003 | svc_epic_int | Dormant privileged service account | Critical | Open |
| IAM-004 | svc_epic_int | Service account over-privilege | Critical | Open |
| IAM-005 | svc_helpdesk | Service account over-privilege | Critical | Open |
| IAM-006 | admin.legacy | Dormant privileged account | High | Open |
| IAM-007 | admin.legacy | Privileged account without MFA | High | Open |
| IAM-008 | admin.legacy | Stale lifecycle status on privileged account | High | Open |
| IAM-009 | t.morrison | Dormant privileged account | High | Open |
| IAM-010 | t.morrison | Privileged account without MFA | High | Open |
| IAM-011 | l.okafor | Departed employee account still enabled | High | Open |
| IAM-012 | j.yamamoto | Dormant privileged account | High | Open |
| IAM-013 | j.yamamoto | Privileged account without MFA | High | Open |
| IAM-014 | j.yamamoto | Transfer without rights removal | High | Open |
| IAM-015 | k.nguyen | No MFA with repeated security failures | Medium | Open |
| IAM-016 | b.carter | Disabled account retaining groups | Medium | Open |
| IAM-017 | svc_monitoring | Service account over-privilege | Medium | Open |
| IAM-018 | admin.legacy | Enabled user without MFA | Low | Open |
| IAM-019 | t.morrison | Enabled user without MFA | Low | Open |
| IAM-020 | l.okafor | Enabled user without MFA | Low | Open |
| IAM-021 | svc_av_mgmt | Service account over-privilege | Low | Open |
| IAM-022 | j.yamamoto | Enabled user without MFA | Low | Open |

## Detailed Findings

### IAM-001: Departed contractor retains Domain Admin and Server Admin membership
**Account:** t.morrison (Tom Morrison, IT Contractors)
**Severity:** Critical (severity_model.md: departed contractor with Domain Admins)
**Check:** check_departed_or_transferred (keyword: contract ended)
**Evidence:** accounts.csv row t.morrison: enabled=TRUE; account_type=user; privileged_groups=Domain Admins;Server Admins; last_login_days_ago=248; mfa_enrolled=FALSE; description="Contract ended 2025-09-01"
**Risk:** A contractor whose engagement ended over a year ago can still authenticate with full domain administration rights, without MFA. The account has not been used in 248 days, meaning no legitimate party would notice an authentication, and any use of the credential by anyone else would not be attributed to the rightful holder. Full domain compromise and total loss of accountability; if used to access ePHI systems, this is a HIPAA breach with no defense in attribution or intent.
**Remediation:** 1. Disable the account today. 2. Remove Domain Admins and Server Admins membership. 3. Have HR confirm contract termination paperwork matches the 2025-09-01 date in the directory. 4. Review domain controller and authentication logs for any activity under this account since contract end. 5. Update the contractor offboarding checklist to require group removal at contract end.
**Owner:** IT Director (Sarah Park), with HR confirmation
**Target completion:** Immediate

### IAM-002: Backup service account holds Domain Admin
**Account:** svc_backup (Backup Service Account, IT)
**Severity:** Critical (severity_model.md: service account with Domain Admins)
**Check:** check_service_account_overpriv
**Evidence:** accounts.csv row svc_backup: enabled=TRUE; account_type=service; privileged_groups=Domain Admins; description="Nightly backup automation; DA granted per legacy config"
**Risk:** Nightly backup automation is executing with full domain administration rights it acquired from a legacy configuration. Backup jobs touch every server, so the credential is present on multiple hosts and in job configurations, expanding the locations from which it can be extracted. A credential extracted from any backup execution host grants Domain Admin and access to ePHI backup archives.
**Remediation:** 1. Grant the backup service account the minimum rights its documented job steps require (typically Backup Operators plus read access to target data), not Domain Admins. 2. Remove the Domain Admins membership. 3. Run the nightly backup job and verify completion status and log output are unchanged. 4. Document the verification result and the new permission set in the service account register.
**Owner:** Systems Administration (Helena Reyes team)
**Target completion:** 7 days

### IAM-003: Dormant privileged service account, 1,156 days
**Account:** svc_epic_int (Epic Integration Service, Clinical Systems)
**Severity:** Critical (severity_model.md: privileged persistence, repeat of prior incident path)
**Check:** check_dormant_privileged (dormant_service_privileged)
**Evidence:** accounts.csv row svc_epic_int: enabled=TRUE; account_type=service; privileged_groups=Domain Admins; last_login_days_ago=1156; description="Post-EHR-migration service account; no current function identified"
**Risk:** This is the highest-risk credential in the inventory: a Domain Admin service account that has not authenticated in over three years and whose own description states no current function is known. Its static password has not been rotated since the EHR migration, and because the account is dormant, any authentication today is almost certainly unauthorized. This exact profile, a privileged service credential extracted from memory, was the mechanism that turned a single workstation compromise into Domain Admin in the prior incident.
**Remediation:** 1. Disable the account immediately. 2. Audit all directory and security logs for authentications under this account in the past 90 days. 3. Contact Clinical Systems owners to confirm no dependency exists. 4. Remove Domain Admins membership. 5. If no function is confirmed within 30 days, delete the account. 6. Any future integration workload must use short-TTL dynamic credentials issued by Vault, per the Vault PAM lab, never a standing service account.
**Owner:** SOC Lead (James Chen), with Clinical Systems confirmation
**Target completion:** Immediate (disable), 30 days (delete decision)

### IAM-004: Service account with Domain Admin membership and no documented function
**Account:** svc_epic_int
**Severity:** Critical (severity_model.md: service account with Domain Admins)
**Check:** check_service_account_overpriv
**Evidence:** accounts.csv row svc_epic_int: account_type=service; privileged_groups=Domain Admins; description="Post-EHR-migration service account; no current function identified"; last_login_days_ago=1156
**Risk:** Independent of dormancy, an enabled service account holding Domain Admins is a standing path to total domain compromise. Stored in configuration files and potentially cached in memory wherever it was deployed, the credential outlived the migration it was created for and now represents pure attack surface. A patient safety consequence follows directly: Domain Admin control enables an attacker to alter, encrypt or disable clinical systems and their ePHI.
**Remediation:** 1. Disable the account immediately (may be executed together with IAM-003). 2. Remove the Domain Admins membership. 3. Delete the account if no function is confirmed within 30 days. 4. Record the deletion decision in the service account register with the confirmation evidence attached.
**Owner:** SOC Lead (James Chen)
**Target completion:** Immediate

### IAM-005: Vendor-granted Domain Admin on helpdesk automation exceeds stated function
**Account:** svc_helpdesk (Helpdesk Automation, IT)
**Severity:** Critical (severity_model.md: service account with Domain Admins)
**Check:** check_service_account_overpriv
**Evidence:** accounts.csv row svc_helpdesk: enabled=TRUE; account_type=service; privileged_groups=Domain Admins; description="Ticket routing automation; DA granted by vendor during install; review later"
**Risk:** Ticket routing automation does not require domain administration. The "review later" noted in the description never occurred, so an active, daily-used automation account operates with full domain rights. It is actively authenticating (last login 0 days), so its credential is in regular use and potentially exposed in the vendor's installed configuration. Any compromise of the automation host yields Domain Admin.
**Remediation:** 1. Review vendor documentation for the ticket routing integration to determine the actual permission set required. 2. Remove svc_helpdesk from the Domain Admins group; grant only Helpdesk-level permissions. 3. Verify that ticket routing continues to operate with Helpdesk group membership only, including a test ticket cycle end to end. 4. Document the verification result. 5. Add vendor-install accounts to the quarterly access review scope.
**Owner:** IT Director (Sarah Park)
**Target completion:** 7 days

### IAM-006: Dormant privileged user account (admin.legacy, 187 days)
**Account:** admin.legacy
**Severity:** High (severity_model.md: dormant privileged user)
**Check:** check_dormant_privileged
**Evidence:** accounts.csv row admin.legacy: enabled=TRUE; privileged_groups=Domain Admins; last_login_days_ago=187; description="Created for EHR migration 2021; migration complete"
**Risk:** A Domain Admin account created for a completed 2021 migration remains enabled and unused for 187 days. Shared "legacy admin" accounts defeat attribution and often carry static passwords never enrolled in MFA (confirmed in IAM-007/IAM-018). Dormancy means abuse would go unnoticed by its legitimate holders.
**Remediation:** 1. Identify who requested the account and whether any current owner exists. 2. If no owner steps forward within 7 days, disable the account. 3. Remove Domain Admins membership. 4. Migrate any residual admin need to individual named accounts with MFA and just-in-time elevation.
**Owner:** IT Director (Sarah Park)
**Target completion:** 7 days

### IAM-007: Privileged account without MFA (admin.legacy)
**Account:** admin.legacy
**Severity:** High (severity_model.md: privileged user without MFA)
**Check:** check_mfa_coverage
**Evidence:** accounts.csv row admin.legacy: enabled=TRUE; privileged_groups=Domain Admins; mfa_enrolled=FALSE
**Risk:** A Domain Admin credential protected only by a password. A phished, guessed or reused password converts directly into full domain administration without any second factor to stop it.
**Remediation:** 1. If the account survives IAM-006 review, enroll it in MFA immediately. 2. Enforce MFA for all privileged logins at the domain policy level so no current or future Domain Admin account can exist without it. 3. Where MFA enrollment fails on shared accounts, that is an indicator the account should be an individual account instead.
**Owner:** IT Security (SOC Lead)
**Target completion:** Immediate

### IAM-008: Lifecycle keyword on privileged account (admin.legacy)
**Account:** admin.legacy
**Severity:** High (pending manual review per check design)
**Check:** check_departed_or_transferred (keyword: migration complete)
**Evidence:** accounts.csv row admin.legacy: privileged_groups=Domain Admins; description="Created for EHR migration 2021; migration complete"
**Risk:** The description documents that the reason for the account's creation has finished, yet the account and its privilege remain. This is a control process failure: nothing in the environment closes accounts when their stated purpose completes.
**Remediation:** 1. Manual review: confirm with IT leadership that the migration purpose has truly ended. 2. Follow the disposition decided under IAM-006 (disable and de-privilege). 3. Add purpose-completion reviews to the service and admin account lifecycle process.
**Owner:** IT Director (Sarah Park)
**Target completion:** 7 days

### IAM-009: Dormant privileged user account (t.morrison, 248 days)
**Account:** t.morrison
**Severity:** High (severity_model.md: dormant privileged user)
**Check:** check_dormant_privileged
**Evidence:** accounts.csv row t.morrison: privileged_groups=Domain Admins;Server Admins; last_login_days_ago=248; enabled=TRUE
**Risk:** Reinforces IAM-001 from the dormancy dimension: an enabled, privileged, dormant account that nobody legitimately uses. Any authentication under this account after the contract end is anomalous and is exactly the signal a dormant-account alert would catch.
**Remediation:** Covered by IAM-001 (disable and strip groups today). Additionally: create a standing detection rule that alerts on any authentication by accounts dormant for more than 90 days.
**Owner:** SOC Lead (James Chen)
**Target completion:** Immediate (with IAM-001)

### IAM-010: Privileged account without MFA (t.morrison)
**Account:** t.morrison
**Severity:** High (severity_model.md: privileged user without MFA)
**Check:** check_mfa_coverage
**Evidence:** accounts.csv row t.morrison: privileged_groups=Domain Admins;Server Admins; mfa_enrolled=FALSE; enabled=TRUE
**Risk:** The departed contractor's Domain Admin credential has no second factor, so its single password is the only barrier between an unknown holder and full domain control.
**Remediation:** 1. Disable the account today (with IAM-001); MFA enrollment for a departed contractor is not meaningful. 2. Verify via log review that no authentications occurred since contract end.
**Owner:** SOC Lead (James Chen)
**Target completion:** Immediate (with IAM-001)

### IAM-011: Departed employee account still enabled (l.okafor)
**Account:** l.okafor (Lena Okafor, Finance)
**Severity:** High (departure keyword; Finance Users is not an admin group, so this is not escalated to Critical)
**Check:** check_departed_or_transferred (keyword: left organization)
**Evidence:** accounts.csv row l.okafor: enabled=TRUE; last_login_days_ago=142; mfa_enrolled=FALSE; description="Left organization per HR 2025-11-28"; privileged_groups=Finance Users
**Risk:** An employee who left nearly a year ago retains an enabled account with finance system access and no MFA. Beyond data exposure risk, orphaned accounts of departed staff routinely retain residual access to systems that later come to hold regulated data. In an organization where several accounts show the same failure, this is an offboarding process defect, not a one-off oversight.
**Remediation:** 1. Confirm departure with HR against the 2025-11-28 date. 2. Disable the account today. 3. Strip all group memberships. 4. Review sign-in activity since the departure date. 5. Fix the offboarding process: HR termination feed must trigger automatic same-day directory disablement.
**Owner:** IT Director (Sarah Park), with HR
**Target completion:** Immediate

### IAM-012: Dormant privileged user account (j.yamamoto, 312 days)
**Account:** j.yamamoto
**Severity:** High (severity_model.md: dormant privileged user)
**Check:** check_dormant_privileged
**Evidence:** accounts.csv row j.yamamoto: privileged_groups=Domain Admins;Server Admins; last_login_days_ago=312; enabled=TRUE; department=Finance
**Risk:** An employee who transferred out of IT in February 2024 retains Domain Admin and Server Admin rights but has not used them in 312 days, indicating privilege with no operational need.
**Remediation:** 1. Confirm current role with the employee's Finance manager. 2. Remove Domain Admins and Server Admins membership within 7 days. 3. If a genuine IT need exists, agree a documented exception with expiry and convert it to just-in-time elevation.
**Owner:** IT Director (Sarah Park)
**Target completion:** 7 days

### IAM-013: Privileged account without MFA (j.yamamoto)
**Account:** j.yamamoto
**Severity:** High (severity_model.md: privileged user without MFA)
**Check:** check_mfa_coverage
**Evidence:** accounts.csv row j.yamamoto: privileged_groups=Domain Admins;Server Admins; mfa_enrolled=FALSE; enabled=TRUE
**Risk:** A non-IT employee holds Domain Admin credentials protected by password only; phishing the user is sufficient to reach full domain control.
**Remediation:** Covered by IAM-012 privilege removal. Interim control: enroll in MFA this week if privilege removal cannot complete sooner.
**Owner:** IT Security (SOC Lead)
**Target completion:** 7 days

### IAM-014: Department transfer without rights removal (j.yamamoto)
**Account:** j.yamamoto
**Severity:** High (pending manual review per check design)
**Check:** check_departed_or_transferred (keyword: transferred from)
**Evidence:** accounts.csv row j.yamamoto: department=Finance; description="Transferred from IT to Finance 2024-02; elevated rights not removed"; privileged_groups=Domain Admins;Server Admins
**Risk:** The directory itself records that elevated rights were not removed at transfer. Transfers create privileged orphan accounts with legitimate-looking owners, which is harder to detect than departures.
**Remediation:** 1. Manual review of the transfer record with HR. 2. Execute the privilege removal from IAM-012. 3. Amend the transfer checklist to require same-week privileged group removal.
**Owner:** IT Director (Sarah Park)
**Target completion:** 7 days

### IAM-015: No MFA with repeated security failures (k.nguyen)
**Account:** k.nguyen (Kevin Nguyen, Radiology)
**Severity:** Medium (severity_model.md: high-risk user without MFA and repeated failures)
**Check:** check_no_mfa_high_risk (escalated)
**Evidence:** accounts.csv row k.nguven: enabled=TRUE; mfa_enrolled=FALSE; description="Three phishing simulation failures in 90 days"; privileged_groups=Epic Users;PACS Users
**Risk:** A clinical-adjacent user with PACS and Epic access has failed three phishing simulations in 90 days and has no MFA. This is the profile most likely to provide the initial endpoint compromise that the incident path requires: the workstation foothold. Successful compromise would expose PHI-bearing imaging and clinical systems.
**Remediation:** 1. Enroll the user in MFA this week and prioritize enrollment for the full Radiology department. 2. Schedule targeted security awareness follow-up rather than generic training. 3. Apply conditional access restrictions (device posture checks) for Epic and PACS access where supported. 4. Track repeat-simulation failures as a review trigger in the security awareness program.
**Owner:** IT Security (SOC Lead), with Radiology management
**Target completion:** 7 days

### IAM-016: Disabled account retaining privileged groups (b.carter)
**Account:** b.carter (Brian Carter, IT)
**Severity:** Medium (severity_model.md: disabled account retaining groups)
**Check:** check_disabled_with_groups
**Evidence:** accounts.csv row b.carter: enabled=FALSE; privileged_groups="Server Admins;Helpdesk"; description="Account disabled; group memberships not removed at offboarding"
**Risk:** The account cannot authenticate today, but it retains Server Admins membership. Disabled-with-groups accounts are re-enablement shortcuts: any error, policy change or rehire process that flips the enabled flag restores full privileged access without review. They also inflate privileged group membership counts and pollute access reviews.
**Remediation:** 1. Remove Server Admins and Helpdesk membership now. 2. Retain the disabled, group-free account for the standard retention period, then delete it. 3. Change the offboarding checklist so group removal occurs at disablement, not after.
**Owner:** IT Director (Sarah Park)
**Target completion:** 7 days

### IAM-017: Monitoring service account holds Server Admin (svc_monitoring)
**Account:** svc_monitoring (Monitoring Agent, IT)
**Severity:** Medium (severity_model.md: service account with Server Admins)
**Check:** check_service_account_overpriv
**Evidence:** accounts.csv row svc_monitoring: account_type=service; privileged_groups=Server Admins; description="Prometheus metrics collection"; last_login_days_ago=0
**Risk:** Metrics collection is read-only by nature, so Server Admins vastly exceeds the stated function. An actively used, widely deployed agent credential holding server administration rights is exposed on every monitored host.
**Remediation:** 1. Define the minimum read set Prometheus requires (performance counters, service status) and scope a dedicated role accordingly. 2. Remove Server Admins membership. 3. Verify dashboards and alerting continue to populate correctly over one full day. 4. Document the new permission set in the service account register.
**Owner:** Systems Administration (Helena Reyes team)
**Target completion:** 30 days

### IAM-018: Enabled user without MFA (admin.legacy)
**Account:** admin.legacy
**Severity:** Low (baseline no-MFA hygiene finding; privilege-level urgency already captured in IAM-007)
**Check:** check_no_mfa_high_risk
**Evidence:** accounts.csv row admin.legacy: enabled=TRUE; account_type=user; mfa_enrolled=FALSE
**Risk:** Baseline credential exposure on an enabled account.
**Remediation:** Subsumed by IAM-006/IAM-007 disposition; no separate action beyond those items.
**Owner:** IT Security (SOC Lead)
**Target completion:** 30 days (tracking item)

### IAM-019: Enabled user without MFA (t.morrison)
**Account:** t.morrison
**Severity:** Low (baseline; superseded by IAM-001 disablement)
**Check:** check_no_mfa_high_risk
**Evidence:** accounts.csv row t.morrison: enabled=TRUE; mfa_enrolled=FALSE
**Risk:** Baseline credential exposure; resolved by disabling under IAM-001.
**Remediation:** No separate action beyond IAM-001.
**Owner:** IT Director (Sarah Park)
**Target completion:** Immediate (closed by IAM-001)

### IAM-020: Enabled user without MFA (l.okafor)
**Account:** l.okafor
**Severity:** Low (baseline; superseded by IAM-011 disablement)
**Check:** check_no_mfa_high_risk
**Evidence:** accounts.csv row l.okafor: enabled=TRUE; mfa_enrolled=FALSE
**Risk:** Baseline credential exposure on a departed employee's still-enabled account.
**Remediation:** No separate action beyond IAM-011.
**Owner:** IT Director (Sarah Park)
**Target completion:** Immediate (closed by IAM-011)

### IAM-021: AV management service account holds Workstation Admins (svc_av_mgmt)
**Account:** svc_av_mgmt (AV Management Agent, IT)
**Severity:** Low (hygiene-level over-privilege relative to Domain/Server tiers)
**Check:** check_service_account_overpriv
**Evidence:** accounts.csv row svc_av_mgmt: account_type=service; privileged_groups=Workstation Admins; description="EDR agent management"; last_login_days_ago=0
**Risk:** Endpoint management agents legitimately need elevated local rights, but Workstation Admins across the fleet is broader than a scoped management role and puts a privileged credential on every workstation, exactly where the prior incident began.
**Remediation:** 1. Review the EDR vendor's documented privilege requirements. 2. Evaluate a scoped management role or per-host JIT elevation if the product supports it. 3. If Workstation Admins is genuinely required, document the exception with an annual review date in the service account register.
**Owner:** IT Security (SOC Lead)
**Target completion:** 30 days

### IAM-022: Enabled user without MFA (j.yamamoto)
**Account:** j.yamamoto
**Severity:** Low (baseline; privilege-level urgency captured in IAM-013)
**Check:** check_no_mfa_high_risk
**Evidence:** accounts.csv row j.yamamoto: enabled=TRUE; mfa_enrolled=FALSE
**Risk:** Baseline credential exposure; resolved alongside IAM-012/IAM-013.
**Remediation:** No separate action beyond IAM-012/IAM-013.
**Owner:** IT Director (Sarah Park)
**Target completion:** 7 days (closed by IAM-012)

## MFA Coverage Analysis

Among the eight user accounts holding Domain Admins or Server Admins
membership (service accounts are excluded; MFA does not apply to machine
credentials, which should instead be eliminated in favor of dynamic
credentials):

- With MFA: 5 of 8 (james.chen, sarah.park, robert.kim, m.torres,
  h.reyes) — 62.5%
- Without MFA: 3 of 8 (admin.legacy, t.morrison, j.yamamoto) — 37.5%

Every one of the three unprotected accounts is simultaneously dormant or
flagged for lifecycle review, meaning the highest-value credentials in the
organization are concentrated in its least-watched accounts. Across all
enabled user accounts in the inventory, 7 of 17 (41%) lack MFA, including
k.nguyen, whose record documents three phishing simulation failures in 90
days.

Regulatory context: HIPAA 45 CFR 164.312(a)(2)(i) requires unique user
identification and 164.312(d) requires automatic logoff and, where
technical controls permit, a means to verify the identity of the person
seeking access. Single-factor credentials on privileged accounts do not
reliably verify identity (shared admin.legacy defeats uniqueness outright),
and an organization operating Domain Admin access with 37.5% single-factor
coverage would struggle to demonstrate that access verification controls
are in place during an OCR audit or after a breach. The recommended
standard is 100% MFA on privileged accounts, enforced by group policy
rather than per-account enrollment.

## Service Account Risk Summary

Service accounts with Domain Admin or Server Admin membership, from
`accounts.csv` and cross-checked against `pam_migration_candidates.csv`:

| Account | Membership | Documented function? | Verdict |
|---|---|---|---|
| svc_epic_int | Domain Admins | No — "no current function identified", dormant 1,156 days | Decommission: disable now, delete in 30 days if no owner claims it (IAM-003/IAM-004) |
| svc_helpdesk | Domain Admins | Function is ticket routing; DA exceeds need | De-privilege to Helpdesk scope and verify routing continues (IAM-005); migrate to Vault-issued credentials |
| svc_backup | Domain Admins | Function is nightly backup; DA exceeds need | De-privilege to backup-required rights and verify job success (IAM-002); align credentials to backup window with short TTL |
| svc_monitoring | Server Admins | Metrics collection needs read-only | Scope to read-only metrics access and verify dashboard continuity (IAM-017) |
| svc_av_mgmt | Workstation Admins | EDR management may justify some elevation | Vendor review and scoped role or documented annual exception (IAM-021) |

Pattern: four of five service accounts hold more privilege than their
documented function requires, and none has an owner-of-record. The target
end state, per the Vault PAM lab evidence, is that no service account
holds a standing Domain Admin or Server Admin credential: workloads
request short-TTL, least-privilege credentials at runtime, every live
credential is enumerable as a Vault lease, and revocation kills the
credential at the database instantly. `pam_migration_candidates.csv`
sequences the migration in that priority order.

## Remediation Roadmap

| Priority | Action | Owner Role | Target | Success Criterion |
|---|---|---|---|---|
| 1 | Disable and de-privilege svc_epic_int (IAM-003/IAM-004) | SOC Lead | Immediate | Account disabled; DA membership removed; 90-day log audit complete |
| 2 | Disable t.morrison; strip groups; verify post-contract activity (IAM-001/009/010/019) | IT Director + HR | Immediate | Account disabled, zero privileged groups; HR confirmation filed |
| 3 | Disable l.okafor per HR departure record (IAM-011/020) | IT Director + HR | Immediate | Account disabled; no authentications since 2025-11-28 verified |
| 4 | Enforce MFA for all Domain Admin/Server Admin logins (IAM-007/010/013) | IT Security (SOC Lead) | 7 days | Policy-enforced; 100% privileged MFA verified by re-running audit_iam.py |
| 5 | Remove vendor-granted DA from svc_helpdesk and verify routing (IAM-005) | IT Director | 7 days | DA removed; test ticket cycle passes with Helpdesk-only rights |
| 6 | De-privilege svc_backup and verify nightly job (IAM-002) | Systems Administration | 7 days | DA removed; next-night backup completes with documented status |
| 7 | Resolve admin.legacy and j.yamamoto lifecycle cases (IAM-006/008/012/014) | IT Director | 7 days | Both accounts disabled or DA/SA membership removed; exceptions documented with expiry |
| 8 | Strip groups from disabled b.carter (IAM-016) | IT Director | 7 days | Zero group memberships on disabled account |
| 9 | Enroll k.nguyen and Radiology in MFA; targeted awareness follow-up (IAM-015) | IT Security + Radiology mgmt | 7 days | MFA active; follow-up session completed |
| 10 | Scope svc_monitoring to read-only and verify monitoring (IAM-017) | Systems Administration | 30 days | SA removed; dashboards and alerts populate for a full day |
| 11 | Review svc_av_mgmt vendor requirements; scope or document exception (IAM-021) | IT Security | 30 days | Scoped role in place or exception documented with annual review date |
| 12 | Establish HR termination feed driving same-day disablement; add transfers and group stripping to offboarding/transfer checklists | IT Director + HR | 30 days | Two consecutive months of zero orphaned accounts at monthly review |
| 13 | Migrate remaining service workloads to Vault-issued short-TTL credentials per pam_migration_candidates.csv | IT Security + Systems Administration | 30 days | No standing privileged service account passwords; live credentials enumerable as leases |
| 14 | Recurring quarterly access review re-running audit_iam.py against fresh exports | IT Security (SOC Lead) | 30 days | Quarterly run scheduled; findings trend downward quarter over quarter |

## Appendix: Audit Script

Findings in this report were generated by `audit_iam.py` (version 1.0),
a Python 3 standard-library script that reads `accounts.csv` and emits
machine-readable findings to `iam_findings.json`. Every finding ID cited
above (IAM-001 through IAM-022) corresponds to one entry in
`iam_findings.json`, which was in turn produced by a single named check
applied to a single inventory row, preserving full traceability from
report to raw evidence. The script, the inventory and the findings file
are submitted together with this report; re-running the script against the
remediated directory is the intended verification mechanism for closing
each finding.
