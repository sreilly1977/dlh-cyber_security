# Identity Program Brief for Dr. Morales

**Classification:** Confidential | **Date:** 08 November 2026
**From:** Steve, Cybersecurity Engineer | **Reviewed by:** James Chen, SOC Lead

## Identity Posture Summary

We completed the first full audit of every privileged account in the
organization. Across the 20 accounts reviewed, we found 22 problems: 5
Critical and 9 High. Separately, the cloud environment review found 10
problems, including 2 Critical. Six accounts still carry standing
administrator rights nobody can justify, three privileged accounts have no
second-factor protection, and two configurations expose us today: a
clinical backup bucket open to the internet, and the AWS root account
protected by a password alone with permanent access keys dating to March
2022. Our identity posture currently permits the same attack that
succeeded against us before. That is the honest position. The difference
is that we can now prove exactly where we stand, with evidence, and we
have begun closing it.

## Connection to the Incident

The prior breach reached Domain Admin in under two hours through a
service account credential extracted from a workstation. Four of the five
Critical audit findings recreate that exact path today: service and
administrative accounts with full domain rights but no valid business
need. The clearest example is finding IAM-003/IAM-004 (svc_epic_int): a
domain administrator service account, dormant for over three years, whose
own record states "no current function identified". Anyone extracting
that credential tomorrow repeats the original attack. Findings IAM-001
(departed contractor with administrator rights) and IAM-005 (vendor
installation account never reviewed) are the same pattern. These are not
hypothetical risks; they are the current state that made the incident
possible.

## What Has Been Completed

- **Full privileged account audit.** Every privileged account inventoried
  and scored, with 22 documented findings, each traceable to a named
  account and named check (findings IAM-001 to IAM-022). The audit is now
  repeatable software, so the board can expect a fresh, comparable result
  every quarter.
- **Least-privilege corrections for the cloud.** All three overly broad
  AWS policies were rewritten to the minimum access each function needs,
  with per-change justification and an MFA-gated emergency access design.
- **Single sign-on designed.** A working reference configuration for one
  login across our systems, so one off-boarding action disables a leaver
  everywhere, ending the two-stale-Epic-accounts problem permanently.
- **Replacement for standing service passwords.** A tested design for
  automatically expiring, individually issued credentials, proving that
  the svc_epic_int class of risk can be eliminated rather than merely
  rotated.

## What Must Be Completed Before the Next Board Meeting

1. **Disable and strip the unjustified administrator accounts**
   (IAM-001 to IAM-005). Owner: IT Director and SOC Lead. By
   01 December 2026.
2. **Close the internet-facing clinical backup exposure and lock the
   AWS root account.** Owner: Systems Administration, IT Security. By
   01 December 2026.
3. **Require second-factor authentication for every administrative
   login.** Owner: IT Security. By 15 December 2026.

## What Requires Board Authorization or Budget

An identity program budget covering three items: enterprise single
sign-on deployment, the privileged-access (expiring-credential) platform,
and security engineering time to execute the roadmap, estimated at two to
three engineer-months of remediation work. If deferred, the specific risk
is that findings IAM-003/IAM-004 remain exploitable, and the open clinical
backup bucket could convert exposure into a reportable HIPAA breach with
mandatory 60-day notification.

## Board Resolution Requested

The Board Risk Committee authorizes the identity program budget and grants
the IT Director emergency authority to disable any account shown by the
audit to hold administrator rights without documented business need.
