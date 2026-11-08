# Identity Program Brief for Dr. Morales

**Classification:** Confidential | **Date:** 08 November 2026
**From:** Steve, Cybersecurity Engineer | **Reviewed by:** James Chen, SOC Lead

## Identity Posture Summary

We audited every privileged account in the organization for the first
time. We found 22 problems: 5 Critical and 9 High. Six accounts hold
full administrator rights that no one can justify. A cloud review found 10
more problems, 2 of them Critical: a clinical backup storage location
readable by anyone on the internet, and our highest-level cloud account
protected by a password alone. Our identity controls today would still
allow the same attack that succeeded before. We now know exactly where we
stand, and we have started fixing it.

## Connection to the Incident

Last time, an attacker went from one infected computer to full control of
our network in under two hours by stealing a service account password.
Four of our five Critical findings recreate that path today. The clearest
is IAM-003/IAM-004: a service account with full network rights, unused for
over three years, whose record says no current function exists. Stealing
that password tomorrow would repeat the original attack. Findings IAM-001
(a departed contractor who still has administrator access) and IAM-005
(an unreviewed vendor account) are the same story.

## What Has Been Completed

- Audited all 20 privileged accounts; every finding is documented,
  evidenced, and re-checkable on demand (IAM-001 through IAM-022).
- Rewrote the three overly broad cloud access permissions to the minimum
  each job needs, and added identity verification plus network
  restrictions to emergency access.
- Designed single sign-on: one login for all staff systems, so disabling
  a departing employee's access once shuts every door at once.
- Built and tested an expiring-password design that makes stolen service
  account passwords worthless within minutes.

## What Must Be Completed Before the Next Board Meeting

1. Disable the five unjustified administrator accounts (IAM-001 to
   IAM-005). Owner: IT Director and SOC Lead. By 01 December 2026.
2. Close the internet-readable clinical backups and lock down the top
   cloud account. Owner: Systems Administrator and IT Security. By
   01 December 2026.
3. Require identity verification for every administrator login. Owner:
   IT Security. By 15 December 2026.

## What Requires Board Authorization or Budget

Funding for the identity program: single sign-on rollout, the
expiring-password platform, and roughly two to three engineer-months of
remediation effort. Without it, the dormant administrator accounts remain
usable by an attacker, and the open backup storage could become a legally
reportable patient-data breach carrying mandatory 60-day notification.

## Board Resolution Requested

The Board Risk Committee authorizes the identity program budget and grants
the IT Director authority to immediately disable any account the audit
shows holding administrator rights without a documented business need.
