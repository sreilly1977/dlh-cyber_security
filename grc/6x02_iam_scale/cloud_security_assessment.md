# MedDefense Cloud Security Assessment

**Classification:** Confidential
**Assessment date:** 08 November 2026
**Prepared by:** Steve, Cybersecurity Engineer
**Reviewed by:** James Chen, SOC Lead; Helena Reyes, Systems Administrator

## Assessment Scope

This assessment evaluates the current state of the MedDefense AWS
environment against the CIS Amazon Web Services Foundations Benchmark
v3.0.0. The input evidence is the ten-observation walkthrough documented
by Helena Reyes in `aws_environment_observations.md`, mapped to benchmark
control areas using `cis_aws_control_map.md`. Severity ratings follow the
same model used in the IAM audit (`severity_model.md`): Critical for
direct compromise pathways and broad ePHI exposure, High for strong attack
paths needing one additional condition, Medium for meaningful exposure or
detection weakness, Low for hygiene issues.

In scope: identity and access management configuration (root account, IAM
users, roles and policies), storage exposure (S3), logging (CloudTrail,
VPC Flow Logs) and organizational guardrails (AWS Organizations and SCPs).
Out of scope: network perimeter (security groups, NACLs), encryption
inventory beyond what the observations state, and application-level
security of the clinical systems hosted on AWS. Companion work in this
project covers the on-premises identity audit (`iam_audit_report.md`) and
the least-privilege policy corrections applied in Task 2
(`iam_policies/`, `iam_policy_analysis.md`).

Compliance status vocabulary: **Non-compliant** (control not met),
**Partially compliant** (control partially met), **Compliant** (control
met). All ten observations assessed here are open gaps; none reaches
Compliant.

CIS v3.0.0 control numbers are cited where individually verified (1.4,
1.5, 3.1, 3.9); remaining controls are cited by benchmark control name,
with `cis_aws_control_map.md` as the project's mapping record.

## Findings Table

| # | Observation | CIS AWS FSB v3.0.0 control | Severity | Compliance status | Remediation summary |
|---|---|---|---|---|---|
| 1 | Root account has no MFA; root access keys created 2022-03-15 and never deleted | 1.5 Ensure MFA is enabled for the "root user" account; 1.4 Ensure no root user account access key exists | **Critical** | Non-compliant | Enable MFA on root, delete both root access keys permanently |
| 2 | Seven IAM users have console access; four have MFA, three do not | Ensure MFA is enabled for all IAM users that have a console password | High | Non-compliant | Enroll the three users in MFA; enforce at policy level |
| 3 | Four users hold long-lived programmatic access keys; two keys older than 22 months with no rotation schedule | Access key rotation control (rotate every 90 days or less) | Medium | Non-compliant | Rotate the two stale keys, adopt a 90-day rotation schedule, prefer IAM roles |
| 4 | Password policy: 8 chars minimum, no complexity, no expiration, no MFA requirement | IAM password policy suite (minimum length 14, complexity, expiration, prevention of reuse) | Medium | Non-compliant | Raise policy to benchmark parameters via `update-account-password-policy` |
| 5 | CloudTrail enabled in us-east-1 only; absent in us-east-2 (DR region with clinical backups) | 3.1 Ensure CloudTrail is enabled in all regions | High | Non-compliant | Enable multi-region CloudTrail with log-file validation and KMS encryption |
| 6 | `meddefense-clinical-backup-2022`: Block Public Access disabled; bucket policy allows `s3:GetObject` to `Principal: "*"`; contains ePHI backups | S3 Block Public Access controls (account and bucket level) | **Critical** | Non-compliant | Enable Block Public Access at bucket and account level; remove the public policy statement |
| 7 | Three roles (`MedDefenseDevRole`, `MedDefenseLegacyRole`, `MedDefenseVendorAccess`) carry AWS-managed AdministratorAccess | Ensure no role is attached the AWS-managed AdministratorAccess policy / least privilege | High | Non-compliant | Replace with scoped policies; treat Legacy role as break-glass with MFA and source-IP conditions |
| 8 | VPC Flow Logs not enabled on any VPC | 3.9 Ensure VPC flow logging is enabled in all VPCs | Medium | Non-compliant | Enable flow logs on all VPCs to a central log destination |
| 9 | `MedDefenseEHRBackupRole` used `s3:*` on `Resource: *` (corrected in Task 2) | Least privilege for IAM policies (no wildcard-action wildcard-resource grants) | High | Partially compliant (pending deployment) | Deploy the corrected `iam_policies/ehr_backup_policy.json`; validate with IAM Access Analyzer |
| 10 | AWS Organizations not configured; no Service Control Policies | Organization-wide guardrail controls (v3.0.0 added organization management controls) | Medium | Non-compliant | Set up AWS Organizations; deploy preventive SCPs (deny public S3, require MFA, region restrictions) |

Aggregate posture: 10 observations, 2 Critical, 4 High, 4 Medium, 0 Low,
0 Compliant.

## Critical Findings

### Observation 1 — Root account without MFA, with permanent access keys

**CIS controls:** 1.5 (MFA for root), 1.4 (no root access keys)
**Severity:** Critical — full account takeover risk with no second factor
and no rotation.

The root user owns the account and can bypass every IAM restriction,
including SCPs. Without MFA, a leaked root password is sufficient for
complete compromise. The access keys created on 2022-03-15 are the worse
half of the finding: they are non-expiring credentials usable from
anywhere without a browser, a console or MFA, and they have existed
unrotated for over four years. CIS requires that root access keys not
exist at all; root should never need programmatic access in a modern AWS
account.

**Remediation (console and CLI):**

1. Sign in to the root user, enable virtual MFA immediately, and migrate
   to a hardware MFA device per the CIS benchmark recommendation.
2. Confirm no workload depends on root access keys (root is not
   programmatically usable for most services, so dependency is unlikely),
   then delete both keys:
   `aws iam list-access-keys` (under a role, keys for root must be
   deleted via the console by the root user) → IAM console → root
   security credentials → Delete each access key.
3. Verify via `aws iam get-account-summary` (or Security Hub check IAM.4)
   that the account reports zero root access keys.
4. Record the event date; any future request to re-create root keys
   requires CISO approval.

### Observation 6 — Publicly readable ePHI backup bucket

**CIS controls:** S3 Block Public Access, account and bucket level
**Severity:** Critical — ongoing exposure of electronic protected health
information to anonymous internet users.

Three elements combine into the exposure:

- **`"Principal": "*"`** in a bucket policy means every AWS identity and
  every anonymous caller on the internet is the audience of the
  statement. The bucket confers no identity requirement whatsoever on the
  requester.
- **`s3:GetObject`** is the permission to download the contents of every
  object in the bucket. Combined with the wildcard principal, anyone who
  learns the bucket name (discoverable via enumeration, referring
  applications, or certificate-transparency-adjacent tooling) can
  download every object.
- **The content is ePHI backup archives.** Downloading an ePHI archive
  without authorization is precisely the conduct HIPAA's Breach
  Notification Rule contemplates. Under **45 CFR 164.402**, a *breach* is
  the unauthorized acquisition, access, use, or disclosure of protected
  health information that compromises its security or privacy, with an
  exception only where the covered entity demonstrates a low probability
  of compromise through the four-factor risk assessment. Here, the
  entity's own bucket policy affirmatively grants anonymous access, so
  the demonstration of low probability of compromise is exceptionally
  hard to construct: the organization would need evidence of what was
  downloaded, by whom, and when, and Block Public Access disabled plus
  wildcard `GetObject` works against that argument, not for it. Absent
  that demonstration, the breach is presumed, triggering the notification
  duties of 164.404 (individuals, without unreasonable delay and no later
  than 60 days), 164.406 (HHS) and, if 500 or more individuals are
  affected, media notice under 164.408, with the full cost and reputational
  consequence that entails. Because this is *exposure* rather than a
  confirmed download, the organization does not automatically owe the
  60-day notification clock today, but every day the configuration stands
  weakens any future low-probability-of-compromise argument and the
  four-factor assessment leans heavily against MedDefense (the data is
  identifiable clinical backups, acquired by literally anyone, actually
  possessed by unknown parties, with no mitigation).

**Remediation (immediate, ~15 minutes of work):**

1. Enable bucket-level Block Public Access:
   ```
   aws s3api put-public-access-block \
     --bucket meddefense-clinical-backup-2022 \
     --public-access-block-configuration \
       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```
2. Enable account-level Block Public Access so no future bucket can be
   made public by policy:
   ```
   aws s3api put-public-access-block \
     --public-access-block-configuration \
       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   ```
3. Remove the `"Principal": "*"` statement from the bucket policy and
   re-grant read access only to the specific roles that need it
   (the corrected backup role from Task 2, plus DR recovery roles).
4. Enable default encryption with the designated KMS key and ensure the
   corrected backup role's `kms:Encrypt/Decrypt/GenerateDataKey` scope
   covers this bucket's key.
5. Check S3 server access logs and CloudTrail (once Observation 5 is
   remediated) for any `GetObject` events from unexpected principals;
   initiate the 164.402 four-factor assessment immediately if any are
   found.

## Remediation Priority Order

Ordered by risk reduction per unit of effort; Critical first, then High,
then Medium, with detection gaps placed ahead of hygiene items because
CloudTrail and Flow Logs change how fast the organization sees everything
else.

| Priority | Observation | Action | Owner role | Target |
|---|---|---|---|---|
| 1 | 6 | Enable bucket + account Block Public Access; remove wildcard principal policy; assess access logs | Systems Administration (H. Reyes) | Immediate (day 0) |
| 2 | 1 | Root MFA on, both root access keys deleted | CISO (executed by IT Security) | Day 0–1 |
| 3 | 5 | Multi-region CloudTrail (incl. us-east-2), KMS-encrypted, validated | IT Security | Day 1–3 |
| 4 | 9 | Deploy corrected EHR backup policy; validate with Access Analyzer | Cloud Engineering | Day 1–3 |
| 5 | 7 | Re-scope all three AdministratorAccess roles; convert Legacy role to break-glass pattern with MFA + source-IP conditions (Task 2 design) | Cloud Engineering + IT Security | Day 3–7 |
| 6 | 2 | Enroll remaining three console users in MFA; enforce | IT Security | Day 3–7 |
| 7 | 4 | Harden account password policy to benchmark levels | IT Security | Day 3–7 |
| 8 | 10 | Stand up AWS Organizations; deploy SCPs (deny public S3, deny root key creation, MFA enforcement, region guards) | Cloud Architecture | Day 7–14 |
| 9 | 3 | Rotate stale keys; publish 90-day rotation standard | Cloud Engineering | Day 7–14 |
| 10 | 8 | Enable VPC Flow Logs on all VPCs to central log destination | Network/Cloud Engineering | Day 14–21 |

Success criterion for closure: every observation re-assessed against its
CIS control and demonstrably compliant, verified with AWS Security Hub's
CIS AWS Foundations Benchmark v3.0.0 conformance pack where the control is
automated (Observations 1, 2, 5, 6, 8 and 9 have automated checks;
Observations 4, 7 and 10 are partly manual).

## Estimated Effort

Effort assumes one experienced engineer with console and CLI access; the
Day 0 items overlap and can share one working session.

| Observation | Remediation effort | Complexity | Notes |
|---|---|---|---|
| 1 (root MFA + keys) | 1–2 hours | Low | Requires root sign-in session; deleting keys is minutes, governance to keep them deleted is the ongoing task |
| 2 (console MFA) | 1–2 hours | Low | Mostly user coordination; policy enforcement is minutes |
| 3 (key rotation) | 4–6 hours | Medium | Rotating without breaking consumers requires identifying every key's workload first |
| 4 (password policy) | 1 hour | Low | Single CLI command; coordinate with users for next-expiry impact |
| 5 (CloudTrail DR) | 4–8 hours | Medium | Enable multi-region trail, KMS key, validation, and verify delivery to us-east-2 |
| 6 (public bucket) | 2–4 hours | Low–Medium | Access controls are minutes; access-log review and 164.402 assessment if hits found is the variable cost |
| 7 (admin roles) | 2–4 days | High | Requires enumerating actual permissions each role needs; break-glass redesign reuses Task 2 patterns |
| 8 (flow logs) | 4–8 hours | Medium | Straightforward per VPC; cost tuning and log destination choice are the work |
| 9 (backup role policy) | 2–4 hours | Low | Policy already corrected in Task 2; remaining work is deployment, testing and Access Analyzer validation |
| 10 (Organizations + SCPs) | 3–5 days | High | New structural capability, not just a fix: account inventory, OU design, SCP set, testing for legitimate breaks |

Total: roughly 2 to 3 engineer-weeks to a fully compliant baseline, of
which the two Critical exposures (Observations 1 and 6) and the DR-region
logging gap (Observation 5) are closable within the first two days.
Recommendation: execute Priorities 1–3 immediately and independently of
the remaining plan, since Observations 6 and 1 are the two states that
make a HIPAA-reportable breach and full account takeover respectively
achievable today.
