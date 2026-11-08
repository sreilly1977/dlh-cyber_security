# MedDefense IAM Policy Analysis

Review and correction of three MedDefense AWS IAM policies originally
written for deployment speed rather than least privilege. Source evidence:
`original_siem_reader_policy.json`, `original_ehr_backup_policy.json`,
`original_break_glass_policy.json`, `aws_environment_observations.md`
(observations 7 and 9), and `cis_aws_control_map.md`.

## Policy 1: MedDefenseSIEMLogReader Violations

Original grants:

- `s3:*` on `Resource: *`: full S3 control (create, delete, overwrite,
  make-public) over every bucket in the account, including
  `meddefense-clinical-backup-2022` which holds ePHI archives.
- `logs:*` and `cloudwatch:*` on `Resource: *`: full CloudWatch Logs and
  CloudWatch control, including deleting the very log streams a SIEM reader
  depends on, altering alarms and dashboards, and modifying retention.

Violations and corrections:

| # | Violation | Attack surface created | Correction applied |
|---|---|---|---|
| 1 | `s3:*` on `*` | A compromised SIEM reader role could delete or alter forensic log objects, sabotage the clinical backup bucket, or exfiltrate any object in the account; log integrity is destroyed in exactly the scenario the role exists to investigate | Scoped to `s3:GetObject` on `meddefense-siemlog-prod/*` and `s3:ListBucket` on `meddefense-siemlog-prod` only |
| 2 | `logs:*` on `*` | Ability to delete or modify arbitrary log groups, destroying evidence and SIEM coverage | Scoped to `logs:CreateLogStream` and `logs:PutLogEvents` on the `siem-log-reader` lambda log group only |
| 3 | `cloudwatch:*` on `*` | Ability to silence alarms, change dashboards and delete metric filters, masking ongoing intrusion activity | CloudWatch actions removed entirely; the stated function (reading SIEM logs and writing its own lambda output) needs none |

A reader role should never hold write or delete authority over the data it
reads. After correction the role can read the SIEM log bucket and append to
its own lambda log stream, and nothing else.

## Policy 2: MedDefenseEHRBackupRole Violations

Original grants:

- `s3:*` on `Resource: *`: full S3 control over all buckets, including the
  ePHI clinical backup bucket and any other present or future bucket.
- `kms:*` on `Resource: *`: full KMS control over every key in the account,
  including key deletion and key policy modification.

Violations and corrections:

| # | Violation | Attack surface created | Correction applied |
|---|---|---|---|
| 1 | `s3:*` on `*` | Observation 9 flags this role by name: with account-wide S3 control, a compromise of the automation role can delete or exfiltrate unrelated buckets, including the public-facing clinical backup bucket containing ePHI | S3 scoped to `meddefense-ehr-backup-prod` (objects and bucket listing); actions reduced to those a backup job performs: `PutObject`, `GetObject`, `AbortMultipartUpload`, `ListBucket`, `ListBucketMultipartUploads` |
| 2 | `kms:*` on `*` | Full KMS control includes scheduling key deletion and rewriting key policies; compromising the backup role would let an attacker deny decryption of every encrypted resource in the account (effective data destruction) or grant themselves access to keys protecting unrelated workloads | KMS scoped to the specific backup key `mrk-abc123def456`; actions reduced to `Encrypt`, `Decrypt`, `GenerateDataKey` |

Backup automation needs to write objects, verify them and encrypt or decrypt
with one designated key. It does not need to create buckets, delete other
buckets' objects, administer KMS keys or modify key policies.

## Policy 3: MedDefenseBreakGlassAdmin Violations

Original grants:

- `Action: *` on `Resource: *` with no conditions of any kind: unconditional,
  standing, account-wide administrator access.

Violations and corrections:

| # | Violation | Attack surface created | Correction applied |
|---|---|---|---|
| 1 | Unconditional `Allow *` on `*` | This is functionally a second root credential attached to a role. Unlike root it can be assumed programmatically and is invisible to root-account hygiene; anyone who can assume the role (or anything that can) gets full takeover with no friction | Emergency admin capability preserved, but the allow is conditioned on `aws:MultiFactorAuthPresent: true` AND `aws:SourceIp` within `198.51.100.0/24` |
|  | A compromise path that ignores the Allow conditions | Long-lived session tokens issued without MFA, or requests from outside the corporate range, could otherwise rely on evaluation order ambiguities or other attached policies | Two explicit `Deny` statements: one denying all actions when `aws:MultiFactorAuthPresent` is false, one denying all actions when `aws:SourceIp` is outside `198.51.100.0/24`. Explicit denies override any allow anywhere in the account |
|  | Self-perpetuating takeover | A break-glass principal could delete the break-glass role or its policy, or escape organizational guardrails via AWS Organizations actions, entrenching access | Explicit `Deny` on `iam:DeletePolicy`, `iam:DeleteRole`, `iam:UpdateRole` and all `organizations:*` actions, unconditionally |

Break-glass access is intentionally powerful; the correction does not reduce
its emergency capability but ensures it can only be exercised by an
authenticated human (MFA) on the corporate network (source IP restriction),
and cannot be used to dismantle the controls that constrain it.

## Least Privilege Summary

| Policy | Original footprint | Corrected footprint |
|---|---|---|
| SIEM reader | `s3:*`, `logs:*`, `cloudwatch:*` on `*` | Read-only on one log bucket; append-only writes to one lambda log group |
| EHR backup | `s3:*`, `kms:*` on `*` | Backup-object write/read on one bucket; encrypt/decrypt on one KMS key |
| Break-glass | `*` on `*`, unconditional | `*` on `*` gated by MFA and source IP, with backstop explicit denies |

All three originals followed the same anti-pattern: the broadest wildcard
action set on the broadest wildcard resource, deferring tightening to a
"later" that never arrived (the same pattern noted on the clinical backup
bucket in observation 6). Corrections apply three techniques consistently:
remove unneeded actions, narrow resources to named principals, and add
conditions or explicit denies where wildcards must remain. These changes
map to the CIS AWS Foundations Benchmark least-privilege control area
(CIS control map observations 7 and 9, rated High).

## Residual Risk and Operational Notes

- Break-glass wildcard allows remain broad by design. The MFA and source IP
  conditions constrain who can activate them, but an activated break-glass
  session is still account-wide. Pair this policy with alerting on role
  assumption and a documented exercise and review schedule.
- The SIEM reader policy still cannot enforce object immutability; if log
  tampering by other privileged principals is a concern, consider S3 Object
  Lock or a dedicated write-once configuration on
  `meddefense-siemlog-prod`.
- The EHR backup policy trusts the named KMS key and bucket. Bucket-level
  protection is a separate gap: `meddefense-clinical-backup-2022` still has
  Block Public Access disabled with a `Principal: "*"` policy per observation
  6. Correcting this role's policy does not close that bucket's exposure,
  which is tracked separately as a Critical finding in the cloud assessment.
- Condition keys like `aws:SourceIp` are not honored by some AWS services
  whose calls originate internally, so the corporate-range restriction may
  not apply uniformly across every API. Monitor evaluation results and
  treat the explicit denies as the enforcement floor.
- Corrected policies should be validated with IAM Access Analyzer policy
  checks before deployment, and the originals retained alongside
  `iam_policies/` for change audit trail.
