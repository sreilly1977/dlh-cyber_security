# Introduction

> "Complexity is the enemy of security." 
>
> — Bruce Schneier

The Cobalt Strike attacker moved from a single compromised workstation to Domain Admin in under two hours. The path was not clever. It was short: extract credentials from memory, authenticate as a service account, and discover that the service account held Domain Admin because nobody remembered why it was granted three years ago. The perimeter held. The detection rules eventually fired. But the identity layer made the entire attack trivial.

Identity is where modern intrusions live. Access rights accumulate over years. Service accounts get created for migrations that finish, then sit dormant with excessive permissions. Contractors leave but accounts remain. Former employees transfer departments but old rights stay. Nobody audits the full list of privileged accounts until after the incident, and by then the damage is done.

## Why this matters

Identity is the most targeted layer in modern attacks. Every ransomware deployment, every data exfiltration chain and every lateral movement path starts with identity. The analyst who can configure federation, design least-privilege cloud IAM, implement JIT access and audit an organization's identity posture against real evidence is doing work that appears in every security architect, cloud security engineer and GRC role description in healthcare.

The IAM audit capability is particularly rare and particularly valued. Most professionals can describe what least privilege means. Few can look at a directory of 200 accounts, write a script to surface the findings and produce a professional assessment with severity ratings, evidence references and remediation actions that a CISO acts on before the next incident. This project builds that capability end to end.

## Context

The post-incident review following the Cobalt Strike breach produced one finding that James Chen returned to repeatedly in the debrief: the attacker needed fewer than two hours from initial compromise to Domain Admin access. The path was three hops: compromised workstation, extracted NTLM hash, service account with Domain Admin rights. None of that should have been possible.

Dr. Morales asked a direct question in the review meeting: "How many accounts in this organization currently have more access than they need?" Nobody in the room could answer.

Robert Kim pulled a partial privileged account list the following morning. He found svc_epic_int: a Domain Admin service account whose last recorded authentication was over three years ago and whose description read "post-EHR-migration service account; no current function identified." He found t.morrison: a contractor whose engagement ended seven months ago, still enabled, still a Domain Admin. He found svc_helpdesk: granted Domain Admin during a vendor installation with the note "required per vendor; review later." Later had never come.

Helena Reyes flagged the cloud environment. Three IAM roles in the MedDefense AWS account carry AdministratorAccess. The S3 bucket used for clinical data backup has Block Public Access disabled. CloudTrail is not configured for the DR region. The IAM policy on the EHR backup automation role uses "Action": "s3:*" against "Resource": "*".

Sarah Park confirmed that MedDefense has no SSO deployment, no formal PAM program and no documented process for IAM access review.

"We need to know exactly where we stand," James Chen said. "Identity is how they got through us. Identity is how we close the gap."

Your assignment has four components. Understand SSO federation by configuring it. Audit and correct the cloud IAM posture. Implement JIT credential controls using Vault to eliminate the svc_epic_int class of risk. Then audit the full account inventory, surface every finding and produce the assessment that answers Dr. Morales's question.

---

# 0. Quiz

---

# [1. Configure SSO Federation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/keycloak_saml_config.md)

## Goal: 

Analyze a SAML 2.0 SSO integration using Keycloak evidence and produce a documented configuration reference.

## Context: 

MedDefense does not have SSO. Clinical staff authenticate to Epic, to the PACS, to the pharmacy system and to the clinical communication platform with separate credentials. When staff leave, accounts must be disabled in each system individually. During the incident, two Epic accounts belonging to departed employees were still active because the off-boarding checklist was not synchronized across all systems. A centralized IdP solves both problems: one authentication event, one off-boarding action.

Before MedDefense can evaluate an SSO deployment, the security team needs to understand the technology at the protocol level. Configuring it is the fastest way to learn it.

## Instructions

Create keycloak_saml_config.md.

Use:

    /opt/meddefense/materials/sso/keycloak_realm_export_meddefense.json
    /opt/meddefense/materials/sso/saml_assertion_d_walsh.xml
    /opt/meddefense/materials/sso/saml_assertion_r_kim.xml
    /opt/meddefense/materials/sso/saml_flow_notes.md
    /opt/meddefense/materials/sso/decoded_saml_response_reference.md

Required sections:

    # MedDefense SAML SSO Configuration Reference
    ## Realm Configuration Summary
    ## Client Configuration Summary
    ## Test Users and Role Attributes
    ## Annotated SAML Assertion: d.walsh
    ## Assertion Expiration and Replay Prevention
    ## Assertion Signing Risk Explanation
    ## Off-Boarding and Centralized Identity Impact

Required content:

    Realm meddefense
    Display name MedDefense Health Systems
    Session idle timeout 30 minutes
    Brute force protection and 5 failed attempts
    Client meddefense-portal
    ACS URL http://localhost:5000/saml/acs
    NameID format email
    Signed assertions and signed documents
    Attribute mapper MedDefenseRole
    Inline comments for Issuer, NameID, Conditions, NotBefore, NotOnOrAfter, AuthnStatement, AttributeStatement, Signature
    Paragraph on expired assertions and replay prevention
    Paragraph on assertion signing risk

---

# [2. Audit and Correct Cloud IAM Policies](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/iam_policy_analysis.md)

Goal: Identify specific least-privilege violations in three MedDefense AWS IAM policies and produce corrected policy documents with per-change justification.

Context: When MedDefense's cloud environment was provisioned two years ago, the IAM policies were written by a systems administrator optimizing for speed of deployment, not least privilege. The standard approach was: grant the broad action set needed to make something work, intend to tighten it later. Later arrived with the compliance audit. Helena Reyes flagged the policies as part of her cloud review and brought them to James Chen. He assigned you to fix them.

Each policy below is a real MedDefense configuration. Each has specific violations. Your job is to identify every violation, write the corrected policy and explain each change in terms of what attack surface the over-privilege creates and how the correction closes it.

Instructions: Create three corrected IAM policy files and one analysis document.

Create:

[iam_policies/siem_reader_policy.json](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/iam_policies/siem_reader_policy.json)

[iam_policies/ehr_backup_policy.json](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/iam_policies/ehr_backup_policy.json)

[iam_policies/break_glass_policy.json](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/iam_policies/break_glass_policy.json)

[iam_policy_analysis.md](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/iam_policy_analysis.md)

Use:

    /opt/meddefense/materials/cloud_iam/original_siem_reader_policy.json
    /opt/meddefense/materials/cloud_iam/original_ehr_backup_policy.json
    /opt/meddefense/materials/cloud_iam/original_break_glass_policy.json

Policy requirements:

    SIEM reader: only s3:GetObject, s3:ListBucket scoped to meddefense-siemlog-prod; CloudWatch Logs write only for /aws/lambda/siem-log-reader.
    EHR backup: scope S3 to meddefense-ehr-backup-prod; scope KMS to arn:aws:kms:us-east-1:123456789012:key/mrk-abc123def456; use only needed KMS actions.
    Break-glass: preserve emergency admin capability but require MFA and restrict source IP to 198.51.100.0/24; include explicit denies where appropriate.

iam_policy_analysis.md sections:

    # MedDefense IAM Policy Analysis
    ## Policy 1: MedDefenseSIEMLogReader Violations
    ## Policy 2: MedDefenseEHRBackupRole Violations
    ## Policy 3: MedDefenseBreakGlassAdmin Violations
    ## Least Privilege Summary
    ## Residual Risk and Operational Notes

---

# [3. Implement PAM Controls with HashiCorp Vault](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/vault_pam_lab.md)
### advanced

## Goal: 

Analyze Vault database secrets engine evidence and explain how TTL-based dynamic credentials eliminate static service account risk.

## Context: 

svc_epic_int was a Domain Admin service account with a static password stored in a configuration file. Nobody knew what it was for. Nobody rotated its password. When the attacker extracted credentials from memory, svc_epic_int was in the list and the attacker used it for three hours before detection. The password had not changed in three years.

The PAM model this task implements is different at the architectural level: no service account holds a standing password. When an application needs database access, it requests a credential from Vault. Vault issues a unique username and password with a defined TTL. When the TTL expires, the credential is automatically revoked at the database. If an attacker extracts the credential from memory, it is valid only until the TTL expires. There is no svc_epic_int to steal.

## Instructions:

Create [vault_pam_lab.md](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/vault_pam_lab.md).

Use:

    /opt/meddefense/materials/pam/vault_database_secrets_transcript.md
    /opt/meddefense/materials/pam/vault_lease_revoke_transcript.md
    /opt/meddefense/materials/pam/svc_epic_int_static_account_risk.md
    /opt/meddefense/materials/pam/pam_migration_candidates.csv

Required sections:

    # MedDefense Vault PAM Lab
    ## Lab Evidence Summary
    ## Dynamic Credential Demonstration
    ## Lease and TTL Evidence
    ## Revocation Evidence
    ## Static vs Dynamic Credential Comparison
    ## Migration Recommendation

Required content:

    Read-only lease ID, username and TTL
    Read-write lease ID, username and TTL
    Explanation of vault lease revoke
    Comparison table: credential lifetime, rotation method, blast radius if stolen, audit trail, off-boarding
    Migration recommendation for highest-risk service accounts

---

# [4. Write the IAM Audit Script](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/audit_iam.py)
### advanced

## Goal: 

Write a Python script that processes a structured account inventory, identifies privilege misconfigurations and dormant account risks, and produces a severity-scored findings report as structured JSON output.

## Context: 

Robert Kim exported the full MedDefense Active Directory account inventory after the post-incident review. The export covers every account with any level of privileged group membership. Running through 200 accounts manually and producing consistent findings is error-prone and slow. A script that processes the inventory, applies consistent scoring logic and produces machine-readable output is both faster and more defensible: the same logic applied to every account, documented in version-controlled code.

The script output feeds directly into Task 5. Every finding in the audit report must be traceable to a row in the inventory and a check in the script.

## Instructions: 

Write audit_iam.py to process account inventory and produce severity-scored JSON findings.

### Copy:

cp /opt/meddefense/materials/iam_audit/accounts.csv ./accounts.csv

### Implement:

check_dormant_privileged(account, dormancy_threshold_days=90)
check_mfa_coverage(account)
check_service_account_overpriv(account)
check_departed_or_transferred(account)
check_disabled_with_groups(account)
check_no_mfa_high_risk(account)

### Required behavior:

    Read accounts.csv
    Process 20 accounts
    Write iam_findings.json
    Include audit_metadata, accounts_processed, audit_timestamp, and severity counts
    Generate finding IDs such as IAM-001
    Print a human-readable summary to stdout

**Script requirements**

audit_iam.py must implement the following checks in defined, named functions:

check_dormant_privileged(account, dormancy_threshold_days=90): flags any account (user or service) with membership in Domain Admins or Server Admins whose last_login_days_ago exceeds the threshold and whose account_type is user. Service accounts with last_login_days_ago exceeding 365 days are flagged separately as dormant_service_privileged.

check_mfa_coverage(account): flags any enabled user account with membership in Domain Admins or Server Admins where mfa_enrolled is FALSE.

check_service_account_overpriv(account): flags any service account with Domain Admins membership. Server Admins on service accounts is Medium severity; Domain Admins is Critical.

check_departed_or_transferred(account): scans the description field for keywords including "contract ended", "left organization", "transferred from" and "migration complete" and flags the account for manual review with the matched keyword.

check_disabled_with_groups(account): flags any account where enabled is FALSE but privileged_groups is not empty.

check_no_mfa_high_risk(account): flags enabled user accounts with mfa_enrolled as FALSE regardless of privilege level, with Low severity; escalate to Medium if the description references repeated security failures.

### Output format

The script must write findings to iam_findings.json with this structure:

```json
{
  "audit_metadata": {
    "script_version": "1.0",
    "accounts_processed": 20,
    "audit_timestamp": "2026-04-28T10:00:00Z",
    "findings_count": {
      "Critical": 0,
      "High": 0,
      "Medium": 0,
      "Low": 0
    }
  },
  "findings": [
    {
      "finding_id": "IAM-001",
      "account": "svc_epic_int",
      "check": "check_service_account_overpriv",
      "severity": "Critical",
      "title": "Service account with Domain Admin membership and no documented function",
      "evidence": "account_type=service; privileged_groups=Domain Admins; last_login_days_ago=1156; description=Post-EHR-migration service account; no current function identified",
      "remediation": "Disable immediately; audit all actions taken under this account in the past 90 days; remove Domain Admins membership; if no function confirmed within 30 days, delete the account"
    }
  ]
}
```

The script must also print a human-readable summary to stdout after writing the JSON:

```bash
Accounts processed : 20
Critical findings  : X
High findings      : X
Medium findings    : X
Low findings       : X

Critical:
  [IAM-001] svc_epic_int: Service account with Domain Admin membership and no documented function
  ...

High:
  ...
```

Run the script and verify the output before submitting. The findings count must match the actual inventory issues; if your script misses a finding present in the data, the audit report in Task 5 will be incomplete.

Expected outputs:

    accounts.csv
    audit_iam.py
    iam_findings.json
    
---

# [5. Write the IAM Audit Report](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/iam_audit_report.md)

## Goal: 

Produce a professional IAM audit report that documents every finding from iam_findings.json with severity rating, evidence, patient safety or regulatory consequence and specific remediation action, ordered so the CISO knows exactly what to fix first.

## Context: 

The script produces the evidence. The report produces the argument for action. James Chen will take this report to Dr. Morales with a proposed remediation plan. The report must speak clearly to non-technical stakeholders where the consequences matter, and precisely to the systems administrators who will execute the remediations. It must not require the reader to have seen the inventory data or the script output to understand the findings.

## Instructions: 

Create iam_audit_report.md using the structure below. Every finding must reference the specific row in accounts.csv that produced it. Every severity rating must be justified. Every remediation must be specific: not "remove excessive permissions" but "remove svc_helpdesk from the Domain Admins group; verify that helpdesk automation functions continue to operate with Helpdesk group membership only; document the verification result."

Use:

    accounts.csv
    audit_iam.py
    iam_findings.json
    /opt/meddefense/materials/iam_audit/severity_model.md
    /opt/meddefense/materials/iam_audit/incident_identity_path.md

**Required structure:**

<pre>
# MedDefense IAM Audit Report
**Classification:** Confidential
**Audit date:** [Date]
**Prepared by:** [Your name]
**Reviewed by:** James Chen, SOC Lead
**Approved by:** _________________________ Date: _________

## Executive Summary
[3 paragraphs: overall posture, most critical finding, 
 connection to the prior incident and what the audit changes]

## Audit Scope and Methodology
[What was audited, what was out of scope, how findings were classified,
 how severity was assigned]

## Findings Summary Table
| Finding ID | Account | Category | Severity | Status |
|---|---|---|---|---|
| IAM-001 | svc_epic_int | Service account over-privilege | Critical | Open |
| ... | ... | ... | ... | ... |

## Detailed Findings

### IAM-001: [Title]
**Account:** svc_epic_int
**Severity:** Critical
**Check:** Service account privilege review
**Evidence:** [Specific fields from accounts.csv that support this finding]
**Risk:** [What an attacker can do with this access and what the patient safety or regulatory consequence is]
**Remediation:** [Specific, numbered steps; not a category description]
**Owner:** [Role]
**Target completion:** [Relative date: immediate / 7 days / 30 days]

[Continue for every finding in iam_findings.json]

## MFA Coverage Analysis
[Counts: privileged accounts with MFA / without MFA; 
 percentage; comparison against HIPAA 164.312(d) requirements for unique user ID]

## Service Account Risk Summary
[All service accounts with Domain Admin or Server Admin membership;
 whether each has a documented function; recommendation for each]

## Remediation Roadmap
[Prioritized action table: Priority | Action | Owner Role | Target | Success Criterion]

## Appendix: Audit Script
[Reference to audit_iam.py and iam_findings.json as source evidence]
</pre>

The executive summary must connect at least one finding directly to the lateral movement path used in the Cobalt Strike incident. The report must not name the attacker or frame the findings as speculative: frame them as current-state organizational risk.

---

# [6. Assess the Cloud Security Posture](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/cloud_security_assessment.md)

## Goal: 

Review the current state of MedDefense's AWS IAM configuration against CIS AWS Foundations Benchmark controls, produce a structured findings table and write specific remediation recommendations for every gap.

## Context: 

Helena Reyes completed a manual walk-through of the MedDefense AWS environment as part of the post-incident cloud review. She documented 10 specific configuration states below. None of them have been formally assessed against a benchmark. Three of them create direct ePHI exposure or unrestricted administrative access. This assessment converts her observations into a structured, auditable record.

## Instructions: 

Review each environment observation below against the CIS AWS Foundations Benchmark v3.0 control it maps to. For each observation, document the specific CIS control, the finding severity, the compliance status and a specific remediation with the exact AWS console or CLI action required.

MedDefense AWS environment observations

| # | Observation |
| --- | --- |
| 1 | AWS root account has no MFA configured; root access keys were created on 2022-03-15 and have never been deleted |
| 2 | Seven IAM users have AWS console access; four have MFA enrolled; three do not |
| 3 | Four IAM users have long-lived programmatic access keys; two of those keys were created more than 22 months ago and have no documented rotation schedule |
| 4 | IAM password policy: minimum 8 characters; no complexity requirement; no expiration; no MFA requirement for console login |
| 5 | CloudTrail is enabled in us-east-1; not enabled in us-east-2 (the DR region where clinical backup S3 buckets reside) |
| 6 | S3 bucket meddefense-clinical-backup-2022: Block Public Access is disabled; the bucket policy contains "Principal": "*" for s3:GetObject; this bucket contains ePHI backup archives |
| 7 | Three IAM roles carry the AWS-managed AdministratorAccess policy: MedDefenseDevRole, MedDefenseLegacyRole and MedDefenseVendorAccess |
| 8 | VPC Flow Logs are not enabled on any VPC |
| 9 | IAM role MedDefenseEHRBackupRole uses the policy corrected in Task 2 (pre-correction state: s3:* on Resource: *) |
| 10 | AWS Organizations is not configured; no Service Control Policies exist |

Create [cloud_security_assessment.md](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x02_iam_scale/cloud_security_assessment.md).

Use:

    /opt/meddefense/materials/cloud_iam/aws_environment_observations.md
    /opt/meddefense/materials/cloud_iam/cis_aws_control_map.md
    Corrected policies from Task 2

Required sections:

    # MedDefense Cloud Security Assessment
    ## Assessment Scope
    ## Findings Table
    ## Critical Findings
    ## Remediation Priority Order
    ## Estimated Effort

Assess all ten observations:

    Root account has no MFA and root access keys exist
    IAM console MFA coverage incomplete
    Long-lived access keys
    Weak password policy
    CloudTrail not enabled in DR region
    Public ePHI backup S3 bucket
    Roles with AdministratorAccess
    VPC Flow Logs disabled
    EHR backup role had s3:* on Resource: *
    AWS Organizations and SCPs not configured

For Observation 6, explain Principal: "*", s3:GetObject, ePHI exposure and HIPAA Breach Notification Rule terminology under 45 CFR 164.402.

---
