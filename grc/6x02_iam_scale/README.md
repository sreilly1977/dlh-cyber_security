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
