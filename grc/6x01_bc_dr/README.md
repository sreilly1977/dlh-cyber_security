# Introduction

> "The time to repair the roof is when the sun is shining."
>
> — John F. Kennedy

At 2:47 AM on a Tuesday in February, MedDefense's primary data center loses power. The generator starts. The UPS holds. Then the cooling system fails. By 3:15 AM, three critical servers are offline. Epic EHR is unreachable. Lab results from the overnight shift cannot be accessed. The charge nurse in the ICU is on hold with the help desk. A physician needs medication history for a patient who is deteriorating.

This is not a hypothetical. Healthcare organizations that have never tested their recovery procedures often discover that the difference between written plans and real recovery is measured in clinical risk, not only in minutes.

This project closes that gap before a real crisis opens it. You will build a Business Impact Analysis that prioritizes systems by patient safety consequence, design a backup architecture that can actually satisfy stated recovery objectives, write command-level recovery runbooks, execute a timed LIS recovery test inside the provided lab container, and convert the recovery gap into a board-ready remediation package.

The answer to disaster recovery is almost never "the plan worked exactly as written." The professional answer is: what did the plan promise, what did the test prove, what changed afterward, and what evidence supports that claim?

## Context

The HHS OCR desk audit preparation surfaced a gap more operationally dangerous than any missing policy: MedDefense has never tested its disaster recovery plan. The existing DR documentation predates the Epic EHR migration, does not account for the Laboratory Information System modernization completed last year, and references backup infrastructure that was decommissioned eighteen months ago.

James Chen escalated this to Dr. Morales immediately. Her response was direct: "I am not going to tell an auditor we have a DR plan and then have them ask when we last tested it and have no answer. Fix it."

Sarah Park pulled the existing documentation. It was 47 pages. It referenced a physical tape library in the basement that was replaced with cloud backup in 2024. The RTO for Epic EHR was listed as four hours, with no evidence that anyone had ever attempted to verify that number.

Robert Kim ran a check against the backup logs. In three cases, the declared RPO was shorter than the backup frequency. On paper, MedDefense was promising to recover data that the backup schedule mathematically could not preserve. A plan that fails arithmetic is not a plan.

Your assignment covers three things: build a defensible BIA, write a DR plan that reflects current infrastructure, and run a real recovery test against the Laboratory Information System using the provided containerized lab artifacts. The LIS was chosen as the test target because it has a clean backup chain and is critical enough to be meaningful without requiring students to manage Docker, MariaDB, or cloud infrastructure during the exercise.

The results will be presented to Dr. Morales and the Board Risk Committee next month. You are not being asked to produce documents only. You are being asked to produce evidence.

---

# 0. Quiz

---

# [1. Build the Business Impact Analysis](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/business_impact_analysis.md)

## Goal: 

Produce a signed BIA document that classifies every critical MedDefense system by patient safety consequence, regulatory obligation, revenue exposure and operational dependencies, and assigns defensible RTO, RPO and MTD values.

## Context

The gap between the old DR plan and operational reality starts here. Whoever wrote the previous BIA listed systems as "critical" or "non-critical" without explaining what made them so. Sarah Park needs a document that answers one question for every system: if this goes down at 2 AM on a Tuesday, what breaks, what is the patient safety consequence, and how long can we be down before the harm is irreversible?

## Instructions

Create business_impact_analysis.md.

Use the provided materials:

    /opt/meddefense/materials/bia/meddefense_system_inventory.csv
    /opt/meddefense/materials/bia/downtime_impact_notes.md
    /opt/meddefense/materials/bia/regulatory_reference_map.md
    /opt/meddefense/materials/backup_architecture/dependency_map_seed.md

Assess these ten MedDefense systems:

    Active Directory
    Epic EHR
    Laboratory Information System
    PACS/RIS
    Pharmacy Dispensing System
    Medical Device Integration Gateway
    Network Core
    Email and Secure Messaging
    Backup and DR Infrastructure
    Security Operations Platform

For each system, document:

    Patient Safety Impact at 1 hour, 4 hours and 24 hours
    Regulatory Impact with specific HIPAA, Joint Commission or reporting references
    Revenue Impact as an estimated exposure per hour
    Operational Dependencies and downstream failure sequence
    Maximum Tolerable Downtime
    Recovery Time Objective
    Recovery Point Objective
    Priority Tier: Tier 1, Tier 2, Tier 3 or Tier 4

Required structure:

<pre>
# MedDefense Business Impact Analysis

**Version:** 1.0
**Classification:** Confidential
**Prepared by:** [Your name]
**Date:** [Date]
**CISO approval:** _________________________ Date: _________

## Executive Summary

## Methodology

## System Impact Assessment

## Dependency Map

## RTO / RPO / MTD Summary Table

## Assumptions and Limitations
</pre>

Quality Requirements

    Every RTO must be lower than the system MTD.
    Every RPO must be stated in time.
    The LIS must be treated as a Tier 1 or Tier 2 system.
    Active Directory and Network Core must appear in the dependency map.
    Generic statements such as "operations are affected" are not sufficient.

---

# [2. Design the Backup Architecture](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/backup_architecture.md)

## Goal: 

Design a specific, implementable backup strategy for each Tier 1 and Tier 2 system that satisfies the RTO and RPO values from the BIA, and produce a dependency-aware restoration sequence for a full data center loss scenario.

## Context

The BIA produces the requirements. This task produces the architecture that meets them. Robert Kim's log review found three cases where the declared RPO was shorter than the backup frequency. The backup architecture must show the math: if a system has an RPO of 1 hour, the backup schedule must produce a verified recovery point no older than 1 hour.

## Instructions

Create backup_architecture.md.

Use the provided materials:

    /opt/meddefense/materials/backup_architecture/current_backup_schedule.csv
    /opt/meddefense/materials/backup_architecture/backup_log_review_findings.md
    /opt/meddefense/materials/backup_architecture/dependency_map_seed.md
    Your business_impact_analysis.md

For each Tier 1 and Tier 2 system in your BIA, include a per-system backup specification table with these fields:

|Field | Required Content |
| --- | --- |
| Backup type | Full, incremental, differential, snapshot or combination |
| Schedule | Exact frequency per backup type |
| Retention | Recent, monthly and archive retention |
| Primary destination | On-site location and storage type |
| Secondary destination | Off-site or cloud location |
| Encryption at rest | AES-256 and key management approach |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Hash and restore-test method |
| Restoration sequence | Ordered recovery steps |
| Responsible role | Who executes and who verifies |

Required sections:

<pre>
# MedDefense Backup Architecture

## Strategy Overview

## RPO Compliance Verification

## Per-System Backup Specifications

## Full Data Center Loss: Restoration Sequence

## Dependency Restore Constraints
</pre>

Quality Requirements

    The RPO Compliance Verification table is mandatory.
    No Tier 1 system may have a backup frequency longer than its declared RPO.
    Every Tier 1 system must have geographically separate backup storage.
    Every ePHI backup must specify AES-256 at rest and TLS 1.2 or later in transit.
    Restoration order must be dependency-based, not alphabetical.

---

# [3. Write the Recovery Runbooks](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/recovery_runbooks.md)

## Goal: 

Produce command-level recovery runbooks for two Tier 1 systems: the Laboratory Information System and Active Directory single DC loss with secondary DC available.

## Context

A runbook that says "restore the database from backup" is not a runbook. The administrator executing a recovery under incident conditions needs the exact command, expected output, verification step and deviation handling.

This rebuilt lab uses a prepared SQLite-based LIS simulation instead of Docker Compose and MariaDB. The learning objective remains the same: write a recovery runbook that can be executed and tested.

## Instructions

Create recovery_runbooks.md containing two complete runbooks.

Use the provided materials:

    /opt/meddefense/materials/runbooks/old_lis_recovery_runbook.md
    /opt/meddefense/materials/runbooks/old_ad_recovery_notes.md
    /opt/meddefense/materials/runbooks/command_output_examples.md
    /opt/meddefense/materials/recovery_test/lab_config.env
    /opt/meddefense/materials/recovery_test/app_config.env

Runbook 1: Laboratory Information System Recovery

The rebuilt lab simulates the LIS database as a SQLite database restored from a compressed SQL backup.

Backup location:

/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz

Manifest location:

/tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256

Recovery target:

/tmp/meddefense-dr-test/recovery/lis_recovered.db

Application config:

/tmp/meddefense-dr-test/config/app_config.env

The old runbook incorrectly refers to /recovery/lis_dump.sql. You must preserve that expected deviation in the runbook as a known failure mode and include the corrected command for the actual lab environment.

Your LIS runbook must cover:

    Identify the latest recovery target.
    Verify backup integrity with sha256sum -c.
    Create the recovery workspace.
    Decompress the backup to the correct staging path.
    Restore the SQL dump into SQLite.
    Check the row count in patient_orders.
    Confirm the critical results for MRN-10043 and MRN-10045.
    Inspect app_config.env and identify DB_HOST=lis-db-prod.meddefense.internal as a configuration artifact.
    Apply the local recovery override by using the local SQLite recovery database path in the validation command.
    Record notification content for the clinical team.

Each step must include:

    Command or action
    Expected output
    Verification check
    Deviation handling

Runbook 2: Active Directory Recovery

MedDefense runs two domain controllers: DC01 and DC02. This runbook covers confirmed unrecoverable loss of DC01 with DC02 healthy.

Write the runbook from the point where the administrator has confirmed DC01 is unrecoverable and DC02 is responding normally.

Include, in this order:

    netdom query fsmo to document current FSMO role holders.
    Authoritative versus non-authoritative restore decision with criteria.
    wbadmin start systemstaterecovery command sequence.
    repadmin /showrepl health check.
    dcdiag validation sequence.
    Recovery declaration criteria.

Because the lab container is Linux-based, the AD runbook is documentation-only. Use command output examples from:

/opt/meddefense/materials/runbooks/command_output_examples.md

---
