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

# [4. Write the Clinical Downtime Procedures](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/clinical_downtime_procedures.md)

## Goal:

Produce one-page quick-reference documents for clinical staff covering Epic EHR unavailability and LIS unavailability.

## Context

Technical recovery runbooks assume IT staff are solving the outage. Clinical downtime procedures assume nurses, lab technicians and physicians must continue care while IT is unavailable. These documents must be usable by clinical staff without IT knowledge.

## Instructions

Create clinical_downtime_procedures.md.

Use the provided materials:

    /opt/meddefense/materials/downtime/nursing_station_locations.md
    /opt/meddefense/materials/downtime/paper_forms_inventory.md
    /opt/meddefense/materials/downtime/clinical_escalation_contacts.md

Create two quick references:

    Epic EHR Downtime Procedures
    Laboratory Information System Downtime Procedures

Each quick reference must:

    Be 350 to 500 words
    Use clear numbered steps
    Avoid IT terminology
    Identify who declares downtime
    Identify where paper forms are physically located
    Include escalation path
    Include reconciliation steps after restoration
    Bold the most critical actions

---

# [5. Execute the Recovery Test](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/recovery_timer.sh)

## Goal: 

Execute a timed recovery of the Laboratory Information System against a simulated failure, document every deviation as it occurs and produce a test record showing actual wall-clock time against the declared RTO of 30 minutes.

## Context

The declared RTO for the MedDefense LIS is 30 minutes. James Chen has scheduled the recovery test and made one thing clear:

    "I do not want a report that says everything went fine. I want to know what the plan got wrong."

This rebuilt lab removes Docker-in-Docker. The LIS recovery target is a SQLite database restored from a compressed SQL backup already staged in the lab container.

Step 1: Write the Timing Script

Create recovery_timer.sh.

The script must:

    Accept a step name and status: START, PASS, FAIL or SUMMARY.
    Record timestamps with date '+%H:%M:%S'.
    On PASS or FAIL, compute elapsed time for that step in minutes and seconds.
    Write completed steps to recovery_test_log.txt as they complete.
    Store state in /tmp/rtest_state.
    Print total elapsed time and PASS/FAIL against the 30-minute RTO when called with SUMMARY.

Example usage:

./recovery_timer.sh "Verify backup integrity" START
./recovery_timer.sh "Verify backup integrity" PASS
./recovery_timer.sh SUMMARY

Expected log format:

[STEP 01] Identify recovery target     | Start: 09:14:32 | End: 09:15:18 | Duration: 0m 46s | PASS
[STEP 02] Verify backup integrity      | Start: 09:15:18 | End: 09:16:05 | Duration: 0m 47s | PASS

Step 2: Confirm the Prepared Test Environment

Do not run Docker commands.

Confirm these files exist:

ls -l /tmp/meddefense-dr-test/backup/lis/2026-04-21/
ls -l /tmp/meddefense-dr-test/config/

Required files:

/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz
/tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256
/tmp/meddefense-dr-test/config/app_config.env

Step 3: Execute the Recovery

Follow your LIS runbook from Task 3. Call recovery_timer.sh at the start and end of each numbered recovery step.

You must encounter and document these three conditions:

Condition 1: Path mismatch

The old runbook specifies the backup decompresses to:

/recovery/lis_dump.sql

The actual lab path must be:

/tmp/meddefense-dr-test/recovery/lis_dump.sql

Document what the runbook got wrong, then correct your command.

Condition 2: Configuration artifact

Before validating the restored LIS, inspect:

/tmp/meddefense-dr-test/config/app_config.env

It contains:

DB_HOST=lis-db-prod.meddefense.internal

For the lab recovery, the validation must use the local SQLite recovery database path instead. Document the configuration artifact and the local override you applied.

Condition 3: Row count check

After restore, run:

sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"

Expected result:

5

Document the result exactly.

Required Recovery Commands

The exact commands may vary if your runbook is more detailed, but the recovery must include these actions:

sha256sum -c /tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256

mkdir -p /tmp/meddefense-dr-test/recovery

gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz \
  > /tmp/meddefense-dr-test/recovery/lis_dump.sql

sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db \
  < /tmp/meddefense-dr-test/recovery/lis_dump.sql

sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db \
  "SELECT COUNT(*) FROM patient_orders;"

sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db \
  "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045');"

Produce the Test Record

Create recovery_test_record.md.

Required structure:

<pre>
# LIS Recovery Test Record

**Test date:** [Date]
**Test conductor:** [Your name]
**Declared RTO:** 30 minutes
**Test environment:** /tmp/meddefense-dr-test/

## Step Timing Log

[Full output from recovery_test_log.txt and recovery_timer.sh SUMMARY]

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** [Timestamp]
**Runbook specified:** /recovery/lis_dump.sql
**Actual path:** /tmp/meddefense-dr-test/recovery/lis_dump.sql
**Resolution:** [Exact commands executed]
**Time added:** [Minutes]

### Condition 2: Configuration artifact

**Discovered at:** [Timestamp]
**Expected:** Local recovery database path for validation
**Actual:** DB_HOST=lis-db-prod.meddefense.internal
**Resolution:** [Exact override or validation command used]
**Time added:** [Minutes]

### Condition 3: Row count check

**Query:** SELECT COUNT(*) FROM patient_orders;
**Expected:** 5
**Actual:** [Your result]
**Outcome:** PASS / FAIL

## Recovery Validation

**Recovered database file:**

[Paste ls -l output]

**Critical values accessible:**

[Paste query output confirming MRN-10043 K+ 6.1 mEq/L and MRN-10045 Troponin 0.08 ng/mL exist]

## Test Result

**Actual recovery time:** [From timer log]
**RTO met:** YES / NO
**Test outcome:** PASS / CONDITIONAL PASS / FAIL
</pre>

**Expected Outputs**

    recovery_timer.sh
    recovery_test_log.txt
    recovery_test_record.md
    /tmp/meddefense-dr-test/recovery/lis_recovered.db

---

# [6. Analyze the Gap](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/gap_analysis.md)
### advanced

## Goal: 

Produce a formal gap analysis that identifies the root cause of every recovery deviation, quantifies the patient safety consequence of each additional minute of delay and delivers an updated runbook that corrects every deficiency the test revealed.

## Context

The test is done. You have two numbers: what the plan promised and what reality delivered. The gap between them is not a failure of execution. It is a failure of planning, and planning is what you can fix.

## Instructions

Create gap_analysis.md.

Use:

    Your business_impact_analysis.md
    Your recovery_runbooks.md
    Your recovery_test_record.md
    /opt/meddefense/materials/recovery_test/condition_cards.md

Required sections:

<pre>
# LIS Recovery Gap Analysis

## Test Summary Table

## Condition Analysis

## Runbook Deficiencies

## Revised RTO

## Updated LIS Recovery Runbook

## Remediation Roadmap
</pre>

Required Content

Test Summary Table

Include:

    Declared RTO
    Actual recovery time
    Delta in minutes
    Overall test result

Condition Analysis

For each condition, document:

    Condition title
    Category: Runbook Error, Environment Assumption, Configuration Drift, Documentation Gap or Training Gap
    Root cause
    Patient safety consequence tied to the LIS downtime thresholds in your BIA
    Time added in minutes

Runbook Deficiencies

List specific deficiencies. Do not write generic statements.

## Example:

Step 4 specifies /recovery/lis_dump.sql, but the lab recovery environment stages the decompressed file at /tmp/meddefense-dr-test/recovery/lis_dump.sql.

Revised RTO

Recommend a revised or corrected RTO based on evidence from the test.

If the corrected recovery process can meet 30 minutes, explain which changes make that possible. If it cannot, state that the BIA must be updated honestly.

Updated Runbook

Provide a complete corrected LIS Recovery Runbook. Mark every changed step with [UPDATED].

Remediation Roadmap

Minimum five actions:

| Priority | Action | Owner Role | Target Completion | Success Criterion |
| --- | --- | --- | --- | --- |

---

# [7. Package the DR Program](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/dr_plan_master.md)
### advanced

## Goal: 

Produce the master DR plan document and a one-page CISO brief that consolidate all program deliverables into an auditable package satisfying HIPAA 164.308(a)(7).

## Context

Dr. Morales needs to sign off on the DR program and present the recovery test results to the Board Risk Committee. She also needs to demonstrate that MedDefense has a tested contingency plan.

## Instructions

Create two documents:

    [dr_plan_master.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/dr_plan_master.md)
    [ciso_dr_brief.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/ciso_dr_brief.md)

Use:

    business_impact_analysis.md
    backup_architecture.md
    recovery_runbooks.md
    clinical_downtime_procedures.md
    recovery_test_record.md
    gap_analysis.md
    /opt/meddefense/materials/package/hipaa_164_308_a7_reference.md
    /opt/meddefense/materials/package/board_brief_template.md

Document 1: [dr_plan_master.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/dr_plan_master.md)

Target length: 3 to 5 rendered pages.

Include:

    Program scope
    Covered systems, sites and scenarios
    Explicit exclusions
    Roles and responsibilities table
    Activation criteria with at least four triggerable conditions
    Communication plan with ordered notification sequence
    Program document index
    Testing and revision schedule
    CISO sign-off block

Required document index:

| Document | Filename | Version | Last Updated | Last Tested |
| --- | --- | --- | --- | --- |
| Business Impact Analysis | businessimpactanalysis.md | 1.0 | [Date] | N/A |
| Backup Architecture | backup_architecture.md | 1.0 | [Date] | N/A |
| Recovery Runbooks | recovery_runbooks.md | 1.0 | [Date] | [Date] |
| Clinical Downtime Procedures | clinicaldowntimeprocedures.md | 1.0 | [Date] | N/A |
| Recovery Test Record (LIS) | recoverytestrecord.md | 1.0 | [Date] | [Date] |
| Gap Analysis | gap_analysis.md | 1.0 | [Date] | N/A |

Document 2: [ciso_dr_brief.md](https://github.com/sreilly1977/dlh-cyber_security/tree/main/grc/6x01_bc_dr/ciso_dr_brief.md)

One page. Audience: Dr. Morales and the Board Risk Committee.

Include, in this order:

    Program status
    Key BIA finding
    Recovery test result
    Items requiring board action or budget
    Open items with owner and date
    Recommended board resolution

Required board resolution wording:

The Board Risk Committee acknowledges receipt of the MedDefense DR Program Status Report dated [Date] and authorizes [specific action with resource commitment if applicable].

Expected Outputs

    dr_plan_master.md
    ciso_dr_brief.md

---
