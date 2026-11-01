# MedDefense Recovery Runbooks

**Version:** 1.0
**Classification:** Confidential
**Prepared by:** Steve, IT Security
**Date:** 2026-11-01

Replaces the retired LIS recovery runbook (which referenced the removed Docker/MariaDB stack) and the incomplete Active Directory recovery notes version 0.5.

---

# Runbook 1: Laboratory Information System Recovery

## Scope

Recovery of the MedDefense Laboratory Information System database from the nightly compressed SQL backup into the local SQLite recovery environment. Declared RTO for this test: 30 minutes (per `lab_config.env`, `DECLARED_RTO_MINUTES=30`). Expected recovered row count: 5.

This runbook preserves a known failure mode inherited from the old runbook: the old document stages the SQL dump at `/recovery/lis_dump.sql`, which does not exist in the current environment. The correct staging path is `/tmp/meddefense-dr-test/recovery/lis_dump.sql`. Any executor following the old document will fail at the decompression step; Step 4 below includes both the failing legacy path and the corrected command.

## Environment Constants

| Variable | Value | Source |
|---|---|---|
| Backup file | `/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz` | `lab_config.env` |
| Manifest file | `/tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256` | `lab_config.env` |
| Staged SQL path | `/tmp/meddefense-dr-test/recovery/lis_dump.sql` | `lab_config.env` |
| Recovery database | `/tmp/meddefense-dr-test/recovery/lis_recovered.db` | `lab_config.env` |
| Application config | `/tmp/meddefense-dr-test/config/app_config.env` | `app_config.env` |
| Declared RTO | 30 minutes | `lab_config.env` |
| Expected row count | 5 | `lab_config.env`, `expected_lis_records.txt` |

## Step 1: Identify the Latest Recovery Target

**Command or action:**

```bash
ls -l /tmp/meddefense-dr-test/backup/lis/
```

**Expected output:** A dated backup directory, most recently `2026-04-21`, containing `lis_backup.sql.gz` and `backup_manifest.sha256`.

**Verification check:** The newest dated directory matches the value of `BACKUP_DATE` in `lab_config.env` (`2026-04-21`). Both the dump and the manifest are present and non-empty.

**Deviation handling:** If the expected directory or files are absent, do not proceed with a partial or older backup silently. Record the discrepancy, notify the IT Incident Commander (extension 7200), and quantify the actual data loss window against the declared RPO before selecting any older recovery point. If multiple dated directories exist, use the newest one that passes Step 2 verification, and document the age of the selected recovery point for the test record.

## Step 2: Verify Backup Integrity

**Command or action:**

```bash
cd /tmp/meddefense-dr-test/backup/lis/2026-04-21
sha256sum -c backup_manifest.sha256
```

**Expected output:**

```text
lis_backup.sql.gz: OK
```

**Verification check:** The manifest reports `OK` for the backup file. Per Finding 4 of the backup log review, hash validation is the minimum verification gate; a backup that has not passed hash validation must not be restored.

**Deviation handling:** If the check reports `FAILED`, stop. Do not attempt to restore a corrupted dump. Record the failure, escalate to the Laboratory Systems Lead and the Infrastructure Manager, and select the next most recent backup that passes verification, documenting the extended data loss window. A hash failure also indicates a backup pipeline defect that must be remediated after recovery.

## Step 3: Create the Recovery Workspace

**Command or action:**

```bash
mkdir -p /tmp/meddefense-dr-test/recovery
mkdir -p /tmp/meddefense-dr-test/validation
```

**Expected output:** No output on success. Directories exist afterward.

**Verification check:**

```bash
ls -ld /tmp/meddefense-dr-test/recovery /tmp/meddefense-dr-test/validation
```

Both directories are listed.

**Deviation handling:** If directories already exist from a previous attempt, do not delete the workspace mid-recovery; the command is idempotent and safe to rerun. If a prior partially restored `lis_recovered.db` exists, move it aside with a timestamp rather than overwriting, so failed attempt evidence is preserved.

## Step 4: Decompress the Backup to the Staging Path

**Known failure mode from the old runbook:** The retired runbook's decompression step targets `/recovery/lis_dump.sql`. That path does not exist in the current environment. Executing the legacy command fails with a permission or nonexistent-directory error. The correct staging path is `/tmp/meddefense-dr-test/recovery/lis_dump.sql`.

**Legacy command (fails, retained for the record):**

```bash
gunzip -c /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /recovery/lis_dump.sql
```

**Corrected command:**

```bash
gunzip -c /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Expected output:** No output on success. The staged SQL file exists and is non-empty.

**Verification check:**

```bash
ls -lh /tmp/meddefense-dr-test/recovery/lis_dump.sql
head /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

The file has non-zero size, and the head shows readable SQL text.

**Deviation handling:** If the legacy command was executed and failed, no harm occurred; proceed with the corrected path. If the corrected file is empty or unreadable, the gzip archive is corrupt despite passing the hash check; return to Step 2, re-verify, and escalate.

## Step 5: Restore the SQL Dump into SQLite

**Command or action:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db < /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Expected output:** No output on success for a clean dump.

**Verification check:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db ".tables"
```

Expected listing includes `patient_orders` among the recovered tables.

**Deviation handling:** If sqlite3 reports SQL errors mid-restore, the dump is partially applied. Move the partial database aside, re-run Steps 4 and 5 cleanly, and record the error text. Do not validate a partially restored database. Note the elapsed time against the 30-minute RTO clock.

## Step 6: Check the Row Count in patient_orders

**Command or action:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
```

**Expected output:**

```text
5
```

**Verification check:** The returned value is `5`, matching `EXPECTED_ROW_COUNT` in `lab_config.env` and `expected_lis_records.txt`. This is also the healthcheck query defined in `app_config.env` (`HEALTHCHECK_QUERY`).

**Deviation handling:** A count lower than 5 indicates an incomplete restore or an older recovery point; do not declare recovery. A count higher than 5 indicates an unexpected data state; freeze the database, preserve it as evidence, and escalate. Record the actual count honestly in the test record either way; a recovery that misses its expected state must be reported as such.

## Step 7: Confirm the Critical Results for MRN-10043 and MRN-10045

**Command or action:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT * FROM patient_orders WHERE mrn='MRN-10043';"
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT * FROM patient_orders WHERE mrn='MRN-10045';"
```

**Expected output:**

```text
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

**Verification check:** Both required critical records are present with critical flag `1`, matching `expected_lis_records.txt` and the documented output format in `command_output_examples.md`. The potassium for MRN-10043 (K+ 6.1 mEq/L) and the troponin for MRN-10045 are critical results; their absence from the recovered database is a patient safety issue, not merely a validation failure.

**Deviation handling:** If either record is missing or the critical flag is not `1`, the recovery is incomplete from a clinical perspective regardless of row count. Do not release the database. Preserve the state, escalate to the Laboratory Systems Lead and the clinical escalation path (accessioning extension 7500, chemistry lead extension 7510), and document the missing record. Per the critical value process, both results require documented notification with read-back once confirmed present.

## Step 8: Inspect app_config.env and Identify the Configuration Artifact

**Command or action:**

```bash
cat /tmp/meddefense-dr-test/config/app_config.env
```

**Expected output:**

```text
APP_ENV=recovery-test
APP_NAME=meddefense-lis
DB_HOST=lis-db-prod.meddefense.internal
DB_NAME=lis_production
RECOVERY_DB_PATH=/tmp/meddefense-dr-test/recovery/lis_recovered.db
HEALTHCHECK_QUERY=SELECT COUNT(*) FROM patient_orders;
```

**Verification check:** The file must be read in full, and the line `DB_HOST=lis-db-prod.meddefense.internal` must be identified as a configuration artifact. This value points the application at the production database host, which does not exist in the recovery environment. Validating against `DB_HOST` would attempt connection to `lis-db-prod.meddefense.internal` and fail during downtime.

**Deviation handling:** Record the artifact in the test record under configuration drift or documentation gap. Do not edit `app_config.env` in place if the environment expects it to remain pristine; the recovery override in Step 9 addresses the conflict without modifying the source file. If additional lines differ from the documented environment constants, document each as a separate finding.

## Step 9: Apply the Local Recovery Override

**Command or action:** Use the local SQLite recovery database path from `RECOVERY_DB_PATH` in `app_config.env` directly in the validation commands rather than relying on `DB_HOST`:

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT * FROM patient_orders WHERE mrn='MRN-10043' AND critical_flag=1;"
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT * FROM patient_orders WHERE mrn='MRN-10045' AND critical_flag=1;"
```

**Expected output:**

```text
5
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

**Verification check:** All three queries return the expected results using the recovery database path. The override resolves the `DB_HOST` artifact by validating directly against `/tmp/meddefense-dr-test/recovery/lis_recovered.db`, the path defined as `RECOVERY_DB_PATH`.

**Deviation handling:** If validation succeeds against the recovery path while the configured `DB_HOST` is unreachable, this confirms the configuration artifact rather than a recovery failure. Document the override used so the test record reflects how validation was performed.

## Step 10: Record Notification Content for the Clinical Team

**Command or action:** Prepare the recovery notification for the clinical team. Content must include:

- LIS recovery status: recovered or not, stated honestly against the 30-minute declared RTO, including actual elapsed time.
- Recovery point: the backup date `2026-04-21`, so clinicians know the recency of restored data.
- Validation results: row count (expected 5) and confirmation that critical results for MRN-10043 (BMP, K+ 6.1 mEq/L) and MRN-10045 (TROPONIN, 0.08 ng/mL) are present with critical flags set.
- Outstanding items: any records created after the backup that must be reconstructed from paper downtime forms (STAT requisitions, manual specimen tracking log, critical value call log).
- Contact for clinical questions: Laboratory Systems Lead, with clinical escalation per the documented path.

**Expected output:** A completed notification record with timestamp, sender identity, and distribution list.

**Verification check:** The notification accurately reflects the validation evidence, including any deviations. The record states whether the declared RTO was met or missed.

**Deviation handling:** If the recovery missed the declared RTO, the notification must say so plainly; concealing a missed RTO from the clinical team is a reporting failure compounding the technical one. If any critical record was absent at Step 7, the notification must flag the affected patients and reference the paper critical value call log for interim documentation.

---

# Runbook 2: Active Directory Recovery — Single DC Loss, Secondary DC Available

## Scope

Confirmed unrecoverable loss of DC01 with DC02 healthy, domain `meddefense.local`. This runbook begins after the administrator has confirmed DC01 is unrecoverable and DC02 is responding normally. It is documentation-only in the Linux-based lab container; command output examples are drawn from `command_output_examples.md`.

Environment: Domain `meddefense.local`, primary DC `DC01`, secondary DC `DC02`, DC01 normally holds all FSMO roles, backup path `\\backup-srv\ad-backups\DC01\`.

## Step 1: Document Current FSMO Role Holders

**Command or action:**

```text
netdom query fsmo
```

**Expected output:**

```text
Schema master               DC01.meddefense.local
Domain naming master        DC01.meddefense.local
PDC                         DC01.meddefense.local
RID pool manager            DC01.meddefense.local
Infrastructure master       DC01.meddefense.local
The command completed successfully.
```

**Verification check:** All five FSMO roles are documented before any restore action. In this scenario DC01 is lost and unrecoverable, so the output confirms all roles are held by the failed server and will require seizure or transfer to DC02.

**Deviation handling:** If any role unexpectedly shows DC02, document it and adjust the role seizure plan accordingly; roles already on DC02 do not need transfer. If the command cannot run because the querying workstation cannot reach a DC, run it from a member server with cached credentials or from DC02 directly.

## Step 2: Authoritative versus Non-Authoritative Restore Decision

**Decision criteria:**

- **Non-authoritative restore** is used when the domain's current state is valid and the problem is the loss of the server itself. The restored DC is brought back older than its replication partners, and inbound replication brings it current. This is the correct choice when DC02 is healthy and holds valid current data.
- **Authoritative restore** is used when the domain's current state is wrong and must be rolled back, such as an accidental deletion of users, groups or OUs that has already replicated to DC02. The restored DC is marked authoritative for the restored objects, forcing its state outbound to all replication partners.

In this scenario DC02 is healthy and the failure is the physical loss of DC01, not a bad directory change. However, with DC01 unrecoverable, this is a **seizure and rebuild**, not a restore-from-backup of DC01. The practical path is: seize or transfer FSMO roles to DC02, rebuild DC01 as a fresh domain controller, and let replication from DC02 populate it. A system state restore of DC01 from backup carries USN rollback risk if DC01's objects were modified after the backup; with DC02 current, rebuilding is safer.

**Decision for this scenario: non-authoritative approach via FSMO seizure to DC02 and rebuild of DC01.** Authoritative restore would only apply if a directory error had replicated to DC02, which the scenario excludes.

**Verification check:** The decision and its rationale are recorded before proceeding.

**Deviation handling:** If investigation reveals the DC01 loss was caused by a bad change that replicated to DC02 (for example mass deletion), stop and reassess; authoritative restore of the affected subtree from a system state backup becomes the correct path, and the backup timestamp versus deletion time must be compared first.

## Step 3: System State Recovery Command Sequence

With DC02 healthy and DC01 being rebuilt rather than restored, the `wbadmin` sequence applies to recovery of system state onto the replacement DC01 hardware or VM, using the most recent verified backup:

```text
wbadmin start systemstaterecovery -version:04/21/2026-01:00 -backuptarget:\\backup-srv\ad-backups\DC01 -quiet
```

**Expected output:** The system state recovery job starts, applies the backup version specified, and completes with a success summary. The version identifier must match a backup version that exists in the backup target, identified beforehand with:

```text
wbadmin get versions -backuptarget:\\backup-srv\ad-backups\DC01
```

**Verification check:** The recovery completes without errors, and the restored server boots into directory services repair or normal mode as appropriate for the chosen restore mode. Because this scenario uses the rebuild path, the restored server rejoins as a replica and receives current data from DC02.

**Deviation handling:** If the specified version does not exist, list available versions with `wbadmin get versions` and select the most recent. If the backup target is unreachable, resolve storage access before proceeding; do not improvise by promoting a DC from an unverified source. If restoring system state onto rebuilt hardware for the non-authoritative path, ensure the server is booted into Directory Services Restore Mode for the restore, then reboot normally so inbound replication reconciles it with DC02.

## Step 4: Replication Health Check

**Command or action:**

```text
repadmin /showrepl
```

**Expected output:**

```text
Default-First-Site-Name\DC01
==== INBOUND NEIGHBORS ======================================
DC=meddefense,DC=local
    Default-First-Site-Name\DC02 via RPC
        Last attempt @ 2026-04-21 09:42:13 was successful.
```

**Verification check:** Inbound replication from DC02 is listed and the last attempt is successful, with no replication backlog or errors. The timestamp is recent.

**Deviation handling:** If the last attempt failed or replication is backlogged, do not proceed to validation. For a rebuilt DC01 receiving initial population, allow the initial synchronization to complete; this can take time proportional to the directory size. If errors persist, check network reachability to DC02, then RPC health, before considering further recovery action.

## Step 5: dcdiag Validation Sequence

**Command or action:**

```text
dcdiag
```

**Expected output:**

```text
Testing server: Default-First-Site-Name\DC01
Starting test: Connectivity
......................... DC01 passed test Connectivity
Starting test: SysVolCheck
......................... DC01 passed test SysVolCheck
Starting test: NetLogons
......................... DC01 passed test NetLogons
```

**Verification check:** DC01 passes Connectivity, SysVolCheck and NetLogons, and the full dcdiag suite completes with the remaining tests passing. SysVolCheck confirms group policy replication is intact; NetLogons confirms the domain controller is servicing authentication.

**Deviation handling:** If any test fails, resolve the specific failure before declaring recovery. Connectivity failures point to network or DNS issues; SysVolCheck failures point to FRS or DFSR replication of SYSVOL; NetLogons failures point to service or secure-channel problems. Do not declare recovery with failed validation tests, and record the failures honestly in the recovery record.

## Step 6: Recovery Declaration Criteria

Recovery is declared complete only when all of the following are true:

1. All five FSMO roles are confirmed held by intended servers, verified with `netdom query fsmo`.
2. Replication between DC01 and DC02 is bidirectional and current, verified with `repadmin /showrepl`.
3. `dcdiag` passes its full suite on DC01.
4. Test authentication succeeds against DC01: a domain user logon and a service account authentication from a dependent system (Epic EHR, LIS, PACS/RIS, pharmacy, email or security tooling) succeed using DC01.
5. Dependent clinical systems confirm successful authentication through domain services.

**Expected output:** A recovery declaration record listing each criterion, its verification evidence, the executing administrator identity, and the date and time.

**Deviation handling:** If any criterion fails, the recovery is not complete and dependent systems must not be released to rely on DC01. Record which criteria passed and which failed, with evidence, and escalate unresolved failures to the Systems Administrator and Infrastructure Manager.

---
