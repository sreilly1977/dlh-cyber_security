# LIS Recovery Gap Analysis

**Version:** 1.0
**Classification:** Confidential
**Prepared by:** Steve, IT Security
**Date:** 2026-11-01

Analysis of the LIS recovery test executed 01 November 2026 against the declared RTO of 30 minutes, per the test record, the BIA version 1.0, recovery_runbooks.md version 1.0, and the condition cards provided in the lab materials.

## Test Summary Table

| Metric | Value |
|---|---|
| Declared RTO | 30 minutes (per `lab_config.env` and `LIS_RTO_MINUTES=30` in `app_config.env`) |
| Actual recovery time | 1 minute 52 seconds (timed run, 8 steps, 0 failures) |
| Delta in minutes | 28 minutes 8 seconds under the declared RTO |
| Total wall-clock effort including diagnostic pass | Approximately 17 minutes |
| Overall test result | PASS — with three documented conditions and one additional finding |

The headline result understates the real story. The timed run passed because three defects had already been found and corrected in an untimed diagnostic pass of approximately 15 minutes. A cold-start recovery following the original runbook would have stalled at the manifest verification step and consumed the diagnostic time inside the RTO clock. The honest reading: the 30-minute RTO is achievable with the corrected procedure, and marginally achievable even with cold-start discovery included, but only after the runbook and backup artifacts are fixed as described below.

## Condition Analysis

### Condition 1: Path mismatch

| Field | Content |
|---|---|
| Title | Old runbook decompression path does not exist in the lab environment |
| Category | Runbook Error (the condition card also permits Environment Assumption; the root cause is squarely a runbook error) |
| Root cause | The old runbook predates the current recovery environment. It stages the decompressed SQL dump at `/recovery/lis_dump.sql`, a path assumed rather than verified. The actual environment stages at `/tmp/meddefense-dr-test/recovery/lis_dump.sql` per `lab_config.env` (`STAGED_SQL`). The runbook was never re-validated after the environment changed. |
| Patient safety consequence | At the 1-hour BIA threshold, LIS downtime risks missed context; STAT workflows continue by phone and paper with elevated mislabeling risk. An executor halting at a failed decompression command extends downtime toward the 4-hour threshold, where mislabeling and delayed critical value notification become primary risks, and toward 8-hour MTD, where missed critical values directly endanger patients such as MRN-10043 (K+ 6.1 mEq/L) and MRN-10045 (critical troponin). Every minute spent debugging a wrong path is a minute critical results are not reaching ordering clinicians. |
| Time added | 0 minutes to the timed run (correction pre-applied); approximately 10 minutes consumed in the untimed diagnostic pass |

### Condition 2: Configuration artifact

| Field | Content |
|---|---|
| Title | `app_config.env` points validation at a production host that does not exist in the recovery environment |
| Category | Configuration Drift (the condition card also permits Documentation Gap; the config itself is drifted, and the runbook's documented expected contents also lagged the actual file) |
| Root cause | `DB_HOST=lis-db-prod.meddefense.internal` reflects the production topology, not the recovery topology. Additionally, the runbook's expected contents for `app_config.env` were based on an outdated version of the file: the actual file contains `DB_ENGINE`, `LIS_RTO_MINUTES` and `BACKUP_DATE` and lacks `APP_NAME` and `HEALTHCHECK_QUERY`. Recovery configuration was not maintained in step with environment changes. |
| Patient safety consequence | Validation commands that reference `DB_HOST` fail during downtime, delaying the confirmation that critical values for MRN-10043 and MRN-10045 are present and correctly flagged. Until validation completes, the LIS cannot be released to clinical use, extending the paper STAT workflow window with its mislabeling and delayed-notification risks. Worse, an executor might mistake a config-induced validation failure for a failed recovery, triggering an unnecessary escalation cycle and further delay. |
| Time added | 0 minutes to the timed run (override pre-applied per runbook Step 9); discovery and analysis consumed several minutes of the diagnostic pass |

### Condition 3: Row count check

| Field | Content |
|---|---|
| Title | Recovered row count matched the expected value |
| Category | Recovery Validation (per the condition card) |
| Root cause | No defect. The condition verifies that recovery produced the expected state: `SELECT COUNT(*) FROM patient_orders;` returned 5, matching `EXPECTED_ROW_COUNT` in `lab_config.env` and `expected_lis_records.txt`, and both critical records were present with `critical_flag=1`. Documented because the test design requires the result to be recorded exactly, not because it is a gap. |
| Patient safety consequence | Positive confirmation: both critical results (MRN-10043, BMP, K+ 6.1 mEq/L; MRN-10045, TROPONIN, 0.08 ng/mL) were accessible in the recovered database, meaning the recovered system supports critical value notification on release rather than forcing continued paper calling. |
| Time added | 0 minutes |

### Additional finding: backup manifest encoding defect

| Field | Content |
|---|---|
| Title | Manifest cannot be parsed by the standard verification tool |
| Category | Documentation Gap / backup pipeline defect (corroborates backup log review Finding 4) |
| Root cause | `backup_manifest.sha256` is emitted with a UTF-8 BOM (`EF BB BF`) and no trailing newline. GNU `sha256sum -c` rejects it with "no properly formatted checksum lines found", despite the embedded hash (`ac918cf7ffd5c5cad3fdec178207c684a00bcb02a19fdcf994b22314fdacf0e1`) being correct. The manifest generator was never verified to produce tool-consumable output; the existence of the artifact was treated as the control. |
| Patient safety consequence | This is the single largest time risk discovered: the diagnostic pass spent approximately 12 minutes on it. In a cold-start recovery, verification of backup integrity stalls before the restore begins, pushing the 30-minute RTO toward breach and extending the LIS outage toward the 4-hour threshold where delayed critical value notification becomes a primary patient safety risk. |
| Time added | Approximately 12 minutes in the untimed diagnostic pass; 0 minutes to the timed run (BOM strip incorporated as Step 2) |

## Runbook Deficiencies

Specific deficiencies identified in `recovery_runbooks.md` version 1.0 and its predecessor:

1. The old runbook's decompression step specifies `/recovery/lis_dump.sql`, but the lab recovery environment stages the decompressed file at `/tmp/meddefense-dr-test/recovery/lis_dump.sql` per `STAGED_SQL` in `lab_config.env`. Version 1.0 preserved this as a documented failure mode, but still requires the executor to absorb the correction mid-procedure.
2. Step 2 of version 1.0 runs `sha256sum -c backup_manifest.sha256` with expected output `lis_backup.sql.gz: OK`. In the actual environment, this command fails because the manifest carries a UTF-8 BOM. The step has no provision for the BOM strip, so a version 1.0 executor hits an unexpected failure not covered by the deviation handling.
3. Step 8 of version 1.0 documents expected `app_config.env` contents that do not match the actual file: expected `APP_NAME` and `HEALTHCHECK_QUERY` are absent from the real file, and actual fields `DB_ENGINE`, `LIS_RTO_MINUTES` and `BACKUP_DATE` are undocumented. The DB_HOST artifact is correctly identified, but against a stale expected-output block.
4. The timed test required a restart of the timer sequence because step state was lost between the diagnostic pass and the timed run. Version 1.0 has no step defining when the recovery clock starts and how a false start or restart is handled in the record.
5. Version 1.0 Step 7 queries `WHERE mrn='MRN-10043'`, but the schema uses column `patient_mrn` as confirmed by the successful validation queries in the test record. The expected-output format was correct; the column reference in the example query was not verified against the schema.

## Revised RTO

**Recommendation: retain the 30-minute RTO, and justify it with the corrected procedure and test evidence.**

The corrected process met the RTO with 28 minutes 8 seconds of margin in the timed run. The three defects that consumed the diagnostic pass are all correctable in documentation and tooling rather than infrastructure:

- The path correction is now embedded in the updated runbook, so no discovery time recurs.
- The manifest BOM strip is now an explicit Step 2, consuming under one second.
- The recovery override for the DB_HOST artifact is now Step 8 with a pre-written validation command.

Even a cold-start scenario that rediscovered these issues consumed approximately 17 minutes total wall clock, inside the 30-minute window. The BIA therefore does not require an RTO revision on current evidence. Two honesty conditions attach to this recommendation:

1. The margin rests on a single test with a small database. Production-scale restore times must be re-measured, and the RTO revalidated, once hourly transaction log backups from the remediation roadmap are implemented, because applying transaction logs in sequence adds time that this test did not exercise.
2. The declared RPO remains the dishonest number. This test proves nothing about RPO: the recovery point was 2026-04-21, and the nightly backup schedule still cannot deliver the BIA's 1-hour RPO for critical values. The RTO can stand at 30 minutes; the RPO commitment must either gain hourly transaction log backups or the BIA must be updated to state 24 hours.

## Updated LIS Recovery Runbook

# LIS Recovery Runbook (Version 2.0)

**Scope:** Recovery of the LIS database from the nightly compressed SQL backup into the SQLite recovery environment. Declared RTO: 30 minutes. Changed steps are marked [UPDATED].

## Step 1: Identify the Latest Recovery Target

Unchanged from version 1.0. List `/tmp/meddefense-dr-test/backup/lis/`, confirm the newest dated directory is `2026-04-21` per `BACKUP_DATE` in `lab_config.env`, and confirm `lis_backup.sql.gz` and `backup_manifest.sha256` are present and non-empty. Deviation handling unchanged: escalate missing artifacts to the IT Incident Commander (extension 7200) and quantify data loss before selecting an older point.

## Step 2: Verify Backup Integrity [UPDATED]

**Command or action:**

```bash
sed 's/^\xEF\xBB\xBF//' /tmp/meddefense-dr-test/backup/lis/2026-04-21/backup_manifest.sha256 > /tmp/manifest_check.sha256
sha256sum -c /tmp/manifest_check.sha256
```

**Expected output:**

```text
/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz: OK
```

**Change:** The manifest is known to carry a UTF-8 BOM that the standard verification tool cannot parse. The BOM strip into a working copy is now the procedure, not an improvised workaround. The original manifest is never modified; it is evidence.

**Verification check:** The check reports `OK` for the backup file.

**Deviation handling:** If the check reports `FAILED`, stop; do not restore. If the strip itself fails because the manifest format has changed again, fall back to manual comparison: `sha256sum` the dump and compare against the 64-character hash extracted from the manifest. Record the fallback used.

## Step 3: Create the Recovery Workspace

Unchanged. `mkdir -p /tmp/meddefense-dr-test/recovery /tmp/meddefense-dr-test/validation`. Idempotent; move aside any prior partial `lis_recovered.db` with a timestamp suffix rather than deleting it.

## Step 4: Decompress the Backup to the Staging Path [UPDATED]

**Command or action:**

```bash
gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Change:** The legacy path `/recovery/lis_dump.sql` from the old runbook is removed from the procedure entirely. It remains documented in the test record and the gap analysis as the root cause of Condition 1, but it no longer appears as an executable command in the runbook, eliminating the possibility of executing a known-bad path.

**Verification check:** `ls -lh /tmp/meddefense-dr-test/recovery/lis_dump.sql` shows non-zero size (test observed 668 bytes); `head` shows readable SQL.

**Deviation handling:** Empty or unreadable output returns to Step 2 for re-verification.

## Step 5: Restore the SQL Dump into SQLite

Unchanged. `sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db < /tmp/meddefense-dr-test/recovery/lis_dump.sql`, then confirm `.tables` lists `patient_orders`. Move partial databases aside before retrying; do not validate a partial restore.

## Step 6: Check the Row Count in patient_orders

Unchanged. `SELECT COUNT(*) FROM patient_orders;` must return 5. Lower or higher counts block release and are recorded honestly.

## Step 7: Confirm the Critical Results [UPDATED]

**Command or action:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045');"
```

**Expected output:**

```text
MRN-10043|BMP|K+: 6.1 mEq/L|1
MRN-10045|TROPONIN|0.08 ng/mL|1
```

**Change:** The query now uses the verified column name `patient_mrn` from the actual schema, and consolidates both critical-record checks into a single query with an IN clause, which is what the executed test validated. Version 1.0's example used `mrn` and issued two separate queries.

**Verification check:** Both records present with `critical_flag=1`.

**Deviation handling:** Missing records or flags block clinical release regardless of row count; escalate per the clinical path (accessioning extension 7500, chemistry lead extension 7510).

## Step 8: Validate Against the Local Recovery Database [UPDATED]

**Command or action:**

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045');"
```

**Change:** Version 1.0 split config inspection (Step 8) and the recovery override (Step 9) into two steps against a stale expected-contents block. This step now performs validation directly against `RECOVERY_DB_PATH` and treats `DB_HOST=lis-db-prod.meddefense.internal` as a known configuration artifact documented in the gap analysis, not a surprise. The expected contents of `app_config.env` are corrected to the actual file: `APP_ENV`, `DB_ENGINE`, `DB_NAME`, `DB_HOST`, `RECOVERY_DB_PATH`, `LIS_RTO_MINUTES`, `BACKUP_DATE`.

**Verification check:** Both queries return the expected results using the local path.

**Deviation handling:** If `DB_HOST` is ever corrected to a recovery-valid value, this step's override is superseded; validation then uses the configured host. Document any residual mismatch.

## Step 9: Record Notification Content for the Clinical Team

Unchanged in substance from version 1.0 Step 10: recovery status against the 30-minute RTO with actual elapsed time, recovery point date 2026-04-21, validation results, outstanding reconstruction items from paper downtime forms, and the honest statement of any missed objective.

## Step 10: Timer Discipline [NEW]

Start the recovery clock at Step 1 and record every step through `recovery_timer.sh`. If a false start occurs, preserve the first log as diagnostic evidence, reset state (`rm -rf /tmp/rtest_state` and a fresh log), and restart from Step 1. The record must state which pass is the timed run and what the preceding diagnostic pass discovered. This formalizes what the test had to improvise.

## Remediation Roadmap

| Priority | Action | Owner Role | Target Completion | Success Criterion |
|---|---|---|---|---|
| P1 | Fix the manifest generator to emit tool-parseable SHA-256 output without a BOM and with a trailing newline; regenerate and verify the current manifest | Infrastructure Manager | 15 November 2026 | `sha256sum -c backup_manifest.sha256` succeeds on the original manifest with no preprocessing |
| P1 | Deploy hourly LIS transaction log backups alongside the nightly full dump to close the RPO arithmetic conflict (backup log review Finding 1) | Laboratory Systems Lead | 30 November 2026 | A verified recovery point exists no older than 1 hour at any time during operation |
| P1 | Adopt runbook version 2.0 and remove version 1.0 and the old runbook from circulation so no executor can follow the stale path | Laboratory Systems Lead | 08 November 2026 | Version 2.0 is the only LIS runbook in the runbook repository |
| P2 | Correct the recovery environment configuration so `DB_HOST` reflects the recovery topology, and align the documented expected contents of `app_config.env` with the actual file | Laboratory Systems Lead | 15 November 2026 | Validation commands work without a manual path override, and documented expected contents match the file exactly |
| P2 | Re-run the timed recovery test using runbook version 2.0 cold, with no diagnostic pass, to validate the 30-minute RTO including transaction log application once P1 items land | Laboratory Systems Lead | 15 December 2026 | Cold-start timed run meets the 30-minute RTO with the production-scale backup chain, recorded honestly either way |
| P3 | Establish quarterly LIS restore testing on the schedule required by 164.308(a)(7)(ii)(D), with tester identity and date recorded per backup log review Finding 4 | Infrastructure Manager | 31 December 2026 | Four quarterly restore tests per year logged with hash validation, row count and critical record checks, tester name and date |

---
