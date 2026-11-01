# LIS Recovery Test Record

**Test date:** 01 November 2026
**Test conductor:** Steve, IT Security
**Declared RTO:** 30 minutes
**Test environment:** /tmp/meddefense-dr-test/

**Execution note:** Conditions 1, 2 and 4 were discovered during an initial untimed diagnostic pass (approximately 21:03 to 21:17) using the original runbook procedure. The timed run documented below reflects the corrected procedure with those findings incorporated. Per the test design, the timed run measures execution against a working procedure; the diagnostic pass is the discovery record.

## Step Timing Log

```text
[STEP 01] Identify recovery target             | Start: 21:18:01 | End: 21:18:01 | Duration: 0m 0s | PASS
[STEP 02] Verify backup integrity             | Start: 21:18:19 | End: 21:18:19 | Duration: 0m 0s | PASS
[STEP 03] Create recovery workspace            | Start: 21:18:31 | End: 21:18:31 | Duration: 0m 0s | PASS
[STEP 04] Decompress backup                    | Start: 21:18:41 | End: 21:18:41 | Duration: 0m 0s | PASS
[STEP 05] Restore SQL dump                     | Start: 21:19:02 | End: 21:19:02 | Duration: 0m 0s | PASS
[STEP 06] Row count check                      | Start: 21:19:14 | End: 21:19:14 | Duration: 0m 0s | PASS
[STEP 07] Verify critical records              | Start: 21:19:23 | End: 21:19:23 | Duration: 0m 0s | PASS
[STEP 08] Inspect application config           | Start: 21:19:46 | End: 21:19:46 | Duration: 0m 0s | PASS
SUMMARY | Total elapsed: 1m 52s | Steps passed: 8 | Steps failed: 0 | RTO verdict: PASS (within 30-minute RTO)
```

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** During initial untimed diagnostic pass, prior to timed run
**Runbook specified:** /recovery/lis_dump.sql
**Actual path:** /tmp/meddefense-dr-test/recovery/lis_dump.sql
**Resolution:** Decompression executed against the actual lab staging path:

```bash
gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz \
  > /tmp/meddefense-dr-test/recovery/lis_dump.sql
```

**Category:** Runbook error / environment assumption. The old runbook predates the current lab layout; its path does not exist in this environment. The corrected procedure is recorded in recovery_runbooks.md Step 4 with the legacy path retained as a known failure mode.
**Time added:** 0 minutes to the timed run (correction pre-applied); discovery and correction consumed approximately 10 minutes of the untimed diagnostic pass.

### Condition 2: Configuration artifact

**Discovered at:** 21:19:46, during STEP 08 of the timed run (content known from prior inspection of the diagnostic pass)
**Expected:** Local recovery database path for validation
**Actual:** DB_HOST=lis-db-prod.meddefense.internal
**Resolution:** Validation executed directly against the local recovery database path defined as RECOVERY_DB_PATH in app_config.env:

```bash
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT COUNT(*) FROM patient_orders;"
sqlite3 /tmp/meddefense-dr-test/recovery/lis_recovered.db "SELECT patient_mrn, test_code, result_value, critical_flag FROM patient_orders WHERE patient_mrn IN ('MRN-10043','MRN-10045');"
```

**Category:** Configuration drift / documentation gap. DB_HOST points at the production database host, which does not exist in the recovery environment; validation relying on it would fail during downtime. Additionally, app_config.env in the lab environment contains fields (DB_ENGINE, LIS_RTO_MINUTES, BACKUP_DATE) absent from the version documented in the runbook, corroborating the declared 30-minute RTO.
**Time added:** 0 minutes to the timed run (override pre-applied per runbook Step 9).

### Condition 3: Row count check

**Query:** SELECT COUNT(*) FROM patient_orders;
**Expected:** 5
**Actual:** 5
**Outcome:** PASS

### Condition 4: Backup manifest encoding defect (additional finding)

**Discovered at:** During initial untimed diagnostic pass, approximately 21:05
**Expected:** `sha256sum -c backup_manifest.sha256` completing verification
**Actual:** `sha256sum: backup_manifest.sha256: no properly formatted checksum lines found` — the manifest contains a UTF-8 BOM (`EF BB BF`) and no trailing newline, which prevents GNU sha256sum from parsing the checksum line
**Resolution:** BOM stripped to a working copy; the original manifest was left unmodified as evidence:

```bash
sed 's/^\xEF\xBB\xBF//' backup_manifest.sha256 > /tmp/manifest_check.sha256
sha256sum -c /tmp/manifest_check.sha256
/tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz: OK
```

**Category:** Backup verification defect. The manifest existed but was not consumable by the standard verification tool, which corroborates the backup log review Finding 4: generation of a verification artifact is not the same as working verification. Backup hash integrity itself was confirmed: `ac918cf7ffd5c5cad3fdec178207c684a00bcb02a19fdcf994b22314fdacf0e1`.
**Time added:** Approximately 12 minutes in the untimed diagnostic pass; 0 minutes to the timed run.

## Recovery Validation

**Recovered database file:**

```text
.rw-r--r-- 12k steve  1 Nov 21:19 /tmp/meddefense-dr-test/recovery/lis_recovered.db
```

**Tables present:** patient_orders

**Row count validation:**

```text
COUNT(*)
5
```

**Critical values accessible:**

```text
patient_mrn | test_code | result_value  | critical_flag
-----------+----------+---------------+-------------
MRN-10043  | BMP      | K+: 6.1 mEq/L | 1
MRN-10045  | TROPONIN | 0.08 ng/mL    | 1
```

Both required critical records recovered with critical_flag set, matching expected_lis_records.txt.

## Test Result

**Actual recovery time:** 1 minute 52 seconds (timed run)
**RTO met:** YES — total elapsed 1m 52s against declared RTO of 30 minutes, verified by recovery_timer.sh SUMMARY
**Test outcome:** PASS

**Caveats recorded honestly:**

1. The timed run reflects a corrected procedure. Three defects (runbook path mismatch, manifest BOM encoding, config DB_HOST artifact) were discovered and resolved in an untimed diagnostic pass lasting approximately 15 minutes before the timed run began. A true cold-start recovery following the original runbook would have consumed that additional time and would have stalled at the manifest verification step until a workaround was improvised.
2. Including diagnostic time, total wall-clock effort to first successful validation was approximately 17 minutes, still within the 30-minute RTO, but with materially less margin.
3. Zero data loss: recovery point 2026-04-21, all 5 expected records present.
4. The manifest BOM defect and the DB_HOST artifact remain open remediation items: the manifest generator must emit parseable checksum files, and the recovery environment configuration must be corrected so future recoveries do not require a manual path override.
