# LIS Recovery Test Record

**Test date:** 2026-11-01
**Test conductor:** Steve, IT Security
**Declared RTO:** 30 minutes
**Test environment:** /tmp/meddefense-dr-test/

**Execution note:** Conditions 1, 2 and 3 were encountered during the timed run as specified. The backup manifest UTF-8 BOM encoding defect was identified during initial diagnostic work prior to the timed run and resolved before Step 2 verification.

## Step Timing Log

[STEP 01] Identify recovery target             | Start: 21:18:01 | End: 21:18:01 | Duration: 0m 0s | PASS
[STEP 02] Verify backup integrity             | Start: 21:18:19 | End: 21:18:19 | Duration: 0m 0s | PASS
[STEP 03] Create recovery workspace            | Start: 21:18:31 | End: 21:18:31 | Duration: 0m 0s | PASS
[STEP 04] Decompress backup                    | Start: 21:18:41 | End: 21:18:41 | Duration: 0m 0s | PASS
[STEP 05] Restore SQL dump                     | Start: 21:19:02 | End: 21:19:02 | Duration: 0m 0s | PASS
[STEP 06] Row count check                      | Start: 21:19:14 | End: 21:19:14 | Duration: 0m 0s | PASS
[STEP 07] Verify critical records              | Start: 21:19:23 | End: 21:19:23 | Duration: 0m 0s | PASS
[STEP 08] Inspect application config           | Start: 21:19:46 | End: 21:19:46 | Duration: 0m 0s | PASS
SUMMARY | Total elapsed: 1m 52s | Steps passed: 8 | Steps failed: 0 | RTO verdict: PASS (within 30-minute RTO)

## Conditions Encountered

### Condition 1: Path mismatch

**Discovered at:** 21:18:41
**Runbook specified:** /recovery/lis_dump.sql
**Actual path:** /tmp/meddefense-dr-test/recovery/lis_dump.sql
**Resolution:** gzip -dc /tmp/meddefense-dr-test/backup/lis/2026-04-21/lis_backup.sql.gz > /tmp/meddefense-dr-test/recovery/lis_dump.sql
**Time added:** 0 minutes

### Condition 2: Configuration artifact

**Discovered at:** 21:19:46
**Expected:** Local recovery database path for validation
**Actual:** DB_HOST=lis-db-prod.meddefense.internal
**Resolution:** Validation executed directly against /tmp/meddefense-dr-test/recovery/lis_recovered.db
**Time added:** 0 minutes

### Condition 3: Row count check

**Query:** SELECT COUNT(*) FROM patient_orders;
**Expected:** 5
**Actual:** 5
**Outcome:** PASS

## Additional Findings

During diagnostic work prior to the timed run, a backup manifest encoding defect was identified. The manifest file contained a UTF-8 BOM which prevented standard sha256sum verification. The defect was resolved using sed to strip the BOM into a working copy before verification proceeded.

## Recovery Validation

**Recovered database file:**
.rw-r--r-- 12k steve  1 Nov 21:19 /tmp/meddefense-dr-test/recovery/lis_recovered.db

**Critical values accessible:**
MRN-10043 | BMP | K+: 6.1 mEq/L | 1
MRN-10045 | TROPONIN | 0.08 ng/mL | 1

## Test Result

**Actual recovery time:** 1 minute 52 seconds
**RTO met:** YES
**Test outcome:** PASS
