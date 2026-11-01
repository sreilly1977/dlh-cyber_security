# DR Program Status Brief

**To:** Dr. Morales, Board Risk Committee
**From:** Steve, IT Security
**Date:** 2026-11-01

## Current Risk

For the first time, MedDefense has tested its disaster recovery plan. The old plan contained recovery objectives it had never attempted to verify. The test revealed three defects that would have delayed recovery during a real outage, including one that would have stalled verification of critical patient data.

**Patient safety exposure remains:** Laboratory data backups are produced once per day, but the hospital operates on a one-hour recovery objective. In a real failure, up to 24 hours of laboratory results—including critical values that determine treatment decisions—could be unrecoverable. This is a data loss gap, not a recovery speed gap.

## What the Test Proved

The LIS recovery test succeeded in under two minutes using the corrected procedure. More importantly, the defects were found and documented before any clinical harm could occur. This is exactly what the test was designed to accomplish: prove what works, identify what fails, and fix it while patients are safe.

However, the test also proves the declared 30-minute recovery time is achievable only after documentation corrections. A cold-start recovery following the original runbook would have consumed additional diagnostic time.

## Board Approval Required

1. **Approve hourly laboratory data backups** — closes the 24-hour data loss gap. Minimal infrastructure cost; no new platform.
2. **Approve off-site encrypted backup for medical device configuration** — currently, a single equipment room fire destroys the only configuration copy.
3. **Endorse quarterly disaster recovery testing** — ensures recovery readiness remains validated over time.
4. **Direct Epic vendor to demonstrate local downtime integration capability** — vendor replication is documented but local continuity is not yet verified.

## Open Items

| Item | Owner | Due Date | Risk if Delayed |
|---|---|---|---|
| Hourly laboratory backups | Laboratory Systems Lead | 30 Nov 2026 | Up to 24 hours of critical lab data at risk |
| Device gateway off-site copy | Infrastructure Manager | 15 Nov 2026 | Single-point failure persists |
| Quarterly testing program | Laboratory Systems Lead | 15 Dec 2026 | Recovery readiness unverified |

## Recommended Board Resolution

The Board Risk Committee acknowledges receipt of the MedDefense DR Program Status Report dated 01 November 2026 and authorizes the implementation of hourly LIS transaction log backups and the medical device gateway off-site copy, with associated infrastructure funding, to close the documented patient data loss gaps.

---

**Attachment:** LIS Recovery Test Record showing actual recovery performance and documented findings.

**CISO Note:** The DR program package is complete for audit purposes. Remaining items are improvements to reduce risk further, not prerequisites for compliance.
