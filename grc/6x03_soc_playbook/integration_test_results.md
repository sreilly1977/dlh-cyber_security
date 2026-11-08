# Integration Test Results

## Overview

The integration test executes both playbooks against five canonical alert
fixtures and verifies the enrichment engine, case manager and playbook logic
are correctly wired end to end. This run doubles as the regression suite:
future playbook changes must reproduce the same five outcomes.

Test date: 2026-11-08 (17:39-17:40 UTC). Environment: local lab,
Python 3, standard library only, offline IOC feed (`ioc_feed.json`).

## Pre-Test Reset

Per `integration/integration_test_checklist.md`, executed before the run:

```bash
rm -f cases.db playbook_audit.log isolation_queue.json
mkdir -p alerts
cp materials/alerts/phishing/*.json alerts/
cp materials/alerts/credential/*.json alerts/
cp materials/threat_intel/ioc_feed.json ./ioc_feed.json
cp materials/iam/privileged_accounts.json ./privileged_accounts.json
```

## Test 1: ALT-20260428-001 - Known Malicious Sender (Phishing)

Expected: ESCALATE, Critical, escalated, no isolation queue entry.

Command:

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-001.json
```

Actual stdout:

```text
[2026-11-08T17:39:22Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-001
Rule       : phishing_email_suspicious_sender
IOCs       : 4 extracted, 2 enriched, 2 dedup skipped
  198.51.100.42            ipv4     BLOCK      score=95  (cobalt_strike,beacon)
  meddefense-secure.net    domain   BLOCK      score=97  (phishing,credential_harvest,impersonation)
  meddefense-secure.net    [dedup, skipped]
  198.51.100.42            [dedup, skipped]
Verdict    : ESCALATE
Case       : CASE-20261108-001  Severity: Critical  Status: escalated
Action     : SOC notification queued for on-call analyst
```

Case record (`python3 case_manager.py get CASE-20261108-001`):
CASE-20261108-001, severity Critical, status escalated, resolution null.
Note attached: "Playbook verdict: ESCALATE. IOCs: 198.51.100.42 (BLOCK/95),
meddefense-secure.net (BLOCK/97)". Two IOCs stored, both BLOCK.

Result: **PASS**. Matches expected verdict, severity, status and queue
expectation (no queue entry).

## Test 2: ALT-20260428-002 - Unknown External Sender (Phishing)

Expected: REVIEW, High, open, no isolation queue entry.

Command:

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-002.json
```

Actual stdout:

```text
[2026-11-08T17:39:38Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-002
Rule       : phishing_email_suspicious_sender
IOCs       : 3 extracted, 2 enriched, 1 dedup skipped
  203.0.113.5              ipv4     INVESTIGATE score=30
  external-health-news.com domain   INVESTIGATE score=30
  external-health-news.com [dedup, skipped]
Verdict    : REVIEW
Case       : CASE-20261108-002  Severity: High  Status: open
Action     : Case queued for analyst review
```

Case record (`python3 case_manager.py get CASE-20261108-002`):
CASE-20261108-002, severity High, status open, resolution null.
Two IOCs stored, both INVESTIGATE at score 30.

Result: **PASS**. Matches expected verdict, severity, status and queue
expectation.

## Test 3: ALT-20260428-003 - Internal Sender, Private IP (Phishing)

Expected: CLOSE, Low, closed, no isolation queue entry.

Command:

```bash
python3 playbook_phishing_triage.py alerts/ALT-20260428-003.json
```

Actual stdout:

```text
[2026-11-08T17:39:44Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-003
Rule       : phishing_email_suspicious_sender
IOCs       : 2 extracted, 2 enriched
  10.0.1.25                ipv4     ALLOW      score=0
  meddefense.internal      domain   ALLOW      score=0
Verdict    : CLOSE
Case       : CASE-20261108-003  Severity: Low  Status: closed
Action     : Case closed automatically: no indicators of compromise
```

Case record (`python3 case_manager.py get CASE-20261108-003`):
CASE-20261108-003, severity Low, status closed, resolution
`no_indicators_of_compromise`. Two IOCs stored, both ALLOW at score 0.

Result: **PASS**. Matches expected verdict, severity, status and queue
expectation. Confirms auto-close fires only when every extracted IOC is
ALLOW, per the governance constraint on benign auto-closure.

## Test 4: ALT-20260428-007 - LSASS Dump from Known C2 IP, Domain Admin (Credential)

Expected: ESCALATE, Critical, escalated, host written to isolation queue.

Command:

```bash
python3 playbook_credential_exposure.py alerts/ALT-20260428-007.json
```

Actual stdout:

```text
[2026-11-08T17:39:54Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-007
Host       : WST-WS-031
User       : svc_helpdesk  Privilege: Domain Admin
Source IP  : 198.51.100.42  Verdict: BLOCK  Score: 95
MITRE      : T1003.001 OS Credential Dumping: LSASS Memory
Verdict    : ESCALATE
Case       : CASE-20261108-004  Severity: Critical  Status: escalated
Action     : Host written to isolation_queue.json for analyst authorization
```

Case record (`python3 case_manager.py get CASE-20261108-004`):
CASE-20261108-004, severity Critical, status escalated, resolution null.
Note attached with the full enrichment summary and matrix reasoning, ending
"Host WST-WS-031 written to isolation_queue.json; analyst must authorize
isolation via EDR console." One IOC stored: 198.51.100.42, BLOCK/95.

Result: **PASS**. Matches expected verdict, severity, status and queue
expectation (queue entry present, status `pending_authorization`).

## Test 5: ALT-20260428-009 - Pass the Hash from Internal IP, Standard User (Credential)

Expected: MANUAL_REVIEW, Medium, open, no isolation queue entry.

Command:

```bash
python3 playbook_credential_exposure.py alerts/ALT-20260428-009.json
```

Actual stdout:

```text
[2026-11-08T17:40:06Z] CREDENTIAL EXPOSURE PLAYBOOK
Alert      : ALT-20260428-009
Host       : WST-WS-041
User       : k.nguyen  Privilege: Standard
Source IP  : 192.168.10.55  Verdict: ALLOW  Score: 0
MITRE      : T1550.002 Use Alternate Authentication Material: Pass the Hash
Verdict    : MANUAL_REVIEW
Case       : CASE-20261108-005  Severity: Medium  Status: open
Action     : Case queued for analyst review; no isolation flag raised
```

Case record (`python3 case_manager.py get CASE-20261108-005`):
CASE-20261108-005, severity Medium, status open, resolution null.
Note attached with the full enrichment summary and matrix reasoning.
One IOC stored: 192.168.10.55, ALLOW/0.

Result: **PASS**. Matches expected verdict, severity, status and queue
expectation.

## Scenario Summary

| Alert | Playbook | Expected Verdict | Expected Severity | Expected Status | Queue | Actual | Result |
|---|---|---|---|---|---|---|---|
| ALT-20260428-001 | phishing_triage | ESCALATE | Critical | escalated | no | ESCALATE / Critical / escalated | PASS |
| ALT-20260428-002 | phishing_triage | REVIEW | High | open | no | REVIEW / High / open | PASS |
| ALT-20260428-003 | phishing_triage | CLOSE | Low | closed | no | CLOSE / Low / closed | PASS |
| ALT-20260428-007 | credential_exposure | ESCALATE | Critical | escalated | yes | ESCALATE / Critical / escalated / queued | PASS |
| ALT-20260428-009 | credential_exposure | MANUAL_REVIEW | Medium | open | no | MANUAL_REVIEW / Medium / open | PASS |

5 of 5 scenarios PASS.

## Post-Test Artifacts

`python3 case_manager.py list`:

```text
+-------------------+------------------+----------+-------------------------------------------------------------------------------------+-----------+
| Case ID           | Alert ID         | Severity | Title                                                                               | Status    |
+-------------------+------------------+----------+-------------------------------------------------------------------------------------+-----------+
| CASE-20261108-001 | ALT-20260428-001 | Critical | Phishing: Known malicious IOC escalated                                             | escalated |
| CASE-20261108-002 | ALT-20260428-002 | High     | Phishing: Suspicious sender review                                                  | open      |
| CASE-20261108-004 | ALT-20260428-007 | Critical | Credential Exposure: T1003.001 OS Credential Dumping: LSASS Memory                  | escalated |
| CASE-20261108-005 | ALT-20260428-009 | Medium   | Credential Exposure: T1550.002 Use Alternate Authentication Material: Pass the Hash | open      |
+-------------------+------------------+----------+-------------------------------------------------------------------------------------+-----------+
4 cases (filter: open + escalated)
```

`cat isolation_queue.json`:

```json
[
  {
    "queued_at": "2026-11-08T17:39:54Z",
    "host": "WST-WS-031",
    "alert_id": "ALT-20260428-007",
    "case_id": "CASE-20261108-004",
    "reason": "T1003.001 from BLOCK-verdict source IP 198.51.100.42 by Domain Admin account svc_helpdesk",
    "action_required": "Analyst must authorize isolation via EDR console before execution",
    "status": "pending_authorization"
  }
]
```

Exactly one queue entry exists: WST-WS-031 from Test 4, pending analyst
authorization. No host was isolated and no EDR API was called.

`cat playbook_audit.log`:

```text
2026-11-08T17:39:22Z | PHISHING_TRIAGE | ALT-20260428-001 | IOCs:2 | BLOCK:2,INVESTIGATE:0,ALLOW:0 | Verdict:ESCALATE | Case:CASE-20261108-001 | Severity:Critical
2026-11-08T17:39:38Z | PHISHING_TRIAGE | ALT-20260428-002 | IOCs:2 | BLOCK:0,INVESTIGATE:2,ALLOW:0 | Verdict:REVIEW | Case:CASE-20261108-002 | Severity:High
2026-11-08T17:39:44Z | PHISHING_TRIAGE | ALT-20260428-003 | IOCs:2 | BLOCK:0,INVESTIGATE:0,ALLOW:2 | Verdict:CLOSE | Case:CASE-20261108-003 | Severity:Low
2026-11-08T17:39:54Z | CREDENTIAL_EXPOSURE | ALT-20260428-007 | Host:WST-WS-031 | User:svc_helpdesk | IPVerdict:BLOCK | Privilege:Domain Admin | Case:CASE-20261108-004 | Severity:Critical | IsolationQueued:yes
2026-11-08T17:40:06Z | CREDENTIAL_EXPOSURE | ALT-20260428-009 | Host:WST-WS-041 | User:k.nguyen | IPVerdict:ALLOW | Privilege:Standard | Case:CASE-20261108-005 | Severity:Medium | IsolationQueued:no
```

All five audit lines match the `audit_log_format_reference.md` field layout.

## Deviations and Decisions

1. **Audit IOC tallies differ from the sample stdout.** The sample in
   `sample_stdout_outputs.md` shows `IOCs:3 | BLOCK:2,INVESTIGATE:0,ALLOW:1`
   for ALT-20260428-001. That tally cannot arise from the required
   extraction rules: the alert contains one sender IP, one sender domain and
   two body URL hostnames that are duplicates of the first two, so only two
   unique IOCs exist and all of them are BLOCK. The playbooks therefore
   report `IOCs:2 | BLOCK:2,INVESTIGATE:0,ALLOW:0` so the audit tally always
   sums to the number of IOCs actually enriched. Verdicts, severities,
   statuses and case structure are unaffected.

2. **Case IDs use the test run date.** Per `case_id_generation_notes.md`,
   IDs sequence per calendar day from `cases.db`. Alerts are dated
   2026-04-28 but cases were created on 2026-11-08, so IDs are
   `CASE-20261108-NNN`. This matches the generation rules; the sample's
   `CASE-20260428-NNN` reflects an April run.

3. **Test tooling fix during collection (no playbook change required).**
   The first attempt to collect case IDs used `grep -oE` over multiple
   files, which prefixes matches with the filename; the resulting strings
   failed the `case_manager.py get` lookup. Fixed by adding `grep -h`.
   Recorded here for completeness; no playbook or case-manager defect was
   involved.
