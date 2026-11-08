# SOC Automation Strategy

**MedDefense SOC | Prepared by: Steve, Cybersecurity Engineer | 08 November 2026**

## Current State Analysis

MedDefense processes 120 to 180 SIEM alerts per day; for planning we use the
midpoint of 150 alerts/day. Average analyst effort is 8 minutes per alert,
giving 1,200 minutes, or 20 analyst-hours, of triage work per day. The March
review found 67 percent of triage time was enrichment activity: IP lookups,
domain checks, URL analysis and hash lookups. That is 13.4 hours per day spent
on lookups rather than decisions, roughly 402 hours per month across the team,
performed by two analysts per shift.

The Cobalt Strike incident shows the operational cost. During an active
breach, one IP enrichment took approximately 45 minutes by hand: reputation
checks across three browser tabs, WHOIS review, and cross-referencing prior
threat intel. By the time the verdict arrived, the attacker had moved
laterally to two additional hosts. The enrichment was correct but 40 minutes
too slow, and every minute of that delay was attacker dwell time.

The Tasks 1-5 build demonstrates the fix is achievable today with
standard-library tooling: the enrichment engine returns a verdict from the
local feed in under two seconds, and the integration test reproduced the
expected outcome for all five scenarios (5 of 5 PASS), including
correct-to-queue isolation recommendation without executing it.

## Automation Candidates

Priority is ordered by volume times effort, tempered by false-positive risk.
Volumes and efforts for rows 2-7 come from the automation candidate matrix;
phishing figures come from the SOC baseline.

| Priority | Process | Daily volume | Manual effort | Complexity | FP risk | Recommended tier | Condition before action-tier automation |
|---|---|---|---|---|---|---|---|
| 1 | Phishing enrichment and triage | 150/day | 8 min/alert | Low | Medium | Enrich-and-triage | < 5% measured FP rate before any auto-close expands |
| 2 | Case creation from playbook verdicts | 60/day | 2 min/case | Low | Low | Enrich-and-triage | None; no destructive action involved |
| 3 | Credential exposure enrichment | 12/day | 8 min/alert | Medium | Medium | Enrich-and-triage | Requires privilege context review before any expansion |
| 4 | Phishing benign auto-close | 35/day | 3 min/alert | Medium | Medium | Enrich-and-triage | < 2% measured false-negative rate, monitored allowlist |
| 5 | Endpoint isolation recommendation | 4/day | 10 min/host | High | High | Enrich-and-human-authorize | < 1% measured FP; queue only until then |
| 6 | Mailbox quarantine | 15/day | 6 min | High | High | Human-authorized action | < 1% measured FP; clinical safety review (patient-safety-relevant email) |
| 7 | Privileged account disablement | 1/day | 15 min | High | Critical | Human-only | < 0.1% measured FP; never fully automated at MedDefense |

Rows 1-3 and 5 are implemented in the Tasks 1-5 build. Row 5 is implemented
at the recommendation tier only: the credential playbook writes
`isolation_queue.json` with `pending_authorization` status and the analyst
authorizes isolation in the EDR console. No playbook isolates a host,
quarantines a mailbox, disables an account, or calls a blocking API.

## Expected Efficiency Gains

Deploying the phishing triage playbook at scale, using the required formula
`(volume x manual_effort x automation_rate) / 60`:

```text
(150 alerts/day x 8 min x 0.67 automation_rate) / 60 = 13.4 hours/day
13.4 hours/day x 30 days = ~402 hours/month
```

The automation rate of 0.67 represents the enrichment portion of triage time
the playbook eliminates outright; the analyst still reviews the pre-enriched
case for REVIEW verdicts and authorizes any escalated action. This recovers
roughly 402 analyst-hours per month, equivalent to about 2.5 FTE-months of
lookup work, without removing a single human decision.

Confidence: moderate to high. The integration test proved the deterministic
core (5/5 scenarios), and the feed-driven lookups are bounded and repeatable.
The estimate would be invalidated if the alert mix shifts away from phishing,
if the 8-minute and 67-percent baselines from the March review drift, or if
feed staleness increases REVIEW rates, pushing work back to analysts. These
assumptions should be re-measured after 90 days of production data.

## Risks of Over-Automation

**1. Auto-closure masking a real incident during a multi-phase attack.**
Scenario: a phishing alert arrives from an unseen sender infrastructure, so
every extracted IOC scores ALLOW; the campaign's first-stage email looks
identical to a benign newsletter, and the second stage arrives from the
already-compromised mailbox of a trusted internal sender. If auto-close fired
on stage one, no case reaches an analyst until stage two detonates. In a
healthcare environment the consequence is a breach of protected health
information with mandatory HIPAA breach notification and Office for Civil
Rights exposure, discovered days late. Control: auto-close is gated on all
IOCs being ALLOW with resolution recorded (implemented in Task 3, verified in
Test 3), requires a measured < 2% false-negative rate before production
auto-close, and every closed case remains queryable in `cases.db` with the
full IOC record for retro-hunting when new intelligence lands.

**2. Automated isolation disrupting patient care.** Scenario: a clinical
workstation in the emergency department matches the credential exposure
pattern because of a misconfigured imaging agent running as a Domain Admin
service account from a scanner-visible IP; automated isolation takes the
workstation offline mid-shift. Consequence: clinicians lose access to
ordering and results at the point of care, which in MedDefense's environment
can delay treatment and creates an operational incident that dwarfs the
security one. Control: the playbook queues hosts for isolation only
(`isolation_queue.json`, status `pending_authorization`); an analyst must
authorize via the EDR console with full enrichment context, and action-tier
automation additionally requires a < 1% measured false-positive rate,
clinical safety review, rollback procedure and owner approval.

**3. Automated privileged account disablement halting clinical operations.**
Scenario: `svc_epic_int` or `svc_backup` appears in a credential exposure
alert; automation disables the account automatically. Consequence: overnight
backups stop or Epic integration fails, disrupting clinical record keeping
during emergency maintenance windows. The IAM context shows several of these
accounts are already fragile: dormant, overprivileged, or lacking MFA, which
makes them frequent false-positive triggers. Control: account disablement is
classified human-only in the governance model; no playbook implements it, and
it remains excluded even in Phase 3 of the roadmap.

## Implementation Roadmap

**Phase 1 (Days 0-90): Enrich and triage only, no automated actions.**
Deploy `enrich_ioc.py`, both playbooks and the case manager into shadow mode:
playbooks create pre-enriched cases, analysts validate every verdict.
Deliverables: deployment of the Task 1-4 components, `playbook_audit.log`
operational, analyst verdict-versus-playbook-agreement tracking. Success
criteria: 100% of phishing and credential alerts processed by playbook;
agreement rate measured on all 150 alerts/day. Gate to Phase 2: 90 consecutive
days of measured verdict data showing the benign auto-close path achieves a
< 2% false-negative rate, with an exception process, rollback procedure and
change-management record in place. The gate exists because per Robert Kim,
automating on an unmeasured rule simply industrializes the error.

**Phase 2 (Days 91-180): Auto-close confirmed-benign phishing alerts.**
Enable automatic closure only for alerts where every extracted IOC is ALLOW
and the sender is internal or allowlisted, initially as notify-only closures
an analyst can reopen. Deliverables: auto-close in production with reopen
SLAs, weekly FP sampling, quarterly feed review. Success criteria: false
negative rate stays < 2%, zero reopened cases that concealed real incidents.
Gate to Phase 3: measured false-positive rate < 1% on isolation
recommendations, plus clinical safety review sign-off.

**Phase 3 (Days 181-270): Conditional escalation and pre-authorized response.**
Introduce conditional escalation: BLOCK-verdict phishing and credential cases
page the on-call analyst automatically; consider limited, pre-approved
response actions for the highest-confidence detections only. Deliverables:
notification integration, action-automation proposals each passing the
governance bar (measured FP rate, exceptions, rollback, owner approval,
clinical safety review, audit logging, change management). Success criteria:
mean time to analyst decision on Critical cases drops below the Cobalt
Strike benchmark; zero unauthorized action-tier executions.

This sequencing is not negotiable because the order is the safeguard:
enrichment is risk-free automation of lookups, triage automation is validated
against ground truth in shadow mode, and only measured performance earns the
right to act. Reversing the order puts the failure modes described above into
production before the evidence exists to rule them out.
