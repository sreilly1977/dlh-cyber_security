# Program Effectiveness Brief: MedDefense Security Awareness Program

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-10
**Version:** 1.0
**Classification:** Confidential
**Prepared for:** Dr. Patricia Morales, CISO — 6-month board presentation
**Framing (James Chen):** "Three questions. Are we safer? Are we improving? What changes next?"
**Materials basis:** `awareness_program_plan.md`, `phishing_campaign_plan.md`, `metrics_baseline.csv`, `board_reporting_template.md`, `program_governance_roles.md`, `post_incident_click_rate_review.md`, `security_awareness_gap_notes.md`, `lure_effectiveness_benchmarks.md`

**Honesty commitment for this artifact:** the brief template below is written to prevent a specific board-room failure — claiming the awareness program alone caused incident reduction when the SOC automation rollout and IAM remediation occurred in the same period. Where causation cannot be established, the templates force trend language, confidence labels, and stated caveats. The attribution methodology in Part 3 governs every number that reaches the board.

---

## Part 1: Board-Ready Effectiveness Brief Template (6-Month)

*Instructions to the program owner: fill every `[bracketed]` field with actual data; delete no caveats. The brief is designed to be presented by Dr. Morales without a security engineer translating. Two pages, printed.*

---

# MedDefense Security Awareness Program — Six-Month Effectiveness Brief

**Reporting period:** [MONTH YEAR] – [MONTH YEAR] | **Presented:** [DATE] | **Prepared by:** IT Security Awareness Lead

## Program Summary

Since [PROGRAM_START], MedDefense has run a behavior-measurement security awareness program in place of compliance-only training. [X] simulation waves reached [N] employees across clinical, administrative, IT, finance, and executive segments, using realistic, healthcare-specific attack scenarios modeled on the Q1 2026 incident. Every employee who clicked received a five-minute, non-punitive training moment, and every report earned a same-minute thank-you. Individual results are protected — they never appear in performance reviews, and managers see team averages only. This brief answers three questions: whether we are safer, whether we are improving, and what changes next.

## Metrics Table

| What we measure | Before the program | Today (6 months) | 12-month target | Healthcare benchmark | Status |
|---|---:|---:|---:|---:|---|
| Employees acting on a simulated attack ("click rate") | 56% — more than 1 in 2 | [CURRENT]% | ≤25% | [BENCHMARK](#ref-BENCHMARK) | [G/Y/R] |
| Employees reporting a simulated attack ("report rate") | 15% — 6 of 41 targeted | [CURRENT]% | ≥50% | [BENCHMARK](#ref-BENCHMARK) | [G/Y/R] |
| Average time to report a suspicious message | 74 minutes | [CURRENT] min | ≤15 min | [BENCHMARK](#ref-BENCHMARK) | [G/Y/R] |
| Employees clicking in consecutive waves, after coaching ("repeat rate") | Never measured | [CURRENT]% | <8% | [BENCHMARK](#ref-BENCHMARK) | [G/Y/R] |
| Clicked-then-trained within 72 hours | Never measured | [CURRENT]% | ≥95% | [BENCHMARK](#ref-BENCHMARK) | [G/Y/R] |
| Clinically targeted staff acting on a lure | 67% — the Q1 worst-performing group | [CURRENT]% | ≤25% | [BENCHMARK](#ref-BENCHMARK) | [G/Y/R] |

† **Benchmark note (retain in presentation):** healthcare-sector benchmarks come from the external benchmarking engagement funded in Year 1; where the engagement has not yet returned data, present the column as "pending" rather than estimating. Internal planning ranges from our own sector research (`lure_effectiveness_benchmarks.md`) are the fallback reference, labeled as internal assumptions, never as industry fact.

## Key Findings — What the Data Says About Employee Behavior

1. **[Finding on trajectory]:** e.g., "Acting on simulated attacks fell from 56% to [X]%. Put plainly: at the start of the year, more than half of us who received a realistic attack would act on it; today that is roughly [1 in N]." *(State the finding as a fraction of people, not only a percentage.)*
2. **[Finding on reporting culture]:** e.g., "Reports rose from 15% to [X]% and arrive in [X] minutes instead of 74. Each report is an early alarm the SOC receives from a person instead of a machine hours later."
3. **[Finding on the hardest group]:** [Clinical staff / finance staff / executives] finding, with the comparison to their own baseline spelled out.
4. **[Honest limitation]:** e.g., "A low click rate on simulations does not prove immunity to novel attacks; it proves improved performance against the attack patterns we know are in use. Confidence in the trend: [high/moderate/low], because [N] waves / [N] months of data."
5. **[Concurrent-controls caveat — mandatory]:** "During the same six months, MedDefense also completed [SOC automation improvements / IAM remediation from the 6x02 audit]. We cannot cleanly separate how much of the improvement in real-incident detection belongs to the awareness program versus these technical controls. The simulation metrics above are the program's own: they measure employee behavior directly and cannot be produced by any technical control."

## Recommendations for the Next Six Months

1. [Recommendation — e.g., tier escalation, new segment, refresh of retired templates]
2. [Recommendation — e.g., vishing expansion per Month 3 tabletop results]
3. [Budget/action request, phrased for the Decisions Needed table of `board_reporting_template.md`]

## Bottom Line

**[ONE SENTENCE — template: "Employees are clicking less ([56%→X%]), reporting faster ([74→X] minutes), and repeat risky behavior is [declining/being established at X%], so the human layer that failed in Q1 is measurably harder to exploit — and the next six months will show whether the trend holds."]**

---

## Part 2: Quarterly Metrics Dashboard Template

*Instructions to the program manager: complete one copy per quarter. Delta notation is percentage points (pp) between the two most recent quarters; time metrics use minutes. Status rules are fixed and non-discretionary.*

# Quarterly Metrics Dashboard — Q[X] FY[YYYY]

**Reporting period:** [DATES] | **Waves run this quarter:** [IDs] | **Segments targeted:** [LIST] | **Prepared:** [DATE] | **Reviewer:** SOC Manager | **Approvers:** CISO, HR Director

## Metric Tracking Table

| # | Metric | Prior quarter | This quarter | Δ (pp / min) | Target | Status | Notes |
|---|---|---:|---:|---:|---:|---|---|
| 1 | Overall click rate | [%] | [%] | [±X pp] | ≤ [tier target] | 🟢/🟡/🔴 | |
| 2 | Clinical click rate (SEG-A/B) | [%] | [%] | [±X pp] | ≤ [tier target] | 🟢/🟡/🔴 | |
| 3 | Report rate | [%] | [%] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 | |
| 4 | Mean time to report | [min] | [min] | [±X min] | ≤ [tier target] | 🟢/🟡/🔴 | |
| 5 | Repeat-clicker rate | [%] | [%] | [±X pp] | < [tier target] | 🟢/🟡/🔴 | |
| 6 | Post-simulation training completion (72h) | [%] | [%] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 | |
| 7 | False-positive report rate | [%] | [%] | [±X pp] | "operationally manageable" | 🟢/🟡/🔴 | SOC workload note |
| 8 | Finance BEC verification rate (Wave 4 onward) | [%/n.m.] | [%/n.m.] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 | n.m. = not measured |
| 9 | Vishing verification success (exercises this quarter) | [%/n.m.] | [%/n.m.] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 | |
| 10 | Manager escalation confidence (survey) | [score] | [score] | [±X] | improvement vs. baseline | 🟢/🟡/🔴 | Survey quarters only |
| 11 | Report-before-click events (leading indicator) | [#] | [#] | [±X] | rising | 🟢/🟡/🔴 | Count, not rate |
| 12 | Real phishing emails reported by employees (not simulations) | [#] | [#] | [±X] | rising | 🟢/🟡/🔴 | Feeds Part 3 |

## Status Definitions (fixed rules — apply mechanically)

- **🟢 Green:** at or better than the current-quarter tier target, or improving on trajectory to it.
- **🟡 Yellow:** within 10 percentage points of target (or 10 minutes for time metrics) and directionally correct, **or** any metric at target but flat for two consecutive quarters (flat-at-target is green only when it has hit its tier ceiling).
- **🔴 Red:** worse than 10 points from target, moving away from target, **or** any direction reversal of ≥10 points in a single quarter.
- **Special rules:** metric 7 (false positives) is yellow only when SOC triage absorbs reports without added analyst queue time — a rising false-positive rate with report rate rising is expected and typically green; metric 11 and 12 are count-based leading indicators — yellow if flat, red if declining while simulation volume continued.

## Overall Program Status (single determination per quarter)

**Overall status: 🟢 / 🟡 / 🔴 — determined by fixed aggregation rules, not judgment:**

| Condition | Overall status |
|---|---|
| Metrics 1–6 (core behavior metrics) all Green | 🟢 Green |
| 1–2 core metrics Yellow, none Red | 🟡 Yellow |
| Any core metric Red, **or** 3+ Yellow | 🔴 Red |
| **Override rule:** metrics 1 (click) and 3 (report) both worsening in the same quarter forces 🔴 regardless of the rest — simultaneous click-rise/report-fall is the signature of a program failing or of an outside event corrupting the data, and either requires review (Part 4) |

**Quarter narrative (3 sentences max):** [What moved, why, what happens next quarter.]

**Actions triggered this quarter:** [List any Part 4 reviews initiated, waves paused, or template retirements — with initiator and date.]

---

## Part 3: Incident Correlation Methodology

### The core challenge, stated plainly

We cannot run a controlled experiment on a live workforce. There is no control group of MedDefense employees left untrained while the rest are trained, and we would not create one if we could. Additionally, real incident frequency is a lagging, noisy, low-frequency signal — a healthcare organization hopes to have so few real phishing incidents per quarter that no single quarter's count is statistically meaningful on its own. The methodology therefore measures what can be measured directly (behavior in simulations), correlates what can only be correlated (real incidents), and assigns confidence honestly rather than claiming causation the data cannot support.

### What data to collect

**Tier A — direct behavioral measurement (simulation telemetry; the program's own evidence):** click, report, and repeat rates; mean time to report; training completion — by wave, segment, and template. These measure employee behavior directly and cannot be produced by any concurrent technical control, which makes them the program's defensible core.

**Tier B — real-world leading indicators (behavioral, outside simulations):** employee reports of *real* phishing emails (dashboard metric 12); report-before-first-click events on genuine campaigns; helpdesk verification calls initiated by employees who refused to act on a request first. These show trained behavior occurring unprompted in the wild.

**Tier C — real incident and threat data (lagging, contaminated by confounders):** phishing emails reaching inboxes (gateway volume), credential-exposure incidents, incidents requiring IR activation, and mean detection time. Also collected: the confounder registry (below), because Tier C is exactly where concurrent security improvements muddy attribution.

**The confounder registry (maintained quarterly by the program manager, reviewed by the SOC Manager):** every concurrent control change that plausibly affects Tier C — e.g., email gateway policy updates, the SOC automation rollout, MFA enforcement from the 6x02 remediation, mail-filter tuning, EDR coverage changes. Any quarter in which a registry entry materially changed, Tier C analysis for that quarter carries an automatic attribution caveat. This is the mechanism that makes honest failure-to-attribute systematic instead of ad hoc.

### Attribution rules — how to attribute, and how to honestly fail to

1. **Claim direct attribution only for Tier A.** "The awareness program moved click rate from 56% to X%" is a causal claim the program's own data supports — the only influence on simulation click rate is employee behavior and lure calibration (both disclosed via the tier system).
2. **Claim association, not causation, for Tier B and C, with named alternatives.** Correct form: "Real-incident detections improved [X]% during the program period, *consistent with* the measured behavioral improvements, though improved gateway filtering and SOC automation were also in effect and cannot be excluded as contributors." Incorrect form: "The awareness program cut incidents by X%." The brief template's mandatory caveat section (Part 1, Finding 5) enforces this.
3. **Use the interrupted time-series logic where data allows:** compare the pre-program baseline period (which we are lucky to have — the Q1 2026 incident provides a fully documented pre-program baseline: 56% click, 15% report, 74-minute MTTR, `post_incident_click_rate_review.md`) against post-program quarters, looking for a change in *level and trend* rather than a single before/after comparison. An isolated bad quarter during a correctly trending series is noise; a genuine trend break is evidence.
4. **Refuse small-number conclusions.** With expected real-incident counts in single digits per quarter, quarter-over-quarter changes of one or two incidents mean nothing and the methodology says so. Interpretation of Tier C requires rolling 6-month windows minimum.
5. **Attribute by exclusion where possible:** if an incident class the program targets (credential exposure via phishing) improves while an unrelated class (e.g., lost devices) stays flat, the differential pattern weakly supports the program's contribution — this triangulation across incident classes is the closest a live workforce gets to a control condition, and it is labeled "weak" evidence even when it works.

### Presenting ROI honestly to a board that wants numbers

Boards want "we spent $84,000 and avoided $X in losses." The honest, defensible version the brief delivers has three elements, in this order:

1. **The program's guaranteed output:** behavioral metrics against baseline, presented as risk-reduction input — "the failure that started the Q1 incident (a 56% click rate) has been reduced to [X]% in controlled testing."
2. **The conditional framing:** "Reducing click rate and increasing report speed decreases attacker dwell time and downstream containment cost" (`budget_assumptions.md`) — presented as mechanism, not receipt: *if* the behavioral improvements hold, *then* the incident path documented in Q1 becomes proportionally less probable, because the documented chain began at the human layer and had no other entry point.
3. **The explicit non-claim:** "We cannot guarantee that prevented incidents would have occurred; avoided-cost figures are therefore scenario estimates, and we present them as such if at all." Where an estimate is unavoidable for the finance committee, derive it from documented incident-response costs (IR activation, containment, forensics, credential reset, executive communications from the Q1 activation) against the measured behavioral delta, label it a planning scenario, and show the assumption list on the same page.

One-sentence board answer, ready-made: *"The awareness program directly controls and demonstrates employee behavior change; real-world incident trends are consistent with improvement but cannot be solely attributed to this program given concurrent security investments — which is why the board sees both numbers every quarter, labeled separately."*

---

## Part 4: Program Improvement Triggers

### Thresholds that initiate a formal program review

Reviews are triggered mechanically by the dashboard (Part 2); nobody has to argue for one. The program manager records trigger conditions in the quarterly dashboard's "Actions triggered" field; the review itself is a standing agenda item at the next quarterly CISO+HR metrics review.

| Trigger | Definition | Review initiator | Data assessed |
|---|---|---|---|
| **T1 — Deteriorating core trend** | Any core metric (dashboard 1–6) shows a worsening delta for **three consecutive quarters**, or worsens ≥10 points within a single quarter | SOC Manager flags; CISO initiates | Wave-level telemetry, tier mix, template ages, delivery timing, segment breakdowns |
| **T2 — Signature failure pattern** | Click rate rising while report rate falls in the same quarter (the Part 2 override signature) | Automatic on dashboard completion | Culture indicators: reinforcement SLA performance, HR distress-contact volume, manager feedback, any punitive signal leaking into the organization |
| **T3 — Segment stall** | Any segment's click rate misses its tier target by >10 points for two consecutive quarters | Program manager flags; CISO initiates with the relevant advisory reviewer (Clinical Ops for clinical segments, Finance Rep for SEG-E/F) | Segment-specific guides, wave timing against `clinical_schedule_constraints.md`, lure realism review |
| **T4 — Escalation-signal trigger** | Repeat-clicker rate exceeding its tier target after coaching is complete, or any single metric requiring HR coordination | HR Director initiates | Coaching-process data under `hr_privacy_rules.md` handling |
| **T5 — Real-incident correlation** | A real phishing or social-engineering incident occurs that the simulation program's current templates did not model, or that succeeded against trained employees | SOC Manager initiates within 5 business days | Incident lure vs. current template inventory; failure point mapped against `cobalt_strike_phishing_path.md` human-layer decision points |
| **T6 — Welfare trigger** | Any employee welfare concern raised mid-campaign (see below) | HR Director (or Clinical Operations for patient-safety concerns) — either may act unilaterally | The specific concern, its scope, and remediation |

**What a deteriorating trend looks like across three consecutive quarters (the T1 test made concrete):** it is not one bad quarter — a wave that lands during a staffing crunch, a new template tier, or a seasonal stressor can dip any single metric. A T1-worthy deterioration is: click rate up two quarters in a row *while* report rate is flat or down; or mean time to report rising across three quarters; or training completion decaying monotonically while assignment volumes are constant. The pattern matters more than any single delta, which is why T1 reads the dashboard's trend column, not the quarterly snapshot.

### Review mechanics

Every triggered review assesses the same four questions: (1) is the measurement sound (platform telemetry, denominators, segment sampling)? (2) is the content stale (template ages against the retirement rule in `awareness_program_plan.md`)? (3) is delivery misaligned (timing, exclusions, cool-downs)? (4) is there an organizational cause outside the program's control (seasonal load, turnover, concurrent change fatigue from the 14-module clinical burden)? Findings go to the next CISO+HR quarterly review; corrective actions enter the dashboard's action log with owners and dates.

### Authority to pause a simulation wave mid-campaign

This authority is deliberately split and deliberately fast, because a wave pause is a safety action, not a governance debate:

- **HR Director (Maria Santos): unilateral authority to pause any wave, mid-send, on any employee welfare concern** — distress reports, support-plan conflicts, or a punitive signal observed anywhere in the organization. Pause does not require CISO concurrence and is reported, not requested. The HR privacy boundary makes welfare the one domain where the program's own rules say training stops until the people are safe.
- **Clinical Operations (Sarah Park): unilateral authority to pause any clinical wave** on a patient-safety concern — staffing shortage declaration, active code activity, or an emerging clinical event intersecting a delivery window. This mirrors the exclusion rules in `clinical_schedule_constraints.md`: "campaign design must balance realism with operational safety."
- **SOC Manager: unilateral authority to pause any wave during a real incident** or when simulation telemetry is contaminating incident triage, per the mid-wave incident protocol in `awareness_program_plan.md` Section 4.
- **Resume authority:** the pausing authority confirms the condition is cleared and the cool-down is recalculated from the actual resume date; the program manager documents the pause window and re-plans the wave against the 21-day rule. Paused waves are rescheduled, never compressed.

**Standing rule for all six triggers:** no trigger is a career event for the program manager. The program's measurement system is designed so that deterioration surfaces automatically and improvement is the *expected* response — a program that hides its bad quarters loses the board's trust in its good ones, and the same principle applies inward.

---

## Closing Note — The Feedback Loop This Artifact Completes

The program now closes its own loop: the threat profile (Task 1) dictates the simulations; simulations generate the behavioral data; the dashboard converts data to status each quarter; triggers convert bad status to reviews; reviews convert to calendar and template changes; and the board brief converts all of it into the two sentences that sustain funding: **what employees now do differently, and what changes next.** A program with this loop defends its own budget at renewal time — with numbers it can prove are its own.
