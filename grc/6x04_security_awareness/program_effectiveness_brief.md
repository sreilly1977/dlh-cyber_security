# Program Effectiveness Brief: MedDefense Security Awareness Program

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-10
**Version:** 2.0 (board-readability revision)
**Classification:** Confidential
**Prepared for:** Dr. Patricia Morales, CISO — 6-month board presentation
**Framing (James Chen):** "Three questions. Are we safer? Are we improving? What changes next?"
**Materials basis:** `awareness_program_plan.md`, `phishing_campaign_plan.md`, `metrics_baseline.csv`, `board_reporting_template.md`, `program_governance_roles.md`, `post_incident_click_rate_review.md`, `security_awareness_gap_notes.md`, `lure_effectiveness_benchmarks.md`

**How this document works:** Part 1 is the brief Dr. Morales presents — written entirely for a board audience. Part 2 is the quarterly tracking sheet the program manager uses between presentations (kept compact on purpose; the board sees only its headline). Part 3 answers the board's hardest question in plain language: "how do we know this program reduced real incidents?" Part 4 defines, in one paragraph each, the conditions under which the program formally reviews itself.

Two rules govern every number that reaches the board:

1. **Numbers are always people, never naked percentages.** "1 in 4" travels with "of the employees tested." A percentage a board member cannot picture has not been presented.
2. **Attribution honesty is built in, not appended.** Concurrent security improvements (SOC automation, IAM remediation) ran during the same period; every claim distinguishes what this program directly controls from what it merely correlates with.

---

## Part 1: Board-Ready Effectiveness Brief Template (6-Month)

*Instructions to the program owner: fill each `[bracketed]` field with actual data and follow the worked example shown in the "Before" column — every figure appears with its people-context. Two pages, printed, presented without technical support in the room.*

---

# MedDefense Security Awareness Program — Six-Month Effectiveness Brief

**Reporting period:** [MONTH YEAR] – [MONTH YEAR] | **Presented:** [DATE] | **Prepared by:** IT Security Awareness Lead

## Program Summary

In March, a realistic fake email about blocked patient records reached 41 of our staff. More than half acted on it, six typed their passwords into a fake site, and only a handful raised the alarm — the resulting security incident took a full response effort to contain. Since [PROGRAM_START], this program has tested our workforce with the same kinds of realistic attacks in a safe, no-blame setting, taught every person who clicked for five minutes at the moment of the mistake, and thanked every person who reported — immediately. Individual results stay private; managers see only team averages; nothing touches performance reviews. This brief answers three questions: are we safer, are we improving, and what changes next.

## How We Compare — Today Against Where We Started

*The comparison standard for a program this age is threefold: our own Q1 incident baseline (fully documented), the Year 1 goals the board approved in March, and healthcare-sector planning ranges from our Year 1 research — shown as a reference range, clearly labeled, until the external benchmarking study the board funded returns its first data. Where a figure is not yet measured, the cell says so plainly.*

| What we measure | Before (March incident) | Where we are today | Goal for this year | Sector reference range* |
|---|---|---|---|---|
| Employees who act on a realistic test attack | 56% — more than 1 in every 2 tested employees | [X]% — about 1 in [N] of the [N] tested this wave | 25% or less — at most 1 in 4 | Typical healthcare results run [30-60]% on first exposures |
| Employees who report the test attack | 15% — only about 6 of 41 raised the alarm | [X]% — [N] in every 10 targeted now report | 50% or more — half act as early alarms | Reported rates in sector programs typically sit [below 35%] |
| How fast an attack gets reported | 74 minutes — the attacker had over an hour of head start | [X] minutes — roughly [a quarter of] the original head start | 15 minutes or less | No comparable internal range; first-year goal is the standard |
| Staff who clicked again in the following test, after coaching | Never measured before this program | [X]% — [N] of the [N] retested | Under 8% | New measurement for the sector; the goal is the standard |
| Clickers finishing their 5-minute lesson within 3 days | Never measured before this program | [X]% — [N] of the [N] who clicked | 95% | New measurement for the sector |
| Clinical staff acting on a lure | 67% — 10 of the 15 clinical staff targeted in March | [X]% — about 1 in [N] of the [N] tested | 25% or less | Highest-risk group in every sector dataset we hold |

*Sector reference ranges come from our Year 1 research into healthcare phishing programs (`lure_effectiveness_benchmarks.md`) — internal planning figures, not certified industry data. The external benchmarking study replaces these once its first report is delivered. **Never present a reference range as an industry statistic.***

## Key Findings — What the Data Says About Employee Behavior

*(Draft each finding in people terms; a finding with only a percentage is rewritten before it reaches the slide.)*

1. **Fewer of us fall for realistic attacks.** Acting on a realistic, healthcare-specific attack fell from 56% — more than half of everyone tested in March — to [X]%, roughly [1 in N] of the [N] employees tested this wave. In people terms: in a typical shift-start team of twelve nurses, [seven] would have acted on the fake Epic message in March; today, about [one] would.
2. **More of us raise the alarm, faster.** Reporting rose from 15% (six people out of forty-one) to [X]% — [N] in every 10 targeted employees — and the alarm now reaches the security team in [X] minutes instead of 74. Every report is an early warning that arrives from a person instead of a machine hours later.
3. **The group most at risk improved the most.** Clinical staff — the group that acted on 67% of attacks in March — now act on [X]%. The people our attackers target hardest are measurably harder to deceive.
4. **What this does not yet prove.** Strong results against the attack patterns we test do not guarantee immunity to a brand-new attack type; we measure the threats actually in circulation against our sector. Confidence in the trend is [high/moderate/low], because [N] waves over [N] months is still a short measurement history.
5. **Other things improved at the same time — and we say so.** During this period MedDefense also upgraded [its monitoring automation / identity controls]. We cannot cleanly separate credit for fewer real incidents between those technical upgrades and this program. What we *can* say directly is this: the behavior numbers above measure what employees actually did when tested, and no technical upgrade can produce them.

## What Changes Next (Months 7-12)

1. [Recommendation — e.g., move advanced testing to finance and executive teams now that foundations are in place]
2. [Recommendation — e.g., extend phone-based training to supervisors based on the tabletop results]
3. [Decision requested — phrased for the Decisions Needed table the board already uses]

## Bottom Line

**[ONE SENTENCE — template: "In March, more than half of tested employees acted on a realistic attack and almost nobody reported it; today, about [1 in N] act and [N in 10] report within [X] minutes — the human layer that failed in the spring incident is measurably harder to exploit, and the next six months will show whether the trend holds."]**

---

## Part 2: Quarterly Metrics Dashboard Template

*Tooling note: this sheet is the program manager's working instrument — it tracks every metric from the campaign plan with quarter-over-quarter movement and a color status per metric. The board sees only its final one-line status, quoted into Part 1. Fill one copy per quarter; deltas are percentage points between the two most recent quarters (minutes for time metrics).*

# Quarterly Metrics Dashboard — Q[X] FY[YYYY]

**Period:** [DATES] | **Waves run:** [IDs] | **Segments tested:** [LIST] | **Prepared:** [DATE] | **Reviewed by:** SOC Manager | **Approved by:** CISO, HR Director

| # | Metric | Prior quarter | This quarter | Δ | Target | Status |
|---|---|---:|---:|---:|---:|---|
| 1 | Overall click rate | [%] | [%] | [±X pp] | ≤ [tier target] | 🟢/🟡/🔴 |
| 2 | Clinical click rate | [%] | [%] | [±X pp] | ≤ [tier target] | 🟢/🟡/🔴 |
| 3 | Report rate | [%] | [%] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 |
| 4 | Mean time to report | [min] | [min] | [±X min] | ≤ [tier target] | 🟢/🟡/🔴 |
| 5 | Repeat-clicker rate | [%] | [%] | [±X pp] | < [tier target] | 🟢/🟡/🔴 |
| 6 | Training completion within 72h | [%] | [%] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 |
| 7 | False-positive report rate | [%] | [%] | [±X pp] | operationally manageable | 🟢/🟡/🔴 |
| 8 | Finance BEC verification rate | [%] | [%] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 |
| 9 | Phone-exercise verification success | [%] | [%] | [±X pp] | ≥ [tier target] | 🟢/🟡/🔴 |
| 10 | Manager escalation confidence (survey) | [score] | [score] | [±X] | +improvement | 🟢/🟡/🔴 |
| 11 | Reports made before anyone clicked | [#] | [#] | [±X] | rising | 🟢/🟡/🔴 |
| 12 | Real phishing emails reported by staff | [#] | [#] | [±X] | rising | 🟢/🟡/🔴 |

**Status rules (applied mechanically):** 🟢 at or better than target; 🟡 within 10 points of target and moving the right way; 🔴 more than 10 points off, moving the wrong way, or reversing sharply in a single quarter. Metric 7 is expected to rise alongside report rate and stays green while the SOC absorbs the workload. Metrics 11-12 are early-warning counters: flat is yellow, falling is red.

**Overall quarter status:** 🟢 all core metrics (1-6) green · 🟡 one or two core metrics yellow, none red · 🔴 any core metric red, three or more yellow, **or the failure signature: clicks rising while reports fall in the same quarter** — that combination means either the program is failing or the workforce has stopped trusting it, and either way a formal review starts immediately (Part 4).

**Narrative (three sentences):** [What moved, why, what happens next.]

---

## Part 3: Did This Program Reduce Real Incidents? — Answering the Board Honestly

This is the section a board member will want but rarely gets: a straight answer about what we can and cannot claim. The short version: **we can prove this program changed tested behavior; we can observe that real-incident indicators moved in the right direction; we cannot cleanly prove the program alone caused the incident improvement, because other security upgrades happened during the same period — and pretending otherwise would be the fastest way to lose this board's trust.**

### Why we cannot run a perfect experiment

The only way to *prove* causation would be to leave part of the workforce untrained and compare their incident rates against the trained majority. We will not deliberately leave colleagues unprotected, and the board would not ask us to. Instead we work with the evidence available — the March incident gives us an exceptionally well-documented "before" picture — and we are disciplined about what each piece of evidence can honestly support.

### The three kinds of evidence, in plain terms

**1. Numbers we fully control (our strongest evidence).** Every test wave measures the same thing the same way: did the employee act, did they report, how fast. Because these results come from our own controlled tests, they measure employee behavior alone — no email filter, monitoring upgrade, or identity control can manufacture them. When we say click rate moved from 56% to [X]%, that claim rests entirely on the program.

**2. Early-warning signals in the wild (good corroborating evidence).** We track how often employees spontaneously report *real* suspicious emails — not our tests. In March, spontaneous reporting barely existed (two reports reached the security team before its own alerts fired). Rising voluntary reporting of genuine attacks means trained behavior is happening when nobody is running a test. This is strong circumstantial evidence, though technically other factors could contribute.

**3. Real incident counts (the number the board cares most about — and the least reliable).** Incidents are rare and lumpy. In a good year MedDefense hopes to count them in single digits per quarter, which means any single quarter's rise or fall of one or two incidents tells us almost nothing. We therefore assess real incidents only over rolling six-month windows, and we maintain a plain running list of **every other security change made in the same period** — filter upgrades, monitoring automation, identity fixes from the spring audit. Any quarter in which one of those changed, our incident commentary says so out loud.

### How we present this to the board — the three-sentence discipline

1. **What we prove:** "The program directly moved tested behavior: [56% → X%] of employees act on attacks, [15% → X%] report them."
2. **What we observe:** "Real-world incident indicators moved in the same direction during the program period, consistent with — though not solely caused by — this program."
3. **What we refuse to claim:** "We cannot state a dollar figure for breaches prevented, because we cannot prove an attack that never happened would have succeeded." Where the finance committee requires a figure, we present a clearly labeled *planning scenario*: documented incident-response costs from March (response team activation, containment, forensics, password resets for the enterprise, executive communications) weighed against the measured behavior change, with every assumption listed beside it. It is a scenario, never a receipt.

**One ready-made sentence for the board:** *"This program directly proves employee behavior change; real-incident trends moved the same way, and while monitoring and identity upgrades contributed, no other control can produce the behavior numbers themselves."*

---

## Part 4: When the Program Reviews Itself

Formal reviews are not discretionary — the dashboard starts them. The rules below state, in one paragraph each, what triggers a review, who starts it, and what happens.

**A trend that keeps going the wrong way.** One bad quarter can be a scheduling accident — a wave landing during a staffing crunch, a harder test, a seasonal burden on clinical staff. Three consecutive quarters of a core metric moving the wrong way is a different thing: it is a pattern. The monitoring team flags it, the CISO convenes a formal review, and the review examines the four likely causes in order: a measurement problem, stale test scenarios, poor delivery timing, or pressure on the workforce that has nothing to do with security (turnover, competing training load).

**The trust alarm.** If click rates rise while reporting falls in the same quarter, the program pauses for a specific check: employees may be back to hiding mistakes, as they did in March out of fear of blame. The HR Director leads this review, looking at how fast we thanked reporters, whether any discipline signal has leaked into the culture, and what managers are hearing. No finding in this review can wait a quarter.

**A stubborn segment.** If one department misses its target by more than 10 points for two straight quarters, the CISO and the relevant operational leader (Clinical Operations for clinical units, Finance for payment teams) review that segment specifically — its delivery times, its guides, and whether the test content still resembles what that group actually faces.

**A real attack our tests did not predict.** If a genuine phishing or phone attack succeeds using a pattern our current tests never modeled, the monitoring team conducts a review within five business days, maps the real attacker's steps against our test scenarios, and the next wave incorporates the pattern. This is the fastest improvement loop the program has.

**Stopping a wave that may be hurting someone.** Three people can halt a live wave immediately and without asking permission: the **HR Director** for any employee-welfare concern (distress, a coaching need surfacing mid-wave), the **Clinical Operations lead** for any patient-safety concern (staffing shortfall, active clinical event), and the **SOC Manager** during a real incident, so our test data never muddies a live investigation. A paused wave is rescheduled — never compressed — and the waiting-period rules recalculate from the actual restart date.

**A closing principle for the board:** these triggers exist so that bad news surfaces automatically, not when it is politically convenient. A program that reports its own worst quarters honestly is the only kind this board should keep funding — and these rules are what make the honesty structural rather than personal.

---

## Closing Note — The Feedback Loop This Artifact Completes

The program now closes its own loop: the threat profile dictates the tests; tests generate behavior data; the dashboard turns data into a quarterly status; the triggers turn bad status into reviews; reviews turn into calendar and content changes; and this brief turns all of it into the three answers that sustain funding — **are we safer (yes, measurably, with stated limits), are we improving (the trend says so, quarter by quarter), and what changes next (on the last page, with the decision the board owns).**
