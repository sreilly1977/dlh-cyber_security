# Annual Security Awareness Program Plan: MedDefense Health Systems

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-10
**Version:** 1.0
**Prepared for:** Dr. Patricia Morales, CISO — Q3 2026 board presentation
**Classification:** Confidential
**Materials basis:** `annual_calendar_constraints.md`, `budget_assumptions.md`, `metrics_baseline.csv`, `program_governance_roles.md`, `workforce_population_breakdown.csv`, `clinical_schedule_constraints.md`, `board_reporting_template.md`, `lure_effectiveness_benchmarks.md`, plus project artifacts `phishing_campaign_plan.md`, `post_click_intervention.md`, and the four role-based quick guides

---

## 1. Executive Summary

In March 2026, MedDefense suffered a Cobalt Strike compromise that began with 41 phishing emails delivered over 36 hours using healthcare-specific lures. Twenty-three employees clicked — a 56% click rate, including 67% among clinical floor staff — and six submitted credentials to a fake Epic authentication page. Only two employees reported the messages before the SOC alert fired; mean time to report was 74 minutes, and the gap between the first click and the first SIEM correlation was 4 hours 33 minutes. Credential exposure was confirmed, a Cobalt Strike beacon was detected, service-account misuse drove lateral movement, and the incident required full IR activation, endpoint containment, forensic reconstruction, enterprise credential resets, and executive communications (`module5_incident_summary.md`, `campaign_reconstruction.md`, `post_incident_click_rate_review.md`). The root cause sat at the human layer: employees lacked phishing recognition tied to their actual clinical and administrative workflows, reporting was slow and fear-driven, and no simulation program existed to measure or change any of it. Every technical control downstream of the first click worked — and every one of them was carrying weight that a behavior change program should have reduced.

This program replaces compliance-artifact training with measured behavior change, built on four mechanisms evidenced in the incident review. Continuous simulation waves calibrated to documented attacker behavior train recognition on the exact lure patterns that worked in Q1 — Epic account threats, compliance framing, vendor pressure, executive impersonation. Immediate post-click microtraining teaches at the moment of failure, in under five minutes, without shaming — because fear of blame is what suppressed Q1 reporting. Role-segmented guidance targets each workforce population with the threats it actually faces, in language it will actually read. And the metrics framework measures what employees *do* — click rate, report rate, time to report, repeat behavior — not how many training certificates were issued. Individual results are protected by HR boundary rules and never touch performance reviews; managers see aggregates only.

At 12 months the board should expect: overall click rate at or below 25% (baseline 56%), report rate at or above 50% (baseline 15%), mean time to report at 15 minutes or less (baseline 74), repeat-clicker rate below 8% (currently unmeasured), and post-click training completion at 95% within 72 hours. At 36 months: click rate at or below 12%, report rate at or above 70%, mean time to report at 10 minutes or less, and repeat-clicker rate below 4% (`metrics_baseline.csv`, with 18-month anchors from `lure_effectiveness_benchmarks.md`). Every figure above is a behavior metric a board member can read directly against its baseline.

---

## 2. Annual Campaign Calendar

Month numbering runs from program start (the 90-day rollout in `phishing_campaign_plan.md` begins at Month 1 following CISO + HR sign-off). The restricted windows fall in Months 10-12 per `annual_calendar_constraints.md`, reflecting Sarah Park's hard rule: no new clinical training content during the Joint Commission accreditation window (Q4) and no new clinical campaigns during flu-season peak (November-January); existing content, reinforcement reminders, and microtraining remain available throughout. All clinical waves respect the safe delivery windows in `clinical_schedule_constraints.md`; every wave enforces the 21-day cool-down.

| Month | Campaign type | Audience | Delivery method | Success metric for the campaign |
|---|---|---|---|---|
| 1 | Baseline phishing waves: T-EPIC-01 + T-MFA-02 | SEG-B clinical (860), SEG-C admin/billing (420) | Email simulation, shift-start and business-hours windows | Denominators established; clinical click rate ≤40%, admin ≤35%; report rate ≥35% of the SEG-C cohort |
| 2 | Post-click intervention and reporting reinforcement | All Wave 1 clickers + all staff | LPV landing pages, MT microtraining, 60-second report reinforcement | ≥90% of clickers complete microtraining within 72h; report-button usage doubles vs. baseline |
| 3 | Wave 2 (intermediate): T-HR-03 benefits lure + secure-message lure; vishing tabletop | SEG-A supervisors, SEG-C remainder, SEG-E; supervisors (34 nursing supervisors) | Email simulation; facilitated vishing tabletop (V-01/V-02) | Vishing full-pass rate ≥50% of tabletop participants; SEG-C/E click rate within the 22-38% planning band |
| 4 | Role-based quick guides rollout | All 17 departments | Four 90-second guides: clinical, IT, executive, remote worker | ≥80% guide completion across targeted segments; manager-visible knowledge of report path |
| 5 | Finance/executive BEC simulation: T-BEC-04 (advanced) | SEG-E (75), SEG-F (35) | Coordinated email simulation, executive-office scheduling | BEC verification rate baseline established; zero replies to caller-supplied channel; SEG-F report rate ≥25% |
| 6 | Insider threat awareness manager training | All department managers, IT, HR | Live training on `insider_threat_program.md` manager guide (post-Legal review) | Manager escalation confidence baseline surveyed; ≥90% attendance |
| 7 | Wave 3 (intermediate + repeat measurement): patient-message lure + vendor-support lure | SEG-B, SEG-D | Email simulation; IT waves outside IR periods | Repeat-clicker rate established (target <12%); SEG-D response to vendor framing quantified |
| 8 | Remote worker security campaign | Remote administrative staff (84) + remote workers across segments | Remote-work guide refresh, VPN/MFA-themed simulation | Remote-segment report rate ≥35%; zero credential submissions |
| 9 | Program metrics review | CISO, HR, program team | Quarterly metrics package per `board_reporting_template.md` | Board pack delivered; targeting strategy and tier mix updated from wave data |
| 10 | **Restricted window — accreditation (Q4)** | — | Reinforcement only; existing microtraining stays available; no new clinical content | Maintenance metric: report-button reinforcement response rate stable |
| 11 | **Restricted window — flu season peak** | Non-clinical segments only (SEG-C/D/E low-intensity reminders) | Existing content, report-button nudges; no new clinical campaigns | Maintenance metric: mean time to report for voluntarily reported real emails |
| 12 | Annual board metrics and Year 2 plan | Board Risk Committee | Annual board brief; budget decision on Year 2 funding | Board resolution passed; 12-month targets (Section 5) assessed and reported |

**Seasonality note:** if program start shifts such that Months 1-3 collide with flu season or accreditation, the calendar slides rather than overrides: clinical waves are deferred, non-clinical waves advance, and the 21-day cool-down is recalculated from actual send dates (`phishing_campaign_plan.md`, concurrency gates).

---

## 3. Budget Justification

Year 1 planning total of $84,000 from `budget_assumptions.md`, reorganized into the board's requested categories. Two honesty items first: the workforce materials disagree on population (department totals sum to 1,311; segment estimates to 1,610), so time-based calculations use segment estimates pending HRIS reconciliation; and `budget_assumptions.md` contains no external benchmarking line — the proposal below funds it from contingency and flags it for the Finance Representative rather than inventing a seventh line.

| Category | Year 1 cost | What it purchases | Cost of not having it |
|---|---:|---|---|
| Simulation platform licensing | $28,000 | Campaign scheduling, segment targeting, landing-page response, report-button integration, HR-private individual-data handling | Manual campaigns are possible (`budget_assumptions.md`) but metrics quality, segmentation, landing-page response, and the HR privacy controls that make the program non-punitive all degrade; individual results become harder to protect precisely when trust is the program's currency |
| Content development | $18,000 + $6,000 | $18k: role-based guides, microtraining modules, templates, vishing scripts. $6k: translation/accessibility/plain-language review (`budget_governance` line folded here) | 14 mandatory modules already compete for clinical attention (`security_awareness_gap_notes.md`); unedited compliance prose is unread by the people it targets, and inaccessible content fails both equity and the test the program was built on |
| Training delivery time (opportunity cost) | ~129 staff-hours (non-cash) | Itemized below: quick guides ~30h; microtraining ~58h (est. 700 clickers at 5 min); Wave 1 employee response time ~26h; vishing tabletop ~9h; manager training ~6h (formula, count TBD) | Compare against the Q1 incident's consumed time: IR activation, endpoint containment, forensic analysis, enterprise credential resets, executive communications — days of specialist effort triggered by 11 wasted minutes (`campaign_reconstruction.md`: mean time to first click). Wage conversion requires the loaded blended rate Finance holds; the hours are the defensible quantity |
| External benchmarking | $4,000 (drawn from contingency) | Healthcare-sector benchmark comparison for click/report/MTTR rates to contextualize board metrics annually | Board metrics float without context: 25% click rate reads differently against sector peers. **Gap flagged:** no benchmarking line exists in `budget_assumptions.md`; this proposal draws from the $7,000 contingency with Finance Representative approval |
| Program management overhead | $5,000 + $8,000 + $7,000 remainder | $5k: HR/legal review of ethics and escalation materials. $8k: metrics dashboard and board-pack preparation. $7k remaining contingency: template refresh and incident-driven updates | Without HR/legal review the program cannot honor its own privacy boundary (a launch precondition, not a luxury); without the dashboard, quarterly board reporting regresses to anecdote; without contingency, a real-world phishing event mid-year leaves the program unable to adapt |

**Line-item derivation (delivery time, all planning estimates from segment populations):**

- Quick guides: 90 seconds × targeted segments (clinical 975 + IT 105 + executive 35 + remote 84 = 1,199 readers) ≈ **30 hours**
- Post-click microtraining: estimated ~700 Year 1 clickers (declining rates across waves) × 5 minutes ≈ **58 hours** — estimate converges to measurement once Wave 1 lands
- Wave 1 employee response overhead: 1,280 recipients × ~90 seconds average (receive, scan, report or ignore) ≈ **26 hours**
- Vishing tabletop: 34 nursing supervisors (`workforce_population_breakdown.csv`) × 15 minutes ≈ **9 hours**, plus facilitation time (contracted in the $12,000 vishing facilitation line of the original budget, administered under content development here)
- Insider threat manager training: [MANAGER_COUNT] × 60 minutes ≈ **6 hours at an assumed 60 managers** — manager headcount is not documented in the materials; the formula ships with the plan and HR fills the count before Month 6

**Risk-reduction rationale (verbatim logic from `budget_assumptions.md`):** reducing click rate and increasing report speed decreases attacker dwell time and downstream containment cost. The Q1 chain ran from a click to a beacon to IR activation in a single night; the 12-month targets (click 25%, report 50%, MTTR 15 min) are the measurable expression of cutting that chain at its origin.

---

## 4. Governance Framework

### Roles and responsibilities

| Function | Role | Responsibilities |
|---|---|---|
| Program owner | CISO (Dr. Patricia Morales), delegated day-to-day to IT Security Awareness Lead | Program strategy, board reporting, final approval of high-risk templates; the accountable name the board sees |
| Content approver | CISO + HR Director jointly (Maria Santos); Legal added for insider-threat and recorded-vishing content | No template, guide, or scenario deploys without sign-off per the `simulation_ethics_guidelines.md` approval table; HR owns the privacy boundary as a hard veto |
| Simulation operator | IT Security Awareness Lead | Runs waves, owns individual-result data (sole holder), assigns microtraining, maintains exclusion lists and cool-downs |
| Metrics reviewer | SOC Manager (operational) + CISO and HR (quarterly) | False-positive workflow, report triage SLAs, quarterly metric packs; quarterly review is mandatory (`program_governance_roles.md`) |
| Escalation authority | HR Director, with Legal | Owns the repeat-click escalation trigger, coaching process, anonymous-path go-live review, and any insider-threat escalation crossing the Section 3.3 threshold of `insider_threat_program.md` |
| Advisory reviewers | Clinical Ops (Sarah Park), Finance Representative, Communications Lead | Clinical timing/patient safety, BEC scenario realism, plain-language review — the realism and safety valves that keep the program credible to the workforce |

### Reporting cadence

| Audience | Content | Frequency |
|---|---|---|
| Board Risk Committee | Four headline metrics — click rate, report rate, mean time to report, repeat-clicker rate — plus plain-language risk message and decisions-needed table, per `board_reporting_template.md` | Quarterly, with the annual brief in Month 12 |
| CISO + HR | Full metrics pack including clinical-subset click rate, completion rates, false-positive rate | Quarterly |
| Program manager | Wave-level telemetry: delivery, open, click, report, MTTR, completion | Per wave and monthly rollup |
| Department managers | Aggregate team trends only; never individual results (`hr_privacy_rules.md`) | Monthly |
| Workforce | The quarterly transparency note from `insider_threat_program.md` 3.2 — report volume, triage outcomes — sustaining trust that reports go somewhere | Quarterly |

### Review cycle

- **Template retirement:** a template retires when its cohort's click rate on it falls below the 18-month overall target (12%) across two consecutive waves — it has finished teaching — or immediately if a real-world campaign begins mimicking it too closely (recycled content trains attackers as well as employees). Retired templates enter the refresh pool funded by contingency.
- **Targeting strategy updates:** annually at Month 9 (feeding the Month 12 board brief) and after any real incident; wave composition, tier mix, and segment priorities re-rank against fresh click/report data and current threat patterns.
- **Mid-wave real-phishing incident protocol:** if a genuine phishing campaign or IR activation occurs during an active wave — the IT-vendor overlap seen in Q1 makes this likely — the wave pauses immediately (constraint: no simulations during declared downtime or active incident response, `clinical_schedule_constraints.md`); the SOC is notified so simulation telemetry cannot contaminate incident triage; the real campaign's lures are compared against live templates for collision; already-delivered simulations continue to receive their landing pages; and the wave resumes or is re-planned under the cool-down rules, never overlapped with incident recovery.

---

## 5. Success Criteria

These are the exact figures Dr. Morales reports to the board. 12-month and 36-month targets come from `metrics_baseline.csv`; the 24-month column is a program-set consolidation milestone interpolated between the documented 18-month anchors (`lure_effectiveness_benchmarks.md`) and 36-month targets, and is labeled as a derived planning value rather than a documented target.

| Metric | Baseline (Q1 2026) | 12 months | 24 months | 36 months |
|---|---:|---:|---:|---:|
| Overall click rate | 56% | ≤25% | ≤12% sustained | ≤12% |
| Clinical click rate | 67% | ≤25% | ≤18% (derived) | ≤12% |
| Report rate | 15% | ≥50% | ≥65% | ≥70% |
| Mean time to report | 74 min | ≤15 min | ≤10 min | ≤10 min |
| Repeat-clicker rate | unmeasured | <8% | ≤4% | <4% |
| Post-click training completion (72h) | unmeasured | ≥95% | ≥95% | ≥98% |
| Finance BEC verification rate | unmeasured | ≥80% | ~87% (derived) | ≥95% |
| Vishing verification success | unmeasured | ≥75% | ~82% (derived) | ≥90% |
| Manager escalation confidence | unmeasured | +25% vs. baseline survey | ~+37% (derived) | +50% |

**Board-readable interpretation (plain-language framing for the four headline metrics):**

- **Click rate ≤25% at 12 months** means: fewer than one in four employees acts on a realistic, healthcare-specific lure — versus more than one in two today.
- **Report rate ≥50%** means: half of targeted employees act as distributed sensors, giving the SOC early warning that in Q1 arrived from only 6 of 41 recipients.
- **Mean time to report ≤15 minutes** means: the attacker's head start shrinks from over an hour to minutes — dwell time is the cost driver identified in `budget_assumptions.md`.
- **Repeat-clicker rate <8%** means: coaching works — employees who clicked once learn the pattern, verified by consecutive-wave measurement rather than course completion.

**What failure looks like (so the board can recognize it):** if at 12 months click rate stalls above 35% or report rate stalls below 35%, the program recalibrates tier mix and delivery windows at the Month 9 review before requesting Year 2 funds for scale; if reporting culture metrics decline while click rate improves, that pattern indicates suppression, not learning, and triggers an HR-led trust review — the Q1 evidence shows a silenced reporter is worse than a clicker, because the clicker at least generated telemetry.

**Resolution sought (per `board_reporting_template.md` format):** the Board Risk Committee acknowledges receipt of the MedDefense Security Awareness Program Report and authorizes the Year 1 budget of $84,000 and the Q1 (Month 1-3) campaign calendar.
