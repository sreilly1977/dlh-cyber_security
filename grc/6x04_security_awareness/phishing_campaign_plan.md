# Phishing Simulation Campaign Plan: MedDefense Health Systems

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-09
**Version:** 1.0
**Classification:** Confidential
**Approval required:** CISO (program strategy and campaign metrics report), HR Director (privacy boundaries and template content), CISO + HR joint sign-off before any template deploys (`simulation_ethics_guidelines.md`, approval table)
**Design brief:** `social_engineering_threat_profile.md` (Task 1)

---

## 1. Campaign Overview

### Scope

- **Organization:** MedDefense Health Systems, 17 departments across clinical, administrative, IT, finance and executive functions.
- **Total population:** The workforce materials provide two different figures, and this plan treats the reconciliation as an open data-quality item rather than choosing silently:
  - `workforce_population_breakdown.csv` department-level totals sum to **1,311 staff**.
  - `employee_segments.csv` segment-level estimates sum to **1,610 staff**.
  - Campaign wave sizing in this plan uses the segment estimates (SEG-A through SEG-F), because targeting, exclusions and manager reporting are all defined at segment level. Before Wave 1 launch, the program manager must reconcile both sources against the HRIS import at platform configuration time and record the true denominator. All rate metrics are computed from the platform's verified delivered count, never from these planning estimates.
- **Program duration:** 90-day initial rollout (Sarah Park approved), continuing into the first-year calendar defined in `annual_calendar_constraints.md`.
- **Platform:** Funded phishing simulation platform ($28,000 Year 1 per `budget_assumptions.md`) providing campaign scheduling, segment targeting, landing-page response, report-button integration and HR-private individual result storage. Manual fallback is possible per `budget_assumptions.md` but degrades metrics quality, segmentation and privacy controls; this plan assumes the funded platform.
- **Out of scope for this document:** vishing live exercises (planned Month 3, designed in Task 6) and insider threat manager training (Month 6). The campaign plan schedules around them; it does not define them.

### Program objectives

Objectives and targets come from `metrics_baseline.csv` and the 18-month targets in `lure_effectiveness_benchmarks.md`:

| Objective | Baseline | 90-day target | 18-month target |
|---|---:|---:|---:|
| Reduce overall click rate | 56% (`post_incident_click_rate_review.md`) | 35% or lower | 12% or lower |
| Increase report rate | 15% | 35% or higher | 65% or higher |
| Reduce mean time to report | 74 minutes | 25 minutes or less | 10 minutes or less |
| Establish and reduce repeat clicker rate | Unknown (no prior program) | Baseline established, under 12% | 4% or lower |
| Post-click training completion within 72 hours | Not measured | 90% | 95%+ |

Behavior is the program's product. Course completion alone is explicitly rejected as a success measure per `module5_incident_summary.md` (root cause 4: training completion existed but produced no behavior change).

### Governance

Per `program_governance_roles.md` and the approval tables in `simulation_ethics_guidelines.md`:

| Function | Owner | Responsibility in this campaign |
|---|---|---|
| Program strategy, board reporting, high-risk template approval | CISO | Approves threat profile, campaign metrics report, all advanced-tier templates |
| Privacy boundary, coaching process, non-punitive policy | HR Director (Maria Santos) | Approves every template alongside CISO; sole joint holder of repeat-click status; owns escalation trigger confirmation |
| Campaign operations, microtraining, metrics | IT Security Awareness Lead | Runs waves, owns individual click/report data, assigns microtraining |
| Simulation report triage, false-positive handling | SOC Manager | Reviews reported simulations; manages false-positive workflow |
| Clinical timing and patient-safety constraints | Clinical Operations Representative (Sarah Park) | Reviews clinical wave timing and exclusion lists before each clinical wave |
| Template launch gate | CISO + HR joint sign-off | No template deploys without both signatures |
| Quarterly metrics review | CISO and HR | Board receives quarterly metrics per `program_governance_roles.md` |

**How findings escalate to HR:** individual click events never reach HR or managers by default. Repeat-click status reaches HR only after the threshold in Section 5, and reaches a department manager only when all four HR privacy conditions in `hr_privacy_rules.md` are met (two consecutive-wave clicks, incomplete assigned microtraining, HR-confirmed trigger, coaching-not-discipline purpose). Simulation results are barred from performance reviews, promotion, compensation and termination decisions (`hr_privacy_rules.md`, Performance Review Boundary).

---

## 2. Employee Segmentation

Six segments from the 6x02 IAM audit basis (`role_inventory.csv`, `employee_segments.csv`). Risk vectors align to the Task 1 threat profile. All segment exclusions below are cumulative with the global exclusions in Section 6.

### SEG-A: Clinical Leadership (charge nurses, nursing supervisors, department clinical leads)

- **Estimated population:** 115
- **Primary risk vectors:** EHR impersonation, vendor support escalation, secure message lures, phone verification failures (`role_inventory.csv`; threat profile Vectors 1 and 3)
- **Template assignment rationale:** supervisors hold escalation authority, so a successful lure here yields privileged follow-on action, not just credential exposure. They receive secure-message and vendor-framed lures and are the priority population for the Month 3 vishing tabletop. No baseline email lure in Wave 1: their exposure begins with Wave 2 intermediate content because `workforce_population_breakdown.md` flags this group for vishing and secure-message lures rather than mass phishing.
- **Exclusion criteria:** active patient safety events, accreditation rounding days (`employee_segments.csv`); ICU cohort requires unit-leadership coordination before any send (`clinical_schedule_constraints.md`)
- **Manager reporting:** aggregate by unit

### SEG-B: General Clinical Staff (nurses, patient care technicians, clinical assistants)

- **Estimated population:** 860
- **Primary risk vectors:** Epic account lures, patient message lures, USB drops, shoulder surfing (`role_inventory.csv`; threat profile Vector 1, Population A)
- **Template assignment rationale:** largest population and highest documented click rate (67% clinical click rate in the Q1 incident, `post_incident_click_rate_review.md`). Receives the baseline Epic lure (T-EPIC-01) in Wave 1, then a secure patient message lure in Wave 3 to build consecutive-wave measurement. Clinical click rate is tracked as its own metric (baseline 67%, `metrics_baseline.csv`).
- **Exclusion criteria:** ICU/OR during critical coverage windows (`employee_segments.csv`); medication pass peaks, active code events, declared downtime, flu-season peak and Joint Commission window (`clinical_schedule_constraints.md`); staffing-shortage units are paused
- **Manager reporting:** aggregate by department

### SEG-C: Administrative and Billing Staff

- **Estimated population:** 420
- **Primary risk vectors:** MFA enrollment lures, benefits lures, payment and document requests (`role_inventory.csv`; threat profile Vector 2)
- **Template assignment rationale:** Q1 billing users clicked specifically on compliance/portal framing (`post_incident_click_rate_review.md`). Receives the baseline MFA/compliance lure (T-MFA-02) in Wave 1, then the intermediate benefits lure (T-HR-03) in Wave 2 — consecutive exposures spaced more than 21 days apart, enabling repeat-clicker measurement for the second-largest population. HR department staff (42) are excluded from benefits-themed lures without HR pre-approval (`workforce_population_breakdown.md`).
- **Exclusion criteria:** payroll close if finance-adjacent (`employee_segments.csv`); billing/admin waves avoid payroll close and month-end (`clinical_schedule_constraints.md`)
- **Manager reporting:** aggregate by business unit

### SEG-D: IT and Security Staff

- **Estimated population:** 105
- **Primary risk vectors:** vendor support lures, privileged access abuse, service account hygiene (`role_inventory.csv`; threat profile Vector 3)
- **Template assignment rationale:** Q1 IT users defeated generic lures but responded to vendor-support framing (`post_incident_click_rate_review.md`), and the 6x02 audit showed their failures convert directly into privilege abuse (IAM-001, IAM-002, IAM-004: dormant and overprivileged service accounts, `privileged_account_findings.md`). They receive a vendor-support email lure with ticket/change framing in Wave 3. No Wave 1 exposure: their training need is verification discipline, not basic recognition, and SOC staff must not be sampled during drill overlap with their monitoring duties.
- **Exclusion criteria:** active incident responders during live incidents (`employee_segments.csv`); IT simulations avoid active IR periods (`annual_calendar_constraints.md`)
- **Manager reporting:** aggregate by IT function

### SEG-E: Finance and Procurement

- **Estimated population:** 75
- **Primary risk vectors:** BEC, invoice fraud, vendor banking changes, sensitive documents (`role_inventory.csv`; threat profile Vector 4)
- **Template assignment rationale:** lowest click volume but highest per-event impact — Q1 finance users opened more than they clicked but moved toward reply and offline action (`post_incident_click_rate_review.md`). Receives the intermediate benefits lure (T-HR-03) in Wave 2 (SEG-C and SEG-E are its defined targets in `phishing_template_constraints.md`) and the advanced BEC lure (T-BEC-04) in Wave 4 only after verification behavior has been trained. Finance BEC verification rate is a tracked metric (`metrics_baseline.csv`: establish baseline, 80% at 12 months).
- **Exclusion criteria:** month-end close day and audit submission day (`employee_segments.csv`); finance waves avoid month-end close (`annual_calendar_constraints.md`)
- **Manager reporting:** aggregate to finance leadership

### SEG-F: Executives and Executive Assistants

- **Estimated population:** 35
- **Primary risk vectors:** spear phishing, BEC, travel security, confidential document verification (`role_inventory.csv`; threat profile Vector 4)
- **Template assignment rationale:** smallest population, zero reports in Q1 despite a 50% click rate (`post_incident_click_rate_review.md`) — the reporting culture problem is most acute here. Receives only the advanced BEC lure (T-BEC-04) in Wave 4, coordinated with the executive office, after company-wide reporting behavior has been established. Wave 4 for this segment doubles as a reporting-culture test as much as a lure test.
- **Exclusion criteria:** board meeting days; all sends coordinated with the executive assistant (`employee_segments.csv`, `clinical_schedule_constraints.md`)
- **Manager reporting:** aggregate to CISO only

---

## 3. Wave Schedule

Four waves across the 90-day rollout. Day counts assume Day 0 = CISO + HR sign-off. Every wave obeys the 21-day minimum cool-down from `clinical_schedule_constraints.md`; this plan uses 25+ days as standard spacing. Any employee who clicks receives immediate microtraining and is excluded from the next lure per the cool-down rules, so repeat-clicker measurement always compares consecutive waves' populations minus coached employees, per the HR-confirmed process in Section 5.

| Wave | Days | Segments | Templates (tier) | Delivery timing and rationale |
|---|---|---|---|---|
| 1: Baseline | 5-12 | SEG-B, SEG-C | T-EPIC-01 (baseline), T-MFA-02 (baseline) | SEG-B: weekdays 07:15-08:30, per the shift-start safe window in `clinical_schedule_constraints.md` — the documented highest-pressure window from the Q1 timeline. SEG-C: Tue-Thu 09:00-11:00, the billing/admin window. Both are baseline-tier first exposures establishing the program's real denominators. |
| 2: Intermediate | 30-40 | SEG-A, SEG-C (remainder), SEG-E | T-HR-03 (intermediate), secure-message lure T-SMG-05 for SEG-A (authored in Task 3 to the same global template requirements) | SEG-A: weekdays 07:15-08:30 with unit-leadership coordination. SEG-C/SEG-E: Tue-Thu 10:00-14:00 (finance window), scheduled to miss month-end close week. More than 21 days after Wave 1 for SEG-C. |
| 3: Intermediate + repeat-measurement | 55-62 | SEG-B, SEG-D | Secure patient message lure for SEG-B (authored in Task 3); vendor-support lure T-VND-06 for SEG-D (authored in Task 3) | SEG-B: weekdays 07:15-08:30, excluding ICU/OR and staffing-shortage units; 43+ days after Wave 1 for that population. SEG-D: business hours Tue-Thu, outside any active IR period and SOC shift-drill days. Consecutive-wave measurement completes for SEG-B and SEG-C cohorts. |
| 4: Advanced BEC | 75-82 | SEG-E, SEG-F | T-BEC-04 (advanced) | SEG-E: Tue-Thu 10:00-14:00, avoiding month-end close. SEG-F: individually coordinated through the executive office, avoiding board meeting days. Advanced tier deliberately withheld until Wave 4 so verification behavior is trained before the hardest test (`phishing_template_constraints.md` difficulty progression). |

**Cool-down rule (all segments):** minimum 21 days between simulations for the same population; any segment that clicked heavily in the prior wave receives microtraining completion tracking before its next exposure. No same-wave double-targeting of any employee.

**Concurrency gates:** no wave launches during the Joint Commission window, flu-season peak (November-January) for clinical segments, declared downtime, or active incident response. If a clinical wave is displaced by a gate, it is rescheduled, not compressed, and the 21-day cool-down is recalculated from the new date.

**Wave day-of-week rationale:** all waves run Tuesday-Thursday for administrative, finance and IT segments because those are the defined business-hours windows in `clinical_schedule_constraints.md`; clinical waves run Monday-Friday within the two shift-start windows only.

---

## 4. Metrics Framework

All metrics computed from platform telemetry per wave, rolled up monthly for the program manager, quarterly for CISO/HR and the board (`board_reporting_template.md`). Baselines and targets from `metrics_baseline.csv` and `lure_effectiveness_benchmarks.md`; formulas are program-defined and stated here so results are reproducible.

| Metric | Formula | Interval | Baseline | 90-day target | 18-month target | Meaning of a deteriorating result |
|---|---|---|---:|---:|---:|---|
| Overall click rate | unique employees who click ≥1 link ÷ emails delivered | per wave; monthly rollup | 56% | ≤35% | ≤12% | Lure difficulty miscalibrated, training not transferring, or attacker-relevant timing not covered. Re-run template calibration against the threat profile before escalating training volume. |
| Clinical click rate (SEG-A/B subset) | same formula, clinical segments only | per wave | 67% | ≤40% | ≤12% (36-month anchor; 18-month value set at first annual review against the 12%/25% published anchors) | Workflow pressure defeating training: shift-start exposure is winning. Re-examine delivery timing realism and handoff-window coaching. |
| Report rate | unique employees reporting ≥1 simulation via Outlook report button or SOC channel ÷ emails delivered | per wave; monthly rollup | 15% | ≥35% | ≥65% | Reporting friction or blame-fear returning. Check report-button availability, feedback speed, and whether any punitive signal has leaked into the culture. |
| Mean time to report | average of (report action timestamp − delivery timestamp) across all reports | per wave | 74 min | ≤25 min | ≤10 min | Employees see the problem but hesitate: verification-path uncertainty or fear of blame. Reinforce "report after clicking is still valuable" (`post_incident_click_rate_review.md`). |
| Repeat clicker rate | employees clicking in two consecutive waves that targeted them ÷ employees targeted in both waves | across consecutive waves | Unknown | baseline established, <12% | <4% | Microtraining is not producing behavior change; escalation path (Section 5) activates for qualifying individuals. |
| Post-simulation training completion | microtraining completions within 72h ÷ assigned (clickers) | per wave | Not measured | 90% | 95% | Assignment friction (mobile access, shift fit) rather than refusal. Fix delivery before assuming non-compliance. |
| False-positive report rate | real (non-simulation) emails reported as phishing ÷ total reports | monthly, SOC reviewed | Not measured | track baseline | operationally manageable, not zero | Rising FP rate is acceptable while report rate rises (`lure_effectiveness_benchmarks.md`); it degrades only if SOC triage capacity cannot absorb it. Deterioration means triage workflow investment, not employee punishment. |

Supplementary metrics tracked from the same telemetry, reported in the quarterly pack: finance BEC verification rate (Wave 4 onward), landing-page engagement (completion of the full 5-minute experience), and report-before-click events (reports arriving before the reporter's own click, a leading indicator the Q1 campaign never produced — its first report arrived after two coworkers had already clicked, `campaign_reconstruction.md`).

**Hard rule from `metrics_baseline.csv` and `hr_privacy_rules.md`:** no completion-certificate or training-hours metric substitutes for a behavior metric in board reporting. The board template tracks exactly four headline numbers: click rate, report rate, mean time to report, repeat clicker rate (`board_reporting_template.md`).

---

## 5. Escalation Criteria

Two distinct escalation tracks, never conflated. A simulation failure is a training event until evidence says otherwise; observable behavior alone is never treated as an insider indicator (`privileged_account_findings.md`: "not every anomaly is malicious").

### Track 1: Coaching escalation (behavioral, HR-owned)

An individual enters the coaching track when all four conditions from `hr_privacy_rules.md` are met:

1. clicks in **two consecutive simulation waves**, and
2. does not complete the assigned microtraining, and
3. HR confirms the escalation trigger, and
4. the documented purpose is coaching, not discipline.

At that point, and only that point, the department manager receives the individual's repeat-click status. Even then: aggregate-team data remains the manager's normal view; the coaching conversation is the exception defined by HR; nothing enters the performance review.

Prior to threshold: repeat-click status is visible to the program manager and HR only. Microtraining failure alone triggers re-assignment and a check for delivery friction before any human follow-up.

### Track 2: Security investigation (evidence-owned, SOC-led)

A simulation result escalates from training event to security investigation when a **converging technical indicator** appears, drawn from `technical_indicators_reference.md` and the 6x02 findings:

- a simulation click is followed by real authentication activity consistent with credential exposure (e.g., LSASS access from privileged context, Sysmon EID 10; or unexpected logons tied to the employee's accounts);
- a report reveals the employee entered credentials on a **real** phishing page (distinct from the simulation);
- privileged-account misuse indicators appear around a repeat-clicking SEG-D member (dormant privileged account activation, service account interactive logon, privileged group changes without ticket, per `privileged_account_findings.md` failure modes);
- bulk download or unusual patient record access coincides with a simulation window (Indicators 5-6, handled with minimum-necessary disclosure).

Investigations run through the triage model in `reporting_and_triage_model.md`: security triage establishes technical evidence first; HR is included only if the concern involves conduct or coaching; Legal is included on privacy, employment or regulatory exposure; the reporter receives acknowledgment. Investigation proceeds on observable facts ("this account is active outside its documented purpose"), never labels ("suspicious person") (`privileged_account_findings.md`).

**The bridge between tracks:** a privileged-segment employee (SEG-D, or any holder of privileged access) reaching the Track 1 threshold prompts a Track 2 *review* of their account context — as a fact-check on the surrounding indicators, not as suspicion of the person — before any coaching conversation, so HR walks in knowing whether a technical problem exists. This is the single place simulation data influences an investigation, and it flows through SOC evidence, not manager opinion.

---

## 6. Exclusion and Ethics Policy

### Global exclusion criteria (checked at every wave build)

Excluded from a wave until the condition clears (`clinical_schedule_constraints.md`, `hr_privacy_rules.md`):

- employees on leave; employees in their first week of employment
- staff involved in an active patient safety event
- staff assigned to incident response (for the wave's duration)
- employees under an HR-approved support plan where a simulation would be inappropriate
- units in a declared staffing shortage; ICU/OR during critical coverage
- HR department staff for benefits-themed lures without HR pre-approval
- any clinical wave during the Joint Commission window or flu-season peak (November-January); reinforcement reminders and existing microtraining may continue, new lures may not

### Aggregate vs. individual disclosure framework

Reproduced as binding from `hr_privacy_rules.md`:

| Data type | Who can see it |
|---|---|
| Individual click event | Security awareness program manager only (training assignment use) |
| Individual report event | Program manager and SOC metrics (positive reinforcement use) |
| Repeat-click status | Program manager and HR, only after threshold; never to a manager before the four Track 1 conditions are met |
| Department trend | Department manager, aggregate only |
| Executive summary | CISO and board, aggregated only |

Data retention: individual simulation data is retained 18 months for trend analysis, then aggregated or deleted unless an active HR-reviewed coaching process requires it.

### Prohibited and permitted lure content

Binding from `simulation_ethics_guidelines.md`. Prohibited themes: personal medical diagnoses, death or severe personal emergencies, immigration status, payroll termination threats, disciplinary threats, protected class attributes, real patient names or conditions, active disasters or recent traumatic events, and any content implying immediate job loss. Permitted high-realism themes (CISO + HR approved): Epic account verification, MFA enrollment, benefits open enrollment, secure document review, vendor support callback, invoice or payment verification, remote-work compliance, travel security notice. All templates carry `[SIMULATION_LINK]` placeholders only; no real credential-harvesting URLs, no credential collection, no real financial transfers, no third-party-controlled external domains (`phishing_template_constraints.md` safety boundaries).

### Post-simulation support for distress

If an employee experiences distress after a simulation, the landing page and microtraining must provide non-shaming language, explicit reassurance the event is training, a manager-neutral support path, an HR contact for concern escalation, and no public naming under any circumstances (`hr_privacy_rules.md`). Debrief tone follows the approved language bank ("You are not in trouble; this is a training moment") and avoids the prohibited phrasings ("You failed," "This was obvious") in `post_click_microtraining_reference.md`. Managers who observe post-simulation confusion follow the signposting duties in `manager_reference_constraints.md` and escalate distress or fear to IT Security or HR without confronting the employee.

### Deployment sign-off gate

No wave launches without: (1) CISO + HR signature on every template in the wave (joint, per `simulation_ethics_guidelines.md`); (2) Clinical Operations sign-off on timing for any clinical segment; (3) verification that no exclusion condition or concurrency gate is active; (4) SOC notification so simulation reports are expected in triage and false-positive handling is prepared; (5) confirmed microtraining and landing pages mapped to each template (LPV mapping, `post_click_microtraining_reference.md`) so no employee can click into a dead-end experience.

---

## Appendix: Material Traceability

| Plan element | Source material |
|---|---|
| Segments, populations, risk vectors, exclusions | `role_inventory.csv`, `employee_segments.csv`, `workforce_population_breakdown.csv` |
| Wave timing windows and cool-down | `clinical_schedule_constraints.md`, `campaign_reconstruction.md` (Q1 timeline) |
| Metric baselines and targets | `metrics_baseline.csv`, `lure_effectiveness_benchmarks.md` |
| Privacy, disclosure and retention rules | `hr_privacy_rules.md` |
| Escalation thresholds and insider boundaries | `hr_privacy_rules.md`, `privileged_account_findings.md`, `iam_audit_summary_6x02.md`, `technical_indicators_reference.md`, `reporting_and_triage_model.md` |
| Ethics, prohibited themes, approvals | `simulation_ethics_guidelines.md`, `phishing_template_constraints.md` |
| Governance roles and review cadence | `program_governance_roles.md`, `annual_calendar_constraints.md`, `board_reporting_template.md` |
| Design brief for templates and targeting | `social_engineering_threat_profile.md` (Task 1) |
