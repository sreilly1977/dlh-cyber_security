# Post-Click Intervention Design: MedDefense Health Systems

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-10
**Version:** 1.0
**Classification:** Confidential
**Governing constraints:** `post_click_microtraining_reference.md` (required landing page structure, LPV mapping, microtraining model, language banks), `simulation_ethics_guidelines.md` (post-click experience requirements), `hr_privacy_rules.md` (individual data handling, escalation trigger, distress support, retention), `metrics_baseline.csv` (completion and report-rate targets)
**Companion artifacts:** `phishing_templates.md` (Task 3), `phishing_campaign_plan.md` (Task 2)

---

## Design Principles

The failure mode this design eliminates: landing pages that say "You were phished," produce negative affect, and reduce clicks in the next wave only because employees are anxious rather than informed. The program's evidence base shows why that is fatal here: Q1 reporting was already suppressed by fear of blame ("I did not want to report it after I clicked"), and mean time to report was 74 minutes (`post_incident_click_rate_review.md`). A shaming intervention would deepen exactly the behavior gap the metrics are built to close.

Every intervention therefore: states this was training before anything else, teaches from the exact cues in the template the employee just saw, gives three concrete next-time actions, shows how to report, and finishes in five minutes or less (`simulation_ethics_guidelines.md`, post-click experience). Prohibited phrasing ("You failed," "You were fooled," "This was obvious," "You should have known") is excluded from every screen and script; the approved language bank from `post_click_microtraining_reference.md` is used throughout.

Completion target: 90% of clickers finish the module within 72 hours within the first 90 days, 95% by 12 months (`metrics_baseline.csv`).

---

## 1. Landing Page Variants (LPV-01 through LPV-04)

### 1.0 Shared wrapper (renders at the top of every variant)

```text
[MedDefense logo]     SECURITY AWARENESS TRAINING — SIMULATION

This was a simulation.

The message you just interacted with was sent by MedDefense's own security
team as part of our security awareness training. It was designed to feel
realistic — that was the point. Nothing bad has happened, and nothing you
did changed any real account, benefit, payment, or record.

Being convinced by it is not a failure. These techniques work against smart,
busy people every day — including security professionals.

What you do in the next five minutes is the part that matters.
Continue to your 5-minute training →

Need to talk to a human? ext. 4-SECURITY · security@meddefense.org
Have a concern about this training? HR contact: [HR_CONTACT_LINE]
```

**Wrapper compliance notes:** opens with "This was a simulation" (required structure item 1, `post_click_microtraining_reference.md`); contains none of the prohibited phrases; addresses the documented Q1 fear-of-blame theme before anxiety sets the tone (`post_incident_click_rate_review.md`); carries the mandated distress support path — manager-neutral, HR contact, no public naming (`hr_privacy_rules.md`).

Variant-specific content (`[Why it was convincing]` / `[What to notice next time]`) renders beneath the wrapper.

### 1.1 LPV-01 — Epic EHR lure (pairs with T-EPIC-01, SEG-B)

```text
WHY IT WAS CONVINCING

The message looked like a routine Epic security notice: operational tone,
no errors, a 48-hour deadline, and a consequence you feel at shift start —
losing patient record and medication log access.

Three details gave it away:

 1. The sender domain was epic-healthsystems.net. The display name can be
    typed by anyone; the domain is the part that has to be true.
 2. MedDefense IT never delivers Epic login or verification tasks through an
    email link. Real Epic notices appear in the clinical portal itself.
 3. The deadline was engineered: urgency at shift start is exactly when a
    busy decision feels like a good reason to skip verification.

WHAT TO NOTICE NEXT TIME

 → Any email about your Epic account: open Epic from your bookmark and
   check there.
 → Read the sender domain, not just the display name.
 → When urgency meets patient care, treat the urgency as your cue to verify
   first — that is what it is for.
```

### 1.2 LPV-02 — MFA/compliance lure (pairs with T-MFA-02, SEG-C)

```text
WHY IT WAS CONVINCING

This message borrowed your familiarity with real IT processes. Genuine
compliance deadlines and MFA enrollments exist — that familiarity is the
attack.

Four details gave it away:

 1. The domain was meddefense-it-support.org. Real MedDefense IT mail comes
    from @meddefense.org. The lookalike survives a quick glance — that is
    its entire job.
 2. Real compliance tasks appear in the intranet compliance portal. No task
    has ever been opened through an emailed link.
 3. "Portal access will be interrupted" was deadline pressure tuned to the
    way administrative work is prioritized — task completion first.
 4. "Will not ask you to reset your password" was reassurance placed there
    to hurry you past scrutiny.

WHAT TO NOTICE NEXT TIME

 → Compliance tasks: known intranet bookmark only. If the task is real,
   it is there.
 → Verify unexpected IT deadlines through the known help channel —
   ext. 4-HELP — never through contacts inside the message.
 → When a message reassures you about what it will not ask for, slow down.
   That sentence exists to speed you up.
```

### 1.3 LPV-03 — HR benefits lure (pairs with T-HR-03, SEG-C and SEG-E)

```text
WHY IT WAS CONVINCING

Benefits deadlines are genuinely personal, so a message about losing
coverage gets read fast and acted on faster. The soft close ("if you have
already confirmed, no action is needed") even imitated the tone of real HR
mailing — that was deliberate.

Three details gave it away:

 1. The domain was meddefense-benefits.org — external. HR communicates
    through the HR intranet and known internal addresses.
 2. No benefits election at MedDefense has ever been confirmed through an
    emailed link. Elections happen inside the HR portal, which you reach
    from the intranet.
 3. "Final notice" and a three-day clock were the manufactured urgency.
    Routine processes rarely need ultimatums.

WHAT TO NOTICE NEXT TIME

 → Any benefits or payroll action: open the HR portal yourself from the
   intranet and confirm your status there.
 → A deadline attached to personal money is a reason to verify through a
   known channel first, not a reason to act fast.
 → Election status is always checkable in the portal. Checking costs two
   minutes; a default election costs a plan year.
```

### 1.4 LPV-04 — Executive wire fraud (pairs with T-BEC-04, SEG-E and SEG-F)

```text
WHY IT WAS CONVINCING

There was almost nothing technical to catch — that was the design. This
lure does not rely on a suspicious link; it relies on making verification
feel disloyal.

Four details gave it away:

 1. "Keep this between us." Confidentiality pressure exists to isolate you
    from the exact verification that would expose it. Real confidential
    workflows survive a callback; fake ones cannot.
 2. "I can't take calls." The sender conveniently removed the easiest
    verification channel — the one that would have ended the attack in
    ten seconds.
 3. Replying to this message would have left MedDefense email entirely:
    the reply-to address pointed outside the organization. This is nearly
    impossible to spot while reading — which is why the trained behavior
    is out-of-band verification, not clever inspection.
 4. The timing sat right before a payment run, when payment action feels
    routine, and named you personally. Flattery plus routine is a strong
    combination.

WHAT TO NOTICE NEXT TIME

 → Any request involving money, credentials, or confidential documents:
   verify independently through a known channel. Dial the requester's
   number from the directory — never a number or reply path from the
   message itself.
 → Never resolve the request inside its own email thread. The thread is
   the attacker's territory.
 → Pressure for secrecy is a verification trigger, not a compliance
   instruction.
```

---

## 2. Microtraining Module Structure (MT-01 through MT-04)

Each module completes in five minutes or less in the same browser session. Parts (a) through (d) follow the four-part model in `post_click_microtraining_reference.md`. Part (d) is a shared component (Section 2.5) rendered at the end of every module.

### 2.5 Shared Part D — Reporting walkthrough (renders in all modules)

```text
HOW TO REPORT — 30 SECONDS

Outlook (desktop or web):
 1. Select the suspicious message. Do not click its links.
 2. Click "Report Phishing" in the ribbon.
 3. Confirm. Outlook removes it from your inbox and alerts the SOC
    instantly.

That is the entire process — under 30 seconds.

Alternatives:
 → Forward to security@meddefense.org (keep the subject line intact)
 → Call ext. 4-SECURITY for anything involving money, patient data, or
   system access

Two rules that never change:
 → Reporting after a click is still valuable. It gives the SOC its
   fastest early warning.
 → False alarms are welcome. Reporting a legitimate email is never a
   problem — the SOC triage team expects and absorbs them.
```

### 2.1 MT-01 — Epic EHR module (SEG-B, after LPV-01)

**(a) What you saw — annotated lines from the email you received:**

| Line in the message | What it was doing |
|---|---|
| From: `notifications@epic-healthsystems.net` | Lookalike domain registered to fool a glance — a real tactic documented in MedDefense's own incident investigation (`email_header_inspection_results.md`) |
| "ACTION REQUIRED ... suspended in 48 hours" | Manufactured deadline, timed to shift start when blocked access genuinely stops work |
| "temporary access hold ... patient records, medication administration logs" | Operational consequence makes the threat concrete — this is why clinical users clicked at the highest rate of any group (67%) in the Q1 incident |
| "open the secure link below" | The single detail MedDefense IT would never do: delivering an Epic login task by email link |
| "contact the IT helpdesk at ext. 4-HELP" | The safe exit was in the message all along. Choosing this path instead of clicking is a full pass |

**(b) What a real attacker gains:** Your Epic credentials are keys to patient records and the clinical network. In MedDefense's Q1 2026 incident, a single Epic-themed lure led to credential capture within minutes, a Cobalt Strike beacon on an endpoint, misuse of privileged service accounts, and a full IR activation (`campaign_reconstruction.md`, `cobalt_strike_phishing_path.md`). No technical control can un-ring that bell — this module is the control that acts before the credentials leave.

**(c) What to do next time — three pre-click steps:**
1. **Bookmark rule:** any email concerning your Epic account gets resolved inside Epic, opened from your bookmark — never from the message.
2. **Domain rule:** on any login-task email, read the sender's actual domain; treat the display name as unverified text.
3. **Urgency rule:** when urgency meets patient care, use the urgency as your cue to call ext. 4-HELP or hit the report button — verification first, action second.

**(d) Reporting:** see the shared walkthrough (2.5).

### 2.2 MT-02 — MFA/compliance module (SEG-C, after LPV-02)

**(a) What you saw — annotated lines:**

| Line in the message | What it was doing |
|---|---|
| From: `mfa-enrollment@meddefense-it-support.org` | Near-miss internal-looking domain; real IT mail is @meddefense.org |
| "MFA re-enrollment required by [DATE]" | Familiar process framing — IT compliance deadlines are routine, so the pattern read as normal |
| "flagged non-compliant ... portal access will be interrupted" | Task-completion pressure tuned to deadline-driven administrative work — Q1 billing users clicked specifically on compliance and portal framing |
| "will not ask you to reset your password" | Reassurance as a speed-up tool: a genuine safety note helps you act carefully; this one hurried you past scrutiny |
| "open the compliance task" | Process-label link language — attackers label links with what you expect to do, not what the link does |

**(b) What a real attacker gains:** Billing portal and document system credentials, with SSO reach into HRIS and email — patient billing and insurance records. Worse, if the lure captures credentials during a real enrollment window, an attacker can register their own MFA factor on your account and maintain silent persistent access. Weak verification around privileged and admin actions was an explicit finding of MedDefense's own IAM audit (`iam_audit_summary_6x02.md`).

**(c) What to do next time — three pre-click steps:**
1. **Portal rule:** compliance tasks are reached from the intranet bookmark only; if the task is real, it exists there.
2. **Channel rule:** verify unexpected IT deadlines by contacting the helpdesk at ext. 4-HELP through the known channel — never contacts supplied in the message.
3. **Reassurance rule:** when a message tells you what it will not ask for, slow down one beat; that sentence is often placed to build trust quickly.

**(d) Reporting:** see the shared walkthrough (2.5).

### 2.3 MT-03 — HR benefits module (SEG-C and SEG-E, after LPV-03)

**(a) What you saw — annotated lines:**

| Line in the message | What it was doing |
|---|---|
| From: `enrollment@meddefense-benefits.org` | External lookalike; genuine HR mail comes from internal systems |
| "Final notice ... close [DATE+3] at 5:00 PM" | Scarcity lever: short clocks make routine processes feel like emergencies |
| "revert to default coverage ... dependent coverage and FSA elections may be affected" | Personalized financial stakes — the documented pressure point for HR lure class attacks |
| "review and confirm your elections" via emailed link | The impossible detail: no MedDefense election has ever been confirmed through an email link |
| "If you have already confirmed your elections this week, no action is needed" | Soft close imitating real HR tone — designed to make you read the rest as equally official |

**(b) What a real attacker gains:** HRIS credentials unlock payroll data, direct deposit details, dependents' information, and identity documents — prime material for identity theft and payroll diversion fraud. Benefits-stage credentials are also reused widely, because the same password often travels. Because the stakes feel personal, this lure class produces action bias faster than any other administrative lure (`healthcare_social_engineering_patterns.md`, Pattern 3).

**(c) What to do next time — three pre-click steps:**
1. **Portal rule:** benefits and payroll actions happen only inside the HR portal, reached from the intranet; confirm election status there before responding to any notice.
2. **Deadline rule:** a deadline attached to your money is a cue to verify through a known channel first.
3. **Ultimatum rule:** "final notice" on a routine process deserves suspicion — routine processes almost never need ultimatums.

**(d) Reporting:** see the shared walkthrough (2.5).

### 2.4 MT-04 — Executive wire fraud module (SEG-E and SEG-F, after LPV-04)

**(a) What you saw — annotated lines:**

| Line in the message | What it was doing |
|---|---|
| "I'm in back-to-back diligence calls ... can't take calls" | Removing the natural verification channel in advance |
| "finalize the revised wire ... ahead of the 3:00 PM payment run" | Vendor banking change pretext, timed to a real workflow rhythm so the request feels procedural |
| "[DIRECTOR_NAME] mentioned you handled the last one" | Social proof plus personal naming — authority with a hook that discourages challenge |
| "Keep this between us until the close is announced" | Confidentiality pressure as an isolation tool: the sentence exists to stop you from making the one call that exposes the fraud |
| Reply-To: an address outside MedDefense | Any reply would have left the organization's mail entirely — invisible during normal reading, which is why out-of-band verification, not header inspection, is the trained behavior (`email_header_inspection_results.md`, Finding 3) |

**(b) What a real attacker gains:** No credentials needed and no clicks required. One compliant reply can authorize a fraudulent wire directly — and the Q1 review showed MedDefense finance staff were already inclined to reply or act offline rather than click (`post_incident_click_rate_review.md`). BEC lures click at only 8–22% but every success is measured in dollars and exposed confidential documents, not in stolen passwords (`lure_effectiveness_benchmarks.md`). A board packet disclosed this way is a full confidentiality breach with zero technical indicators.

**(c) What to do next time — three pre-click steps:**
1. **Verify rule:** any request involving money, credentials, or confidential documents gets independent verification — dial the requester at their directory number, never a number or reply path contained in the message.
2. **Thread rule:** never resolve the request inside its own email thread; the thread belongs to the attacker until proven otherwise.
3. **Secrecy rule:** "keep this between us" is a verification trigger. Confidentiality pressure means check more, not comply faster.

**(d) Reporting:** see the shared walkthrough (2.5) — plus, for suspected BEC specifically, an immediate call to ext. 4-SECURITY and notification to finance leadership before any reply is composed.

---

## 3. Repeat-Click Escalation Protocol

**Definition:** a repeat click is a click in two consecutive simulation waves targeting that employee. Multiple clicks within one wave count once, and repeat-click evaluation requires consecutive waves — never volume within a wave (`clinical_schedule_constraints.md`, cool-down rules). An employee who clicks receives immediate microtraining and no further lure in the same wave.

**Governing boundary:** individual results never enter performance reviews, promotion, compensation, or termination decisions (`hr_privacy_rules.md`, Performance Review Boundary). Managers receive aggregate team data only. The four-stage ladder below implements the HR escalation trigger exactly as specified in `hr_privacy_rules.md` — no stage jumps ahead of it.

| Stage | Trigger | Who is notified | What happens | What the employee is told |
|---|---|---|---|---|
| **R0 — single click** | Any click, any wave | Program manager only (event); nobody else sees the identity | LPV + MT in session; completion tracked to the 72-hour target | Landing page text: training moment, results protected, support paths available |
| **R1 — microtraining incomplete** | Click + module unfinished after 72 hours | Program manager only | Friction check first (leave, shift pattern, mobile access, technical delivery) before any reminder; gentle reminders at 72h and 144h; assignment re-sent if friction found | "Your 5-minute training is waiting. No rush beyond this week — it stays available." |
| **R2 — pattern forms** | Second click in a consecutive wave | Program manager + HR only (repeat-click status visibility, `hr_privacy_rules.md` data table). Department manager: still NOT notified | Refresher variant assigned; optional 10-minute live Q&A offered; optional no-stakes practice set | Script S-R2 below |
| **R3 — formal coaching trigger** | All four HR conditions met: two consecutive-wave clicks AND assigned microtraining incomplete AND HR confirms the trigger AND purpose is coaching, not discipline | HR (leads), program manager (data), department manager (receives the individual's repeat-click status for the first time, in a coaching frame) | HR-coordinated coaching conversation; support options: 1:1 walkthrough, workflow-tailored guidance, adjusted microtraining format | Script S-R3 below |

**Script S-R2 (from the awareness team, private message):**

```text
You've clicked in each of the last two practice simulations. That is
information about how good the fakes have gotten — modern simulations are
built to fool smart, busy people, and they fool security professionals too.
It is not a judgment about you, and it is not visible to your manager.

Here's a short refresher, and if useful, a practice set where mistakes are
free — nothing is scored, recorded, or reported.

Ask us anything, any time: security@meddefense.org · ext. 4-SECURITY
```

**Script S-R3 (opening of the HR-coordinated coaching session):**

```text
This conversation is a coaching session arranged with HR. It is not
disciplinary. Simulation results at MedDefense are training data — they
never enter your performance review, and they are not shared with anyone
outside this session's stated purpose.

What we'd like to do today is understand what made the last two
simulations difficult to spot in your workflow, and agree on support that
fits how you actually work. Nothing about today's discussion becomes a
record of discipline.
```

**Conduct rules at R3 (binding, from `manager_reference_constraints.md` and `hr_privacy_rules.md`):** the manager does not confront the employee as a problem case, does not inform the team, does not document the session as discipline, and does not use simulation data in any review. If the employee shows distress at any stage, the manager-neutral support path and HR contact apply immediately, with no public naming (`hr_privacy_rules.md`, distress support).

**Separation from security investigations:** a repeat click is never, by itself, an insider indicator, and this protocol never feeds a security investigation on its own ("not every anomaly is malicious," `privileged_account_findings.md`). The single documented bridge — defined in `phishing_campaign_plan.md` Section 5 — applies to privileged-segment employees reaching R2/R3: SOC performs a technical fact-check of the surrounding account indicators before any coaching conversation, as evidence gathering about account context, not suspicion about a person.

**Retention:** individual simulation data is retained 18 months for trend analysis, then aggregated or deleted unless an active HR-reviewed coaching process requires it (`hr_privacy_rules.md`).

---

## 4. Positive Reinforcement Design

Correct reports are the program's most valuable events — every report is an early-warning sensor the SIEM cannot replace, and the Q1 incident produced only 6 reports out of 41 delivered messages, with 2 arriving before the SOC alert (`module5_incident_summary.md`). Reinforcement design follows the 60-second standard in `post_click_microtraining_reference.md`: confirmation, the specific cue the employee defeated, a thank-you, and what happens next.

### 4.1 Reinforcement sequence on a correct report

**T+0 — in-thread confirmation (instant).** The Outlook report event triggers an immediate banner toast in the mail client:

```text
✓ Report received — thank you. Confirmation is on its way to your inbox.
```

Simultaneously, the SOC ticket auto-closes as "simulation — correctly reported," so report-button events are absorbed without touching analyst queues (false-positive workflow per `phishing_campaign_plan.md` Section 4).

**T+60 seconds — reinforcement message (email + chat ping where available).**

```text
Subject: You spotted it — nice work, [First Name]

The "[email subject line]" message you reported a moment ago was a
MedDefense security simulation — and you caught it.

Specifically, you defeated an attack that relied on [SPECIFIC_CUE — see
cue table]. That exact pattern started a real incident at MedDefense
earlier this year, and reports like yours are the fastest early warning
this organization has.

What happens next: nothing. Reports are positive training data only.
They are never performance data, and they are never shared with your
manager as individual results.

Keep them coming.

— Security Awareness Team · ext. 4-SECURITY · security@meddefense.org
```

**Report-after-click variant:** when the platform correlates a click followed by a report of the same message, the reinforcement adds one line after the second paragraph:

```text
Reporting after clicking is exactly the right reflex — it gives the SOC
its earliest possible warning, and it still counts fully. You did the
most useful thing available at that moment.
```

**Report-before-click:** when the report arrives before the reporter's own click (the gold-standard behavior; no Q1 report achieved it — the first report arrived after two coworkers had already clicked, `campaign_reconstruction.md`), the message opens with the addition:

```text
You reported it before anyone clicked — that is the single most valuable
report action there is.
```

### 4.2 Specific cue lines (variant-aware `[SPECIFIC_CUE]` values)

| Reported template | Cue line inserted into the reinforcement |
|---|---|
| T-EPIC-01 | "a lookalike Epic domain and a 48-hour account threat — the same technique that started MedDefense's Q1 incident" |
| T-MFA-02 | "an almost-right IT domain dressed up as a routine compliance task" |
| T-HR-03 | "a benefits deadline with a personal financial stake attached to a fake portal link" |
| T-BEC-04 | "an executive impersonation engineered to make verification feel disloyal — the hardest lure category there is" |

### 4.3 Proportionality and recognition rules

- Reinforcement is proportional: report-without-click > report-after-click > false alarm, but all three are positively acknowledged; no report is ever treated as an inconvenience (false positives are an accepted and managed SOC cost, per `metrics_baseline.csv`).
- A report of a legitimate (non-simulation) email receives the light-touch variant: "That one was real and harmless — but the instinct to check was exactly right. Thank you for reporting." This keeps false-positive rate operational, not shameful.
- Sustained recognition: three correct reports in a quarter earns a private thank-you from the awareness team and an opt-in invitation to serve as a unit reporting champion. Aggregate team report rates may be celebrated with managers; **individual recognition is private or opt-in only** — no public naming of individual reporters or clickers, per `hr_privacy_rules.md`.
- Reinforcement messages never reference anything the employee previously clicked. Positive events are positive events.

### 4.4 Metric hookup

Every correct report feeds report rate and mean time to report (baselines 15% / 74 minutes; 90-day targets ≥35% / ≤25 minutes, `metrics_baseline.csv`). Reinforcement speed is itself tracked: the 60-second acknowledgment SLA is monitored per wave, because slow reinforcement extinguishes reporting behavior — the Q1 review found no department had a consistent expectation of what happens after reporting (`post_incident_click_rate_review.md`), and this design fixes that expectation explicitly.

---

## Compliance Checklist

- [x] All four landing pages state "This was a simulation" first
- [x] No prohibited phrasing anywhere in landing pages, modules, or scripts
- [x] Each variant teaches from the exact cues of its paired template
- [x] Each module contains all four parts (a)–(d) and finishes in under 5 minutes
- [x] Reporting walkthrough includes Outlook report button, ext. 4-SECURITY, security@meddefense.org
- [x] Escalation stages implement the four HR conditions verbatim; no stage precedes them
- [x] Managers receive individual data only at R3, in a coaching frame, never for discipline
- [x] Distress support path present on every landing page; no public naming anywhere
- [x] 60-second reinforcement: confirmation, specific cue, thanks, what happens next
- [x] Individual data retention: 18 months, then aggregate or delete
