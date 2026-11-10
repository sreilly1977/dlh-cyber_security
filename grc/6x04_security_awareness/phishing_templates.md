# Phishing Email Templates: MedDefense Health Systems

**Inventory:** T-EPIC-01 (Baseline), T-MFA-02 (Baseline), T-HR-03 (Intermediate), T-BEC-04 (Advanced)
**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-10
**Ethics review:** Pending joint CISO + HR sign-off (per `simulation_ethics_guidelines.md` approval table; no deployment before both signatures)
**Approved by:** [CISO Dr. Patricia Morales] — [signature pending] / [HR Director Maria Santos] — [signature pending]
**Usage:** Controlled internal simulation only. Deploy exclusively within the wave schedule in `phishing_campaign_plan.md`. All links are `[SIMULATION_LINK]` placeholders routing to approved training infrastructure only. No template collects credentials, requests real financial action, or uses live third-party infrastructure (`phishing_template_constraints.md` safety boundaries).

**Design basis:** Every template reproduces documented attacker behavior: neutral, error-free operational language and process-oriented link labels from `phishing_kit_analysis_summary.md` and `email_header_inspection_results.md` (Finding 5), lookalike sender domains drawn directly from the Module 4 header samples, and pressure-window timing from `campaign_reconstruction.md`. No spelling errors or cartoonish threats; the trained behavior is verification, not proofreading (`phishing_kit_analysis_summary.md`).

---

## T-EPIC-01: Epic EHR Account Management (Baseline)

**Template ID:** T-EPIC-01
**Target segment:** SEG-B (general clinical floor staff), per `workforce_population_breakdown.md` Medical-Surgical and ED floor cohorts
**Tier:** Baseline
**Psychological mechanism:** Authority + urgency (`healthcare_social_engineering_patterns.md`, Pattern 1)
**Expected click-rate range:** 40-62% first exposure (`lure_effectiveness_benchmarks.md`, rank 1: EHR account suspension; Q1 incident clinical click rate was 67%, `post_incident_click_rate_review.md`)
**Deployment timing constraints:** Weekdays 07:15-08:30 (day-shift window; the documented Q1 first click came at 07:07 during shift handoff, `campaign_reconstruction.md`). Never during ICU/OR critical coverage, medication pass peaks, active code events, declared downtime, the Joint Commission window, or flu-season peak. Wave 1 assignment per `phishing_campaign_plan.md`.
**Teaching cues (must be present in the landing page, LPV-01):** external sender domain, unexpected verification request, deadline pressure tied to shift timing.

### Email as the recipient sees it

```text
From:    Epic Health Systems Notifications <notifications@epic-healthsystems.net>
To:      [First Name Last Name] <[employee@meddefense.org]>
Subject: ACTION REQUIRED: Epic account security verification — access suspended in 48 hours

Dear [First Name],

A failed security verification has been recorded against your Epic EHR account.

Per MedDefense IT Security Policy, accounts with unresolved verification are placed
on a temporary access hold after 48 hours to protect patient data. While the hold
is in effect, your access to patient records, medication administration logs and
clinical documentation will be unavailable.

To complete verification and maintain uninterrupted access, open the secure link
below before 11:59 PM on [DATE+2]:

   [SIMULATION_LINK]

If you believe this notification was sent in error, contact the IT helpdesk at
ext. 4-HELP or help@meddefense.org before the deadline to request a manual review.

Epic Health Systems | Account Security
Sent on behalf of MedDefense Health Systems Information Security
```

**Why it passes the "would I have clicked this?" test:** It arrives during shift start when a blocked Epic account genuinely prevents work, it names the real system and real consequences ("patient records, medication administration logs"), and its language is operational, not hysterical — "temporary access hold," "failed security verification" — matching the kit's documented lure vocabulary (`phishing_kit_analysis_summary.md`). The escape hatch (call ext. 4-HELP) is deliberately included because it is the safe behavior: employees who choose the helpdesk route pass the simulation without clicking.

**Attacker notes:** A real threat actor registers `epic-healthsystems.net` days before launch and configures SPF/DKIM so the message passes gateway authentication (documented in `email_header_inspection_results.md`, Finding 2: "a message can pass technical checks and still be malicious if the domain is not the real business partner"). The harvest page copies the real clinical portal sign-in layout with familiar header and badge colors, and the link embeds a user-like token that pre-populates the username field, removing one step between click and submission (`phishing_kit_analysis_summary.md`, kit components). An open-tracking pixel confirms delivery so the attacker can time a follow-up wave to non-openers. Later variants time delivery to the minute before evening handoff, when the 48-hour threat intersects shift anxiety. None of these mechanics are reproduced in the simulation; the template teaches the victim-side cues only.

**Safety note for simulation operators:** Sender domain is a display-field construct configured on the approved simulation platform; it must not resolve to any third-party host, and `[SIMULATION_LINK]` routes only to LPV-01. The landing page states "this was a simulation" immediately, uses non-shaming language, and finishes in under 5 minutes (`simulation_ethics_guidelines.md`). Exclude units under staffing shortage and any employee on the exclusion list before send. No credential fields may exist behind the link.

---

## T-MFA-02: IT Helpdesk MFA Enrollment (Baseline)

**Template ID:** T-MFA-02
**Target segment:** SEG-C (administrative and billing staff, excluding the HR department for themed lures without HR approval, per `workforce_population_breakdown.md`)
**Tier:** Baseline
**Psychological mechanism:** Familiarity + authority (`healthcare_social_engineering_patterns.md`, Pattern 2)
**Expected click-rate range:** 25-42% first exposure (`lure_effectiveness_benchmarks.md`, rank 3)
**Deployment timing constraints:** Tuesday-Thursday 09:00-11:00 (billing/admin window, `clinical_schedule_constraints.md`); never during payroll close or month-end. Wave 1 assignment per `phishing_campaign_plan.md`.
**Teaching cues (must be present in the landing page, LPV-02):** link verification against the known portal path, use of the known portal bookmark, Outlook report button.

### Email as the recipient sees it

```text
From:    MedDefense IT Compliance <mfa-enrollment@meddefense-it-support.org>
To:      [First Name Last Name] <[employee@meddefense.org]>
Subject: MFA re-enrollment required by [DATE+7] — compliance hold on portal access

Hello [First Name],

As part of the MedDefense multi-factor authentication program, all billing and
administrative portal users are required to complete MFA re-enrollment before
[DATE+7].

Accounts that are not re-enrolled by the deadline will be flagged
non-compliant, and portal access (billing portal, document systems) will be
interrupted until enrollment is complete.

To complete your enrollment, open the compliance task:

   [SIMULATION_LINK]

This task takes approximately five minutes. The enrollment wizard uses your
existing MedDefense credentials and will not ask you to reset your password.

MedDefense IT Compliance
Information Security | ext. 4-HELP
```

**Why it passes the test:** SEG-C staff expect periodic IT compliance communications, so the pattern itself is familiar; Q1 billing users clicked specifically when messages referenced compliance or portal access (`post_incident_click_rate_review.md`). The domain `meddefense-it-support.org` is drawn directly from Module 4 sample MSG-002 (claimed sender "MedDefense IT Compliance"), so the template models the exact documented lookalike rather than a hypothetical one. "Will not ask you to reset your password" is included deliberately: it is the reassuring detail real kits use to lower defenses, and the landing page will unpack it.

**Attacker notes:** A real attacker exploits the genuine MFA rollout documented in the 6x02 IAM context (`iam_audit_summary_6x02.md`: MFA and admin discipline were an audit finding, so enrollment messages are expected and hard to distinguish). The lookalike domain is chosen because it survives casual sender inspection — "meddefense" is prominent and "-it-support.org" is skimmed past (`email_header_inspection_results.md`, Finding 1: display name and recognizable domain fragments persuade more than full domains). The link label reads "open the compliance task" — process language, never "reset password" (Finding 5). The hardest real-world variant lands during the actual enrollment push, when peer chatter confirms "everyone got this email," providing social proof no attacker has to fabricate.

**Safety note for simulation operators:** No credential collection, no password reset flow behind `[SIMULATION_LINK]` — LPV-02 only. The template must be suppressed for HR department staff and any finance-adjacent SEG-C cohort during payroll close. The enrollment deadline must be far enough out that no employee believes real access loss is imminent; the landing page immediately confirms no action was actually required and no account state has changed.

---

## T-HR-03: HR Open Enrollment Benefits Deadline (Intermediate)

**Template ID:** T-HR-03
**Target segments:** SEG-C and SEG-E (administrative and finance staff), per `phishing_template_constraints.md`
**Tier:** Intermediate — familiar business process plus personal financial pressure
**Psychological mechanism:** Urgency + scarcity (`healthcare_social_engineering_patterns.md`, Pattern 3)
**Expected click-rate range:** 22-38% first exposure (`lure_effectiveness_benchmarks.md`, rank 4)
**Deployment timing constraints:** Tuesday-Thursday 10:00-14:00; never during month-end close or audit submission days; excluded outright for HR department staff without HR pre-approval. Best realism if scheduled in genuine open-enrollment season, but the scarcity frame works year-round for "dependent verification" framing — coordinate timing with HR so employees who act on a real enrollment process are not confused by the simulation. Wave 2 assignment per `phishing_campaign_plan.md`, minimum 21 days after Wave 1 exposure for SEG-C.
**Teaching cues (must be present in the landing page, LPV-03):** access HR systems through the known intranet path, not an email link; verify enrollment status inside the HR portal itself.

### Email as the recipient sees it

```text
From:    MedDefense Benefits Center <enrollment@meddefense-benefits.org>
To:      [First Name Last Name] <[employee@meddefense.org]>
Subject: Final notice: benefits elections close [DATE+3] — dependent coverage
         changes required

Dear [First Name],

Our records show one or more of your benefit elections still requires
confirmation before the open enrollment window closes on [DATE+3] at 5:00 PM.

Elections that are not confirmed by the deadline will revert to default coverage
for the coming plan year. Dependent coverage and FSA elections may be affected.

To review and confirm your elections:

   [SIMULATION_LINK]

If you have already confirmed your elections this week, no action is needed.
Questions about your coverage can be directed to the Benefits team through the
HR intranet portal.

MedDefense Benefits Center
Human Resources
```

**Why it passes the test:** Financial consequences feel personal and immediate — fear of losing benefits or pay is the documented employee pressure point for this lure class (`healthcare_social_engineering_patterns.md`). The template mixes plausible administrative furniture ("revert to default coverage," FSA elections) with a soft close ("if you have already confirmed... no action is needed") that mimics real HR messaging and makes the reader check rather than dismiss. This is the intermediate tier: the process is genuinely familiar to every employee, so recognition must come from the destination check (known intranet path, not email link) rather than from spotting anything obviously wrong.

**Attacker notes:** A real actor times this to the genuine open-enrollment announcement so the message hides inside expected traffic, and sends it to the whole workforce rather than one segment — the email blast is cheap and the yield is broad. The scarcity mechanism is doing the technical work: "Final notice" and a hard deadline override the reader's normal caution because the cost of ignoring a real notice is felt as personal financial loss. The advanced variant drops the link entirely and asks the employee to "reply with your confirmation number," converting the attack to pure reply-thread harvesting. The domain `meddefense-benefits.org` is constructed for this simulation to model the lookalike-pattern risk flagged for HR-adjacent lures in `phishing_kit_analysis_summary.md` (domain-lookalike risk cues); no such domain is registered and none may be.

**Safety note for simulation operators:** This lure borders a prohibited theme (financial consequence) while remaining inside the permitted list (benefits open enrollment, `simulation_ethics_guidelines.md`) — it must never threaten payroll termination or immediate hardship, and the landing page must lead with reassurance that no benefits action is real and the employee's elections are untouched. HR must approve content even for non-HR department targets because the message impersonates an HR process. Coordinate with the actual HR communications calendar to avoid collision with genuine enrollment messaging.

---

## T-BEC-04: Executive Wire Fraud (Advanced)

**Template ID:** T-BEC-04
**Target segments:** SEG-F and SEG-E (executives, executive assistants, finance and procurement), per `phishing_template_constraints.md`
**Tier:** Advanced — low technical indicators; relies on authority and workflow realism (`phishing_template_constraints.md` difficulty progression)
**Psychological mechanism:** Authority + social proof (`healthcare_social_engineering_patterns.md`, Pattern 5)
**Expected click-rate range:** 8-22% first exposure (`lure_effectiveness_benchmarks.md`, rank 6) — but the metric that matters for this template is not clicks; it is the finance BEC verification rate (`metrics_baseline.csv`: establish baseline at Wave 4)
**Deployment timing constraints:** SEG-E: Tuesday-Thursday 10:00-14:00, never during month-end close or audit deadlines. SEG-F: individually coordinated through the executive office, never on board meeting days (`clinical_schedule_constraints.md`). Wave 4 only, per `phishing_campaign_plan.md` — deployed after verification behavior has been taught, never before. CISO approval is mandatory at this tier (`simulation_ethics_guidelines.md`: high-risk templates).
**Teaching cues (must be present in the landing page, LPV-04):** independent verification through a known channel; never resolve the request by replying in-thread; the reply-to address does not match the displayed sender (`email_header_inspection_results.md`, Finding 3).

### Email as the recipient sees it

```text
From:    "[CFO_LASTNAME], [CFO_FIRSTNAME]" <cfo.office@meddefense-exec-mail.com>
Reply-To: cfo.private.contact@exec-mail-consult.com
To:      [First Name Last Name] <[employee@meddefense.org]>
Subject: Confidential: wire authorization needed before the 3:00 PM payment run

[First Name],

I'm in back-to-back diligence calls for the rest of the afternoon and can't take
calls. We need to finalize the revised wire for [VENDOR_NAME] ahead of the 3:00
PM payment run — [AMOUNT] to the updated remittance details Finance received
last week.

Can you review and confirm the authorization packet today? The wire instructions
are here:

   [SIMULATION_LINK]

This is time-sensitive and shouldn't sit until tomorrow. I'm copying you because
[DIRECTOR_NAME] mentioned you handled the last one. Keep this between us until
the close is announced.

Thanks,
[CFO_FIRSTNAME]

Sent from my mobile — please excuse brevity.
```

**Why it passes the test:** Every pressure documented for this segment is stacked: authority you don't want to slow down ("If a director asks for something, you don't want to slow them down," `post_incident_click_rate_review.md`), confidentiality that suppresses peer verification ("keep this between us"), social proof ("[DIRECTOR_NAME] mentioned you handled the last one"), and timing tied to a real workflow (vendor payment runs, which the Q1 finance wave deliberately preceded, `campaign_reconstruction.md`). There is no technical indicator to spot: the domain pattern models the documented `meddefense-exec-mail.com` sample (MSG-003), and the Reply-To divergence — drawn directly from Finding 3 — is invisible without header inspection, which is exactly why the trained behavior is out-of-band verification rather than link or header checking. `[CFO_NAME]`, `[VENDOR_NAME]`, `[AMOUNT]` and `[DIRECTOR_NAME]` remain unfilled placeholders at authoring time; the campaign manager populates them from approved internal names at deployment, per the authority-realism requirement in `social_engineering_threat_profile.md` Section 5 while never impersonating real external parties.

**Attacker notes:** A real actor arms this lure with intelligence gathered from LinkedIn, the MedDefense website and prior compromised threads, so names, vendors and amounts are accurate. The kill chain deliberately avoids links: the reply-to address `exec-mail-consult.com` routes responses to an attacker-controlled mailbox while the display suggests internal mail, meaning a reply is a full compromise with zero clicks and zero telemetry (`email_header_inspection_results.md`, Finding 3). Variants hijack a genuine thread so the forged message inherits real history and formatting. The "sent from my mobile" line pre-excuses the informality that would otherwise be a tell. The professional follow-up escalates by phone — a vishing call referencing the email — which is why this template pairs with the Task 6 vishing scenarios for SEG-F and SEG-E: known-channel verification is the single defense that covers both channels (`vishing_facilitator_notes.md`: vishing teaches known-channel verification, not caller politeness).

**Safety note for simulation operators:** No real wire, payment, banking or vendor details may ever be used — `[VENDOR_NAME]` and `[AMOUNT]` must be fictitious placeholders approved by the Finance Representative before deployment (`program_governance_roles.md`). The reply-to divergence must route only to the simulation platform's monitored inbox; any inbound reply triggers an immediate automated response telling the recipient this was a simulation, before any real-world follow-on anxiety develops. Executive assistants receiving this template get an explicit note in the debrief that their verification behavior — not the executive's — is being trained, since the assistant is the true target of real-world BEC. Individual results stay with the program manager; SEG-F reporting is aggregate to CISO only (`employee_segments.csv`).

---

## Deployment Summary

| Template | Segment(s) | Wave | Tier | Click-rate anchor | Landing page |
|---|---|---|---|---:|---|
| T-EPIC-01 | SEG-B | 1 | Baseline | 40-62% | LPV-01 |
| T-MFA-02 | SEG-C | 1 | Baseline | 25-42% | LPV-02 |
| T-HR-03 | SEG-C, SEG-E | 2 | Intermediate | 22-38% | LPV-03 |
| T-BEC-04 | SEG-F, SEG-E | 4 | Advanced | 8-22% | LPV-04 |

All four templates map to landing-page variants per `post_click_microtraining_reference.md`; the landing pages themselves are designed in `post_click_intervention.md` (Task 4). No template deploys without joint CISO + HR signature, and none may be modified after signature without re-approval (`simulation_ethics_guidelines.md`, approval table).
