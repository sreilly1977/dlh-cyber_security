# Vishing and Social Engineering Scenario Scripts: MedDefense Health Systems

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-10
**Version:** 1.0
**Classification:** Confidential — facilitator use only
**Approval required:** CISO + HR; Legal review required if any session is recorded (`simulation_ethics_guidelines.md`, approval table)
**Use modes:** live simulation exercises, tabletop training, onboarding awareness sessions
**Companion artifacts:** `social_engineering_threat_profile.md` (design brief), `phishing_campaign_plan.md` (Month 3 vishing tabletop assignment)

---

## Facilitator Ground Rules (binding for all scenarios)

Derived from `vishing_facilitator_notes.md` and `simulation_ethics_guidelines.md`. These rules supersede any dialogue in a scenario if a conflict arises.

1. **Never obtain a real secret.** The script may test whether the employee begins to comply, but the facilitator must redirect before any real password, MFA code, or live credential fragment is spoken. If an employee begins reciting an actual password, interrupt with the safety phrase: *"Stop — this is a simulation. Please do not say any real password out loud, ever, including to us."*
2. **Stop the scenario the moment a real secret is at risk.** Debrief immediately afterward.
3. **Do not impersonate emergency medical staff during real patient-care events**, and never run a live exercise during an actual clinical emergency, downtime, or active incident (`clinical_schedule_constraints.md`, `annual_calendar_constraints.md`).
4. **Use approved internal names only where authorized.** Executive names in V-03 use the same deployment-time placeholder convention as T-BEC-04: `[EXEC_FIRSTNAME] [EXEC_LASTNAME]` and `[EXEC_TITLE]` are filled with approved internal names by the program manager, and employees are told in the debrief that impersonation of the named person was authorized for training.
5. **Document behavior, not personality.** Rubric scores record observable actions only.
6. **Debrief immediately, in the approved tone.** Use: "The attacker used urgency and authority." "The safe behavior was to verify through a known channel." "You can slow down a request without being unhelpful." Never: "You almost caused a breach," "That was wrong," "This should have been obvious."
7. **Privacy:** individual results go to the program manager only, for training assignment. No result reaches a manager as individual data, and nothing enters any performance review (`hr_privacy_rules.md`). Employees must be told this before the exercise begins — this program buys trust with transparency.
8. **Known-channel rule for every scenario:** the universal pass behavior is verification through a known channel (directory number, approved vendor contact list, ext. 4-HELP). Every script must contain at least one moment where the caller actively works against verification, because that is the realistic experience (`vishing_facilitator_notes.md`: teach known-channel verification, not caller politeness).
9. **Live-exercise recruitment:** participants are drawn from scheduled training cohorts (starting with the Month 3 tabletop for SEG-A supervisors, per `phishing_campaign_plan.md`). Employees on the exclusion list — leave, first week, active patient safety involvement, IR assignment, HR-approved support plans — are never called (`clinical_schedule_constraints.md`).

---

## V-01: IT Helpdesk Impersonation

### Scenario Header

| Field | Value |
|---|---|
| Scenario ID | V-01 |
| Target role | General clinical or administrative staff (SEG-B / SEG-C) |
| Attack objective | Get the employee to provide their current password, or accept an attacker-initiated password reset ("verify your identity by reading back the code we send you") |
| Psychological mechanisms | Authority + urgency + familiarity (`healthcare_social_engineering_patterns.md`, Patterns 1-2: IT is trusted, outages are feared) |
| Success criteria (attacker's perspective) | Employee states a password, reads back a reset/MFA verification code, or confirms willingness to accept a reset the "agent" initiates |
| Corresponding phishing analog | T-EPIC-01 / T-MFA-02; the phone version of the email story employees have already been trained on |
| Mode | Live call or tabletop read-through |

**Facilitator setup:** caller poses as a MedDefense helpdesk agent named "Alex Rivera," badge/agent number "HS-2247" (fictional), responding to a "ticket" about a failed Epic verification affecting the employee's unit. Caller displays skill at supplying plausible-but-checkable facts (the employee's unit name and start time, drawn from public/internal-sounding sources) to model the OSINT preparation described in the sector pattern for vendor/IT pretexting.

### Caller Script

```text
CALL OPENING

"Hi, this is Alex Rivera calling from the MedDefense IT helpdesk, agent
number HS-2247. I'm calling about ticket 44821 — we've got a failed
security verification on your Epic account that's going to suspend your
access at the top of the hour. I need about two minutes to clear it
before your shift gets busy. Can you confirm I'm speaking with
[EMPLOYEE_NAME]?"

[Pause for response. The name and unit details create the authority +
familiarity frame.]
```

```text
PRESSURE STEP (used after any hesitation)

"I get why you'd check — good instinct. But here's the situation: this
isn't a scheduled thing, the verification batch failed overnight and
about forty accounts on your unit are affected. The ones who don't get
cleared before 8:00 get locked out at shift start, and the backlog after
a lockout is two days. You do not want to be charting on paper for two
days. So: quickest path is I verify your identity right now and push the
clear through. Ready?"
```

```text
THE ASK (the objective)

"Okay — for the reset I need to confirm it's really you. Two options: you
can read me your current password so I can match it against the account,
or I can push a reset code to your phone right now and you read it back
to me. Either works — whichever is faster for you."
```

**BRANCH A — COMPLIANCE**

If the employee begins to comply (starts reading/recalling a password, or says "okay, one second" and reaches for their phone):

```text
[If a real password starts being spoken — INTERRUPT IMMEDIATELY:]
"Stop — this is a simulation. Please never say any real password out
loud, including to IT. Real IT never needs it. That interruption is the
whole lesson; let's finish the debrief."

[If the employee is merely moving toward compliance without disclosing
anything yet, push one more step to test the limit:]
"Great — go ahead whenever you're ready. And to confirm, you're okay with
me pushing the reset from my side? Then you'll get a code on your phone —
just read it straight back to me."

[End the scenario the moment compliance becomes concrete. Do not allow an
actual password or code to be spoken. Debrief immediately per Branch A
rubric.]
```

**BRANCH B — HESITATION**

If the employee stalls ("I'm not sure...", "can you hold on?", "let me ask my charge nurse") but does not verify and does not refuse:

```text
"I hear you — look, I don't want to hold you up either. Tell you what,
I'll keep the ticket open fifteen minutes under your name. But after
that the verification batch rolls over and it becomes a lockout, and a
lockout needs a supervisor approval form and that's a whole thing. So
it's much easier if we just wrap this now. Which option did you want —
password match or reset code?"

[If the employee continues hesitating without choosing verification:]
"No problem — the ticket stays open. You can call the helpdesk back on
this. Although heads up, if you call the main line you'll hit the queue,
could be half an hour, and the batch rolls at the top of the hour."

[End scenario. The correct resolution was a known-channel callback, not
politeness with a stranger. Score per rubric.]
```

**BRANCH C — VERIFICATION REQUEST**

If the employee asks to verify the caller ("Let me call the helpdesk back," "What's your callback number?"):

```text
[Attempt 1 — redirect:]
"I'd love that, but the queue's brutal right now and the batch rolls
within the hour. Since I'm already on the line with you, this is the
fastest way to protect your access."

[Attempt 2 — supply a number (the trap):]
"If it helps, you can call me back direct at 555-0148 — it's my desk
line, rings straight to me."

[If the employee insists on using the independently found known channel:]
"You know what, that's fine — actually, that's the right call. I'll
leave a note on the ticket."

[END SCENARIO — FULL PASS PATH. The redirect attempts and the fake
direct-desk number are the teaching payload: an attacker's callback
number is worthless; only a directory-found number proves anything.]
```

### Assessment Rubric

| Decision point | Full pass | Partial pass | Fail |
|---|---|---|---|
| Opening (name/unit recital) | Employee notes they did not initiate contact and treats the call as unverified | Employee is polite but engaged, no red-flag recognition yet | Employee accepts caller identity from the opening alone |
| The ask (password or reset code) | Refuses both options outright; recognizes that real IT never asks for a password or reads-back code | Refuses the password option specifically but engages with the reset-code option without verifying | Begins complying with either option (facilitator halts before disclosure) |
| Verification response | Ends the call politely and re-establishes contact via ext. 4-HELP or the directory-found helpdesk number | Attempts verification but uses, or nearly uses, the number the caller supplied | Continues engagement on the caller's terms; urgency wins |
| Post-call action | Reports the call (ext. 4-SECURITY / security@meddefense.org / tells supervisor), including the supplied fake callback number | Reports after prompting during debrief | No reporting intent expressed even in debrief |

**Full pass definition:** does not disclose a password or code, refuses the reset the caller initiates, refuses the caller-supplied callback number in favor of a known channel, and reports the call. Consistent with the safe-pass behaviors in `vishing_facilitator_notes.md`.

**Scoring guidance:** a live-halt under Branch A is scored as the fail for the disclosure decision point only; the employee's composure, honesty, and debrief engagement are noted qualitatively but never scored, and the halt language itself reinforces the culture rule (nobody, including IT, ever needs your password).

### Debrief Notes

**What to explain:**

- The caller's facts came from public and quasi-public sources — unit name, shift start, a plausible agent name. Attackers preparing vishing calls use LinkedIn and facility websites, exactly as documented in the peer-organization incidents noted by Mike Torres. Plausible detail is not verification.
- Real MedDefense IT never asks for your current password, on the phone, ever. Any request to read back a reset code transfers control of your account to whoever is on the line — a reset code is a new password handed to a stranger.
- The "callback number" the caller offered was the trap. Verification only counts through a number you found yourself: ext. 4-HELP from the intranet, or the IT directory entry. The attacker's greatest enemy is the independently dialed call.
- The urgency ("batch rolls at the top of the hour," "two-day lockout backlog") was manufactured. The Cobalt Strike path analysis makes the general rule plain: slow down requests involving credentials, money, PHI, or remote access — urgency is the attacker's scheduling tool, not yours (`cobalt_strike_phishing_path.md`, training message).
- You were told in advance that results are training data, never performance data, and never shared with your manager individually — and that promise holds (`hr_privacy_rules.md`).

**What made this realistic:** the scenario mirrors the second failure documented in the Module 5 aftermath — a misdirected helpdesk verification call, where the receiving employee had no framework for verifying the caller. The lure vocabulary matches the phishing kit's documented language ("failed security verification," "access hold") so the phone experience and email training reinforce each other.

**What a real attacker would have gained:** an account takeover of the employee's Epic identity — full ePHI access under a legitimate clinical account, with activity attributed to the victim. The Q1 incident demonstrated where that leads: credential exposure, Cobalt Strike beaconing, service-account misuse, lateral movement, and IR activation (`module5_incident_summary.md`, `cobalt_strike_phishing_path.md`). A password surrendered by phone skips the entire email stage of that chain and hands over access with no link, no attachment, and no detection surface for the mail gateway.

---

## V-02: Vendor Support Escalation

### Scenario Header

| Field | Value |
|---|---|
| Scenario ID | V-02 |
| Target role | Clinical staff or clinical supervisor (SEG-B / SEG-A), run with unit-leadership coordination for supervisors |
| Attack objective | Get the employee to install a remote support tool, grant screen-sharing access, or admit an unknown caller to a workstation for an "emergency Epic patch" |
| Psychological mechanisms | Authority + urgency + technical dependency (`healthcare_social_engineering_patterns.md`, Pattern 4) |
| Success criteria (attacker's perspective) | Employee installs software at the caller's direction, grants screen/remote control, or hands session access to the caller in any form |
| Corresponding pattern | Documented Case C: vendor requesting domain admin without ticket justification or expiration; Q1 IT staff responded specifically to vendor-support framing (`insider_threat_case_notes.md`, `post_incident_click_rate_review.md`) |
| Mode | Live call or tabletop read-through |

**Facilitator setup:** caller poses as "Dev Malhotra" from "Nexus Clinical Systems" (fictional vendor), calling a nurse or supervisor about an "urgent compatibility patch" for the interface the unit's documentation workflow depends on, tied to a ticket reference the caller recites confidently. The scenario is built so that the *desire to restore or protect patient-care workflow* — the documented pressure point — does the persuading.

### Caller Script

```text
CALL OPENING

"Hi, is this [EMPLOYEE_NAME]? This is Dev Malhotra, Nexus Clinical
Systems — we're the vendor supporting the documentation interface on
your unit. Listen, I'll be quick because your night shift was probably
already told: we pushed a compatibility update to Epic's interface engine
last night and it broke the CCD exchange for a handful of units, yours
included. Charge nurse [SUPERVISOR_SURNAME] is copied on ticket CHG-2214.
Right now charts are syncing with a two-hour lag, and it degrades the
longer we wait. I need ten minutes with someone at a workstation to
apply the patch client-side."

[Pause. Ticket references and supervisor names are checkable — that's
the test.]
```

```text
PRESSURE STEP (after hesitation)

"Totally fair — I'd check too. Here's what I can tell you: your charge
nurse should have the ticket, CHG-2214, and it names your unit. The
delay between now and the fix isn't on our side, it's the sync degrading
every cycle. Worst case, overnight chart lag turns into a mismatch
between MAR and the chart, and you do not want to be the unit explaining
that at morning huddle. Ten minutes and it's done."
```

```text
THE ASK (the objective)

"So here's the fastest path. Go to any workstation — it doesn't need to
be yours — open your browser and go to nexus-clinical-support[dot]net/
patch. It's our support client, I'll walk you through it, takes about
ten minutes. It'll show a window asking to share the screen — you'll
need to approve that so I can confirm the patch landed. If you prefer,
we can do it as a remote session from my side and you just approve the
prompt when it pops."
```

**BRANCH A — COMPLIANCE**

If the employee begins navigating to the URL or agrees to screen share:

```text
[If the employee reaches for a browser:]
"Perfect — I'll stay on the line while it loads."

[FACILITATOR: end the scenario before any install or share prompt is
actually completed. If a browser is already open in a live exercise,
halt:]
"Stop — this is a simulation. Nothing would have installed; that
address doesn't exist outside this exercise. Close the browser if you
opened it. Let's debrief."

[If the employee verbally agrees to the session, end:]
"Great, approving it now—" [HALT: "This is a simulation. No software is
being installed; no session exists. Let's debrief."]
```

**BRANCH B — HESITATION**

If the employee neither complies nor verifies ("I'm not sure I'm supposed to do that," "Let me find my supervisor"):

```text
"I understand — you know your unit better than I do. But can I flag the
timeline? The degraded sync compounds overnight. If you can't help me
now, I need to escalate this to the after-hours queue, and that means
your unit's charts sit degraded until the morning team picks it up.
You'd basically be first in line if you give me ten minutes now. Your
supervisor already agreed this is a priority — you can call her, but
she's probably mid-rounds. What do you say, workstation nearby?"

[If hesitation continues, one final push:]
"Okay — I'll do one better. If you're worried about permissions, I can
email you the link directly so you have it in writing from our support
address. That way it's all documented. Want me to send it now?"

[End scenario. The email offer is the escalation to a second channel —
both channels belong to the attacker. Score per rubric.]
```

**BRANCH C — VERIFICATION REQUEST**

If the employee attempts verification ("Let me call Nexus back on our approved list," "Does IT know about this?"):

```text
[Attempt 1 — reframe:]
"IT's aware of the ticket, but they're not the ones who can patch
client-side — that's us, that's why you're getting me directly."

[Attempt 2 — undermine the channel:]
"If you call the number on the vendor list you'll get our dispatch
queue — they'll read you the same ticket and put you in line for the
next available engineer. That could be hours. I'm already here with the
fix. The ticket number is on your side too — CHG-2214. That's your
proof."

[If the employee insists on the approved-list callback:]
"...Sure. Okay. Yeah — do that. The ticket's under Malhotra."

[END SCENARIO — FULL PASS PATH. Note in scoring whether the employee
recognized that a ticket number recited by a caller proves nothing: the
approved vendor list is the only usable proof, and IT change control —
not the vendor — announces patch windows.]
```

### Assessment Rubric

| Decision point | Full pass | Partial pass | Fail |
|---|---|---:|
| Opening (vendor self-ID + ticket recital) | Treats the caller as unverified regardless of detail supplied; notes that vendors do not cold-call floor staff | Engages but expresses doubt about process | Accepts vendor identity and ticket recital as sufficient |
| Software/screen-share ask | Refuses to install anything or grant screen access; states that vendor access goes through IT | Refuses install but is swayed toward "approve the prompt" | Navigates to URL, agrees to share, or accepts the remote-session prompt (facilitator halts) |
| Channel offers (URL, email, remote prompt) | Recognizes all channels offered by the caller as untrusted, including the follow-up email offer | Accepts that "having it in writing" adds safety | Takes any attacker-supplied channel as progress toward resolution |
| Verification response | Callback through the approved vendor contact list and/or IT confirmation (ext. 4-HELP) before any workstation action | Calls a number found on-screen/quickly but not the approved list | Defers to caller's assurance ("IT's aware") |
| Patient-safety balance | Halts workstation action without dismissing the operational concern; hands the issue to the proper channel so the workflow problem still gets solved | Solves nothing — either complies to "be helpful" or dismisses the entire issue without referral | Complies specifically to avoid being blamed for workflow degradation |

**Full pass definition:** does not install software or grant screen/remote access; refuses to use the caller's URL, email, or session channel; verifies through the approved vendor contact list and/or IT; reports the call. Per `vishing_facilitator_notes.md` safe-pass behaviors: refuses unverified remote access and uses the known callback path.

**Scoring guidance:** refusing remote access is weighted above everything else — this is the highest-impact failure in the scenario, since granting screen or session access equals handing over an authenticated clinical session. Partial credit is available for operational responsibility: an employee who refuses the caller but also ensures the (possibly real) workflow issue gets routed to IT demonstrates the complete safe behavior — refuse the channel, preserve the mission.

### Debrief Notes

**What to explain:**

- The caller's credibility props — ticket number, supervisor surname, plausible technology (CCD exchange, sync lag) — were all either invented or repurposed from public information. A recited ticket number is not verification; the approved vendor contact list is.
- Software installation and screen sharing on a workstation is the modern equivalent of handing a stranger your badge. Approval of a session prompt gives the caller the employee's authenticated clinical context. The safest response is also the easiest to say: *"I can't do that — our vendor access goes through IT."*
- The vendor's pushback against the callback number was scripted deliberately: real vendor relationships survive callbacks; impostor relationships die at the first independently dialed call. That asymmetry is the employee's advantage — use it every time, on every call, forever.
- The scenario's realism comes from Case C in the insider-threat case notes: an unnamed clinical vendor requesting temporary domain admin with no ticket justification and no expiration. The documented lesson is that vendor urgency cannot bypass privilege approval (`insider_threat_case_notes.md`).
- Note the safety valve used in the script: the caller offered to send the link by email. Being offered "proof in writing" by an unverified party is not verification — the writing comes from the same source as the call.
- Results are training data only, protected from individual manager view and from any performance review (`hr_privacy_rules.md`).

**What made this realistic:** clinical operations genuinely depend on vendors and urgent support; the caller exploited the documented employee pressure point — the desire to restore or protect patient-care workflow — rather than fear alone. That is what makes vendor pretexting the highest-realism scenario class for clinical targets (18–35% expected effectiveness in email form, `lure_effectiveness_benchmarks.md`; the phone version carries no link to inspect at all).

**What a real attacker would have gained:** with screen sharing or a remote-support session granted from a clinical workstation, the attacker inherits the employee's authenticated Epic context — patient records, MAR data, and the clinical network segment — without capturing a single credential. From there the documented chain applies: credential access from an already-authenticated session, lateral movement via privileged or service accounts, Cobalt Strike beaconing, full IR activation (`cobalt_strike_phishing_path.md`). One approved dialog box bypasses mail gateway, EDR heuristics, and every mail-side lesson at once — which is why the phone matters as much as the inbox.

---

## V-03: Executive Authority Impersonation

### Scenario Header

| Field | Value |
|---|---|
| Scenario ID | V-03 |
| Target role | Administrative or finance staff (SEG-C / SEG-E) — staff with authority to initiate payment action or handle sensitive documents; executive assistants are a priority cohort |
| Attack objective | Get the employee to initiate a financial action (payment release, banking change confirmation) or transmit a sensitive document based solely on a phone call from someone impersonating an executive by name |
| Psychological mechanisms | Authority + social proof (+ manufactured secrecy) (`healthcare_social_engineering_patterns.md`, Pattern 5) |
| Success criteria (attacker's perspective) | Employee commits to initiating the payment/banking change before the call ends, or attaches/transmits the document to the caller's channel |
| Corresponding phishing analog | T-BEC-04; the phone-first version of the same fraud, with the reply-channel trick replaced by a caller-supplied channel ("send it to this number/email") |
| Mode | Live call or tabletop read-through; coordinate SEG-F-adjacent runs through the executive office and Finance Representative per `program_governance_roles.md` |

**Facilitator setup:** caller poses as `[EXEC_FIRSTNAME] [EXEC_LASTNAME]`, `[EXEC_TITLE]` (approved internal name, per ground rule 4), calling an AP/finance analyst or senior administrative staff member. The caller invokes a confidential acquisition, an imminent payment run, a known peer's name for social proof, and a strong don't-verify frame. This scenario deliberately stacks every documented BEC pressure: authority you don't slow down, social proof, workflow timing, and secrecy (`healthcare_social_engineering_patterns.md`, Pattern 5; `post_incident_click_rate_review.md` executive themes).

### Caller Script

```text
CALL OPENING

"[FIRST_NAME], hi — it's [EXEC_FIRSTNAME]. I know this is out of the
blue and I've only got a few minutes before I'm back on with the
lawyers. We're closing the sensitive piece of the [PROJECT_NAME] matter
today. I need a wire released under the revised remittance before the
3:00 payment run — the vendor moved their account and the updated
banking details went to [DIRECTOR_NAME] last week. I need you to confirm
the release amount of [AMOUNT] and I need it handled this afternoon.
[DIRECTOR_NAME] speaks very highly of how you ran the last one, which is
why I'm calling you directly and not going through the usual chain."

[Pause. Name, peer endorsement, confidential matter, deadline: the full
authority + social proof stack.]
```

```text
SECRECY FRAME (delivered early and reinforced)

"One more thing — this is still confidential until the close is
announced, so I'd rather this doesn't go through the regular approval
workflow today. Nothing improper, just timing: the fewer people involved
before announcement, the better. Between the two of us and [DIRECTOR_NAME]
that's everyone who needs to know."
```

```text
THE ASK (the objective)

"So: can you confirm you'll push the [AMOUNT] release against the
updated remittance this afternoon? And once it's done, just send me the
confirmation — fastest is my personal email, it's
[exec].[lastname].personal@mail-secure-direct[dot]com — or text it to this
number if that's easier. I'll be in meetings on and off."
```

**BRANCH A — COMPLIANCE**

If the employee verbally commits to releasing the payment, or begins transmitting the document/confirmation to the supplied channel:

```text
"If you can get it moving now, I'll text [DIRECTOR_NAME] that you're on
it. Appreciate you, [FIRST_NAME]."

[FACILITATOR: end the scenario the moment commitment is concrete.]
"Stop — this is a simulation. [EXEC_FIRSTNAME] [EXEC_LASTNAME] did not
call you; the wire, the acquisition, and the banking change do not
exist, and nothing has been sent anywhere. Let's debrief."
```

**BRANCH B — HESITATION**

If the employee stalls ("I usually need the requisition...", "our process says I can't...", "let me check with my supervisor") without verifying or refusing:

```text
"I hear you, and I'm not asking you to break process — I'm asking you
to accelerate a decision I've already made. The requisition exists;
it's attached to the confidential file, which is exactly why I can't
have it circulating today. What I need from you is momentum this
afternoon. If it helps, consider this my verbal authorization, and I'll
retroactively sign whatever the process needs next week once this is
announced. Payment runs at 3:00 — can I count on you to have it queued
by then?"

[If hesitation continues, one more leverage push:]
"Or — and tell me honestly if this is easier — I can loop in
[DIRECTOR_NAME] to green-light it with you. He's mid-something, but if
you'd feel better with him saying so, I'll text him now and he'll call
you inside ten minutes. Should I do that?"

[Note: the peer-call offer is a bluff the caller cannot fulfill, but
some employees accept it as verification-by-proxy. End scenario on the
employee's answer; score accordingly.]
```

**BRANCH C — VERIFICATION REQUEST**

If the employee attempts verification ("Let me call you back on your office line," "I'll confirm with [DIRECTOR_NAME]", "This needs the standard approval"):

```text
[Attempt 1 — channel refusal:]
"Don't call the office line — I'm not there, I'm at the lawyers' office
all afternoon. And don't email the corporate address either, it's on the
deal file and the paralegals monitor it. That's why the personal email
is the only reliable path today."

[Attempt 2 — process dismissal:]
"About the approval — the requisition is signed, it's in the deal file,
you'll see it next week. Today the only bottleneck is the payment run.
[Try reframing the delay as disloyalty:] Look, [DIRECTOR_NAME] told me
you're the one person who can move without drama. Let's not make this
complicated."

[Attempt 3 — the callback compromise (trap):]
"If you really must, call me back at 555-0187 — that's my direct line
at the lawyers' office."

[If the employee still insists on the directory-known office line or
the standard workflow / director confirmation:]
"Fine. Do what you need to do. I'll tell [DIRECTOR_NAME] it may slip to
tomorrow."

[END SCENARIO — FULL PASS PATH. The score hinges on whether the
employee accepted any caller-supplied channel as verification. Only a
directory-found number or the standard documented approval workflow
counts.]
```

### Assessment Rubric

| Decision point | Full pass | Partial pass | Fail |
|---|---|---|---|
| Opening (name + peer endorsement + deadline) | Recognizes that caller ID and a recited name prove nothing; does not treat flattery/social proof as authorization | Engages professionally but notes discomfort without acting on it yet | Treats the caller as the executive based on voice/caller ID/name alone |
| Secrecy frame | Identifies "keep this between us" as a verification trigger; proceeds only through standard workflow | Notices the secrecy pressure but does not connect it to the response | Treats confidentiality as a reason to bypass the approval workflow |
| The ask (payment/document release + personal channel) | Refuses to initiate any financial action or send any document; states the requirement for standard authorization | Refuses the personal channel but leaves payment commitment open ("I'll try") | Commits to release the payment, or sends/prepares to send the document to the caller's channel (facilitator halts) |
| Verification response | Callback via the directory-found office line, or confirmation through the standard workflow/second approver; declines caller-supplied numbers and emails | Uses the caller's "direct line" but insists on confirming with the peer approver anyway | Accepts "I'm at the lawyers' office" or the bluff of a peer call as verification |
| Peer-call bluff (Branch B/C) | Recognizes that a promised intermediary call from an unnamed-but-imminent third party is still caller-controlled | Hesitates but ultimately requests independent confirmation | Waits for or relies on the promised peer call rather than acting on independent verification |

**Full pass definition:** does not commit to any financial action; does not transmit any document or confirmation to any caller-supplied channel; treats the secrecy request as a red flag; verifies through the directory-found executive line or the standard documented approval workflow; reports the call. Per `vishing_facilitator_notes.md`: no disclosure, known-channel callback path used, call reported, escalates to supervisor or security.

**Scoring guidance:** the single most weighted behavior is refusing to act on the caller's authority alone — money and confidential documents are the two irreversible actions in the fraud class, which is precisely why the sector data shows BEC's impact rating dominates despite low click rates (`lure_effectiveness_benchmarks.md` rank 6). Commitment on the call is scored as fail even though nothing real moved; the facilitator's halt, per Branch A, prevents any real-world consequence and preserves the no-shame debrief frame. A refusal-plus-referral — "I can't, but [STANDARD_WORKFLOW] will handle it properly this afternoon" — is a full pass with distinction: the employee neither enabled fraud nor stalled legitimate business.

### Debrief Notes

**What to explain:**

- The caller's authority was performed, not proven. Names, a peer endorsement, a confidential acquisition, and a deadline are all things an attacker gathers from LinkedIn, press, and facility websites — the exact OSINT base documented in the peer-organization vishing incidents from Q1 2026. Social proof ("[DIRECTOR_NAME] spoke highly of you") is a tactic, not a credential.
- "Keep this between us" is the tell. Confidentiality pressure in an unexpected request exists to remove you from the people who could expose the fraud. Real executives survive a callback through the directory; impostors cannot. That sentence should raise your verification temperature, never lower it.
- The personal email channel — and the office-line refusal, and the "direct line at the lawyers' office" — all served one goal: keeping the conversation inside channels the caller controls. The T-BEC-04 phishing analog does the same thing invisibly with a reply-to mismatch (`email_header_inspection_results.md`, Finding 3); on the phone, the trained response is identical: the only trustworthy channel is one you reached yourself.
- The peer-call bluff ("I'll have [DIRECTOR_NAME] call you inside ten minutes") is the most advanced move in the script. Verification-by-proxy is still verification-by-attacker: you cannot control what the promised callback actually is, only what number you dial yourself.
- "Consider this my verbal authorization, and I'll retroactively sign next week" was engineered to sound reasonable. Authorization that exists only as a promise is indistinguishable from no authorization, and no real process at MedDefense works on retroactive signatures for wire releases.
- Results are training data only: no performance review, no individual manager disclosure, and no public naming under any circumstance (`hr_privacy_rules.md`).

**What made this realistic:** finance and executive-assistant staff are the documented sweet spot — Q1 showed MedDefense finance users opening messages more than clicking them, preferring to reply or take offline action (`post_incident_click_rate_review.md`), and executive assistants hold the exact authorization interfaces this fraud needs (`workforce_population_breakdown.md`). The call-only format removes even the limited technical cues email offers; the only defense left is behavior, which is why this scenario trains a single reflex — independent verification — rather than a checklist.

**What a real attacker would have gained:** an outbound wire to attacker-controlled banking details, or a confidential acquisition/board document in an attacker's inbox. Either outcome completes with zero credentials stolen and zero systems compromised — the employee takes the action on the attacker's behalf, which is what defines vishing impact: a successful call bypasses every technical control by getting a trained, authorized employee to do the work (`vishing_facilitator_notes.md`, facilitator purpose). Wire recall windows close in hours, and document disclosure cannot be recalled at all.

---

## Cross-Scenario Training Summary (handout version)

The debrief of every scenario lands on the same three reflexes. Distribute this card after any live exercise or tabletop.

| Reflex | What it sounds like |
|---|---|
| **Slow down** | "I can't act on urgency alone — my workflow has a speed limit for money, credentials, PHI, and remote access." |
| **Verify on a known channel** | "I'll call you back on the number I find myself — the helpdesk (ext. 4-HELP), the approved vendor list, or the directory." |
| **Report it** | "Every suspicious call gets reported — ext. 4-SECURITY or security@meddefense.org — even if I refused the caller. Reporting is training data, never trouble." |

One sentence to remember: **a callback you dialed yourself beats every credential a caller can recite.**
