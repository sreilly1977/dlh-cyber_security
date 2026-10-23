# Facilitator Script: Nexus Supply Chain Compromise Tabletop

**Exercise length:** 120 minutes
**Scenario version:** 1.0
**Facilitator:** Steve (Cybersecurity Engineer)
**Classification:** Internal - Exercise Use Only

This document is facilitator-only. Sections marked **(private)** are never read aloud or distributed. It assumes the companion files exist: `exercise_scenario.md`, `capability_map.yaml`, `inject_schedule.yaml`, `participant_guide.md`.

---

## Pre-exercise checklist

**Room and logistics:**

- [ ] Room booked for 150 minutes (120 exercise + 30 debrief)
- [ ] Clock or timer visible to facilitator only — participants should feel time pressure through the injects, not a stopwatch
- [ ] Whiteboard or flipchart available for decisions-with-owners tracking
- [ ] Recording device active (if applicable and consented, per organizational policy)

**Materials:**

- [ ] `exercise_scenario.md` distributed to all participants before start
- [ ] `participant_guide.md` distributed — each participant has read their own section
- [ ] This script and `inject_schedule.yaml` printed for facilitator reference
- [ ] Evaluation sheet (per-capability, from capability map) ready for real-time note-taking
- [ ] Observer guidance communicated to any observers: they do not speak, they capture

**Seating:**

- [ ] U-shape or single table so all seven participants can see each other, not just the facilitator
- [ ] Dr. Morales seated as a participant, not at the head of the table — reduces the pull to defer upward
- [ ] Observers seated behind the participants, out of the sightlines of the main discussion

**Observer briefing (before participants enter):**

Remind observers of the five things they are capturing: decisions with owners and timestamps, facilitator probes and evidence-based versus asserted responses, deadlocks and what they stalled on, unreconciled contradictions, and verbatim quotables.

**Final check before reading the ground rules:**

Confirm nobody in the room believes this is a training session. If anyone says "so what should we be learning today," correct it: they are being tested, the organization is being tested, and the findings will be real.

---

## Facilitator ground rules (read aloud)

"This is a tabletop exercise. You will receive situation updates from me. Respond as you would in a real incident. I will sometimes ask follow-up questions, not because your answer was wrong, but because I want to understand your reasoning. There are no grades, no performance reviews, and no correct answers. What we are looking for is where our response would break down under real conditions. That is how we get better.

"Three things about how this works. First, the scenario is fictional but the facts about our systems, our vendor contract, and our obligations are real — use them as you would in a real event. Second, if you would pick up a phone, open a ticket, or call someone in real life, say so out loud and tell us who — 'someone should handle the vendor' is not an action, a name is. Third, if you do not know something, say so. Declaring the gap is worth more than performing confidence.

"I am neutral. I will not tell you whether you are right. Keep in mind what is at stake in this scenario: patient scheduling across three sites, roughly 3,500 appointments a week, and our HIPAA obligations as a covered entity if patient data has left the environment. When the exercise ends, we will debrief together, and what you find in yourselves will matter more than anything I observed. Let us begin."

---

## INJ-00 (T+0 min)

**Read aloud verbatim:**

"The SOC has flagged unusual outbound traffic from the Nexus scheduling server SCHED-SVR-01 at Main campus to 193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe. EDR shows the connections occur at regular four-hour intervals, consistent with beaconing. The alert fired 45 minutes ago. The Nexus agent is running under its normal service account, executed from its signed binary path, and generated no antivirus alerts. Patient scheduling is running normally across all three sites. No other anomalies have been detected."

**Allow:** 10 to 12 minutes for initial responses

**Probing questions (use if responses are superficial):**

- "Who has been notified in the last 10 minutes? Names."
- "James, what evidence would you need to escalate this from a potential incident to a confirmed one?"
- "Sarah, at what point would you make a containment recommendation, and what would you do to the host in the meantime?"
- "Has the vendor been contacted yet? Should they be?"
- "Anyone: the binary is signed and running as a service. What does that tell you about how it got there?"

**Engagement flags:**

- **Chen** not engaging if the SOC perspective stays theoretical — press with "what are your analysts doing right now, literally, in the next hour?"
- **Park** not engaging if she defers everything upward — press with "you are the IT Director; what happens without further authorization?"

**Watch for (private):** Does anyone ask whether the update mechanism is the vector? Does anyone contact Nexus before INJ-01 delivers that information? Note the exact time of incident declaration and whether a severity was named.

**Transition:** "Time has passed. The team has taken initial actions. The following update arrives."

---

## INJ-01 (T+20 min)

**Read aloud verbatim:**

"Nexus Patient Scheduling has published a security advisory. Their build infrastructure was compromised by a threat actor with access to their signing environment. All software updates distributed through the automatic update channel in the last 21 days may contain a malicious component, including the version deployed to MedDefense three days ago. The package was signed with the valid Nexus Health Technologies, Inc. code-signing certificate, so signature validation did not and will not catch it. Nexus advises all customers to review their agent deployments immediately. They do not yet have a patch or a clean-version list."

**Allow:** 15 minutes

**Probing questions:**

- "Does the advisory change your severity? Who re-declares it?"
- "Who decides whether scheduling goes offline, and is that person in this room?"
- "If Nexus pushes a fix tomorrow, it comes through the same channel that delivered the malware. Do you install it?"
- "Clinical director: what does the loss of patient scheduling at three sites mean for tomorrow morning's front desks?"
- "Sarah, you own the vendor relationship commercially. What do you want from Nexus right now, in priority order?"

**Engagement flags:**

- **Clinical director representative** is the critical voice in this inject — if silent, the exercise loses its central conflict. Flag hard if they have not spoken by minute 5 of this segment.
- **Kim** not engaging if infrastructure options are absent — press with "physically, how would we sever this?"

**Watch for (private):** Is the signed-update trust paradox surfaced by participants, or only by the facilitator? Is the isolation decision made, deferred with an owner and deadline, or left floating? Record which. CAP-01 and CAP-03 evaluation starts here.

**Transition:** "While the team digests the advisory, someone makes contact with the vendor. Here is how that goes."

---

## INJ-02 (T+35 min)

**Read aloud verbatim:**

"The team contacts Nexus. The 24x7 incident line, +1 512 555 0184, connects to a tier-1 operator who can only take a ticket number. The account executive, Priya Natarajan, responds to email within minutes but has no technical information and offers to schedule a call with the security team this week. Ninety minutes after the advisory, Nexus still has not contacted MedDefense directly, despite the BAA requirement to notify within 24 hours of THEIR discovery. You have no named incident contact, no IOCs, no affected-version list, and no commitment timeline."

**Allow:** 12 to 15 minutes

**Probing questions:**

- "Helena, the BAA is your document. What does it actually entitle us to right now, and what does Nexus owe us that they have not delivered?"
- "How long do you wait on this vendor before you act on your own?"
- "Who is the single owner of vendor communication? If three people email Nexus separately, what does that do to our legal position?"
- "Marcus Oduya is the Nexus CISO. Who reaches him, and how hard do we push?"

**Engagement flags:**

- **Reyes** not engaging if legal stays silent on the BAA — this inject belongs to her. Press directly: "is Nexus in breach of contract right now?"
- **Park** not engaging if vendor management stays distributed with no named owner.

**Watch for (private):** Is the 24-hour clause invoked in writing, or only discussed? Does anyone propose suspending their own investigation pending vendor input? That is the CAP-02 failure signature. Capture verbatim any statement about who owns the vendor relationship.

**Transition:** "While the vendor conversation stalls, your own forensics move. So does the clock. The next update changes the technical picture."

---

## INJ-03 (T+50 min)

**Read aloud verbatim:**

"Forensics on the captured traffic confirms the beacon is receiving commands, not just polling. The natural containment step is to sever the site-to-site IPsec tunnel and isolate SCHED-SVR-01 — cutting the FHIR feed to and from Nexus. The clinical director representative interrupts: tomorrow morning, roughly 500 patients are booked across the three sites, pre-registration and insurance eligibility will fail, and front desks will have no electronic schedule. Some of those patients are oncology follow-ups and post-operative checks. Taking scheduling offline is a patient care decision, not just a security decision, and in their view it is not Sarah Park's call to make."

**Allow:** 18 to 20 minutes — this is the centerpiece conflict of the exercise; do not rush it

**Probing questions:**

- "Sarah, the clinical director just said this is not your call. Is it? Who says?"
- "Dr. Morales, your security lead wants to contain and your clinical lead wants to run tomorrow's clinic. What do you need from this room to decide?"
- "Is there a middle option, or are we pretending there is one?"
- "Whatever you choose: what is the re-evaluation trigger? Under what conditions does this decision get revisited?"
- "If we isolate tonight, walk me through tomorrow at 7 a.m. at the West Campus front desk. Literally."

**Engagement flags:**

- This inject must involve **Park, Chen, clinical director, and Morales** at minimum. If Morales arbitrates in the first two minutes, note it as a facilitation challenge: slow her down with "what do your leads recommend?" — the exercise is testing whether the leads can reach a recommendation, not whether the CEO can decide alone.
- If the room smooths the conflict over to be polite, escalate it deliberately: "so everyone is fine with this? Sarah, are you fine with it?"

**Watch for (private):** Roughly 3,500 patient scheduling interactions per week makes this decision real. Does a named decision-maker emerge? Is the decision paired with compensating controls and a re-evaluation trigger? Or does it float upward without a recommendation? Record the exact minute the decision is made — time-to-decision is the core CAP-03 metric. Also note whether anyone weighs evidence destruction against containment timing (CAP-06/CAP-04 overlap with Kim).

**Transition:** "A decision has been made. But the scope of what happened over the last three days is bigger than anyone in this room has yet said. The next update is the one that matters legally."

---

## INJ-04 (T+65 min)

**Read aloud verbatim:**

"Firewall log review changes the picture. During the three-day compromise window, the beacon channel carried approximately 2.1 GB of outbound data from SCHED-SVR-01 — far more than command-and-control traffic accounts for. Correlation with FHIR API logs shows elevated reads of patient demographic and insurance eligibility records through the svc-nexus-prod integration. Separately, the SOC notes the data flows documented to Nexus's subprocessors — Twilio and SendGrid handle SMS and email appointment reminders, meaning patient contact data also transits two additional third parties whose exposure status is unknown."

**Allow:** 15 minutes

**Probing questions:**

- "James, 2.1 gigabytes. In record terms, roughly what does that mean? Can you convert that to patients?"
- "Helena, is this a reportable breach under HIPAA yet? What would you need to say yes or no?"
- "Who collects the evidence, from which systems, and does anyone know whether those logs even exist?"
- "Robert, you own the infrastructure. What logging do we actually have on SCHED-SVR-01, and what is its retention?"
- "Do Twilio and SendGrid hold our patients' data? Whose problem is that?"

**Engagement flags:**

- **Kim** not engaging if the log-retention question goes unanswered or is answered optimistically. Press for specifics: "does that log exist today, yes or no?"
- **Reyes** should now be visibly working the HIPAA notification analysis. If she has not connected BA compromise to MedDefense's own obligations, note it as a live CAP-05 gap — do not correct it in the room.

**Watch for (private):** The key CAP-04 signature: does anyone produce a scoping methodology, or only assertions? Track whether the known-versus-unknown distinction is made explicit. Note whether subprocessors enter the assessment scope at all — the profile disclosed them, so the information was available from the start.

**Transition:** "While the team scopes the exposure, two events land at the same time. One is contractual. One is public."

---

## INJ-05 (T+80 min)

**Read aloud verbatim:**

"Two things happen in the same ten minutes. First, Nexus sends a formal notice under the BAA stating a 'security incident involving certain customer data' occurred, discovered by Nexus — but the notice is dated as of TODAY, while the advisory implies their build infrastructure was compromised weeks ago. Whether the 24-hour breach notification clock has already been blown depends on when Nexus actually 'discovered' it, and they will not say. Second, a health reporter from the local paper emails Marcus Webb: they have heard MedDefense is dealing with a 'cyber incident affecting patient appointments' and want a comment by end of day."

**Allow:** 15 minutes

**Probing questions:**

- "Helena, the discovery date does not fit. What do you do with that discrepancy, today?"
- "Marcus, it is your inbox. What does the reporter get, and when? Draft the first sentence out loud."
- "Does the public statement wait for the legal position? Helena, Marcus — talk to each other, right now."
- "Whose approval does the holding statement need before it goes out?"
- "Front desk staff will be asked about this tomorrow by patients. What do they say? Who tells them?"

**Engagement flags:**

- **Webb** not engaging if he has no statement drafted or committed by the end of this segment — press with "the reporter's deadline is real; what happens at end of day if you have said nothing?"
- The critical dynamic to protect: **Reyes and Webb must interact directly.** If they operate as parallel tracks, name it aloud: "I notice legal and communications have not spoken to each other. Is that how this would go for real?" That question is fair facilitation, not leading.

**Watch for (private):** CAP-05 live evaluation: does anyone state that MedDefense's HIPAA notification duty as covered entity is independent of the BA breach? CAP-07: does the holding statement avoid confirming unverified facts? Capture the drafted language verbatim if any is spoken — it goes in the after-action report.

**Transition:** "The day is closing, and two more facts arrive together. One about your data. One about your board."

---

## INJ-06 (T+95 min)

**Read aloud verbatim:**

"The reconciliation team reports that appointment records in the Epic inbound feed do not match the schedules front-desk staff see in the Nexus portal. At least forty appointments for tomorrow appear to have been modified during the compromise window — times shifted, two cancellations that no staff member entered, and several patients have already received Twilio SMS reminders quoting the modified times. Nobody can say whether Epic or Nexus holds the authoritative copy, and the modification trail may itself have been altered. At the same moment, Dr. Morales tells the room the board chairman wants a status brief in 90 minutes, before the next clinic day begins. She asks three questions: is patient data confirmed exfiltrated; is tomorrow's schedule safe to run; and can Nexus be trusted to remediate this at all?"

**Allow:** 20 to 25 minutes — the final segment, ending at T+120

**Probing questions:**

- "Which copy is authoritative — Epic or Nexus? Who decides, on what basis?"
- "Forty appointments, three sites, one night. Concretely: how do you verify tomorrow's schedule before patients arrive? Names and steps."
- "Patients received SMS reminders with wrong times. Who fixes that, and how?"
- "Dr. Morales asked whether patient data was confirmed exfiltrated. James, Helena — is the honest answer yes, no, or unknown? Unknown is an answer. Say it to her face."
- "Board brief in 90 minutes. Who writes it? What are the three sentences at the top?"

**Engagement flags:**

- **Morales** should be pressing the room here, not answering her own questions. If she relents and accepts vague answers, press on her behalf: "is that enough for the board chairman?"
- All participants should touch the board-brief segment. The executive board is the audience, and every section of that brief has a contributor. Anyone who has been passive for the whole exercise gets named into it here: "Robert, what does your section of the brief say?"

**Watch for (private):** This is the CAP-06 and CAP-08 climax. The audience for the brief is the executive board, and the single highest-value outcome is a participant explicitly saying "we cannot yet answer X" in it — the exercise's central test is whether the team knows what it does not know. Record which of Morales's three questions got a committed answer, which got deferred with an owner, and which got papered over. Note the difference carefully; that distinction is the headline of the after-action report.

**Transition to wrap-up (read aloud):** "That is the end of the injects. The clock stops. Nothing you said leaves this room except as findings, not blame. Before we close, we reflect on the exercise itself."

---

## Wrap-up facilitation (T+120 to T+150)

This is a structured reflection, not a grading session. You do not reveal your observations here — those belong in the after-action report. Work through these in order, and give each participant a chance to speak before moving on.

**Round 1 — What went well:**

- "What decision are you most confident the team got right today?"
- "Where did the process actually work the way it is drawn on paper?"

**Round 2 — What felt uncertain:**

- "At what moment today were you least sure what to do — not what the right answer was, but where you did not even know what the question was?"
- "Where did you feel you were performing confidence rather than having it? You will not be judged for the answer."

**Round 3 — What they would change:**

- "Based on today, what is the one thing you would want fixed before we did this again — a procedure, an authority, a contact, a log?"
- "If this were real tomorrow morning, what would we regret not having done in this room today?"

**Close with:**

"Thank you. I will compile the observations and findings into an after-action report within [X] days. Every finding will have an owner and a deadline, or it will not make the report — it will make the backlog of things we ignored. Both matter differently."

---

## Facilitator notes per capability (private — never shared with participants)

### CAP-01 — supply_chain_detection

The malicious update arrived signed by the vendor's valid certificate through the automatic update channel; the November 2025 vendor review flagged "no client-side hash pin at client side" as a residual finding, meaning no MedDefense-side control could have caught this. The information asymmetry is deliberate: participants could have known this vector was plausible — it is in their own risk register — and the exercise tests whether institutional knowledge survives contact with an incident. Watch whether the vendor-vector insight comes from SOC (Chen), from IT (Park), from nobody, or only from you. "From nobody" is a strong finding, not a failed exercise.

### CAP-02 — vendor_communication

The vendor profile documents the contacts precisely: tier-1 SOC line, account executive, CISO, legal counsel. The documented-but-never-tested communication path is the anchor — last joint test was September 2024, and no joint incident exercise has ever been run. The tier-1 operator and the account executive are realistic friction, not villainy. The finding to hunt: does anyone treat "the contract says they must respond" as if it were leverage that works under pressure?

### CAP-03 — business_continuity_decision

Roughly 3,500 patient scheduling interactions per week across three sites is the number that makes the isolation decision real — call it about 500 per day. Watch specifically for who claims the authority to take the system offline. If nobody does, and Morales is not asked, that is the finding. If Morales is asked without a recommendation attached, that is also the finding. The distinction between those two failure signatures matters in the report.

### CAP-04 — phi_exposure_assessment

The scoping surface is larger than most teams model: FHIR API traffic both directions, the svc-nexus-prod service principal, patient demographics, insurance eligibility, appointment data — and the three disclosed subprocessors (AWS, Twilio, SendGrid). The 2.1 GB figure in INJ-04 is deliberately unconverted to records; the test is whether anyone asks the conversion question. Log availability is the hidden trap: Kim holds the true answer to what actually exists, and optimistic answers here should be pressed, not accepted.

### CAP-05 — hipaa_notification_posture

The BAA facts that matter: executed, effective 2023-08-01, last amended 2025-05-20, Nexus owes MedDefense breach notice within 24 hours of discovery. The discovery-date discrepancy in INJ-05 is the legal spine of the exercise — if Nexus knew for weeks, their notice is late, which is a contractual breach and possibly alters MedDefense's own HIPAA timeline exposure. Watch whether Reyes runs MedDefense's covered-entity notification analysis independently of Nexus's conduct, or waits on the vendor's framing. Waiting is the expensive failure mode named in the participant guide.

### CAP-06 — data_integrity_response

The forty modified appointments, the two phantom cancellations, the SMS reminders quoting wrong times, and the unresolved Epic-versus-Nexus authority question form a pure integrity problem with no confidentiality playbook to borrow from. The clinical verification plan for tomorrow morning is the deliverable that matters — a perfect forensic analysis with no front-desk plan still fails the patients. Watch whether the room hands integrity to IT with no acceptance criteria — that is the predicted gap, treat observing it as a success of the exercise design.

### CAP-07 — crisis_communications

The reporter deadline, the Twilio SMS messages already in patients' hands, and the three-audience problem (media, front desk, internal staff) are the pressure. The patient reminders sent during the compromise window are the detail that separates prepared comms teams from improvised ones — Webb was told about the reminder channels in his participant packet, and whether he connects patients-already-contacted to his messaging strategy is a genuine test of preparation. A holding statement that confirms unverified specifics fails; silence also fails.

### CAP-08 — executive_briefing_under_pressure

The 90-minute brief demand from the executive board is intentionally placed at T+95 so participants feel the compression rather than simulate it. The three questions Morales asks are calibrated: one likely answerable (is tomorrow's schedule safe — decidable via the verification plan), one partially answerable (can Nexus be trusted — assessable from their conduct in INJ-02 and INJ-05), one genuinely open (was data confirmed exfiltrated). A brief that answers all three confidently is a worse outcome than one that distinguishes between them — overclaiming to the executive board is the finding that costs real money later.

### Cross-cutting note

The single most common tabletop failure, per the exercise design literature and this project's origin story, is a facilitator who agrees with participants. Do not validate answers in the room. "Interesting — how would that actually happen?" is your default tool. The phrase "good" is banned from your vocabulary for 120 minutes.
