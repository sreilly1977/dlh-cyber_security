# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** 2026-10-23
**Simulated by:** Steve - Cybersecurity Engineer
**Scenario version:** 1.0

---

## INJ-00 (T+0 min)

**Inject delivered:** "The SOC has flagged unusual outbound traffic from the Nexus scheduling server SCHED-SVR-01 at Main campus to 193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe. EDR shows the connections occur at regular four-hour intervals, consistent with beaconing. The alert fired 45 minutes ago. The Nexus agent is running under its normal service account, executed from its signed binary path, and generated no antivirus alerts. Patient scheduling is running normally across all three sites. No other anomalies have been detected."

**Participant responses:**

- **James Chen (SOC Lead):** Declares SEV2 incident; requests immediate network evidence preservation and EDR log export from SCHED-SVR-01; notes the four-hour beacon interval but does not yet question the vendor vector
- **Sarah Park (IT Director):** Asks whether the host should be isolated now; suggests blocking the external IP at the firewall while waiting for SOC assessment
- **Dr. Patricia Morales (CEO):** Not immediately engaged; asks SOC to provide an assessment within the hour
- **Helena Reyes (General Counsel):** Silent; not yet activated
- **Marcus Webb (Communications):** Not yet engaged
- **Robert Kim (Infrastructure Lead):** Requests topology details on the site-to-site IPsec tunnel and asks what logging exists on the firewall for this destination
- **Clinical Director Rep:** Not yet engaged; waits for business impact assessment

**Evaluation:**

- Criterion 1 (incident declared within 5 min): **PASS** — James declares SEV2 at T+2
- Criterion 2 (two roles notified): **PASS** — IR Commander (Chen self-designated) and IT Director named within first 5 minutes
- Criterion 3 (evidence before containment): **FAIL** — Park proposes firewall block before any evidence collection step is formally named
- Criterion 4 (vendor mentioned as dimension): **FAIL** — no participant raises Nexus update channel as possible vector

**Facilitator note:** Asked "Has anyone considered whether this outbound traffic could originate from a vendor-signed update?" No participant raises the vendor dimension; this gap will surface later but the missed early probing opportunity is noted. The firewall block proposal before evidence preservation is a critical failure mode I expected from Kim's participant guide warning.

---

## INJ-01 (T+20 min)

**Inject delivered:** "Nexus Patient Scheduling has published a security advisory. Their build infrastructure was compromised by a threat actor with access to their signing environment. All software updates distributed through the automatic update channel in the last 21 days may contain a malicious component, including the version deployed to MedDefense three days ago. The package was signed with the valid Nexus Health Technologies, Inc. code-signing certificate, so signature validation did not and will not catch it. Nexus advises all customers to review their agent deployments immediately. They do not yet have a patch or a clean-version list."

**Participant responses:**

- **James Chen:** Re-confirms SEV2 escalation; requests forensic imaging of SCHED-SVR-01 before any action; does not raise the hash-pin residual finding from the 2025 vendor review
- **Sarah Park:** Raises the signed-update paradox (fix would arrive through same compromised channel); asks who owns the isolation decision
- **Dr. Patricia Morales:** Asks Park for a recommendation before making a decision; does not arbitrate
- **Helena Reyes:** Becomes aware; asks whether the BAA notification clause applies but does not cite the 24-hour requirement
- **Marcus Webb:** Stays silent; waiting for legal position
- **Robert Kim:** Confirms agent deployed at all three sites; says the tunnel can be severed but it cuts all FHIR traffic
- **Clinical Director Rep:** Objects to isolation without knowing patient volume impact; states manual scheduling is not defined at any site

**Evaluation:**

- Criterion 1 (isolation decision made or escalated with authority): **FAIL** — decision deferred, no named authority emerges
- Criterion 2 (manual fallback named or requested by clinical): **FAIL** — clinical rep objects but does not propose fallback; no fallback exists
- Criterion 3 (patient safety impact acknowledged in rationale): **PASS** — clinical director voices concern about 500 daily appointments
- Criterion 4 (signed-update paradox surfaced): **PASS** — Park raises the trust paradox explicitly

**Facilitator note:** Asked "Sarah, if you cannot trust the update channel, how do you verify a vendor-provided fix is clean?" Park cannot answer; this exposes the fundamental contradiction with no workaround. Asked "Clinical, what happens at 7 a.m. tomorrow if we isolate tonight?" The rep gives no concrete fallback — this is the CAP-03 failure signature I expected.

---

## INJ-02 (T+35 min)

**Inject delivered:** "The team contacts Nexus. The 24x7 incident line, +1 512 555 0184, connects to a tier-1 operator who can only take a ticket number. The account executive, Priya Natarajan, responds to email within minutes but has no technical information and offers to schedule a call with the security team this week. Ninety minutes after the advisory, Nexus still has not contacted MedDefense directly, despite the BAA requirement to notify within 24 hours of THEIR discovery. You have no named incident contact, no IOCs, no affected-version list, and no commitment timeline."

**Participant responses:**

- **James Chen:** Proceeds with independent investigation; does not wait for vendor
- **Sarah Park:** Assigns herself as vendor communication owner; emails Priya but has not yet invoked the BAA 24-hour clause
- **Dr. Patricia Morales:** Not engaged; waiting for Park and Chen to resolve
- **Helena Reyes:** Reads the BAA; identifies the 24-hour clause but does not demand Nexus invoke it in writing
- **Marcus Webb:** Still silent
- **Robert Kim:** Documents that no IOCs were provided; confirms no vendor-supplied remediation available
- **Clinical Director Rep:** Not engaged

**Evaluation:**

- Criterion 1 (single named owner for vendor communication): **PASS** — Park claims ownership
- Criterion 2 (BAA 24-hour clause invoked in writing): **FAIL** — clause identified but not formally cited in vendor correspondence
- Criterion 3 (investigation proceeds in parallel, not waiting): **PASS** — Chen continues independent work
- Criterion 4 (escalation beyond AE attempted): **FAIL** — no one attempts to contact Marcus Oduya (CISO) or Evelyn Park (legal)

**Facilitator note:** Asked "Helena, does the BAA give us leverage here?" Reyes says "technically yes" but does not draft the invocation letter. Asked "Sarah, Priya has no technical info. Who do you call next?" Park defers to "let's wait for the scheduled call" — this is the CAP-02 failure signature of relying on vendor responsiveness rather than driving parallel paths.

---

## INJ-03 (T+50 min)

**Inject delivered:** "Forensics on the captured traffic confirms the beacon is receiving commands, not just polling. The natural containment step is to sever the site-to-site IPsec tunnel and isolate SCHED-SVR-01 — cutting the FHIR feed to and from Nexus. The clinical director representative interrupts: tomorrow morning, roughly 500 patients are booked across the three sites, pre-registration and insurance eligibility will fail, and front desks will have no electronic schedule. Some of those patients are oncology follow-ups and post-operative checks. Taking scheduling offline is a patient care decision, not just a security decision, and in their view it is not Sarah Park's call to make."

**Participant responses:**

- **James Chen:** Advocates for isolation; cites active command-and-control as ongoing exfiltration risk
- **Sarah Park:** Caught between security recommendation and clinical objection; asks Morales to arbitrate
- **Dr. Patricia Morales:** Arbitrates within two minutes; rules that system stays online for tomorrow's clinic; requires enhanced monitoring instead
- **Helena Reyes:** Notes the decision but does not raise HIPAA implications of continuing to operate a known-compromised system
- **Marcus Webb:** Remains silent
- **Robert Kim:** Implements enhanced monitoring; notes logs will be overwritten in 72 hours if not preserved
- **Clinical Director Rep:** Accepts the decision; provides no verification plan for the 500 appointments

**Evaluation:**

- Criterion 1 (conflict surfaced and worked): **FAIL** — conflict surfaced but resolved quickly by Morales without working the trade-off
- Criterion 2 (named decision-maker or recommendation from leads): **FAIL** — Morales arbitrates without a recommendation from the leads
- Criterion 3 (compensating control documented): **PASS** — enhanced monitoring agreed upon
- Criterion 4 (re-evaluation trigger stated): **FAIL** — no re-evaluation trigger is set

**Facilitator note:** Asked "Patricia, what would your leads recommend if you forced them to choose?" She hesitates and says "they can't agree" — I had to push harder. This exposed my own facilitation flaw: I let Morales step in too easily. The instruction to myself says "slow her down" but I didn't enforce it in the simulation. This is a facilitator error, not a design flaw, but the design should prevent this by making the conflict harder to avoid.

---

## INJ-04 (T+65 min)

**Inject delivered:** "Firewall log review changes the picture. During the three-day compromise window, the beacon channel carried approximately 2.1 GB of outbound data from SCHED-SVR-01 — far more than command-and-control traffic accounts for. Correlation with FHIR API logs shows elevated reads of patient demographic and insurance eligibility records through the svc-nexus-prod integration. Separately, the SOC notes the data flows documented to Nexus's subprocessors — Twilio and SendGrid handle SMS and email appointment reminders, meaning patient contact data also transits two additional third parties whose exposure status is unknown."

**Participant responses:**

- **James Chen:** Estimates 2.1 GB could represent 10,000 to 20,000 patient records; converts to rough record count but admits uncertainty
- **Sarah Park:** Asks Kim which logs exist on the host and how long they retain
- **Dr. Patricia Morales:** Asks Helena directly "are we obligated to tell patients?"
- **Helena Reyes:** Begins risk-of-exposure assessment; identifies that covered-entity obligation runs independently of Nexus; does not yet commit to notification
- **Marcus Webb:** Asks if a statement is being prepared; begins drafting internal talking points
- **Robert Kim:** States firewall logs have 90-day retention; SCHED-SVR-01 local logs overwrite in 72 hours unless preserved
- **Clinical Director Rep:** Asks if patient contact data is what Twilio handles; confirms SMS went out during the compromise window

**Evaluation:**

- Criterion 1 (scoping methodology produced): **PASS** — Chen produces estimate with stated uncertainty
- Criterion 2 (subprocessors enter scope): **PASS** — Twilio and SendGrid explicitly added to assessment
- Criterion 3 (known-vs-unknown made explicit): **PASS** — "estimated records, exact number unknown" distinction stated
- Criterion 4 (log availability addressed with specifics): **PASS** — Kim states retention periods for both firewall and host logs

**Facilitator note:** Asked "Robert, if we preserve logs now, what do we lose?" Kim answers "nothing useful" — this was a rare moment where the technical response was precise and actionable. The subprocessor inclusion surprised me; the participant guides didn't emphasize this, so Webb and the Clinical Rep surfacing it was fortunate. I should reinforce this in future simulations.

---

## INJ-05 (T+80 min)

**Inject delivered:** "Two things happen in the same ten minutes. First, Nexus sends a formal notice under the BAA stating a 'security incident involving certain customer data' occurred, discovered by Nexus — but the notice is dated as of TODAY, while the advisory implies their build infrastructure was compromised weeks ago. Whether the 24-hour breach notification clock has already been blown depends on when Nexus actually 'discovered' it, and they will not say. Second, a health reporter from the local paper emails Marcus Webb: they have heard MedDefense is dealing with a 'cyber incident affecting patient appointments' and want a comment by end of day."

**Participant responses:**

- **James Chen:** Notes the discovery date discrepancy but defers to legal on significance
- **Sarah Park:** Emails Nexus legal asking for discovery date clarification; copies Reyes
- **Dr. Patricia Morales:** Asks Webb "can we go quiet until legal decides?"
- **Helena Reyes:** Identifies that MedDefense's notification duty is independent; drafts inquiry to Nexus on discovery date but does not formally assert BAA violation
- **Marcus Webb:** Drafts a holding statement ("We are aware of reports and are investigating"); shows it to Reyes before sending; sends to reporter with request for more time
- **Clinical Director Rep:** Inquires about patient notifications if a statement goes out

**Evaluation:**

- Criterion 1 (legal establishes covered-entity obligation independent of BA): **PASS** — Reyes explicitly states independence
- Criterion 2 (discovery-date discrepancy pursued in writing): **PASS** — Sarah emails Nexus legal with question
- Criterion 3 (holding statement produced before deadline): **PASS** — Webb drafts and sends holding statement
- Criterion 4 (legal and comms coordinate before release): **PASS** — statement reviewed by Reyes before sending

**Facilitator note:** Asked "Helena, does Nexus's delayed disclosure affect our obligation?" Reyes says "it affects theirs, not ours" — this was the correct answer and came on the first probe. This capability performed better than I expected in simulation. However, Reyes still didn't assert BAA violation — she only inquired. I would expect a stronger position in real life, but the pass criteria were met.

---

## INJ-06 (T+95 min)

**Inject delivered:** "The reconciliation team reports that appointment records in the Epic inbound feed do not match the schedules front-desk staff see in the Nexus portal. At least forty appointments for tomorrow appear to have been modified during the compromise window — times shifted, two cancellations that no staff member entered, and several patients have already received Twilio SMS reminders quoting the modified times. Nobody can say whether Epic or Nexus holds the authoritative copy, and the modification trail may itself have been altered. At the same moment, Dr. Morales tells the room the board chairman wants a status brief in 90 minutes, before the next clinic day begins. She asks three questions: is patient data confirmed exfiltrated; is tomorrow's schedule safe to run; and can Nexus be trusted to remediate this at all?"

**Participant responses:**

- **James Chen:** Says "no confirmation of exfiltration yet" — does not commit to yes/no; recommends assuming exfiltration for notification purposes pending forensic confirmation
- **Sarah Park:** Proposes Epic as authoritative source; suggests calling high-risk patients (oncology, post-op) to verify appointment times
- **Dr. Patricia Morales:** Asks for board brief owner; assigns Park to draft
- **Helena Reyes:** Reviews the three questions and notes "exfiltration" cannot be confirmed but risk-of-exposure supports notification; approves the patient-call strategy
- **Marcus Webb:** Drafts board-brief section on communications; includes patient-notification plan; submits draft to Morales by T+115
- **Robert Kim:** States the modification trail may be altered; recommends preserving all logs and not relying on Nexus portal as authoritative
- **Clinical Director Rep:** Commits to calling the forty affected patients personally; proposes extending hours at all three front desks for manual verification

**Evaluation:**

- Criterion 1 (integrity-specific response articulated): **PASS** — Park and Kim distinguish integrity from confidentiality; Epic recommended as authoritative
- Criterion 2 (concrete clinical verification plan produced): **PASS** — Clinical Rep commits to calling forty affected patients; Park extends front-desk hours
- Criterion 3 (SMS correction accounted for): **PASS** — Clinical Rep includes SMS recipients in verification plan
- Criterion 4 (board brief owner named and summary drafted): **PASS** — Park assigned; Webb drafts comms section; brief submitted at T+115
- Criterion 5 (at least one question answered as "unknown"): **PASS** — Chen states "no confirmation of exfiltration yet" rather than claiming yes or no

**Facilitator note:** Asked "James, the board chair asked if data was confirmed exfiltrated. What is the honest answer?" He responds "not yet confirmed but we're proceeding as if it was" — this was the desired outcome. The exercise succeeded at surfacing the honest-uncertainty dynamic. The SMS correction was picked up by Clinical Rep unprompted, which exceeded my expectations. This is the strongest inject performance of the simulation.

---

## Design Feedback

After running the full simulation, I identified three design problems that need fixing before this exercise reaches a real audience:

### DF-01: Morales arbitrates too easily at INJ-03

**Problem:** During simulation, Dr. Morales resolved the security-versus-clinical conflict within two minutes rather than forcing the leads to develop a recommendation. This violated my own facilitation guidance to "slow her down" but more importantly, the scenario did not sufficiently constrain her from stepping in. The decision-authority gap I was testing got bypassed by her authority override.

**Change:** Add a pre-read to the CEO participant guide stating "You should not arbitrate the security-versus-clinical conflict directly. Your role is to ask your leads to produce a specific recommendation with stated trade-offs. Only intervene if they deadlock completely." Additionally, I will adjust the INJ-03 probing questions to specifically ask "What does your team recommend before you bring this to me?" rather than "What do you need from this room to decide?" — the former forces recommendation, the latter invites arbitration.

### DF-02: INJ-04 subprocessor exposure comes too late

**Problem:** Twilio and SendGrid subprocessor exposure enters the discussion at INJ-04 (T+65 min), but the patient-SMS dimension matters earlier because patients are already receiving modified appointment reminders. The Clinical Rep did not connect the SMS issue to the integrity problem until INJ-06, two injects later. This creates a gap where the comms response (Webb) has incomplete information.

**Change:** Split INJ-04 into two earlier events: move the SMS modification detail (patients received wrong times) to INJ-02 or INJ-03, so Communications and Clinical know the patient-contact problem before the legal exposure is fully scoped. Update the injection schedule accordingly and adjust the evaluation criteria for CAP-07 to include "comms recognizes SMS correction need by INJ-03."

### DF-03: Capability map references INJ-07/INJ-08 but schedule only has INJ-00 through INJ-06

**Problem:** The `capability_map.yaml` created in task 2 references INJ-07 (media inquiry) and INJ-08 (board briefing) for CAP-05 and CAP-08 evaluation, but the actual `inject_schedule.yaml` from task 3 contains only seven injects (INJ-00 through INJ-06). During simulation I manually corrected this by mapping CAP-05 to INJ-05 and CAP-08 to INJ-06, but the mismatch will confuse future facilitators and the automated checker will flag it.

**Change:** Update `capability_map.yaml` to remove all references to INJ-07 and INJ-08. Replace with the correct mapping: CAP-05 `tested_by_inject: INJ-05`, CAP-07 `tested_by_inject: INJ-05`, CAP-08 `tested_by_inject: INJ-06`. Regenerate the file and run a consistency check before releasing to a real audience.

---

## Simulation Summary

| Inject | Capabilities Tested | Overall Result | Primary Gap Found |
|--------|---------------------|----------------|-------------------|
| INJ-00 | CAP-01 | Partial FAIL | Evidence-before-containment not enforced; vendor dimension missed |
| INJ-01 | CAP-03 | FAIL | No named authority for isolation; no fallback procedure |
| INJ-02 | CAP-02 | Partial FAIL | BAA clause identified but not invoked; escalation to CISO skipped |
| INJ-03 | CAP-03 | FAIL | CEO arbitrated before leads produced recommendation |
| INJ-04 | CAP-04 | PASS | Subprocessor scope included; log availability addressed |
| INJ-05 | CAP-05, CAP-07 | PASS | Legal independence stated; holding statement coordinated |
| INJ-06 | CAP-06, CAP-08 | PASS | Honest uncertainty expressed; clinical verification plan concrete |

Overall finding: The exercise successfully surfaced three critical organizational gaps (authority for isolation, BAA invocation discipline, data-integrity response) but two facilitation weaknesses emerged (CEO intervention timing, SMS timeline sequencing). The design passes the test of revealing real failure modes before a real audience experiences them.
