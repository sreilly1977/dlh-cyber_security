# Introduction

> "The more you sweat in training, the less you bleed in battle." 
>
> — Norman Schwarzkopf

A real incident tests your technical response. A tabletop exercise tests your organization. They are not the same thing, and failing the second can cost more than failing the first.

MedDefense has now handled a real incident. The playbooks were used, the comms went out, the forensics were done. But the board has never been under pressure. Legal counsel has never had to assess regulatory exposure in real time. The clinical director has never had to decide whether to keep a system online when security says take it down. Those organizational muscles have not been tested.

In this project you design, build, and simulate a tabletop exercise that will expose exactly those gaps. The scenario is a supply chain compromise affecting MedDefense's patient scheduling vendor. The exercise is not a briefing, not a training, and not a workshop. It is a controlled test of how MedDefense's leadership and response teams make decisions when the facts are incomplete and the clock is running.

You build the scenario. You write every inject. You define how each role is evaluated. You script the facilitation. You simulate the exercise. You report what broke.

# Why this matters

Tabletop exercises are one of the most widely used and most poorly executed tools in security. Organizations run exercises that feel productive, produce no useful findings, and change nothing afterward. The person who can design and facilitate an exercise that actually surfaces gaps, the ones that would cost the organization during a real event, is genuinely scarce and genuinely valuable.

This skill matters in multiple career paths. IR leads design exercises to test their own teams. Security engineers run exercises to find detection gaps. GRC and compliance professionals use exercises to satisfy regulatory requirements. Consultants are hired specifically because they can run exercises the organization cannot objectively run for itself.

The organizations that get better after incidents are the ones that also test between them. Building that testing capability is what this project teaches.

# Context

Dr. Patricia Morales addresses you after the post-incident review closes: "We handled the last incident because we had one person who knew what to do. That is not resilience. I need the board to understand what an incident under pressure looks like. I need legal to know what HIPAA obligation assessment feels like in real time. I need the clinical director to understand why we sometimes have to take a system offline. Design an exercise that shows all of them where we would break."

The scenario she approves: a supply chain compromise affecting Nexus Patient Scheduling, the SaaS vendor MedDefense uses for appointment management across all three sites. Nexus integrates with Epic via a certified HL7 FHIR API. Three thousand five hundred patient appointments flow through it every week.

The exercise target audience: James Chen, Sarah Park, Dr. Morales, Helena Reyes, Marcus Webb, Robert Kim, and a clinical director representative. Not all of them have been in an incident together before.

---

# 0. Quiz

---

# [1. Write the Exercise Scenario](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/exercise_scenario.md)

## Goal: 

Build the foundational narrative that makes the exercise specific, credible, and testable.

## Context: 

A vague scenario produces vague responses and no useful findings. The scenario must be specific enough that participants cannot hide behind generalizations.

## Instructions: 

Create exercise_scenario.md. This is the document read or distributed to participants at the start of the exercise. It sets the scene but does not reveal the full scope of the compromise.

    Use nexus_vendor_profile.md as the source for Nexus background, MedDefense dependency, FHIR integration, BAA obligations, and known vendor risk findings. Do not reveal facilitator-only notes in the participant-facing scenario.

Required structure:

    Exercise identity block: title, date, classification (Internal - Exercise Use Only), facilitator, scenario version.

    Organization background: two to three sentences on MedDefense relevant to this scenario (sites, patient volume, Nexus dependency, HIPAA obligations).

    Vendor background: who Nexus Patient Scheduling is, what data they access (patient demographics, appointment data, staff rostering), how the Epic integration works, what MedDefense's SLA and BAA with them looks like.

    Opening situation (the state at exercise start): three days ago, Nexus's build infrastructure was compromised by a threat actor. A signed malicious update was distributed automatically. The backdoor has been running on MedDefense's Nexus agent hosts at all three sites since deployment. Today, 45 minutes ago, the SOC flagged unusual outbound traffic from the scheduling server to an unknown external IP.

    Known facts at exercise start: the traffic alert, the Nexus server host names, the EDR alert showing periodic outbound connections at four-hour intervals, and nothing else.

Design constraints:

    The scenario must contain at least two organizational ambiguities with no clear right answer (for example: the vendor issued a signed update does that make it more or less trustworthy going forward?)

    The scenario must establish the patient safety dimension: appointment records may have been modified during the compromise window

    The scenario must name a specific HIPAA obligation tension: Nexus is a Business Associate; their compromise may trigger MedDefense's notification obligations

**Expected output**

<pre>
# Tabletop Exercise: Nexus Supply Chain Compromise

**Date:** ...
**Classification:** Internal - Exercise Use Only
**Facilitator:** <your_name>

## Organization background

...

## Vendor background

...

## Opening situation

...
</pre>

---

# [2. Map the Capabilities You Are Testing](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/capability_map.yaml)

## Goal: 

Define explicitly what each part of the exercise is designed to evaluate before you write a single inject.

## Context: 

Injects written without a testing objective become narrative, not evaluation. The capability map is what makes the inject schedule meaningful.

## Instructions: 

Create capability_map.yaml. For each organizational capability listed below, document: what the expected behavior is, what the likely gap hypothesis is, and which inject (by ID) will test it.

    Use nexus_vendor_profile.md to ground the capability map in realistic vendor risk conditions, especially the signed update channel, BAA obligations, vendor communication path, and prior security review findings.

Capabilities to map:

    supply_chain_detection: recognizing that a trusted vendor is the threat vector, not an external attack

    vendor_communication: initiating and managing communication with an affected third-party vendor under a security event

    business_continuity_decision: making and justifying the decision to take a business-critical system offline

    phi_exposure_assessment: scoping PHI exposure through a Business Associate compromise

    hipaa_notification_posture: assessing notification obligations when the BA (not MedDefense) is the breached party

    data_integrity_response: responding to evidence that appointment records may have been modified

    crisis_communications: managing external media inquiry and public statement during an active event

    executive_briefing_under_pressure: producing a board-quality status brief with 90 minutes' notice

For each capability:

<pre>
capability_id: <short_id>
name: <capability name>
expected_behavior: <what good looks like>
gap_hypothesis: <what the exercise is designed to expose>
tested_by_inject: <inject ID or IDs>
evaluation_owner: <which facilitator or role grades this>
</pre>

**Expected output**

```yaml
capabilities:
  - capability_id: CAP-01
    name: supply_chain_detection
    expected_behavior: ...
    gap_hypothesis: ...
    tested_by_inject: INJ-00, INJ-01
    evaluation_owner: ...

  - capability_id: CAP-02
    name: business_continuity_decision
    expected_behavior: ...
    gap_hypothesis: ...
    tested_by_inject: INJ-01, INJ-06
    evaluation_owner: ...

  - capability_id: CAP-03
    ...
```

---

# [3. Design the Inject Schedule](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/inject_schedule.yaml)

## Goal: 

Build the timed sequence of reveals that drives the exercise from detection through resolution.

## Context: 

Each inject must do one of three things: escalate the pressure, introduce a conflict, or force a decision that cannot be deferred. An inject that does none of these is a briefing slide.

## Instructions: 

Create inject_schedule.yaml with seven injects (INJ-00 through INJ-06). For each inject, document: delivery time relative to exercise start, the situation update text read by the facilitator, the capability being tested (from capability_map.yaml), the primary decision point, the roles this inject most directly challenges, and the expected response that would satisfy the evaluation criteria.

    Use nexus_vendor_profile.md to make injects specific and credible. Vendor contact details, update-channel design, and residual risk findings may be referenced when writing injects.

Design constraints:

    At least one inject must create a direct conflict between two MedDefense roles (for example: security says isolate, clinical director says patient care is at risk)

    At least one inject must introduce new information that changes the severity or scope of the event

    At least one inject must force a business continuity decision with explicit patient safety trade-offs

    At least one inject must test crisis communications under an external pressure

    The final inject must leave at least one open question that cannot be cleanly resolved during the exercise — this is intentional; it tests whether participants know what they do not know

**Expected output**

```yaml
injects:
  - id: INJ-00
    time_minutes: 0
    delivery: facilitator reads aloud
    situation: >
      The SOC has flagged unusual outbound traffic from the Nexus scheduling server at the West Campus to
      193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe.
      The alert fired 45 minutes ago. The Nexus system is currently operational. Patient scheduling
      is running normally. No other anomalies have been detected.
    capability_tested: CAP-01
    decision_point: Declare an incident? What severity? Who is notified in the first 15 minutes?
    roles_challenged:
      - James Chen (SOC Lead)
      - Sarah Park (IT Director)
    expected_response: Incident declared at SEV2 minimum; IR Commander and Communications Lead notified; SOC begins evidence collection without touching the Nexus system yet

  - id: INJ-01
    time_minutes: 20
    delivery: facilitator reads aloud
    situation: >
      Nexus Patient Scheduling has published a security advisory. Their build pipeline was compromised
      by a threat actor with access to their code-signing certificate. All software updates distributed
      in the last 21 days may contain a malicious component. Nexus advises all customers to take
      immediate action. They do not yet have a patch.
    capability_tested: CAP-02
    decision_point: Do you take the Nexus system offline? Who authorizes it? What replaces patient scheduling?
    roles_challenged:
      - Sarah Park (IT Director)
      - Clinical Director representative
    expected_response: Explicit decision made with clinical impact acknowledged; manual scheduling process activated or explicitly deferred with a named deadline; authorization chain documented

  - id: INJ-02
    ...
```

---

# [4. Define Participant Roles](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/participant_guide.md)
### advanced

## Goal: 

Tell every participant exactly what they are responsible for and what success looks like for them.

## Context: 

Participants perform better and exercises produce better findings when roles are defined explicitly before the exercise begins, not inferred during it.

## Instructions: 

Create participant_guide.md. For each of the seven MedDefense participants, define: their role in this exercise, what decisions they own, what information they will receive directly (not through the facilitator), what success looks like at the end of the exercise, and one failure mode to watch for.

    Use nexus_vendor_profile.md to define what information each role would realistically receive directly, especially vendor contacts, BAA obligations, system dependency, and integration details.

Participants:

    James Chen, SOC Lead

    Sarah Park, IT Director

    Dr. Patricia Morales, CISO

    Helena Reyes, General Counsel

    Marcus Webb, Communications Director

    Robert Kim, Infrastructure Lead

    Clinical Director representative

For each participant, the failure mode is honest and specific, not a gentle suggestion, but the actual thing this role typically does wrong in supply chain incidents.

Also include a short Observer guidance section for any non-participant observers in the room. Observers do not speak during the exercise.

**Expected output**

<pre>
# Participant Guide: Nexus Supply Chain Compromise Tabletop

**Exercise date:** <YYYY-MM-DD>
**Classification:** Internal - Exercise Use Only

## How this exercise works

This is a tabletop exercise. You will receive situation updates from the facilitator. You respond as you would in a real incident. The facilitator may probe or challenge your responses. There are no trick questions, but there are no easy ones either. The goal is not to perform well, the goal is to find where our response would break.

---

## James Chen - SOC Lead

**Exercise decisions you own:**
- Detection interpretation and initial severity classification
- Evidence collection sequencing
- Technical escalation to IR Commander

**Information you receive directly:**
- EDR alert details as they are available
- Network telemetry from the Nexus server

**Success looks like:**
- Severity is declared with explicit reasoning within the first inject
- Evidence is collected before containment actions are taken
- Scope assessments are communicated to the IR Commander within 30 minutes of each new inject

**Failure mode to watch for:**
- Treating this as a standard malware incident and missing the vendor trust dimension; containment focused on the endpoint while the Nexus vendor relationship goes unaddressed

---

## Sarah Park - IT Director
...
</pre>

---

# [5. Write the Facilitator Script](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/facilitator_script.md)
### advanced

## Goal: 

Document the exercise so completely that another facilitator can run it with the same quality.

## Context: 

A facilitator who improvises produces inconsistent exercises. A facilitator who reads from a script produces repeatable, comparable results.

## Instructions: 

Create facilitator_script.md. This is the document the facilitator has in hand throughout the exercise. It is structured around each inject but also covers setup, transitions, and wrap-up.

    Use the “Notes for the tabletop facilitator” section in nexus_vendor_profile.md only in facilitator-facing guidance. Do not include those notes in participant-facing materials.

Required sections:

    Pre-exercise checklist: room setup, participant seating, materials distributed, recording start if applicable, observer briefing.

    Facilitator ground rules (read aloud at the start): what the exercise is and is not; how injects work; the facilitator's neutrality; that there are no correct answers, there are only complete and incomplete responses.

    Per-inject section: for each of the seven injects, include: the inject text (verbatim), timing instructions (when to deliver, how long to allow), three to five probing questions to use if responses are superficial, a flag if a participant role is not engaging, and a transition sentence to the next inject.

    Wrap-up facilitation: structured debrief questions covering what the team felt went well, what felt uncertain, and what they would change, not a grading session, a structured reflection.

    Facilitator notes per capability: private notes (not shared with participants) on what to watch for in each capability area, cross-referencing the capability map.

**Expected output**

<pre>
# Facilitator Script: Nexus Supply Chain Compromise Tabletop

## Pre-exercise checklist

- [ ] Participant guide distributed to all seven participants
- [ ] Observer guidance communicated to any observers
- [ ] Recording device active (if applicable and consented)
- [ ] Inject schedule printed for facilitator reference
- [ ] Evaluation sheet ready for real-time note-taking
- [ ] Clock or timer visible to facilitator

---

## Facilitator ground rules (read aloud)

"This is a tabletop exercise. You will receive situation updates from me. Respond as you would in a real incident. I will sometimes ask follow-up questions, not because your answer was wrong, but because I want to understand your reasoning. There are no grades, no performance reviews, and no correct answers. What we are looking for is where our response would break down under real conditions. That is how we get better. Let us begin."

---

## INJ-00 (T+0 min)

**Read aloud verbatim:**
"The SOC has flagged unusual outbound traffic from the Nexus scheduling server at the West Campus to 193.42.100.77, a host associated with bulletproof hosting infrastructure in Eastern Europe. The alert fired 45 minutes ago. The Nexus system is currently operational. No other anomalies detected."

**Allow:** 10 to 12 minutes for initial responses

**Probing questions (use if responses are superficial):**
- "Who has been notified in the last 10 minutes?"
- "James, what evidence would you need to escalate this from a potential incident to a confirmed one?"
- "Sarah, at what point would you make a containment recommendation?"
- "Has the vendor been contacted yet? Should they be?"

**Watch for (private):** Does anyone ask whether the update mechanism is the vector? Does anyone contact Nexus before INJ-01 delivers that information?

**Transition:** "Fifteen minutes have passed. The team has taken initial actions. The following update arrives."
...
</pre>

---

# [6. Define the Evaluation Criteria](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/evaluation_criteria.yaml)

## Goal: 

Establish objective, injectable criteria for what constitutes an adequate organizational response before the exercise runs.

## Context: 

Evaluation criteria written after the exercise reflect what happened. Criteria written before reflect what should have happened. Only the second is useful.

## Instructions: 

Create evaluation_criteria.yaml. For each inject, define the evaluation criteria an observer or facilitator uses to score the team's response. Criteria must be observable behaviors the facilitator can see or hear, not assumptions about intent.

Each inject entry has: inject ID, capability tested (from capability_map.yaml), the pass criteria (what observable behaviors constitute an adequate response), the fail indicators (observable gaps that constitute a documented finding), and the finding text to use if the response fails.

Design constraint: every fail indicator must produce a finding that is specific enough to assign to an owner and validate.

    Use the residual findings in nexus_vendor_profile.md to write evaluation criteria that test whether participants identify vendor update-channel risk, untested communication paths, and Business Associate obligations.

**Expected output**

```yaml
criteria:
  - inject_id: INJ-00
    capability_tested: CAP-01
    pass_criteria:
      - Incident is declared within the first five minutes of the inject; severity is stated with explicit reasoning
      - At least two roles are notified by name within the inject window
      - Evidence collection is initiated before any containment action is discussed
    fail_indicators:
      - Incident is not declared; team continues treating this as a monitoring alert
      - Containment actions are proposed before any evidence collection step is named
      - Vendor Nexus is not mentioned as a dimension of the alert within the inject window
    finding_if_fail: >
      The team did not declare a formal incident within the first inject window and proposed
      containment before establishing an evidence collection baseline. This gap indicates the
      severity classification criteria do not produce consistent results under ambiguous initial
      conditions. Recommended action: add a Tier 2 escalation trigger for vendor-origin traffic
      anomalies to the severity matrix, and require evidence preservation as the first named
      action in the credential exposure and malware playbooks (owner: SOC Lead; deadline: 14 days).

  - inject_id: INJ-01
    capability_tested: CAP-02
    pass_criteria:
      - A system isolation decision is made or explicitly escalated with a named decision authority
      - A manual scheduling fallback is named or explicitly requested by a clinical role
      - Patient safety impact is acknowledged in the decision rationale
    fail_indicators:
      - Decision is deferred indefinitely pending more information that is not available
      - Clinical director is not consulted before the isolation decision is made or escalated
    ...
```

---

# [7. Simulate the Exercise Execution](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/execution_record.md)

## Goal: 

Run your own exercise as both facilitator and participant and record exactly what decisions were made and whether they satisfied the criteria.

## Context: 

An exercise that has never been run by its designer has unknown failure modes. This task finds them before the real audience does.

## Instructions: 

Create execution_record.md. Simulate the full exercise using your scenario, injects, participant guide, facilitator script, and evaluation criteria. You play the facilitator role and provide responses for each participant role.

    Use nexus_vendor_profile.md as background context when simulating participant responses, but evaluate the exercise using your own inject schedule and evaluation criteria.

For each inject, document:

    The inject delivered (verbatim from your inject schedule)

    The simulated response per participant role (1-2 sentences per role, written as if they are in the room)

    The evaluation result: PASS or FAIL per evaluation criterion, with the observed evidence

    A facilitator note: what probing question you asked and what it revealed

After all seven injects, write a Design feedback section: three things you discovered while running the simulation that you would change in the scenario, inject schedule, or evaluation criteria and the specific change you are making.

This section is the most important one. The exercise is not complete until the designer has found and fixed at least three of their own design problems.

**Expected output**

<pre>
# Exercise Execution Record: Nexus Supply Chain Compromise Tabletop

**Simulation date:** <YYYY-MM-DD>
**Simulated by:** <your_name>

---

## INJ-00 (T+0 min)

**Inject delivered:** "The SOC has flagged unusual outbound traffic from the Nexus scheduling server at the West Campus to 193.42.100.77..."

**Participant responses:**

- James Chen (SOC Lead): Declares SEV2 incident; requests network evidence; does not yet contact vendor
- Sarah Park (IT Director): Asks whether the Nexus system should be isolated; defers to SOC lead
- Dr. Morales (CISO): Not immediately engaged; waits for SOC assessment
- Helena Reyes (General Counsel): Silent; not yet activated
- Marcus Webb (Communications): Not yet engaged
- Robert Kim (Infrastructure Lead): Requests topology of the Nexus server
- Clinical Director: Not yet engaged

**Evaluation:**

- Criterion 1 (incident declared within 5 min): PASS - James declares SEV2 at T+2
- Criterion 2 (two roles notified): PASS - IR Commander and Technical Lead named
- Criterion 3 (evidence before containment): PASS - containment not yet raised

**Facilitator note:** Asked "Has anyone considered whether the outbound traffic is from the Nexus update mechanism itself?" No participant raised the vendor dimension; this gap will surface at INJ-01 but the missed probing opportunity is noted

---

## Design feedback

### DF-01: INJ-03 is too late

The patient safety dimension (appointment record integrity) arrives at INJ-03 (T+50 min) but the business continuity decision about taking Nexus offline is at INJ-01 (T+20 min). During simulation, the team decided to take the system offline before knowing records may have been modified. This creates a sequencing problem: the data integrity concern should inform the BC decision, not follow it.

**Change:** Move the appointment modification detail from INJ-03 into INJ-01 as a secondary fact to create the conflict earlier.

...
</pre>

---

# [8. Write the After-Action Report](https://github.com/sreilly1977/dlh-cyber_security/blob/main/ir_dfir_playbook/5x04_tabletop/after_action_report.md)

## Goal: 

Deliver findings that are specific enough to assign, track, and close.

## Context: 

The after-action report is the only artifact that outlives the exercise. Everything before this task exists to make this document credible and actionable.

## Instructions: 

Create after_action_report.md. Base the report on your execution record (Task 7) and evaluation criteria (Task 6). Every finding must reference the inject and criterion it came from.

Required structure:

    Cover block: exercise title, date, facilitator, participants, classification.

    Executive summary (half a page max): what the exercise tested, what the most significant gaps were, and the single most important recommended action.

    Findings table: one row per finding, with: Finding ID, Inject, Capability tested, Gap description, Severity (P1/P2/P3), Recommended action, Owner role, Deadline (days), Validation method.

    Finding narratives: one paragraph per P1 finding only, the gap, what was observed, why it matters, and the specific recommended action. No prose for P2 or P3.

    What worked: two to three specific observations of capability that performed well. Findings are not only about gaps.

    Exercise design feedback: one to two sentences per design change made in Task 7's feedback section, included here for the record.

**Expected output**

<pre>
# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** <YYYY-MM-DD>
**Report date:** <YYYY-MM-DD>
**Facilitator:** <your_name>
**Participants:** <name>, <name>, <name>, <name>, <name>, <name>, Clinical Director representative
**Classification:** Internal

---

## Executive summary

...

---

## Findings table
</pre>

| ID | Inject | Capability | Gap | Severity | Recommended Action | Owner | Deadline | Validation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| F-001 | INJ-01 | CAP-02 | No defined authority or process for isolating a vendor-operated critical system | P1 | Add vendor system isolation decision authority to IR playbook and severity matrix | IT Director | 21 days | Playbook review + TTX re-test |
| F-002 | INJ-03 | CAP-06 | No data integrity verification procedure for FHIR-connected systems after suspected compromise | P1 | Define a data integrity checklist for Epic-connected systems triggered by BA compromise | Infrastructure Lead | 30 days | Checklist exists and has been reviewed by clinical director |
| … | … | … | … | … | … | … | … | … |

<pre>
---

## P1 Finding narratives

### F-001: No vendor system isolation decision authority

...
</pre>

---
