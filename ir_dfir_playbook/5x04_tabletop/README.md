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
