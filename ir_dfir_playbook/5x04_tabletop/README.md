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
