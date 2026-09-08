# Introduction

> "The art of SOC is not detecting everything. It is knowing which detections matter right now." 
> 
> - Anton Chuvakin, former Gartner VP Research

Your rules shipped on Friday. The detection catalog is live. The runner fired them against the evaluation window overnight and produced an alert queue that was sitting on your workstation when you walked in this morning. Every alert in that queue came from detections you wrote yourself. Every alert has a priority score that came from the risk register. Every alert points back at a specific event in the normalized dataset you built in 3x00. The pipeline is complete. The only thing still missing is the analyst.

That is what changes today. You stop being the person who wrote the rules and become the person who works the queue. For the next shift you process every alert in alert_queue.json, top to bottom, one by one, and you make a decision on each: true positive, false positive, or benign. Every decision gets a written justification. Every true positive gets escalated into an incident assembly with timeline, IOCs, affected assets, and a recommended containment action. Every false positive gets aggregated into a tuning recommendation that James Chen can hand to the detection engineer on Monday. Every classification goes into a structured ticket. Nothing leaves the queue without a paper trail.

You do not have a SIEM dashboard today. You have five flat JSON files: the alert queue from 3x02, the asset inventory from 3x00, the baseline summary from 3x01, the enriched events that every alert references, and an IOC context file that Robert Kim dropped in ~/3x03_assets/ with reputation data for every external IP your detections touched overnight. Your tools are jq, python3, and a set of triage scripts you write against those files. This is intentional. A Tier 1 analyst who only knows how to click through a dashboard gets stuck the moment the dashboard is down or the moment the investigation needs a field the dashboard does not surface. An analyst who can triage from a flat export will never be stuck.

The shift output is a single triage_package/ directory. Tier 2 reads it tomorrow. Compliance audits it next quarter. The detection engineering team uses it next week to tune the catalog. If your package is clean, the whole downstream response works. If it is sloppy, something real will slip through and you will hear about it.

## Why this matters

The Tier 1 SOC analyst job is not to detect threats. The detection engine does that. The Tier 1 analyst job is to separate signal from noise under pressure with incomplete information against the clock, and to do it consistently enough that the SOC's metrics stay healthy week after week. Alert triage is the highest-volume skill in defensive security. A Tier 1 analyst processes between one hundred and five hundred alerts per shift. The industry average false positive rate sits around forty-five percent. That means roughly half of everything the pipeline flags is wrong on the day you look at it, and the hard part is telling which half. The same brute force pattern can be an attacker or a backup service. The same off-hours login can be a compromised credential or an on-call rotation. Context decides. Process decides. Documentation decides.

Three numbers define a SOC's operational health: MTTD (mean time to detect), MTTR (mean time to respond), and false positive rate. Triage quality drives all three directly. Faster triage reduces MTTD and MTTR. Better false positive identification drives rule tuning that brings the FP rate down. Every SOC manager on the planet tracks these three numbers. Every Tier 1 analyst is measured by them. Every Tier 2 interview starts with "walk me through how you triaged a hard alert". This project gives you one shift worth of alerts to walk through, in writing, in a form that you can replay on any future interview whiteboard.

## Context

You are currently working as a SOC Tier 1 Analyst for MedDefense Health Systems.
The Scenario: "Your First Shift"

---

**FROM:** James Chen, SOC Lead - MedDefense Health Systems

**TO:** SOC Tier 1 Analyst (You)

**SUBJECT:** First analyst shift. Queue is populated. Go.

**PRIORITY:** Normal

Morning. Welcome to your first shift as a Tier 1 analyst at MedDefense. Until today you have been the detection engineer. Starting now you work the queue your own rules produced. This is deliberate. I want you to see what your detection catalog actually feels like on the other side of the SLA.

Your queue is at ~/3x02_package/detection_catalog/alerts/alert_queue.json. The runner fired every rule in the catalog against the evaluation window overnight. The queue is populated and waiting. It is not a small queue. It is not a huge queue either. It is realistic for a small hospital SOC on a quiet Tuesday and it has every class of alert you will see in production: a handful of clear true positives that need to be escalated fast, a larger batch of clear false positives that need to be closed with justification, a middle block of ambiguous alerts where the classification depends on context you have to go fetch, and a pocket of correlation cases where two or three alerts describe the same underlying incident and must be grouped before you act on any of them.

You work against five flat files, not a dashboard:

    alert_queue.json from 3x02 is the queue itself

    asset_inventory.json from 3x00 tells you which host each alert hit and how critical that host is

    baseline_summary.json from 3x01 tells you what normal looks like when you need to compare an observed pattern against a baseline

    enriched_events.json from 3x00 is the event store the alerts reference. When you need to see what actually happened, the event is in there

    ioc_context.json sits in ~/3x03_assets/ and was produced by Robert Kim's threat intelligence integration overnight. It contains reputation, geolocation, and threat-feed category tags for every external IP and domain your detections touched

I want three things out of this shift.

First, I want every alert triaged, classified, and documented in a structured ticket. No free-form notes. No "looks fine" and close. Classification plus justification plus referenced evidence, for every single alert.

Second, I want a clean escalation package for every true positive you surface. Each escalation becomes an incident record with a timeline, affected assets, extracted IOCs, ATT&CK technique mapping from the source rule, and your recommended first containment action. Tier 2 picks up tomorrow and should not have to redo any of your work.

Third, I want a shift report and a triage_package/ directory that I can hand to Dr. Morales on Monday as the concrete output of the MedDefense SOC's first analyst shift. Compliance will audit the directory later this quarter. If the audit cannot reconstruct what happened from your package, the package is wrong.

One more thing. If a rule is producing false positives, I want a tuning recommendation written against it. Not "fix the rule". Specifically: which exclusion to add, which threshold to change, what the expected impact is on TP and FP counts. That recommendation goes back to the detection engineer, which this week happens to be you, so you get to see both sides of the feedback loop in one project.

Good luck. Work the queue top to bottom. If you need me, I am on the bridge.

-- James Chen

---
