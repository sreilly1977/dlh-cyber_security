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

# [0. Queue Assessment](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/0-queue_assessment.sh)

## Goal: 

Load the alert queue, validate its schema, and produce a structured shift briefing that tells you exactly what you are walking into.

## Context: 

A shift begins with situational awareness, not with opening the first ticket. Before you touch any individual alert you need to know the shape of the queue: how many alerts, distributed across which priority bands, hitting which hosts, firing which rules. This briefing is the first artifact you produce every day of your career in a SOC. It is the document you show James Chen in the first five minutes of your shift when he asks "how are we looking".

## Instructions: 

Write a script 0-queue_assessment.sh that reads $CATALOG_DIR/alerts/alert_queue.json and $CATALOG_DIR/alerts/alert_queue_schema.json, validates every alert against the schema, and produces queue_assessment.json containing:

    queue_size
    validation_errors: list of alerts that failed schema validation
    by_priority_band: counts for critical (>= 20), high (10–19), medium (5–9), low (1–4)
    by_rule: count per rule_id sorted descending
    by_hostname: count per target host sorted descending
    by_attack_tactic: count per ATT&CK tactic derived from rule tags
    time_span: first and last event_summary.timestamp in the queue
    top_targets: the three hosts with the highest cumulative priority_score

Default CATALOG_DIR to ~/3x02_package/detection_catalog if not set. Print a human-readable shift briefing to stdout.

**Expected Output:**

```bash
$ source ~/m3_env.sh && ./0-queue_assessment.sh
=== SHIFT BRIEFING <date> ===
queue size           : <N> alerts
validation errors    :  <N>
time span            : <start> -> <end>
priority bands
  critical  :  6
  high      : 14
  medium    : 12
  low       :  6
top rules (5)
  010 credential_theft_chain         4
  012 medical_segment_egress         4
  007 unknown_outbound_destination   5
  001 ssh_brute_force                3
  011 patient_data_access            3
top hosts (3 by cumulative score)
  db-patient-01   score 78
  clin-ws-07      score 54
  med-img-02      score 42
attack tactics covered : 7
queue_assessment.json written
```

---

# [2. Context Assembly](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/2-context_assembly.sh)

## Goal: 

Merge the alert queue with every supporting artifact into a single enriched queue that every subsequent triage script reads from.

## Context: 

Opening five JSON files for every single alert is the fastest way to waste a shift. The context assembly step reads the queue once, joins each alert with the matching asset context, the baseline profile for the target host, the event record referenced by event_ref, and any IOC context hits for IPs or domains present in the alert, and writes the whole thing to a single enriched queue file. Every downstream script in Block 2 reads from the enriched queue and never re-opens the individual sources.

## Instructions: 

Write a script 2-context_assembly.sh that reads alert_queue.json, $HANDOFF_DIR/context/asset_inventory.json, $HANDOFF_DIR/data/enriched_events.json, $BASELINE_PKG/baselines/baseline_summary.json, and $ASSETS_DIR/ioc_context.json, and produces enriched_queue.json. For every alert the enriched entry must contain:

    All original alert fields
    asset: full asset record (criticality, role, data_classification, owner, network_zone)
    baseline_host_profile: per-host baseline slices relevant to the alert category
    event_record: the full enriched event dereferenced from event_ref
    ioc_hits: list of IOC context entries matched by any IP/domain fields; entries with reputation != clean must have ioc_flag: true
    priority_band: one of critical, high, medium, low derived from priority_score

All env vars default to their standard paths if not set. Create tickets/ directory if it does not exist.

**Expected Output:**

```bash
$ source ~/m3_env.sh && export ASSETS_DIR=$HOME/3x03_assets && ./2-context_assembly.sh
alerts processed          : 38
assets joined             : 38
missing asset records     :  0
alerts with IOC hits      : 11
  malicious               :  3
  suspicious              :  6
  unknown                 :  2
baseline profiles joined  : 38
enriched_queue.json written (612 KB)
```

---

# [3. Batch 1: Clear-Cut True Positives](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/3-triage_clearcut_tp.sh)

## Goal: 

Process the high-confidence true positives at the top of the queue where priority, IOC hits, and baseline deviation all point at the same conclusion.

## Context: 

The first batch is the easy one. These are the alerts where everything lines up: a high-priority rule from the 3x02 catalog, a malicious IOC match on the destination, an event that violates every relevant baseline, and an asset in a critical zone. The correct action is a fast, clean escalation. The goal of this task is to prove that you can close clear-cut cases quickly without over-investigating, because the rest of the shift depends on the hour you save here.

## Instructions: 

Write a script 3-triage_clearcut_tp.sh that reads enriched_queue.json and processes every alert matching ALL of these predicates:

    priority_band == critical

    At least one ioc_hit with reputation == malicious

    The source rule's category (auth, process, network, file, correlation) shows a baseline violation against baseline_host_profile

For each matching alert, produce a ticket with classification: true_positive, recommended_action: escalate_tier2, justification naming the specific IOC category and the baseline field that was violated, and evidence_refs listing the event reference from the alert plus any linked correlation primitives.

Write all resulting tickets to tickets/batch1_clearcut_tp.json as an array and print a compact summary table.

**Expected Output:**

```bash
$ ./3-triage_clearcut_tp.sh
batch 1 clear-cut true positives
  alert_00042  010 credential_theft_chain     db-patient-01   malicious  ESCALATE
  alert_00031  011 patient_data_access        meddb-01        malicious  ESCALATE
  alert_00017  012 medical_segment_egress     med-img-02      malicious  ESCALATE
  alert_00019  012 medical_segment_egress     med-img-02      malicious  ESCALATE
batch size               : 4
tickets written          : 4
tickets/batch1_clearcut_tp.json
```

---

# [4. Batch 2: Clear-Cut False Positives](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/4-triage_clearcut_fp.sh)

## Goal: 

Process the batch of alerts that clearly match authorized activity and close them with the minimum documentation that satisfies the methodology.

## Context: 

The second batch is the other side of the clear-cut line. These are alerts where the rule fired correctly on something that is either a known service behavior, a scheduled administrative task, or an authorized change that shows up in the asset context. You close them, you justify the close with the specific evidence that made it obvious, and you tag them for the tuning engine so T10 can aggregate the root cause later. Speed matters here too. If you spend as much time on a clear false positive as on a real incident, you will never finish the shift.

## Instructions: 

Write a script 4-triage_clearcut_fp.sh that reads enriched_queue.json and processes every alert matching ANY of these false positive signatures:

    Target user matches the service_account_prefix in the asset_inventory.json owner metadata (for example svc_) AND the rule is one of the authentication or process rules

    Source IP is in the asset inventory management_subnets range AND the rule is a network rule

    The event references a process_name that appears in the baseline_host_profile.process.expected set for the target host

    All ioc_hits have reputation == clean AND baseline deviation is absent

For each match produce a ticket with classification: false_positive, recommended_action: tune_rule, a one-sentence justification naming the specific false positive signature matched, and an fp_reason tag (one of service_account_activity, management_subnet, baseline_match, clean_ioc_no_deviation) used in T10.

Write all resulting tickets to tickets/batch2_clearcut_fp.json.

**Expected Output:**

```bash
$ ./4-triage_clearcut_fp.sh
batch 2 clear-cut false positives
  alert_00003  002 windows_offhours_priv_logon  CLOSE  service_account_activity
  alert_00008  007 unknown_outbound_destination CLOSE  management_subnet
  alert_00011  003 interpreter_abuse            CLOSE  baseline_match
  alert_00025  002 windows_offhours_priv_logon  CLOSE  service_account_activity
  alert_00029  004 recon_tool_execution         CLOSE  baseline_match
  alert_00034  007 unknown_outbound_destination CLOSE  management_subnet
batch size               : 6
tickets written          : 6
tickets/batch2_clearcut_fp.json
```

---
