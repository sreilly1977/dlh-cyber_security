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

# [5. Batch 3: Benign Activity Filter](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/5-triage_benign.sh)
### advanced

## Goal: 

Identify and close the low-priority alerts that are technically correct but operationally benign, with minimal ticket overhead.

## Context: 

The benign classification is the one new analysts misuse most often. A benign alert is not a false positive: the rule was right to fire and the behavior happened, but it has no security meaning at MedDefense. A single failed login followed by success is benign. A DHCP renewal is benign. An NTP drift warning is benign. These alerts still need a ticket because the compliance auditor will ask why they were closed, but the ticket is short and the justification references a fixed list of benign patterns declared in triage_methodology.md.

## Instructions: 

Write a script 5-triage_benign.sh that reads enriched_queue.json and processes every alert where priority_band == low OR the alert matches one of these benign patterns:

    A single login_failure event immediately followed by a login_success for the same user on the same host within sixty seconds (looked up in event_record.correlated_events or the enriched event store)

    A DHCP renewal pattern visible in the event record

    An NTP drift event with delta < 500 ms

    A blocked SMB scan from an external perimeter IP that never bypassed the firewall

For each match produce a ticket with classification: benign, recommended_action: close, and a one-line justification naming the benign pattern. Write the tickets to tickets/batch3_benign.json.

**Expected Output:**

```bash
$ ./5-triage_benign.sh
batch 3 benign
  alert_00001  low   single_fail_then_success
  alert_00004  low   dhcp_renewal
  alert_00015  low   ntp_drift_under_threshold
  alert_00022  low   perimeter_smb_block
  alert_00027  low   single_fail_then_success
batch size               : 5
tickets written          : 5
tickets/batch3_benign.json
```

---

# [6. Batch 4: Ambiguous Authentication Alerts](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/6-triage_ambiguous_auth.sh)

## Goal: 

Resolve the authentication alerts where neither the IOC nor the baseline gives a clean verdict and the decision depends on cross-referencing multiple context files.

## Context: 

This is where triage becomes a real skill. The queue contains authentication alerts where the account is in known_accounts but logged in from an IP the host has never seen, or where the failure count is above the business-hours average but below the clean baseline's maximum failure burst. Neither the baseline nor the IOC feed alone answers the question. You have to fetch the user's historical pattern, cross-reference with the enriched events to confirm the sequence, and consider the asset criticality before deciding. This is the batch that separates a competent Tier 1 from a clicker.

## Instructions: 

Write a script 6-triage_ambiguous_auth.sh that reads enriched_queue.json and processes every authentication alert not already handled in batches 1 to 3. For each alert:

    Fetch the user's historical login pattern from baseline_summary.json (per-user login times, source IPs, and host set)

    Fetch the last twenty authentication events for the same user from enriched_events.json

    Apply this decision tree:

        Unknown source IP on a critical or high asset AND baseline shows the user has never logged in to that host -> true_positive, escalate_tier2

        Unknown source IP on a medium or low asset AND no IOC hit -> false_positive, tune_rule, fp_reason: unknown_ip_low_asset

        Known source IP AND failure burst between max_failures_1h_window and max_failures_1h_window * 2 -> false_positive, tune_rule, fp_reason: baseline_edge_burst

        Any other ambiguous state -> true_positive, recommended_action: monitor, with a justification that documents the uncertainty and cites the specific fields checked

Write the tickets to tickets/batch4_auth.json.

**Expected Output:**

```bash
$ ./6-triage_ambiguous_auth.sh
batch 4 ambiguous authentication
  alert_00006  001 ssh_brute_force                true_positive   escalate
  alert_00012  002 windows_offhours_priv_logon    false_positive  tune_rule
  alert_00020  001 ssh_brute_force                true_positive   monitor
  alert_00028  013 privileged_shift_violation     true_positive   escalate
batch size               : 4
tickets written          : 4
tickets/batch4_auth.json
```

---

# [7. Batch 5: Ambiguous Process and Network Alerts](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/7-triage_ambiguous_proc_net.sh)

## Goal: 

Resolve process execution and network connection alerts that require joining the enriched event record with IOC context before a verdict is possible.

## Context: 

Process and network alerts are ambiguous for a different reason than authentication alerts. A powershell.exe execution might be a scheduled maintenance job the asset owner is running, or it might be post-exploitation code execution. An outbound connection to an unknown IP might be a new software update source, or it might be command-and-control. The deciding factor is almost always in the IOC context: is the destination known to the threat feed, how recently was it seen, what category is it in. This batch exercises that join discipline.

## Instructions: 

Write a script 7-triage_ambiguous_proc_net.sh that reads enriched_queue.json and processes every process or network alert not already handled. For each alert:

    For process alerts, extract the process_name, parent_process, and command_line from the enriched event record

    For network alerts, extract every dst_ip, dst_host, and dst_port, and look up reputation in ioc_context.json

    Apply this decision tree:

        Any IOC hit with reputation == malicious -> true_positive, escalate_tier2

        IOC reputation suspicious AND asset criticality critical or high -> true_positive, recommended_action: monitor

        IOC reputation suspicious AND asset criticality medium or low AND process or destination is present in baseline_host_profile for a different host -> false_positive, tune_rule, fp_reason: suspicious_but_baseline_known_elsewhere

        IOC reputation clean AND no baseline deviation -> false_positive, tune_rule, fp_reason: clean_ioc_no_deviation

        Any other state -> true_positive, recommended_action: monitor, with a justification documenting what was checked

Write the tickets to tickets/batch5_proc_net.json.

**Expected Output:**

```bash
$ ./7-triage_ambiguous_proc_net.sh
batch 5 ambiguous process and network
  alert_00014  003 interpreter_abuse              true_positive   escalate
  alert_00018  007 unknown_outbound_destination   true_positive   monitor
  alert_00023  008 uncommon_port_outbound         false_positive  tune_rule
  alert_00026  004 recon_tool_execution           true_positive   monitor
  alert_00030  003 interpreter_abuse              true_positive   escalate
batch size               : 5
tickets written          : 5
tickets/batch5_proc_net.json
```

---

# [8. Batch 6: Multi-Alert Correlation](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/8-triage_correlation.sh)

## Goal: 

Group multiple related alerts into single incident records before classifying, so that one attack does not produce six unrelated tickets.

## Context: 

A real attack rarely produces one alert. It produces a brute force alert, then a successful authentication alert, then a privilege escalation alert, then a network connection alert, all on the same host within a few minutes. If you triage each one independently you end up with six tickets referencing the same event and three duplicate escalations. The correlation step groups related alerts into a single incident record keyed by host and time window, classifies the incident once, and references every contributing alert from the incident ticket.

## Instructions: 

Write a script 8-triage_correlation.sh that reads enriched_queue.json and groups alerts into incidents using this rule: any two alerts on the same hostname whose event_summary.timestamp values are within six hundred seconds of each other belong to the same incident. Incidents with three or more alerts are marked high_confidence, incidents with two are marked medium_confidence.

For each incident produce a single ticket with:

    ticket_id: incident_<hostname>_<start_iso>

    classification: true_positive if any contributing alert is already true_positive from a previous batch, else evaluated fresh using the highest priority_score in the group

    contributing_alerts: list of all alert_ids in the group

    incident_window: start and end timestamps

    attack_techniques: deduplicated union of techniques from all contributing rules

    recommended_action: escalate_tier2 for any high_confidence group on a critical or high asset

Alerts that belong to a correlated incident must be marked grouped: true in their individual tickets so T10 and T12 can deduplicate counts.

Write the incident tickets to tickets/batch6_incidents.json.

**Expected Output:**

```bash
$ ./8-triage_correlation.sh
batch 6 correlated incidents
  incident_db-patient-01_2026-03-25T02:14:08Z  alerts=4  high_confidence  escalate
  incident_clin-ws-07_2026-03-25T09:41:22Z     alerts=3  high_confidence  escalate
  incident_med-img-02_2026-03-25T17:08:39Z     alerts=2  medium_confidence monitor
incidents assembled      : 3
alerts regrouped         : 9
tickets/batch6_incidents.json
```

---

# [9. Batch 7: Priority Conflicts](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/9-triage_priority_conflicts.sh)
### advanced

## Goal: 

Resolve the alerts where the rule-driven priority score conflicts with the asset-driven or context-driven urgency and document the override decision.

## Context: 

This is the last batch, and the one Dr. Morales will ask you about first. The 3x02 runner assigns priority by rule quality and risk score. But sometimes a medium-priority rule fires on a critical asset in a way that the rule author did not anticipate, and sometimes a critical-priority rule fires on a test box where the finding does not matter. The triage analyst is the human layer that catches these conflicts and documents why the machine ranking was overridden. The audit trail is the point: if you override a priority you must say which field and value forced the override, and the downstream tuning engine will later use the override record to propose a permanent rule-side fix.

## Instructions: 

Write a script 9-triage_priority_conflicts.sh that reads enriched_queue.json plus the tickets already produced in batches 1 to 6, and identifies conflicts matching any of these patterns:

    priority_band == low or medium AND asset.criticality == critical AND asset.data_classification in (phi, pci, confidential) -> force classification: true_positive, recommended_action: escalate_tier2, with override_reason: critical_data_asset

    priority_band == critical AND asset.criticality == low AND asset.role == test -> downgrade to false_positive, recommended_action: monitor, with override_reason: test_asset_not_production

    Any alert whose ioc_hits all have reputation == unknown AND the asset is in a regulated zone (phi, medical_devices) -> force recommended_action: monitor, with override_reason: regulated_zone_unknown_reputation

Every override must emit a ticket with the override reason recorded in justification. Write to tickets/batch7_overrides.json. Alerts without a conflict that are still unclassified after batches 1 to 6 must be carried forward with classification: true_positive, recommended_action: monitor, and a justification stating that they fell through every previous batch and require human review.

**Expected Output:**

```bash
$ ./9-triage_priority_conflicts.sh
batch 7 priority conflicts
  alert_00035  medium -> true_positive   critical_data_asset
  alert_00037  low    -> true_positive   critical_data_asset
  alert_00009  critical -> false_positive test_asset_not_production
  alert_00016  medium -> monitor         regulated_zone_unknown_reputation
unclassified carried forward : 2
tickets written              : 6
tickets/batch7_overrides.json
```

---

# [10. False Positive Aggregation and Tuning Recommendations](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/10-fp_tuning.sh)
### advanced

## Goal: 

Aggregate every false positive ticket from the shift into root-cause patterns and write a tuning recommendation per pattern.

## Context: 

Individual false positive tickets are the raw material. The tuning recommendations are the finished product the detection engineer consumes next week. The goal of this task is to stop treating false positives as isolated events and start treating them as evidence of systematic rule drift. A rule that produced four false positives in one shift is not a rule that needs four one-off exclusions. It is a rule that needs one surgical predicate change. Your job is to name the pattern and propose the change.

## Instructions: 

Write a script 10-fp_tuning.sh that reads every tickets/batchN_*.json file, collects every ticket with classification: false_positive, and groups them by rule_id and fp_reason. For each group with two or more tickets, produce a tuning recommendation with:

    rule_id

    rule_title

    fp_count

    fp_reason

    sample_alert_ids: up to five example ticket references

    proposed_change: a concrete Sigma filter modification expressed as a YAML fragment the detection engineer can paste into the rule

    expected_fp_reduction: integer count

    tp_risk_note: a one-sentence assessment of whether the change could introduce a false negative, citing a specific scenario

Write the full output to tuning_recommendations.json and print a compact summary ordered by fp_count descending.

**Expected Output:**

```bash
$ ./10-fp_tuning.sh
tuning recommendations
  002 windows_offhours_priv_logon     fp=3  reason=service_account_activity
  007 unknown_outbound_destination    fp=2  reason=management_subnet
  003 interpreter_abuse               fp=2  reason=baseline_match
recommendations written : 3
tuning_recommendations.json
```

---

# [11. Incident Assembly](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x03_triage_shift/11-incident_assembly.sh)

## Goal: 

Assemble every true positive and correlated incident into a structured incident record that Tier 2 can act on without repeating your work.

## Context: 

The escalation package is the most operationally important artifact this shift produces. It is the document Tier 2 opens first on Monday morning. It has to contain everything they need to start containment without asking you a single clarifying question. A vague escalation wastes an hour of Tier 2 time per incident and costs MTTR directly. A precise escalation lets Tier 2 hit the ground running and shortens the gap between detection and containment.

## Instructions: 

Write a script 11-incident_assembly.sh that reads every ticket produced in batches 1 to 7, selects every ticket with classification: true_positive AND recommended_action in (escalate_tier2, monitor), and for each produces an incident record with:

    incident_id (deterministic from the ticket)

    summary (one sentence derived from the rule title and target host)

    timeline: ordered list of event records referenced by the ticket, with timestamp, hostname, event_category, and a short description

    affected_assets: deduplicated list of host records from the asset inventory, each with hostname, criticality, data_classification, and network_zone

    iocs: deduplicated list of IPs, domains, user accounts, and process names extracted from the event records

    attack_techniques: deduplicated list from the source rules

    recommended_containment: a specific first action drawn from a fixed table (for example isolate_host for confirmed C2, disable_account for credential compromise, block_ip_at_egress for egress to malicious destination)

    related_incidents: list of other incident IDs that share any IOC or hostname

Write the incidents to incidents.json and print one line per incident.

**Expected Output:**

```bash
$ ./11-incident_assembly.sh
incidents assembled
  INC-20260326-0001  db-patient-01  credential_theft_chain       isolate_host
  INC-20260326-0002  clin-ws-07     interpreter_abuse            isolate_host
  INC-20260326-0003  meddb-01       patient_data_access          disable_account
  INC-20260326-0004  med-img-02     medical_segment_egress       block_ip_at_egress
  INC-20260326-0005  db-patient-01  ssh_brute_force              block_source_ip
  INC-20260326-0006  clin-ws-07     privileged_shift_violation   disable_account
total incidents         : 6
incidents.json written
```

---
