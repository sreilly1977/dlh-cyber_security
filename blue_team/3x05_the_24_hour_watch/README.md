# Introduction

> "Detection is a process, not a product." 
>
> - Richard Bejtlich, The Tao of Network Security Monitoring

Every project in this module built one component of that process. 3x00 built the pipeline. 3x01 built the baselines. 3x02 built the catalog. 3x03 built the triage floor. 3x04 made you fluent across interfaces. None of those projects asked the question you are about to answer: can you run the full chain, against data you have never seen, inside a single shift, and hand the next analyst a package they can act on without calling you back?

This capstone is that question made operational. You receive a fresh evidence pack from a 24-hour observation window on MedDefense infrastructure. You do not see the attacks in advance. You do not see the asset inventory annotated with "compromised host here." You run your own pipeline against raw logs, execute your own baselines, fire your own detection catalog, work through your own triage process, and investigate the incidents that surface. At the end of the shift you assemble a shift handoff package that stands on its own.

There are at least three real incidents buried in the noise. Some of them match threat intelligence already in your hands. Some of them do not. Some of the alerts that fire are not incidents at all, they are legitimate activity that happens to trigger your rules. Part of the grading is whether you can tell which is which and document your reasoning clearly enough that a grader who has never seen the pack can verify your conclusions.

## Why this matters

The BTL1 practical, the blue-team rotation at any real SOC, and the Security+ Domain 4 objectives all converge on one skill: sustained analytical operation under time pressure with imperfect information. Every task in this capstone maps to an operational deliverable that a Tier 1 analyst actually produces during a shift, a running pipeline, a triaged alert queue, investigation findings, incident reports, tuning proposals, and a clean handoff. Your grade is the set of artifacts. The artifacts are countable. A grader checking compliance against the schema never has to guess whether your work is "good enough."

What you build here also becomes your portfolio exhibit. When a hiring manager asks you to describe a SOC shift, you will not recite theory. You will show them a directory, walk them through the MANIFEST.json, and point to the specific JSON files that prove each phase of the work.

## Context

You are the SOC Tier 1 analyst on duty for MedDefense Health Systems. James Chen, SOC Lead, has just activated a heightened monitoring posture based on a threat intelligence advisory received from the regional healthcare ISAC.

---

**FROM:** James Chen, SOC Lead

**TO:** SOC Tier 1 on duty

**SUBJECT:** Heightened monitoring posture / Shift Pack / Cluster HC-RED7

**PRIORITY:** High

An ISAC advisory this morning confirmed that an activity cluster designated HC-RED7 has been targeting regional healthcare networks across our state for the past six weeks. Three hospitals in the region have confirmed intrusions tied to this cluster. Initial access has come through a mix of credential compromise and targeted phishing. The cluster installs a service-based persistence mechanism, beacons on an irregular interval, and stages data against approved business processes to blend in.

Dr. Morales has authorized heightened monitoring for the next 24 hours. I am activating the shift pack protocol.

You are receiving a fresh evidence pack from the last 24-hour window across our three sites. It contains Windows event logs, Linux auth and system logs, Sysmon telemetry from the endpoints we hardened in Module 2, network artifacts, and Suricata output. You will also receive the updated IOC feed, the asset inventory, and the ISAC advisory summary.

Your job across this shift:

    Run your pipeline against the pack

    Run your baselines and your catalog

    Triage everything that fires

    Investigate the incidents you identify, using both CLI tools and the Wazuh exports from 3x04

    Document each incident, map techniques, propose tuning, and assemble the full shift handoff package

I am not going to tell you how many incidents are in there. I am going to tell you what a clean shift package looks like when you hand it off, and I am going to grade you against that.

If you hit an ambiguous case, document the ambiguity in the finding and note what information would resolve it. Do not guess. Do not close something you are not sure about. Escalate on paper and keep moving.

The shift starts when you acknowledge this message.

-- James Chen
The Evidence Pack

---

The capstone evidence pack is placed at $CAPSTONE_PACK. You have never seen this data before. It was captured from MedDefense production sources during a 24-hour window and contains:

    Windows .evtx exports from three sites (clinical, radiology, billing)

    Linux syslog, auth.log, and audit.log from Linux endpoints and servers

    Sysmon JSON telemetry from hardened endpoints

    Suricata eve.json with IDS alerts

    Firewall logs in CEF-like format

    A set of network artifacts (PCAP slices, NetFlow summaries)

    An updated asset inventory (assets.json) with site, zone, criticality, data classification

    The HC-RED7 IOC feed (ioc_feed.json) with network and host indicators

    An ISAC advisory summary (hc_red7_advisory.md)

    The change management log for the window (change_tickets.json)

    A partial triage log from the previous shift (prior_shift_notes.md)

The pack is in the same input format that 3x00 expects. Your pipeline ingests it. There is no shortcut.
What is in the Pack

You are told the following up front because you will not have time to discover it through trial and error:

    At least three incidents are hidden in the pack

    At least one incident matches the HC-RED7 IOC feed

    At least one incident is ambiguous and requires checking context beyond the raw events

    The pack contains dirty data: clock skew on one host, a duplicate event stream on another, a gap in Sysmon telemetry during an agent restart, and a handful of malformed syslog lines

    Some of the alerts that fire are false positives tied to approved change activity

    Some of the alerts that fire are noise and should be batch-closed with justification

You are NOT told which host is compromised, which user is involved, or which rule will catch which incident. The grading relies on countable outputs, not on whether you match a specific narrative.

---

### Locked Finding Schema

Every investigation finding across this project must conform to this schema:

```json
{
  "finding_id": "string",
  "incident_id": "INC-YYYYMMDD-X",
  "interface": "cli | wazuh_export",
  "investigation_start": "ISO-8601",
  "investigation_end": "ISO-8601",
  "time_to_first_answer_seconds": 0,
  "actions": ["string"],
  "event_refs": ["string"],
  "attack_techniques": ["Txxxx[.yyy]"],
  "hypothesis": "string",
  "confidence": "low | medium | high",
  "ambiguity_notes": "string",
  "created_at": "ISO-8601"
}
```

### Locked Incident Report Schema

Every incident report is a markdown file with exactly these sections, in this order:

<pre>
    ## Incident Identifier

    ## Executive Summary (3 to 5 sentences)

    ## Timeline (chronological UTC events)

    ## Affected Assets

    ## Indicators of Compromise

    ## ATT&CK Mapping

    ## Detection Performance

    ## Recommended Actions

    ## Evidence References
</pre>

No prose outside these sections. Per-section caps are defined in Task 11.

### Provided Files

| File | Description |
|------|-------------|
| `$ASSETS_DIR/assets.json` | Updated asset inventory |
| `$ASSETS_DIR/ioc_feed.json` | HC-RED7 IOC feed |
| `$ASSETS_DIR/hc_red7_advisory.md` | ISAC advisory summary |
| `$ASSETS_DIR/change_tickets.json` | Change management log |
| `$ASSETS_DIR/prior_shift_notes.md` | Prior shift open items |
| `$WAZUH_EXPORTS/incident_A_search_results.json` | Wazuh export for incident A |
| `$WAZUH_EXPORTS/incident_B_search_results.json` | Wazuh export for incident B |
| `$WAZUH_EXPORTS/incident_C_search_results.json` | Wazuh export for incident C |
| `$WAZUH_EXPORTS/campaign_dashboard_summary.md` | Campaign overview |
| `$WAZUH_EXPORTS/exported_dashboard_workflow.json` | Dashboard pivot workflow |

### Shift Workspace Layout (locked)

<pre>
$SHIFT_WORKSPACE/
├── MANIFEST.json
├── runtime/
│   ├── shift_start.json
│   ├── pipeline_run.json
│   ├── baseline_run.json
│   └── catalog_run.json
├── enriched/
│   ├── enriched_events.jsonl
│   ├── timeline.jsonl
│   ├── baseline.json
│   └── source_stats.json
├── alerts/
│   ├── alert_queue.json
│   ├── shift_briefing.json
│   ├── triage_log.jsonl
│   └── incidents.json
├── investigations/
│   ├── incident_A.json
│   ├── incident_B.json
│   ├── incident_C_cli.json
│   └── incident_C_export.json
├── campaign/
│   └── campaign_assessment.json
├── reports/
│   ├── incident_A.md
│   ├── incident_B.md
│   └── incident_C.md
├── response/
│   ├── tuning_recommendations.json
│   ├── containment.json
│   └── ioc_package.json
└── handoff/
    └── shift_handoff.md
</pre>

---

# [0. Shift Intake and Toolchain Verification](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/0-shift_intake.sh)

## Goal: 

Acknowledge the shift, verify the complete environment, and write a machine-readable shift start record before touching any evidence.

## Context: 

A shift that begins with a broken tool ends with a missed incident. Before you touch the evidence pack, confirm that every moving part from prior projects is available and functional: the pipeline binary you wrote in 3x00, the baseline script from 3x01, the detection catalog from 3x02, and the triage runner from 3x03. The shift intake record is also the clock reference for every metric that follows — time-to-detection, time-to-first-finding, shift duration. If the record is missing or malformed, downstream scripts that compute those metrics will fail.

You also verify that the Wazuh export artifacts are staged correctly. For Task 9, you will need the incident-level search result exports from $WAZUH_EXPORTS/. Confirming they exist now prevents a surprise failure six tasks later when you are deep in investigation.

## Instructions: 

Write 0-shift_intake.sh that:

    Verifies presence of all required binaries on PATH: jq, python3, yq, sigma-cli, sha256sum. Print each binary name and its version on a single line. Exit non-zero with a message naming the missing binary if any is absent.

    Verifies that the four prior-project binaries or directories exist and are accessible:

    $PIPELINE_BIN — executable file
    $BASELINE_BIN — executable file
    $CATALOG_DIR — readable directory containing at least one .yml file
    $TRIAGE_BIN — executable file Print the result of each check on its own line.

    Verifies that $CAPSTONE_PACK/ is a non-empty directory accessible to the student user. Print the top-level subdirectory list.

    Verifies that $ASSETS_DIR/ contains all five required context files: assets.json, ioc_feed.json, hc_red7_advisory.md, change_tickets.json, prior_shift_notes.md. Exit non-zero if any is missing.

    Verifies that $WAZUH_EXPORTS/ contains the four required export files: incident_A_search_results.json, incident_B_search_results.json, incident_C_search_results.json, campaign_dashboard_summary.md. Exit non-zero if any is missing.

    Reads $ASSETS_DIR/ioc_feed.json and extracts the total IOC count (jq '.iocs | length'). Reads $ASSETS_DIR/hc_red7_advisory.md and extracts the cluster ID by scanning for the line containing HC-RED7. Prints both values.

    Creates $SHIFT_WORKSPACE/ with the full locked workspace layout. Use mkdir -p for every subdirectory in the layout. Stub empty files where required by later tasks: $SHIFT_WORKSPACE/MANIFEST.json, the four runtime/ JSON files, all four enriched/ files, all four alerts/ files, the four investigations/ finding files, campaign/campaign_assessment.json, three reports/ Markdown files, three response/ JSON files, handoff/shift_handoff.md.

    Writes $SHIFT_WORKSPACE/runtime/shift_start.json:

```json
{
  "shift_id": "SHIFT-YYYYMMDD-HHMM",
  "analyst_host": "hostname-of-lab-container",
  "started_at": "ISO-8601-UTC",
  "tools": {
    "jq": "x.y.z",
    "python3": "x.y.z",
    "yq": "x.y.z",
    "sigma-cli": "x.y.z",
    "sha256sum": "present"
  },
  "prior_project_bins": {
    "pipeline": true,
    "baseline": true,
    "catalog": true,
    "triage": true
  },
  "capstone_pack": "$CAPSTONE_PACK resolved path",
  "ioc_feed_count": 0,
  "advisory_cluster_id": "HC-RED7",
  "wazuh_exports_verified": true
}
```

The script exits non-zero immediately on any failed check and prints the failing check on stderr so the output is unambiguous.

**Expected Output:**

```bash
$ ./0-shift_intake.sh
[intake] jq 1.6 OK
[intake] python3 3.10.12 OK
[intake] yq 4.44.3 OK
[intake] sigma-cli 1.0.4 OK
[intake] sha256sum OK
[intake] PIPELINE_BIN OK
[intake] BASELINE_BIN OK
[intake] CATALOG_DIR OK (13 rules)
[intake] TRIAGE_BIN OK
[intake] CAPSTONE_PACK OK
[intake] ASSETS_DIR: 5 meta files OK
[intake] WAZUH_EXPORTS: 4 export files OK
[intake] ioc_feed.json OK (12 entries)
[intake] advisory HC-RED7 loaded
[intake] workspace layout created at $SHIFT_WORKSPACE
[intake] shift_start.json written
$ echo $?
0
```

---

# [1. Evidence Pipeline Execution](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/1-run_pipeline.sh)

## Goal: 

Run your 3x00 pipeline against the fresh evidence pack and produce normalized, enriched, and timelined events ready for detection.

## Context: 

The pipeline you built and tested in 3x00 now runs against data you have never seen. Any fragility in your pipeline scripts will surface here. Missing field handling, hardcoded paths, syslog year assumptions, timestamp format edge cases — every one of these was a theoretical concern in 3x00. Now it is a real failure mode against production-style data.

The secondary evidence pack has the same directory layout as the primary — windows/, linux/, network/, context/, student_telemetry/ — but different hosts, a different 8-day time window, and deliberately injected dirty data: clock skew on one host, a duplicate event stream on another, a gap in Sysmon telemetry during an agent restart, and a handful of malformed syslog lines. Your pipeline must handle all of these and report what it corrected.

This task is graded on whether the pipeline completes cleanly, not on whether your detection rules fire. The enriched events file it produces is the substrate for every downstream task.

## Instructions: 

Write 1-run_pipeline.sh that:

    Reads $SHIFT_WORKSPACE/runtime/shift_start.json to confirm the intake check passed (exit non-zero with a message if shift_start.json is absent or empty).

    Invokes $PIPELINE_BIN with $CAPSTONE_PACK as the input pack and $SHIFT_WORKSPACE/enriched/ as the output directory. Passes the output directory path as the second argument exactly as your 3x00 pipeline expects.

    Captures the pipeline's stdout and stderr together into $SHIFT_WORKSPACE/runtime/pipeline_run.log. The script prints a progress line every time a stage completes so the analyst can see the pipeline is alive.

    After the pipeline exits, verifies that the following files exist and are non-empty in $SHIFT_WORKSPACE/enriched/:

    enriched_events.jsonl or enriched_events.json
    timeline.jsonl or timeline_index.json
    source_stats.json Exit non-zero with a message identifying the missing file if any is absent.

    Reads source_stats.json and confirms that at least four source types show a non-zero event count. Print a one-line summary per source type.

    Writes $SHIFT_WORKSPACE/runtime/pipeline_run.json:

```json
{
  "pipeline_version": "string (from $PIPELINE_BIN --version or 'unknown')",
  "started_at": "ISO-8601",
  "ended_at": "ISO-8601",
  "duration_seconds": 0,
  "input_pack": "$CAPSTONE_PACK",
  "events_in": 0,
  "events_out": 0,
  "events_dropped": 0,
  "source_counts": {
    "windows_json": 0,
    "linux_text": 0,
    "firewall": 0,
    "suricata_alert": 0,
    "pcap_flow": 0
  },
  "dirty_data_detected": [],
  "exit_status": 0
}
```

The script exits non-zero if the pipeline itself returns non-zero, if any required output file is missing, or if all source counts are zero.

**Expected Output:**

```bash
$ ./1-run_pipeline.sh
[pipeline] intake check: OK
[pipeline] invoking $PIPELINE_BIN
[pipeline] input: $CAPSTONE_PACK
[pipeline] output: $SHIFT_WORKSPACE/enriched/
[pipeline] stage 0 source_inventory ... ok
[pipeline] stage 1 telemetry_import ... ok
[pipeline] stage 2 windows_parse    ... ok
[pipeline] stage 3 linux_parse      ... ok
[pipeline] stage 5 normalize        ... ok
[pipeline] stage 6 network_normalize... ok
[pipeline] stage 7 schema_validate  ... ok
[pipeline] stage 8 data_quality     ... ok
[pipeline] stage 9 enrich           ... ok
[pipeline] stage 10 timeline        ... ok
[pipeline] stage 11 source_stats    ... ok
[pipeline] duration 180s
[pipeline] events_in=N events_out=N dropped=N
[pipeline] source windows_json=N linux_text=N firewall=N suricata_alert=N
[pipeline] pipeline_run.json written
```

---

# [2. Behavioral Baseline Execution](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/2-run_baselines.sh)

## Goal: 

Run your 3x01 baselining methodology against the enriched events and produce per-host deviation markers that the triage step uses to separate signal from noise.

## Context: 

Baselines turn raw events into "what is abnormal on this specific host." Running them against unseen data shows whether your baseline scripts generalize beyond the dataset you built them against. A baseline script that hardcodes the primary pack's host list will produce zero deviation markers here and make Task 5 triage useless. The deviation markers are one of the two most important inputs to shift triage — the other is the IOC feed. Together they tell you which alerts to prioritize and which to batch-close as expected activity.

## Instructions: 

Write 2-run_baselines.sh that:

    Reads $SHIFT_WORKSPACE/runtime/pipeline_run.json and confirms exit_status is 0 (exit non-zero if not).

    Invokes $BASELINE_BIN with the enriched events file from $SHIFT_WORKSPACE/enriched/ as input. Passes the output path $SHIFT_WORKSPACE/enriched/baseline.json as an argument or through environment variables as your 3x01 script expects.

    After the baseline run, verifies that $SHIFT_WORKSPACE/enriched/baseline.json exists and is non-empty.

    Reads baseline.json and computes:

    Total unique hosts processed
    Number of hosts with at least one deviation marker
    The five hosts with the highest total deviation score Prints a one-line summary for each hot host.

    Writes $SHIFT_WORKSPACE/runtime/baseline_run.json:

```json
{
  "baseline_version": "string",
  "hosts_total": 0,
  "hosts_with_deviations": 0,
  "deviation_markers": [
    {
      "host": "string",
      "marker": "unseen_src_ip | off_hours_login | unusual_parent_process | unknown_destination | new_service | encoding_anomaly",
      "field": "string (the specific field that triggered the marker)",
      "observed_value": "string",
      "baseline_reference": "string (what the baseline expected)",
      "deviation_score": 0.0
    }
  ],
  "hot_hosts": ["string"],
  "started_at": "ISO-8601",
  "ended_at": "ISO-8601",
  "exit_status": 0
}
```

The script exits non-zero if the baseline script fails or if hosts_total is zero.

**Expected Output:**

```bash
$ ./2-run_baselines.sh
[baseline] pipeline check: OK
[baseline] invoking $BASELINE_BIN
[baseline] input: $SHIFT_WORKSPACE/enriched/enriched_events.jsonl
[baseline] output: $SHIFT_WORKSPACE/enriched/baseline.json
[baseline] hosts processed: N
[baseline] hosts with deviations: N
[baseline] hot hosts: hostname-1 hostname-2 hostname-3
[baseline] markers: N total (unseen_src_ip: N  off_hours: N  new_service: N)
[baseline] baseline_run.json written
```

---

# [3. Detection Catalog Execution](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/3-run_detections.sh)

## Goal: 

Run your 3x02 Sigma detection catalog against the enriched events and produce the shift alert queue.

## Context: 

The catalog is your detection layer. Running it produces alert_queue.json, the artifact that drives every downstream triage and investigation task. If a rule that should fire does not, you discover it here — or you discover it in Task 12 when you realize an incident you found through investigation should have produced an alert that it did not. That gap is detection engineering feedback. Both outcomes are graded.

The secondary pack was deliberately built with at least three incidents, each of which fires at least one rule from your catalog. If zero alerts fire, the catalog is broken or the enriched events are malformed. The script must exit non-zero in that case so the shift does not continue on a false foundation.

## Instructions: 

Write 3-run_detections.sh that:

    Reads $SHIFT_WORKSPACE/runtime/pipeline_run.json and confirms exit_status is 0.

    Counts the total number of .yml rule files in $CATALOG_DIR/rules/sigma/ (or the path structure your 3x02 catalog uses) and prints the count.

    Invokes your 3x02 detection runner — either sigma-cli directly or the wrapper script you built in 3x02 — against the enriched events file from $SHIFT_WORKSPACE/enriched/. Passes the catalog directory and the output path $SHIFT_WORKSPACE/alerts/alert_queue.json as arguments.

    After the detection run, verifies that $SHIFT_WORKSPACE/alerts/alert_queue.json exists and is non-empty.

    Reads alert_queue.json and computes:

    Total alert count
    Alert count by severity (critical, high, medium, low)
    Alert count per rule ID, sorted descending Prints a human-readable summary table.

    Writes $SHIFT_WORKSPACE/runtime/catalog_run.json:

```json
{
  "catalog_rules_total": 0,
  "catalog_rules_fired": 0,
  "alerts_total": 0,
  "alerts_by_severity": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "alerts_by_rule": {
    "rule_id_string": 0
  },
  "started_at": "ISO-8601",
  "ended_at": "ISO-8601",
  "exit_status": 0
}
```

The script exits non-zero if the detection runner fails or if alerts_total is zero.

**Expected Output:**

```bash
$ ./3-run_detections.sh
[detect] pipeline check: OK
[detect] catalog loaded: N rules
[detect] invoking detection runner
[detect] matched: N rules / N alerts
[detect] severity critical=N high=N medium=N low=N
[detect] top rules:
  001_ssh_brute_force   : N alerts
  002_offhours_priv     : N alerts
  ...
[detect] alert_queue.json written
[detect] catalog_run.json written
```

---

# [4. Shift Briefing and Context Assembly](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/4-shift_briefing.sh)

## Goal: 

Build the shift briefing document that ties the IOC feed, advisory, change tickets, prior shift notes, and baseline deviations into a single reference object for triage.

## Context: 

The briefing is the reference you open every time you touch an alert. It tells you what the threat actor looks like, what approved activity to expect in the window, what the previous shift already flagged, and which hosts are already on the deviation list. Without it, triage becomes guesswork because you cannot distinguish an alert on a host with ten deviation markers from an alert on a host the baseline never saw before.

The briefing is machine-readable so that later scripts can join it mechanically without requiring human memory. The IOC list embedded in it lets triage scripts flag alerts that share an indicator with the feed. The change ticket list lets them identify alerts that correspond to approved maintenance. Both lookups are O(1) if the briefing is structured correctly.

## Instructions: 

Write 4-shift_briefing.sh that:

    Reads and validates all five required input files exist: $ASSETS_DIR/hc_red7_advisory.md, $ASSETS_DIR/ioc_feed.json, $ASSETS_DIR/change_tickets.json, $ASSETS_DIR/prior_shift_notes.md, and $SHIFT_WORKSPACE/runtime/baseline_run.json. Exit non-zero if any is missing.

    From $ASSETS_DIR/ioc_feed.json, extracts: total IOC count, IOC count by type (ip, domain, hash, account, service_name, port). Builds a flat list of all IOC values for fast lookup in later scripts.

    From $ASSETS_DIR/hc_red7_advisory.md, extracts the cluster ID (scan for HC-RED7), the listed tactics (lines beginning with T1), and the note count. Confirms the cluster ID matches shift_start.json.advisory_cluster_id. Exit non-zero if they differ.

    From $ASSETS_DIR/change_tickets.json, extracts every approved change window: ticket ID, window start/end, host list, owner, and approved activity description.

    From $ASSETS_DIR/prior_shift_notes.md, extracts the open items list (lines under the "Open Items" heading).

    From $SHIFT_WORKSPACE/runtime/baseline_run.json, extracts the hot_hosts list and the count of hosts with deviations.

    Writes $SHIFT_WORKSPACE/alerts/shift_briefing.json:

```json
{
  "cluster_id": "HC-RED7",
  "cluster_tactics": ["T1078", "T1543", "T1071"],
  "ioc_count": 0,
  "ioc_by_type": {
    "ip": 0, "domain": 0, "hash": 0, "account": 0, "service_name": 0, "port": 0
  },
  "ioc_values": ["string"],
  "active_change_tickets": [
    {
      "ticket_id": "string",
      "window_start": "ISO-8601",
      "window_end": "ISO-8601",
      "hosts": ["string"],
      "owner": "string",
      "approved_activity": "string"
    }
  ],
  "prior_shift_open_items": ["string"],
  "baseline_hot_hosts": ["string"],
  "hosts_with_deviations": 0
}
```

The script exits non-zero if any required input file is missing or if the cluster ID cross-check fails.

**Expected Output:**

```bash
$ ./4-shift_briefing.sh
[brief] checking input files... OK
[brief] cluster HC-RED7 loaded
[brief] tactics: T1078 T1543 T1071 T1110 T1041
[brief] IOCs: ip=5 domain=2 hash=1 account=2 service_name=2 port=0 total=12
[brief] active change tickets in window: 3
[brief] prior shift open items: 2
[brief] baseline hot hosts: 6
[brief] cluster ID cross-check: OK
[brief] shift_briefing.json written
```

---

# [5. Alert Queue Triage and Classification](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/5-triage_queue.sh)

## Goal: 

Run your 3x03 triage methodology over the full alert queue and produce a classified triage log where every alert has a disposition.

## Context: 

This is the main triage pass. Every alert gets classified as TP, FP, or NOISE using the schema you locked in 3x03. The classification must be backed by evidence from the briefing, the baseline, and the events themselves. Nothing is closed on intuition and nothing is left unclassified — an unclassified alert at the end of a shift is a missed incident waiting to happen.

The secondary pack has approved change activity that partially covers some alerts. A billing database maintenance window covers some network activity on bill-db-01. An off-hours domain controller GPO push covers some authentication events on srv-dc-01. Cross-referencing every alert against the change tickets before classifying as FP is not optional. An alert classified FP that is actually a TP because the change window did not match exactly is a critical failure in this task.

## Instructions: 

Write 5-triage_queue.sh that:

    Reads $SHIFT_WORKSPACE/alerts/alert_queue.json and $SHIFT_WORKSPACE/alerts/shift_briefing.json. Confirms both exist (exit non-zero if either is missing).

    Invokes $TRIAGE_BIN against alert_queue.json, passing shift_briefing.json, $SHIFT_WORKSPACE/enriched/baseline.json, and $ASSETS_DIR/assets.json as context inputs. Your 3x03 triage script handles the actual classification logic.

    For each alert, appends one record to $SHIFT_WORKSPACE/alerts/triage_log.jsonl. Each record must conform to this schema:

```json
{
  "alert_id": "string",
  "rule_id": "string",
  "host": "string (lowercase)",
  "user": "string or null",
  "classification": "TP | FP | NOISE",
  "severity": "critical | high | medium | low",
  "matches_ioc": ["string (IOC value matched, empty list if none)"],
  "baseline_deviation": true,
  "change_ticket_match": "ticket_id or null",
  "analyst_note": "string (reason for classification, <= 200 chars)",
  "classified_at": "ISO-8601"
}
```

    After classification completes, reads triage_log.jsonl and counts records by classification. Verifies that zero alerts remain unclassified. Exit non-zero if any alert is missing from the log.

    Prints a one-line summary with TP, FP, NOISE, and unclassified counts.

**Expected Output:**

```bash
$ ./5-triage_queue.sh
[triage] alert_queue: N alerts
[triage] briefing loaded (12 IOCs, 3 change tickets)
[triage] invoking $TRIAGE_BIN
[triage] classifying N alerts
[triage] TP=N FP=N NOISE=N unclassified=0
[triage] triage_log.jsonl written
```

---

# [6. Incident Grouping and Correlation](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/6-correlate_alerts.sh)

## Goal: 

Cluster true-positive alerts into candidate incidents using shared IOCs, hosts, accounts, and temporal proximity.

## Context: 

Alerts are events. Incidents are stories. Grouping collapses a wall of alerts into a small number of investigable cases. The grouping is mechanical and evidence-based, not intuition-based, so a grader can verify the clusters by re-running the same rules.

The clustering rules are fixed so two analysts with the same evidence reach the same grouping. Alerts within 15 minutes on the same host are grouped. Alerts sharing a user account are grouped regardless of host. Alerts sharing a source IP from the IOC feed are grouped. Everything else is a standalone candidate that forms its own incident.

You must produce at least 3 incidents from the TP alerts. If your catalog produced at least 3 TP alerts covering the three planted scenarios, the grouping will yield exactly 3 incidents. If your triage classified too aggressively as NOISE and the TP count is below 3, this task exits non-zero and forces you to re-examine the prior step.

## Instructions: 

Write 6-correlate_alerts.sh that:

    Reads $SHIFT_WORKSPACE/alerts/triage_log.jsonl and extracts all records with classification: "TP".

    Groups TP records by the following clustering rules (applied in order):

    Same host + temporal proximity: two TP alerts on the same host (after hostname normalisation to lowercase) within 15 minutes of each other belong to the same candidate.
    Shared user: two TP alerts with the same non-null user field belong to the same candidate, regardless of host.
    IOC match: two TP alerts where at least one entry in matches_ioc is shared belong to the same candidate.
    Residual: any remaining TP alert not grouped by the above forms its own single-alert candidate.

    Assigns incident IDs in the order candidates surface: INC-YYYYMMDD-A, INC-YYYYMMDD-B, INC-YYYYMMDD-C. Uses today's date in the YYYYMMDD portion.

    Writes $SHIFT_WORKSPACE/alerts/incidents.json:

```json
{
  "shift_id": "string",
  "generated_at": "ISO-8601",
  "incidents": [
    {
      "incident_id": "INC-YYYYMMDD-A",
      "host_list": ["string"],
      "user_list": ["string"],
      "ioc_list": ["string"],
      "alert_ids": ["string"],
      "first_seen": "ISO-8601",
      "last_seen": "ISO-8601",
      "grouping_rule": "temporal | shared_user | ioc_match | residual",
      "tentative_category": "credential_abuse | persistence | c2 | staging | lateral_movement | unknown",
      "confidence": "low | medium | high"
    }
  ],
  "incident_count": 0,
  "unmatched_tp_count": 0
}
```

    Prints a one-line summary per incident and exits non-zero if incident_count is lower than 3.

**Expected Output:**

```bash
$ ./6-correlate_alerts.sh
[group] TP alerts: N
[group] grouping by temporal proximity, shared user, IOC match
[group] INC-YYYYMMDD-A: N alerts  host=hostname-1  rule=temporal
[group] INC-YYYYMMDD-B: N alerts  host=hostname-2  rule=ioc_match
[group] INC-YYYYMMDD-C: N alerts  host=hostname-3  rule=shared_user
[group] incident_count=3
[group] incidents.json written
```

---

# [7. Incident A Deep Investigation (CLI)](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/7-investigate_A.sh)

## Goal: 

Use CLI tools to investigate the first candidate incident end to end and produce a finding conforming to the Locked Finding Schema.

## Context: 

The candidate came out of correlation. Now you build the case. Walk the events chronologically, pivot across sources, confirm the kill chain, map the techniques, write the finding. CLI only for this task: jq for event extraction, yq for rule reading, sha256sum for integrity checks on referenced files.

The IOC feed has already been cross-referenced mechanically in Task 5 and 6. The investigation step is the human work: reading the event chain, forming a hypothesis, checking the hypothesis against the asset inventory, deciding whether the ambiguity in the evidence is resolvable or must be documented. A finding with confidence: "high" must leave no material question open. A finding with lower confidence must document exactly what information would resolve the ambiguity — not vague uncertainty, but a specific question with a specific data source that would answer it.

## Instructions: 

Write 7-investigate_A.sh that:

    Reads $SHIFT_WORKSPACE/alerts/incidents.json and loads the INC-YYYYMMDD-A record. Print the incident summary (host list, alert count, tentative category).

    Pulls all events from $SHIFT_WORKSPACE/enriched/enriched_events.jsonl (or .json) that match any host in the incident's host_list within the time range first_seen - 15min to last_seen + 15min. Print the count.

    Reconstructs the event timeline: sort the matching events by timestamp ascending, extract at minimum the 6 events with the highest analytical significance (authentication events, process events, network events closest to the incident time window). Print each event as a one-liner: TIMESTAMP HOST SOURCE_TYPE EVENT_CATEGORY RAW_MESSAGE[:80].

    Checks every event src_ip and dst_ip against $ASSETS_DIR/ioc_feed.json IOC values. Print each IOC match found.

    Reads $SHIFT_WORKSPACE/enriched/baseline.json (or $SHIFT_WORKSPACE/runtime/baseline_run.json) and checks whether the incident hosts appear in the deviation markers. Print the relevant markers.

    Forms an investigation hypothesis: one sentence describing the attack pattern observed, supported by at minimum 2 ATT&CK technique IDs.

    Writes $SHIFT_WORKSPACE/investigations/incident_A.json conforming to the Locked Finding Schema with interface: "cli". The actions list must contain every jq or yq command executed. The event_refs list must contain at least 6 event IDs from the enriched events file. The attack_techniques list must contain at least 2 technique IDs.

The script exits non-zero if the finding contains fewer than 6 event_refs or fewer than 2 attack_techniques.

**Expected Output:**

```bash
$ ./7-investigate_A.sh
[inv-A] loading INC-YYYYMMDD-A
[inv-A] host_list: hostname-1
[inv-A] events in window: N
[inv-A] timeline (top 6):
  TIMESTAMP  hostname-1  windows_json  authentication  An account failed...
  TIMESTAMP  hostname-1  windows_json  authentication  An account failed...
  TIMESTAMP  hostname-1  windows_json  authentication  Logon successful...
  TIMESTAMP  hostname-1  linux_text    process         new_service installed...
  TIMESTAMP  hostname-1  suricata_alert network_alert  C2 beacon pattern...
  TIMESTAMP  hostname-1  firewall      network         outbound 443 match IOC
[inv-A] ioc_matches: 2 (198.51.100.73, MedSyncHelper)
[inv-A] baseline deviations: 3 markers for hostname-1
[inv-A] hypothesis: service-based persistence installed after credential brute force
[inv-A] techniques: T1110.003 T1543.003 T1071.001
[inv-A] confidence: high
[inv-A] incident_A.json written
```

---

# [8. Incident B Deep Investigation (CLI)](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/8-investigate_B.sh)

## Goal: 

Investigate the second candidate incident and resolve any ambiguity between authorized activity and malicious behavior using change tickets, baseline, and asset context.

## Context: 

Incident B is the ambiguous case. On the surface it looks like it might be covered by an approved change ticket. The change ticket CHG-2026-0341 authorizes disk expansion work on rad-srv-02, but the delegating account (rad_admin_miller) is on annual leave. An activity window that looks like maintenance but is carried out by an account that should not be active is the exact pattern HC-RED7 uses to blend in. You must decide based on evidence what it actually is, and document your reasoning whether or not you settle the question.

The prior shift notes flagged unusual outbound HTTPS from rad-srv-02 to 198.51.100.73. That IP is in the IOC feed. The change ticket does not cover outbound network activity to that destination. These two data points together raise the confidence level. You must document both the ticket match outcome and the IOC match outcome in the finding.

## Instructions: 

Write 8-investigate_B.sh that:

    Loads $SHIFT_WORKSPACE/alerts/incidents.json and extracts the INC-YYYYMMDD-B record.

    Pulls events for every host in the incident's host_list from enriched_events.jsonl in the incident time window (±15 minutes).

    Loads $ASSETS_DIR/change_tickets.json and attempts to match the incident activity:

    Check whether each incident host appears in any active ticket's hosts list.
    Check whether the incident time window overlaps the ticket's approved window.
    Check whether the account identified in the incident matches the ticket owner. Print the outcome of each check: match or mismatch with the specific field that mismatches.

    Checks all outbound destination IPs in the incident events against $ASSETS_DIR/ioc_feed.json. Print each match found with the IOC type and confidence.

    Reads $ASSETS_DIR/assets.json and extracts the criticality and data_classification for each affected host. Print them.

    Forms the investigation hypothesis. If the ticket check produces a mismatch on any field (owner, window, host, or scope), the activity is not covered by the approved change and must be treated as a TP regardless of the partial match. Explains this logic in ambiguity_notes if confidence is not high.

    Writes $SHIFT_WORKSPACE/investigations/incident_B.json conforming to the Locked Finding Schema with interface: "cli". The finding must include:

    ambiguity_notes populated if confidence is "medium" or "low" (empty string if "high")
    At least one matches_ioc value if any IOC hit was found
    A ticket_match_outcome field in event_data (not in the schema proper, but embed it in the actions list narrative)

The script exits non-zero if the finding is missing ambiguity_notes when confidence is not high, or if the ticket match outcome is not documented.

**Expected Output:**

```bash
$ ./8-investigate_B.sh
[inv-B] loading INC-YYYYMMDD-B
[inv-B] host: rad-srv-02 (criticality: HIGH, data_class: RADIOLOGY)
[inv-B] events in window: N
[inv-B] ticket match: CHG-2026-0341 FOUND
[inv-B]   host match:   OK (rad-srv-02 in ticket)
[inv-B]   window match: OK (within approved window)
[inv-B]   owner match:  FAIL (rad_admin_miller — account on leave)
[inv-B]   scope match:  FAIL (outbound 198.51.100.73:443 not in approved activity)
[inv-B] ioc_match: 198.51.100.73 (type: ip, confidence: high, cluster: HC-RED7)
[inv-B] verdict: TP (ticket does not cover observed activity scope or actor)
[inv-B] confidence: high
[inv-B] incident_B.json written
```

---

# [9. Incident C Dual-Interface Investigation (CLI + Wazuh Export)](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/9-investigate_C.sh)
### advanced

## Goal: 

Investigate the third candidate incident through both the CLI pipeline and the pre-exported Wazuh evidence artifacts, and confirm that both interfaces reach the same hypothesis.

## Context: 

In this capstone, the "dashboard" side of the dual-interface investigation uses local Wazuh export files from $WAZUH_EXPORTS/ instead of a live dashboard. The Wazuh exports were generated from the primary evidence pack and represent what an analyst would see in the Wazuh interface for scenarios of this type. The analytical workflow is identical to what 3x04 taught: read the export document, extract the equivalent of a dashboard query result, record the click path from the dashboard trace, compare field names against field_mapping.json.

Both interfaces must converge on the same hypothesis and the same ATT&CK techniques. If they do not, the script exits non-zero and the discrepancy must be resolved before grading. Two independent readings of the same incident from two different vantage points that disagree on technique attribution means one of the readings is wrong.

## Instructions: 

Write 9-investigate_C.sh that:

Part 1 — CLI investigation:

    Loads $SHIFT_WORKSPACE/alerts/incidents.json and extracts the INC-YYYYMMDD-C record.

    Pulls events for incident C hosts from enriched_events.jsonl in the incident time window.

    Reconstructs the timeline, identifies at least 2 ATT&CK techniques, checks the IOC feed, reads baseline deviation markers, and forms a hypothesis.

    Writes $SHIFT_WORKSPACE/investigations/incident_C_cli.json conforming to the Locked Finding Schema with interface: "cli". Requires at least 4 event_refs and at least 2 attack_techniques.

Part 2 — Wazuh export investigation:

    Reads $WAZUH_EXPORTS/incident_C_search_results.json:

    Extracts hits_total, the kql query used, the time range, and the events array.
    For the first 3 events, prints the Wazuh field names and values: @timestamp, _source.agent.name, _source.source.ip, _source.destination.ip, _source.rule.description.
    Reads field_mapping.json (from $HOME/3x04_assets/wazuh_exports/field_mapping.json or $WAZUH_EXPORTS/../3x04_assets/wazuh_exports/) and documents the field name translation for at least 4 fields.

    Reads $WAZUH_EXPORTS/exported_dashboard_workflow.json and extracts the steps list. These steps form the actions list for the export-interface finding.

    Writes $SHIFT_WORKSPACE/investigations/incident_C_export.json conforming to the Locked Finding Schema with interface: "wazuh_export". The actions list must contain the dashboard workflow steps extracted from exported_dashboard_workflow.json. The attack_techniques list must be identical to the CLI finding.

Part 3 — Agreement check:

    Reads both findings and compares:

    attack_techniques lists must contain the same techniques (order-independent).
    hypothesis strings must describe the same attack category (the check is fuzzy: both must contain at least one of the same ATT&CK technique IDs in their attack_techniques lists).
    Exit non-zero if the techniques lists do not overlap.
    Print a per-interface summary and an agreement line.

**Expected Output:**

```bash
$ ./9-investigate_C.sh
[inv-C] loading INC-YYYYMMDD-C
[inv-C] --- CLI investigation ---
[inv-C] events in window: N
[inv-C] cli: techniques=T1021.002,T1053.005 conf=medium
[inv-C] incident_C_cli.json written
[inv-C] --- Wazuh export investigation ---
[inv-C] reading incident_C_search_results.json (hits_total=N)
[inv-C] click path: N steps loaded from exported_dashboard_workflow.json
[inv-C] export: techniques=T1021.002,T1053.005 conf=high
[inv-C] incident_C_export.json written
[inv-C] --- Agreement check ---
[inv-C] techniques match: OK
[inv-C] both findings complete
```

---

# [10. Campaign Correlation](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/10-campaign_correlation.sh)

## Goal: 

Determine whether the three incidents are components of a single campaign linked to HC-RED7, using mechanical rules over counted evidence.

## Context: 

Campaign analysis is not a feeling. It is a counting exercise over shared IOCs, temporal windows, and tactical signatures. The output is a single JSON record that says what you found, counted the way you found it. The rules are fixed so that two analysts with the same evidence reach the same verdict.

The Wazuh export artifacts also provide a campaign-level view: $WAZUH_EXPORTS/campaign_dashboard_summary.md documents what an analyst would see in the Wazuh security events module when correlating the incidents. $WAZUH_EXPORTS/exported_dashboard_workflow.json records the dashboard pivot path used to establish the link. Reading both provides a second evidence view alongside the mechanical rule output.

A campaign is declared campaign_linked: true if at least two of the three incidents are pairwise linked by any of the mechanical rules. The cluster ID is HC-RED7 only if at least one of the linked incidents has a direct feed match. If neither linked incident has a feed match, the cluster is unknown.

## Instructions: 

Write 10-campaign_correlation.sh that:

    Loads the three CLI finding files: incident_A.json, incident_B.json, and incident_C_cli.json (use the CLI finding for this mechanical analysis).

    Loads $ASSETS_DIR/ioc_feed.json and builds a set of all IOC values for fast lookup.

    For each incident, computes the IOC feed match count: how many event_refs reference events whose IP addresses or user accounts appear in the feed.

    Builds a pairwise overlap matrix for all three incident pairs (A-B, A-C, B-C):

    IOC overlap: count of IOC values that appear in both incidents' matches_ioc lists (from incidents.json).
    Tactic overlap: count of ATT&CK techniques shared between the two findings' attack_techniques lists.
    Temporal distance: difference in minutes between the earlier incident's last_seen and the later incident's first_seen (from incidents.json).

    Applies mechanical linkage rules to each pair:

    Shared IOC count >= 1 AND at least one incident in the pair has a direct feed match → linked
    Shared tactic count >= 2 AND temporal distance <= 360 minutes → linked
    Shared user or shared host across the two incidents → linked

    Reads $WAZUH_EXPORTS/campaign_dashboard_summary.md and $WAZUH_EXPORTS/exported_dashboard_workflow.json to extract the export-view campaign verdict. Prints the export view alongside the mechanical result.

    Writes $SHIFT_WORKSPACE/campaign/campaign_assessment.json:

```json
{
  "incidents": ["INC-YYYYMMDD-A", "INC-YYYYMMDD-B", "INC-YYYYMMDD-C"],
  "ioc_overlap_matrix": {"A-B": 0, "A-C": 0, "B-C": 0},
  "tactic_overlap_matrix": {"A-B": 0, "A-C": 0, "B-C": 0},
  "temporal_distance_minutes": {"A-B": 0, "A-C": 0, "B-C": 0},
  "ioc_feed_matches": {"A": 0, "B": 0, "C": 0},
  "linked_pairs": ["A-B"],
  "campaign_linked": true,
  "cluster_id": "HC-RED7 | unknown",
  "confidence": "low | medium | high",
  "export_view_verdict": "string (from campaign_dashboard_summary.md)",
  "supporting_counts": {
    "shared_iocs_total": 0,
    "shared_tactics_total": 0
  }
}
```

**Expected Output:**

```bash
$ ./10-campaign_correlation.sh
[campaign] loading 3 incident findings
[campaign] ioc feed: N IOCs loaded
[campaign] A-B: ioc_overlap=N tactic_overlap=N temporal_dist=Nmin
[campaign] A-C: ioc_overlap=N tactic_overlap=N temporal_dist=Nmin
[campaign] B-C: ioc_overlap=N tactic_overlap=N temporal_dist=Nmin
[campaign] feed matches: A=N B=N C=N
[campaign] linked pairs: A-B (shared_ioc + temporal)
[campaign] export view: campaign_linked=true cluster=HC-RED7
[campaign] verdict: campaign_linked=true cluster=HC-RED7 confidence=high
[campaign] campaign_assessment.json written
```

---

# [11. Incident Reports](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/11-incident_reports.sh)

## Goal: 

Produce one bounded incident report per incident, conforming to the Locked Incident Report Schema with enforced per-section caps.

## Context: 

Reports are the artifacts the rest of the organization reads. If the board sees one page of your shift output, it is this one. The length caps exist because SOC reports are read under time pressure by people who did not work the incident. Every word past the cap is a word the reader skims over on the way to the next page.

All three reports must be generated by the same script. A report generator that requires you to write each report by hand does not scale to a real shift with ten incidents. Your script reads the investigation findings, the incident record, the asset inventory, and the IOC feed to assemble the report content programmatically. The analyst's judgment goes into the findings. The report assembly is mechanical.

## Instructions: 

Write 11-incident_reports.sh that generates $SHIFT_WORKSPACE/reports/incident_A.md, $SHIFT_WORKSPACE/reports/incident_B.md, and $SHIFT_WORKSPACE/reports/incident_C.md.

Each report must follow the Locked Incident Report Schema with these hard caps:

    ## Executive Summary — 3 to 5 sentences
    ## Timeline — at most 15 events, each on one line in format: TIMESTAMP | HOST | EVENT_DESCRIPTION
    ## Affected Assets — at most 10 rows in a Markdown table: HOST | CRITICALITY | DATA_CLASS | ZONE
    ## Indicators of Compromise — at most 15 rows in a Markdown table: TYPE | VALUE | CONFIDENCE | SOURCE; all IP values must be defanged as a[.]b[.]c[.]d
    ## ATT&CK Mapping — at most 8 techniques in a Markdown table: TECHNIQUE | NAME | EVIDENCE
    ## Detection Performance — one line per rule that fired, one line per rule that should have fired but did not (if any)
    ## Recommended Actions — at most 6 numbered actions
    ## Evidence References — at most 12 event IDs, one per line

The script must:

    Read the investigation finding for each incident, the incidents.json record, and the $ASSETS_DIR/assets.json inventory.
    Populate each section from the finding data — do not hardcode any incident-specific values.
    Defang all IP addresses in the report body using sed or python string replacement (a[.]b[.]c[.]d format).
    Count the items in each section and exit non-zero if any cap is exceeded.
    Verify that every event ID in ## Evidence References exists as an event_ref in enriched_events.jsonl. Exit non-zero if any reference is missing.

**Expected Output:**

```bash
$ ./11-incident_reports.sh
[report] generating incident_A.md
[report] A: timeline=N assets=N IOCs=N techniques=N actions=N refs=N
[report] A: section caps respected
[report] generating incident_B.md
[report] B: timeline=N assets=N IOCs=N techniques=N actions=N refs=N
[report] B: section caps respected
[report] generating incident_C.md
[report] C: timeline=N assets=N IOCs=N techniques=N actions=N refs=N
[report] C: section caps respected
[report] N event references verified against enriched_events.jsonl
[report] reports written
```

---

# [12. Detection Gap Analysis and Tuning Recommendations](https://github.com/sreilly1977/dlh-cyber_security/tree/main/blue_team/3x05_the_24_hour_watch/12-tuning_recommendations.sh)
### advanced

## Goal: 

Produce tuning recommendations grounded in counted false positives, missed detections, and rule noise from the shift.

## Context: 

A good shift always produces tuning. Your catalog is not static. The evidence from this shift tells you exactly where to adjust thresholds, add rules, or suppress noise. False positives from approved change activity should produce suppression rules scoped to the change window. Missed detections from incidents you found through investigation but whose alerting rule did not fire are detection gaps that need new or modified rules. Noise rules that fired 30 times on routine activity need threshold adjustments.

Every recommendation must be backed by a counted observation in triage_log.jsonl, incidents.json, or an investigation finding. A recommendation that says "add a rule for T1543.003" with no evidence that you observed T1543.003 activity in this shift is not a recommendation — it is a guess. The machine-readable format ensures that recommendations can be fed back into 3x02 in a future sprint without requiring manual transcription.

## Instructions: 

Write 12-tuning_recommendations.sh that:

    Reads $SHIFT_WORKSPACE/alerts/triage_log.jsonl and computes per-rule FP rate: count of FP classifications divided by total classifications for that rule.

    Identifies rules with FP rate > 0 as rules_with_fp. Identifies rules where every classification was NOISE as rules_with_noise.

    Compares the ATT&CK techniques in all three investigation findings against the alerts_by_rule map in catalog_run.json. Any technique identified in a finding that does not have a corresponding rule match is a detection gap → rules_that_missed.

    Writes $SHIFT_WORKSPACE/response/tuning_recommendations.json:

```json
{
  "shift_id": "string",
  "fp_rate_by_rule": {"rule_id": 0.0},
  "rules_with_fp": ["rule_id"],
  "rules_with_noise": ["rule_id"],
  "rules_that_missed": [
    {
      "expected_behavior": "string (<= 160 chars)",
      "incident_id": "INC-...",
      "missed_because": "threshold | field_mapping | correlation_gap | missing_rule",
      "proposed_fix": "string (<= 240 chars)",
      "estimated_fp_risk": "low | medium | high"
    }
  ],
  "rules_to_suppress": [
    {
      "rule_id": "string",
      "reason": "string (<= 160 chars)",
      "supporting_observation": "alert_id or triage_log line number"
    }
  ],
  "new_rules_proposed": [
    {
      "working_name": "string",
      "logsource_category": "string",
      "detection_sketch": "string (<= 240 chars, pseudocode Sigma detection block)",
      "attack_technique": "Txxxx[.yyy]",
      "estimated_fp_risk": "low | medium | high"
    }
  ]
}
```

Every rules_that_missed entry must cite an incident_id from incidents.json. Every rules_to_suppress entry must cite a supporting_observation from triage_log.jsonl. The script exits non-zero if any entry references a rule that did not appear in catalog_run.json or if any missed_because value is outside the allowed set.

**Expected Output:**

```bash
$ ./12-tuning_recommendations.sh
[tune] triage_log: N alerts (TP=N FP=N NOISE=N)
[tune] rules_with_fp: N (fp_rate > 0)
[tune] rules_with_noise: N (100% noise)
[tune] detection gaps: N (techniques in findings not matched by catalog)
[tune] rules_to_suppress: N
[tune] new_rules_proposed: N
[tune] tuning_recommendations.json written
```

---
