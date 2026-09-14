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

```jason
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

```jason
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
