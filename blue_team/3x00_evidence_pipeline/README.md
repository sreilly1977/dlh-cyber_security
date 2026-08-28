# Introduction

>"Before you can find the needle, you have to build the haystack you can actually search." 
>
> - SOC engineering proverb

The SOC runs on data. Not dashboards. Not alerts. Not war rooms. Data. Every detection rule, every hunt query, every triage decision, every incident timeline is built on top of a pile of raw events that somebody, at some point, had to collect, parse, normalize, clean, and enrich before any of it could be useful. That somebody is you this week.

MedDefense is in the middle of a platform migration. For the next 48 hours the centralized SIEM is offline. Telemetry is still being produced by every endpoint, every firewall, every network sensor, but there is no platform to catch it. Exports are being dropped into a shared directory in whatever format the source system happens to produce: EVTX files from Windows, plain syslog from Linux, JSON blobs from Suricata, CSV exports from the firewall. Raw, inconsistent, duplicated, incomplete, and arriving faster than anyone can read.

Your mission is to build the pipeline that turns this flood of raw exports into analyst-ready evidence. You will inventory sources, parse six different formats into structured JSON, design the unified schema that every downstream project in this module will consume, normalize, validate, clean the dirty data that real-world logging always produces, enrich events with asset and network context, index everything into a chronological timeline, and wrap the whole thing into a reproducible pipeline script that a new analyst can run with a single command.

This project is the foundation of Module 3. Every line of data that 3x01 analyzes, every detection rule that 3x02 runs, every alert that 3x03 triages, every SIEM query that 3x04 executes, is data you shaped here. Get this wrong and everything downstream breaks. Get it right and the rest of the module becomes a series of focused exercises instead of an ongoing fight with malformed data.

## Why this matters

The glamorous part of the SOC is the investigation. The invisible part is the pipeline behind it. Real incident postmortems almost always include a sentence like "the data was there but we could not correlate it" or "the timestamps did not line up across sources" or "the field we needed was dropped during normalization." These are not analyst failures. They are pipeline failures. The reason senior detection engineers and SOC architects are paid more than junior analysts is that they understand how data moves from source to search, and they know that every detection rule is only as good as the record it runs against.

This project teaches you to think like a data engineer with a security brain. You will not deploy a SIEM. You will do the work that a SIEM does under the hood, by hand, in scripts you wrote yourself. When you later query a production Wazuh or Splunk or Sentinel instance and something does not behave the way you expect, you will know exactly which stage of the pipeline is lying to you, and you will know how to fix it.

## Context

You are currently working as a SOC Analyst for MedDefense Health Systems.

### The Scenario: "48 Hours Without a Platform"

**FROM:** James Chen, SOC Lead - MedDefense Health Systems

**TO:** SOC Analyst (You)

**SUBJECT:** SIEM migration window. We need a bridge.

**PRIORITY:** High

Good morning, and welcome to Module 3. You finished your Module 2 work on Friday. Your hardened endpoints are running. Your student_telemetry/ package has been staged inside the primary evidence pack on your workstation. Normally you would hand that directory to our SIEM and the ingestion layer would do the rest.

We do not have that luxury this week.

Infrastructure is migrating our Wazuh stack to a new dedicated cluster. The migration window is 48 hours starting now. During that window, the SOC has no centralized platform. Endpoints are still producing telemetry. Sarah Park negotiated a shared directory where every source system is dropping raw exports every 15 minutes. Right now it contains multiple different formats from five different sources, nobody has touched it, and I have a pile of investigation requests that cannot wait until Wednesday.

I need you to build an evidence pipeline. Start from the raw exports. Parse them. Normalize them into a single schema you design yourself. Clean the dirty records that always come with real logs. Enrich every event with asset context so I can tell at a glance whether a given alert hit a critical system or a test box. Index the whole thing into a timeline my Tier 1 team can actually read. Wrap it into a pipeline script that runs end to end with one command, because by Wednesday I want to be able to rerun the whole thing against a fresh drop in under five minutes.

Your Module 2 student_telemetry/ is already staged at ~/evidence_pack_primary/student_telemetry/. Treat it as one more source on top of the baseline evidence pack Infrastructure left you. The primary evidence pack is at ~/evidence_pack_primary/ on your workstation.

One more thing. Robert Kim wants the pipeline specification, not a novel. Two pages, stages in, stages out, failure modes. If anyone on my team cannot read the spec and rebuild the pipeline from it, the spec is wrong.

Get this right. Everything we do for the next four weeks runs on what you build today.

-- James Chen

---

# [0. Evidence Pack Inventory](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/0-source_inventory.sh)

## Goal: 

Inventory every source file in the primary evidence pack and produce a structured manifest of what you have to work with.

## Context: 

Before you parse anything, you need to know what you received. Real evidence drops are never what the cover email says they are. Files are missing, names are misspelled, exports are truncated, timezones are wrong. The first job of the pipeline is to tell you, loudly and in a machine-readable format, exactly what arrived. Every subsequent stage reads this manifest instead of walking the filesystem.

## Instructions: 

Write a script 0-source_inventory.sh that walks ~/evidence_pack_primary/ and produces source_inventory.json. For each file found under windows/, linux/, and network/, record:

    path relative to the evidence pack root

    source_type (one of windows_json, linux_text, network_csv, network_json)

    size_bytes

    sha256 hash

    line_count or record_count depending on format

    first_event_time and last_event_time extracted from the file (best effort per format)

The script must also print a human-readable summary to stdout listing the total number of files per category and the combined byte count.

Note: The Windows event logs are pre-exported JSON files (NDJSON format). Use source_type: windows_json for them. No EVTX conversion is required.

**Expected Output:**

```bash
$ ./0-source_inventory.sh
windows : 3 files  |  62.0 MB
linux   : 3 files  |  17.2 MB
network : 3 files  |   6.5 MB
total   : 9 files  |  85.7 MB
manifest written to source_inventory.json
```

---

# [1. Telemetry Import](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/1-telemetry_import.sh)
### advanced

## Goal: 

Validate the pre-staged student telemetry files and confirm they meet the data contract before they are merged into the pipeline.

## Context: 

Your Module 2 telemetry has already been staged at ~/evidence_pack_primary/student_telemetry/. Before treating it as pipeline input, you must validate that it arrived intact and conforms to the expected schema. If you trust it blindly and it turns out to be malformed, every downstream stage inherits the corruption. This task validates the telemetry against the contract the pipeline expects, then writes a machine-readable report. Any mismatch is reported and the script exits non-zero so the pipeline stops before bad data propagates.

## Instructions: Write a script 1-telemetry_import.sh that:

    Locates the telemetry directory at ~/evidence_pack_primary/student_telemetry/

    Confirms the three required files exist: windows_events.json, linux_events.json, attack_ground_truth.json

    Validates each file is parseable JSON and contains at least one record

    Checks that every record in windows_events.json and linux_events.json has the four required fields: timestamp, hostname, source_type, event_category

    Writes import_validation.json with per-file pass or fail, record counts, and the list of unique source_type values observed

The script must exit with code 0 on full pass and 1 on any failure.

**Expected Output:**

```bash
$ ./1-telemetry_import.sh
[OK] windows_events.json    1859 records    sources: Security, Sysmon
[OK] linux_events.json      1879 records    sources: auditd, auth
[OK] attack_ground_truth.json  12 records
3/3 files validated. Import OK.
```

---

# [2. Windows Event Parsing](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/2-windows_parse.sh)

## Goal: 

Merge the three Windows JSON source files into a single combined intermediate file, appending student telemetry, ready for normalization.

## Context: 

The Windows event logs are provided as pre-exported NDJSON files (one JSON object per line). Each file covers a different event channel: security.json (4625, 4624, 4720, etc.), sysmon.json (process creation, network connections, etc.), and powershell.json (script block logging). This stage merges all three into a single windows_events.json file and appends the student telemetry windows events. Every record already contains timestamp_raw, hostname, event_id, channel, provider, raw_message, event_data, and source_origin: "evidence_pack". Student telemetry records must be tagged with source_origin: "student_telemetry" if not already set.

## Instructions: 

Write a script 2-windows_parse.sh that reads security.json, sysmon.json, and powershell.json from ~/evidence_pack_primary/windows/ and produces windows_events.json as a newline-delimited JSON file with one record per line. The script must:

    Read each of the three JSON files from ~/evidence_pack_primary/windows/

    Ensure each record contains at minimum: timestamp_raw, hostname, event_id, channel, provider, raw_message, event_data, source_origin

    Set source_origin: "evidence_pack" for records from the windows/ directory (it is already set in the files; verify and preserve it)

    Read ~/evidence_pack_primary/student_telemetry/windows_events.json and append those records tagged with source_origin: "student_telemetry" if not already set

    Write the combined output to windows_events.json

    Print per-file record counts and a total

**Expected Output:**

```bash
$ ./2-windows_parse.sh
reading security.json      ... 38498 records
reading sysmon.json        ... 72810 records
reading powershell.json    ...  9408 records
appending student telemetry ... 1859 records
windows_events.json: 122575 records
```

---

# [3. Linux Log Parsing](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/3-linux_parse.sh)

## Goal: 

Parse auth.log, audit.log, and syslog into structured JSON records with consistent intermediate fields.

## Context: 

Unlike the pre-parsed Windows files, Linux logs are plain text with three different grammars. auth.log uses syslog format, audit.log uses the auditd type=... key-value format, and syslog mixes both. Each grammar needs its own parser, but the output shape must match the Windows intermediate so the normalization stage can treat them uniformly.

## Instructions: 

Write a script 3-linux_parse.sh (bash plus Python is fine) that reads ~/evidence_pack_primary/linux/auth.log, audit.log, and syslog and produces linux_events.json as newline-delimited JSON. Each record must contain at minimum:

    timestamp_raw (original timestamp string)

    hostname

    program (for auth.log and syslog) or audit_type (for auditd)

    pid if present

    user if present

    raw_message (the full original line)

    parsed_fields (object containing the key-value pairs extracted from the line)

    source_origin: "evidence_pack"

Your student telemetry linux_events.json from ~/evidence_pack_primary/student_telemetry/ must also be appended to the output, tagged with source_origin: "student_telemetry".

Hint: auditd records can span multiple lines sharing the same msg=audit(...) timestamp. Group them before emitting a single record, or emit one record per line and flag the group in parsed_fields.audit_group_id.

**Expected Output:**

```bash
$ ./3-linux_parse.sh
parsing auth.log      ... 24880 lines  -> ~24880 records
parsing audit.log     ... 67368 lines  -> ~50000 records (grouped)
parsing syslog        ... 41736 lines  -> ~41736 records
appending student telemetry ... 1879 records
linux_events.json: written
```

---

# [4. Unified Event Schema Design](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/event_schema.json)

## Goal: 

Design and justify the unified event schema that every source in the pipeline will be normalized into.

## Context: 

Every downstream project in Module 3 reads events produced by this pipeline. If your schema is missing a field, 3x02 cannot write a detection rule that looks at it. If your schema collapses two distinct concepts into one field, 3x03 analysts cannot tell them apart during triage. This is the single most consequential design decision in the module. Make it carefully and commit to it.

## Instructions: 

Produce event_schema.json containing your unified schema definition. The schema must be a JSON document with the following top-level structure:

    version (string, your schema version)

    author (string, your name)

    fields (array of field definitions)

Each field definition must contain:

    name (the field name as it appears in a normalized record)

    type (one of string, integer, float, boolean, timestamp, object, array)

    required (boolean)

    description (one sentence explaining what the field represents)

    justification (one sentence explaining why this field exists in the schema, what downstream question it answers)

    source_mapping (object mapping each source type to the intermediate field it is derived from, or null if derived)

Your schema must include at minimum: timestamp, hostname, source_type, event_category, severity, user, process_name, src_ip, dst_ip, raw_message. You are expected to add additional fields as you see fit and to justify every single one.

Note: this is the only task in this project where written justification is graded. Keep each justification to a single sentence. No essays.

**Expected Output:**

A valid JSON file. Example of one field definition:

```json
{
  "name": "event_category",
  "type": "string",
  "required": true,
  "description": "High-level category of the event such as authentication, process, file, network, or audit",
  "justification": "Needed by 3x02 detection rules and 3x03 triage filters to group events independently of source vendor",
  "source_mapping": {
    "windows_json": "channel + event_id mapping table",
    "linux_text": "program or audit_type mapping table",
    "network_csv": "constant: network"
  }
}
```

---

# [5. Normalization Script](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/5-normalize.sh)

## Goal: 

Transform the Windows and Linux intermediate JSON files into a single normalized dataset that conforms to the schema you designed.

## Context: 

This is where the pipeline stops speaking raw log grammar and starts speaking your schema. Downstream tasks never touch the intermediate files again. Every field in every record must be mapped, every missing optional field must be explicitly null (not absent), and every required field must be populated or the record must be flagged for quarantine.

## Instructions: 

Write a script 5-normalize.sh (or a Python equivalent) that:

    Reads windows_events.json and linux_events.json from the working directory

    For each record, emits a normalized record conforming to event_schema.json

    Applies the field mappings declared in your schema

    Converts timestamp_raw to ISO 8601 UTC in the timestamp field

    Writes the combined normalized dataset to normalized_events.json as newline-delimited JSON

    Writes any records that cannot be normalized (missing required fields, unparseable timestamp) to quarantine.json with a quarantine_reason field

The script must print per-source counts of normalized and quarantined records.

**Expected Output:**

```bash
$ ./5-normalize.sh
windows_json     : normalized    0 quarantined
linux_text       : normalized    0 quarantined
total            : normalized    quarantined
normalized_events.json written
quarantine.json  written
```

---

# [6. Network Artifact Normalization](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/6-network_normalize.sh)

## Goal: 

Ingest the firewall CSV, Suricata EVE JSON, and PCAP summary, and normalize them into the same unified schema.

## Context: 

Network telemetry is the third leg of the pipeline. Each of the three network sources has its own format and its own idea of what a "timestamp" and a "host" mean. The firewall CSV uses Unix epoch seconds, Suricata uses ISO 8601 with microseconds, the PCAP summary uses human-readable localized strings. They all end up as records with the same schema as the endpoint events so the analyst can pivot from a process event to a network event without changing tools.

## Instructions: 

Write a script 6-network_normalize.sh that:

    Reads firewall.csv, suricata_eve.json, and pcap_summary.json from ~/evidence_pack_primary/network/

    Parses each source into records

    Normalizes each record to the unified schema

    Appends the resulting records to normalized_events.json

    Also writes a standalone network_events.json containing only the network records

For firewall events, event_category should be network, source_type should be firewall, and the action field should preserve ALLOW or BLOCK. For Suricata, event_category should be network_alert and the signature and severity fields should be populated. For PCAP summaries, event_category should be network_flow.

Note on formats:

    firewall.csv: Unix epoch timestamp in first column, header row: timestamp,src_ip,src_port,dst_ip,dst_port,protocol,action,interface,rule_id,bytes_in,bytes_out
    suricata_eve.json: NDJSON, timestamp field in ISO 8601+TZ format, alert details under alert.signature
    pcap_summary.json: NDJSON, start_time and end_time in MM/DD/YYYY HH:MM:SS AM/PM format

**Expected Output:**

```bash
$ ./6-network_normalize.sh
firewall.csv        :  ~67547 records normalized
suricata_eve.json   :   ~9977 records normalized
pcap_summary.json   :   ~4096 records normalized
appended to normalized_events.json
network_events.json written
```

---

# [7. Schema Validation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/3x00_evidence_pipeline/7-schema_validate.sh)
### advanced

## Goal: 

Validate every record in the normalized dataset against the schema you designed and produce a machine-readable compliance report.

## Context: 

A schema is a contract. A normalization script that produces records that violate the contract is a bug. This task is the automated check that catches that bug before the bad data reaches 3x02. Run it every time normalization changes.

## Instructions: 

Write a script 7-schema_validate.sh that:

    Reads event_schema.json and normalized_events.json

    For every record, checks that every required field is present and has a non-null value

    For every field, checks that the value matches the declared type

    Counts compliant records, non-compliant records, and per-field completeness percentage across the dataset

    Writes validation_report.json containing overall counts, per-field completeness, and up to 20 example non-compliant records with the reason

The script must exit with code 0 if compliance is above 99 percent and 1 otherwise.

**Expected Output:**

```bash
$ ./7-schema_validate.sh
records checked       : <total>
fully compliant       : <N> (>99%)
non-compliant         : <N>
per-field completeness:
  timestamp      100.00%
  hostname        99.xx%
  source_type    100.00%
  event_category 100.00%
validation_report.json written
```

---
