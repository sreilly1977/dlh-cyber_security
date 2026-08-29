# Pipeline Specification

## Overview

The Evidence Pipeline ingests heterogeneous security telemetry (Windows JSON, Linux text logs, network CSV/JSON), normalizes records into a unified event schema, enriches them with asset and network zone context, and outputs a sorted timeline index plus source statistics. The pipeline is invoked via `./evidence_pipeline.sh <evidence-pack-path>` from the `scripts/` directory.

## Stage Table

| Stage | Script | Input | Output | Failure Modes |
|-------|--------|-------|--------|---------------|
| 0 | 0-source_inventory.sh | `<pack>/windows/*`, `<pack>/linux/*`, `<pack>/network/*` | `source_inventory.json` | Missing evidence pack, unreadable files |
| 1 | 1-telemetry_import.sh | Raw source files per inventory | `import_validation.json` | Invalid source origin, encoding errors |
| 2 | 2-windows_parse.sh | Imported Windows NDJSON | `windows_events.json` | Malformed JSON, missing EventID, parse exceptions |
| 3 | 3-linux_parse.sh | Imported Linux text logs | `linux_events.json` | Timestamp format mismatch, multiline auditd failures |
| 5 | 5-normalize.sh | `windows_events.json`, `linux_events.json` | `normalized_events.json` | Unknown timestamp format, type coercion failures |
| 6 | 6-network_normalize.sh | Network CSV/JSON | `network_events.json` | Column misalignment, IP parse errors |
| 7 | 7-schema_validate.sh | `normalized_events.json` | `validation_report.json` | jsonschema library missing, schema mismatch, parse errors |
| 8 | 8-data_quality.sh | Validated events + `quarantine.json` | `cleaned_events.json`, `cleaning_log.json` | Timestamp repair failure, duplicate deduplication errors |
| 9 | 9-enrich.sh | `cleaned_events.json` + context files | `enriched_events.json` | Asset lookup miss, CIDR zone resolution failure |
| 10 | 10-timeline.sh | `enriched_events.json` | `timeline_index.json` | Timestamp sort failure, severity extraction error |
| 11 | 11-source_stats.sh | All event sources | `source_stats.json` | Aggregation overflow, missing metrics |

**Note:** Stage 4 (schema design) is a pre-flight design task, not a pipeline stage. Its output (`event_schema.json`) must exist in the working directory before execution.

## Schema Summary

Reference: `event_schema.json` (custom JSON schema, Draft 7 compatible)

Required fields:
- `timestamp` — ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`)
- `hostname` — Source host identifier (string)
- `source_type` — Origin category (windows_json, linux_text, firewall, suricata, pcap_flow)
- `event_category` — Classification (audit, security, network_alert, powershell, etc.)
- `severity` — Risk level (low, info, medium, high, critical)
- `summary` — Human-readable description
- `event_ref` — Unique identifier (UUID or source-native ID)

Optional fields (13 total): asset.criticality, asset.owner, src_zone, dst_zone, src_ip, dst_ip, process_name, user, command, hash, parent_process, tags, raw_payload

## Inputs and Outputs

**Evidence Pack Layout:**

<pre>
&lt;pack&gt;/
├── windows/*.json              # Windows Event Log NDJSON
├── linux/*.txt                 # auth.log, syslog, auditd (text)
├── network/*.csv               # Firewall/Suricata CSV
├── network/*.json              # PCAP flow records
├── context/assets.csv          # hostname → criticality mapping
├── context/zone_networks.csv   # CIDR → zone mapping
└── student_telemetry/          # Optional supplementary data
</pre>

**Handoff Directory Layout:**

<pre>
&lt;handoff_dir&gt;/
├── scripts/                      # All .sh stage scripts
├── event_schema.json             # Schema definition
├── source_inventory.json         # Stage 0 output
├── import_validation.json        # Stage 1 output
├── windows_events.json           # Stage 2 output
├── linux_events.json             # Stage 3 output
├── normalized_events.json        # Stage 5 output
├── network_events.json           # Stage 6 output
├── validation_report.json        # Stage 7 output
├── quarantine.json               # Quarantined invalid records
├── cleaned_events.json           # Stage 8 output
├── cleaning_log.json             # Stage 8 cleaning log
├── enriched_events.json          # Stage 9 output
├── timeline_index.json           # Stage 10 output
├── source_stats.json             # Stage 11 output
├── pipeline_run.log              # Execution log
├── pipeline_test_report.json     # Generalization test report
└── pipeline_spec.md              # This document
</pre>

## Running the Pipeline

**Primary pack execution:**

<pre>
./evidence_pipeline.sh ~/evidence_pack_primary/
</pre>

**Generalization test (secondary pack):**

<pre>
./13-pipeline_test.sh
</pre>

Both commands exit 0 on success, non-zero on failure. The pipeline writes all stage output to `pipeline_run.log`. The generalization test writes captured output to `test_output/` and a structured report to `pipeline_test_report.json`.

## Known Limitations

- Requires Python 3 with `jsonschema` library installed (`pip install --user jsonschema`)
- Timestamp normalization limited to ISO 8601, Unix epoch, and MM/DD/YYYY HH:MM:SS formats
- CIDR zone lookup requires `/24` or larger prefixes; smaller subnets may misclassify
- Enrichment coverage limited to assets defined in `context/assets.csv` (unmapped hosts get "unknown" criticality)
- Pipeline runs sequentially with fail-fast semantics; no parallel stage execution supported
