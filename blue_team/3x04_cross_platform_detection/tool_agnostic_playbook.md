# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose

This playbook defines the standard investigation workflow for MedDefense SOC analysts, executable on any SIEM or analysis platform. It separates the durable workflow from the perishable tooling so that platform migrations require no rewrite.

## Scope

Covers single-host and single-indicator investigations arising from alerts, hunt hypotheses, or escalated triage tickets: authentication abuse, credential theft chains, off-hours insider activity, and medical-device egress. Does not cover incident response containment, malware reverse engineering, forensically sound evidence collection, or long-term threat intelligence operations. Escalate those to Tier 2 or IR per the triage methodology (3x03).

## Inputs

The analyst must have access to the six locked artifacts:

1. **Enriched events** — the NDJSON evidence stream (never slurped whole; always streamed with filters).
2. **Asset inventory** — host classification, owner, and zone per hostname.
3. **Baseline** — behavioral norms per asset class (3x01 package).
4. **Detection catalog** — Sigma rules, runner contract, and correlation primitives (3x02 package).
5. **Triage package** — methodology and prior triage decisions (3x03 package).
6. **IOC context** — indicator reputation, actor attribution, and geolocation.

## Workflow Steps

Each step lists the CLI path and the dashboard/export path side by side. Record every action; the finding's action list is capped at 20.

| # | Step | CLI path | Export / dashboard path |
|---|------|----------|-------------------------|
| 1 | Frame the hypothesis | State it in one sentence; write it before querying | Type it into the finding draft first |
| 2 | Scope by host, IP, and window | `jq -c 'select(...)' \| wc -l` over the stream | Filter bar: `agent.name:"host" AND winlog.event_id:(...)` in Discover |
| 3 | Capture event refs | Collect `_id`s per matching event | Read `_id`s from the export document set |
| 4 | Enrich context | Join asset_inventory, zones, and IOC context in jq | Use `agent.labels`, `source.zone`; fall back to asset inventory where labels are absent |
| 5 | Analyze behavior | Interval math (`strptime`/`mktime`), byte totals, sequence chains (EID ordering) | Inspect rendered timeline and document fields |
| 6 | Map to MITRE | Tag techniques from the observed chain; cross-check detection catalog | Same; use rule metadata where present |
| 7 | Cross-validate | Recompute counts from raw evidence; compare against the export | Compare export count against a raw recount |
| 8 | File the finding | Emit JSON to the locked schema, validated | Fill the same schema from the dashboard side |

## Field Name Translation Table

Normalized schema to Wazuh (ECS) field names:

| Normalized | Wazuh |
|------------|-------|
| hostname | agent.name |
| src_ip | source.ip |
| dst_ip | destination.ip |
| user | user.name |
| event_id | winlog.event_id |
| event_ref | _id |
| timestamp | @timestamp |
| zone | source.zone |
| process / command_line | process.command_line (in full_log where absent) |
| bytes_out | null — reconstruct from full_log |

## Query Decomposition Rule

Every investigative query decomposes into three parts. Build them separately, then combine.

1. **Filter.** The predicate selecting events: jq `select()`; Sigma `selection`/`condition`; KQL `field:"value" AND ...`; Lucene `field:value AND ...`.
2. **Aggregation.** The computation over the filtered set: jq `group_by`/`add`/`unique`; Sigma count-based conditions (`frequency`, `|gte`); KQL `summarize` (where supported) or count in the UI; Lucene count endpoint `_count` or the hits total.
3. **Time window.** The bounding interval: jq timestamp comparison (`>= start and <= end`); Sigma runner `--window`; KQL/Lucene the dashboard time picker (half-open `[start, end)` — mind boundary events).

Express the same question in all four languages before trusting any one answer; a genuine dialect divergence is data, not an error.

## Finding Schema

Short form; all 13 locked keys required:

- `finding_id` — `scenario_id` + `_` + `interface`
- `scenario_id` — `anchor`, `scenario_a`, `scenario_b`, `scenario_c`
- `interface` — `cli` or `wazuh_export`
- `hypothesis` — one sentence, stated before querying
- `actions` — ordered list, max 20
- `time_to_first_answer_seconds` — integer, UTC-clock derived
- `event_refs` — list of evidence `_id`s
- `fields_touched` — list of fields examined
- `attack_techniques` — MITRE ATT&CK IDs
- `confidence` — `low`, `medium`, `high`
- remaining three keys per the Requirements locklist (timestamps, conclusion, evidence source)

## Exit Criteria

An investigation is complete and ready for a finding when: the event set is fully enumerated with refs recorded; every count is reproducible from raw evidence; the hypothesis is confirmed, refuted, or explicitly inconclusive; techniques are tagged; and the schema validates.

## Known Pitfalls

1. Wazuh export leaf fields carry the `_source.` prefix — strip it with `ltrimstr("_source.")` before joining.
2. Dashboard exports are single JSON objects entered via `.events`, not arrays or NDJSON; blind `jq -s` matches nothing.
3. Export windows can omit boundary events — the anchor pair counted 47 exported against 48 in the raw stream; treat exports as possibly incomplete.
4. Enrichment gaps in `agent.labels` (e.g., missing `data_classification`) force fallback joins; record them as extra actions.
5. Numeric fields such as `bytes_out` arrive null in exports — reconstruct from `full_log` via the raw stream.
6. Tool-generated prose can contradict the underlying data; always recompute intervals and byte totals from events.
