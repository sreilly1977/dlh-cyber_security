# MedDefense Detection Engineering Specification

## Purpose

This document defines the contract of MedDefense's detection layer: how rules are authored, executed, measured, tuned, and ranked before they reach the triage queue. It is the reference for any engineer joining the SOC and the acceptance basis for rule changes.

## Inputs

- Evidence (normalized): `$HANDOFF_DIR/data/normalized_events.json` — lacked enriched fields (zones, labels, asset.*) during development; labeled dataset used instead.
- Evidence (labeled): `$BASELINE_PKG/labeled_events.json` — 270,735 NDJSON records, 2026-03-17 to 2026-03-27.
- Baselines: `$BASELINE_PKG/baseline_summary.json`, `baselines/baseline_process.json`, `baselines/baseline_network.json`.
- Assets and allowlists: `$ASSETS_DIR/risk_register.json` (`RISK_REGISTER`), `attack_taxonomy.json`.
- Environment resolution: `source ~/m3_env.sh`; `ASSETS_DIR`, `HANDOFF_DIR`, `BASELINE_PKG`, `CATALOG_DIR` resolve all paths.

## Rule Authoring Standard

Rules are Sigma YAML, numbered `NNN_snake_case_description.yml` in `rules/sigma/`; tuned variants share the filename under `rules/sigma/tuned/`. Required fields: `title`, `id` (UUID), `status`, `description`, `references`, `author`, `date`, `tags`, `logsource`, `detection`, `falsepositives`, `level`. ATT&CK tags (`attack.tXXXX[.YYY]`) are mandatory on every rule; tags drive the coverage report and risk ranking. Names must describe behavior, not product.

## Execution Model

`3-sigma_runner.sh rule.yml [evidence] [--dry-run|--count-only|--preprocess|--window START,END]` executes rules over NDJSON evidence. Rules referencing labeled-only fields (canonical_label, src_zone, dst_zone, shift_hour_match, asset.*) trigger automatic evidence substitution to the labeled dataset. The runner derives helper fields (hour_of_day, parent_process_name, whitelist membership) and supports count aggregation with timeframe windows. Correlation rules (e.g. 010) consume primitives from `8-correlation_primitives.py` via `--preprocess`. Evaluation window: 2026-03-24T00:00Z onward; baseline window is the preceding 7 days. Match lists truncate at 10,000; `--count-only` counts are uncapped.

## Quality Thresholds

`13-rule_quality.sh` scores each rule against tier-2 attack-narrative ground truth on the evaluation window. A rule ships only if: precision ≥ 0.5, recall measurable against its scoped ground-truth labels, F1 computable, and baseline-window false positives ≤ 100 (fp_baseline.json). Tripwire rules (intentionally 0-match, e.g. 004, 011) are exempt from recall gates but must remain fp=0. Degenerate rules (all-TP or all-FP) are flagged, not auto-passed.

## Tuning Protocol

Rules exceeding the fp gate enter `11-tune_rules.sh`: a tuned variant is authored (deeper time bands, destination allowlists, service-account exclusions, zone filters) and validated against both windows. Acceptance requires fp reduction meeting the halving bar AND no loss of true-positive matches vs the base rule. On a fleet where benign traffic dominates by three orders of magnitude, match-volume retention is the measurable proxy for recall — this limitation is documented in tuning_report.json. Rejected variants remain in tuned/ for review but do not supersede the base rule.

## Risk Ranking Model

`14-rule_prioritization.sh` intersects each rule's ATT&CK tags with the risk register's threat scenarios (hierarchical, case-insensitive match; parent techniques cover sub-techniques). `risk_score` = Σ (likelihood × impact) over covering scenarios, scaled likelihood {low:1, medium:2, high:3} and impact {low:1 … critical:4}. `priority_score = risk_score × F1`, floored at `risk_score × 0.1` for zero-F1 rules. Rules matching no scenario are flagged as orphans — detection work that does not map to MedDefense risk.

## Outputs

`15-generate_alerts.sh` produces `alert_queue.json`: a priority-sorted array of alerts, each carrying alert_id (deterministic uuid5 of rule_id + event_ref), event_ref, event_summary, asset_context, attack_techniques, evidence_hash (sha256 of the source record), and dedup counts (60-second window on rule_id/hostname/user). `alert_queue_schema.json` fixes the field contract consumed by 3x03 Triage Shift. `16-detection_catalog.sh` packages the locked catalog layout with a sha256 MANIFEST.

## Failure Modes

1. **Missing correlation primitives** — rules using `--preprocess` fail at startup. Symptom: immediate runner exit. Fix: regenerate `correlation_primitives.json` via `8-correlation_primitives.py`.
2. **Evidence substitution mismatch** — a rule selecting labeled-only fields runs against the smaller schema; fields vanish silently except for a stderr NOTE. Symptom: unexpectedly low or zero match counts.
3. **Truncated match lists** — high-volume rules silently cap at 10,000 matches. Symptom: alert queue shorter than `--count-only` totals; verify counts before shipping.
4. **Allowlist drift** — fail-closed allowlists (lateral movement, clinical access) silently drop legitimate-service alerts when asset inventory changes.

## Reviewer Checklist

- [ ] Sigma validates (`sigma check`), shellcheck-clean tooling
- [ ] ATT&CK tags present and map to the taxonomy
- [ ] Counts verified on both baseline and evaluation windows (`--count-only`)
- [ ] Precision/recall/F1 computed; meets shipping gates
- [ ] Tuned variant (if any) accepted by 11-tune_rules.sh criteria
- [ ] Priority score present in rule_prioritization.json; orphan status reviewed
- [ ] Evidence refs resolve in the alert queue; hashes verify
