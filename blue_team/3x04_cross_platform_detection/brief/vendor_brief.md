# MedDefense Interface Evaluation Brief v1

## Purpose

This brief recommends the primary analyst interface for MedDefense SOC investigations, based on counted evidence from the March 2026 evaluation week. It is written for Dr. Morales's decision and the compliance audit folder.

## Evaluation Methodology

Four scenarios were investigated: the anchor SSH brute force against db-patient-01 (203.0.113.41-44, 2026-03-25), plus three scripted intrusions covering credential theft on clin-ws-12, off-hours PHI access on clin-ws-07, and medical-device egress from med-mri-02. Each scenario was investigated twice: once via CLI streaming over enriched_events.json (270,735 events, ~264 MB NDJSON), and once via pre-computed Wazuh dashboard exports (index meddefense-evidence-2026-03). This produced eight schema-validated findings. Metrics were recorded per finding: time to first answer, action count, fields touched, event references, and confidence. Aggregation is mechanical and reproducible (workflow_comparison.json). Interface advantages are attributed to counted causes (tradeoff_table.json). Query equivalence was separately tested across jq, Sigma, KQL, and Lucene (query_comparison.json). Rule portability was tested by translating three Sigma rules to Wazuh XML, all validating (translation_report.json: counts 28/3/0).

## Findings Summary

From workflow_comparison.json (8 findings, 4 per interface):

- **CLI:** 97s total time to first answer; avg 24.25s; median 24s; 28 actions; 108 fields touched; 75 event refs.
- **Wazuh export:** 2s total; avg 0.5s; median 0.5s; 30 actions; 134 fields touched; 74 event refs.
- Per-scenario deltas (export minus CLI): anchor -24s, scenario_a -24s, scenario_b -23s, scenario_c -24s; the export was faster in all four.
- Confidence: high=3, medium=1, low=0 for both interfaces. The interfaces converge on the same conclusions; they differ in effort, not outcome.

## Strengths and Weaknesses per Interface

**Wazuh dashboard/export.** Its counted advantage is speed with zero context loss on the happy path: filter_bar_efficiency carried the anchor and scenario_b wins (pre-computed query artifacts answered in about 1s against 24s CLI stream passes), and native_field_surface carried scenario_a and scenario_c (rule.description, process.name, and source.zone available per document, eliminating the zone join entirely). Its counted weaknesses: a wider evidence surface to normalize (134 fields touched vs 108), a higher action total (30 vs 28, driven by scenario_b's two-step fallback when agent.labels lacked data_classification), and non-reproducibility — the export answer is frozen at artifact-generation time and omitted one boundary event the raw stream contained (47 vs 48 on the anchor).

**CLI.** Its counted strengths are reproducibility and expressiveness: every investigation reruns deterministically against raw evidence (counter-advantage on the anchor), a single jq join absorbed the missing classification label (counter-advantage on scenario_b), and only the raw stream could perform scenario_c's 12-minute interval math and byte totals because bytes_out is null in the export documents (counter-advantage on scenario_c). Its counted weakness is uniform latency: roughly 24s per full stream pass on this evidence volume, against fractions of a second for pre-computed exports, and it exposes no timeline visualization.

## Recommendation

MedDefense should adopt the Wazuh dashboard as the primary analyst interface. The CLI stream should be used whenever counts must be independently reproduced for compliance, when enrichment gaps require joins (classification, zone), and when behavioral analysis needs interval arithmetic or byte accounting the export fields cannot carry.

## Operational Risks of Being Wrong

1. **Wrong primary (CLI chosen):** every Tier 1 investigation pays the ~24s stream pass plus query-building overhead; at an estimated 40 investigations/week that is roughly 2.5 analyst hours per week lost, before counting transcription errors from manual query maintenance.
2. **Wrong primary (dashboard chosen without CLI verification):** export truncation and boundary omissions (anchor: 47 vs 48) and enrichment gaps could produce under-counted findings; correcting one mis-scoped finding after the fact costs an estimated 1-2 analyst hours per occurrence, roughly 1.5 hours per week at current alert volume.
3. **Dialect drift unmanaged:** query languages that agreed in testing diverged by an order of magnitude in one case (Q2: 798 vs 55); unverified re-expressions during an incident could mislead triage at an estimated 0.5-1 hour per week in re-running and reconciling queries.

## Security+ 4.7 Considerations

The dashboard-primary recommendation favors efficiency and scaling — pre-computed answers reuse automated indexing work, avoiding repeated full-stream passes — while the CLI retains the complex, high-expressiveness work where orchestration cannot yet substitute for judgment. Choosing the dashboard alone would accumulate technical debt in unverifiable answers; keeping the CLI as the secondary preserves automation gains without abandoning reproducibility or deferring cost to future staffing.

## Next Steps

1. **Detection engineering:** extend the correlation primitive set to cover the Q2 dialect divergence; add a regression check that re-expresses one production query in all four languages per sprint.
2. **Detection engineering:** adopt the translated Wazuh rules (001, 003, 010) with their documented deltas (28/3/0 provenance) into a staged rollout.
3. **Compliance:** validate the finding schema and export completeness boundary (47 vs 48) against audit requirements before certification.
4. **Compliance:** file this brief, the manifest, and the playbook in the audit folder with sha256 verification.
5. **SOC manager:** schedule Tier 1 training on the playbook and its known pitfalls; staff a CLI-capable secondary rotation for cross-validation duties.
