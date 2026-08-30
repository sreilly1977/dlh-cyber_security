# Learning Objectives

---

## Evidence Pipeline

---

### Evidence Engineering

**Q: What is an evidence pipeline and what are its stages?** 

**A**: An evidence pipeline is an automated workflow that ingests raw logs through intake, parsing, normalization, cleaning, enrichment, indexing, and validation to transform chaotic data into actionable intelligence.

**Q: How do raw log exports from Windows, Linux, and network devices differ structurally?**

**A:** They differ in format (EventXML vs syslog vs binary), field naming conventions, timestamp standards, and severity levels, requiring reconciliation to enable cross-platform correlation.

**Q: What is a unified event schema and how are fields justified?**

**A:** A unified event schema is a standardized data model where required fields ensure core investigative utility (like timestamps and source IPs) while optional fields preserve source-specific context for deep dives.

**Q: Why is data normalization a trade-off between fidelity and searchability?**

**A:** Normalization sacrifices granular, vendor-specific details to create consistent, searchable fields, which can obscure unique attack indicators hidden in proprietary log structures.

---

### Data Quality and Enrichment

**Q: What does dirty data look like in a security context?**

**A:** Dirty data manifests as malformed timestamps, duplicate events, encoding errors, timezone mismatches, and missing hostnames, often arising from misconfigured agents or legacy system limitations.

**Q: How does asset context change the operational meaning of an event?**

**A:** Asset context determines risk severity by distinguishing whether an alert targets a critical database server or an isolated test machine, fundamentally altering the response priority.

**Q: Why is a chronological timeline with source attribution the primary SOC lookup tool?** 

**A:** It reconstructs the attacker's movement and impact sequence, allowing analysts to trace the kill chain from initial access to exfiltration with verified source provenance.

---

### Operational Reproducibility

**Q: Why must an evidence pipeline be runnable from a single command and generalize to unseen data?** 

**A:** Single-command execution ensures rapid, repeatable forensic readiness during incidents, while generalization guarantees the pipeline processes new log sources without manual reconfiguration.

**Q: How do you write a bounded technical specification for a data pipeline?**

**A:** You define precise input formats, transformation logic, output schemas, and failure handling rules in a documented standard that allows another engineer to rebuild the exact environment.

**Q: How does the evidence handoff package feed downstream projects?** 

**A:** It provides the validated, enriched dataset that serves as the single source of truth for all subsequent detection engineering, triage automation, and deep-dive investigations.

---

## Reading the Noise

---

### Log Reading and Format Literacy

**Q: How do you identify, enumerate, and profile every source type present in a normalized security dataset?**

**A:** Extract and count distinct values from the source-identifying field (e.g., `source_type`), then profile each by collecting field sets, sample values, and record volumes to build a per-source reference catalog.

**Q: How do field presence, field cardinality, and example values reveal the operational role of a log source?**

**A:** Which fields exist (presence), how many distinct values each holds (cardinality), and representative sample values collectively fingerprint whether a source handles auth, process execution, network flow, or file activity.

**Q: How do you build a reusable CLI query toolkit that filters, aggregates, and pivots across a flat JSON dataset without a SIEM?**

**A:** Chain `jq` (for filtering, projection, and grouping), `sort`, and `uniq -c` into parametric shell scripts that accept field names and values as arguments, producing repeatable queries for any JSONL dataset.

---

### Behavioral Baselining

**Q: What is a behavioral baseline, why is it the foundation of anomaly detection, and how does it differ from a static threshold?**

**A:** A behavioral baseline is a statistical profile of normal activity (counts, rates, distinct values, timing patterns) computed from historical data; unlike a static threshold (fixed number), it adapts to context by reflecting observed norms per entity.

**Q: How do you compute authentication, process, network, file, and temporal baselines from historical normalized data?**

**A:** Group records by entity (host, user) and time bucket, then compute per-group statistics—distinct counts, frequency distributions, min/max, and percentile ranges—for each event category independently.

**Q: Why must baselines be specific to host, role, and time of day or week to remain useful in production?**

**A:** Normal behavior varies wildly across assets and timeframes (a web server at noon vs. a workstation at 2 AM), so coarse baselines drown analysts in false positives from expected context-dependent variation.

**Q: How do you store a baseline in a machine-readable format that another script can consume without human interpretation?**

**A:** Serialize the baseline as structured JSON or YAML with explicit schema (entity ID, time bucket, metric name, statistical values), enabling automated comparison without parsing ambiguity.

---

### Anomaly Detection and Correlation

**Q: How do you compare an evaluation window against a baseline to surface deviations in activity?**

**A:** Compute the same metrics from the evaluation window and flag any value exceeding the baseline's upper bound (e.g., mean + 2σ or 95th percentile) or containing previously unseen entities (new users, hosts, process hashes).

**Q: Why is a single-source anomaly rarely actionable and why does correlating across sources multiply signal confidence?**

**A:** One anomalous reading is often noise or a benign change (patch deployment, onboarding); when the same timeframe shows correlated deviations across auth, process, and network logs, the likelihood of a true security event rises sharply.

**Q: How do you rank anomalies by a composite score combining asset criticality, deviation magnitude, and cross-source confirmation?**

**A:** Assign weighted numeric values to each factor (e.g., criticality tier 1–5, z-score magnitude, count of corroborating sources), then sum into a single prioritization score for triage ranking.

---

### Validation and Operational Reuse

**Q: Why must every baseline be validated against a known-clean window to bound its false positive rate before production use?**

**A:** Running the baseline detector against a confirmed-clean period quantifies how many alerts fire without a real incident, letting you tune thresholds to an acceptable FP rate before live deployment.

**Q: How do you package a reusable analytical toolkit that another analyst can run on a fresh dataset with zero configuration?**

**A:** Ship self-contained scripts with hardcoded field mappings, sensible default thresholds, auto-detection of source types, and a single entry point that accepts only a file path, producing a formatted report with no manual setup required.
