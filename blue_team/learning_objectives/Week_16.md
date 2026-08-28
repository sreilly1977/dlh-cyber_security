# Learning Objectives

## Evidence Engineering

**Q: What is an evidence pipeline and what are its stages?** 

**A**: An evidence pipeline is an automated workflow that ingests raw logs through intake, parsing, normalization, cleaning, enrichment, indexing, and validation to transform chaotic data into actionable intelligence.

**Q: How do raw log exports from Windows, Linux, and network devices differ structurally?**

**A:** They differ in format (EventXML vs syslog vs binary), field naming conventions, timestamp standards, and severity levels, requiring reconciliation to enable cross-platform correlation.

**Q: What is a unified event schema and how are fields justified?**

**A:** A unified event schema is a standardized data model where required fields ensure core investigative utility (like timestamps and source IPs) while optional fields preserve source-specific context for deep dives.

**Q: Why is data normalization a trade-off between fidelity and searchability?**

**A:** Normalization sacrifices granular, vendor-specific details to create consistent, searchable fields, which can obscure unique attack indicators hidden in proprietary log structures.

## Data Quality and Enrichment

**Q: What does dirty data look like in a security context?**

**A:** Dirty data manifests as malformed timestamps, duplicate events, encoding errors, timezone mismatches, and missing hostnames, often arising from misconfigured agents or legacy system limitations.

**Q: How does asset context change the operational meaning of an event?**

**A:** Asset context determines risk severity by distinguishing whether an alert targets a critical database server or an isolated test machine, fundamentally altering the response priority.

**Q: Why is a chronological timeline with source attribution the primary SOC lookup tool?** 

**A:** It reconstructs the attacker's movement and impact sequence, allowing analysts to trace the kill chain from initial access to exfiltration with verified source provenance.

## Operational Reproducibility

**Q: Why must an evidence pipeline be runnable from a single command and generalize to unseen data?** 

**A:** Single-command execution ensures rapid, repeatable forensic readiness during incidents, while generalization guarantees the pipeline processes new log sources without manual reconfiguration.

**Q: How do you write a bounded technical specification for a data pipeline?**

**A:** You define precise input formats, transformation logic, output schemas, and failure handling rules in a documented standard that allows another engineer to rebuild the exact environment.

**Q: How does the evidence handoff package feed downstream projects?** 

**A:** It provides the validated, enriched dataset that serves as the single source of truth for all subsequent detection engineering, triage automation, and deep-dive investigations.
