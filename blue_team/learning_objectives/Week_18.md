# Learning Objectives

---

## Cross-Platform Detection Analysis

---

### Cross-Platform Investigation

**Q: How do you run the same investigation via CLI pipeline vs. SIEM export, and why does the workflow stay the same?**

**A:** Both reduce to the same cognitive loop of filtering, correlating, and interpreting events; only the access mechanism differs, so keep filter → aggregate → timebox steps constant and record per-platform mappings.

**Q: How do you compare efficiency across interfaces without bias?**

**A:** Count measurable proxies: time to first answer, number of fields touched, and events reviewed, turning comparison into a tally rather than an opinion.

**Q: How do you handle different field names for the same event across platforms?**

**A:** Build a reconciliation map (e.g. client_ip vs. src_ip vs. winlog.event_data.IpAddress) and normalize to canonical names before analysis.

**Q: How do you produce findings readable regardless of origin?**

**A:** Enforce a locked JSON schema (fields, severity, evidence refs, timestamps) so a finding from jq and one from a Wazuh export validate identically.

---

### Detection Rule Translation

**Q: How do Sigma and Wazuh XML rules map structurally?**

**A:** Sigma's logsource → Wazuh rule prematch/decoder matching, detection field selectors → match/if_matched attributes, condition → logic combinators, aggregation → frequency-based options.

**Q:** Which Sigma elements translate cleanly and which don't?

**A:** Simple keyword/field selectors map directly; modifiers like regex hints, multiples|conditions, near operators, and cross-logsource references require manual creative adaptation.

**Q: Why use Sigma at all, and where does auto-conversion fail?**

**A:** Sigma is a vendor-neutral abstraction so detections port across platforms, but converters struggle with platform-specific quirks (field naming, regex dialects, correlation features), so review is still required.

**Q: How do you validate a Wazuh XML rule before deploying it?**

**A:** Run xmllint --noout against the rule file to catch well-formedness and DTD/schema errors before it enters the catalog.

---

### Query Language Comparison

**Q: What are the key syntactic/semantic differences between jq, Sigma, KQL, and Lucene?**

**A:** jq is a functional JSON pipe language; Sigma is declarative YAML detection logic; KQL is terse boolean field-value filtering; Lucene adds rich term, fuzzy, and proximity operators.

**Q: What three canonical components underlie any SIEM query?**

**A:** Every query decomposes into a filter (which events), an aggregation (how they're grouped/counted), and a time window (when).

**Q: How would you express one question in four languages?**

**A:** Pick a question like "count failed logins per host in the last hour" and show filter/agg/window variations in jq, Sigma YAML, KQL, and Lucene side by side.

---

### Vendor-Agnostic Reasoning

**Q: What separates interface-dependent from interface-independent skills?**

**A:** Syntax and button-click fluency are interface-dependent; investigative reasoning, hypothesis testing, and evidence structuring are interface-independent and portable.

**Q: How do you structure a vendor evaluation brief?**

**A:** Use a bounded scope with counted evidence: requirements list, scored matrix per vendor, workload samples, gaps, then a defensible recommendation.

**Q: How does Security+ 4.7 apply to SIEM evaluation?**

**A:** It frames SIEM evaluation around automation/orchestration fit: connector breadth, playbook integration, and API/SOAR compatibility, not just dashboard features.

---

### Security+ SY0-701 Coverage

**Q: Which Security+ domains does this cover?**

**A:** Domain 4.4 security monitoring and alert handling, plus Domain 4.7 automation and orchestration concepts.

---

## The 24-Hour Watch

---

### Full-Chain Shift Operation

**Q: How is an end-to-end detection chain executed against an unseen evidence pack?**

**A:** The pipeline, baseline, catalog, and triage phases run sequentially to ingest, normalize, score, and disposition evidence from a pack the analyst has never seen before.

**Q: How does the pipeline recover from dirty data without manual intervention?**

**A:** Bad records are quarantined and logged to a rejected-events artifact while clean records continue processing, so no human fix is needed mid-shift.

**Q: Why must countable artifacts be produced at every phase?**

**A:** Quantifiable outputs like event counts, baseline deviations, catalog hits, and triage dispositions make the entire shift measurable, auditable, and defensible.

---

### Investigative Depth

**Q: How are multi-step intrusions reconstructed from fragmented evidence?**

**A:** Correlating events across disparate sources by time, host, and indicator lets the analyst stitch scattered fragments into a coherent kill-chain narrative.

**Q: How are true incidents distinguished from approved activity and noise?**

**A:** Bounded, auditable reasoning applies explicit criteria, baselines, and allowlist checks so every disposition can be traced back to its supporting evidence.

**Q: How do analysts operate across CLI and pre-exported Wazuh artifacts in one investigation?**

**A:** Live command-line querying and exported Wazuh dashboards, alerts, and logs are treated as complementary inputs joined within the same investigative workflow.

---

### Campaign Analysis

**Q: How are incidents linked into a campaign?**

**A:** Shared indicators, temporal proximity, and consistent tactics across incidents are used to cluster related activity into a single coordinated campaign.

**Q: How do you determine whether observed activity maps to HC-RED7 or an unrelated actor?**

**A:** Comparing observed TTPs, indicators, and timing against the HC-RED7 profile confirms attribution or identifies the activity as an unrelated actor.

---

### Professional Handoff

**Q: What does an incident report conforming to a locked schema look like?**

**A:** A standardized report with fixed fields for classification, evidence, timeline, and disposition, ensuring consistency across every incident documented.

**Q: How are tuning changes justified?**

**A:** Each proposal cites specific, counted evidence such as alert volumes, false positive rates, or baseline deviations that demonstrably motivate the change.

**Q: What goes into a complete shift handoff package?**

**A:** Incident reports, tuning proposals, countable phase artifacts, and campaign findings bundled so the incoming shift can pick up with full context.

---
