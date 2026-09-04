# Learning objectives

---

## The Alert Factory

---

### Detection Engineering Fundamentals

**Q: What are the four detection types and which data source and rule structure supports each?**

**A:** Signature matches exact known indicators (exact field values, e.g. hash or registry key, supported by event logs and lookup/threshold rule structures); anomaly detects deviations from learned baselines (numeric/statistical rule structure fed by telemetry like netflow and counts); behavioral identifies sequences of actions characteristic of a technique (process and command-line telemetry with ordered, condition-combined selections); correlation combines multiple events or sources over time (multi-event rule structure across agent, network, and SIEM-aggregated data).

**Q: What is the difference between true positive, false positive, true negative, and false negative, and why does each matter?**

**A:** True positives confirm real threats (good alerts, build confidence); false positives are benign activity flagged as malicious (they inflate SOC workload and erode analyst trust); true negatives are correctly ignored benign events (proof the rule discriminates well); false negatives are missed real threats (the most dangerous outcome, directly undermining detection confidence and coverage).

**Q: Why must every detection rule be a precise predicate against specific fields, and why is free-text matching a last resort?**

**A:** Precise field predicates are deterministic, testable, tunable, and fast to evaluate; free-text matching (regex/grep over raw messages) is slow, brittle to log format changes, harder to tune, and generates more ambiguity and false positives.

---

### Sigma Rule Authoring

**Q: What is the full Sigma rule structure?**

**A:** `title` (short description), `id` (stable UUID for tracking), `status` (experimental/stable/deprecated), `logsource` (category/product/service defining the expected log), `detection` (named selections plus a `condition`), `falsepositives` (known benign causes), `level` (informational to critical), and `tags` (MITRE ATT&CK mappings and other classification).

**Q: How are selection, count, timeframe, and boolean logic expressed in Sigma detection blocks?**

**A:** Selections are lists of field/value filters that AND internally; multiple values for one field OR; `|` modifiers such as `count()` with a `timeframe` (e.g. `count() >= 5` over `5m`) express thresholds; the `condition` combines named selections with `and`, `or`, and `not`, including quantifiers like `1 of sel*`.

**Q: How is a rule mapped to MITRE ATT&CK techniques and why is the mapping not cosmetic?**

**A:** Via `tags` using the standard `attack.<tactic>` and `attack.<technique-id>` format (e.g. `attack.t1059`); the mapping drives coverage-gap analysis, prioritization against likely adversary behavior, reporting, and cross-referencing with threat intelligence, so it shapes engineering decisions rather than just labeling.

**Q: Why does vendor-neutral detection authoring outlive any specific SIEM, and why did Sigma become the industry reference?**

**A:** Rules written in Sigma's YAML survive SIEM migrations and tool churn because translation to each backend is automated; its open specification, converter tooling (pySigma/sigmac), large community repository, and human-readable schema made it the de facto shared language for detections.

---

### Detection Quality and Tuning

**Q: How do you measure precision, recall, and false positive rate for a rule against labeled evidence?**

**A:** Replay the rule over labeled (benign/malicious) datasets: precision = true alerts / all alerts, recall = true alerts / all actual malicious events, false positive rate = benign events alerted / total benign events, then track these metrics per rule version.

**Q: How do you tune a rule that fires too often without losing its ability to catch the targeted behavior?**

**A:** Add discriminating conditions (process path, parent process, user scope, host scope) rather than loosening the core indicator, raise thresholds on count/timeframe, add known-good exclusions verified against labeled data, and re-measure recall after each change to confirm the target behavior is still caught.

**Q: How do you assess detection coverage across the MITRE ATT&CK matrix and identify gaps?**

**A:** Tag every rule with its techniques, plot the set against the ATT&CK matrix (e.g. with ATT&CK Navigator heatmaps), compare against threat-relevant techniques for your organization, and flag tactics/techniques with no rule or only low-quality rules as gaps.

**Q: Why must rule prioritization be driven by organizational risk, not technical novelty?**

**A:** Limited engineering and SOC capacity means effort must go to detections addressing techniques adversaries actually use against your crown jewels, exposed attack surface, and likely impact; novel-but-irrelevant rules consume effort without reducing real risk.

---

### Cross-Source Detection

**Q: Why do multi-source correlation rules produce higher confidence findings than single-source rules?**

**A:** Independent evidence streams (endpoint, network, identity, cloud) corroborating the same story dramatically reduce false positives and rule out single-telemetry artifacts, so an alert backed by multiple sources is far more likely to be a true incident worth escalating.

**Q: How is a correlation rule structured in Sigma, and what are the limits of pure Sigma correlation?**

**A:** Correlation rules (per the correlation specification) define a base query of events with a `type` (event_count, temporal, temporal_ordered, value_count), referenced rules or queries, `timespan`, and grouping/condition fields; pure Sigma's limits are that it expresses relatively simple temporal/count relationships and depends heavily on backend SIEM capabilities, so complex multi-stage logic may need SIEM-native correlation.

**Q: When should evidence be preprocessed into correlation primitives before rule evaluation?**

**A:** When raw events are voluminous, heterogeneous, or noisy; normalizing and summarizing them into standardized primitives (parsed fields, sessions, entity timelines, aggregates such as per-host/per-user counts) makes correlation rules simpler, faster, and more reliable than evaluating logic over raw logs.

---
