# Learning Objectives

---

## Intelligence-Driven Defense

---

### Threat Intelligence Lifecycle

**Q: What are the five phases of the intelligence cycle?**

**A:** Collection, processing, analysis, dissemination, and feedback.

**Q: How do internal investigation findings become shareable intelligence?**

**A:** By stripping sensitive/internal context and packaging observations into standardized, sanitized intel reports (e.g., STIX/TAXII sharing with ISACs or partners).

**Q: What distinguishes strategic, operational, and tactical intelligence?**

**A:** Strategic informs leadership/long-term risk, operational covers specific campaigns/adversaries and their capabilities, and tactical provides immediate technical detail for defenders.

**Q: What does it mean to operationalize intelligence?**

**A:** Turning intel into detections, hunt hypotheses, and decision support that drive real defensive actions.

**Q: Why is intelligence a cycle rather than a one-time report?**

**A:** Because feedback from consumers drives new collection requirements and refines analysis as threats evolve.

---

### Source Assessment and Intelligence Quality

**Q: What is the Admiralty Code?**

**A:** A two-part rating system grading source reliability (A–F) and information credibility (1–6).

**Q: Why assess source reliability and information credibility separately?**

**A:** A historically reliable source can publish a bad report, and a dubious source can occasionally report true information.

**Q: Is conflicting intelligence abnormal?**

**A:** No, it is expected given imperfect visibility and differing collection methods; conflicts should be reconciled analytically.

**Q: How do you reconcile conflicting attribution labels?**

**A:** Compare supporting evidence, weight sources by reliability, and present competing hypotheses with stated confidence (e.g., APT vs. crimeware overlap).

**Q: How do confirmed facts, assessments, and assumptions differ?**

**A:** Facts are directly evidenced, assessments are analytic judgments from evidence, and assumptions are unverified premises that must be flagged.

**Q: Why assign confidence levels consistently?**

**A:** Standardized language (e.g., low/moderate/high) prevents misinterpretation and lets consumers gauge how much to rely on a judgment.

---

## Indicator Triage and Enrichment

**Q: What are the first steps in indicator triage?**

**A:** Deduplicate and normalize indicators (standardize type, format, and syntax) before classification.

**Q: What are the three indicator triage categories?**

**A:** ACTIONABLE (act now, e.g., block), CONTEXTUAL (analysis only), and NOISE (discard or archive).

**Q: Why are some indicators only useful for analysis?**

**A:** Shared/benign infrastructure (CDNs, dynamic DNS, cloud hosts) causes false positives if blocked, but still reveals adversary tradecraft.

**Q: What context do WHOIS, DNS, cert transparency, VT, and passive DNS add?**

**A:** Registration history, resolution history, certificates/domains linked by reuse, sample relationships, and prior domain resolutions.

**Q: How can enrichment change defensive recommendations?**

**A:** It can confirm maliciousness (raise confidence, recommend blocking) or reveal benign reuse (lower confidence, monitor only).

---

## Infrastructure and Campaign Analysis

**Q: What is infrastructure clustering?**

**A:** Grouping related domains, IPs, and servers by shared attributes to reveal adversary infrastructure.

**Q: What attributes suggest shared infrastructure ownership?**

**A:** Common registrar, ASN/hosting provider, TLS certificate issuer or reuse, naming conventions, and overlapping tooling/configurations.

**Q: What is a pivot point?**

**A:** An attribute (shared cert, name server, registration email, hash) linking two apparently separate clusters.

**Q: How do you determine if similar indicators belong to the same campaign?**

**A:** Weigh multiple independent linkages, target overlap, timing, and TTP consistency, not a single coincidental similarity.

**Q: How do you reconstruct a multi-stage campaign from incomplete intel?**

**A:** Chain observed fragments via pivots and timelines into a coherent kill chain narrative, clearly labeling inferred gaps.

---

## MITRE ATT&CK

**Q: What is MITRE ATT&CK?**

**A:** A globally accessible knowledge base of adversary tactics and techniques organized by the attack lifecycle.

**Q: What is the difference between OBSERVED and INFERRED techniques?**

**A:** Observed techniques are directly evidenced in telemetry/artifacts; inferred ones are plausible but supported indirectly.

**Q: What is an ATT&CK Navigator layer?**

**A:** An interactive visualization scoring techniques across tactics, used for coverage comparison and gap analysis.

**Q: How does ATT&CK mapping identify defensive gaps?**

**A:** Comparing observed adversary techniques against current detections/controls exposes uncovered behaviors.

**Q: How do you prioritize detection engineering from ATT&CK data?**

**A:** Prioritize techniques frequently used by relevant threat actors and applicable to your environment that lack coverage.

---

## YARA Rule Development

**Q: What are the components of a YARA rule?**

**A:** Metadata, strings section, condition, and rule declaration with an identifier.

**Q: What can YARA rules target besides binaries?**

**A:** Any file content, including PDF structure, email headers, and script/campaign patterns.

**Q: How should rules be tested before deployment?**

**A:** Run against known-benign corpora (false positive check) and known-malicious samples (true positive/coverage check).

**Q: How do you measure rule quality?**

**A:** Track true positives, false positives, and false negatives, then tune for precision and recall.

**Q: When is a rule ready to deploy?**

**A:** When true positives are high, false positives negligible, and false negatives acceptable after tuning; otherwise monitor or keep tuning.

---
