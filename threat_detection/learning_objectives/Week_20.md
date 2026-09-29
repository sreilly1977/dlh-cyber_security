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

### Indicator Triage and Enrichment

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

### Infrastructure and Campaign Analysis

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

### MITRE ATT&CK

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

### YARA Rule Development

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

## Malware Awareness

---

### Malware Classification

**Q: How to classify malware by type (dropper, downloader, RAT, infostealer, backdoor, exfiltration script)?**

**A:** Classify by purpose and behavior — a dropper installs malware, a downloader fetches it, a RAT enables remote control, an infostealer harvests credentials, a backdoor maintains covert access, and an exfiltration script moves data out.

**Q: How to distinguish between a delivery mechanism, a primary implant and a post-exploitation tool?**

**A:** Delivery mechanisms arrive first (phishing attachment, dropper), the implant is the persistent core payload on the host, and post-exploitation tools (e.g., Mimikatz, Cobalt Strike) are run afterwards to escalate, move laterally or achieve objectives.

**Q: Why does malware classification matter for detection engineering?**

**A:** Knowing the malware type tells you what behaviors, artifacts and telemetry to expect, so you can build targeted detections instead of relying solely on signatures of known samples.

**Q: How should classification be based on observed behavior and static evidence, not vendor labels alone?**

**A:** Vendor names differ across engines and often just match family similarity, so classification should rest on what the binary actually does and contains (imports, strings, runtime actions), not marketing labels.

---

### Static Analysis

**Q: How to extract useful intelligence from a file without executing it?**

**A:** Static analysis: compute hashes, identify file type, examine metadata, parse structures (PE headers, macros), inspect strings, imports and resources, and optionally disassemble — all without running the sample.

**Q: How to use hashes, file types, metadata and strings to establish identity and capability?**

**A:** Hashes (MD5/SHA-256) uniquely identify the sample, file type reveals the execution environment, metadata shows authorship/tooling clues, and strings expose APIs, paths, C2 domains, commands and config data.

**Q: How to analyze a VBA macro dump for auto-execution triggers, shell commands and encoded payloads?**

**A:** Look for AutoOpen/Document_Open/Workbook_Open triggers, trace Shell/WScript.Run/CreateObject calls for command execution, and decode Base64/hex/str-reversed blobs to recover hidden payloads.

**Q: How to read PE metadata, imports, strings and section entropy to infer capabilities?**

**A:** Imports show capabilities (network APIs, process injection, registry writes), timestamps and compile details aid attribution, strings reveal indicators, and high section entropy (~7+) suggests packing or encryption.

**Q: How to analyze PowerShell scripts by deobfuscating commands and identifying operational logic?**

**A:** Decode Base64 (-enc), reverse Gzipped or concatenated strings, resolve nested variables and aliases (e.g., IEX), then map the reconstructed logic to actions like downloads, persistence or credential theft.

---

### Dynamic / Behavioral Analysis

**Q: How to interpret sandbox reports?**

**A:** Read them critically: prioritize the process tree, dropped files, network traffic and signature hits, but account for sandbox evasion, anti-analysis tricks and environment differences that can suppress true behavior.

**Q: How to read process trees, command lines, registry modifications, file writes and network activity?**

**A:** Follow the parent-child chain to see how execution started and spread, scrutinize command lines for encoded or suspicious arguments, flag persistence-related registry changes, unexpected dropped files, and anomalous domains/IPs/protocols.

**Q: How to correlate static predictions with dynamic behavior?**

**A:** Use static clues (suspicious imports, high entropy, embedded URLs) to form hypotheses, then confirm them against sandbox runtime actions — consistent findings raise confidence, contradictions prompt deeper analysis.

**Q: How to distinguish observed behavior from inferred capability?**

**A:** Observed behavior is what demonstrably happened in execution; inferred capability is what the code appears able to do (from imports/strings) but wasn't seen — label each accordingly and never report inference as confirmed fact.

**Q: How to extract behavioral IOCs such as process chains, registry keys, mutexes, scheduled tasks and DNS patterns?**

**A:** Mine sandbox logs and telemetry for exact parent→child process chains, written registry persistence keys (Run/RunOnce), mutex names used for single-instance checks, schtasks/at creations, and repeated or DGA-like DNS lookups.

---

### Campaign Integration

**Q: How does malware analysis update a previous intelligence assessment?**

**A:** New sample evidence can confirm, refine or overturn prior assessments — upgrading suspected TTPs to confirmed ones, linking samples to campaigns, and revising scope, attribution and risk statements with dated judgments.

**Q: How do inferred ATT&CK techniques become observed when new evidence confirms them?**

**A:** An analyst may predict "T1055 Process Injection" from static imports; once telemetry or sandbox captures it actually occurring, the technique's confidence shifts from inferred/possible to observed/confirmed.

**Q: How do host-based IOCs complement infrastructure IOCs?**

**A:** Host IOCs (mutexes, file paths, registry keys, process chains) prove compromise on endpoints, while infrastructure IOCs (C2 domains, IPs, TLS/JA3 fingerprints) expose the network side — together they enable broad pivoting and detection.

**Q: How to produce a malware incident summary for SOC escalation and partner sharing?**

**A:** Include a TL;DR verdict, sample hashes, classification, key behaviors with MITRE ATT&CK mappings, IOCs (host and network), timeline, and recommended detection/response actions — clearly separating observed facts from analyst inference.

**Q: How to convert malware behavior into detection logic and YARA coverage?**

**A:** Turn generic behaviors (registry persistence, suspicious process chains, odd DNS) into SIGMA/EDR analytics, and build YARA rules from distinctive static strings, byte patterns and import combinations unique to the family.

---
