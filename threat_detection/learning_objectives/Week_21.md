# Learning Objectives

---

## Threat Hunting

---

### Threat Hunting Methodology

**Q: What's the difference between alert-driven detection and hypothesis-driven threat hunting?**

**A:** Alert-driven detection reacts to known indicators, while hypothesis-driven hunting proactively searches for threats based on assumed adversary behaviors.

**Q: How do you derive hunt hypotheses from an advisory and ATT&CK gap analysis?**

**A:** Map the advisory's TTPs to ATT&CK, compare against your existing detection coverage, and hypothesize attacks that exploit uncovered gaps.

**Q: How do you define a positive finding before running the query?**

**A:** Write out what suspicious evidence the query results must show (specific hosts, users, times, behaviors) before executing it.

**Q: Why does hunting require a documented baseline?**

**A:** Without knowing what "normal" looks like, you cannot reliably distinguish anomalies from routine activity.

**Q: Why doesn't the absence of SIEM alerts prove the absence of threats?**

**A:** Alerts only cover configured detections, so adversaries operating outside existing rules go unnoticed — this is the coverage illusion.

---

### Living Off The Land Detection

**Q: Why are PsExec, WMI, and PowerShell Remoting hard to detect with static IOCs?**

**A:** They are legitimate built-in administration tools, so their binaries match trusted hashes and leave no unique static indicators.

**Q: How do legitimate tools become suspicious through context?**

**A:** Context (unusual source host, unauthorized user, unexpected target system, or odd timing) makes benign tool usage stand out.

**Q: How does service account misuse reveal credential compromise?**

**A:** Service accounts normally authenticate predictably, so interactive logons or access from unusual hosts signal stolen credentials.

**Q: How can off-hours activity identify adversary operations?**

**A:** Legitimate administrators rarely work overnight, so activity during those windows stands out as anomalous.

---

### Baseline Analysis

**Q: How do you profile legitimate administrator behavior?**

**A:** Collect and document historical activity patterns — who does what, from where, to which systems, and when.

**Q: How do you use an authorized schedule as a false-positive filter?**

**A:** Compare observed activity against documented maintenance windows to quickly dismiss expected events.

**Q: How do you validate service account authentication against an authorization matrix?**

**A:** Check each observed authentication against a table defining which accounts may access which resources, flagging violations.

**Q: How do you separate normal maintenance from adversary lateral movement?**

**A:** Match activity against baseline and authorization records; deviations in account, host, or timing indicate lateral movement.

---

### Evidence Correlation

**Q: How do you combine separate findings into a unified attack timeline?**

**A:** Sort all events by timestamp and link related artifacts (accounts, hosts, files) to reconstruct the attack sequence.

**Q: How do you correlate credential theft, lateral movement, reconnaissance, and staging?**

**A:** Trace shared indicators (same credentials, source hosts, and timestamps) across those activities to reveal a single campaign.

**Q: How do you map hunt findings to MITRE ATT&CK?**

**A:** Assign each observed behavior to the corresponding tactic, technique, and sub-technique ID.

**Q: How do you turn hunt findings into new detection rules?**

**A:** Convert validated hunt queries into tuned, automated SIEM/EDR rules with defined thresholds and alert logic.

---

### Reporting

**Q: How do you write a hunting report for SOC and leadership audiences?**

**A:** Give SOC actionable technical detail, give leadership an executive summary covering risk, impact, and business exposure.

**Q: How do you explain the coverage illusion?**

**A:** Emphasize that "no alerts" means only "no matched detections," not "no threats present."

**Q: How do you document remaining gaps and next-step recommendations?**

**A:** List uncovered ATT&CK techniques and residual risks, then prioritize hunts, rule creation, and tooling improvements to close them.

---

## Attack Reconstruction

---

### Cross-Evidence Correlation

**Q: How do you integrate findings from multiple investigation domains (email, network, endpoint, intelligence, SIEM)?**

**A:** Normalize all findings into a common schema (time, actor, artifact, source) on a single master timeline, then correlate entities across domains to build one unified picture.

**Q: How do you identify convergences and divergences across sources?**

**A:** Convergences are findings independently confirmed by two or more sources; divergences are claims supported by only one source or contradicted by others, flagged for further scrutiny.

**Q: How do you assess evidence reliability — which sources are authoritative for which claims?**

**A:** Match each claim to its most authoritative source (endpoint telemetry for process activity, network for wire traffic, SIEM for aggregated alerts), recognizing they corroborate rather than override each other.

**Q: Why may network timestamps not match SIEM timestamps for the same event?**

**A:** Timezone offsets, NTP clock skew, log shipping delays, and differing collection points mean timestamps describe observation times, not true event times.

**Q: How do you resolve apparent contradictions between evidence sources?**

**A:** Check for collection gaps, timezone misconfiguration, clock drift, and evidence preservation limits before concluding a real contradiction exists.

---

### Attack Timeline Reconstruction

**Q: How do you construct a chronological attack narrative from fragmented, multi-source evidence spanning days or weeks?**

**A:** Pivot off artifacts (IOCs, accounts, hosts) to stitch events across sources, then order them onto a normalized UTC master timeline.

**Q: How do you establish temporal anchors?**

**A:** Identify high-confidence, precisely-timestamped events (e.g., logins, malware execution with embedded timestamps) as fixed points to order surrounding, less certain events.

**Q: How do you distinguish confirmed sequence from inferred sequence?**

**A:** Confirmed sequence has direct causal correlation (e.g., matching artifact/hash between events); inferred sequence relies on technique logic alone.

**Q: How do you identify dwell time, breakout time, and operational tempo from reconstructed timelines?**

**A:** Dwell time = initial compromise to detection; breakout time = initial access to lateral movement start; operational tempo = pacing/gaps between attacker actions.

---

### ATT&CK Mapping at Scale

**Q: How do you map a multi-phase attack to MITRE ATT&CK with confidence annotations?**

**A:** Assign each technique a tier — Confirmed (direct evidence), Probable (strong circumstantial evidence), or Possible (technique logic only) — and cite the supporting artifacts.

**Q: How do you identify blind-spot gaps vs. collection-limitation gaps?**

**A:** Blind spots lack coverage where evidence *should* exist; collection limitations lack evidence because the source wasn't capturing data during the window.

**Q: Why can ATT&CK coverage percentages create a false sense of security?**

**A:** Coverage percentage measures breadth of detections, not depth — attackers leverage the few uncovered techniques that matter, which reconstruction reveals.

---

### Impact Assessment

**Q: How do you determine organizational impact of an attack?**

**A:** Map compromised systems to the asset inventory and data classification scheme to determine what assets and data classifications were touched.

**Q: How do you distinguish confirmed, potential, and prevented data exposure?**

**A:** Confirmed = evidence of access/exfiltration; potential = access was possible but unproven; prevented = staging detected and blocked before exfiltration.

**Q: How do you assess regulatory implications (HIPAA notification triggers)?**

**A:** Tie notification decisions to evidence of actual PHI access/acquisition, not mere system compromise, using the exposure determinations above.

---

### Professional Reporting

**Q: How do you produce a report serving both technical and executive audiences?**

**A:** Use a layered structure — executive summary with impact and actions up front, technical appendices with full evidence behind it.

**Q: How do you structure evidence citations?**

**A:** Every claim references a unique finding ID tied to a specific source, timestamp, and raw artifact, forming an auditable evidence chain.

**Q: How do you document unknowns, and why does that strengthen a report?**

**A:** Explicitly list unknowns, their cause (collection gap vs. pending analysis), and impact on conclusions; intellectual honesty prevents overstatement and builds stakeholder trust.

---
