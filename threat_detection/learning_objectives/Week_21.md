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
