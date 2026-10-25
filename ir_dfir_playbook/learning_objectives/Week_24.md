# Learning Objectives

---

## The Tabletop

---

### Technical

**Q: How do you ensure scenario injects test the organization rather than trivia?**
A: Anchor each inject to a specific organizational capability (e.g., escalation, comms, decision authority) with a realistic trigger that forces a response, never a quiz question.

**Q: What should you do before writing any inject?**
A: Build a capability-to-scenario map first, so every inject traces back to a capability you intend to evaluate.

**Q: How do you make inject evaluation objective?**
A: Give each inject pre-defined, observable success criteria (who should act, what within what timeframe) so any facilitator scores it the same way.

---

### Conceptual

**Q: What separates an exercise from a meeting?**
A: Exercises pressure-test decisions via injects and expose gaps; meetings discuss and align — if participants aren't making decisions under evolving conditions, it's a meeting.

**Q: Why does facilitator neutrality matter?**
A: A neutral facilitator captures what actually happened (useful findings), while a leading one steers participants toward "correct" answers and produces comfortable but worthless outcomes.

**Q: How do you turn observations into actionable findings?**
A: Record each observation with the specific capability, the observed behavior, the gap, and the consequence — phrased precisely enough that someone can design a fix against it.

---

### Transversal

**Q: Why must scenarios include stress?**
A: Scenarios that are too easy let participants succeed on autopilot, producing zero findings and a false sense of readiness.

**Q: Why write artifacts for another facilitator?**
A: Exercise materials must be self-contained (timelines, criteria, expected actions) so the exercise runs identically without your personal knowledge in the room.

**Q: What makes a finding real?**
A: An owner and a deadline — an unassigned, unscheduled finding is just an observation that will quietly disappear.

---

## The Breach

---

### Technical

**Q: Activate and execute an IR program across a multi-host, multi-phase incident without procedural guidance?**

**A:** Independently initiate the IR lifecycle (preparation, identification, containment, eradication, recovery, lessons learned) across all affected hosts using NIST SP 800-61 as the guiding framework.

**Q: Preserve volatile and non-volatile evidence across four affected hosts under active-threat conditions?**

**A:** Follow order-of-volatility (memory, network state, running processes, then disk) with validated write-blockers, hashing (e.g., SHA-256), and proper chain-of-custody documentation.

**Q: Analyze memory, disk, proxy, and Sysmon artifacts to reconstruct a 72-hour attack chain?**

**A:** Correlate timestamps across artifact sources to build a defensible timeline mapping initial access, persistence, lateral movement, and exfiltration across the three-day window.

**Q: Execute eradication for a Cobalt Strike implant with staged ransomware and credential exposure?**

**A:** Remove implant and persistence mechanisms, rotate all exposed credentials, patch exploited vulnerabilities, and rebuild compromised hosts from known-good images.

**Q: Produce a HIPAA four-factor assessment and a board-quality brief under time pressure?**

A: Apply the HHS breach-notification risk factors (nature/extent of PHI, unauthorized recipient, mitigation) and deliver an executive summary with severity, impact, and recommended actions.

---

### Conceptual

**Q: Synthesis of all prior incident response, forensic, and improvement competencies?**

**A:** Integrate detection, analysis, containment, eradication, and post-incident hardening skills into a single end-to-end incident handling effort.

**Q: Decision-making under incomplete information with documented trade-offs?**

**A:** Make defensible risk-based choices (e.g., isolate vs. monitor) and log the rationale, alternatives considered, and information gaps at each decision point.

**Q: Professional communication calibrated to audience, severity, and regulatory obligation?**

**A:** Tailor technical detail to executives, IR teams, and compliance stakeholders while meeting HIPAA notification duties and deadlines.

---

### Transversal

**Q: Everything the student produces must stand alone, no prior context, no verbal explanation?**

**A:** All deliverables (reports, timelines, assessments) must be fully self-documenting and interpretable without supplementary narration.

**Q: Every decision must be traceable to evidence in the artifacts or reasoning in the record?**

**A:** Each action must cite a supporting artifact (log entry, memory capture finding, hash) or explicit documented reasoning, ensuring full auditability.

---
