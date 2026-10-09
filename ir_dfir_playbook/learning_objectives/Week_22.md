# Learning Objectives

---

## When the Alarm Sounds

---

### Technical

**Q: How do you translate the incident response lifecycle into organizational artifacts?**

**A:** Map each phase (prep, detection, containment, eradication, recovery, lessons learned) to concrete deliverables like runbooks, severity matrices, contact trees, and post-incident report templates.

**Q: How do you define severity classification tied to operational and patient impact?**

**A:** Build a tiered matrix (e.g., SEV1–SEV4) that scores incidents by clinical service disruption, patient safety exposure, and data scope rather than purely technical indicators.

**Q: How do you design playbooks an on-call analyst can execute under pressure?**

**A:** Use short, numbered, checklist-style steps with explicit decision points, pre-approved actions, and escalation contacts, so no step requires improvisation at 3 AM.

**Q: How do you produce communication templates tuned to distinct audiences?**

**A:** Create separate pre-drafted templates per audience: technical detail for responders, impact-focused updates for executives, and plain-language notices for patients or regulators.

---

### Conceptual

**Q: How do you align IR structure with healthcare regulatory obligations?**

**A:** Ensure the IR process triggers HIPAA breach risk assessment and OCR notification timelines (60 days), embedding legal and privacy review into defined lifecycle checkpoints.

**Q: How do you distinguish decision authority across incident severity levels?**

**A:** Delegate SEV1 escalation and declaration to the CISO/incident commander, reserve patient-care and clinical downtime decisions for medical leadership, and empower analysts for lower tiers.

**Q: How do you reason about trade-offs between evidence preservation and operational continuity?**

**A:** Prioritize patient safety first, then apply order-of-volatility capture and forensic snapshots before restoring service where feasible, documenting any evidence destroyed by recovery actions.

---

### Transversal

**Q: What does "write for operators, not readers" mean?**

**A:** Optimize documents for execution speed and scanning under stress, not for narrative completeness.

**Q: What does "standardize before you scale" mean?**

**A:** Stabilize consistent terminology, severity, and playbook formats across teams before expanding IR coverage to more systems.

**Q: What does "validate a design by running it, not by reviewing it" mean?**

**A:** Test IR designs through tabletop exercises and simulations, since paper reviews miss the friction that emerges during live execution.

---
