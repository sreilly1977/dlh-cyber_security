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

## Contain and Control

---

### Technical

**Q: Perform initial triage on progressively revealed alert and log evidence**

**A:** Correlate each new artifact against the emerging hypothesis, rank findings by threat and blast radius, and update the severity and scope continuously.

**Q: Preserve volatile and non-volatile evidence before any containment action**

**A:** Capture memory, active connections, running processes, and network state first; then disk images, logs, and configs, with documented chain of custody, before touching the live system.

**Q: Select containment strategies against explicit operational trade-offs**

**A:** Weigh isolation, segmentation, or full shutdown against business impact, evidentiary loss, and adversary visibility, recording the chosen option and its justification.

**Q: Execute eradication steps with verification across Windows persistence surfaces**

**A:** Remove malware, backdoors, rogue accounts, scheduled tasks, services, registry run keys, WMI subscriptions, and startup folders, then rescan and diff to confirm removal.

**Q: Validate service recovery with proof instead of assumption**

**A:** Monitor restored services, run functional and security tests, compare against clean baselines, and validate hardened configurations before declaring recovery.

---

### Conceptual

**Q: Order of operations between evidence preservation and containment**

**A:** Preserve first, contain second, because containment actions destroy volatile evidence that cannot be recovered once a host is isolated or powered off.

**Q: Severity reassessment on scope change**

**A:** Any expansion of scope, such as a second host or credentials, triggers immediate severity and priority reassessment with escalation to stakeholders.

**Q: Eradication completeness across process, credential, and network persistence**

**A:** Eradication is complete only when attacker access is removed at all three layers: malicious processes, compromised or backdoor credentials, and network footholds like VPNs, firewall rules, and C2 channels.

**Q: Handoff quality as a measurable outcome, not a courtesy**

**A:** A handoff succeeds when the receiving analyst can act independently, verified by timeline continuity, decision rationale, open items, and confirmation of comprehension.

---

### Transversal

**Q: Maintain a timeline under pressure**

**A:** Timestamp every event and decision in real time as they occur, rather than reconstructing afterwards.

**Q: Justify every decision on the page at the moment it is taken**

**A:** Record the action, rationale, alternatives rejected, and who authorized it, immediately, because retrospective justification erodes auditability.

**Q: Separate what is known from what is assumed**

**A:** Log observed facts with sources first, then explicitly label inferred or hypothesized items as unverified until confirmed by evidence.

---
