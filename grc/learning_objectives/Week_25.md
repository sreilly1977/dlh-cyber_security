# Learning Objectives

---

## The Compliance Engine

---

### Technical

**Q: How are deployed security controls mapped to NIST CSF 2.0 subcategories?**

**A:** Each control (e.g., encryption, access reviews, SIEM alerts) is matched to its CSF 2.0 subcategory ID, with evidence references (change tickets, logs, configuration exports) drawn from actual MedDefense artifacts proving the control operates.

**Q: How are compliance gaps identified across the six CSF functions?**

**A:** By comparing implemented controls and evidence against each applicable subcategory in Govern, Identify, Protect, Detect, Respond, and Recover, flagging any subcategory lacking a control, ownership, or verifiable evidence.

**Q: How is a vendor's security posture evaluated?**

**A:** Using a structured methodology (e.g., questionnaire, SOC 2/HITRUST review, scan data) scored against weighted risk criteria to rank vendors by inherent risk and residual exposure.

---

### Conceptual

**Q: How do NIST CSF 2.0 subcategories relate to HIPAA Security Rule implementation specifications?**

**A:** The CSF Informative References crosswalk maps subcategories to specific §164.308/.310/.312 safeguards, so implementing CSF controls demonstrates HIPAA compliance coverage.

**Q: What distinguishes a control that exists from one that is documented and evidence-supported?**

**A:** A control may technically operate in the environment, but only documentation plus retrievable evidence lets an auditor independently verify design and operation over time.

**Q: Why is policy without specificity and enforcement not policy?**

**A:** A statement that assigns no owner, defines no measurable requirement, and carries no consequence for noncompliance cannot be tested or enforced, so it is aspiration rather than policy.

---

### Transversal

**Q: What makes a policy both readable and enforceable?**

**A:** Concise scope, explicit requirements, named accountable roles, defined frequency, and stated enforcement consequences, short enough to be read and specific enough to audit.

**Q: How should compliance evidence be packaged for auditors?**

**A:** As a control-by-control matrix with a description, evidence reference (system, document ID, date, owner), test procedure, and result, so an independent party can re-perform the verification.

**Q: How are findings translated into executive language without losing accuracy?**

**A:** Frame each finding by business risk (regulatory exposure, patient safety, cost), remediation effort, and recommended decision, while preserving the underlying technical facts and evidence trail.

---

## When Everything Fails

---

### Technical

**Q: Conduct a Business Impact Analysis using patient safety, regulatory, revenue and operational impact criteria across a clinical environment**

**A:** Score every clinical system against all four criteria on a fixed scale, weight patient safety highest, and rank the estate by combined score to drive recovery priority.

**Q: Design a backup architecture that satisfies declared RTO and RPO values with documented verification procedures per system**

**A:** Map each system to its RTO/RPO pair, select the matching method (continuous replication, frequent snapshots, or nightly full plus incremental), and attach a scheduled restore test with a signed result record per system.

**Q: Write command-level recovery runbooks with explicit expected outputs, checkpoints and deviation handling**

**A:** Number every step, give the exact command, state the expected output string, insert a checkpoint to confirm success before continuing, and branch to a documented fallback if the output differs.

**Q: Execute a timed recovery test against a simulated LIS failure, measuring wall-clock time per step and documenting deviations in real time**

**A:** Run the LIS runbook against a simulated failure with a stopwatch per step, log wall-clock time and every deviation as it occurs, then compare total elapsed time against the declared RTO.

---

### Conceptual

**Q: Distinguish RTO, RPO and MTD as distinct business decisions with different clinical implications**

**A:** RTO (Recovery Time Objective) is how long clinicians can tolerate working without the system, RPO (Recovery Point Objective) is how much data loss they can absorb, and MTD (Maximum Tolerable Downtime) is the point beyond which patient harm or organisational failure becomes likely.

**Q: Understand how system dependency chains determine restoration sequencing in a multi-system outage**

**A:** Restore along the dependency graph rather than the criticality list, bringing up identity, network and data layers first, then the clinical application, then interfaces and downstream consumers.

**Q: Connect the gap between declared and actual recovery time to specific runbook deficiencies, not general unpreparedness**

**A:** Attribute each minute of overrun to a named runbook defect such as a missing step, stale credential, unverified restore or undocumented dependency, rather than to vague unreadiness.

---

### Transversal

**Q: Write clinical downtime procedures in language a nurse on a first night shift can follow without IT involvement**

**A:** One action per numbered line, no acronyms, printed and laminated at the nurses' station, covering who to call, where the paper forms are kept, and how to reconcile records afterwards.

**Q: Translate a failed recovery test into a gap analysis a CISO can present to a Board Risk Committee**

**A:** Open with tested recovery time against declared RTO, quantify the clinical and financial exposure, name the specific control failures, and close with costed remediation options and a re-test date.

**Q: Produce a DR program package that satisfies HIPAA 164.308(a)(7) without requiring verbal explanation**

**A:** Assemble the written BIA, backup plan, disaster recovery plan, emergency mode operations plan, and testing and revision log as one self-contained set mapped element by element to §164.308(a)(7).

---
