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
