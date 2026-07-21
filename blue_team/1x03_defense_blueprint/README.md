# 0. The Framework Landscape

## Goal
Understand the purpose, scope and relationship of the three major security frameworks used in enterprise defense.

## Context
James Chen opens the strategy meeting with a question to Sarah Park: "Which framework should we use?" Sarah answers: "NIST." James pushes: "NIST what? CSF? 800-53? RMF? And what about CIS Controls? The auditor mentioned ISO 27001 last month."

The framework landscape is confusing even for experienced professionals. Before you can build a strategy, you need to understand your tools: what each framework does, where they overlap and when to use which one.

## Instructions
Research NIST CSF 2.0, CIS Controls v8 and ISO 27001. Then produce a **Framework Comparison** using this structure:

---

### Part 1 - Three-Framework Summary

For each framework, document in **3-5 sentences**:

1. What it is and who publishes it
2. What it is designed to do (its primary purpose)
3. How it is structured (functions/controls/clauses)
4. Who typically uses it and in what context

---

### Part 2 - Relationship Map

Explain in **one paragraph** how the three frameworks relate to each other. They are not competitors. They serve different purposes and can be used together. How?

> A useful mental model: NIST CSF answers "What should we do?", CIS Controls answers "How should we do it?", ISO 27001 answers "Can we prove we are doing it?"

---

### Part 3 - MedDefense Framework Selection

Recommend which framework(s) MedDefense should adopt as its strategic backbone and justify your choice. Consider:

- MedDefense is a regional hospital (not a federal agency)
- Has no current framework in place
- Has limited staff (1 security analyst, 1 deputy CISO)
- Must demonstrate compliance to regulators and the Board

---

# 1. The NIST CSF Mapping

## Goal
Apply **NIST CSF 2.0** to MedDefense by mapping the organization's current security posture to each of the six core functions.

## Context
NIST CSF 2.0 organizes all security activities into **six functions**:

- **Govern** – Establish and monitor the security strategy
- **Identify** – Understand what you need to protect
- **Protect** – Implement safeguards
- **Detect** – Find incidents when they happen
- **Respond** – Act on detected incidents
- **Recover** – Restore operations after an incident

Each function contains categories and subcategories that describe specific outcomes.

This is not a theoretical exercise. You are building **MedDefense's Current Profile**, a realistic snapshot of where the organization stands today against each function. This profile will become the foundation for the **Target Profile** (where MedDefense needs to be), and the gap between them drives the entire strategy.

### Provided Files
[`nist-csf-reference.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/nist-csf-reference.txt) (summary of CSF 2.0 functions, categories and key subcategories)

## Instructions
For each of the **6 CSF functions**, assess MedDefense's current maturity using a **4-level scale**:

| Level | Description |
|-------|-------------|
| Not Implemented | No activity exists for this function |
| Partial | Some activity exists but is informal, inconsistent or incomplete |
| Managed | Activity is documented, repeatable and covers most of the scope |
| Optimized | Activity is continuous, measured and actively improved |

### Produce a NIST CSF Current Profile for MedDefense:

```
Function: [Name]
Current Level: [Not Implemented / Partial / Managed / Optimized]
Evidence: [What specific findings from Projects 1x00, 1x01 and 1x02 support this rating?]
Key Gaps: [What is the most significant gap within this function?]
Target Level: [Where should MedDefense be in 6 months? Justify.]
```


### Calibration Points to Guide Your Assessment

1. **Identify:** You built the asset inventory in 1x00. Did MedDefense have one before you arrived?

2. **Protect:** The vulnerability scan (1x02) revealed the state of MedDefense's protective controls. How would you rate them?

3. **Detect:** Marcus's notes mentioned zero monitoring capability. What does that mean for this function?

---

# 2. The CIS Controls Audit

## Goal
Score MedDefense against the **CIS Top 18 Controls** to produce a concrete, actionable security maturity assessment.

## Context
NIST CSF tells you what functions to address. CIS Controls tell you exactly what to implement, in what order. The CIS Controls are organized into three **Implementation Groups**:

- **IG1 (Essential):** The minimum standard every organization should meet. 56 safeguards. Think of this as "basic hygiene."
- **IG2 (Foundational):** Additional safeguards for organizations with more complex environments. Builds on IG1.
- **IG3 (Organizational):** Advanced safeguards for organizations with dedicated security teams handling sophisticated attacks.

MedDefense, as a healthcare organization handling regulated data with a small security team, should target **IG1 fully implemented** and **IG2 partially implemented** within 6 months.

### Provided Files
[`cis-controls-summary.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/cis-controls-summary.txt) (all 18 controls with IG1/IG2 safeguard descriptions)

## Instructions
Score MedDefense against each of the **18 CIS Controls** using a simple **3-level scale**:

| Score | Meaning |
|-------|---------|
| Implemented | The control is in place and functioning |
| Partial | Some elements of the control exist but coverage is incomplete |
| Not Implemented | The control is absent |

For each control:

```
CIS Control [#]: [Name]
Score: [Implemented / Partial / Not Implemented]
Evidence: [One sentence referencing a specific finding from 1x00, 1x01 or 1x02]
```


After scoring all 18, produce:

1. **Scorecard Summary:** Count of Implemented / Partial / Not Implemented

2. **Top 5 Priority Controls:** The 5 controls whose implementation would have the greatest impact on MedDefense's security posture. Justify each choice in one sentence.

---

# 3. The Gap-to-Framework Bridge

## Goal
Connect every significant gap from prior projects to a specific framework control, transforming raw findings into structured, framework-aligned action items.

## Context
You have gaps from 1x00, threats from 1x01, vulnerabilities from 1x02, and framework scores from T1 and T2. Right now, they exist in separate documents. This task connects them into a single traceability chain: **Gap → Vulnerability → Threat → Framework Control → Recommended Action**.

This bridge is what makes a strategy credible. When the Board asks, "Why should we implement network segmentation?", the answer is not "because it is a best practice." The answer is:

> "Because Gap GAP-003 (flat network) enables Kill Chain #1 (ransomware), is exploited by Vulnerability Finding 003 (PostgreSQL unrestricted access), maps to CIS Control 12 (Network Infrastructure Management) at IG1, and closing it reduces our ransomware ALE by an estimated $180,000 per year."

## Instructions
Select the **8 highest-priority gaps** from your prior work (use the re-prioritized list from 1x01 T15 and 1x02 findings). For each:

```
Gap Reference: [ID from 1x00/1x02]
Description: [One line]
Vulnerability Evidence: [Finding ID(s) from 1x02]
Threat Context: [Actor type + kill chain from 1x01]
NIST CSF Function: [Which function does this gap fall under?]
CIS Control: [Which CIS Control addresses this gap? Include the control number.]
Recommended Action: [One sentence: what MedDefense should do]
```

After all 8, produce a **Traceability Summary Table** showing the full chain in a single view.

---

# 4. The Governance Architecture

## Goal
Design the security governance structure that MedDefense needs to execute and sustain a security program.

## Context
A strategy without governance is a document that sits on a shelf. Governance defines who is responsible, who makes decisions, who is accountable and how the program is sustained beyond the initial implementation.

James Chen raises this concern:

> "Right now, security decisions are made by whoever shouts loudest. Sarah thinks she owns endpoint security because IT manages the endpoints. I think I own it because it is a security function. Dr. Patel in Cardiology thinks he can do whatever he wants with his data because he is a physician. We need clear roles."

## Instructions

### Part 1 - RACI Matrix

Build a RACI (Responsible, Accountable, Consulted, Informed) matrix for the following security activities at MedDefense:

| Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Security budget approval | | | | | |
| Vulnerability remediation | | | | | |
| Incident response execution | | | | | |
| Security policy approval | | | | | |
| Risk acceptance decisions | | | | | |
| Security awareness training | | | | | |
| Vendor risk assessment | | | | | |
| Audit coordination | | | | | |

### Part 2 - Role Definitions

Using the correct role terminology, assign the following roles to specific people or positions at MedDefense: Data Owner, Data Controller, Data Processor, Data Custodian/Steward. For each, explain what the role means and why that person holds it.

### Part 3 - The CISO Question

MedDefense currently has no CISO (the position is vacant, James is Deputy). What are the consequences of this gap for the security program? Recommend whether MedDefense should hire a full-time CISO or outsource the function (vCISO), with a one-paragraph justification that references the budget constraint.

---


