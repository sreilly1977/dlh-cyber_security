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


