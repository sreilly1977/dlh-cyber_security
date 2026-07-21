# [0. The Framework Landscape](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/0-framework_landscape.md)

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

# [1. The NIST CSF Mapping](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/1-nist_csf_mapping.md)

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

# [2. The CIS Controls Audit](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/2-cis_controls_audit.md)

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

# [3. The Gap-to-Framework Bridge](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/3-gap_framework_bridge.md)

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

# [4. The Governance Architecture](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/4-governance_architecture.md)

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

# [5. The Risk Equation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/5-risk_equation.md)

## Goal
Master quantitative risk analysis by calculating SLE, ARO and ALE for concrete MedDefense scenarios.

## Context
Up to this point, you have assessed risk qualitatively: Critical, High, Medium, Low. That is useful for triage but useless for budgeting. A CFO does not fund "High risk." A CFO funds "$180,000 in expected annual loss that we can reduce to $12,000 for a $40,000 investment."

Quantitative risk analysis replaces opinions with math:

- **Asset Value (AV):** What is the asset worth? (Replacement cost + revenue loss + regulatory fines + reputation damage)
- **Exposure Factor (EF):** If the threat materializes, what percentage of the asset value is lost? (0% to 100%)
- **Single Loss Expectancy (SLE):** AV × EF = the cost of one incident
- **Annualized Rate of Occurrence (ARO):** How many times per year do we expect this incident? (Can be less than 1, for example 0.2 means once every 5 years)
- **Annualized Loss Expectancy (ALE):** SLE × ARO = the expected annual cost of this risk

The math is simple. The judgment behind the numbers is what matters.

### Provided Files
[`risk-scenarios.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/risk-scenarios.txt) (5 risk scenarios with data for calculation)

## Instructions
Work through the **5 risk scenarios** provided. Each gives you an asset, a threat, supporting data and some numbers to work with. For each scenario:

1. **Identify or estimate the Asset Value (AV)** with reasoning
2. **Determine the Exposure Factor (EF)** with reasoning
3. **Calculate SLE = AV × EF**
4. **Determine the ARO** using the data provided and your threat landscape knowledge
5. **Calculate ALE = SLE × ARO**
6. **State your confidence level** in the ALE (High / Medium / Low) and explain what assumption, if wrong, would change the number most dramatically

Show all work. The math is not the hard part. The judgment calls (what is the AV of patient trust? what is the realistic ARO for a ransomware attack?) are where the learning happens.

---

# [6. The ALE Workshop](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/6-ale_workshop.md)

## Goal
Calculate **ALE** for MedDefense's top 5 real risks and use the results to connect risk analysis to control investment.

## Context
The risk scenarios in Task 5 were exercises with provided data. Now you build the real ALE calculations for MedDefense, using the risks **YOU** identified across three projects, the asset values **YOU** assessed and the threat frequencies from the intelligence **YOU** gathered.

This is the point where your entire body of work converts into numbers that drive decisions.

## Instructions
Select the **5 highest-priority risks** from your work (combining gaps, vulnerabilities and threats from all three prior projects). For each risk, produce a complete ALE calculation:

```
Risk: [Descriptive name, e.g., "Ransomware encrypts EHR system"]
Source: [Gap ID + Vulnerability Finding + Threat Actor from prior projects]

Asset: [Name, from 1x00 Asset Registry]
Asset Value (AV): [$ amount, with reasoning]
  Replacement/recovery cost: [$]
  Revenue loss during downtime: [$ per day × estimated days]
  Regulatory penalties: [$]
  Reputation/patient trust impact: [$, estimated]

Exposure Factor (EF): [%]
  Reasoning: [Why this percentage?]

SLE: AV × EF = [$]

ARO: [Frequency]
  Reasoning: [Based on sector data from 1x01 + MedDefense-specific factors]

ALE: SLE × ARO = [$]

Proposed Control: [What would mitigate this risk?]
Control Annual Cost: [$]
Estimated ALE After Control: [$, with new ARO or EF]
Net Benefit: (ALE Before) - (ALE After) - (Control Cost) = [$]
```


After all 5, produce a **Risk Prioritization by ALE table** ranking the risks from highest to lowest ALE.

---

# [7. The Cost-Benefit Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/7-cost_benefit_analysis.md)

## Goal
Evaluate 8 proposed security controls using formal cost-benefit analysis to determine which investments are financially justified.

## Context
Security controls cost money. Some are worth every cent. Some cost more than the risk they mitigate. The CFO does not care about "best practices." The CFO cares about return on investment.

A control is financially justified when: **(ALE before control)** minus **(ALE after control)** is greater than **(annual cost of the control)**.

If the control costs more than the risk reduction it provides, the rational decision is to accept the risk or find a cheaper control. This is not an opinion. It is math.

## Instructions
Evaluate the following 8 proposed controls for MedDefense. Some are straightforward wins. Some are borderline. At least one is not cost-justified at all.

For each control, you will need to estimate costs and ALE impacts. Use your ALE calculations from Task 6 where applicable, and make reasonable estimates with stated assumptions for the rest.

```
Control [N]: [Name]
CIS Control Reference: [Number]
Annual Cost: [$ estimate with breakdown: license + labor + maintenance]
Risk(s) Addressed: [Which risk(s) from T6]
ALE Reduction: [$ estimate: ALE before - ALE after]
Net Value: ALE Reduction - Annual Cost = [$]
Verdict: [Justified / Marginal / Not Justified]
Recommendation: [Implement / Defer / Reject, with one-sentence reasoning]
```


### The 8 Proposed Controls

1. **Network segmentation** (VLAN implementation for server, workstation, medical device and guest zones)
2. **MFA deployment** on VPN and administrative accounts (using existing O365 E3 licenses)
3. **Enterprise SIEM deployment** (Wazuh, open-source, labor cost only)
4. **Offsite backup replication** (cloud immutable storage, AWS S3 Glacier)
5. **Endpoint Detection and Response upgrade** (from Sophos basic to Sophos Intercept X, all endpoints including servers)
6. **Dedicated firewall for Westside Clinic** (replacing the consumer router)
7. **24/7 Security Operations Center staffing** (outsourced managed SOC)
8. **Full medical device network isolation** with dedicated monitoring

After all 8, produce a **Cost-Benefit Summary Table** ranked by Net Value (highest first) and identify which controls fit within the **$120,000 annual budget**.

---

# [8. The Budget Game](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/8-budget_allocation.md)

## Goal
Make binding resource allocation decisions under realistic budget constraints, demonstrating that every dollar has a reason behind it.

## Context
You have 8 controls evaluated, ranked by net value. You have $120,000. The math does not lie: you cannot fund everything. This task forces the trade-offs that every real security program faces.

James Chen frames it bluntly:

> "The Board gave us $120,000. Not $121,000. Every dollar we spend on one control is a dollar we cannot spend on another. Choose wisely."

## Instructions

### Part 1 - The Selection

From your 8 evaluated controls (Task 7), select the combination that fits within $120,000 and maximizes total risk reduction. Document:

1. Which controls you fund (with cost)
2. Which controls you defer to next fiscal year (with reasoning)
3. Which controls you reject entirely (with reasoning)
4. Total spend vs. budget remaining

### Part 2 - The Opportunity Cost

For each deferred control, calculate the opportunity cost: what is the ALE that remains unaddressed because this control was not funded? Express it as: "By deferring [control], MedDefense accepts an estimated $[X] in annual risk exposure."

### Part 3 - The Alternative

Is there a different combination of controls that could achieve similar risk reduction at lower cost? Propose one alternative allocation and compare its total risk reduction to your primary recommendation.

---

# [9. The CFO Challenge](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/9-cfo_challenge.md)

## Goal
Defend your security recommendations against realistic financial pushback, proving you can communicate risk in the language of business.

## Context
Robert Kim, MedDefense's CFO, has reviewed your cost-benefit analysis. He has objections. Your job is not to dismiss them but to address each one with data, logic and business reasoning.

This is a skill you will use in every security role. Technical people who cannot defend their recommendations to financial stakeholders do not get funded.

### Provided Files
`cfo-pushback.txt` (5 specific objections from the CFO)

## Instructions
Read the CFO's 5 objections. For each one, write a structured rebuttal (4-6 sentences) that:

1. Acknowledges the concern as legitimate (do not dismiss the CFO)
2. Provides specific data from your analysis to counter the objection
3. Reframes the issue in terms the CFO values (cost avoidance, liability reduction, ROI, regulatory compliance)
4. If the CFO's point has genuine merit, concede partially and propose a compromise

### Format for each rebuttal:

```
Objection [N]: [CFO's statement]
Acknowledgment: [What is valid about this concern]
Counter-Evidence: [Data from your analysis]
Business Framing: [Why this matters in financial terms]
Recommendation: [What you propose, adjusted if needed]
```

After all 5 rebuttals, write a **Closing Statement** (one paragraph) summarizing the total cost of inaction vs. the cost of your proposed program.

---
