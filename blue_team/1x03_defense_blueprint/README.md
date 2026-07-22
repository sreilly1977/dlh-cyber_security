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

# [10. The Risk Register](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/10-risk_register.md)

## Goal
Build the formal **Risk Register** that will serve as the operational backbone of MedDefense's security program.

## Context
Every deliverable you have produced so far, the gap analysis, the threat landscape, the vulnerability assessment, the ALE calculations, feeds into one master document: the **Risk Register**. This is not a summary. It is the living governance instrument that tracks every identified risk through its lifecycle: identification, scoring, treatment, monitoring and review.

A professional Risk Register is the document the CISO opens when the Board asks, "What keeps you up at night?" It is reviewed monthly, updated when new threats emerge and when controls are deployed. It is the single source of truth for the security program's risk posture.

## Instructions
Build a **MedDefense Risk Register** containing your top 10 risks. Use the following fields for each entry:

| Field | Description |
|-------|-------------|
| Risk ID | Sequential identifier (RISK-001, RISK-002, etc.) |
| Risk Description | One sentence describing the risk event |
| Risk Category | Strategic / Operational / Compliance / Financial |
| Threat Source | Actor type from 1x01 |
| Vulnerability | Finding ID from 1x02 |
| Affected Asset(s) | From 1x00 Asset Registry |
| Likelihood | 1-5 scale with definition |
| Impact | 1-5 scale with definition |
| Inherent Risk Score | Likelihood × Impact |
| ALE | From T5/T6 calculations (where available) |
| Risk Owner | Specific person/role at MedDefense |
| Treatment Decision | Mitigate / Transfer / Accept / Avoid |
| Treatment Justification | Why this decision, in one sentence |
| Planned Control(s) | Specific controls from T7 |
| Residual Risk | After planned controls are applied |
| KRI | Key Risk Indicator that would signal this risk is increasing |
| Review Date | When this risk entry will be reassessed |

After the register, write a **Risk Register Governance Note** (one paragraph): Who maintains this register at MedDefense? How often is it reviewed? What triggers an out-of-cycle review? What happens when a KRI threshold is breached?

--- 

# [11. The Control Selection](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/11-control_selection.md)

## Goal
Select and justify specific security controls for each risk in the register, mapping every choice to CIS Controls and NIST CSF.

## Context
The Risk Register tells you WHAT risks exist. Now you decide WHAT to do about each one. Every control you select must satisfy three criteria: it must reduce the specific risk it targets (effectiveness), it must be affordable within the budget (efficiency) and it must map to a recognized framework so auditors can verify it (traceability).

## Instructions
For each of the 10 risks in your Risk Register that has a treatment of "Mitigate," select one or more specific controls. For each control:

```
Risk: [RISK-ID from T10]
Selected Control: [Specific name/description]
CIS Control Mapping: [Control number and safeguard ID]
NIST CSF Mapping: [Function.Category, e.g., PR.AC]
Control Type: [Preventive / Detective / Corrective / Compensating]
Control Category: [Technical / Administrative / Operational / Physical]
Implementation Cost: [From T7 analysis]
Expected Risk Reduction: [Quantified where possible]
Dependencies: [Does this control require another control to be in place first?]
```

After the individual selections, produce a **Control Dependency Map:** a text diagram showing which controls must be implemented before others. For example, network segmentation must precede medical device isolation. SIEM must precede 24/7 monitoring.

---

# [12. The Policy Draft](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/12-acceptable_use_policy.md)

## Goal
Draft an **Acceptable Use Policy** for MedDefense that is grounded in identified risks, enforceable and realistic for a hospital environment.

## Context
Frameworks give structure. Controls give protection. Policies give authority. Without a written, approved policy, a security team cannot enforce anything. When the billing clerk plugs in a personal USB drive, the response is either "please do not do that" (informal, unenforceable) or "you are violating Section 3.2 of the AUP, which was signed during onboarding and approved by the CEO" (formal, enforceable, documented).

This task is unique because it requires you to think about security from the perspective of the people who have to live with it. A policy that forbids everything is ignored by everyone. A policy that is unreasonably strict for clinical staff will be worked around. A good policy is one that people can actually follow.

## Instructions
Draft an **Acceptable Use Policy (AUP)** for MedDefense Health Systems. The policy must cover:

1. **Purpose and Scope:** Who does this policy apply to? What systems does it cover?

2. **Acceptable Use of Systems:** What are employees permitted to do with MedDefense systems and network resources?

3. **Prohibited Activities:** What is explicitly forbidden? (Connect to the specific risks you identified, not generic lists.)

4. **Personal Devices and Removable Media:** Rules for USB drives, personal phones, personal laptops. Reference the shadow IT findings from 1x00 and the USB finding from 1x02.

5. **Password and Authentication Requirements:** Minimum requirements aligned with the MFA deployment from your control selection.

6. **Data Handling:** How must patient data, financial data and credentials be handled? Reference your data classification from 1x00.

7. **Monitoring and Enforcement:** What does MedDefense monitor and what happens when the policy is violated?

8. **Acknowledgment:** A signature block for employees.

### Quality Criteria
The policy must be specific enough to be enforceable but practical enough for a hospital where nurses are busy saving lives and will not read a 20-page document. Target 2-3 pages.

---

# [13. The Quick Wins](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/13-quick_wins.md)

## Goal
Identify and design 5 security improvements that can be implemented within 2 weeks at zero or minimal cost.

## Context
The full roadmap takes 6 months. The Board approved the budget last week. But James Chen has a more immediate concern:

> "What can we do THIS WEEK that makes us safer? Not the big purchases. Not the architecture changes. What can we do with what we already have?"

Quick wins matter because they demonstrate momentum, reduce risk immediately and build credibility with the Board before the big spending begins.

## Instructions
Identify 5 quick wins that MedDefense can implement within 2 weeks using existing resources. These must require no budget approval (free or covered by existing contracts) and no major infrastructure changes.

For each quick win:

```
Quick Win #[N]: [Descriptive name]
Risk Addressed: [RISK-ID from T10]
Action: [What specifically to do, step by step]
Owner: [Who executes this?]
Timeline: [Days to implement]
Cost: [$0 or minimal, explain]
Risk Reduction: [What threat path does this disrupt? Reference kill chains from 1x01]
Verification: [How do you confirm this was done correctly?]
```

After all 5, answer in one paragraph: Why do quick wins matter beyond their immediate risk reduction? What organizational purpose do they serve in the first month of a security program?

---

# [14. The Segmentation Architecture](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/14-segmentation_architecture.md)

## Goal
Design a network segmentation plan that transforms MedDefense's flat network into a defensible architecture.

## Context
The flat network appeared in every kill chain you built in 1x01. It amplified every vulnerability in 1x02. It is the single architectural weakness whose resolution has the greatest cascading effect on MedDefense's risk posture. Now you design the fix.

This task is different from the others because it is a design exercise. You are not analyzing or assessing. You are creating a network architecture that does not yet exist.

## Instructions
Design a network segmentation plan for MedDefense with the following deliverables:

### Part 1 - Zone Definition

Define at least 5 network zones (VLANs) with their purpose, what systems belong in each and what traffic flows are permitted between zones:

1. **Server zone** (EHR, billing, file server, AD)
2. **Clinical workstation zone** (nurse stations, physician workstations)
3. **Medical device zone** (monitors, pumps, PACS, MRI)
4. **Management zone** (IT admin workstations, security tools)
5. **Guest/IoT zone** (non-clinical devices, visitor WiFi)

For each zone: name, IP range, systems included, allowed outbound connections and allowed inbound connections.

### Part 2 - Firewall Rules

Write 10 critical firewall rules (in pseudocode format: source zone → destination zone : port/protocol : allow/deny) that enforce the segmentation. Include at least 2 deny rules and explain what each rule prevents.

### Part 3 - Kill Chain Impact

Take your #1 kill chain from 1x01 (the ransomware scenario). Walk through it step by step and identify at which step(s) the segmentation would have broken the chain. Estimate the percentage of your top 5 kill chains that would be disrupted by this segmentation design.

---

# [15. Red Team Your Blueprint](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/15-red_team_blueprint.md)

## Goal
Attack your own security strategy to find its weaknesses before an adversary does.

## Context
Every plan has blind spots. The best way to find them is to think like the attacker. In this task, you switch sides: you are no longer the security architect defending MedDefense. You are the **BlackReef ransomware affiliate** (from 1x01) who has read your Security Strategy Document and needs to find a way in despite the new controls.

This adversarial thinking exercise is what separates good strategies from great ones. A plan that survives its own red team is a plan worth funding.

## Instructions

### Part 1 - The Attacker's Perspective

Assume all controls from your budget allocation (T8) are fully implemented. As a BlackReef affiliate:

1. Which of your 5 kill chains from 1x01 is STILL viable despite the new controls? Why?

2. What alternative attack path would you use to bypass the implemented controls? Describe a 4-5 step attack sequence that exploits the gaps your budget could NOT close (the deferred controls from T8).

3. What insider threat scenario remains dangerous despite the new controls? (Reference T3 from 1x01.)

### Part 2 - The Honest Assessment

Based on your red team exercise:

1. Rate the overall residual risk after your proposed controls: Critical / High / Medium / Low. Justify.

2. Identify the single biggest remaining gap in MedDefense's defenses.

3. Recommend what should be the #1 priority for next year's budget based on what you found.

---

# [16. The Risk Appetite Debate](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/16-risk_appetite.md)

## Goal
Define MedDefense's risk appetite and demonstrate that risk acceptance is a legitimate, documented governance decision.

## Context
Not every risk is worth mitigating. Some risks cost more to fix than they cost if they happen. Some risks require accepting for operational reasons: the Windows XP MRI workstation cannot be replaced until the $2.1M scanner lease expires in 18 months. Accepting risk is not negligence. It is a governance decision made by an authorized person, documented, monitored and reviewed.

The Board must decide: What level of risk is MedDefense willing to live with?

## Instructions

### Part 1 - Risk Appetite Statement

Draft a **Risk Appetite Statement** for MedDefense (3-5 sentences). It should define: the overall level of risk the Board considers acceptable, any absolute limits (risks that must always be mitigated regardless of cost, for example risks to patient safety) and the authority required to accept risks above a defined threshold.

### Part 2 - The Three Decisions

Select 3 risks from your Risk Register that received a treatment decision of "Accept" or that you now believe should be accepted despite an earlier "Mitigate" recommendation. For each:

```
Risk: [RISK-ID]
Treatment Decision: Accept
Authority: [Who approved this acceptance? Why is it their decision?]
Justification: [Why is acceptance rational? Reference cost-benefit from T7]
Compensating Measure: [What monitoring or alternative action partially offsets the accepted risk?]
Review Trigger: [What event would require revisiting this acceptance?]
```

### Part 3 - The Debate

James Chen (security-first mindset) and Robert Kim (cost-first mindset) disagree on whether to accept the risk of the Windows XP MRI workstation. Write James's argument for mitigation (3-4 sentences) and Robert's argument for acceptance (3-4 sentences). Then write your own verdict (3-4 sentences), noting whose reasoning you find more compelling and why.

---

# [17. The Security Strategy Document](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/17-security_strategy.md)

## Goal
Produce the comprehensive Security Strategy Document that synthesizes all analysis into a Board-ready deliverable.

## Context
This is the capstone deliverable of the project. It is the companion document to the Security Posture Assessment (1x00), the Threat Landscape Report (1x01) and the Vulnerability Assessment Summary (1x02). Together, the four documents form the complete security intelligence and strategy package for MedDefense.

## Instructions
Produce a complete **MedDefense Health Systems, Security Strategy Document**.

### Required Structure:

1. **Executive Summary** (1 page max)
    - The current risk posture in 2-3 sentences
    - The strategic approach (framework adopted, methodology)
    - Total investment requested and expected risk reduction
    - Top 3 priority actions

2. **Governance Framework**
    - Framework selection rationale (T0)
    - NIST CSF Current vs Target Profile summary (T1)
    - CIS Controls maturity scorecard (T2)
    - Governance structure and roles (T4)

3. **Quantitative Risk Analysis**
    - Top 5 risks by ALE (T6)
    - Risk Register summary (T10)
    - Risk appetite statement (T16)

4. **Control Strategy**
    - Cost-benefit analysis results (T7)
    - Budget allocation with justification (T8)
    - Control selection with framework mapping (T11)
    - Quick wins for immediate implementation (T13)

5. **Architecture Recommendations**
    - Network segmentation design (T14)
    - Kill chain disruption analysis

6. **Policy Foundation**
    - AUP summary (T12)
    - Policy roadmap (what other policies are needed and when)

7. **Residual Risk Assessment**
    - Red team findings (T15)
    - Accepted risks with justification (T16)
    - Year 2 priorities

8. **Implementation Roadmap**
    - 6-month timeline with milestones and dependencies
    - Phase 1 (Month 1-2): Quick wins + procurement
    - Phase 2 (Month 3-4): Core controls deployment
    - Phase 3 (Month 5-6): Validation + optimization
    - Success metrics for each phase

9. **Next Steps**
    - Connection to Project 1x04 (Cryptographic Foundation)
    - The path from strategy to implementation
    
---

# 18. [The Roadmap](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/18-roadmap.md)

## Goal
Transform the strategy into a visual, dependency-aware implementation timeline.

## Context
A strategy document says "what." A roadmap says "when." The IT Director, Sarah Park, needs a document she can pin to the wall and track weekly: what happens first, what depends on what, who owns each milestone and how she knows each phase is complete.

## Instructions
Produce a **6-Month Security Roadmap** for MedDefense with:

- **Month-by-month breakdown:** For each month (1-6), list the specific actions, the responsible owner, the dependencies (what must be completed before this can start) and the completion criteria (how do you know it is done).

- **Dependency chain:** Identify at least 3 dependencies between actions (for example: network segmentation must precede medical device isolation, SIEM deployment must precede alert monitoring).

- **Milestones:** Define 4 milestones that represent meaningful checkpoints. For each: the date, what has been accomplished and what the measurable indicator of success is.

- **Risk to timeline:** What are the 2 most likely causes of schedule slippage? For each, describe the contingency plan.

---

# [19. The Board Pitch](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x03_defense_blueprint/19-board_pitch.md)

## Goal
Deliver the entire strategy in 300 words or fewer.

## Context
Same drill, fourth time. Board meeting Monday. James Chen gives you the brief:

> "This time, you are not just reporting findings. You are asking for money. The Board needs to approve the $120,000 spend. You have 300 words to convince them."

The pitch must answer exactly four questions: Where are we today? What is at stake? What do we recommend? What do we gain?

## Instructions
Write a Board Pitch of **300 words maximum**.

### Structure:

1. **Current State** (2-3 sentences): Where MedDefense stands after 4 weeks of security assessment. The one-line verdict.

2. **The Risk** (2-3 sentences): What happens if MedDefense does nothing. One specific scenario with a specific dollar amount (from your ALE).

3. **The Plan** (3-4 sentences): What you recommend, how much it costs, what it achieves. Reference the top 3 controls and their combined risk reduction.

4. **The Return** (1-2 sentences): For every dollar invested, how many dollars of expected loss are avoided? The ROI in business terms.

### Constraint
A Board member who reads ONLY this pitch must understand the risk, the plan and the return. No jargon without immediate translation.

---
