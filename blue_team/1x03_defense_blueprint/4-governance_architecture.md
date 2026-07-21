# 4. The Governance Architecture
## Security Governance Structure for MedDefense Health Systems

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 4)  
**Reference:** 1x00 Organizational Context, 1x03 Task 0 Framework Selection

---

## Part 1 — RACI Matrix

**Legend:** R = Responsible (does the work), A = Accountable (owns the outcome, one per row), C = Consulted (provides input), I = Informed (kept up to date)

| Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst |
|----------|-----|----------------------|----------------------|------------|-------------------|
| Security budget approval | A | R | C | I | C |
| Vulnerability remediation | I | A | R | I | R |
| Incident response execution | I | A | R | C | R |
| Security policy approval | A | C | C | C | R |
| Risk acceptance decisions | A | C | C | C | R |
| Security awareness training | I | A | I | R | R |
| Vendor risk assessment | I | A | C | C | R |
| Audit coordination | I | A | R | C | R |

### Notes on Key Decisions

**Security Budget Approval:** The CEO is Accountable as the ultimate fiscal authority. James is Responsible for preparing the budget proposal with cost estimates and justification from the Priority Matrix. Sarah is Consulted because IT operational budgets intersect with security spending. Department Heads are Informed when budget decisions affect their resources.

**Vulnerability Remediation:** James is Accountable for ensuring remediations are completed within SLA timelines. Sarah is Responsible for executing patches and configuration changes on IT-managed systems. The Security Analyst is Responsible for validation, rescans, and verifying effectiveness per the Task 23 Validation Plan. This maintains business accountability (James) while distributing technical execution (Sarah) and verification (Analyst).

**Incident Response Execution:** James is Accountable for IR plan activation, breach notification decisions, and external communications. Sarah is Responsible for IT infrastructure containment actions (isolating systems, disabling accounts). The Security Analyst is Responsible for technical investigation, forensic preservation, and eradication. Department Heads are Consulted when clinical operations are impacted, ensuring business continuity considerations inform response decisions.

**Security Policy Approval:** The CEO is Accountable as the organizational authority. James is Consulted, providing security expertise and drafting policy language. Sarah is Consulted regarding IT feasibility and implementation requirements. Department Heads are Consulted where policies affect operational workflows, particularly clinical departments. The Security Analyst is Responsible for researching requirements and drafting initial policy documents, but holds no approval authority.

**Risk Acceptance Decisions:** The CEO is Accountable as the sole risk acceptance authority for the organization. The CEO owns the business decision to accept, mitigate, or transfer risk; this authority cannot be delegated to a security function. James is Consulted, providing risk analysis and quantified impact (ALE, remediation cost) to inform the CEO's decision. Sarah and Department Heads are Consulted when risk acceptance affects their operational domains. The Security Analyst is Responsible for collecting supporting data, calculating ALE figures, and documenting the risk register entry, but holds no decision-making authority. This ensures that risk acceptance remains a business accountability, not a security department determination, preserving separation between risk identification (security) and risk ownership (business leadership).

**Security Awareness Training:** James is Accountable for program delivery and effectiveness measurement. Department Heads are Responsible for ensuring their staff completes training and participates in phishing simulations. The Security Analyst is Responsible for content development and simulation execution. This distributes operational responsibility to business leaders who manage their staff daily.

**Vendor Risk Assessment:** James is Accountable for overall vendor security posture and contract compliance. Sarah is Consulted on technical requirements and integration considerations. Department Heads are Consulted when vendors support their operations. The Security Analyst is Responsible for conducting assessments and documenting findings.

**Audit Coordination:** James is Accountable for audit readiness and regulatory compliance. Sarah is Responsible for providing technical evidence and implementing corrective actions. Department Heads are Consulted when audits affect their areas. The Security Analyst is Responsible for compiling audit documentation and responding to auditor questions.

---

## Part 2 — Role Definitions

### Data Owner

**Assigned To:** Department Heads (e.g., Dr. Patel in Cardiology owns cardiovascular patient data, Revenue Cycle Manager owns billing data)

**Definition:** The Data Owner is the senior business leader who is accountable for a specific data domain, including determining who should have access, classifying the data sensitivity, and approving access requests. The Data Owner decides the business purpose for which data is used and bears the business consequences if it is compromised.

**Why This Person Holds It:** Department Heads understand the clinical or operational context of their data and are positioned to make informed risk decisions about its use. Dr. Patel understands which staff members need access to cardiology patient records and what constitutes appropriate clinical use. Assigning data ownership to IT or Security would place business decisions in the hands of people who do not understand the clinical context.

### Data Controller

**Assigned To:** MedDefense Health Systems (represented by the CEO as the organizational authority)

**Definition:** Under HIPAA, the Data Controller (referred to as "Covered Entity" in HIPAA terminology) is the organization that determines the purposes and means of processing Protected Health Information (PHI). The Data Controller bears legal accountability for how PHI is collected, stored, used, and shared, and is responsible for ensuring HIPAA compliance including breach notification.

**Why This Entity Holds It:** MedDefense, as a healthcare provider that creates, receives, maintains, and transmits PHI, is a Covered Entity under HIPAA. The CEO, as the highest organizational authority, represents the entity in legal and regulatory matters. This role cannot be delegated to IT or contracted out; the organization itself holds the legal obligation.

### Data Processor

**Assigned To:** External service providers handling PHI on MedDefense's behalf (e.g., SecurePoint Consulting for security scanning, BD for infusion pump cloud telemetry, O365 for email processing)

**Definition:** Under HIPAA, the Data Processor (referred to as "Business Associate" in HIPAA terminology) is a third-party organization that creates, receives, maintains, or transmits PHI on behalf of the Covered Entity to perform a function or service. Data Processors must sign Business Associate Agreements (BAAs) that legally bind them to safeguard PHI.

**Why These Entities Hold It:** These organizations handle PHI or systems containing PHI but do not determine the purposes of processing. Each requires a signed BAA defining their security obligations.

### Data Custodian / Steward

**Assigned To:** IT Director Sarah Park and IT Operations staff

**Definition:** The Data Custodian is the person or team responsible for the technical implementation of data protection controls, including access provisioning, encryption, backup, transmission security, and storage configuration. The Custodian executes the Data Owner's access decisions and the Controller's policy requirements at the technical level.

**Why This Person Holds It:** Sarah Park and the IT Operations team manage the servers, databases, network infrastructure, and backup systems where PHI physically resides. They configure PostgreSQL access controls, manage Active Directory accounts, administer the Synology NAS backups, and implement network segmentation. IT does not decide who should access data or for what purpose; they implement and enforce those decisions technically.

---

## Part 3 — The CISO Question

### Consequences of the Vacant CISO Position

The vacant CISO position creates five specific consequences for the security program:

**1. No Single Point of Accountability.** Without a CISO, security accountability is distributed ambiguously between James (Deputy CISO) and Sarah (IT Director). This creates the jurisdictional friction James described, where both believe they own endpoint security and neither fully does. During an incident, unclear authority delays containment decisions.

**2. Insufficient Authority for Cross-Departmental Enforcement.** A Deputy CISO lacks the organizational standing to enforce security requirements on Department Heads. Dr. Patel in Cardiology can resist security mandates because James does not have C-level authority to override departmental autonomy. A CISO at the executive table holds the authority to mandate compliance.

**3. No Strategic Owner for the Security Program.** The Deputy CISO role is operational, focusing on day-to-day security activities. Building and sustaining a multi-year security program (the 1x03 roadmap, HIPAA compliance, framework adoption, audit readiness) requires someone whose primary responsibility is strategic security leadership, not tactical execution.

**4. Board-Level Visibility Gap.** The Board approved a $120K security budget based on the threat landscape (1x01). Without a CISO, there is no executive-level advocate consistently presenting security posture, risk metrics, and progress to the Board. James is invited to Board meetings as a Deputy, not as a peer to the CEO and CFO.

**5. Audit and Regulatory Risk.** HIPAA Security Rule does not explicitly require a CISO, but OCR investigators look for clear security leadership during breach investigations. An organization with a vacant CISO position during a breach faces heightened scrutiny and potential penalties for organizational negligence.

### Recommendation: Virtual CISO (vCISO)

MedDefense should engage a Virtual CISO (vCISO) through a managed security services provider rather than hiring a full-time CISO at this stage. A full-time CISO commands a salary of $180K to $250K in the healthcare market, which would consume the entire $120K security budget and leave no funds for the remediation actions identified in 1x02 Task 20. A vCISO engagement typically costs $60K to $90K annually for 1-2 days per week of strategic guidance, fitting within the budget while preserving funds for vulnerability remediation, network segmentation, and monitoring infrastructure. The vCISO provides the executive-level authority, Board reporting, HIPAA compliance leadership, and cross-departmental enforcement that the vacant position demands, while James Chen continues as the operational security lead executing the day-to-day program. This arrangement should be revisited in 12 to 18 months when the initial remediation wave is complete and the security program matures to a point where a full-time CISO becomes sustainable.

---

## Governance Structure Diagram (Text)

**Board of Directors** — Approves budget, accepts enterprise risk, receives quarterly CSF reports  
&nbsp;&nbsp;&nbsp;&nbsp;**|**  
&nbsp;&nbsp;&nbsp;&nbsp;**v**  
**CEO** — Accountable for organizational security, owns risk acceptance decisions, delegates execution  
&nbsp;&nbsp;&nbsp;&nbsp;**|**  
&nbsp;&nbsp;&nbsp;&nbsp;**v**  
**Virtual CISO (vCISO)** — Strategic security leadership, Board reporting, HIPAA compliance, cross-departmental authority  
&nbsp;&nbsp;&nbsp;&nbsp;**|**  
&nbsp;&nbsp;&nbsp;&nbsp;**v**  
**Deputy CISO (James Chen)** — Security program execution, risk analysis preparation, IR plan activation, vendor risk assessment  
&nbsp;&nbsp;&nbsp;&nbsp;**|**  
&nbsp;&nbsp;&nbsp;&nbsp;**v**  
**IT Director (Sarah Park)** — Infrastructure security implementation, patch management, account management, backup administration  
&nbsp;&nbsp;&nbsp;&nbsp;**|**  
&nbsp;&nbsp;&nbsp;&nbsp;**v**  
**Department Heads** — Data ownership, staff training compliance, operational risk consultation  
&nbsp;&nbsp;&nbsp;&nbsp;**|**  
&nbsp;&nbsp;&nbsp;&nbsp;**v**  
**Security Analyst** — Vulnerability scanning, validation, monitoring, awareness training content, forensic investigation  

---

*Prepared by: Security Department*  
*References: 1x00 Organizational Context (staffing, budget, vacant CISO), 1x02 Task 20 (budget deficit), 1x03 Task 0 (framework selection), HIPAA Security Rule 45 CFR 164.308 (Administrative Safeguards — Security Management Process), NIST CSF 2.0 Govern Function*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
