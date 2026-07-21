# 0. The Framework Landscape
## Understanding Enterprise Security Frameworks for Strategic Defense Planning

**Date:** July 22, 2026  
**Analyst:** Security Department  
**Document:** Project 1x03 — Defense Strategy and Risk Register (Task 0)  
**Predecessor Projects:** 1x00 (Security Posture), 1x01 (Threat Landscape), 1x02 (Vulnerability Assessment)  

---

## Part 1 - Three-Framework Summary

### NIST Cybersecurity Framework (CSF) 2.0

**What it is and who publishes it:** The NIST CSF is published by the U.S. National Institute of Standards and Technology (NIST) under the Department of Commerce. Version 2.0 was released in February 2024, updating the original 2014 framework. It is voluntary guidance, not a regulation, though federal contractors are increasingly expected to adopt it.

**Primary purpose:** The CSF is designed to help organizations manage cybersecurity risk through a common language and structured approach. It answers the question "What should we do?" by providing high-level categories for identifying assets, protecting systems, detecting threats, responding to incidents, and recovering from disruptions. It is intended for executives, risk managers, and boards to understand security posture at a strategic level.

**Structure:** The CSF 2.0 is organized into six core Functions (Govern, Identify, Protect, Detect, Respond, Recover) broken down into Categories and Subcategories. Version 2.0 added the Govern function as a sixth pillar and restructured the original five to better align with enterprise governance. Each Subcategory includes Implementation Tiers (Partial, Risk-Informed, Repeatable, Adaptive) and Profiles that help organizations customize the framework to their context.

**Typical users and context:** Widely adopted by U.S. critical infrastructure, healthcare providers, and private sector organizations. Healthcare organizations frequently use NIST CSF because it aligns with HIPAA Security Rule requirements and is recognized by CMS (Centers for Medicare and Medicaid Services) and OCR (Office for Civil Rights) for breach investigations. Regional hospitals typically use it for internal risk management and regulatory demonstrations rather than third-party certification.

### CIS Controls v8

**What it is and who publishes it:** The CIS Controls are published by the Center for Internet Security (CIS), a nonprofit organization founded in 2000 that brings together government agencies, healthcare providers, financial institutions, and technology companies. Version 8 was released in June 2021, replacing v7 and introducing implementation groups and alignment with NIST and ISO frameworks.

**Primary purpose:** The CIS Controls answer the question "How should we do it?" by providing prioritized, specific, and actionable security measures. Unlike NIST CSF's high-level guidance, the CIS Controls are tactical checklists that tell IT and security teams exactly what to implement (e.g., "Inventory and Control of Hardware Assets," "Email and Web Browser Protections"). They are designed to be immediately actionable and measurable.

**Structure:** The CIS Controls v8 consists of 18 Safeguards grouped into three Implementation Groups (IG1, IG2, IG3). IG1 represents basic cyber hygiene achievable by any organization with minimal resources. IG2 is for medium-risk organizations. IG3 is for high-security environments. Each Safeguard has precise implementation steps with technical details, references to industry standards, and measurable outcomes.

**Typical users and context:** Organizations seeking practical, step-by-step security guidance across all sectors. Particularly popular among IT operations teams and security engineers who need concrete action items. Often used alongside NIST CSF (CSF defines the "what," CIS defines the "how") or as an independent program for resource-constrained organizations. Healthcare IT teams use it to establish baseline security without requiring extensive policy development or third-party audits.

### ISO/IEC 27001:2022

**What it is and who publishes it:** ISO/IEC 27001 is an international standard published by the International Organization for Standardization (ISO) and the International Electrotechnical Commission (IEC). The current version (ISO/IEC 27001:2022) was released in October 2022. It is part of the ISO 27000 family of information security standards.

**Primary purpose:** ISO 27001 answers the question "Can we prove we are doing it?" by establishing requirements for an Information Security Management System (ISMS). Unlike NIST CSF and CIS Controls which are guidelines, ISO 27001 is auditable and certifiable. Organizations can engage accredited auditors to verify their ISMS meets the standard, producing an internationally recognized certificate that demonstrates security maturity to customers, partners, and regulators.

**Structure:** ISO 27001:2022 is organized into clauses (4 through 10) that define ISMS requirements, plus Annex A containing 93 security controls organized into four themes (Organizational, People, Physical, Technological). Clause 4 covers context and scope, Clause 5 covers leadership commitment, Clause 6 covers planning, Clause 7 covers support, Clause 8 covers operation, Clause 9 covers performance evaluation, and Clause 10 covers improvement. Organizations must implement Clause 4-10 requirements and select appropriate Annex A controls based on risk assessment.

**Typical users and context:** Organizations needing third-party assurance or operating in regulated industries with international partners. Financial institutions, cloud service providers, and multinational corporations use it extensively. In the United States, healthcare providers typically do not seek ISO 27001 certification because HIPAA compliance does not require it. However, vendors selling to government agencies or multinational healthcare enterprises increasingly expect ISO 27001 certification from their suppliers. Certification costs $20K-$100K annually and requires dedicated resources for maintenance and recertification every three years.

---

## Part 2 - Relationship Map

The three frameworks are complementary, not competitive. NIST CSF provides the strategic risk management vocabulary that executives and Boards need to understand security posture and allocate resources. It defines the goals and categories but stops short of prescribing technical implementation. CIS Controls fills that gap by providing the tactical, prioritized safeguards that IT and security teams can deploy immediately. It translates NIST's high-level categories into concrete action items that can be tracked, measured, and verified. ISO 27001 adds the formal management system layer that enables third-party verification and audit readiness. When used together, NIST CSF guides organizational strategy and governance decisions, CIS Controls delivers the implementation roadmap for IT operations, and ISO 27001 provides the audit trail and certification path for regulatory or customer assurance. For resource-constrained organizations, you do not need all three at full depth. A typical integration approach is: use NIST CSF for Board reporting and risk management, use CIS Controls (IG1 initially, then IG2) for daily security work, and pursue ISO 27001 certification only if business requirements demand it.

---

## Part 3 - MedDefense Framework Selection

### Recommendation

**MedDefense should adopt the NIST CSF 2.0 as its strategic backbone, supplemented by CIS Controls v8 Implementation Group 1 for tactical execution.** ISO 27001 should be deferred unless a specific business requirement emerges (e.g., a major payer or vendor mandates it).

### Justification

**Staffing Reality:** With only one security analyst and one deputy CISO, MedDefense lacks the personnel to manage a full ISO 27001 certification program, which typically requires 3-5 dedicated FTEs for documentation, evidence collection, audit preparation, and maintenance. NIST CSF + CIS Controls can be managed by 1-2 people using the existing vulnerability management cycle already established in Tasks 1x00-1x03.

**Regulatory Alignment:** Healthcare organizations in the United States must comply with HIPAA Security Rule requirements. NIST CSF maps directly to HIPAA Administrative, Physical, and Technical Safeguards, making it easier to demonstrate compliance to OCR during investigations. CMS and state health departments also recognize NIST CSF. ISO 27001 provides no additional HIPAA compliance benefit but adds significant cost and complexity.

**Budget Constraints:** The $120K annual security budget cannot absorb ISO 27001 certification costs ($20K-$50K initial audit plus $10K-$20K annual surveillance audits) without sacrificing other priorities. NIST CSF and CIS Controls are free to adopt. Investment can go toward tools and remediation rather than certification fees.

**Maturity Path:** Starting with NIST CSF allows MedDefense to establish the risk vocabulary and governance structure needed for Board communication without overwhelming technical teams. CIS Controls IG1 provides achievable baseline hygiene that can be deployed within 90 days, building momentum before progressing to IG2. This phased approach delivers visible progress without requiring immediate transformation of the entire security program.

**Deferral Rationale:** ISO 27001 certification should remain on a 12-24 month watchlist. If MedDefense expands to serve commercial health plans, cloud hosting customers, or international entities that require supplier security certification, ISO 27001 may become necessary. Until then, it is a luxury MedDefense cannot afford given the active vulnerabilities requiring remediation in 1x02.

### Implementation Plan (First 90 Days)

| Week | Action | Framework Component |
|------|--------|---------------------|
| **Week 1-2** | Publish Governance Charter assigning CSF responsibilities | NIST CSF (Govern Function) |
| **Week 3-4** | Map existing findings to NIST CSF Subcategories | NIST CSF (Identify Function) |
| **Week 5-8** | Deploy CIS Controls IG1 Safeguards 1-7 (asset inventory, secure config) | CIS Controls v8 IG1 |
| **Week 9-12** | Establish quarterly CSF profile reviews with Board reporting | NIST CSF (Detect/Respond/Recover Functions) |

---

*Prepared by: Security Department*  
*References: NIST CSF 2.0 (February 2024), CIS Controls v8 (June 2021), ISO/IEC 27001:2022, HIPAA Security Rule (45 CFR Parts 160 and 164), HHS Office for Civil Rights Audit Protocol*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
