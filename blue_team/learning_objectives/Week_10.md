# Week 10 Learning Objectives

## The First Watch

### Security Fundamentals

**Q: What is the CIA Triad and how do you apply it to evaluate incidents and assets?**  
A: The CIA Triad (Confidentiality, Integrity, Availability) provides a framework to assess how incidents compromise asset properties and to prioritize protection efforts accordingly.

**Q: What is the difference between a vulnerability, a threat, and a risk?**  
A: A vulnerability is a weakness, a threat is a potential cause of unwanted impact, and risk is the likelihood and impact of a threat exploiting a vulnerability.

**Q: How do you decompose a security observation into structured risk components?**  
A: Decompose observations by identifying the affected asset, the underlying vulnerability, potential threats, and the resulting business impact to create structured risk components.

**Q: Why can the same vulnerability represent different risk levels depending on the asset it affects?**  
A: Risk varies because the same vulnerability on a critical asset with high impact represents greater risk than on a low-value asset with minimal consequences.

---

### Security Controls

**Q: What are the three categories of security controls?**  
A: Technical controls use technology, administrative controls rely on policies and procedures, and physical controls involve tangible barriers and environmental measures.

**Q: What are the five functions of security controls?**  
A: Preventive stops incidents before they occur, detective identifies them during occurrence, corrective restores systems afterward, compensating substitutes for weaker controls, and deterrent discourages attacks.

**Q: How do you classify any security measure using both dimensions simultaneously?**  
A: Classify any control by specifying its implementation type (Technical/Administrative/Physical) and its functional purpose (Preventive/Detective/Corrective/Compensating/Deterrent) simultaneously.

**Q: What is a compensating control and when is it the only viable option?**  
A: Compensating controls provide alternative protection when primary controls are impractical due to cost, technical constraints, or operational requirements.

---

### Asset and Data Management

**Q: How do you build a structured asset inventory from incomplete and scattered sources?**  
A: Build inventory by systematically aggregating records from IT systems, network scans, departmental surveys, and cloud configurations into a unified repository.

**Q: How do you classify assets by criticality using CIA-based evaluation?**  
A: Classify assets by evaluating confidentiality sensitivity, integrity requirements, and availability demands specific to each asset's role in operations.

**Q: What is the difference between data classification levels (Public, Internal, Confidential, Restricted)?**  
A: Public data is openly shareable, Internal is for employees only, Confidential requires strict access limits, and Restricted demands highest-level authorization and handling.

**Q: Why must data be protected in all three states: at rest, in transit, and in use?**  
A: Data requires protection at rest to prevent unauthorized storage access, in transit to secure network transmission, and in use to defend against runtime exploitation.

---

### Risk Assessment

**Q: How do you perform a gap analysis by cross-referencing asset criticality with existing controls?**  
A: Perform gap analysis by mapping each asset's criticality level against implemented controls to identify where protection falls below acceptable thresholds.

**Q: What are the four risk treatment strategies?**  
A: Mitigate reduces risk through controls, transfer shifts responsibility via insurance, accept acknowledges residual risk, and avoid eliminates the risk entirely.

**Q: How do you prioritize gaps based on asset criticality and potential impact?**  
A: Prioritize gaps addressing critical assets with high potential impact first, then work toward less critical systems with lower consequence profiles.

**Q: How do you validate internal findings against real-world threat intelligence?**  
A: Validate findings by cross-referencing identified vulnerabilities and threats with current intelligence feeds, CVE databases, and adversary TTPs.

---

### Professional Communication

**Q: How do you structure a security posture assessment for executive consumption?**  
A: Structure assessments with executive summary, key findings with business context, prioritized recommendations, and clear budget/resource requirements.

**Q: How do you translate technical findings into business impact language?**  
A: Translate technical findings into revenue impact, regulatory exposure, operational downtime costs, and reputational damage metrics stakeholders understand.

**Q: How do you produce a briefing that is concise, actionable, and budget-justified?**  
A: Produce briefings with quantified risks, concrete remediation steps, timeline estimates, and ROI justification tied to business outcomes.

---

## Know Your Enemy

### Threat Actors and Motivations

**Q: What are the six categories of threat actors and how do you distinguish them?**  
A: Nation-states (high resources/sophistication), criminals (profit), hacktivists (ideology), insiders (privilege), script kiddies (low skill), terrorists (destruction) — distinguished by behavior, resources, and sophistication levels.

**Q: What are threat actor motivations, and why can one org face multiple reasons?**  
A: Motivations include financial gain, espionage, disruption, ideology, revenge, and thrill-seeking; organizations face different attacks because various actors pursue different objectives against the same target.

**Q: How do you profile a threat actor from observed behavior without attribution?**  
A: Analyze TTPs, tools used, targeting patterns, operational hours, language cues, and attack sophistication to infer actor category and capabilities without claiming definitive identity.

**Q: Why do ransomware groups target healthcare, and how does RaaS work?**  
A: Healthcare has critical uptime needs and sensitive data, increasing payment likelihood; RaaS allows affiliates to rent malware infrastructure and split profits with developers.

**Q: What's the difference between malicious and negligent insiders, and why are both threats?**  
A: Malicious insiders intentionally harm the organization; negligent insiders cause breaches through carelessness; both bypass perimeter defenses with legitimate access.

**Q: How does supply chain risk create uncontrollable exposure?**  
A: Third-party vendors introduce vulnerabilities the organization cannot directly secure, creating attack paths through trusted relationships beyond perimeter controls.

---

### Threat Vectors and Attack Surfaces

**Q: What is the complete taxonomy of threat vectors?**  
A: Message-based (email/SMS), file-based (malicious documents), network-based (protocols/services), physical (access/devices), human (social engineering), and supply chain (vendors/partners).

**Q: What are every major social engineering technique?**  
A: Phishing (email), vishing (voice), smishing (SMS), pretexting (false scenario), BEC (business email compromise), impersonation, watering hole (compromised site), brand impersonation, typosquatting (fake domains).

**Q: How do you decompose an organization's attack surface?**  
A: External (internet-facing systems), internal (network segments/trusted users), human (employee awareness/processes) — mapped to identify all potential entry points.

**Q: How do you trace a vector from initial access through to objective?**  
A: Map the progression from initial access → persistence → privilege escalation → lateral movement → data exfiltration/impact, documenting each phase and control opportunities.

---

### Threat Modeling and Frameworks

**Q: How do you apply STRIDE to a specific system architecture?**  
A: Evaluate each component against Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege to systematically identify threat classes.

**Q: How do you map attack steps to MITRE ATT&CK tactics?**  
A: Align observed or modeled actions to ATT&CK framework tactics (reconnaissance, initial access, execution, persistence, etc.) for standardized threat tracking and defense planning.

**Q: How do you construct a kill chain showing full attack sequence?**  
A: Document reconnaissance, weaponization, delivery, exploitation, installation, command-and-control, and action on objectives to visualize complete attack flow from entry to impact.

**Q: How do you correlate internal gap analysis with external threat landscape?**  
A: Match identified control gaps against active threat actor TTPs and priorities to focus remediation on risks that align with real-world attacker behaviors.

---

### Professional Communication

**Q: How do you produce a Threat Landscape Report?**  
A: Include current threat trends, specific indicators of compromise, affected assets, evidence sources, risk ratings, and prioritized actionable recommendations for leadership.

**Q: How do you communicate threat intelligence to non-technical stakeholders?**  
A: Translate technical threats into business impact: financial exposure, regulatory risk, operational disruption, reputational damage, and resource requirements for mitigation.
