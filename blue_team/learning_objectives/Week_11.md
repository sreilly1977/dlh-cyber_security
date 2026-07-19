# The Vulnerability Ecosystem

**What a CVE is, how CVE identifiers are structured and what the lifecycle states mean**
CVE is a standardized identifier format (CVE-YEAR-NUMBER) for publicly known vulnerabilities, with lifecycle states tracking progression from assignment through resolution.

**How to navigate the National Vulnerability Database (NVD) to research a specific vulnerability**
Search NVD by CVE ID, keyword, or product name at nvd.nist.gov to access detailed vulnerability records with scoring, references, and mitigation data.

**How CVSS v3.1 scoring works: every base metric component, what it measures and how it affects the score**
CVSS v3.1 uses 8 base metrics across two categories — Exploitability (Attack Vector, Attack Complexity, Privileges Required, User Interaction) and Impact (Confidentiality, Integrity, Availability) plus Scope — to calculate a 0–10 severity score.

**How to use the NIST CVSS Calculator to compute base and environmental scores**
Input metric values into NIST's online calculator to automatically derive base scores, then add temporal/environmental modifiers to reflect real-world risk context.

**The relationship between CVE (specific instance) and CWE (weakness category)**
A CVE documents a specific vulnerability instance while CWE describes the underlying weakness class that caused it (e.g., CVE-2021-44228 stems from CWE-502 Deserialization of Untrusted Data).

**How to use searchsploit and Exploit-DB to assess exploit availability**
Use `searchsploit [CVE/keyword]` locally or browse exploit-db.com to determine if public exploits exist, indicating higher immediate risk requiring urgent remediation.

**What the CISA Known Exploited Vulnerabilities (KEV) catalog is and why it matters for prioritization**
CISA KEV catalogs actively exploited vulnerabilities that organizations must remediate by federal deadlines, serving as a high-confidence signal for prioritizing patch deployment.

---

# Vulnerability Types

**The complete Sec+ 2.3 taxonomy**
Sec+ categorizes vulnerabilities across eleven domains: applications, operating systems, web services, hardware/firmware/end-of-life systems, virtualization, cloud infrastructure, supply chains, cryptography, misconfiguration, mobile platforms, and zero-days.

**Why misconfigurations are vulnerabilities even without CVE identifiers**
Misconfigurations create exploitable weaknesses through improper settings rather than software bugs, remaining outside CVE scope despite presenting identical security risks.

**Why end-of-life systems are permanently vulnerable**
EOL systems no longer receive security patches, leaving discovered vulnerabilities unfixable and perpetually exploitable until replacement occurs.

---

# Vulnerability Management

**The complete vulnerability management lifecycle**
The lifecycle consists of identification, analysis, prioritization, response, validation, and reporting — performed continuously.

**How to distinguish false positives from true findings**
Validate scan results through manual inspection, checking if the reported condition actually exists on the target system versus scanner misinterpretation or outdated signatures.

**Why CVSS base score alone is insufficient for prioritization**
Base scores ignore organizational context like asset importance, existing controls, exploit availability, and business impact, requiring environmental adjustments for realistic risk assessment.

**How to apply environmental context to adjust priorities**
Factor in asset criticality, active threat landscape, and exploit availability to weight CVSS scores and focus remediation where real-world risk is highest.

**The four response strategies**
Organizations respond by applying vendor patches, implementing compensating controls, adjusting system configurations, or formally accepting residual risk via exception.

**Why vulnerability management must be continuous, not one-time**
New vulnerabilities emerge constantly, environments change, and previously mitigated issues can reappear, requiring ongoing scanning and reassessment cycles.

---

# Professional Skills

**How to read and triage a vulnerability scan report efficiently**
Filter by severity and exploitability, cross-reference against asset inventory, eliminate duplicates and false positives, and prioritize findings affecting critical systems first.

**How to produce a threat-informed vulnerability assessment**
Combine vulnerability data with intelligence on active threats targeting your industry, technologies, and adversary TTPs to focus remediation on likely attack paths.

**How to run and interpret Lynis security audit results**
Execute `lynis audit system`, review hardening indices and warning sections, then implement recommended configuration changes ranked by security impact and feasibility.
