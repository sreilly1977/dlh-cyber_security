# Common CWEs & Their Impact
**By Stephen Reilly** | *Understanding Vulnerabilities Series*

With over 900 CWEs, it would be beyond the scope of this series to list them all. Instead, we’ll be looking at a selection of the top six repeat offenders.

## Top 6 Repeat Offenders

1. **CWE-89 (SQL Injection)**
   - **Description:** If inputs aren't properly sanitized, attackers can slip SQL commands right into database queries.
   - **Impact:** Data theft, data manipulation, authentication bypass, or even full system compromise if the DB has elevated privileges.

2. **CWE-79 (Cross-Site Scripting - XSS)**
   - **Description:** Attackers inject malicious scripts into web pages viewed by other users.
   - **Impact:** Session hijacking, credential theft, defacement, or redirecting users to phishing sites.

3. **CWE-22 (Path Traversal)**
   - **Description:** If directory traversal checks fail, attackers can read arbitrary files on the server.
   - **Impact:** Exposure of sensitive config files, source code, or system credentials.

4. **CWE-787 (Out-of-Bounds Write)**
   - **Description:** A memory corruption issue where data is written beyond the allocated buffer.
   - **Impact:** Code execution crashes, arbitrary code execution, privilege escalation. Often leads to remote code execution (RCE).

5. **CWE-502 (Deserialization of Untrusted Data)**
   - **Description:** Trusting serialized objects without validation allows attackers to execute arbitrary code during deserialization.
   - **Impact:** Remote code execution, denial of service, or information leakage.

6. **CWE-352 (Cross-Site Request Forgery - CSRF)**
   - **Description:** Forces an authenticated user to perform unwanted actions on a trusted site.
   - **Impact:** Unauthorized transactions, profile changes, or admin operations executed without the user’s knowledge.

## How to Prioritize Addressing These Weaknesses

What follows is a practical framework, adaptable based on project specifics:

### 1. Risk-Based Scoring (CWSS + Context)
Use the Common Weakness Scoring System (CWSS) to get a baseline score based on exploitability, prevalence, and potential damage. Then layer in organizational context:
* Is the vulnerable component internet-facing?
* Does it handle PII or financial data?
* What’s the likelihood of exposure given current threat intelligence?

> **Example:** An unpatched CWE-79 (XSS) in a public marketing site might be lower priority than a CWE-89 (SQL Injection) in an internal admin tool handling customer records.

### 2. Exploitability & Threat Intelligence
Check if there’s active exploitation (e.g., CISA Known Exploited Vulnerabilities, MITRE ATT&CK mappings). If attackers are already weaponizing a specific CWE variant, move it up the queue.

### 3. Remediation Effort vs. Impact
Sometimes a high-severity flaw is a one-line fix; other times, it requires architecture redesign. Balancing the effort against the risk reduction helps build momentum and stakeholder trust.

### 4. Regulatory & Compliance Drivers
If certain weaknesses violate standards like PCI-DSS, GDPR, or HIPAA, they are targeted for immediate attention regardless of technical severity. Compliance isn’t optional.

### 5. DevSecOps Integration
Embed SAST/DAST scans in CI/CD pipelines. Prioritize training for common patterns (like secure input validation for CWE-89/79) so devs can self-heal before code ever reaches production.

### 6. Business Criticality
Not all apps are created equal. A legacy HR system might have critical CWEs but zero external exposure, whereas a customer-facing API with medium-severity issues could be high priority due to blast radius.

## Conclusion

Ultimately, while no organization can eliminate every one of the 900+ known weaknesses overnight, focusing on these high-impact offenders provides the best return on security investment. By layering risk-based scoring with real-world exploitability data and business context, teams can move beyond theoretical severity to tackle the vulnerabilities that actually matter most to their specific threat landscape. Integrating these prioritization strategies directly into DevSecOps pipelines ensures that security isn't just a bottleneck, but a scalable, proactive part of the development lifecycle.
