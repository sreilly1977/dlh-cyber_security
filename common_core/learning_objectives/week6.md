# Week 6 Learning Objectives

---

## OWASP Top 10

**Q: What is the OWASP Top 10?**

A: A standard awareness document listing the ten most critical web application security risks, updated periodically by the OWASP community.

**Q: Why is injection dangerous?**

A: It allows attackers to send malicious data to an interpreter, potentially executing unintended commands or accessing unauthorized data.

**Q: How does XSS affect web applications?**

A: It lets attackers inject client-side scripts into pages viewed by other users, enabling session hijacking, defacement, or credential theft.

**Q: What is the risk of broken authentication?**

A: It allows attackers to compromise passwords, keys, or session tokens to assume other users' identities.

**Q: Can you explain sensitive data exposure?**

A: It occurs when applications fail to adequately protect sensitive data (like credentials or PII), exposing it to unauthorized access through weak encryption or missing controls.

**Q: Describe a security misconfiguration.**

A: Any insecure default setting, incomplete setup, open cloud storage, or unnecessary features left enabled—like default admin accounts or verbose error messages.

**Q: What is XML External Entity (XXE)?**

A: An attack exploiting poorly configured XML parsers to disclose internal files, execute server-side requests, or cause denial of service.

**Q: How do broken access controls impact security?**

A: They let users act outside their intended permissions, accessing data or functions they shouldn't—often the most prevalent and impactful flaw.

**Q: What are common web application security flaws?**

A: Injection, broken authentication, XSS, broken access controls, misconfigurations, insecure deserialization, and vulnerable components rank among the most common.

**Q: How to prevent Insecure Deserialization?**

A: Implement integrity checks (like digital signatures), enforce strict type constraints, and avoid deserializing data from untrusted sources entirely.

**Q: What is the use of security logging and monitoring?**

A: Detecting, responding to, and investigating breaches by recording suspicious activity and alerting on anomalies in real time.

**Q: Explain the risks of using components with known vulnerabilities.**

A: Attackers can exploit known CVEs in libraries, frameworks, or dependencies to compromise the application without crafting new exploits.

**Q: How can using APIs increase security risks?**

A: APIs expand the attack surface by exposing additional endpoints, often with inconsistent authentication, excessive data exposure, or missing rate limiting.

**Q: Understand SSRF and modern API-related risks.**

A: SSRF lets attackers coerce a server into making requests to unintended internal or external resources, often bypassing firewalls to access internal services.

**Q: Explain the importance of Security Logging and Monitoring.**

A: Without it, breaches go undetected for extended periods—logging provides forensic evidence and monitoring enables rapid incident response.

**Q: Identify risks from Vulnerable and Outdated Components.**

A: Outdated libraries may contain unpatched CVEs, lack vendor support, or introduce supply chain compromises that attackers actively target.

**Q: Analyze common web application security flaws.**

A: Most stem from insufficient input validation, poor access control enforcement, weak authentication mechanisms, and failure to keep dependencies updated.

**Q: Understand how modern APIs expand the attack surface.**

A: APIs introduce new endpoints with varying auth models, expose underlying business logic and data structures, and often inherit backend trust that attackers can abuse.

---

## Burp Suite — Fundamentals

**Q: What is Burp Suite?**

A: A comprehensive integrated platform for performing security testing of web applications, developed by PortSwigger.

**Q: How do you set up a proxy in Burp Suite?**

A: Configure your browser or system proxy settings to route traffic through 127.0.0.1 on port 8080 (default) and install Burp's CA certificate to intercept HTTPS.

**Q: What are Burp Suite's main components?**

A: Proxy, Repeater, Intruder, Scanner (Pro only), Decoder, Comparer, and Extender, each serving distinct roles in interception, manipulation, automation, and analysis.

**Q: How does Spider work in Burp Suite?**

A: It crawls the target website automatically to discover content, functionality, and hidden parameters by following links and parsing forms.

**Q: What is the purpose of Repeater in Burp Suite?**

A: To manually modify and resend individual HTTP requests repeatedly while observing how the server responds to different payloads.

**Q: How can Intruder be used for attacks?**

A: It automates customized attacks like fuzzing, brute-forcing, or credential stuffing using payload lists, position markers, and grep-matching rules.

**Q: What is Burp Scanner and when to use it?**

A: An automated vulnerability scanning tool (available in Pro) that identifies issues like SQLi, XSS, and misconfigurations during active assessments.

**Q: How to interpret results from Burp Suite?**

A: Review findings categorized by severity, examine request/response details, validate false positives manually, and prioritize based on exploitability and impact.

**Q: What are some common issues that Burp Suite can identify?**

A: Injection flaws (SQLi, command injection), XSS, broken authentication, insecure direct object references, security misconfigurations, and vulnerable components.

**Q: How do you configure Burp Suite for HTTPS traffic?**

A: Enable SSL/TLS in Proxy settings, navigate to any HTTPS site using the Burp-configured browser, and install Burp's Certificate Authority to decrypt encrypted traffic.

---

## Content Discovery

**Q: What is content discovery?**

A: The process of identifying hidden or undocumented web resources, endpoints, directories, and files that aren't linked from the main site navigation.

**Q: Why is content discovery important?**

A: It reveals attack surface areas attackers could exploit—often containing unpatched admin panels, backup files, or misconfigured services missed during standard audits.

**Q: How does directory bruteforcing work?**

A: It systematically tests a wordlist of common directory/file names against a target server, checking HTTP response codes to identify existing resources.

**Q: What is Gobuster and how is it used?**

A: A fast command-line tool for brute-forcing directories, subdomains, and virtual hosts by iterating through wordlists and analyzing server responses.

**Q: Explain the use of Burp Suite in content discovery.**

A: Burp's Spider and passive scanning features automatically map website structure, while extensions like "Site Map" and Active Scan help uncover hidden paths.

**Q: How does OWASP ZAP assist in content discovery?**

A: Its automated spider crawls sites to find all accessible URLs, and active scan modules probe for hidden content using configurable wordlists and heuristics.

**Q: What are wordlists and how are they used in content discovery?**

A: Precompiled lists of common filenames/directories (like `/admin`, `/backup`) used to systematically test which paths exist on a target server.

**Q: Describe the purpose of tools like DirBuster.**

A: Multi-threaded directory/file enumeration tools designed to efficiently brute-force web paths by testing thousands of wordlist entries against targets.

**Q: What are hidden directories and files in web security?**

A: Resources not publicly linked but still accessible via direct URL—often admin interfaces, config backups, or developer files exposed through poor access controls.

**Q: Explain fuzzing in the context of web security.**

A: Automated input manipulation where testers send unexpected/payload data to parameters to trigger errors, reveal vulnerabilities, or discover undocumented endpoints.
