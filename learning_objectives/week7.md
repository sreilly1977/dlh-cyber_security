# Week 7 Learning Objectives

---

## Understanding Vulnerabilities

**What is a cybersecurity vulnerability?**

A weakness or flaw in a system, process, or design that can be exploited to compromise security.

**What are the different types of vulnerabilities (software, hardware, network)?**

Software bugs/implementation flaws, hardware firmware/physical weaknesses, and misconfigured network protocols or services, plus the human factor.

**How do vulnerabilities lead to security breaches in technology-driven organizations?**

Attackers identify and exploit weaknesses to gain unauthorized access, exfiltrate data, or disrupt operations.

**What is the difference between vulnerabilities, threats, and risks?**

A vulnerability is a weakness, a threat is a potential attacker or event exploiting it, and risk is the likelihood/consequence of that exploitation.

**What are Common Vulnerabilities and Exposures (CVE)?**

A standardized database of publicly known security vulnerabilities with unique identifiers for consistent tracking and communication.

**What is vulnerability management?**

The ongoing process of identifying, assessing, prioritizing, remediating, and monitoring security vulnerabilities across an organization.

**What is responsible disclosure in the context of vulnerabilities?**

Reported finding vulnerabilities privately to vendors first, allowing time for fixes before public disclosure.

**What are common tools used for vulnerability scanning?**

Nessus, OpenVAS, Qualys, Burp Suite, Nmap, and Microsoft Baseline Security Analyzer.

**Why is vulnerability management essential for a company's cybersecurity posture?**

It proactively reduces attack surface by systematically addressing weaknesses before adversaries can exploit them.

---

## CVE, CWE and NVD

**What are CVEs (Common Vulnerabilities and Exposures), and how do they help in identifying and sharing information about publicly known cybersecurity vulnerabilities?**

CVEs are standardized identifiers for publicly known security vulnerabilities that enable consistent tracking, communication, and reference across the global cybersecurity community.

**What is the structure of a CVE identifier (e.g., CVE-2024-1234), and what is the significance of each part?**

Format breaks down as: "CVE" prefix, year discovered/assigned (2024), and sequential ID number (1234) within that year's issuance.

**What role do CVE Numbering Authorities (CNAs) play in the CVE assignment process, and what are the criteria for becoming a CNA?**

CNAs are trusted organizations authorized to assign CVE IDs; they must demonstrate expertise in vulnerability handling and agree to follow MITRE's policies and procedures.

**How are vulnerabilities reported, reviewed, and assigned a CVE identifier through the CVE entry process?**

Reporters submit findings to relevant CNAs or MITRE directly, which review validity, uniqueness, and public disclosure readiness before issuing CVE assignments.

**How can you use the CVE database to search for and retrieve information about specific vulnerabilities?**

Use cve.mitre.org with keyword/CVE-ID search filters by year, product, vendor, or severity ratings for targeted lookups.

**What are CWEs (Common Weakness Enumeration), and how do they help in identifying common software weaknesses that can lead to vulnerabilities?**

CWEs catalog software design/code flaws that could become exploitable vulnerabilities, providing a taxonomy for secure development and testing.

**What are the different categories, types, and hierarchical structures of CWEs?**

Organized as tree hierarchy from root weaknesses (like CWE-79 XSS) through subclasses showing specific instances and relationships between weakness types.

**How are CWEs related to CVEs, and how do they describe the types of weaknesses that lead to vulnerabilities?**

Multiple CVE entries often map back to single CWEs—CWE describes the root cause flaw type while CVE documents specific instance manifestations.

**What are some common mitigation techniques and best practices for addressing weaknesses identified by CWEs?**

Input validation, output encoding, parameterized queries, proper memory management, code review, static analysis tools, and secure coding training.

**How can weaknesses be prioritized based on their severity, exploitability, and potential impact using CWE scoring?**

Using the Common Weakness Scoring System (CWSS), a MITRE-developed framework that assigns severity scores to software weaknesses from the CWE list, complementing the vulnerability-focused CVSS.

**What is the role of the NVD (National Vulnerability Database) in the cybersecurity ecosystem, and how does it support vulnerability management?**

NVD serves as US-government maintained repository aggregating CVE data with enriched details like CVSS scores, affected configurations, and remediation guidance.

**What types of data feeds are provided by the NVD, including vulnerability metrics, configurations, and impact scores?**

JSON/XML feeds containing CVE details, CVSS v2/v3 scores, CPE configurations, affected products, references, and patch availability status updates.

**How can you use the CVSS (Common Vulnerability Scoring System) to assess the severity of vulnerabilities listed in the NVD?**

CVSS provides base/temporal/environmental metrics (attack vector, complexity, privileges required, impact) generating numeric scores 0.0-10.0 for severity ranking.

**How can you effectively search, filter, and retrieve vulnerability information from the NVD?**

Apply nvd.nist.gov filters by CVE-ID, keywords, publish date ranges, CVSS score thresholds, CPE product names, or vendor/platform combinations.

**How can NVD data be integrated with security tools and platforms for automated vulnerability management?**

Pull API feeds into SIEMs, scanners, ticketing systems, and SOAR platforms to auto-correlate discoveries with known vulnerability data for prioritization workflows.

---

## Upload Vulnerabilities

**What is an unrestricted file upload?**

It is a web vulnerability where an application accepts uploaded files without adequately validating their content, type, or structure.

**Why are file uploads a security risk?**

They allow attackers to bypass application controls by uploading malicious code that the server may execute, leading to full system compromise.

**How can file upload forms be exploited?**

Attackers trick servers into storing and executing malware, web shells, or scripts by spoofing headers, bypassing client checks, or exploiting extension weaknesses.

**What is a web shell?**

A web shell is a malicious script uploaded to a server that provides attackers with a remote command line interface to control the compromised system.

**How do MIME types relate to upload security?**

MIME types indicate file formats in HTTP headers, but relying solely on them is insecure because they can be easily forged by attackers.

**What is content-type spoofing?**

This is the technique of manipulating the Content-Type header in an upload request to make a malicious file appear as a safe image or document.

**How can server-side validation mitigate risks?**

Server-side validation enforces strict checks on file magic numbers, extensions, and content before storage, effectively preventing execution of unauthorized payloads.

**What is the importance of file extension filtering?**

Whitelisting allowed extensions ensures that only expected file types (like `.jpg`) can be saved, blocking executable scripts (like `.php` or `.exe`).

**How can client-side checks be bypassed?**

Client-side validations run in the user's browser and can be easily circumvented by modifying requests with proxy tools like Burp Suite or curl.

**What are some secure file upload practices?**

Best practices include whitelisting extensions, verifying file magic numbers, renaming files upon upload, storing outside the web root, and disabling script execution in upload folders.

**How does file size limitation help security?**

Limiting file sizes prevents denial-of-service attacks caused by massive uploads filling disk space and slows down brute-force attempts to upload large payloads.

**What are the risks of storing files on the same domain?**

Storing uploads on the same domain allows malicious scripts to potentially access cookies, local storage, or perform Same Origin Policy bypasses against your legitimate site.

**How do file permissions affect upload security?**

Improper permissions (like `777`) on upload directories grant unintended read/write/execute rights, enabling attackers to modify or run the malicious files they placed there.

**Why should upload directories not be executable?**

Disabling execution permissions ensures that even if a malicious script is successfully uploaded, the web server treats it as data rather than running it as code.
