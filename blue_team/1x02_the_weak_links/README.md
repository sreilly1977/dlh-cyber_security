# 0. The Scan Report

## Goal
Develop the professional reflex of reading a scan report for structure and context before diving into individual findings.

## Context
Thirty-one findings. Four Critical. Seven High. The temptation is to jump straight to the red ones. Resist it.

A scan report is a dataset, not an analysis. Before you investigate any single finding, you need to understand the shape of the data: how many findings, what severity distribution, which systems are most affected, what the scanner covered and, critically, what it did not cover.

This is the same discipline that separates a junior analyst from a senior one. The junior panics at "4 Critical." The senior asks: "4 Critical out of how many? On which systems? Are they on the same asset? Are they related?"

## Provided Files
- [`meddefense-vulnerability-scan.txt`](blue_team/1x02_the_weak_links/meddefense-vulnerability-scan.txt)

## Instructions
Read the entire scan report from beginning to end. Do not research any individual finding yet. Then produce a **First Impressions Summary** containing:

1. **Scan Metadata:** What was scanned, when, by whom, what scan policy was used, what was NOT scanned (read the methodology notes).

2. **Finding Distribution:** Count by severity (Critical/High/Medium/Low/Informational). Which severity level has the most findings?

3. **Asset Heat Map:** Which hosts appear most frequently in the findings? List the top 5 hosts by finding count. Cross-reference with your Asset Registry (1x00 T7) to identify what role each host plays.

4. **First Observations:** Based on a quick read (not deep research), what patterns do you notice? Are the Critical findings concentrated on one system or spread across several? Do any findings appear related to each other? Does anything surprise you?

5. **Scan Limitations:** What does this scan NOT tell you? What assets, services or vulnerability types are outside its scope?

---

# 1. The CVE Ecosystem

## Goal
Navigate the National Vulnerability Database to research specific CVEs and understand the global vulnerability identification system.

## Context
Every CVE in that scan report is an entry in a global registry. Behind each identifier is a story: who discovered the flaw, what it affects, how severe it is, whether a patch exists, whether an exploit exists. The NVD is where those stories live.

You will use NVD constantly as a security professional. This task builds the navigation reflex.

## Instructions
Select **3 CVEs** from the scan report: one Critical, one High, and one Medium. Go to `nvd.nist.gov` and research each one.

### For Each CVE, Document:

| Field | Value |
|-------|-------|
| **CVE ID** | [e.g., CVE-2021-44790] |
| **NVD URL** | [direct link to the NVD page] |
| **Description** | [In your own words – do not copy the NVD description verbatim] |
| **Affected Products** | [List at least 3 affected products/versions from the NVD CPE data] |
| **CVSS v3.1 Vector String** | [Copy the full vector] |
| **CVSS Base Score** | [Score] |
| **CWE** | [The CWE ID and name listed on the NVD page] |
| **References** | [List 3 reference links from the NVD page and identify what each is: vendor advisory, patch, write-up, PoC, etc.] |
| **Published Date** | [When was this CVE published?] |
| **Last Modified** | [When was it last updated?] |

---

## After the 3 CVE Analyses, Answer These Questions:

1. **What is the structure of a CVE ID?** (What do the year and number signify?)

2. **What is a CNA (CVE Numbering Authority) and what role does it play?**

3. **What lifecycle states can a CVE have?** (Reserved, Published, Rejected – explain each.)

4. **Find one CVE on NVD that has a status of "Rejected."** Why was it rejected?

---

# 2. The CVSS Deconstruction

## Goal
Master the **CVSS v3.1 scoring system** by deconstructing, constructing and comparing scores using the NIST Calculator.

## Context
A CVSS score without understanding is a number. A CVSS score with understanding is a decision tool. This task turns the former into the latter.

---

## Instructions

### Open the NIST CVSS v3.1 Calculator in your browser
You will use it for all three exercises.

---

## Exercise 1: Deconstruction

Take the following CVSS vector string from the scan report (**Finding 001, CVE-2021-44790**):


```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```


For each component, explain:

1. What the abbreviation stands for
2. What the selected value means
3. What other values are possible and how they would change the score
4. Why this specific value was selected for this vulnerability

Then answer: **If the Attack Vector was changed from Network (N) to Local (L)**, what would the new score be? Calculate it on the NIST Calculator and explain why the score changes.

---

## Exercise 2: Construction

You discover a vulnerability with these characteristics:

- Exploitable only from the local network (not the internet)
- Exploitation is complex and requires specific conditions
- The attacker needs low-level privileges
- No user interaction is needed
- The vulnerability only affects the targeted system (scope unchanged)
- Successful exploitation compromises confidentiality completely
- No impact on integrity
- No impact on availability

**Tasks:**

1. Build the CVSS vector string manually
2. Enter it into the NIST Calculator and verify your score
3. Document the vector string, the calculated score and the severity rating

---

## Exercise 3: Comparison

Select two findings from the scan report:

| Finding Criteria | CVSS Score Range |
|------------------|------------------|
| Finding A        | Above 9.0        |
| Finding B        | Between 5.0 and 7.0 |

**Tasks:**

1. Enter both vector strings into the calculator side by side
2. Identify the specific components that explain the score difference
3. Which components have the biggest impact on the final score?

---

# 3. The Weakness Beneath

## Goal
Use the **CWE taxonomy** to identify weakness patterns behind individual CVEs.

## Context
CVE tells you **"what is broken."** CWE tells you **"why it keeps breaking."** If three different CVEs on three different products all trace back to **CWE-787 (Out-of-bounds Write)**, that is not a coincidence, it is a pattern. Understanding the pattern lets you predict where the next vulnerability will appear, not just react to the current one.

---

## Instructions

### Go to cwe.mitre.org

---

## Part 1: Tracing CVEs to CWEs

Select **3 CVEs** from the scan report that have CWE assignments on their NVD page. For each:

1. **Identify the CWE** (ID + name)
2. **Go to the CWE page** and read the description
3. **Find the CWE's position in the hierarchy** (is it a child of a broader weakness? which parent?)
4. **Check:** Is this CWE in the **CWE Top 25 Most Dangerous Software Weaknesses**?

---

## Part 2: Pattern Analysis

Look across **all 31 findings** in the scan report:

| Question | Action |
|----------|--------|
| How many distinct CWEs can you identify? | Count unique CWE IDs across findings |
| Are there findings that share the same underlying CWE even though they are different CVEs? | Look for repeated CWE patterns |
| Identify at least one such pattern. | Document the CWE and affected findings |

---

## Part 3: Recommendation

Based on the CWE patterns you found in the MedDefense scan:

> If MedDefense were developing software internally, which **one CWE category** should their developers be trained to avoid first, and why?

Document your recommendation with supporting evidence from your analysis.

---

## Why This Matters for Security+

*Understanding CWE helps you:*

- Move beyond reactive patching to proactive prevention
- Recognize developer training gaps before they become CVEs
- Speak the language of secure development lifecycle (SDL) practices
- Connect individual vulnerabilities to organizational risk patterns

---

# 4. The Exploit Hunt

## Goal
Assess exploit availability for critical vulnerabilities using **searchsploit**, **Exploit-DB** and the **CISA KEV catalog**.

## Context
A vulnerability with no known exploit is a theoretical risk. A vulnerability with a weaponized exploit in the **CISA KEV catalog** is an active emergency. The distance between the two determines your response timeline. This task teaches you to measure that distance.

---

## Instructions

For the **5 most critical CVEs** in the scan report, conduct a three-stage exploit research:

---

## Stage 1: searchspolit (Command Line)

Run searchsploit queries for each service and version:

```bash
searchsploit apache 2.4.29
searchsploit postgresql
searchsploit openssh 8.9
searchsploit "windows xp" smb
searchsploit tomcat 9.0
```
For each CVE, produce an **Exploitability Score (1-5)**:

| Score | Meaning |
|-------|---------|
| 5 | Weaponized, in CISA KEV, actively exploited |
| 4 | Working PoC public, minor adaptation needed |
| 3 | PoC exists but complex or unreliable |
| 2 | Vulnerability confirmed, no public exploit |
| 1 | Theoretical, no known exploitation method |

---

## Deliverables Template

Use this template to document your findings for each of the 5 CVEs:

### CVE #1: [Insert CVE Number]

| Stage | Finding |
|-------|---------|
| **searchsploit Command** | `searchsploit [exact command]` |
| **searchsploit Output** | `[paste output]` |
| **Exploit-DB Status** | PoC / Weaponized / Metasploit Module |
| **Publication Date** | [DD Month YYYY] |
| **Verified by Exploit-DB** | Yes / No |
| **CISA KEV Listed** | Yes / No |
| **Date Added (if applicable)** | [DD Month YYYY] |
| **Patch Due Date (if applicable)** | [DD Month YYYY] |
| **Exploitability Score** | [1-5] |
| **Notes** | [Additional observations] |

---

# 5. The Exploit Research Script

## Goal
Write a **bash script** that automates searchsploit queries for a list of services and produces a structured report.

## Context
In the real world, you do not run searchsploit five times manually. You **script it**. An analyst who receives a scan report with 200 services writes a script that queries all of them and formats the results for triage. This is your first **automation task** in this project.

---

## Instructions

Write a bash script **`5-exploit_check.sh`** that:

1. **Takes a text file as input.** The file contains one service per line in the format: `service_name version` (e.g., `apache 2.4.29`)

2. **For each line, runs `searchsploit`** with the service name and version

3. **Outputs a formatted report** showing:
   - The service queried
   - The number of exploits found
   - The exploit titles (if any)
   - A summary line: `"Services with exploits: X / Total: Y"`

**Input file format** (provided as services.txt):

```
apache 2.4.29
postgresql 14
openssh 8.9
tomcat 9.0
windows xp smb
grafana 8.2
```

**Expected output format:**

```
[1] apache 2.4.29
    Exploits found: 3
    - Apache 2.4.29 - mod_lua Buffer Overflow | ...
    - Apache 2.4.17-2.4.38 - Privilege Escalation | ...
    [...]

[2] postgresql 14
    Exploits found: 0

[...]

Services with known exploits: X / 6
```

---

# 6. The Misconfiguration Findings

## Goal
Analyze vulnerabilities that have **no CVE identifier** and understand why they are equally dangerous.

## Context
The scan report contains findings marked as **"Misconfiguration"** with no CVE. No CVE means:

| Missing Element | Consequence |
|-----------------|-------------|
| No CVE | No CVSS score |
| No NVD page | No official vulnerability database entry |
| No Exploit-DB entry | No public exploit research available |
| No automated prioritization | Most tools will ignore them |

That is exactly the problem.

### Historical Precedents

> **The MongoDB Ransomware Wave of 2017** affected **28,000 databases**. Not one had a CVE. Every single compromise was a misconfiguration: databases exposed to the internet with no authentication.

> **The Capital One Breach of 2019** that exposed **100 million records** was a misconfiguration. Not a software bug. A misconfigured AWS WAF rule.

---

## Instructions

Identify **6 misconfiguration findings** from the scan report (findings with `"N/A"` for CVE). For each one:


```
Finding ID: [From scan report]
Host: [Affected system]
Misconfiguration: [What is wrong, specifically]
Why No CVE: [Explain why this is a configuration error, not a software bug]
Severity Assessment: [Critical/High/Medium/Low - your judgment, justified]
Cross-Reference 1x00: [Does this correspond to an observation from your walk-through (1x00 T3), a control gap (1x00 T5), or a network scan finding (1x00 T7)? Be specific.]
Comparable CVE Risk: [Name a CVE from the scan that has a similar real-world risk level, and explain why the misconfiguration is equally or more dangerous despite having no CVSS score]
```


---

## Critical Reflection Question

After the 6 analyses, answer in one paragraph:

> Why does the statement *"Our CVE scan shows nothing critical, we are secure"* provide dangerous false assurance?

---

# 7. The Vulnerability Taxonomy

## Goal
Classify all scan findings into the **Sec+ 2.3 vulnerability taxonomy** to identify the organization's vulnerability profile.

## Context
Security+ 2.3 defines **11 vulnerability categories**. Your scan report contains examples of most of them. Classifying every finding reveals **MedDefense's vulnerability profile**, not just individual weaknesses, but the systemic pattern of what types of vulnerabilities dominate and what that says about the organization's security maturity.

---

## Instructions

Classify every finding in the scan report (all 31) into the following **Sec+ 2.3 categories**:

| Category | Sec+ Definition |
|----------|----------------|
| Application | Memory injection, buffer overflow, race conditions, malicious update |
| OS-based | Vulnerabilities in operating system components |
| Web-based | SQLi, XSS, broken access control, security misconfig |
| Hardware/Firmware/EOL | Firmware vulnerabilities, end-of-life, legacy systems |
| Virtualization | VM escape, resource reuse |
| Cloud-specific | Cloud misconfigurations, shared responsibility failures |
| Supply chain | Third-party component vulnerabilities |
| Cryptographic | Weak algorithms, protocol downgrade, certificate issues |
| Misconfiguration | Human error in system configuration |
| Mobile device | Side loading, jailbreaking, unmanaged devices |
| Zero-day | No patch available at time of disclosure |

---

## Produce

1. ### Classification Table

| Finding ID | Category | Justification |
|------------|----------|---------------|
| Finding 001 | [Category] | [One sentence justification] |
| Finding 002 | [Category] | [One sentence justification] |
| ... | ... | ... |
| Finding 031 | [Category] | [One sentence justification] |

2. ### Category Count

| Category | Count |
|----------|-------|
| Application | [X] |
| OS-based | [X] |
| Web-based | [X] |
| Hardware/Firmware/EOL | [X] |
| Virtualization | [X] |
| Cloud-specific | [X] |
| Supply chain | [X] |
| Cryptographic | [X] |
| Misconfiguration | [X] |
| Mobile device | [X] |
| Zero-day | [X] |

3. ### Profile Analysis

Write **one paragraph** answering:

- Which categories dominate?
- What does this tell you about MedDefense's security maturity?
- Which categories are absent, and is that because MedDefense has no exposure or because the scan did not cover them?

---

# 8. The Self-Audit

## Goal
Run a real security audit tool on your own machine, interpret the results, and project the findings onto the MedDefense environment.

## Context
You have been reading a scan report someone else produced. Now you **generate your own**. **Lynis** is an open-source security auditing tool that checks your system against hundreds of security best practices:

- Kernel hardening
- Authentication
- File permissions
- Networking
- Logging
- Malware detection
- And more

Running it on your own machine teaches you:

1. What a scanner actually checks
2. How to read raw audit output
3. How to distinguish important findings from noise

Then you will **project that understanding onto MedDefense**.

---

## Instructions

### Part 1: Install and Run

On your Linux machine or VM:

```
# Install Lynis
sudo apt update && sudo apt install lynis -y
# OR clone from GitHub for the latest version
# git clone https://github.com/CISOfy/lynis && cd lynis

# Run a full system audit
sudo lynis audit system
```

---

### Part 2: Analyze Results

After the audit completes, document:

| Metric | Documentation Required |
|--------|----------------------|
| **Hardening Index** | What score did your machine receive? |
| **Top 5 Warnings** | For each:<br>- What Lynis checks<br>- Why it matters<br>- What the remediation would be |
| **Top 5 Suggestions** | From the "Suggestions" section. For each:<br>- Explain what security improvement it recommends |
| **Category Breakdown** | Lynis organizes checks by category (Kernel, Authentication, Networking, etc.):<br>- Which categories scored highest?<br>- Which scored lowest?<br>- What does this tell you about your system's security posture? |

---

### Part 3: MedDefense Projection

Without access to MedDefense's servers, **project what Lynis would likely find** on `billing-srv-01`:

**Server Profile:**
- Ubuntu 18.04
- Apache 2.4.29
- MySQL
- Crypto-miner compromise history
- SSH password auth enabled

**Task:** List **5 specific findings** you would expect Lynis to flag on this server, with your reasoning for each prediction.

---

# 9. The OSINT Hunt

## Goal
Use open-source intelligence to identify vulnerabilities affecting MedDefense that the automated scan missed.

## Context
Automated scanners are **not omniscient**. They check what they are configured to check, against the databases they have. They miss:

| Limitation | What Scanners Miss |
|------------|-------------------|
| Outdated plugins | Vulnerabilities disclosed after their plugin database was last updated |
| Unfingerprinted services | Vulnerabilities in services they cannot fingerprint |
| Logical gaps | Logical vulnerabilities that require context to identify |
| Authenticated limits | Weaknesses in configurations they do not have authenticated access to assess |

A complete vulnerability assessment **supplements the scan with manual OSINT research**.

---

## Instructions

Using **public sources** (vendor security advisories, CISA alerts, security blogs, NVD), research vulnerabilities that affect MedDefense's technology stack but were **NOT identified in the scan report**.

### Focus Areas

#### 1. FortiGate FortiOS Vulnerabilities
- **MedDefense uses:** FortiGate 100F
- **Task:** Search NVD for recent FortiOS CVEs
- **Requirement:** Identify at least **1 critical or high CVE** that could affect this device (the scan may not have checked the firewall's own firmware)

#### 2. Microsoft Office 365 / Entra ID Vulnerabilities
- **MedDefense uses:** O365 E3 for the entire organization
- **Context:** The scan did not cover cloud services
- **Task:** Research at least **1 recent vulnerability or attack technique** targeting O365 environments

#### 3. Synology DSM Vulnerabilities
- **MedDefense uses:** Backup NAS runs Synology DSM 7
- **Task:** Search NVD for DSM 7 CVEs
- **Requirement:** Identify at least **1**

---

## For Each Vulnerability Found, Document:

```
Source: [Where you found it, NVD URL, CISA advisory, vendor page]
CVE: [If applicable]
Affected Product: [MedDefense asset]
Why the Scan Missed It: [Was it out of scope? Unauthenticated scan? Plugin not available?]
CVSS / Severity: [If available]
MedDefense Impact: [What would exploitation mean for MedDefense specifically?]
Recommendation: [What should MedDefense do about this?]
```

---



