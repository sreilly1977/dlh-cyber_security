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

