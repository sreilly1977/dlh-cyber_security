# 2. The CVSS Deconstruction
## Mastering CVSS v3.1 Scoring System

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 2)  

---

## Exercise 1: Deconstruction

### Original Vector String (Finding 001, CVE-2021-44790)
**CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H**

### Component Breakdown

| Component | Abbreviation | Selected Value | Meaning | Other Possible Values | Why This Value Was Selected |
|-----------|--------------|----------------|---------|----------------------|----------------------------|
| **Attack Vector** | AV | **N (Network)** | Vulnerability is exploitable over a network (Internet/intranet) without physical or local access | A (Adjacent), L (Local), P (Physical) | Apache server is publicly accessible on port 80/443. Any remote attacker can send crafted HTTP requests without needing local system access. |
| **Attack Complexity** | AC | **L (Low)** | Specialized conditions not required; exploitation is straightforward | H (High) | The vulnerability can be weaponized by sending a specially crafted request body. No specific timing, race conditions, or privileged setup needed. |
| **Privileges Required** | PR | **N (None)** | No authentication or privileges needed to exploit | L (Low), H (High) | Remote code execution can be triggered by unauthenticated HTTP requests. No login required. |
| **User Interaction** | UI | **N (None)** | Exploitation does not require any user action | R (Required) | Attacker sends malicious HTTP request directly; no victim clicks, no user involvement. |
| **Scope** | S | **U (Unchanged)** | Vulnerability affects only resources managed by the vulnerable component | C (Changed) | The bug exists in Apache mod_lua itself. Successful exploitation doesn't expand attack beyond the web server's privilege context. |
| **Confidentiality** | C | **H (High)** | Complete information disclosure possible | L (Low), N (None) | RCE allows attacker to read any file on the server including configuration files, database credentials, and logs. |
| **Integrity** | I | **H (High)** | Complete modification/destruction of data possible | L (Low), N (None) | RCE allows attacker to modify any file, install backdoors, or alter system configuration. |
| **Availability** | A | **H (High)** | Complete denial of service possible | L (Low), N (None) | Buffer overflow can crash the Apache process entirely, taking the server offline. |

### CVSS Score Analysis

**Base Score:** 9.8 (Critical)

### What if Attack Vector changes from Network (N) to Local (L)?

**Modified Vector String:**


```
CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```


Using the NIST CVSS Calculator:

| Component | Original | Modified |
|-----------|----------|----------|
| AV | N (Network) | **L (Local)** |
| AC | L (Low) | L (Low) |
| PR | N (None) | N (None) |
| UI | N (None) | N (None) |
| S | U (Unchanged) | U (Unchanged) |
| C | H (High) | H (High) |
| I | H (High) | H (High) |
| A | H (High) | H (High) |

| Metric | Result |
|--------|--------|
| **Original Score** | 9.8 |
| **Modified Score** | **8.8** |
| **Change** | **-1.0 points** |

**Why the score changes:**

Changing from Network to Local dramatically reduces exploitability because the attacker must already have local shell access to the system. If someone already has local shell access on billing-srv-01, they likely already have the ability to compromise the system directly. The Network vector means anyone on the Internet can trigger this—no prior access needed. That's why the score drops: the barrier to entry becomes much higher, making the vulnerability less dangerous despite identical impacts (C/I/A all remaining high).

---

## Exercise 2: Construction

### Vulnerability Characteristics

| Characteristic | CVSS Translation | Value Selected |
|----------------|------------------|----------------|
| Exploitable only from the local network (not Internet) | AV | **A (Adjacent)** |
| Exploitation is complex and requires specific conditions | AC | **H (High)** |
| Attacker needs low-level privileges | PR | **L (Low)** |
| No user interaction is needed | UI | **N (None)** |
| Vulnerability only affects targeted system (scope unchanged) | S | **U (Unchanged)** |
| Compromises confidentiality completely | C | **H (High)** |
| No impact on integrity | I | **N (None)** |
| No impact on availability | A | **N (None)** |

### Constructed Vector String


```
CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
```


### Calculated Results (NIST CVSS Calculator)

| Metric | Value |
|--------|-------|
| **Vector String** | CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N |
| **Base Score** | **4.0** |
| **Severity Rating** | **Medium** |
| **Exploitability Score** | 2.1 |
| **Impact Score** | 1.8 |

### Validation Notes

**Why Adjacent (A) instead of Network (N)?**  
The requirement specifies "local network (not the Internet)." In CVSS terminology:
- **Network (N)** = Reachable via Internet without physical proximity
- **Adjacent (A)** = Requires same broadcast domain (LAN, WiFi, Bluetooth)

Since this is a LAN-only vulnerability, Adjacent is the correct choice.

**Why Low Privileges (PR:L)?**  
The attacker needs some level of access (e.g., standard user account, authenticated session) but not administrative/root privileges. This is different from "None" where no authentication at all is required.

**Why the relatively low score (4.0)?**  
Despite Complete Confidentiality impact (C:H), the combination of Adjacent access requirement, High complexity, and Low privileges required creates multiple barriers before exploitation. Additionally, there's no Integrity or Availability impact, which significantly limits the overall damage potential.

---

## Exercise 3: Comparison

### Finding Selection

| Finding | CVE ID | CVSS Score | Severity | Vector String |
|---------|--------|------------|----------|---------------|
| **Finding 001 (High Score)** | CVE-2021-44790 | **9.8** | Critical | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **Finding 005 (Lower Score)** | CVE-2011-3389 | **7.5** | High | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |

### Side-by-Side Comparison

| Component | Finding 001 (9.8) | Finding 005 (7.5) | Difference |
|-----------|-------------------|-------------------|------------|
| **AV** | N (Network) | N (Network) | Same |
| **AC** | L (Low) | L (Low) | Same |
| **PR** | N (None) | N (None) | Same |
| **UI** | N (None) | N (None) | Same |
| **S** | U (Unchanged) | U (Unchanged) | Same |
| **C** | H (High) | H (High) | Same |
| **I** | **H (High)** | **N (None)** | **DIFFERENCE** |
| **A** | **H (High)** | **N (None)** | **DIFFERENCE** |

### Key Differences Analysis

**The Only Difference:** Integrity and Availability impact ratings.

| Metric | Finding 001 (CVE-2021-44790) | Finding 005 (CVE-2011-3389) |
|--------|------------------------------|-----------------------------|
| **Impact Categories** | C:H, I:H, A:H | C:H, I:N, A:N |
| **What Happens** | RCE → Full system compromise (files read, modified, server crashed) | TLS BEAST → Partial data decryption (only confidentiality breached) |
| **Attack Outcome** | Complete takeover | Limited data exposure |

### Components with Biggest Impact on Final Score

**1. Availability (A) Impact** - Highest Influence  
- Finding 001: A:H (+contribution to higher score)
- Finding 005: A:N (0 points)
- **Difference:** significant

**2. Integrity (I) Impact** - Second Highest Influence  
- Finding 001: I:H (+contribution to higher score)
- Finding 005: I:N (0 points)
- **Difference:** significant

**Combined Effect:** These two differences account for nearly the entire 2.3-point gap between 9.8 and 7.5.

### Why These Components Matter Most

**The CIA Triad in CVSS:**
The Base Score formula weights Impact components heavily:
- **Confidentiality (C):** Data exposure
- **Integrity (I):** Data modification
- **Availability (A):** System downtime

Finding 001 is worse because it doesn't just expose data—it **destroys** the system. Finding 005 is limited to reading some encrypted traffic that might reveal cookie/session data, but the server keeps running and data remains unmodified.

**Practical Implication for MedDefense:**
If we could only patch one vulnerability this quarter:
- CVE-2021-44790 (9.8) takes priority because losing the billing server entirely means we cannot process payments at all
- CVE-2011-3389 (7.5) is important for compliance, but patients can still access the portal even if some header encryption is theoretically vulnerable

This is why CVSS scores drive remediation prioritization—they translate technical characteristics into business risk.

---

## Summary of Lessons Learned

### Key Takeaways from This Exercise

| Lesson | Application to MedDefense |
|--------|--------------------------|
| **AV has enormous score impact** | A CVSS score can drop 1+ points just by changing from Network to Local. This is why network segmentation (GAP-001) is so valuable—it effectively converts "Network" vulnerabilities into "Local" ones. |
| **Impact categories (C/I/A) drive severity** | CVE-2021-44790 scores 9.8 because it has High impact across all three CIA categories. Understanding which vulnerabilities affect C vs I vs A helps prioritize based on business needs. |
| **Complexity and Privileges act as dampeners** | Finding 005 scores 7.5 because it requires TLS decryption skills (complex) and only exposes headers (limited confidentiality). Not all high-severity vulnerabilities are equally dangerous. |
| **Scores must be contextualized** | A 9.8 score assumes the vulnerability is actively exploitable. CVE-2023-38408 (9.8 CVSS) was rated Medium in our scan because the specific conditions (ssh-agent forwarding) don't apply. |
| **Adjacent network access matters** | Medical device vulnerabilities (CVE-2020-25165, 7.5) are Adjacent (LAN only). Isolating the IoT VLAN (GAP-007) makes these vulnerabilities harder to reach. |

---

*Prepared by: Security Department*  
*References: NIST CVSS v3.1 Calculator, CVE-2021-44790, CVE-2011-3389, CVE-2020-25165*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
