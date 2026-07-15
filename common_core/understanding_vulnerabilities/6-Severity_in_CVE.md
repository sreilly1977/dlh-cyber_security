# Severity in CVE
**By Stephen Reilly** | *Understanding Vulnerabilities Series*

Severity dictates urgency, but context dictates priority.

While CVSS (Common Vulnerability Scoring System) scores provide a mathematical baseline for how "bad" a vulnerability is theoretically, an organization's actual prioritization strategy is almost always a weighted calculation involving exploitability, asset criticality, and business impact. A "Critical" vulnerability in a disconnected legacy system might get lower priority than a "Medium" one sitting on your primary internet-facing authentication gateway.

## How Different Severity Levels Shape Response Strategies

### 1. Critical (CVSS 9.0–10.0)

These are vulnerabilities that are actively being exploited in the wild, allow remote code execution (RCE), or bypass authentication with zero interaction.

**Response Strategy:** Immediate triage. This often triggers an incident response workflow even before full validation. Teams will deploy emergency patches, apply out-of-band firewall rules, or isolate affected segments immediately. The focus is on containment first, remediation second.

**Example:** Log4Shell (CVE-2021-44228). Even though it was technically "Critical," the fact that exploit kits appeared within hours forced organizations to treat it as a business-critical outage event. Response wasn't just "schedule a patch"; it was "hunt across the whole network for JNDI logs."

---

### 2. High (CVSS 7.0–8.9)

These usually require some specific conditions to be exploited (like local access or user interaction) but still carry significant potential impact, such as privilege escalation or data exfiltration.

**Response Strategy:** Aggressive remediation within a tight SLA (e.g., 48–72 hours). If the asset is high-value (domain controller, DB server), this moves to the top of the sprint. If it's a low-risk internal dev box, it might slip to a scheduled maintenance window.

**Example:** A SQL Injection vulnerability in a public-facing web app. While not always "Critical" if mitigated by WAFs, the potential for full database compromise pushes it to the top of the queue for immediate code fixes or WAF rule updates.

---

### 3. Medium (CVSS 4.0–6.9)

These often require complex chains of other vulnerabilities to be useful or have limited impact (like information disclosure that doesn't reveal credentials).

**Response Strategy:** Standardized patching cycles. These are aggregated and addressed in regular maintenance windows (weekly or monthly). Security teams might look for compensating controls (like network segmentation) if immediate patching isn't feasible due to stability risks.

**Example:** An Information Disclosure flaw that leaks error messages revealing server paths. On its own, it's annoying, but combined with other bugs, it's dangerous. A CISO might accept the risk temporarily while waiting for the vendor to bundle the fix in the next stable release.

---

### 4. Low (CVSS 0.1–3.9)

These have minimal impact, often requiring physical access or highly unlikely conditions.

**Response Strategy:** Usually deferred. They are logged for completeness but rarely drive resource allocation unless they accumulate into a pattern or are part of a known attack chain. Sometimes, the effort to patch causes more downtime than the risk posed by the bug itself (the classic "patch vs. stability" dilemma).

**Example:** A Local Denial of Service on a non-critical workstation OS that requires the user to log in locally and run a specific script. Most orgs will wait for the standard OS update cycle rather than deploying an emergency hotfix.

---

## The "Reality Check" Factor

Two major factors often override the raw severity score:

1. **Exploit Availability (EPSS):** A "Medium" severity bug with a working PoC (Proof of Concept) circulating on GitHub often gets treated like a "Critical" because attackers don't care about the CVSS score; they care about what's easy to weaponize.

2. **Asset Context:** A Critical RCE on a printer in the lobby (not exposed to the internet, no sensitive data) might be lower priority than a Medium Cross-Site XSS on your customer portal where social engineering is rampant.

---

## Bottom Line

Ultimately, the severity score is the map, but the organization's risk appetite and threat landscape are the compass. Over-relying on severity alone can lead to "alert fatigue," while ignoring it leads to catastrophic breaches.
