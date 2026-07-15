# Calculating CVSS
**By Stephen Reilly** | *Understanding Vulnerabilities Series*

There’s a complex formula used to calculate CVSS scores; the details for the version 3.1 specification can be found here:  
[CVSS 3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

Thankfully, Cuberk provides a handy tool published on the web that allows us to calculate the CVSS score:  
[Cuberk CVSS v3.1Calculator](https://cuberk.com/cvss/v3-1/)

To illustrate how we would go about scorring a CVSS, consider the following:

## Scenario Consideration

A **remote code execution (RCE)** vulnerability in a widely used web server software. The vulnerability allows an attacker to execute arbitrary code remotely **without requiring authentication**.

With this information, we can calculate the score by assigning the following metrics:

### Metric Assignment

| Metric | Value | Justification |
| :--- | :--- | :--- |
| **Attack Vector (AV)** | Network (N) | Attacker can exploit remotely over network |
| **Attack Complexity (AC)** | Low (L) | No special conditions or race conditions mentioned |
| **Privileges Required (PR)** | None (N) | Explicitly states "without requiring authentication" |
| **User Interaction (UI)** | None (N) | No mention of victim action needed |
| **Scope (S)** | Unchanged (U) | RCE occurs within original security boundary of web server |
| **Confidentiality (C)** | High (H) | Arbitrary code execution enables reading any accessible data |
| **Integrity (I)** | High (H) | Attacker can modify any file/system state |
| **Availability (A)** | High (H) | Can crash/replace service or system resources |

**Metric String:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

### Score Calculation

Using the CVSS v3.1 calculator:
*   **CVSS Base Score:** 9.8

### Severity Classification

| Range | Severity | Our Score |
| :--- | :--- | :--- |
| 9.0–10.0 | Critical | **9.8** |

## Security Implications for Organizations

This is essentially a perfect storm vulnerability from an attacker's perspective—the CVSS trifecta of easy exploitation, no prerequisites, and complete compromise.

### Immediate Risk Profile
*   **Widespread Exposure:** Since it's in "widely used" web server software, our attack surface expands significantly.
*   **No Precondition Required:** There’s no need for phishing, physical access, or stolen credentials.
*   **Total System Ownership:** An attacker who exploits this owns the entire system hosting the web server.

### Business Impact Considerations
*   Customer data exposure (confidentiality breach).
*   Defacement or malicious modification capabilities (integrity loss).
*   Service disruption potential (availability threat).
*   Possible lateral movement from compromised server into internal network.

## Recommended Mitigation Strategies

Given the **Critical severity (9.8)**, we should implement a prioritized defense-in-depth approach:

### Immediate (0-24 hours)
1.  **Patch Deployment:** Apply vendor patches immediately; verify patch validity in staging first.
2.  **Network Segmentation:** Isolate affected servers from critical internal resources.
3.  **Temporary Workarounds:** Disable vulnerable functionality/modules if patches aren't available.
4.  **Enhanced Monitoring:** Deploy WAF rules, increase logging granularity, enable alerting.

### Short-Term (1-7 days)
1.  **Asset Inventory:** Identify all affected systems across infrastructure.
2.  **Vulnerability Scanning:** Run authenticated scans to confirm patch status.
3.  **Compromise Assessment:** Check for indicators of prior exploitation (backdoors, suspicious processes, log anomalies).
4.  **Access Control Review:** Minimize privileges on affected web server service accounts.

### Long-Term (Ongoing)
1.  **Patch Management Process:** Automate critical patch deployment pipelines.
2.  **Defense Layers:** Implement application-layer firewalls, intrusion detection/prevention.
3.  **Architecture Review:** Consider microservices segmentation to limit blast radius.
4.  **Penetration Testing:** Regular external testing specifically targeting web server configurations.
5.  **Threat Intelligence Integration:** Subscribe to vendor advisories and CVE monitoring feeds.

## Additional CVSS Context

**Temporal & Environmental Metrics Could Adjust the Score:**
*   If the vendor has already released patches → Temporal score decreases.
*   If exploit code is publicly available → Exploitability increases urgency.
*   In our specific environment (firewalls, IDS, hardened configs) → Environmental score might differ from base 9.8.

## Conclusion

In essence, a CVSS 9.8 remote code execution vulnerability represents the cybersecurity equivalent of leaving your front door wide open; while the immediate panic should drive rapid patching and network isolation as outlined in our timeline, true resilience for an organization requires real-world mitigations, like segmentation or WAF rules that can lower the effective environmental risk. Defense-in-depth is our best friend as it ensures that even if the worst happens, the blast radius stays contained within a single microservice rather than compromising the entire infrastructure.
