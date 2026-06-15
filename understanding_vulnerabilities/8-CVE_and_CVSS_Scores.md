# CVE and CVSS Scores
**By Stephen Reilly** | *Understanding Vulnerabilities Series*

CVEs give us standardized identifiers, but they don't tell us what matters. CVSS provides severity scores, but out-of-the-box scores ignore our specific environment. The magic happens when you treat both as inputs rather than decisions.

Like network monitoring, we could collect every packet, but effective security comes from understanding which packets represent actual threats.

## Strategic Integration Points

### 1. Risk-Based Prioritization Framework
We don't just patch by CVSS score alone. A 9.8 vulnerability on an internet-facing asset handling customer data deserves different treatment than the same score on a disconnected test server.

We combine:
- **CVSS Base Score** (inherent severity)
- **Exploit Availability** (is there public PoC code? Active exploitation in the wild?)
- **Asset Criticality** (what business function does this support?)
- **Threat Intelligence** (are threat actors actively targeting this?)
- **Compensating Controls** (is WAF protection already mitigating exposure?)

*Research by VulnCheck, a threat intelligence and vulnerabilities aggregate service, has shown that many high-CVSS vulnerabilities never get exploited, while some medium-scoring ones become critical because weaponization happened quickly.*

### 2. Environmental CVSS Adjustment
The Environmental Metrics group exists precisely for our use case. Adjust scores based on:
- Security requirements (confidentiality/integrity/availability needs)
- Modified mitigation factors (existing controls reducing impact)

For example, a database vulnerability with "Low" confidentiality requirement internally might drop from Critical to High when scored with environmental adjustments.

### 3. Automation + Correlation Workflows
Effective programs integrate CVE data across:
- Vulnerability scanners (continuous discovery)
- Patch management systems (deployment tracking)
- Asset inventory (contextual risk calculation)
- SIEM/SOAR platforms (threat detection linkage)

We need automated ticketing with risk context, not raw CVE lists dumped to admins who then have to do our homework.

## Operational Best Practices

| Practice | Why It Matters |
| :--- | :--- |
| **SLA tiers by adjusted severity** | Critical internet-facing = 72hrs, Internal low-risk = 30 days |
| **Weekly CVE triage reviews** | Catch emerging exploit trends before automated scans flag them |
| **False positive reduction process** | Document when vulnerabilities aren't applicable to save future cycles |
| **Vendor coordination channels** | Some vendors push fixes faster when engaged proactively |
| **Historical trend analysis** | Which teams/vendors are consistently slow on patches? Address root causes |

## Common Pitfalls to Avoid

- **The "Critical Score Everything" Problem:** When all vulnerabilities appear critical due to naive scoring, nothing gets prioritized. Resource allocation becomes guesswork instead of strategy.
- **Asset Context Blindness:** Running CVE checks without knowing what runs where leads to wasted effort.
- **Ignoring Temporal Metrics:** CVSS temporal metrics account for exploit maturity and remediation availability. A 9.0 vulnerability with no patch available and active exploitation demands different tactics than one with vendor updates ready.

## Emerging Enhancements

The industry is moving toward **EPSS (Exploit Prediction Scoring System)**, which predicts the probability a vulnerability will be exploited within 30 days. Some security teams now use EPSS alongside CVSS—high CVSS scores tell you potential damage, EPSS tells you likelihood of attack.

There's also growing adoption of **KEV (Known Exploited Vulnerabilities)** catalogs from CISA and other authorities. For regulated industries, KEV items often carry mandatory remediation timelines regardless of your internal scoring.

## Bottom Line

CVEs and CVSS work best when they're part of a broader risk quantification framework—not the entire framework itself. The goal isn't to fix every vulnerability; it's to reduce real risk to acceptable levels given our constraints.
