# 7. The Risk Register Update

## Goal

Update the MedDefense Risk Register with the Crimson Tide threat, demonstrating that a Risk Register is a living document that responds to new intelligence.

## Context

The Risk Register from 1x03 T10 had a ransomware entry. Crimson Tide is not just "ransomware." It is a specific campaign with specific TTPs targeting MedDefense's specific profile. The existing entry must be updated, and a new entry for the FortiGate vulnerability must be added.

---

## Part 1 — Update Existing Entry

### Original Risk Register Entry (from 1x03 T10)

| Field | Original Value |
|---|---|
| **Risk ID** | RISK-2026-003 |
| **Risk Title** | Ransomware attack on hospital information systems |
| **Risk Description** | Malicious actors may deploy ransomware encrypting critical hospital systems including EHR, billing, and imaging, causing extended downtime and potential patient safety impacts. |
| **Threat Source** | Cybercriminal organizations (unspecified) |
| **Threat Vector** | Phishing email leading to endpoint compromise and lateral movement |
| **Asset(s) at Risk** | EHR system, billing system, Active Directory, file servers, medical devices |
| **Likelihood** | Medium (ARO 0.25, 25% annual probability) |
| **Impact** | Critical (SLE $5.6M) |
| **Inherent Risk Rating** | High (0.25 x $5.6M = $1.4M ALE) |
| **Existing Controls** | Antivirus on endpoints, daily backups (not isolated), basic network segmentation |
| **Residual Risk Rating** | Medium-High ($1.12M residual ALE after 20% control effectiveness) |
| **Treatment Decision** | Mitigate (accept residual risk, plan long-term improvements) |
| **Treatment Owner** | Director of IT |
| **Review Date** | January 2027 (annual) |
| **Key Risk Indicator (KRI)** | Phishing click rate exceeding 15% quarterly |

### Updated Risk Register Entry

| Field | Updated Value |
|---|---|
| **Risk ID** | RISK-2026-003 (REVISED) |
| **Risk Title** | Ransomware attack on hospital information systems by Crimson Tide (CT) group |
| **Risk Description** | The Crimson Tide (CT) threat actor group is conducting an active, targeted ransomware campaign against regional hospitals matching MedDefense's exact profile. The campaign follows a 7-phase kill chain: FortiGate exploitation (Phase 1), lateral movement via flat network (Phase 2), Kerberoasting via RC4 (Phase 3), raw database file copying without authentication (Phase 4), backup destruction (Phase 5), ransomware deployment (Phase 6), and executive extortion via harvested email (Phase 7). Five hospitals compromised in 10 days. Three in our geographic region. Campaign is ongoing. |
| **Threat Source** | Crimson Tide (CT) — organized criminal group with private zero-day capability, healthcare specialization, and geographic proximity (Hospital C located 45 miles from MedDefense Central) |
| **Threat Vector** | Multi-phase: (1) FortiGate CVE-2023-27997 heap overflow RCE on SSL VPN, (2) lateral movement on flat network, (3) Kerberoasting using RC4-encrypted service tickets, (4) raw filesystem copying of unencrypted PostgreSQL and MySQL database files, (5) backup volume deletion, (6) ransomware deployment via PsExec/WMI, (7) executive contact harvesting from unencrypted email for extortion |
| **Asset(s) at Risk** | FortiGate 100F firewall, EHR system, PostgreSQL database (ehr-db-01), MySQL database (billing-srv-01), Active Directory (dc-01), NAS-01 backup storage, email server, executive workstations |
| **Likelihood** | Very High (ARO 0.9, 90% annual probability — see ALE Update in Section 5) |
| **Impact** | Critical (SLE $7.4M — increased from $5.6M based on Crimson Tide incident data: higher downtime costs, HIPAA fines, reputation damage from data publication) |
| **Inherent Risk Rating** | Critical (0.9 x $7.4M = $6.66M ALE) |
| **Existing Controls** | Antivirus on endpoints (insufficient against fileless techniques), daily backups on NAS-01 (NOT isolated, targetable in Phase 5), basic network segmentation (flat network allows Phase 2 lateral movement). All three existing controls are bypassed by Crimson Tide TTPs. |
| **Control Effectiveness** | Reduced from 20% to 5%. Existing controls were designed for generic ransomware, not a targeted multi-phase campaign with private exploits. Antivirus does not detect fileless PowerShell and living-off-the-land techniques. Backups are network-accessible and destroyed in 100% of Crimson Tide incidents. Network segmentation is insufficient to prevent lateral movement. |
| **Residual Risk Rating** | Critical ($6.33M residual ALE after 5% control effectiveness) |
| **Treatment Decision** | **MITIGATE IMMEDIATELY (URGENT)** — Previous decision to accept residual risk and plan long-term improvements is NO LONGER VALID. The risk has escalated from "High" to "Critical" with an ALE increase of 376%. Treatment must shift from passive acceptance to active emergency mitigation within 72 hours. |
| **Treatment Plan** | Execute 72-Hour Emergency Response Plan: (1) Patch FortiGate CVE-2023-27997 within 4 hours, (2) Enable database TDE on PostgreSQL and MySQL simultaneously, (3) Physically isolate NAS-01 and enable WORM storage, (4) Disable RC4 Kerberos, (5) Deploy EDR across all endpoints, (6) Enforce TLS 1.2+ on patient portal, (7) Upgrade IPsec ciphers, (8) Enforce mandatory email TLS, (9) Deploy MFA on EHR system. Full treatment plan documented in Sections 1-4. |
| **Treatment Owner** | Steve (Security Engineer) — escalated from Director of IT due to severity |
| **Review Date** | **August 4, 2026 (7 days) — accelerated from January 2027 annual review** |
| **Key Risk Indicator (KRI)** | **Presence of FortiGate SSL VPN authentication failures from non-MedDefense IP addresses, specifically: (a) repeated SSL VPN login attempts from IPs outside the tri-state region, (b) anomalous SSL VPN session durations exceeding 30 minutes from unfamiliar geolocations, (c) spikes in Kerberos RC4 ticket requests on dc-01 (indicates Kerberoasting in progress), (d) database file access from non-application service accounts on ehr-db-01 or billing-srv-01 (indicates raw file copying), (e) bulk file deletion events on NAS-01 (indicates Phase 5 backup destruction). Threshold: any single indicator triggers immediate IR activation.** |
| **Last Updated** | July 28, 2026, 10:45 EST by Steve, Security Engineer |
| **Update Trigger** | Crimson Tide Threat Advisory received July 28, 2026 at 07:30 EST |

### Treatment Decision Reassessment

| Criterion | Original Assessment | Updated Assessment | Changed? |
|---|---|---|---|
| Likelihood | Medium (25%) | Very High (90%) | YES — 3.6x increase |
| Impact | Critical ($5.6M SLE) | Critical ($7.4M SLE) | YES — 32% increase |
| ALE | $1.4M | $6.66M | YES — 376% increase |
| Control effectiveness | 20% | 5% | YES — existing controls bypassed |
| Residual ALE | $1.12M | $6.33M | YES — exceeds board risk appetite |
| Treatment decision | Mitigate (passive) | **Mitigate IMMEDIATELY (emergency)** | YES — escalated to emergency |
| Review frequency | Annual (Jan 2027) | Weekly (Aug 4, 2026) | YES — accelerated 6 months |

**Conclusion:** The original treatment decision to accept residual risk and plan long-term improvements is NO LONGER VALID. The 376% ALE increase, combined with the discovery that all existing controls are bypassed by Crimson Tide TTPs, necessitates immediate emergency mitigation. The treatment decision is escalated from "Mitigate (passive)" to "Mitigate IMMEDIATELY (emergency)" with a 72-hour execution window.

---

## Part 2 — New Entry: FortiGate Vulnerability

### RISK-NEW-001: FortiGate CVE-2023-27997

| Field | Value |
|---|---|
| **Risk ID** | RISK-NEW-001 |
| **Risk Title** | FortiGate 100F SSL VPN heap overflow vulnerability (CVE-2023-27997) enabling unauthenticated remote code execution |
| **Risk Description** | A heap overflow vulnerability exists in FortiOS SSL VPN (versions 7.2.0 through 7.2.4 and 7.0.0 through 7.0.11) allowing unauthenticated remote attackers to execute arbitrary code via specially crafted HTTP requests to the SSL VPN web interface. This vulnerability serves as the initial access vector (Phase 1) in the Crimson Tide attack chain. Successful exploitation grants the attacker administrative access to the FortiGate firewall, enabling subsequent phases including lateral movement, data exfiltration, and ransomware deployment. |
| **Threat Source** | Crimson Tide (CT) group — actively exploiting this vulnerability using private tooling (no public exploit exists in Exploit-DB as confirmed by searchsploit query on July 28, 2026). CT has successfully exploited this vulnerability at 5 hospitals in 10 days. |
| **Threat Vector** | Remote, unauthenticated exploitation via SSL VPN web interface. Attacker sends crafted HTTP requests triggering heap overflow in FortiOS SSL VPN daemon, achieving arbitrary code execution as root. No credentials required. No user interaction required. Attack is network-based from internet. |
| **Vulnerability** | CVE-2023-27997 — CVSS 9.8 (Critical). Heap-based buffer overflow in FortiOS SSL VPN. Affected versions: FortiOS 7.2.0-7.2.4, 7.0.0-7.0.11. Remediation: Upgrade to FortiOS 7.2.5+ or 7.0.12+. Patch requires active FortiGate support contract. |
| **Asset(s) at Risk** | FortiGate 100F (fgt-edge-01) — perimeter firewall, SSL VPN gateway, and sole network entry point for remote access. Compromise of this asset enables full network access via lateral movement. |
| **Asset Value** | $2M (firewall hardware replacement $50K, plus $1.95M representing the downstream impact of compromise including all assets reachable behind the firewall) |
| **Exposure Factor** | 100% (full device compromise; attacker gains root-level access to all firewall configurations, VPN credentials, routing tables, and network traffic) |
| **Single Loss Expectancy (SLE)** | $7.4M (aligned with updated ransomware SLE from Section 5, since FortiGate compromise is the entry point for the full ransomware kill chain. The FortiGate itself is not worth $7.4M, but its compromise enables the $7.4M outcome.) |
| **Likelihood** | Very High (ARO 0.9 — 90% annual probability. Crimson Tide is actively exploiting this exact vulnerability on identical hardware in the same geographic region. Hospital C, 45 miles away, was compromised 3 days ago using this vector.) |
| **Inherent ALE** | $6.66M ($7.4M SLE x 0.9 ARO — equals the ransomware ALE because this IS the entry point for ransomware) |
| **Existing Controls** | None. The FortiGate is unpatched (FortiOS 7.2.3). SSL VPN is enabled and internet-facing. No WAF or IDS in front of the firewall. No alerting on SSL VPN authentication failures. Support contract lapsed, preventing firmware download. |
| **Control Gap** | Complete. Zero controls mitigate this vulnerability. The only effective control is applying the vendor patch (FortiOS 7.2.5+), which requires an active support contract. |
| **Risk Rating (Inherent)** | **CRITICAL** — CVSS 9.8, active exploitation in progress, zero existing controls, target profile match 100% |
| **Risk Rating (Residual)** | **CRITICAL** — no controls reduce residual risk below inherent risk |
| **Treatment Option** | Mitigate (apply firmware patch) |
| **Treatment Description** | Renew FortiGate support contract ($2,400 for 1 year), download FortiOS 7.2.5 firmware, verify SHA-256 hash against vendor portal, schedule 30-minute maintenance window, upgrade firmware, verify SSL VPN functionality post-upgrade, verify no indicators of compromise from pre-patch exposure. |
| **Treatment Cost** | $2,400 (1-year FortiGate support contract renewal — enables firmware download and vendor support access) |
| **Post-Treatment ALE** | $666K ($7.4M SLE x 0.09 ARO — 90% likelihood reduction from patching, assuming attacker seeks unpatched targets and moves on) |
| **ALE Reduction** | $5.994M ($6.66M minus $666K) |
| **Benefit-Cost Ratio** | 2,498:1 ($5.994M benefit / $2,400 cost) |
| **ROI** | 249,650% (($5.994M minus $2,400) / $2,400 x 100) |
| **Treatment Decision** | **JUSTIFIED — APPROVE IMMEDIATELY** |
| **Treatment Justification** | The FortiGate support contract renewal costs $2,400. The patch prevents a $6.66M ALE exposure. The benefit-cost ratio is 2,498:1. The payback period is 3.16 hours of prevented downtime exposure. This is the single highest-ROI security investment available to MedDefense. Failure to renew the contract and apply the patch guarantees continued exposure to an active campaign that has compromised 5 hospitals in 10 days. The cost of inaction ($6.66M ALE) exceeds the cost of action ($2,400) by a factor of 2,775. |
| **Implementation Timeline** | Within 4 hours of Board approval (maintenance window: July 28, 2026, 23:00-23:30 EST) |
| **Treatment Owner** | Steve (Security Engineer) |
| **Verification Method** | (1) Confirm FortiOS version upgraded to 7.2.5+, (2) Verify SHA-256 hash of firmware matches vendor-provided checksum, (3) Confirm SSL VPN functionality restored, (4) Review FortiGate logs for pre-patch exploitation indicators, (5) Document patch in change management system |
| **KRI** | (a) SSL VPN authentication failure count exceeding 10 per hour from any single IP, (b) SSL VPN sessions originating from IPs outside the tri-state region, (c) Unexpected SSL VPN admin interface access from non-internal IPs, (d) FortiGate configuration changes not initiated by authorized administrators. Threshold: any single indicator triggers IR activation and immediate forensic review. |
| **Review Date** | August 4, 2026 (7 days post-patch to verify effectiveness) |
| **Entry Created** | July 28, 2026, 10:45 EST by Steve, Security Engineer |

### Patching Cost Justification Calculation

```
Treatment Cost: FortiGate support contract (1 year): $2,400 Firmware download: $0 (included with contract) Labor (Steve, 30 min): $0 (internal resource) Maintenance window (30 min downtime): $2,000 (estimated revenue impact) Total Treatment Cost: $4,400

Risk Reduction: Pre-treatment ALE: $6.66M Post-treatment ALE: $666K (90% reduction — patched systems no longer targeted) ALE Reduction: $5.994M

Benefit-Cost Ratio: BCR = ALE Reduction / Treatment Cost BCR = $5.994M / $4,400 BCR = 1,362:1

ROI: ROI = (ALE Reduction - Treatment Cost) / Treatment Cost x 100 ROI = ($5.994M - $4,400) / $4,400 x 100 ROI = 136,045%

Payback Period: Hours = Treatment Cost / (Pre-treatment ALE / 8,760 hours) Hours = $4,400 / $760 Hours = 5.79 hours

Conclusion: Patching is overwhelmingly justified. The treatment cost represents 0.07% of the risk it mitigates. Any delay beyond the 4-hour target increases exposure by $760 per hour.
```

---

## Part 3 — Register Governance Test

### Original Governance Review Triggers (from 1x03 T10)

The Risk Register governance framework defined the following out-of-cycle review triggers:

> *"The Risk Register shall be reviewed out-of-cycle when any of the following conditions occur:*
> 
> *1. A new threat intelligence advisory is received that materially affects an existing risk entry*
> *2. A significant change in threat actor capability or intent is identified*
> *3. A control failure is detected that increases residual risk above the board-approved threshold*
> *4. An actual security incident occurs (at MedDefense or a comparable organization)*
> *5. A regulatory change alters compliance obligations*
> *6. The annual ALE for any risk entry changes by more than 25%"*

### Does the Crimson Tide Advisory Qualify as an Out-of-Cycle Review Trigger?

**YES. The Crimson Tide advisory qualifies under FOUR of the six defined triggers:**

| Trigger | Met? | Evidence |
|---|---|---|
| 1. New threat intelligence advisory materially affecting existing risk | **YES** | Crimson Tide advisory received July 28, 2026 at 07:30 EST directly affects RISK-2026-003 (ransomware). The advisory provides specific TTPs, victim profiles, and attack timelines that materially change the risk assessment. |
| 2. Significant change in threat actor capability or intent | **YES** | Crimson Tide demonstrates new capabilities not assessed in original risk entry: (a) private zero-day exploit for CVE-2023-27997, (b) 7-phase structured kill chain with healthcare specialization, (c) active campaign with 5 victims in 10 days, (d) geographic targeting of MedDefense's region (3 of 5 attacks local). Threat actor capability escalated from "generic cybercriminal" to "organized healthcare-targeting group with private exploit tooling." |
| 3. Control failure increasing residual risk above board threshold | **YES** | All three existing controls in RISK-2026-003 (antivirus, daily backups, basic network segmentation) are bypassed by Crimson Tide TTPs. Control effectiveness dropped from 20% to 5%. Residual ALE increased from $1.12M to $6.33M. The board-approved risk threshold is $500K residual ALE. At $6.33M, residual risk exceeds the board threshold by 1,266%. |
| 4. Actual security incident at comparable organization | **YES** | Five comparable hospitals compromised in 10 days. Three in MedDefense's geographic region. Hospital C is 45 miles from MedDefense Central and shares the identical infrastructure profile (FortiGate 100F, flat network, unencrypted databases). Hospital C is currently in active compromise (day 3-7 window). This is not a hypothetical risk — it is an observed incident at a peer institution with identical vulnerability surface. |
| 5. Regulatory change altering compliance obligations | No | No new regulatory requirements triggered by this advisory. However, existing HIPAA obligations (Section 164.308(a)(1)(ii)(A) — risk analysis, and Section 164.312(b) — audit controls) are now more relevant given the elevated threat. |
| 6. ALE change exceeding 25% | **YES** | ALE increased from $1.4M to $6.66M. This is a 376% increase, far exceeding the 25% threshold defined in the governance framework. The ALE change alone would trigger an out-of-cycle review even without the other four triggers. |

### Governance Determination

| Criterion | Result |
|---|---|
| Triggers met | 4 of 6 (triggers 1, 2, 3, 4, and 6 — five triggers, not four) |
| Review required? | **YES — MANDATORY** |
| Review type | Out-of-cycle, emergency |
| Review timeline | **Immediate (July 28, 2026)** — cannot wait for next scheduled review |
| Review authority | Steve (Security Engineer) initiates, Director of IT approves, CISO/CEO notified |
| Documentation required | Updated Risk Register entries (RISK-2026-003 revised, RISK-NEW-001 created), ALE recalculations (Section 5), treatment plan updates (Sections 1-4) |

### Governance Statement

*"The Crimson Tide Threat Advisory, received July 28, 2026 at 07:30 EST, satisfies five of six out-of-cycle review triggers defined in the MedDefense Risk Register Governance Framework (1x03 T10). Specifically: (1) a new threat intelligence advisory materially affecting existing risk RISK-2026-003, (2) a significant change in threat actor capability from generic cybercriminal to organized healthcare-targeting group with private zero-day tooling, (3) a control failure reducing effectiveness from 20% to 5% and raising residual ALE to $6.33M, exceeding the board threshold of $500K by 1,266%, (4) actual security incidents at five comparable hospitals including Hospital C located 45 miles from MedDefense Central, and (6) an ALE increase of 376% (from $1.4M to $6.66M), far exceeding the 25% threshold. An out-of-cycle emergency review is therefore MANDATORY and was conducted on July 28, 2026 by Steve, Security Engineer."*

---

## Risk Register Summary Post-Update

| Risk ID | Title | Pre-Update ALE | Post-Update ALE | Change | Treatment |
|---|---|---|---|---|---|
| RISK-2026-003 | Ransomware (Crimson Tide) | $1.4M | $6.66M | +376% | Mitigate IMMEDIATELY (emergency) |
| RISK-NEW-001 | FortiGate CVE-2023-27997 | N/A (new) | $6.66M | NEW | Mitigate (patch within 4 hours) |
| RISK-2026-001 | Insider threat (data exfiltration) | $200K | $200K | 0% | Monitor (no change) |
| RISK-2026-002 | DDoS attack on patient portal | $150K | $150K | 0% | Accept (no change) |
| RISK-2026-004 | Phishing (credential theft) | $350K | $350K | 0% | Mitigate (no change, covered by MFA in 72-hour plan) |
| **Total Register ALE** | | **$2.1M** | **$13.72M** | **+553%** | |

### Note on FortiGate ALE vs Ransomware ALE

RISK-NEW-001 (FortiGate) and RISK-2026-003 (Ransomware) share the same ALE of $6.66M because the FortiGate vulnerability is the entry point for the ransomware kill chain. These are NOT independent risks to be summed — they represent the SAME risk at different stages of the kill chain. The FortiGate risk feeds directly into the ransomware risk. To avoid double-counting in the total register ALE, RISK-NEW-001 should be treated as a sub-component of RISK-2026-003, not a separate independent risk.

**Corrected Total Register ALE: $7.02M** ($6.66M for ransomware/FortiGate combined + $200K insider + $150K DDoS + $350K phishing, less $340K overlap with phishing as a component of the ransomware kill chain)

---

-- Steve, Security Engineer  
July 28, 2026, 10:45 EST  
Risk Register Version: 2.1 (Emergency Out-of-Cycle Update)
