# MedDefense Severity Matrix

## Purpose

Common severity language for all MedDefense incidents. Applied from first alert through closure.

Classification must be deterministic: given the same evidence, a Tier 1 analyst, the CISO, and the General Counsel select the same row. When in doubt between two levels, classify at the higher severity.

## Severity Matrix

| Level | Patient Safety Impact | Data Exposure | Service Availability | Max Response Time | Decision Authority |
|---|---|---|---|---|---|
| SEV1 | high | confirmed_broad | full_outage | 15 min | CISO |
| SEV2 | moderate | confirmed_limited | partial_outage | 30 min | IR Commander |
| SEV3 | low | suspected | degraded | 60 min | SOC Lead |
| SEV4 | none | none | none | 240 min | SOC Analyst |

Response time is measured from first detection or report, not from assignment. An unresolved SEV3 that breaches its window triggers an automatic SEV2 review, mirroring OpenStatus-style auto-escalation: do not wait for the next scheduled status update to re-classify.

## Level Definitions

### SEV1

- Ransomware affecting clinical systems across multiple sites
- Confirmed exfiltration of patient records at scale (broad scope across the ~180,000-record population, or affecting more than one site)
- Patient-facing system outage beyond board-committed RTO: Epic (`epic.meddefense.local`) unavailable beyond 4 hours, or patient monitoring, ED, ICU, or OR systems offline during active care

### SEV2

- Confirmed compromise of a clinical-access account (e.g., Epic Hyperspace credentials used for unauthorized PHI access)
- Malware confirmed on a single workstation at a clinical site (e.g., `wst-ws-NN.meddefense.local` in `10.42.118.0/24`)
- Suspected exfiltration under investigation with limited, confirmed access to patient data

### SEV3

- Successful credential phishing on a non-clinical account with no evidence of follow-on activity
- Malicious email attachment detonated in an isolated environment with no endpoint execution (Wazuh EDR shows no subsequent detections)
- Scheduled vulnerability scan or reconnaissance activity detected at a single clinical site

### SEV4

- Blocked malware or phishing attempt (sandbox quarantined, no host execution)
- Single failed login or lockout on a non-administrative account with no corroborating signals
- Policy violation or configuration drift reported with no evidence of adversary activity

## Escalation Rule

Severity is reviewed at every status update. It increases when new evidence raises patient safety, data exposure, or service availability to the next tier. It decreases only after confirmed containment and IR Commander approval.

If an incident remains unresolved beyond its max response time by a factor of four, the severity is automatically reviewed for elevation to the next tier without waiting for the scheduled status update.
