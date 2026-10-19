<!-- Name: rule_validation_report.md -->
<!-- Purpose: Document validation results for both Sigma rules against incident -->
<!--          and clean Sysmon data, including match counts, false positive rates, -->
<!--          and all tuning decisions made for production deployment. -->
<!-- Author: Steve - Cybersecurity Engineer -->
<!-- Date: 19 October 2026 -->

# Rule Validation Report: IR-2026-0414-01

## Executive Summary

Both Sigma rules validated against incident data with expected positive detection on
the attack chain. The process creation rule required no tuning. The network connection
rule required one hostname-based filter to eliminate false positives from legitimate
NuGet package restore operations before production deployment.

---

## Environment

| Parameter | Value |
|-----------|-------|
| Incident log | `5x03/incident_sysmon.jsonl` (17 events, 02:40Z–04:00Z on 2026-04-14) |
| Clean baseline | `5x03/clean_sysmon.jsonl` (21 events, 30-day window from WST clinical workstations) |
| Target FP rate | Under 0.1 percent (0.001) |
| Validation tool | `validate_rules.sh` (jq + bc-based matcher) |

**Note on sample sizes:** The provided JSONL files contain 17 and 21 events respectively,
substantially smaller than the lab specification (4,812 and 287,341). Rate calculations
reflect this subset; the absolute pattern analysis (which events matched, not just
the percentage) is the primary evidence.

---

## sigma_powershell_msbuild_lolbin.yml (Task 3: Process Creation)

### Incident Data Results

| Metric | Value |
|--------|-------|
| Total events | 17 |
| Matches | 2 |
| Match rate | 11.765% |

**Verdict:** PASS

**Matched events:**

| Timestamp | Host | User | PID | Parent → Child |
|-----------|------|------|-----|----------------|
| 2026-04-14T02:46:58Z | WST-WS-031 | MEDDEFENSE\dmarsh | 8104 | `powershell.exe` → `MSBuild.exe` |
| 2026-04-14T03:27:13Z | WST-WS-017 | MEDDEFENSE\dmarsh | 5108 | `powershell.exe` → `MSBuild.exe` |

These two matches correspond to confirmed forensic findings ART-002-M01 and ART-003-M01:
the LOLBin execution chain where PowerShell spawned MSBuild.exe to load the inline-task
XML shellcode payload.

### Clean Baseline Results

| Metric | Value |
|--------|-------|
| Total events | 21 |
| Matches | 0 |
| False positive rate | 0.000% |

**Verdict:** PASS

**Analysis:** No false positives. The clean baseline contains one PowerShell-spawned
build activity (`powershell.exe → dotnet.exe`), which correctly does not match because
the rule targets `MSBuild.exe` specifically, not the broader .NET toolchain.

### Tuning Decisions

No tuning required. The rule deployed unchanged.

---

## sigma_msbuild_network_connection.yml (Task 4: Network Beaconing)

### Incident Data Results

| Metric | Value |
|--------|-------|
| Total events | 17 |
| Matches | 2 |
| Match rate | 11.765% |

**Verdict:** PASS

**Matched events:**

| Timestamp | Host | PID | Destination |
|-----------|------|-----|-------------|
| 2026-04-14T02:47:02Z | WST-WS-031 | 8104 | `185.220.101.47:443` |
| 2026-04-14T03:27:15Z | WST-WS-017 | 5108 | `91.234.99.107:443` |

These two matches correspond to confirmed C2 channels: the Tor exit node and the
Cobalt Strike team server, both carrying the MSBuild.exe payload as the initiating
process with `dst_hostname: null` (raw IP, no DNS resolution).

### Clean Baseline Results (Pre-Tuning)

| Metric | Value |
|--------|-------|
| Total events | 21 |
| Matches | 14 |
| False positive rate | 66.667% |

**Verdict:** REVIEW (exceeds 0.1% target)

**Matched events:** All 14 matches are MSBuild.exe connections to `168.62.42.37:443`
with `dst_hostname: api.nuget.org`, originating from developer workstations
WST-WS-042 and WST-WS-051 across the 30-day window (dates: 2026-03-17 through 2026-04-12).

**Analysis:** Despite exceeding the 0.1% threshold numerically, all 14 false positives
share a single identifiable pattern: legitimate NuGet package restore operations.
The IP `168.62.42.37` resolves to `api.nuget.org`, Microsoft's public NuGet package
registry endpoint. This traffic is benign by definition, and eliminating it from
the alert queue imposes no security risk. The cost of a hostname-based filter is
negligible; the benefit is substantial noise reduction.

### Tuning Applied

**Change:** Added `DestinationHostname|endswith` filter for NuGet CDN domains.

**Location:** `sigma_msbuild_network_connection.yml`, added after `filter_localhost`:

```yaml
  filter_nuget:
    DestinationHostname|endswith:
      - '.nuget.org'
  condition: selection and not filter_rfc1918 and not filter_localhost and not filter_nuget
```

**Rationale:** MSBuild.exe has no malicious reason to contact the official NuGet
package registry. The incident C2 traffic carried `dst_hostname: null` (raw IP
communication), so this filter excludes benign package-restore traffic without
creating blind spots for the observed tradecraft. The filter is intentionally
specific to `.nuget.org` rather than broadening to other CDNs; additional
allowlisting can be added reactively if other benign destinations generate
false positives in production.

### Clean Baseline Results (Post-Tuning)

| Metric | Value |
|--------|-------|
| Total events | 21 |
| Matches | 0 |
| False positive rate | 0.000% |

**Verdict:** PASS

---

## Production Deployment Checklist

- [x] `sigma_powershell_msbuild_lolbin.yml` — validated, no changes required
- [x] `sigma_msbuild_network_connection.yml` — tuned post-test (hostname filter added);
      the pre-tuning version has been archived, the tuned version replaces it as
      the production artifact
- [ ] Deploy to SIEM/Elasticsearch with EventID mapping validated against current
      Sysmon configuration (EventID 1 for process creation, EventID 3 for network
      connection)
- [ ] Configure alert correlation: both rules firing on same host within 5 minutes
      escalates to P1 (high-confidence C2)
- [ ] Document exception process for build-agent OUs requiring temporary
      whitelist on the network connection rule (rare, but the hostname filter
      reduces likelihood of this need)

---

## Known Limitations and Blind Spots

1. **Hostname-dependent detection.** The tuned rule now ignores MSBuild-initiated
   connections that do resolve to a hostname ending in `.nuget.org`. An attacker
   who resolves C2 through a domain mimicking this pattern (impossible, since
   nuget.org is Microsoft-controlled and not delegatable) or tunnels C2 via DNS
   would slip through. This trade-off is acceptable given the layered coverage
   model; the process creation rule remains unaffected.

2. **Raw-IP C2 only.** Both incident C2 connections had `dst_hostname: null`.
   Domain-based C2 with valid resolution bypasses the RFC 1918 filter but would
   require additional allowlisting or threat-intelligence feed integration to
   block proactively. Recommendation: integrate AbuseIPDB confidence scores and
   OTX pulse tags into the SIEM for dynamic reputation blocking.

3. **Sample-size volatility.** The 66.667% false positive rate on 21 events
   does not translate linearly to the full 287,341-event baseline. The absolute
   finding—not the rate—is the defensible result: all 14 matches were NuGet
   restores, and the filter eliminated them entirely. Monthly re-validation
   against rolling 30-day clean baselines will catch any drift.

---

## Recommendations Beyond Validation

1. **Add hostname-based threat intelligence.** The incident C2 domains were IP-based,
   but a `DestinationHostname` filter referencing threat feeds would catch domain-based
   C2 before DNS resolves to known-bad IPs. Requires SIEM integration with AbuseIPDB,
   URLhaus, and OTX feeds.

2. **Expand RFC 1918 coverage.** The current filter enumerates 172.16–172.31
   explicitly because the `sysmon` config maps `DestinationIp` as a keyword field.
   CIDR notation is unavailable in legacy sigmac. Migration to pySigma enables
   single `cidr: 172.16.0.0/12` expressions for future maintenance.

3. **Correlation alerting.** The two-layer design (high-level process creation
   + medium-level network beacon) enables escalation logic: when both rules fire
   on the same host within 5 minutes, the SOC receives a single high-confidence
   C2 alert instead of two separate lower-confidence hits. This reduces analyst
   triage overhead while maintaining coverage.

4. **Re-validate monthly.** Run `./validate_rules.sh` against a rolling 30-day
   clean baseline each month. New developer tooling or build pipeline changes
   could introduce fresh false positives; proactive re-validation prevents
   alert-fatigue accumulation.

---

## Attachments

- `sigma_powershell_msbuild_lolbin.yml` — validated, no changes
- `sigma_msbuild_network_connection.yml` — validated, tuned (hostname filter added)
- `validate_rules.sh` — reusable validation harness for future rules

---

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Analyst | Steve - Cybersecurity Engineer | 2026-10-19 |
| Review | James Chen | Pending |
| Approved | | Pending |

**Closure criteria:** Both rules tested against incident and clean data, FP rates
documented and resolved, tuning changes recorded, deployment checklist populated.
Ready for SIEM integration.
