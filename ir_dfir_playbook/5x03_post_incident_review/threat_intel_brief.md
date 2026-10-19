<!-- Name: threat_intel_brief.md -->
<!-- Purpose: Enrich IR-2026-0414-01 IOCs and the observed TTP cluster against -->
<!--          offline OSINT snapshots, produce an actor profile assessment, and -->
<!--          derive forward-looking hunting priorities for MedDefense. -->
<!-- Author: Steve - Cybersecurity Engineer -->
<!-- Date: 19 October 2026 -->

# Threat Intelligence Brief: IR-2026-0414-01 / LH-2026-0414-01

**Classification:** Internal — TLP:AMBER
**Date:** 2026-10-19
**Author:** Steve — Cybersecurity Engineer
**Sources:** Offline enrichment snapshots (VirusTotal, AlienVault OTX, AbuseIPDB,
URLhaus) captured 2026-04-14T08:12Z–08:19Z; forensic findings summary dated
2026-04-14T09:45Z. No live queries were performed; all dates below are as recorded
in the snapshots.

---

## IOC Enrichment

| IOC | Type | First Seen | Last Seen | Reputation Tags | Associated Reports |
|---|---|---|---|---|---|
| 185.220.101[.]47 | IP | Tor relay infrastructure, tracked on OTX for years (relay snapshot created 2026-04-02) | AbuseIPDB last report 2026-04-13T22:18Z | tor, tor-exit, anonymizer; AbuseIPDB confidence 84, 9,412 reports from 1,284 users; VT reputation −58, 181 malicious votes | OTX Tor exit relays (DanMeUk list, applied-privacy.net); OTX "MSBuild loader campaign targeting healthcare" (HC3_ISAC, Mar 2026, hhs.gov threat brief); AS 208294 Foundation for Applied Privacy, DE |
| 91.234.99[.]107 | IP | First VT submission epoch decodes to Jul 2024 | AbuseIPDB last report 2026-04-13T22:18Z | cobalt-strike, bulletproof-hosting; AbuseIPDB confidence 92, 1,874 reports from 412 users; VT reputation −42, 94 malicious votes | OTX "Cobalt Strike C2 infrastructure — Eastern Europe cluster" (ShadowServer, Mar 2026, ransomware affiliate); OTX "Healthcare breach wave — April 2026" (Health-ISAC); AS 203727 PE Dmytro Nedilskyi, UA, datacenter/transit |
| ms0365-support[.]login-verification[.]click | Domain | VT creation epoch decodes to 2025-04 (registered approx one year before use); first URLhaus listing 2026-04-07T14:18Z | URLhaus status still online at snapshot 2026-04-14; VT analysis date same day | phishing, typosquat, credential-harvesting; Sophos, Forcepoint, BitDefender categorisations; VT reputation −84, 72 malicious votes vs 0 harmless | URLhaus /auth (credential phishing), /auth/drop/update.zip (malware download matching incident payload hash), /auth/submit (harvesting); Spamhaus DBL and SURBL listed; resolves to 45.63.9[.]88 (NameSilo registrar) |
| a4f1e9b4fe7aa6d5d3f3e2b8c9a7d4e8f5b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3 | SHA-256 (update.xml) | First VT submission epoch decodes to 2025-04 | Last VT submission/analysis epoch decodes to 2025-04 (days after first) | msbuild, inline-task, shellcode-loader, lolbin; 34 malicious / 3 suspicious / 36 undetected; reputation −22 | VT popular threat label: Trojan.MSIL.MSBuildLoader (trojan x28, loader x14); 8,412-byte XML also seen as task.xml and build.xml |

**Data caveat:** The VT epoch timestamps embedded in the snapshots decode to April
2025 dates while the surrounding snapshot and incident narrative dates are April
2026. The narrative dates (incident, snapshot, containment) are internally
consistent and are treated as authoritative; the epoch-decoded dates are reported
above as-is with this flag rather than silently reconciled.

**Analytic link:** The phishing domain's A record resolves to 45.63.9[.]88, which
is the same address recorded as the origin of the compromised Office 365 session
at 2026-04-13T18:14:41Z in the forensic findings. This ties the credential
harvesting infrastructure directly to the subsequent account takeover session,
indicating the operator reused the phishing host for session replay.

---

## TTP Cluster Match

Observed cluster: credential phishing (T1566.002) → PowerShell execution (T1059.001)
→ MSBuild LOLBin with inline-task XML (T1127.001) → LSASS credential access
(T1003.001) → Kerberos ticket abuse (T1550.003, T1558.003) → Tor and
bulletproof-hosted C2 (T1071.001, T1090.003) → PHI collection (T1005/T1083).

| Technique | Closest Matching Profiles | Confidence |
|---|---|---|
| Spear-phishing link, O365 credential harvest (T1566.002) | eCrime ransomware affiliates broadly; FIN7 | Medium (pattern), Low (named actor) |
| MSBuild inline-task LOLBin execution (T1127.001) | FIN7 (documented MSBuild abuse); ransomware affiliates adopting LOLBAS tradecraft | Medium |
| LSASS memory credential access (T1003.001) | Ubiquitous across both eCrime and state-aligned toolkits | High (technique), Low (attribution) |
| Cobalt Strike over bulletproof hosting, Tor overlay (T1071.001/T1090.003) | Conti-tradition ransomware affiliates; the OTX ShadowServer pulse explicitly tags this infrastructure cluster as ransomware-affiliate team servers | Medium-High for cluster, unattributed |
| Healthcare vertical targeting | Health-ISAC April 2026 breach wave; HC3_ISAC MSBuild healthcare campaign (Mar 2026) | High (campaign corroboration) |

No single named actor is matched at usable confidence. The evidence supports
assessment at the cluster level only.

---

## Actor Profile Summary

The infrastructure and tradecraft profile is consistent with an eCrime actor,
most plausibly a ransomware affiliate operating commodity tooling against
healthcare targets opportunistically. The C2 pair is telling: a Tor exit node for
one channel and a bulletproof-hosted (Ukrainian datacenter, small ISP registrant)
team server for the other matches the dual-channel resilience pattern documented
in the OTX ShadowServer pulse, which explicitly associates this exact IP
(91.234.99[.]107) with a Cobalt Strike team server supporting a ransomware
affiliate. The phishing domain shows moderate operator discipline: hosted on a
dedicated IP that also served the credential-submission session, registered
roughly a year ahead of use, and structured as a Microsoft-branded typosquat.
The payload is a known, publicly catalogued MSBuildLoader family rather than a
bespoke implant, indicating reliance on purchasable or leaked tooling over custom
development.

The targeting context strengthens the eCrime reading over state-aligned activity.
Two independent ISAC pulses, Health-ISAC's "Healthcare breach wave — April 2026"
and HC3's March 2026 MSBuild healthcare campaign brief, place this exact
infrastructure and TTP pattern within an ongoing multi-site US healthcare
compromise wave. MedDefense therefore appears to be one participant in a
sector-wide campaign, not a uniquely selected target. The data accessed,
laboratory report PDFs containing PHI for 14 patients, fits pre-encryption
collection for extortion value, which is standard affiliate tradecraft: establish
foothold, harvest credentials, stage data, then negotiate.

Attribution should remain deliberately loose. Nothing in the snapshots identifies
a specific named group, and the techniques involved (phishing, LOLBins, Cobalt
Strike) are shared across dozens of eCrime operators. The defensible conclusion
is cluster-level: ransomware-affiliate-class eCrime actor, commodity Cobalt
Strike tooling, healthcare-sector opportunistic targeting, moderate operational
security with several public flags on infrastructure before the incident.

---

## Predicted Next Steps

- Escalate privileges on the domain via the harvested credential material,
  prioritising privileged service accounts vulnerable to Kerberoasting, before
  any destructive action.
- Stage and exfiltrate the PHI collection for extortion leverage (the 14 PDFs
  are confirmed accessed; whether they left the network is still open pending
  DLP review).
- Rotate C2 infrastructure: burned IPs (both were publicly flagged) will be
  replaced with fresh bulletproof-hosted team servers, likely retaining Tor
  overlays and raw-IP connections without DNS.
- Establish redundant persistence beyond the observed Run key and scheduled
  task, since MedDefense has now demonstrated awareness of both.
- Deploy ransomware pre-stages: disable or evade endpoint protection, delete
  shadow copies, target backup infrastructure, then execute encryption under a
  payload staged via the same LOLBin channel.
- Contact the organisation for extortion, using the PHI access as leverage,
  irrespective of whether encryption was ultimately deployed.

---

## Recommended Proactive Hunting

1. **Signed-utility network hunt.** Search all Sysmon Event ID 3 records
   estate-wide for any process named MSBuild.exe, csc.exe, or vbc.exe initiating
   outbound connections, extending the validated Task 4 rule beyond the WST host
   class and beyond the incident window.

2. **LSASS handle hunt.** Sweep Sysmon Event ID 10 for TargetImage lsass.exe with
   unusual GrantedAccess masks from non-system parents across all servers and
   workstations, not just the three incident hosts.

3. **Kerberos weak-encryption hunt.** Search domain controller Event ID 4769 for
   service ticket requests using RC4 (0x17) encryption toward unusual SPNs,
   indicating Kerberoasting activity, and review service accounts with
   long-lived passwords.

4. **User-writable persistence hunt.** Inventory all registry Run/RunOnce values
   and scheduled tasks across the estate for binary paths resolving to
   AppData\Local\Temp or other user-writable directories.

5. **Raw-IP egress hunt.** Correlate firewall flow logs for outbound connections
   to IP addresses with no corresponding DNS query from the same host within the
   preceding window, plus any destination appearing on the current Tor exit list.

---

**Recommendation:** Treat the ransomware-affiliate assessment as the planning
assumption for the next 90 days. The hunting list above, the tuned Sigma pair,
and HRD-005 egress enforcement should be run as a coordinated sweep before
second-stage tooling can be assumed dormant rather than absent.
