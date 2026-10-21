# Forensic Investigation Report

**Case number:** LH-2026-0414-01
**Litigation hold reference:** Memo from Helena Reyes, 2026-04-14T07:30Z
**Date:** 2026-04-14
**Lead investigator:** Steve — Cybersecurity Engineer
**Classification:** Internal — Legal Hold
**Distribution:** Dr. Patricia Morales (CISO), Helena Reyes (General Counsel), James Chen (SOC Lead)

---

## Executive Summary

Between April 13 and April 14, 2026, an external attacker stole the login credentials of a
MedDefense laboratory technician through a fraudulent email and used them to enter
MedDefense systems remotely. Over roughly nine and a half hours, the attacker ran malicious
software on two clinical workstations and opened fourteen patient laboratory reports on the
laboratory information system workstation at West Campus. Those reports contain patient
names, dates of birth, attending physicians, and clinical lab results.

The attacker's first step was at 18:14 UTC on April 13, when the technician entered
credentials into a counterfeit Microsoft login page reached from a phishing email
(proxy_log lines 6–10; ART-001-F01). The attacker's software replayed those credentials into
the organization's cloud mail service from Russia within the same second, taking advantage
of a security policy that trusted the technician's device (ad_auth_log line 3). Fourteen
seconds after the technician handed over the page's password, a malicious file was pushed to
him as a download; he saved it to his Downloads folder (proxy_log line 11; ART-001-F01).

After midnight, the attacker logged in remotely over the company VPN using the stolen
password (ad_auth_log line 7), ran hidden malicious software that abused two trusted
Microsoft programs to disguise itself (ART-002-M01; SIEM alert A-20260414-9841), and
maintained a covert connection to an external command-and-control server through an
anonymizing network (ART-002-M02; proxy_log lines 12–14). The attacker then used the
technician's identity to hop to a second workstation and from there to the laboratory
server, where he opened the fourteen patient reports (ad_auth_log lines 8–14). The security
monitoring system raised a high-severity alert thirteen seconds after the malicious software
first ran, but no analyst was assigned to it (SIEM alert A-20260414-9841, `analyst_assigned:
null`), and the intrusion proceeded for another 56 minutes before the reports were opened.

No evidence currently confirms that copies of the reports left the network, but the
investigation did not fully rule it out (see Gaps and Limitations). Under federal health
privacy law, opening the reports by an unauthorized party is sufficient to constitute a
breach; the assessment and notification obligations are summarized below.

## Methodology

Three artifacts were analyzed under litigation hold LH-2026-0414-01: disk image
`wst-ws-031.dd` (ART-001) and memory captures `wst-ws-031.mem` (ART-002) and
`wst-ws-017.mem` (ART-003). Baseline SHA-256 values were computed at first forensic access
(hashes.txt; verification_log.txt) and verified before every analysis session
(`verify_artifacts.sh`); no acquisition-time hashes existed, so integrity is attested from
first access forward. Disk analysis used The Sleuth Kit (mmls, fsstat, fls, icat, mactime)
and registry parsers against the read-only image, with working-copy extraction of files and
hives logged as derived evidence in the chain of custody. Memory analysis used Volatility 3
(pslist, pstree, cmdline, netscan, dlllist, malfind, handles, hashdump). Log correlation drew
on `proxy_log.jsonl`, `ad_auth_log.jsonl`, and `siem_alert_export.json` as supplementary
sources. Known handling deviations from the acquisition period are recorded in the chain of
custody (DEVIATION notes) and addressed under Gaps and Limitations.

## Technical Findings

### Disk artifacts (ART-001)

**ART-001-F01:** Malicious archive `update.zip` (421,004 bytes) created in
`C:\Users\dmarsh\Downloads\` at 2026-04-13T18:14:43Z, matching a 421,004-byte download from
the phishing site in the same second (proxy_log line 11) — delivery vehicle for the payload.

**ART-001-F02:** MSBuild inline-task payload `update.xml` staged in
`C:\Users\dmarsh\AppData\Local\Temp\` around 2026-04-14T02:46Z. An inline task embeds
executable code inside a build file, letting code run without dropping a conventional
program (T1127.001). Strings include `System.Net.WebClient`.

**ART-001-R01:** Run-key persistence, `HKCU\...\Run\MsUpdateCheck`, chaining an encoded,
hidden PowerShell launch into MSBuild execution of `update.xml` at every logon (T1547.001).

**ART-001-R03:** Redundant scheduled task `\MsUpdateCheck` (trigger: logon; principal:
dmarsh; action: MSBuild `update.xml`) surviving Run-key removal (T1053.005). Identical
naming across both mechanisms indicates one operator.

**ART-001-F05:** The C2 address 185.220.101.47:443 (Tor exit relay) referenced on disk,
confirming anonymizer-based egress planning (T1090.003).

### Memory artifacts (ART-002, ART-003)

**ART-002-M01:** Process tree at capture: explorer.exe → `powershell.exe` PID 7812
(`-ep bypass -w hidden -enc`) → `MSBuild.exe` PID 8104 executing `Temp\update.xml`
(T1059.001 / T1127.001). Confirms the SIEM alert's process-tree claim from primary
evidence.

**ART-002-M02:** At the 03:02Z capture, PID 8104 held an ESTABLISHED TCP connection to
185.220.101.47:443 (Tor exit relay) — live C2 channel at acquisition (T1071.001 /
T1090.003).

**ART-002-M03:** Phishing URL, C2 IP, and payload name co-resident in memory strings,
tying initial access, C2, and payload to the same session.

**ART-003 series (WST-WS-017):** Full Volatility results for ART-003 are pending; see
Gaps and Limitations.

### Network / proxy evidence

Proxy log lines 12–14: MSBuild.exe PID 8104 CONNECTs to the Tor exit relay at
02:46:58Z–02:47:30Z, then continued beacons; lines 15–16: MSBuild.exe PID 5108 on
WST-WS-017 CONNECTs to a second C2, 91.234.99.107:443 (`c2_infrastructure`), at 03:27:13Z
and 03:27:45Z. Two C2 channels of distinct infrastructure classes operated concurrently
(correlated_timeline rows 13, 22).

### Authentication evidence

**ad_auth_log line 3:** Azure AD sign-in from 45.63.9.88 (RU) in the same second as
credential submission; `impossibleTravel` risk flagged medium but overridden by the
`compliant_device` conditional-access policy.

**ad_auth_log line 7:** VPN logon as dmarsh from the same RU IP at 02:44:17Z — remote
attacker entry (T1133). **Lines 8–10:** Kerberos TGS requests for `cifs/` and `host/`
WST-WS-017 followed by a type-3 Kerberos logon to WST-WS-017 — lateral movement via the
stolen technician identity (T1550.003 / T1021.002). **Lines 11–13:** Repeat TGS for
`cifs/LIS-WSIDE-01` (one noted `ticket_reuse`) and type-3 logon to LIS-WSIDE-01.
**Line 14:** Fourteen patient report PDFs opened via `LIS_REPORTS$` at 03:43:30Z as dmarsh.

## Incident Timeline (condensed)

| Time (UTC) | Event | Evidence |
|---|---|---|
| 04-13 18:14:02 | Phishing link clicked; typosquat page loaded | proxy_log ln 7 |
| 04-13 18:14:41 | Credentials submitted; attacker cloud sign-in from RU same second | proxy_log ln 10; ad_auth ln 3 |
| 04-13 18:14:43 | `update.zip` downloaded/created | proxy_log ln 11; ART-001-F01 |
| 04-14 02:44:17 | VPN logon from RU as dmarsh | ad_auth ln 7 |
| 04-14 02:46:41 | Encoded PowerShell runs payload | ART-002-M01; SIEM A-20260414-9841 |
| 04-14 02:46:57–58 | MSBuild executes `update.xml`; C2 beacon to Tor exit starts | ART-002-M01/M02; proxy_log ln 12 |
| 04-14 02:47:11 | SIEM alert fires; no analyst assigned | siem_alert_export |
| ~02:46–03:02 | Dual persistence installed (Run key + task) | ART-001-R01/R03 |
| 04-14 03:22–23:01 | Kerberos requests and logon to WST-WS-017 | ad_auth ln 8–10 |
| 04-14 03:27:13 | Second C2 beacon from WST-WS-017 | proxy_log ln 15 |
| 04-14 03:40–03:42:08 | Kerberos requests and logon to LIS-WSIDE-01 | ad_auth ln 11–13 |
| 04-14 03:43:30 | 14 patient report PDFs opened (PHI access) | ad_auth ln 14 |
| 04-14 ~04:00→06:14 | Isolation; memory and disk acquisitions | chain of custody |

## Breach Scope Determination

Fourteen patient laboratory report PDFs were opened by an unauthorized party between
03:43:30Z and 03:44Z (ad_auth_log line 14). Contents: patient name, date of birth,
attending physician, complete blood count, and metabolite panel results — directly
identifying, clinically sensitive PHI. Patients: 14 individuals from an ER department for
whom the account holder (a lab technician) had no legitimate access basis. Certainty of
access: confirmed (object-access audit events; correlated_timeline final data-access rows).

Four-factor assessment under 45 CFR 164.402: (1) nature/extent of PHI — adverse (direct
identifiers plus clinical results); (2) unauthorized person — adverse (criminal intruder
via compromised account, no treatment relationship); (3) actually acquired or viewed —
adverse (files demonstrably opened); (4) risk mitigation — adverse (no mitigation reached
the data; attacker controlled the session until containment). The low-probability-of-
compromise exception is not met; the impermissible access constitutes a reportable breach.
Notification: 14 individual notices and HHS Secretary annual-report entry; discovery date
2026-04-14 (individual notice due without unreasonable delay, no later than 2026-06-13).

## Gaps and Limitations

1. **No acquisition-time hashes.** Integrity is attested from first forensic access
forward (chain-of-custody DEVIATION notes); the artifacts cannot be proven unchanged
relative to original collection.
2. **Live, post-isolation disk acquisition and a pre-imaging read-write mount** limit
atime reliability and single-instant filesystem claims (see Tasks 3–4 caveats).
3. **Pending analyses:** ART-003 Volatility output (second-host process detail);
ART-002 Malfind/Handles/Hashdump confirmations; exact MAC seconds and registry last-write
times. The timeline sequence is unaffected (anchored by three corroborating log sources).
4. **Exfiltration not ruled out.** No confirmed egress of the PDFs, but DLP log review was
outside this engagement; conclusions about data *transfer* cannot be drawn.
5. **Origin of the 04-13 Azure AD session post-submission and the suppressed risk
signals** were not traced (open items, forensic_findings_summary).

## Recommendations

1. **Assign and escalate high-severity EDR alerts automatically.** Alert A-20260414-9841
   fired 13 seconds after execution with `analyst_assigned: null`; mandate paging-tier
   routing for severity-high alerts and an acknowledgment SLA (James Chen, SOC).
2. **Close the conditional-access gap.** Replace the `compliant_device` override with
   step-up MFA and geography-based blocking for VPN and cloud sign-ins from unseen
   countries (ad_auth ln 3, 7; Infrastructure/Identity).
3. **Restrict LOLBin abuse on clinical workstations.** Application-control policy
   blocking MSBuild execution for non-administrator/non-developer accounts, addressing
   ART-001-F02 / ART-002-M01 (Infrastructure).
4. **Scope-based share access on clinical file servers.** Enforce department-aligned access
   so a lab account cannot open ER reports via `LIS_REPORTS$` (ad_auth ln 14; Identity/IT).
5. **Complete the exfiltration determination.** Commission the DLP/egress review to close
   open item 4 above before the notification letters are finalized (Helena Reyes/Steve).

---
*Prepared under LH-2026-0414-01. Append-only chain of custody and verification logs
maintain the evidentiary record for this report.*
