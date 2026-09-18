# 6-ioc_correlation.md

**Name:** IOC Correlation Plan

**Purpose:** Normalize phishing indicators from the email batch, correlate them
          with the reported click event, and document the log queries a SOC
          analyst would perform if telemetry were available

**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — IOC CORRELATION REPORT

Evidence source: Email evidence batch (8 emails, collected 2026-04-17 by Mike Torres)

plus the click note for Diane Marsh recorded in the batch footer.

No live SIEM, Wazuh, Sysmon or Suricata data was used or required.

All indicators are defanged for safe documentation.

================================================================================

## IOC Correlation Report

### Normalized IOC List

| Type | Indicator (defanged) | First Seen (CDT) | Context |
|------|----------------------|------------------|---------|
| Domain | meddefense-portal[.]com | 2026-04-14 09:47 | E2 sending domain, credential harvesting host (sender IP 91.234.99.107) |
| Domain | outlook-protection[.]com | 2026-04-15 09:13 | E3 sending domain, Microsoft brand impersonation (sender IP 51.38.42.17) |
| Domain | medequip-supplies[.]net | 2026-04-16 11:28 | E5 sending domain, fraudulent invoice/payment portal (sender IP 185.176.43.22) |
| Domain | meddefense-benefits[.]org | 2026-04-16 15:22 | E7 sending domain, HR benefits harvesting host (sender IP 164.90.218.73) |
| Domain | canadian-pharma-discount[.]org | 2026-04-16 13:04 | E6 spam domain, not campaign-linked (sender IP 203.0.113.228) |
| URL | hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 | 2026-04-14 09:47 | E2 credential harvesting URL — CLICKED by Diane Marsh |
| URL | hxxps://meddefense-portal[.]com/assets/logo[.]png | 2026-04-14 09:47 | E2 impersonation branding asset |
| URL | hxxps://outlook-protection[.]com/verify | 2026-04-15 09:13 | E3 M365 credential harvesting URL |
| URL | hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 | 2026-04-16 11:28 | E5 fraudulent payment portal (body and PDF attachment) |
| URL | hxxps://medequip-supplies[.]net/portal/login | 2026-04-16 11:28 | E5 secondary harvesting path |
| URL | hxxps://meddefense-benefits[.]org/enroll | 2026-04-16 15:22 | E7 benefits enrollment harvesting URL |
| IPv4 | 91[.]234[.]99[.]107 | 2026-04-14 09:47 | E2 sending IP |
| IPv4 | 51[.]38[.]42[.]17 | 2026-04-15 09:13 | E3 sending IP |
| IPv4 | 185[.]176[.]43[.]22 | 2026-04-16 11:28 | E5 sending IP |
| IPv4 | 164[.]90[.]218[.]73 | 2026-04-16 15:22 | E7 sending IP |
| IPv4 | 203[.]0[.]113[.]228 | 2026-04-16 13:04 | E6 spam send/serve host (noise) |
| File | INV-2026-04891.pdf (application/pdf, base64) | 2026-04-16 11:28 | E5 attachment, wkhtmltopdf 0.12.6 producer, embedded URI, visible SHA-256 indicator string |
| Recipient | dmarsh@meddefense[.]com (Diane Marsh, WS-NURSE-04, 10.10.2.15) | 2026-04-14 09:47 | E2 target — CONFIRMED CLICK |
| Recipient | rmendez@meddefense[.]com (Rafael Mendez) | 2026-04-15 09:13 | E3 target, click status unknown |
| Recipient | arivera@meddefense[.]com (Angela Rivera) | 2026-04-16 11:28 | E5 target, reported suspicious, click status unknown |
| Recipient | lpatterson@meddefense[.]com (Linda Patterson) | 2026-04-16 15:22 | E7 target, did not engage, click status unknown |
| Recipient | jmoore@meddefense[.]com, pwhite@meddefense[.]com | 2026-04-14 / 2026-04-16 | E1/E6 recipients (noise, no exposure) |
| Event | Click at 2026-04-14 15:02:33 CDT by Diane Marsh from WS-NURSE-04 (10.10.2.15) | 2026-04-14 15:02:33 | Per workstation NTP, recorded in the evidence batch footer |

Infrastructure fingerprint shared by E2, E3, E5, E7: PHPMailer 6.6.0, Message-ID format PHP-{hex}@domain, localhost (127.0.0.1) injection hop, urgency pretexts, role-targeted lures, domain keywords portal/protection/supplies/benefits.

---

### Exposure Timeline

| Time (CDT) | Event | Evidence Status |
|------------|-------|-----------------|
| 2026-04-14 09:47 | E2 credential phishing delivered to Diane Marsh (dmarsh@meddefense.com) | Confirmed by batch (headers) |
| 2026-04-14 15:02:33 | Diane Marsh clicks harvesting link hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 from WS-NURSE-04 (10.10.2.15) | Confirmed by batch click note (workstation NTP) — ~5 hours 15 minutes after delivery |
| 2026-04-14 15:02 onward | Potential credential submission window | NOT confirmed — requires proxy/endpoint/auth logs |
| 2026-04-15 09:13 | E3 Microsoft impersonation delivered to Rafael Mendez | Confirmed by batch |
| 2026-04-15 10:00 | Legitimate internal password-change reminder (E4) circulated to clinical staff | Confirmed by batch |
| 2026-04-16 08:47 | HC3 sector advisory (E8) received at SOC alerts mailbox | Confirmed by batch |
| 2026-04-16 11:28 | E5 fraudulent invoice delivered to Angela Rivera (AP) | Confirmed by batch |
| 2026-04-16 13:04 | E6 pharmaceutical spam delivered to Patricia White (noise) | Confirmed by batch |
| 2026-04-16 15:22 | E7 HR benefits phish delivered to Linda Patterson | Confirmed by batch |
| 2026-04-17 09:15 | Evidence batch collected by Mike Torres; investigation begins | Confirmed by batch |
| 2026-04-17 ~21:15 | Approximate elapsed time since Diane Marsh click at investigation start | Derived from batch (~36 hours stated in brief) |

The exposure window is the critical driver: at the time of investigation, roughly 36 hours separate the confirmed click from containment opportunity. Any credential submitted at 2026-04-14 15:02 has been valid in attacker hands for a day and a half, with the E3 delivery occurring nearly 18 hours after the click, meaning continued campaign activity was ongoing while the first compromise window was already open.

---

### Confirmed Evidence From Batch

The following facts are established directly by the email evidence batch and the recorded click note, requiring no additional telemetry:

1. Four lookalike or impersonation domains delivered phishing emails to MedDefense staff within a 57-hour window (E2, E3, E5, E7), all sharing the PHPMailer 6.6.0 sending fingerprint.
2. Diane Marsh (dmarsh@meddefense.com, workstation WS-NURSE-04, IP 10.10.2.15) clicked the E2 harvesting URL hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 at 2026-04-14 15:02:33 CDT.
3. The clicked URL contained her username (id=dmarsh) and a tracking token (token=a8f3e2d1), enabling attacker-side victim attribution regardless of whether credentials were ultimately submitted.
4. E2, E5 and E7 failed SPF, DKIM and DMARC; E3 passed all three for a domain the attacker controls (outlook-protection.com), which does not validate the Microsoft brand claim.
5. The E5 attachment is a fabricated invoice (wkhtmltopdf 0.12.6 producer, created one second before send) with an embedded payment-redirect URI matching the body links.
6. Role-targeted delivery is evident: clinical staff (E2), generic M365 user (E3), Accounts Payable (E5), billing/HR (E7), consistent with the campaign pattern described in the HC3 advisory received 2026-04-16 (E8).
7. Recipients Linda Patterson and Angela Rivera did not report engaging with their lures; their click status is simply unknown, not confirmed safe.

The following remain UNKNOWN and require logs or interviews: whether Diane Marsh entered credentials after clicking, whether a session was created for the attacker, whether any other staff clicked E2/E3/E5/E7 beyond the reports received (Sarah Park's concern), whether the E5 portal logged in from MedDefense networks, and whether any EHR access followed the click.

---

### Queries To Run If Logs Were Available

The following queries define what a SOC analyst should search for, per telemetry source. None were executed; these are the correlation plan.

**DNS logs (internal resolver or recursive forwarder):**

- Search for A/AAAA/CNAME queries to meddefense-portal[.]com, outlook-protection[.]com, medequip-supplies[.]net, meddefense-benefits[.]org, canadian-pharma-discount[.]org across the full window 2026-04-14 00:00 CDT to present.
- Specifically expect a DNS query for meddefense-portal[.]com from 10.10.2.15 at approximately 2026-04-14 15:02:30–15:02:33 CDT — this validates the click note against resolver telemetry and establishes the precise resolution time.
- Enumerate ALL client IPs resolving these domains, not just the known victims. Any other internal host resolving meddefense-portal[.]com between 2026-04-14 09:47 and 2026-04-16 is an unreported click candidate (Sarah Park's concern about additional clicks).
- Check for queries to the apex domains without the /verify path (harvesting infrastructure often serves the kit on multiple paths).
- Long-tail check: queries to any meddefense-prefixed or lookalike domains not in the batch, in case other campaign domains were used against staff whose reports were not collected.

**Proxy / web gateway logs (Squid, Bluecoat, Zscaler, or equivalent):**

- Search HTTP CONNECT or GET records for the four campaign domains and all six listed URLs, filtered to internal source ranges, from 2026-04-14 through the investigation date.
- Expected finding: a GET to /verify/staff from source IP 10.10.2.15 at 2026-04-14 15:02:33 CDT. Critically, examine what FOLLOWS that record: a POST to the same or adjacent path (e.g., /verify/staff/process, /login) with a payload size consistent with a submitted form would indicate credential submission. Absence of any POST after the GET suggests click-through without submission.
- Check for repeated hits (cookie refresh, follow-on visits) which would indicate harvested credentials were still valid and in use, or that the victim revisited.
- Examine user-agent strings for POSTs from 10.10.2.15 — an unusual or scripted user-agent after the click could indicate automated harvesting or Session 2 activity rather than Diane's browser.
- Search for any traffic to the E5 payment portal from Accounts Payable VLAN/subnets, and any access to meddefense-benefits[.]org/enroll from billing networks.
- Search for requests from egress IPs other than expected MedDefense ranges hitting the same harvesting token (token=a8f3e2d1 is attacker-side unique — its presence in any outbound request string identifies the victim session even across NAT).

**Endpoint logs (Sysmon-class, AV, or local host artifacts on WS-NURSE-04):**

- Retrieve browser history and cache for WS-NURSE-04 covering 2026-04-14 14:00–16:00 CDT: confirm the visited URL, whether a form was autofilled or typed, and whether credentials appear in form-history artifacts.
- Process creation events around 15:02:33 CDT — distinguish browser navigation from any download or script execution (Stage 2 deployment per HC3 advisory). No malware delivery is proven by the batch, so endpoint review is the confirming step for the "possible Stage 2" concern.
- Check for scheduled tasks, persistence registry keys, or unexpected child processes of the browser in the 36-hour post-click window.
- Review credential manager, cookie stores, and cached session tokens for meddefense-portal.com artifacts.
- Pull AV/EDR detections for WS-NURSE-04 over the same window as a completeness check.

**Authentication logs (domain controller, VPN, SSO/IdP, EHR application):**

- Review authentication attempts for dmarsh from 2026-04-14 15:02:33 CDT forward: look for sign-ins from unfamiliar source IPs, unusual geolocation, off-shift hours (Diane is clinical staff; an EHR login at 03:00 would be anomalous), or new-device registrations.
- Correlate timing: any successful authentication for dmarsh originating outside 10.10.2.15's expected pattern within hours after the click is presumptively attacker use of harvested credentials.
- Check VPN logs for dmarsh credentials used from external IPs — harvested domain credentials commonly surface first at the VPN gateway.
- Check EHR audit trails for dmarsh's account: patient record access patterns, mass export, or abnormal query volumes would indicate data access using the compromised account (HIPAA exposure determination).
- Review password change events for dmarsh; note E4 establishes the legitimate quarterly change window opens April 20 — a change BEFORE that date outside self-service would itself be an anomaly.
- Also review rmendez M365 sign-in logs against the claimed "Lagos, Nigeria / 41.203.72.188" detail in E3 — although that claim is attacker-fabricated bait, checking whether any genuine anomalous sign-ins existed for that account closes the loop on E3.

---

### Detection Gaps

1. **No centralized mail telemetry.** Without mail flow logs beyond the batch, we cannot determine how many copies of E2/E3/E5/E7 reached other mailboxes beyond the six reports and two quarantines. Sarah Park's concern — additional unreported recipients of the portal phish — cannot be answered from the batch alone. Recommendation: export mail gateway logs for the four sending IPs and domains across the full campaign window.

2. **Click visibility depends on proxy/DNS retention.** The single click we know about came from a user report with a workstation-recorded timestamp, not from tooling. Organizations without proxy or DNS logging would have zero visibility into who clicked. Recommendation: verify proxy and DNS log retention covers at least 90 days and that harvesting URLs are searchable by path parameters (token= values), not just domains.

3. **Credential submission is not directly observable by email evidence.** The strongest confirmation that credentials were harvested requires either proxy POST inspection, IdP sign-in anomaly records, or interviewing Diane Marsh. Currently the investigation knows the click happened but not the outcome. Recommendation: prioritized interview with Diane plus password reset regardless of outcome.

4. **Follow-on access detection on clinical systems.** EHR application audit logging (who accessed what patient data, when, from where) is the only way to bound the HIPAA impact if credentials were harvested. If EHR audit logging is thin or not reviewed, this is the largest gap given Diane's clinical role.

5. **Lookalike domain monitoring.** Four lookalike domains reached mailboxes before any proactive alert fired; detection was user-report driven (HC3's advisory arrived only on day three). Recommendation: subscribe to certificate transparency monitoring (crt.sh alerts) and newly-registered-domain feeds for defensive-domain permutations (meddefense-, meddefense*, .org/.net variants).

6. **DMARC enforcement posture.** E2, E5 and E7 show action=none, meaning DMARC failures were accepted rather than rejected or quarantined — except E6, where action=quarantine caught the loudest offender. Recommendation: enforce p=reject on meddefense.com and consider stricter inbound policy for lookalike-prone spoof classes; note this would NOT have stopped E3 (which passes authentication) nor E2/E5/E7 if sent from attacker-owned lookalike domains — domain lookalike detection, authentication-based filtering, and user awareness are complementary controls, none sufficient alone.

7. **User reporting latency.** E2 was delivered at 09:47 and clicked at 15:02 the same day, but the investigation began 2026-04-17 — roughly 53 hours of dwell time on a single-click compromise. Recommendation: one-click report button and same-day SOC triage workflow, with high-risk lures (portal, payroll, benefits) routed for priority review.

---

### Conclusion

The email batch independently establishes a coordinated phishing campaign against MedDefense Health Systems: four role-targeted lures (E2, E3, E5, E7) sharing PHPMailer 6.6.0 infrastructure and lookalike domains, matching the pattern in the HC3 sector advisory received 2026-04-16. The batch also confirms the highest-severity event: Diane Marsh of WS-NURSE-04 (10.10.2.15) clicked the Email 2 credential harvesting URL hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 at 2026-04-14 15:02:33 CDT, approximately 36 hours before investigation began.

What the batch cannot tell us defines the immediate priority actions: whether credentials were submitted, whether additional staff clicked unreported links, and whether any follow-on access occurred. The IOC list above is ready for gateway blocking now (four domains, five sending IPs, six URLs, one file hash indicator), and the log query plan defines the confirmation path through DNS, proxy, endpoint, and authentication telemetry once those sources are engaged. Until proxy or IdP logs rule out credential submission, Diane Marsh's account must be treated as potentially compromised: force password reset, revoke active sessions, review EHR access for her account from the click time forward, and interview her regarding the post-click interaction. IOCs should be prepared for submission to the HC3 portal per the E8 advisory, since the batch evidence suggests MedDefense may be among the first reporters of this campaign.

================================================================================
