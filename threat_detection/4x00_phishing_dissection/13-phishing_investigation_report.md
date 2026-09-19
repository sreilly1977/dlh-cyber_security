# 13-phishing_investigation_report.md

**Name:** Phishing Campaign Investigation Report

**Purpose:** Synthesize the complete investigation into a professional narrative
          report suitable for SOC lead review and sharing with HC3

**Author:** Steve - Cybersecurity Engineer

**Date:** 19 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — PHISHING CAMPAIGN INVESTIGATION REPORT

Case Reference: Phishing Dissection — Evidence Batch 2026-04-17

Prepared for: James Chen (SOC Lead), HC3 sector submission per advisory

HC3-2026-PRELIM-001 (TLP:CLEAR)

Distribution: Internal SOC, IT Leadership, Compliance; external IOC extract
approved for HC3 submission

================================================================================

## 1. Executive Summary

Between April 14 and April 16, 2026, MedDefense Health Systems was targeted by a coordinated phishing campaign that sent convincing fraudulent emails to staff in our clinical, finance, and benefits departments. Four of the eight emails examined were part of this attack, each impersonating a trusted function (our patient portal, Microsoft, a medical supply vendor, and our HR benefits office) and each pressuring staff with urgent deadlines to steal login credentials or divert payments. One nurse, Diane Marsh, clicked the fraudulent portal link roughly 15 minutes after receiving it, and her account must be treated as potentially compromised because we cannot yet confirm whether she entered her password on the attacker's page. The attack matches in detail an alert issued on April 16 by the federal Health Sector Cybersecurity Coordination Center (HC3), suggesting MedDefense is among the first victims of a wider regional campaign targeting hospitals, which presents us an early-reporting opportunity. Immediate protective measures — password resets, blocking of the attacker's internet addresses, and warnings to finance staff about the fake invoice — are already underway, and we recommend completing them within 24 hours.

---

## 2. Investigation Timeline

| Date/Time (CDT) | Event | Source |
|-----------------|-------|--------|
| 2026-04-14 07:22 | E1 legitimate newsletter delivered (J. Moore) | Evidence batch headers |
| 2026-04-14 14:47 | E2 portal credential phish delivered to Diane Marsh | Evidence batch headers |
| 2026-04-14 15:02:33 | **Diane Marsh clicks E2 harvesting link from WS-NURSE-04 (10.10.2.15)** | Batch click note (workstation NTP) |
| 2026-04-15 09:13 | E3 Microsoft impersonation delivered to R. Mendez | Evidence batch headers |
| 2026-04-15 10:00 | E4 legitimate internal password-change reminder distributed | Evidence batch headers |
| 2026-04-16 08:47 | E8 HC3 sector alert received at SOC alerts mailbox | Evidence batch headers |
| 2026-04-16 11:28 | E5 fraudulent invoice delivered to A. Rivera (Accounts Payable) | Evidence batch headers |
| 2026-04-16 13:04 | E6 pharmaceutical spam delivered (P. White, quarantined by gateway) | Evidence batch headers |
| 2026-04-16 15:22 | E7 HR benefits phish delivered to L. Patterson | Evidence batch headers |
| 2026-04-17 09:15 | Evidence batch compiled by M. Torres; investigation begins | Batch collection note |

**Collection window:** Approximately 57 hours of email activity (2026-04-14 07:22 through 2026-04-16 15:22 CDT), comprising 6 user-reported emails and 2 gateway-quarantined emails, collected with full raw SMTP headers intact.

**Investigation scope:** All 8 emails analyzed for authentication, headers, content, social engineering, URLs, and attachments. Click event analysis for WS-NURSE-04. Campaign correlation and IOC extraction performed from evidence only; no live DNS, endpoint, or SIEM data was available to this investigation.

**Key exposure fact:** At investigation start, the confirmed click on E2 was approximately 36 hours old, with the attacker potentially holding harvested credentials for that entire window.

---

## 3. Email-by-Email Analysis

| Email | Verdict | Classification | Confidence | Key Evidence |
|-------|---------|----------------|------------|--------------|
| E1 | Legitimate marketing newsletter | LEGITIMATE | HIGH | SPF/DKIM/DMARC all pass; MailChimp infrastructure; subscription record from 2024; working unsubscribe links; TLS relay |
| E2 | Targeted credential phishing (patient portal impersonation) — CONFIRMED CLICK | PHISHING-TARGETED | VERY HIGH | Lookalike domain meddefense-portal[.]com; total authentication failure; per-victim URL token; nursing-specific lure; clicked by Diane Marsh at 15:02:33 CDT |
| E3 | Targeted credential phishing (Microsoft impersonation) | PHISHING-TARGETED | HIGH | outlook-protection[.]com is not a Microsoft domain; authentication passes only for the attacker's own domain; PHPMailer fingerprint matching campaign; 48-hour lockout pressure |
| E4 | Legitimate internal IT announcement | LEGITIMATE | HIGH | Internal origin (exchange-hub, 10.10.1.15); full authentication pass for meddefense.com; consistent with IT policy; states IT never emails password links |
| E5 | Targeted invoice fraud / BEC variant | PHISHING-TARGETED | HIGH | SPF softfail, no DKIM, DMARC fail; $24,716.38 fabricated invoice; PDF generated by wkhtmltopdf 0.12.6 one second before send; embedded payment link mirrors body link |
| E6 | Unsolicited pharmaceutical spam | SPAM | HIGH | Gateway spam score 9.8; drug-related content tests; raw-IP link; XPedia bulk mailer; completely divergent from campaign fingerprint |
| E7 | Targeted credential phishing (HR benefits impersonation) | PHISHING-TARGETED | HIGH | Lookalike domain meddefense-benefits[.]org; total authentication failure; false enrollment premise (recipient never enrolled); "closes TOMORROW" urgency |
| E8 | Legitimate HC3 sector threat advisory | LEGITIMATE | HIGH | Authentic hhs.gov origin with valid SPF/DKIM (selector hhs2026); TLS1.3 relay; proper TLP:CLEAR marking; content independently matches observed campaign |

---

## 4. Campaign Analysis

**Why E2, E5, and E7 are connected:** Three independent evidence families link these emails to a single operator. First, tooling: all three carry the identical PHPMailer 6.6.0 X-Mailer signature, the same PHP-{hex} Message-ID format, and the same localhost (127.0.0.1) injection hop in their Received chains — a fingerprint unlikely to arise by coincidence across independent attackers. Second, infrastructure design: each domain co-locates its mail server with its phishing web content on a single disposable host (budget VPS profile), and each domain is a lookalike construct using brand or functional keywords (portal, supplies, benefits). Third, tradecraft: all three use urgency deadlines with threatened consequences (24 hours, 7 days, midnight), personalized delivery to named staff, and lures calibrated to each recipient's department — clinical, Accounts Payable, and HR respectively. The targeting map shows deliberate segmentation of MedDefense's workforce; the timing map shows staged waves over 57 hours (April 14, then April 11:28 and 15:22 on April 16), consistent with pacing deliveries rather than a single blast.

**How E8 supports the hypothesis:** The HC3 advisory, received 2026-04-16 from authenticated hhs.gov infrastructure, describes a regional healthcare phishing campaign with four observable patterns: newly-registered keyword domains (portal, benefits, supplies, login), PHPMailer-based sending on budget VPS hosting, urgency-based social engineering with lockout and enrollment cutoffs, and role-targeted lures for clinical, billing, and HR staff. Every one of the four patterns has a direct match in the MedDefense evidence, providing independent third-party corroboration that these are not isolated incidents. Critically, HC3 states no IOCs have been submitted yet, meaning MedDefense may be the first organization in a position to report this campaign.

**How E3 should be interpreted:** E3 is the campaign's outlier and deserves separate treatment. Unlike E2/E5/E7, it passes SPF, DKIM, and DMARC — but only because the attacker registered outlook-protection[.]com and properly configured authentication for their own domain. Passing authentication proves control of that domain, not any affiliation with Microsoft (microsoft.com or outlook.com). E3's link to the campaign rests on the shared PHPMailer 6.6.0 fingerprint, identical Message-ID construction, urgency pretext, and the wp-admin origin hostname echoing E7's wp-portal host. It represents a deliberate diversification within the same operation: a generic Microsoft-365 lure cast alongside the MedDefense-specific lures. Its lesson for defenders is that authentication results cannot be read as proof of legitimacy — the From display name and the actual domain must both be evaluated.

---

## 5. Click Incident Assessment

**What is known from the evidence batch alone:** Diane Marsh, clinical staff on workstation WS-NURSE-04 (10.10.2.15), received the E2 portal phishing email at 14:47:52 CDT on 2026-04-14 and clicked its link at 15:02:33 CDT — approximately 15 minutes later. The URL (hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1) embedded her username and a unique tracking token, meaning the attacker can attribute the visit to her specifically. The harvesting page itself impersonated a MedDefense security re-verification flow, and the legitimate internal announcement (E4, delivered the next day) confirms the real password portal is reachable only from the internal network — the link she clicked could never have led anywhere genuine.

**What cannot be concluded from the batch alone:** Whether Diane entered credentials on the harvesting form, whether any payload was delivered to her browser, whether her account has since been accessed by the attacker, and whether other staff clicked the same or related links without reporting. All of these require proxy, DNS, endpoint, and authentication logs that fall outside this evidence batch. The absence of confirmation is not absence of risk — the 36-hour window between click and investigation must be treated as an open exposure period.

**Recommended safe next actions (per report 7):** Force an immediate password reset through a verified channel (in-person or helpdesk-mediated, not email); revoke all active sessions and MFA tokens for the account; review registered MFA devices; interview Diane non-punitively about what she saw and entered after the click; search retrospective logs for anomalous authentications, inbox rules, and EHR access under her account; retain WS-NURSE-04 for forensic review if compromise is confirmed; monitor the account with heightened alerting for 30 days.

---

## 6. IOC Summary

All indicators defanged. Full quality-rated list in report 11; items below are the high-confidence core.

**Domains (4):**
- meddefense-portal[.]com (E2 — confirmed click target)
- outlook-protection[.]com (E3)
- medequip-supplies[.]net (E5)
- meddefense-benefits[.]org (E7)

**Sending IPs (4):**
- 91[.]234[.]99[.]107 (meddefense-portal[.]com)
- 51[.]38[.]42[.]17 (outlook-protection[.]com)
- 185[.]176[.]43[.]22 (medequip-supplies[.]net)
- 164[.]90[.]218[.]73 (meddefense-benefits[.]org)

**Harvesting / payment URLs (5):**
- hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 (clicked)
- hxxps://outlook-protection[.]com/verify
- hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
- hxxps://medequip-supplies[.]net/portal/login
- hxxps://meddefense-benefits[.]org/enroll

**Sender addresses (4):**
- noreply@meddefense-portal[.]com (Reply-To: no-reply@)
- security@outlook-protection[.]com
- invoices@medequip-supplies[.]net (Reply-To: billing@)
- hr-notifications@meddefense-benefits[.]org (Reply-To: no-reply@)

**File artifact (1):**
- INV-2026-04891.pdf — producer wkhtmltopdf 0.12.6, created 1 second before send, embedded payment URI identical to body link. Declared SHA-256 visible in content (2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f) requires recomputation from the extracted sample before external submission.

**Correlation notes for HC3 (TLP:CLEAR):** All four domains used PHPMailer 6.6.0 with PHP-{hex} Message-ID format and localhost injection hops; mail/web co-location on each domain; role-targeted lures with 24-hour-to-7-day urgency deadlines; delivery window 2026-04-14 through 2026-04-16; wp-admin/wp-portal hostnames on E3/E7 origin servers; matches all four preliminary patterns of HC3-2026-PRELIM-001.

---

## 7. Detection and Control Gaps

**What existing controls did not prevent:**
- The mail gateway allowed three of the four phishing emails (E2, E5, E7) through to user mailboxes despite total SPF/DKIM/DMARC authentication failure — DMARC action=none meant failures were accepted, not rejected. Only E6's louder spam profile triggered quarantine.
- No lookalike-domain detection existed: meddefense-portal[.]com and meddefense-benefits[.]org reached clinical and billing staff unchallenged.
- No alert fired when Diane clicked the harvesting URL; the click was discovered through user reporting to the helpdesk, not tooling. The single most consequential event of the campaign was invisible to SOC instrumentation.
- No monitoring of newly-registered keyword domains despite this being a known and widely published campaign pattern (E8 confirmed the same day the later lures arrived).
- The ~53 hours between click and investigation start reflect both user reporting latency (Diane did not report her click) and triage latency; the campaign was partly detected only because HC3 happened to publish an advisory.

**What should be improved (from report 12):**
- Email gateway: brand lookalike domain matching against internal names; quarantine (not mere acceptance) of authentication triple-failures from external senders; PHPMailer-plus-context correlation rules; invoice-pretext attachment scanning for embedded payment URIs.
- DNS and web filtering: alerting on workstation DNS resolution of known and newly-registered suspicious domains; URL inspection for harvesting patterns (verify/login paths with per-victim id/token parameters).
- Endpoint/browser: browser history and process monitoring on workstations correlated with click reports.
- Threat intelligence: IOC blocklists propagated from this investigation to all gateways and DNS resolvers, and subscription to newly-registered-domain and certificate-transparency feeds for MedDefense brand permutations.

---

## 8. Recommendations

**Immediate (next 24 hours):**
1. Force password reset, session revocation, and MFA re-registration for dmarsh via verified channel; interview Diane regarding post-click interaction
2. Blocklist the four campaign domains, four sending IPs, and five harvesting URLs at mail gateway, DNS, and proxy layers
3. Notify Accounts Payable and finance leadership of the fraudulent invoice (INV-2026-04891, $24,716.38) and verify no payment has been initiated; block the invoice pattern at gateway
4. Verify no interaction with the E3 link by Rafael Mendez; review his M365 sign-in logs post-delivery
5. Preserve all evidence under chain of custody; retain the click record and raw batch
6. Draft and submit IOCs to the HC3 portal per advisory HC3-2026-PRELIM-001 (coordinate through the ISAC liaison), positioning MedDefense as a first reporter of the campaign

**Short-term (next 7 days):**
1. Retrieve and review proxy, DNS, endpoint, and authentication logs for WS-NURSE-04 and all recipients covering 2026-04-14 onward; apply the decision matrix from report 7 to classify the incident (no compromise / possible exposure / confirmed compromise)
2. Pull EHR audit trails for dmarsh's account from the click time forward; assess any HIPAA exposure with the compliance/privacy officer
3. Search DNS and proxy logs for ALL internal hosts resolving the four campaign domains — identifying any unreported clicks across the organization (Sarah Park's concern)
4. Broadcast a non-punitive staff awareness notice describing the campaign's lookalike-domain and urgency patterns (protecting the victim's identity), reinforcing E4's own guidance that IT never emails password-change links
5. Implement email gateway detection improvements from report 12: lookalike domain matching and authentication-failure quarantine

**Medium-term (next 30 days):**
1. Move MedDefense DMARC policy to p=reject for meddefense.com; pair with lookalike-domain monitoring since authentication alone would not have stopped E3 or attacker-owned lookalikes
2. Deploy the full detection suite from report 12 across email gateway, DNS, proxy, and endpoint telemetry, with special attention to per-victim-parameter harvesting URLs
3. Subscribe to newly-registered-domain and certificate-transparency monitoring for defensive registrations around the MedDefense brand
4. Verify proxy and DNS log retention supports at least 90-day retrospective investigation, with URL-parameter-level searchability (token values)
5. Conduct targeted phishing-awareness refresh for clinical, AP, and HR staff — the three roles the campaign specifically targeted — including a one-click report button rollout and same-day SOC triage commitment for high-risk lures
6. Establish recurring review of HC3 advisories as standing SOC intake, so the next regional campaign is detected from threat intel rather than from a victim's click

================================================================================
