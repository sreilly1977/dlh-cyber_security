# 12-detection_recommendations.md

**Name:** Detection Recommendations

**Purpose:** Convert investigation findings into practical, vendor-neutral detection
          recommendations for SIEM, email gateway, DNS, endpoint and threat intel
          platforms

**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — DETECTION RECOMMENDATIONS

Evidence basis: Investigation reports 0-11, campaign infrastructure analysis (E2,

E3, E5, E7), HC3 advisory patterns (E8). No live SIEM, IDS, Wazuh, Suricata, or

endpoint deployment was required or performed. All recommendations are expressed

as vendor-neutral logic suitable for adaptation to any security platform.

================================================================================

## 1. Detection Opportunities

### Detection 1 — Lookalike Domain Matching Against Internal Brand Names

**Detection name:** BRAND_LOOKALIKE_DOMAIN_INBOUND_MAIL

**Data source needed:** Email gateway headers (From domain, Reply-To, Return-Path, Message-ID domain)

**Example logic (pseudocode):**
```
WHEN email_received AND
     (
       FROM_domain CONTAINS "meddefense" AND
       FROM_domain != "meddefense.com" AND
       FROM_domain NOT MATCHES "*.meddefense.com"
     ) OR
     (
       FROM_domain MATCHES "(portal|benefits|supplies|login)-?meddefense.*" OR
       FROM_domain MATCHES "meddefense-(portal|benefits|supplies|login).*"
     )
THEN trigger_alert
  severity = HIGH
  context = "External email from brand-mimicking lookalike domain"
```

**Expected match from evidence batch:**
- E2: meddefense-portal[.]com (contains "meddefense" but not *.meddefense.com)
- E5: medequip-supplies[.]net (contains "supplies" keyword, not exact brand match but pattern-adjacent)
- E7: meddefense-benefits[.]org (hyphenated .org variant)

**Severity:** HIGH

**False-positive considerations:** Subdomains like help.meddefense.com, portal.meddefense.com are legitimate; the rule explicitly excludes wildcard *.meddefense.com matches. Legitimate third-party vendors using "meddefense" in their business name should be whitelisted after verification. This rule flags EXTERNAL domains only, never internal subdomains.

**Recommended response action:** Quarantine the message, escalate to SOC analyst for manual review, block the sending domain at gateway level upon confirmation.

---

### Detection 2 — SPF/DKIM/DMARC Triple-Failure on External Senders

**Detection name:** AUTH_FAILURE_TRIPLE_EXTERNAL_SENDER

**Data source needed:** Email gateway Authentication-Results header (SPF result, DKIM result, DMARC result/action)

**Example logic (pseudocode):**
```
WHEN email_received AND
     FROM_domain DOES_NOT_CONTAIN "meddefense.com" AND
     AuthenticationResults SPF == "fail" OR "softfail" AND
     AuthenticationResults DKIM == "none" AND
     AuthenticationResults DMARC == "fail"
THEN trigger_alert
  severity = HIGH
  context = "External email with no valid authentication on any mechanism"
```

**Expected match from evidence batch:**
- E2: spf=fail, dkim=none, dmarc=fail
- E5: spf=softfail, dkim=none, dmarc=fail
- E7: spf=fail, dkim=none, dmarc=fail

Note: E3 would NOT match (it passes all three), which is intentional — E3's risk comes from brand impersonation despite passing auth, not from auth failure itself.

**Severity:** HIGH

**False-positive considerations:** Some legitimate bulk senders misconfigure SPF/DKIM temporarily during migrations. The rule should not auto-quarantine; alert for analyst review. If combined with Detection 1 (lookalike domain) in the same message, confidence increases significantly.

**Recommended response action:** Log alert, add sender domain to watchlist, increase mail gateway spam score for future messages from same domain.

---

### Detection 3 — PHPMailer Fingerprint in External Email Headers

**Detection name:** PHPMAILER_FINGERPRINT_EXTERNAL_SENDER

**Data source needed:** Email gateway X-Mailer and Message-ID headers, plus FROM domain analysis

**Example logic (pseudocode):**
```
WHEN email_received AND
     X-Mailer CONTAINS "PHPMailer" AND
     Message-ID MATCHES "PHP-[A-Z0-9]+@" AND
     FROM_domain DOES_NOT_MATCH "*.meddefense.com" AND
     FROM_domain != "hhs.gov" AND
     FROM_domain != "healthcare-education-weekly.com"
THEN trigger_alert
  severity = MEDIUM
  context = "External email using PHPMailer script stack"

  IF (FROM_domain CONTAINS "meddefense" OR
      FROM_domain CONTAINS "portal" OR
      FROM_domain CONTAINS "benefits" OR
      FROM_domain CONTAINS "supplies")
  THEN upgrade_severity = HIGH
```

**Expected match from evidence batch:**
- E2: X-Mailer "PHPMailer 6.6.0", Message-ID "PHP-5D7E2F4A@meddefense-portal.com"
- E3: X-Mailer "PHPMailer 6.6.0", Message-ID "PHP-9F2D7E1B@outlook-protection.com"
- E5: X-Mailer "PHPMailer 6.6.0", Message-ID "PHP-7C2D4E1A@medequip-supplies.net"
- E7: X-Mailer "PHPMailer 6.6.0", Message-ID "PHP-2E4A7B1C@meddefense-benefits.org"

E1 would NOT match because MailChimp uses its own X-Mailer signature. E4 would NOT match because Exchange Server 2019 generates different headers.

**Severity:** MEDIUM (upgrade to HIGH if combined with brand keywords or lookalike domain)

**False-positive considerations:** PHPMailer is used by thousands of legitimate applications (CMS systems, newsletters, transactional emails). Never block PHPMailer globally. Use as a correlation signal combined with domain reputation, lookalike matching, or authentication failure. This detection is valuable primarily as a CAMPAIGN CORRELATION rule, not a standalone block trigger.

**Recommended response action:** Add to alert context, use as correlation input for Detection 1 or Detection 2, do not block solely on PHPMailer presence.

---

### Detection 4 — DNS Query to Phishing Domains from Workstations

**Detection name:** DNS_QUERY_PHISHING_DOMAIN_WORKSTATION

**Data source needed:** Internal DNS resolver logs or proxy/web gateway DNS request logs

**Example logic (pseudocode):**
```
WHEN dns_query AND
     QUERY_domain IN (phishing_domain_list) AND
     CLIENT_IP IN (workstation_subnet_range) AND
     QUERIED_TIMESTAMP WITHIN 7_days_of_domain_registration OR
     (domain_age < 30_days_from_RDAP_check)
THEN trigger_alert
  severity = HIGH
  context = "Workstation resolved known phishing domain or newly-registered suspicious domain"

  IF CLIENT_IP == WORKSTATION_WITH_RECENT_USER_CLICK_REPORT
  THEN upgrade_severity = CRITICAL
```

**Expected match from evidence batch:**
- 10.10.2.15 (WS-NURSE-04) resolving meddefense-portal[.]com at approximately 2026-04-14 15:02:30–15:02:33 CDT

**Severity:** HIGH (CRITICAL if correlated with known victim workstation)

**False-positive considerations:** Some legitimate new businesses operate on newly-registered domains. The rule should prioritize known-phishing domains from threat intelligence feeds over age-only triggers. Domain-age alerts are best used in conjunction with content/context analysis (e.g., query for domain that sends urgent financial/credential pretexts).

**Recommended response action:** Alert SOC immediately, cross-reference with proxy logs for HTTP POST to harvesting URL, initiate user interview for that workstation.

---

### Detection 5 — Credential Harvesting URL with Per-Victim Parameters

**Detection name:** HARVESTER_URL_VICTIM_TRACKING_PARAM

**Data source needed:** Web proxy logs, URL inspection at mail gateway, browser extension telemetry

**Example logic (pseudocode):**
```
WHEN http_request AND
     URL_domain IN (phishing_domain_list OR new_domain_flagged_by_detection_4) AND
     URL_PATH MATCHES "/(verify|login|enroll|pay)/" AND
     URL_PARAMETER CONTAINS ("id=" OR "user=" OR "token=" OR "session=") AND
     PARAMETER_VALUE MATCHES "[a-z]+@[a-z]+\.[a-z]+" OR "employee_id_pattern"
THEN trigger_alert
  severity = CRITICAL
  context = "Harvesting URL with per-victim tracking parameters detected"
```

**Expected match from evidence batch:**
- hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
  - Contains id=dmarsh (victim identifier) and token=a8f3e2d1 (per-session tracking)

**Severity:** CRITICAL

**False-positive considerations:** Legitimate single-sign-on flows use URL parameters, but they typically involve internal domains or SSO provider domains (okta.com, azuread.microsoft.com) with established trust. The rule should exclude whitelisted SSO and enterprise application domains. Focus on external, lookalike, or newly-registered domains.

**Recommended response action:** Block request immediately, terminate browser session, alert SOC for incident response, notify user and supervisor of potential compromise.

---

### Detection 6 — Invoice Attachment with Embedded Payment URI

**Detection name:** PDF_ATTACHMENT_EMBEDDED_URI_INVOICE_PRETEXT

**Data source needed:** Email attachment metadata scanners, PDF analysis tools (offline sandbox)

**Example logic (pseudocode):**
```
WHEN email_attachment AND
     Content_Type == "application/pdf" AND
     File_Name MATCHES ".*(INV|invoice|payment|bill).*.pdf" AND
     Attachment_Mail_Pretext CONTAINS ("invoice" OR "payment required" OR "amount due" OR "payment deadline") AND
     PDF_Metadata.Producer MATCHES "(wkhtmltopdf|HTMLDOC|prince)" OR
     PDF_Analysis.Embedded_URI MATCHES "(pay|invoice|login|portal)"
THEN trigger_alert
  severity = HIGH
  context = "Invoice PDF with embedded payment URI generated by HTML converter tool"
```

**Expected match from evidence batch:**
- E5: INV-2026-04891.pdf, producer "wkhtmltopdf 0.12.6", embedded URI hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891

**Severity:** HIGH

**False-positive considerations:** Many legitimate invoices are generated by HTML converters. The key indicator is the COMBINATION of: (1) invoice pretext in email body, (2) PDF producer is wkhtmltopdf or similar HTML renderer, (3) embedded URI pointing to external payment/login portal rather than official vendor portal. Alone, wkhtmltopdf is too noisy.

**Recommended response action:** Quarantine attachment pending sandbox detonation, alert AP/finance recipients, scan extracted URI against threat intelligence feeds.

---

### Detection 7 — Role-Targeted Urgency Pretext Matching

**Detection name:** ROLE_URGENCY_PRETEXT_PATTERN

**Data source needed:** Email content scanning (subject line, body text), recipient department mapping

**Example logic (pseudocode):**
```
WHEN email_received AND
     (
       (Recipient_Department CONTAINS "Clinical" AND Subject_Or_Body CONTAINS "(scheduling|EHR|shift)") OR
       (Recipient_Department CONTAINS "Accounts Payable" AND Subject_Or_Body CONTAINS "(invoice|payment|due)") OR
       (Recipient_Department CONTAINS "HR" AND Subject_Or_Body CONTAINS "(enrollment|benefits|coverage)")
     ) AND
     Urgency_Keyword CONTAINS "(within 24 hours|TOMORROW|midnight|deadline|expires)" AND
     Consequence_Threat CONTAINS "(suspend|lockout|lapse|late fee)"
THEN trigger_alert
  severity = MEDIUM (upgrade to HIGH if combined with Detection 1 or 2)
  context = "Role-appropriate urgency pretext matching campaign pattern"
```

**Expected match from evidence batch:**
- E2: Clinical staff (nurse) + scheduling/EHR/shift keywords + "within 24 hours" + "locked out"
- E5: AP + invoice/payment/amount due + "within 7 days" + "late fee" + "suspension"
- E7: HR/benefits + enrollment/benefits/coverage + "TOMORROW/midnight" + "lapse"

**Severity:** MEDIUM (upgrades to HIGH with other indicators)

**False-positive considerations:** Legitimate IT announcements may reference deadlines (E4 references April 20 password change window). Distinguisher: E4 is INTERNAL domain, has full authentication, no external links, and explicitly warns users not to click email links. External domain + urgency + consequence threat = high risk.

**Recommended response action:** Increase spam score, flag for human review, add recipient to awareness training follow-up queue.

---

### Detection 8 — Threat Intelligence IOC Matching (Static Domain/IP Lists)

**Detection name:** THREAT_INTEL_IOC_MATCH_BLOCKLIST

**Data source needed:** Threat intelligence feeds (HC3 submissions, VirusTotal, commercial TI), mail gateway allow/deny lists, DNS sinkhole lists

**Example logic (pseudocode):**
```
WHEN (email_received OR dns_query OR http_request) AND
     (FROM_domain OR URL_domain OR DESTINATION_IP IN threat_intel_blocklist)
THEN trigger_alert AND execute_preventive_action
  severity = HIGH (automated block)
  context = "Match against known malicious IOC list"
  action = BLOCK (preventive)
```

**Expected match from evidence batch:**
- Domain IOC: meddefense-portal[.]com
- IP IOC: 91[.]234[.]99[.]107
- URL IOC: hxxps://meddefense-portal[.]com/verify/staff?*
- Once IOCs submitted to HC3 and distributed via feeds, all subsequent attempts to reach these indicators would be blocked automatically

**Severity:** HIGH

**False-positive considerations:** Only apply to domains/IPs confirmed malicious by multiple sources or incident investigation. Never block based on a single organization's claim. IOC sharing platforms (HC3, ISAC feeds) provide the vetting layer that prevents false positives.

**Recommended response action:** Automate block/prevention at gateway/firewall/DNS level, no analyst intervention required for known IOCs.

---

## 2. Coverage Across Detection Categories

| Category | Detection Numbers | Brief Description |
|----------|-------------------|-------------------|
| Email gateway | 1, 2, 3, 6, 7 | Lookalike domains, auth failures, PHPMailer fingerprint, invoice attachments, urgency pretexts |
| DNS / web filtering | 4, 5, 8 | New domain queries, harvesting URLs with victim params, IOC blocklists |
| Endpoint / browser activity | 4, 5 | DNS resolution from workstations, browser URL visits with per-victim tracking |
| Threat intelligence / IOC matching | 8 | Domain/IP/URL blocklists from external feeds |

---

## 3. Which Detections Would Have Caught Diane Marsh's E2 Click Earlier

If deployed during the campaign window (2026-04-14 through 2026-04-16), these detections would have intervened at various points:

| Detection Point | When It Would Trigger | Could Prevent Click? |
|-----------------|----------------------|---------------------|
| Detection 1 (lookalike domain) | When E2 entered mail gateway at 2026-04-14 14:47 CDT | YES — could quarantine before reaching Diane's inbox |
| Detection 2 (auth failure) | Same as Detection 1 | YES — could increase spam score leading to quarantine |
| Detection 3 (PHPMailer) | Same as Detection 1, as a secondary correlation signal | SUPPORTIVE — strengthens Detection 1/2 confidence |
| Detection 4 (DNS query) | At 2026-04-14 15:02:33 CDT when DNS resolves meddefense-portal[.]com | PARTIAL — would alert on resolution, but click already occurred; could block subsequent navigation |
| Detection 5 (harvesting URL) | At 2026-04-14 15:02:33 CDT when HTTP request reaches gateway | YES — could block HTTP GET, preventing credential form from loading |
| Detection 7 (urgency pretext) | Same as Detection 1 at mail gateway | SUPPORTIVE — adds to overall risk score |
| Detection 8 (IOC matching) | AFTER IOC submission to HC3 and distribution via feeds | NO — too late for initial click; only prevents subsequent attacks |

Best outcome scenario: Detections 1, 2, 5 combined would have prevented the incident entirely — Detection 1 or 2 blocks/quarantines the email before it reaches the inbox; Detection 5 provides a second-line defense if the email somehow bypasses mail gateway filters and the user clicks anyway.

Worst outcome scenario (no detection): User clicks, submits credentials, attacker gains access — this is the actual historical timeline of E2.

---

## 4. Preventive vs Detective vs Responsive Classification

| Detection | Preventive (stops before harm) | Detective (alerts after occurrence) | Responsive (triggers automated mitigation) |
|-----------|-------------------------------|-------------------------------------|--------------------------------------------|
| Detection 1 | YES (quarantine before delivery) | YES (log alert) | YES (auto-quarantine configured) |
| Detection 2 | YES (raise spam score to quarantine threshold) | YES | CONDITIONAL (depends on admin configuration) |
| Detection 3 | NO | YES (correlation signal) | NO |
| Detection 4 | NO | YES | CONDITIONAL (DNS sinkhole can block resolution) |
| Detection 5 | YES (block HTTP request) | YES | YES (terminate connection) |
| Detection 6 | YES (quarantine attachment) | YES | YES (hold for sandbox analysis) |
| Detection 7 | NO | YES (increase spam score) | CONDITIONAL |
| Detection 8 | YES (automatic block at gateway/DNS) | YES | YES (fully automated) |

Summary: Detections 1, 2, 5, 6 and 8 have strong preventive capability when properly configured to act automatically on known bad indicators (IOCs, lookalike domains, harvesting URLs). Detections 4, 5 and 8 also have responsive capability (blocking or terminating connections). All detections have detective value (logging and alerting).

The optimal layered defense combines:
- **Preventive:** Detection 8 (IOC blocklists) + Detection 1 (lookalike domain matching)
- **Detective:** Detections 2, 3, 4, 7 (signals for correlation and hunting)
- **Responsive:** Detection 5 (URL blocking) + Detection 6 (attachment holding)

This hierarchy ensures that even if preventive controls fail (e.g., E2 arrived before IOCs were known), detective controls provide visibility for retrospective analysis, and responsive controls limit damage from follow-on activity.

================================================================================
