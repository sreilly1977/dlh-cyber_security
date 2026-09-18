# 1-header_analysis.md

**Name:** Header Analysis of Suspicious Emails

**Purpose:** Parse SMTP header chains for E2, E3, E5, E7 to identify true origin,
          routing indicators, and header anomalies supporting suspicion

**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — HEADER ANALYSIS

Analysis targets: E2, E3, E5, E7 (identified as SUSPICIOUS during initial triage)

Evidence source: Email evidence batch only (collected 2026-04-17 by Mike Torres)

================================================================================

## Email 2 — meddefense-portal.com

### Header Evidence

- From: "MedDefense IT Security" <noreply@meddefense-portal.com>
- Return-Path: <noreply@meddefense-portal.com>
- Sending IP: 91.234.99.107 (mail.meddefense-portal.com)
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-5D7E2F4A@meddefense-portal.com>

### Received Chain Summary

1. Generated locally at mail.meddefense-portal.com by PHPMailer 6.6.0 via localhost (127.0.0.1) — Mon, 14 Apr 2026 19:47:48 +0000
2. Relayed from mail.meddefense-portal.com (91.234.99.107) to mx01.meddefense.com over plain ESMTP (no TLS advertised on this hop) — Mon, 14 Apr 2026 14:47:51 -0500
3. Accepted by inbound-relay.meddefense.com from mx01.meddefense.com (10.10.1.20) for dmarsh@meddefense.com — Mon, 14 Apr 2026 14:47:52 -0500

### Anomalies

- [HIGH] Authentication triple-failure: spf=fail (91.234.99.107 not authorized for meddefense-portal.com), dkim=none, dmarc=fail — the sender cannot cryptographically prove ownership of its own domain
- [HIGH] Domain deception: Display name "MedDefense IT Security" paired with meddefense-portal.com (hyphen-append lookalike of meddefense.com); display name asserts IT authority the domain cannot substantiate
- [MEDIUM] Reply-To mismatch: From shows noreply@meddefense-portal.com but Reply-To shows no-reply@meddefense-portal.com — cosmetic inconsistency typical of templated phishing kits
- [MEDIUM] Message-ID format: "PHP-5D7E2F4A@meddefense-portal.com" — PHPMailer-generated ID indicating scripted mass sending rather than managed corporate mail platform
- [MEDIUM] No TLS on origin-to-MX hop: relay from 91.234.99.107 used plain ESMTP (no TLS marker), unlike legitimate high-volume senders E1/E8 which negotiated ESMTPS with TLS1.3
- [HIGH] Clicked by victim: Evidence states Diane Marsh (WS-NURSE-04, 10.10.2.15) clicked this email at 2026-04-14 15:02:33 CDT (~15 minutes after receipt)

### Conclusion

E2 exhibits classic phishing characteristics: authentication failure across all three mechanisms (SPF/DKIM/DMARC), lookalike domain impersonation of MedDefense's legitimate portal, urgency-based social engineering ("24 hours"), and PHPMailer infrastructure typical of budget VPS sending setups. The confirmed user click elevates this to active credential harvesting incident.

================================================================================

## Email 3 — outlook-protection.com

### Header Evidence

- From: "Microsoft Account Protection" <security@outlook-protection.com>
- Return-Path: <security@outlook-protection.com>
- Sending IP: 51.38.42.17 (mail.outlook-protection.com)
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-9F2D7E1B@outlook-protection.com>

### Received Chain Summary

1. Generated locally at wp-admin.outlook-protection.com by PHPMailer 6.6.0 via localhost (127.0.0.1) — Tue, 15 Apr 2026 14:13:40 +0000
2. Relayed from mail.outlook-protection.com (51.38.42.17) to mx01.meddefense.com with ESMTPS (TLS1.2) — Tue, 15 Apr 2026 09:13:43 -0500
3. Accepted by inbound-relay.meddefense.com from mx01.meddefense.com (10.10.1.20) for rmendez@meddefense.com — Tue, 15 Apr 2026 09:13:44 -0500

### Anomalies

- [CRITICAL] Brand impersonation: Claims to be Microsoft Account Protection but originates from outlook-protection.com (third-party domain), NOT microsoft.com, outlook.com, or live.com domains
- [HIGH] SPF/DKIM/DMARC pass for wrong entity: Authentication validates that the email legitimately came FROM outlook-protection.com, NOT that it represents Microsoft — passing auth on a deceptive domain is not legitimacy
- [HIGH] Message-ID format: "PHP-9F2D7E1B@outlook-protection.com" — identical PHPMailer signature to E2, suggesting same sending infrastructure cluster
- [HIGH] Urgency pretext: 48-hour account lockout threat mirrors HC3 advisory pattern ("24-48 hour deadlines, account lockout threats")
- [MEDIUM] Fake logo hotlinking: MS logo hosted at https://outlook-protection.com/img/ms_logo.png — attacker-hosted stolen asset rather than official Microsoft CDN
- [MEDIUM] Geographic baiting: Claims sign-in from Lagos, Nigeria (IP 41.203.72.188) — common scare tactic to induce panic response

### Conclusion

E3 is a brand impersonation attack targeting Microsoft 365 credentials. While SPF/DKIM/DMARC technically pass for the sending domain, this validates the attacker's control of outlook-protection.com, not any affiliation with Microsoft. The PHPMailer fingerprint matches E2, suggesting coordination. This fits HC3's "credential harvesting using lookalike domains" pattern precisely.

================================================================================

## Email 5 — medequip-supplies.net

### Header Evidence

- From: "MedEquip Supplies Billing" <invoices@medequip-supplies.net>
- Return-Path: <invoices@medequip-supplies.net>
- Sending IP: 185.176.43.22 (mail.medequip-supplies.net)
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-7C2D4E1A@medequip-supplies.net>

### Received Chain Summary

1. Generated locally at billing-svc.medequip-supplies.net by PHPMailer 6.6.0 via localhost (127.0.0.1) — Wed, 16 Apr 2026 16:28:35 +0000
2. Relayed from mail.medequip-supplies.net (185.176.43.22) to mx01.meddefense.com over plain ESMTP (no TLS) — Wed, 16 Apr 2026 11:28:37 -0500
3. Accepted by inbound-relay.meddefense.com from mx01.meddefense.com (10.10.1.20) for arivera@meddefense.com — Wed, 16 Apr 2026 11:28:39 -0500

### Anomalies

- [HIGH] SPF softfail: spf=softfail indicates sender IP 185.176.43.22 is NOT in medequip-supplies.net's authorized SPF record; DMARC fails as consequence
- [HIGH] DKIM missing: dkim=none (message not signed) — legitimate business invoicing typically signs messages to establish trust
- [MEDIUM] Third-party PHPMailer stack: Same PHPMailer 6.6.0 fingerprint as E2, E3, E7 — unlikely for a legitimate medical supplies vendor's billing infrastructure
- [MEDIUM] Large-dollar unsolicited invoice: $24,716.38 with 7-day payment deadline creates financial urgency without prior purchase order verification
- [MEDIUM] PDF attachment with embedded link: INV-2026-04891.pdf contains annotation action pointing to https://medequip-supplies.net/invoices/pay — attachment + redirect pattern bypasses initial email-link inspection
- [HIGH] Recipient report: Angela Rivera in AP explicitly flagged "the invoice looks wrong" — business verification failure

### Conclusion

E5 follows BEC (Business Email Compromise) / invoice fraud patterns: unsolicited high-value invoice, authentication gaps, PHPMailer infrastructure inconsistent with professional billing systems, and dual-channel delivery (email + attachment) to evade link scanning. Matches HC3 advisory observation of "supplies" in hostname for supplier-spoofing campaigns.

================================================================================

## Email 7 — meddefense-benefits.org

### Header Evidence

- From: "MedDefense HR Benefits" <hr-notifications@meddefense-benefits.org>
- Return-Path: <hr-notifications@meddefense-benefits.org>
- Sending IP: 164.90.218.73 (mail.meddefense-benefits.org)
- X-Mailer: PHPMailer 6.6.0 (https://github.com/PHPMailer/PHPMailer)
- Message-ID: <PHP-2E4A7B1C@meddefense-benefits.org>

### Received Chain Summary

1. Generated locally at wp-portal.meddefense-benefits.org by PHPMailer 6.6.0 via localhost (127.0.0.1) — Thu, 16 Apr 2026 20:22:02 +0000
2. Relayed from mail.meddefense-benefits.org (164.90.218.73) to mx01.meddefense.com over plain ESMTP — Thu, 16 Apr 2026 15:22:05 -0500
3. Accepted by inbound-relay.meddefense.com from mx01.meddefense.com (10.10.1.20) for lpatterson@meddefense.com — Thu, 16 Apr 2026 15:22:07 -0500

### Anomalies

- [HIGH] Authentication triple-failure: spf=fail (164.90.218.73 not authorized for meddefense-benefits.org), dkim=none, dmarc=fail
- [HIGH] Domain spoofing: meddefense-benefits.org (hyphenated .org) mimics MedDefense's internal HR/benefits communications; actual MedDefense domain is meddefense.com
- [CRITICAL] Recipient confirmation: Linda Patterson in Billing stated "she never signed up for anything" — direct user verification of fraudulent nature
- [HIGH] Urgency social engineering: "TOMORROW", "closes at midnight" language creating artificial deadline pressure
- [MEDIUM] PHPMailer fingerprint consistency: Matches E2, E3, E5 exactly (version 6.6.0) — strong correlation indicator for coordinated campaign
- [MEDIUM] No TLS on origin-to-MX hop: Plain ESMTP from 164.90.218.73, matching pattern seen in E2 and E5
- [MEDIUM] Reply-To mismatch: From hr-notifications@ but Reply-To no-reply@ same domain — templated kit artifact

### Conclusion

E7 is a clear HR benefits impersonation attack exploiting open enrollment pretexts. The authentication failures, lookalike domain structure, PHPMailer infrastructure, and direct recipient denial confirm malicious intent. This maps directly to HC3's observed "benefits" keyword pattern and HR-targeted role lures.

================================================================================

## Cross-Email Infrastructure Correlation

| Metric | E2 | E3 | E5 | E7 |
|--------|-----|-----|-----|-----|
| X-Mailer | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 |
| TLS on Origin Hop | No | Yes (TLS1.2) | No | No |
| SPF Result | fail | pass* | softfail | fail |
| DKIM Result | none | pass* | none | none |
| DMARC Result | fail | pass* | fail | fail |
| Message-ID Format | PHP-{hex}@domain | PHP-{hex}@domain | PHP-{hex}@domain | PHP-{hex}@domain |

*Note: E3 passes authentication for outlook-protection.com, which is NOT a Microsoft-owned domain — this validates the attacker controls their spoofed domain, not that the message is authentic Microsoft correspondence.

### Campaign Attribution Assessment

All four suspicious emails share identical PHPMailer 6.6.0 fingerprints, suggesting deployment from a single or tightly clustered infrastructure. Three of four (E2, E5, E7) use unencrypted relays from budget VPS-style IPs. Four of four employ urgency-based social engineering pretexts aligned with HC3's advisory patterns. This supports James Chen's hypothesis of a coordinated campaign rather than random spam.

================================================================================
End of header analysis document
