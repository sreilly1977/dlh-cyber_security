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
2. Relayed from mail.meddefense-portal.com (91.234.99.107) to mx01.meddefense.com over plain ESMTP (no TLS) — Mon, 14 Apr 2026 14:47:51 -0500
3. Accepted by inbound-relay.meddefense.com from mx01.meddefense.com (10.10.1.20) for dmarsh@meddefense.com — Mon, 14 Apr 2026 14:47:52 -0500

### Anomalies

- [HIGH] Authentication triple-failure: spf=fail (91.234.99.107 not authorized for meddefense-portal.com), dkim=none, dmarc=fail
- [HIGH] Display name/domain mismatch: "MedDefense IT Security" display name paired with hyphenated lookalike domain (meddefense-portal.com ≠ meddefense.com)
- [MEDIUM] Reply-To discrepancy: From shows noreply@meddefense-portal.com but Reply-To shows no-reply@meddefense-portal.com (hyphen variation)
- [MEDIUM] Message-ID format: PHP-{hex}@domain pattern indicates scripted PHPMailer generation rather than enterprise MTA
- [MEDIUM] No TLS on origin hop: plain ESMTP from 91.234.99.107 without TLS negotiation marker

### Conclusion

Header evidence shows complete authentication failure across SPF/DKIM/DMARC, with display name asserting MedDefense identity while the domain lacks cryptographic proof of legitimacy. PHPMailer fingerprint and PHP-style Message-ID suggest automated sending infrastructure rather than managed corporate mail system.

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

- [HIGH] Display name/domain mismatch: "Microsoft Account Protection" display name paired with third-party domain (outlook-protection.com NOT owned by Microsoft)
- [HIGH] SPF/DKIM/DMARC pass for deceptive domain: Authentication validates sender controls outlook-protection.com, not any Microsoft affiliation
- [HIGH] Message-ID format: PHP-{hex}@domain pattern identical to E2, suggesting common PHPMailer infrastructure
- [MEDIUM] No X-Mailer version differentiation: Same PHPMailer 6.6.0 version string as E2, E5, E7

### Conclusion

Header evidence demonstrates brand impersonation through display name claiming Microsoft authority while originating from independent third-party domain. Authentication passing for the spoofed domain confirms attacker infrastructure control, not message authenticity. PHPMailer fingerprint aligns with other suspicious emails in batch.

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

- [HIGH] SPF softfail: spf=softfail indicates 185.176.43.22 not in medequip-supplies.net authorized sender list
- [HIGH] DKIM absent: dkim=none (message not signed)
- [HIGH] DMARC failure: dmarc=fail action=none consequence of SPF softfail and missing DKIM
- [MEDIUM] Message-ID format: PHP-{hex}@domain pattern matching E2, E3, E7
- [MEDIUM] No TLS on origin hop: plain ESMTP from 185.176.43.22 without TLS negotiation marker

### Conclusion

Header evidence reveals authentication gaps across all three mechanisms (SPF softfail, no DKIM signature, DMARC fail). The third-party domain claims billing authority without cryptographic validation. PHPMailer fingerprint consistent with other suspicious emails suggests common infrastructure source.

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
- [HIGH] Domain structure anomaly: Hyphenated domain (meddefense-benefits.org) mimics legitimate org structure while lacking cryptographic authorization
- [MEDIUM] Reply-To discrepancy: From hr-notifications@ but Reply-To no-reply@ (hyphen variation)
- [MEDIUM] Message-ID format: PHP-{hex}@domain pattern identical to E2, E3, E5
- [MEDIUM] No TLS on origin hop: plain ESMTP from 164.90.218.73 without TLS negotiation marker

### Conclusion

Header evidence shows complete authentication failure with hyphenated lookalike domain structure failing SPF authorization. Display name asserts MedDefense HR authority without domain-level cryptographic validation. PHPMailer fingerprint matches suspicious cluster.

================================================================================

## Cross-Email Infrastructure Correlation

| Metric | E2 | E3 | E5 | E7 |
|--------|-----|-----|-----|-----|
| X-Mailer | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 | PHPMailer 6.6.0 |
| TLS on Origin Hop | No | Yes (TLS1.2) | No | No |
| SPF Result | fail | pass | softfail | fail |
| DKIM Result | none | pass | none | none |
| DMARC Result | fail | pass | fail | fail |
| Message-ID Pattern | PHP-{hex}@domain | PHP-{hex}@domain | PHP-{hex}@domain | PHP-{hex}@domain |

### Infrastructure Assessment

All four suspicious emails share identical PHPMailer 6.6.0 X-Mailer signatures and PHP-generated Message-ID formats ({hex} hash pattern). Three of four use unencrypted ESMTP on the origin-to-MX relay hop (E2, E5, E7). This uniformity in sending stack and authentication posture supports correlated infrastructure origin rather than independent spam sources.

================================================================================
