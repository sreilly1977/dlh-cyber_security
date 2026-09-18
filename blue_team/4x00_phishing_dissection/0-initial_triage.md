**0-initial_triage.md**
**Name:** Initial Email Triage
**Purpose:** Rapid classification of 8-email evidence batch into SPAM/SUSPICIOUS/LEGITIMATE categories
**Author:** Steve - Cybersecurity Engineer
**Date:** 18 September 2026

================================================================================
MEDDEFENSE HEALTH SYSTEMS — INITIAL EMAIL TRIAGE
================================================================================

| Email | From | Subject | SPF | DKIM | DMARC | Class | Priority | Evidence |
|-------|------|---------|-----|------|-------|-------|----------|----------|
| E1 | newsletter@healthcare-education-weekly.com | Your April newsletter: Medication reconciliation best practices | pass | pass | pass | LEGITIMATE | P4-LOW | MailChimp infrastructure, valid subscription record (2024-08-11), working unsubscribe links, TLS-encrypted relay, no urgency indicators |
| E2 | noreply@meddefense-portal.com | ACTION REQUIRED: Portal re-verification needed within 24 hours | fail | none | fail | SUSPICIOUS | P1-URGENT | Lookalike domain (meddefense-portal.com ≠ meddefense.com), all auth failures, 24-hour deadline urgency, Diane Marsh confirmed clicking link at 2026-04-14 15:02:33 CDT |
| E3 | security@outlook-protection.com | Unusual sign-in activity detected on your Microsoft 365 account | pass | pass | pass | SUSPICIOUS | P2-HIGH | Brand impersonation (outlook-protection.com is NOT Microsoft domain), 48-hour lockout threat, credential harvesting URL, matches HC3 campaign pattern despite passing auth for its own domain |
| E4 | it-announcements@meddefense.com | Reminder: Quarterly password change window opens April 20 | pass | pass | pass | LEGITIMATE | P4-LOW | Internal sender (10.10.1.15 exchange-hub.meddefense.local), Exchange Server 2019, proper DKIM signature for meddefense.com, no external links, instructs users IT will NOT email password links |
| E5 | invoices@medequip-supplies.net | Invoice INV-2026-04891 — Payment required within 7 days | softfail | none | fail | SUSPICIOUS | P2-HIGH | Auth failures (spf=softfail, dmarc=fail), unsolicited large-dollar invoice ($24,716.38), PDF attachment with embedded payment portal link, 7-day payment deadline urgency |
| E6 | deals@canadian-pharma-discount.org | 90% OFF Viagra, Cialis, Xanax — No prescription needed!!! | softfail | none | fail | SPAM | P4-LOW | X-Spam-Score 9.8 (threshold 5.0), DRUGS_ERECTILE test flagged, numeric IP link (203.0.113.228), explicit spam characteristics, already quarantined by gateway |
| E7 | hr-notifications@meddefense-benefits.org | Open Enrollment closes TOMORROW — action required | fail | none | fail | SUSPICIOUS | P2-HIGH | Lookalike domain (meddefense-benefits.org ≠ meddefense.com), all auth failures, TOMORROW deadline urgency, recipient (Linda Patterson) confirmed never enrolled, matches HC3 HR-lure pattern |
| E8 | HC3@hhs.gov | [HC3 ALERT — TLP:CLEAR] Active phishing campaign targeting regional healthcare | pass | pass | pass | LEGITIMATE | P3-MEDIUM | Official hhs.gov domain with valid DKIM/SPF, authenticated HHS Secure Mail Gateway, TLP:CLEAR marking, contextual threat intel from HC3 (not campaign itself) |

================================================================================
## Triage Summary

- **SPAM:** 1 (E6 - pharmaceutical spam, obvious noise, already quarantined)
- **SUSPICIOUS:** 4 (E2, E3, E5, E7 - potential phishing campaign with role-targeted lures)
- **LEGITIMATE:** 3 (E1, E4, E8 - verified subscriber, internal comms, authentic threat intel)

- **Highest priority:** E2 (P1-URGENT) — Diane Marsh clicked malicious link 36 hours prior to investigation; potential credential compromise requires immediate follow-up investigation
- **Campaign correlation indicator:** E2, E3, E5, and E7 all share PHPMailer 6.6.0 sending stack, auth failures (or brand impersonation for E3), and urgency-based social engineering consistent with HC3 preliminary advisory pattern

================================================================================
