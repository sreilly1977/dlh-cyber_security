# 8-verdict_matrix.md

**Name:** Verdict Matrix

**Purpose:** Produce the final evidence-based classification of all 8 emails,
          replacing the initial rapid triage with definitive verdicts and
          recommended actions
          
**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — FINAL VERDICT MATRIX

Evidence basis: Full investigation chain — initial triage (0), header analysis (1),

authentication analysis (2), social engineering analysis (3), URL/attachment

autopsy (4), attachment analysis (5), IOC correlation (6), click investigation (7).

All conclusions are grounded in the email evidence batch only.

================================================================================

| Email | Initial Class | Final Class | Confidence | Key Evidence | Recommended Action |
|-------|--------------|-------------|------------|--------------|--------------------|
| E1 | LEGITIMATE | LEGITIMATE | HIGH | SPF/DKIM/DMARC all pass; MailChimp infrastructure; subscription record dated 2024-08-11; working unsubscribe with RFC 8058 List-Unsubscribe-Post; TLS-protected relay; content matches declared marketing purpose | No action required. Optionally confirm Jennifer Moore's subscription is policy-approved for the corporate mailbox |
| E2 | SUSPICIOUS | PHISHING-TARGETED | VERY HIGH (confirmed click) | Lookalike domain meddefense-portal[.]com; SPF fail, DKIM none, DMARC fail; PHPMailer 6.6.0; per-victim URL parameters (id=dmarsh, token=a8f3e2d1); 24-hour urgency pretext; nursing-specific system references; CONFIRMED CLICK by Diane Marsh at 2026-04-14 15:02:33 CDT from WS-NURSE-04 (10.10.2.15) | P1 incident response: treat dmarsh account as potentially compromised — password reset, session/MFA revocation, endpoint and authentication log review, user interview (per report 7); blocklist domain and 91.234.99.107; submit IOCs to HC3 |
| E3 | SUSPICIOUS | PHISHING-TARGETED | HIGH | outlook-protection[.]com is not a Microsoft domain (vs microsoft.com/outlook.com); brand impersonation via display name and attacker-hosted logo; SPF/DKIM/DMARC pass for attacker's own domain proves only domain control, not Microsoft affiliation; same PHPMailer 6.6.0 and PHP-{hex} Message-ID fingerprint as E2/E5/E7; 48-hour lockout urgency; forged sign-in detail (Lagos, 41.203.72.188) as fear bait | Blocklist domain and 51.38.42.17; interview Rafael Mendez for click/interaction; review rmendez M365 sign-in logs post-delivery; add explicit "authenticating domain ≠ brand authorization" rule to mail gateway heuristics |
| E4 | LEGITIMATE | LEGITIMATE | HIGH | Internal origin from exchange-hub.meddefense.local (10.10.1.15); full SPF/DKIM/DMARC pass for meddefense.com; Exchange Server 2019 X-Mailer; content consistent with IT policy (states IT will never email password links) | No action required. Retain as a control specimen — its statement that the real portal is internal-only is evidentiary support that E2's external link was necessarily fraudulent |
| E5 | SUSPICIOUS | PHISHING-TARGETED | HIGH | SPF softfail, DKIM none, DMARC fail; PHPMailer 6.6.0 stack; fabricated invoice $24,716.38 with 7-day/2%-fee pressure; attachment INV-2026-04891.pdf produced by wkhtmltopdf 0.12.6 one second before send — no accounting system generates invoices this way; embedded PDF URI identical to body payment link; Reply-To/From divergence; BEC-style AP targeting | Alert Accounts Payable and finance leadership to the fake invoice and invoice number format; verify no payment initiated; blocklist domain and 185.176.43.22; hash the extracted attachment sample and submit to reputation services and HC3 |
| E6 | SPAM | SPAM | HIGH | X-Spam-Score 9.8 (threshold 5.0); DRUGS_ERECTILE, NORMAL_HTTP_TO_IP, NUMERIC_HTTP_ADDR tests triggered; bulk mailer fingerprint (XPedia); raw-IP affiliate link with ref=pwhite tracker; diverges completely from campaign infrastructure (no PHPMailer, no lookalike domain, no urgency pretext, no targeting) | Retain in quarantine; blocklist 203.0.113.228. Classify as noise — not part of the campaign. Recommend scrubbing leaked email prefixes from outbound-facing marketing wherever possible |
| E7 | SUSPICIOUS | PHISHING-TARGETED | HIGH | Lookalike domain meddefense-benefits[.]org (.org/hyphen variant); SPF fail, DKIM none, DMARC fail; PHPMailer 6.6.0; wp-portal origin host; "closes TOMORROW / midnight" scarcity urgency; personalization (Linda); double-compromise "verify even if enrolled" trap; recipient states she never enrolled — the premise itself is false | Blocklist domain and 164.90.218.73; confirm Linda Patterson took no action; check DNS/proxy logs for any billing-staff interactions with the /enroll path; include in HC3 IOC submission as the benefits-lure variant |
| E8 | LEGITIMATE | LEGITIMATE | HIGH | Authentic hhs.gov origin with full SPF/DKIM pass (selector hhs2026); TLS1.3 relay from HHS mail infrastructure; proper TLP:CLEAR marking and advisory reference (HC3-2026-PRELIM-001); content accurately describes the campaign pattern later confirmed by the batch itself (portal/benefits/supplies keywords, PHPMailer, urgency lures, role targeting) | Treat as authoritative campaign context. Distribute the awareness points to staff; track for the forthcoming named-campaign advisory; submit MedDefense IOCs through the channel it identifies |

---

## Classification Changes Explained

Three emails changed classification between initial triage and final verdict — none changed verdict direction, but all sharpened from the generic "SUSPICIOUS" label to specific attack taxonomy:

- **E2: SUSPICIOUS → PHISHING-TARGETED.** Initial triage flagged lookalike domain, auth failures and urgency. Deeper analysis of the URL parameters (per-victim id and token), the nursing-specific system references in the lure, and the confirmed click note elevated this from "suspicious" to a confirmed targeted credential harvesting incident with an active victim. This is the only email where the final verdict rests partly on a confirmed user action, not just message properties.
- **E3: SUSPICIOUS → PHISHING-TARGETED.** Superficially, E3 looked weaker because authentication passed. Authentication analysis (report 2) showed the pass validates only the attacker's own domain, not the Microsoft brand claim — outlook-protection.com has no relationship to microsoft.com or outlook.com. Header analysis then tied E3 to the campaign via the shared PHPMailer 6.6.0 fingerprint and PHP-{hex} Message-ID format, upgrading it from generic suspicious to targeted campaign member with a deceptive-authentication twist.
- **E5: SUSPICIOUS → PHISHING-TARGETED.** Initial triage noted the auth failures and odd invoice. Attachment analysis revealed the decisive evidence: the PDF was produced by wkhtmltopdf 0.12.6 exactly one second before the email was sent, proving the invoice is machine-generated fraud rather than genuine vendor billing, with an embedded payment link mirroring the body. This upgraded E5 from "suspicious invoice" to targeted BEC/payment-fraud variant within the same campaign.
- **E7: SUSPICIOUS → PHISHING-TARGETED.** Initial triage relied on domain lookalike, auth failure and urgency. Social engineering analysis added the per-victim personalization and the false-premise confirmation (recipient never enrolled), and infrastructure correlation tied it to the campaign via PHPMailer fingerprint and the wp-portal origin host pattern shared with E3.

No email moved from LEGITIMATE to malicious or vice versa. The benign verdicts for E1, E4 and E8 held up under all eight stages of analysis, and the spam verdict for E6 was reinforced by its total divergence from the campaign infrastructure fingerprint.

---

## Triage Accuracy Assessment

Of the 8 emails, the initial triage (report 0) assigned classifications consistent with the final verdicts in all 8 cases — a 100% agreement rate at the coarse level (SPAM / SUSPICIOUS / LEGITIMATE buckets).

Where initial triage was less precise:

- All four malicious emails were initially bucketed generically as "SUSPICIOUS." None carried a campaign-specific taxonomy, and E3's uniqueness (passing authentication) was initially noted but not yet explained. The refinement to PHISHING-TARGETED for all four came from staged analysis, not from triage error.
- Triage correctly separated the single spam item (E6) and the three legitimate items (E1, E4, E8), and correctly prioritized E2 as P1-URGENT ahead of the confirmed click details — the single most consequential triage judgment in the batch.
- No false negatives occurred: no email initially dismissed as noise turned out to be malicious. No false positives forced reclassification of legitimate mail as hostile.

Assessment: rapid triage achieved correct bucketing with acceptable refinement debt. The four-stage refinement (headers → authentication → content → infrastructure correlation) converted every generic SUSPICIOUS verdict into a specific, actionable attack classification tied to a single coordinated campaign. This validates the triage methodology while demonstrating that triage speed comes at the cost of attribution specificity, which deeper analysis must recover.

---

## Campaign Summary for the Record

Final assessment: E2, E3, E5 and E7 constitute one coordinated, role-targeted phishing campaign against MedDefense Health Systems, characterized by PHPMailer 6.6.0 infrastructure, lookalike or brand-impersonation domains, urgency-based pretexts, per-victim tracking, and lures matched to clinical, generic M365, Accounts Payable, and billing/HR roles — matching the pattern described in the HC3 sector advisory (E8). The confirmed click on E2 by Diane Marsh is the sole confirmed user impact; all other recipients' engagement status is unknown pending log review. E6 is unrelated spam; E1, E4 and E8 are legitimate. All campaign IOCs are catalogued in report 6 and ready for gateway enforcement and HC3 submission.

================================================================================
