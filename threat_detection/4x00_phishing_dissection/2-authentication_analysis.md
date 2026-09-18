# 2-authentication_analysis.md

**Name**: Email Authentication Analysis

**Purpose:** Validate SPF, DKIM and DMARC results for all 8 emails and explain
          what each result means for the investigation
**Author:** Steve - Cybersecurity Engineer
**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — EMAIL AUTHENTICATION ANALYSIS

Evidence source: Email evidence batch (collected 2026-04-17 by Mike Torres)

================================================================================

## Email 1 — healthcare-education-weekly.com

- **SPF:** pass (sender IP 198.51.100.42 authorized for healthcare-education-weekly.com)
- **DKIM:** pass (signature present for domain healthcare-education-weekly.com)
- **DMARC:** pass (action=none, header.from domain aligned)
- **Authentication verdict:** Supported — The sending infrastructure is authorized by the claimed domain
- **Investigation meaning:** Authentication results align with apparent legitimacy. Combined with valid subscription trail, MailChimp infrastructure, and working unsubscribe mechanisms, this indicates a genuine marketing newsletter rather than spoofed content.

---

## Email 2 — meddefense-portal.com

- **SPF:** fail (sender IP 91.234.99.107 not authorized for meddefense-portal.com)
- **DKIM:** none (message not signed)
- **DMARC:** fail (action=none, header.from domain failed alignment)
- **Authentication verdict:** Failed — No mechanism validates sender as authorized
- **Investigation meaning:** All three authentication mechanisms fail, indicating the sender has no cryptographic relationship to meddefense-portal.com. The display name "MedDefense IT Security" cannot be trusted when the underlying domain lacks authentication proof. This contradicts any appearance of internal MedDefense origin.

---

## Email 3 — outlook-protection.com

- **SPF:** pass (sender IP 51.38.42.17 authorized for outlook-protection.com)
- **DKIM:** pass (signature present for domain outlook-protection.com)
- **DMARC:** pass (action=none, header.from domain aligned)
- **Authentication verdict:** Technically passed — but validates wrong entity
- **Investigation meaning:** SPF, DKIM and DMARC all pass, which proves the sender controls outlook-protection.com. However, outlook-protection.com is not the same as microsoft.com or outlook.com. The email displays "Microsoft Account Protection" in the From field, but authentication validates only the third-party domain, not any Microsoft affiliation. Passing authentication on a deceptive domain demonstrates attacker infrastructure control, not message authenticity. This is brand impersonation where the attacker registered their own domain and configured it properly — authentication cannot detect this because it only validates the domain itself, not whether that domain is trustworthy or impersonating another organization.

---

## Email 4 — meddefense.com (internal)

- **SPF:** pass (sender IP 10.10.1.15 is internal to MedDefense network)
- **DKIM:** pass (signature present for domain meddefense.com)
- **DMARC:** pass (action=none, header.from domain aligned)
- **Authentication verdict:** Supported — Internal sending infrastructure authorized for organizational domain
- **Investigation meaning:** Authentication results are consistent with legitimate internal communication. The sender originates from exchange-hub.meddefense.local (10.10.1.15), uses Exchange Server 2019, and carries valid DKIM signature for the organization's primary domain. This matches expectations for genuine MedDefense IT announcements.

---

## Email 5 — medequip-supplies.net

- **SPF:** softfail (sender IP 185.176.43.22 not in authorized list for medequip-supplies.net)
- **DKIM:** none (message not signed)
- **DMARC:** fail (action=none, header.from domain failed alignment)
- **Authentication verdict:** Failed — SPF softfail and missing DKIM prevent DMARC passage
- **Investigation meaning:** SPF softfail indicates the sending IP is not explicitly authorized by medequip-supplies.net's SPF record. Combined with absent DKIM signature, DMARC fails. For a legitimate business billing department transmitting high-value invoices, proper signing would be expected. These gaps contradict the appearance of professional commercial correspondence.

---

## Email 6 — canadian-pharma-discount.org

- **SPF:** softfail (sender IP 203.0.113.228 not authorized)
- **DKIM:** none (no signature present)
- **DMARC:** fail (action=quarantine applied, header.from domain failed alignment)
- **Authentication verdict:** Failed — Multiple authentication gaps triggered gateway quarantine
- **Investigation meaning:** SPF softfail, missing DKIM, and DMARC failure align with spam classification. The gateway assigned X-Spam-Score 9.8 and placed this in quarantine based on authentication failures plus content indicators (DRUGS_ERECTILE test, numeric IP link). Authentication results support the spam verdict but are not the sole basis.

---

## Email 7 — meddefense-benefits.org

- **SPF:** fail (sender IP 164.90.218.73 not authorized for meddefense-benefits.org)
- **DKIM:** none (message not signed)
- **DMARC:** fail (action=none, header.from domain failed alignment)
- **Authentication verdict:** Failed — No validation of sender authorization
- **Investigation meaning:** Complete authentication failure mirrors Email 2. The hyphenated domain meddefense-benefits.org fails to authenticate as authorized to represent MedDefense, even though the display name asserts "MedDefense HR Benefits." DMARC cannot pass when the sending domain has no SPF authorization and no DKIM signature. This contradicts any legitimacy claim for HR-related communications.

---

## Email 8 — hhs.gov

- **SPF:** pass (sender IP 134.174.47.82 authorized for hhs.gov)
- **DKIM:** pass (signature present for domain hhs.gov)
- **DMARC:** pass (action=none, header.from domain aligned)
- **Authentication verdict:** Supported — Government domain with valid cryptographic signatures
- **Investigation meaning:** Authentication validates the message originates from HHS infrastructure authorized for hhs.gov. The DKIM signature includes selector hhs2026, indicating active key management. Combined with TLP:CLEAR marking and HHS Secure Mail Gateway headers, this confirms authentic government threat intelligence rather than spoofed advisory.

================================================================================

## Authentication Results Summary Table

| Email | Domain | SPF | DKIM | DMARC | Alignment With Claim |
|-------|--------|-----|------|-------|---------------------|
| E1 | healthcare-education-weekly.com | pass | pass | pass | ✓ Legitimate marketing infrastructure |
| E2 | meddefense-portal.com | fail | none | fail | ✗ Impersonation without validation |
| E3 | outlook-protection.com | pass | pass | pass | ✗ Valid domain, deceptive claim |
| E4 | meddefense.com | pass | pass | pass | ✓ Genuine internal communication |
| E5 | medequip-supplies.net | softfail | none | fail | ✗ Business spoofing without signing |
| E6 | canadian-pharma-discount.org | softfail | none | fail (quarantine) | ✗ Spam infrastructure |
| E7 | meddefense-benefits.org | fail | none | fail | ✗ Impersonation without validation |
| E8 | hhs.gov | pass | pass | pass | ✓ Authentic government advisory |

---

## Key Takeaways for Investigation

Authentication results alone cannot distinguish legitimate from malicious emails. E1, E4, E8 and E3 all show passing SPF/DKIM/DMARC, but only E1, E4 and E8 are genuinely legitimate. E3 passes authentication while impersonating Microsoft because the attacker owns outlook-protection.com. This illustrates the core limitation: authentication validates the domain, not the truthfulness of the From display name.

For the MedDefense investigation, the four suspicious emails (E2, E3, E5, E7) split into two patterns. E2, E5 and E7 show complete authentication failure with lookalike domains, indicating they cannot cryptographically prove ownership of their claimed identity. E3 is distinct because it passes authentication for its own domain while falsely representing Microsoft. The investigation must treat E3 differently — not as an authentication failure, but as a brand impersonation case where authentication works as designed but does not provide safety assurance.

================================================================================
