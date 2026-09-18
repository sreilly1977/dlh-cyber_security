# 11-ioc_extraction.md

**Name:** IOC Extraction

**Purpose:** Extract, categorize and structure indicators of compromise from the
          phishing investigation into a shareable, quality-rated IOC report

**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — INDICATORS OF COMPROMISE REPORT

Evidence basis: Email evidence batch (E1-E8) and investigation reports 0-10.

All indicators are defanged for safe handling and sharing.

Confidence ratings reflect evidence strength from the batch, not live verification.

================================================================================

## 1. Structured IOC Table

| # | Type | IOC Value (defanged) | Source | Context | Confidence | Recommended Action |
|---|------|---------------------|--------|---------|------------|-------------------|
| 1 | Domain | meddefense-portal[.]com | E2 | Lookalike domain for credential harvesting; hosts mail server and phishing page on same host; target of confirmed click by Diane Marsh | HIGH | BLOCK |
| 2 | URL | hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 | E2 | Per-victim credential harvesting URL (username + tracking token); confirmed clicked 2026-04-14 15:02:33 CDT from WS-NURSE-04 | HIGH | BLOCK |
| 3 | IP | 91[.]234[.]99[.]107 | E2 | Sending mail server for meddefense-portal[.]com (mail.meddefense-portal.com) | HIGH | BLOCK |
| 4 | Email address | noreply@meddefense-portal[.]com | E2 | Sender address used in portal re-verification lure; Reply-To no-reply@meddefense-portal[.]com also observed | HIGH | BLOCK/alert at gateway |
| 5 | Domain | outlook-protection[.]com | E3 | Brand impersonation of Microsoft (not microsoft.com or outlook.com); attacker-configured SPF/DKIM/DMARC pass on own domain | HIGH | BLOCK |
| 6 | URL | hxxps://outlook-protection[.]com/verify | E3 | Microsoft 365 credential harvesting URL | HIGH | BLOCK |
| 7 | IP | 51[.]38[.]42[.]17 | E3 | Sending mail server for outlook-protection[.]com | HIGH | BLOCK |
| 8 | Email address | security@outlook-protection[.]com | E3 | Sender address used in "unusual sign-in activity" lure | HIGH | BLOCK/alert at gateway |
| 9 | Domain | medequip-supplies[.]net | E5 | Vendor fraud lookalike domain; hosts mail server, payment portal and login portal | HIGH | BLOCK |
| 10 | URL | hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 | E5 + PDF attachment | Fraudulent payment portal URL; identical in email body and embedded PDF link annotation | HIGH | BLOCK |
| 11 | URL | hxxps://medequip-supplies[.]net/portal/login | E5 | Secondary harvesting path offered as invoice-retrieval fallback | HIGH | BLOCK |
| 12 | IP | 185[.]176[.]43[.]22 | E5 | Sending mail server for medequip-supplies[.]net | HIGH | BLOCK |
| 13 | Email address | invoices@medequip-supplies[.]net | E5 | Sender address in invoice lure; Reply-To billing@medequip-supplies[.]net also observed | HIGH | BLOCK/alert at gateway |
| 14 | File hash | 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f (SHA-256) | E5 attachment | Hash indicator visible in decoded PDF content of INV-2026-04891.pdf; labeled xxxSHA-256 in object stream; NOT independently verified against a locally computed digest — treat as indicative, verify before external submission | MEDIUM | Monitor/search (hash search in VT, SIEM lookups once verified) |
| 15 | File name | INV-2026-04891[.]pdf | E5 attachment | Fabricated invoice attachment (application/pdf, base64); wkhtmltopdf 0.12.6 producer; created 1 second before send | HIGH | Alert/block filename pattern at mail gateway |
| 16 | Tool | wkhtmltopdf 0.12.6 | E5 attachment | PDF producer string proving scripted HTML-to-PDF invoice generation; not a standard accounting system output | MEDIUM | Context only for hunting; alert if seen in inbound attachment metadata paired with invoice pretexts |
| 17 | Domain | meddefense-benefits[.]org | E7 | HR benefits lookalike (.org + hyphen variant of meddefense.com) | HIGH | BLOCK |
| 18 | URL | hxxps://meddefense-benefits[.]org/enroll | E7 | Benefits enrollment credential/PII harvesting URL | HIGH | BLOCK |
| 19 | IP | 164[.]90[.]218[.]73 | E7 | Sending mail server for meddefense-benefits[.]org | HIGH | BLOCK |
| 20 | Email address | hr-notifications@meddefense-benefits[.]org | E7 | Sender address in open enrollment lure; Reply-To no-reply@meddefense-benefits[.]org also observed | HIGH | BLOCK/alert at gateway |
| 21 | Tool | PHPMailer 6.6.0 + PHP-{hex} Message-ID + localhost injection | E2, E3, E5, E7 | Shared sending-stack fingerprint linking all four malicious emails to one campaign | MEDIUM | Monitor/context — do not block PHPMailer globally (legitimate bulk senders use it); useful as correlation/detection rule when combined with lookalike domain context |
| 22 | Infrastructure note | Single-domain mail/web co-location pattern (each campaign domain serves both SMTP origin and phishing web content) | E2, E3, E5, E7 | Disposable VPS stand-up pattern; corroborates HC3 budget-VPS description | MEDIUM | Context only — informs hunting, not blockable |
| 23 | Infrastructure note | Budget VPS hosting tier per HC3 advisory (names Hostinger, DigitalOcean pricing tier generically) | E8 | Attacker infrastructure profile; HC3 attributes to unnamed regional healthcare campaign | LOW | CONTEXT ONLY — hosting providers are shared by millions of legitimate customers; never block by provider alone |
| 24 | Infrastructure note | Newly-registered domains (<30 days) with keywords portal/benefits/supplies/login | E8 | HC3-observed campaign pattern; matches all four MedDefense domains (registration ages INFERRED, not confirmed by WHOIS in this investigation) | MEDIUM | Monitor/alert — feed into newly-registered-domain detection rules at mail gateway |
| 25 | Infrastructure note | Role-targeted delivery (clinical, AP, HR) with urgency deadlines (24h/48h/7d/midnight) | E2, E3, E5, E7 + E8 | Behavioral pattern common to campaign; useful for awareness and detection engineering | MEDIUM | Monitor/context |
| 26 | Email address | HC3@hhs[.]gov | E8 | Legitimate sector alert sender — reference for verification of future advisories | HIGH | Context only (whitelist baseline; do NOT block) |
| 27 | Email address | dmarsh@meddefense[.]com | E2 victim note | Confirmed click victim (WS-NURSE-04, 10.10.2.15) — internal case data, not attacker infrastructure | HIGH | Internal incident tracking only — not shareable as IOC |

---

## 2. IOCs Categorized by Attack Phase

**Delivery (how the campaign reached victims):**
- IOC 1, 5, 9, 17 — lookalike/impersonation sending domains
- IOC 3, 7, 12, 19 — sending mail server IPs
- IOC 4, 8, 13, 20 — phishing sender addresses (with observed Reply-To variants)
- IOC 21 — PHPMailer 6.6.0 fingerprint (correlation rule, not standalone block)
- IOC 24 — newly-registered keyword-domain pattern (gateway detection rule)

**Credential harvesting (where stolen data would land):**
- IOC 2 — E2 harvesting URL with per-victim token (CONFIRMED CLICKED)
- IOC 6 — E3 Microsoft-impersonation harvesting URL
- IOC 10, 11 — E5 payment/login portal URLs
- IOC 18 — E7 enrollment harvesting URL

**Attachment/lure artifacts:**
- IOC 14 — PDF SHA-256 indicator (unverified; needs recomputation before external use)
- IOC 15 — INV-2026-04891.pdf filename
- IOC 16 — wkhtmltopdf 0.12.6 producer fingerprint

**Infrastructure:**
- IOC 22 — mail/web co-location pattern
- IOC 23 — budget VPS hosting tier (context only)
- IOC 25 — role/urgency behavioral pattern

**Context-only indicators (not blockable):**
- IOC 21 (as a block), 22, 23, 25 — shared tooling and hosting patterns
- IOC 26 — legitimate HHS sender (verification baseline)
- IOC 27 — internal victim identifier (case data)
- Victim email addresses embedded in URLs (id=dmarsh, ref=pwhite in E6) — demonstrate per-victim tracking technique, but the addresses themselves belong to MedDefense staff, not the attacker

---

## 3. IOC Quality Assessment

**High-confidence, safe to block:**
IOCs 1-13 and 17-20 — the four campaign domains, their URLs, sending IPs and sender addresses. These are purpose-built, attacker-registered lookalike domains with no legitimate use plausible. Blocking them cannot cause collateral damage to any legitimate sender because nothing legitimate operates on them. The E2 harvesting URL (IOC 2) additionally carries forensic weight: its token parameter ties the click to a specific victim session.

**Monitor-only (detection value without block safety):**
- IOC 14 — the SHA-256 string: visible in the decoded PDF content but self-declared by the attacker's own file; it must be recomputed from the extracted attachment and matched before treating it as a true file fingerprint. Hash-search only.
- IOC 24 — newly-registered keyword domains: strong campaign signal, but newly-registered domains are also used by legitimate new businesses. Use as a scoring input in gateway rules (new domain + invoice/portal pretext + urgency), never as a standalone block.
- IOC 16 — wkhtmltopdf: a legitimate, widely-used open-source tool. Its presence in an inbound "invoice" is suspicious in context but meaningless alone.

**Not safe to use alone (false-positive risk if blocked indiscriminately):**
- IOC 21 — PHPMailer 6.6.0: enormous legitimate user base including legitimate newsletters and applications (E1's MailChimp ecosystem and countless OSS deployments). Blocking PHPMailer headers outright would quarantine legitimate mail. It is valuable only when combined with lookalike-domain or authentication-failure context.
- IOC 23 — budget VPS hosting providers (Hostinger/DigitalOcean-tier): these providers host millions of legitimate websites. Blocking provider IP ranges would cause massive collateral damage. The correct use is per-IP blocking of specific malicious hosts (IOCs 3, 7, 12, 19) plus newly-registered-domain monitoring.
- IOC 22, 25 — architectural and behavioral patterns: hunting hypotheses, not blockable indicators.

**Special cases:**
- IOC 26 (hhs.gov) and IOC 27 (victim identity): these exist in the report for completeness and internal case continuity. HHS addresses must never be blocked; victim identifiers are internal-only and must be excluded from any external IOC sharing to protect the affected employee.

---

## 4. HC3-Ready Summary

Prepared for submission via the HC3 portal per advisory HC3-2026-PRELIM-001 (E8), TLP:CLEAR. Indicators defanged; confidence assessed against batch evidence only.

**Domains (4) — all HIGH confidence, recommend block:**
- meddefense-portal[.]com
- outlook-protection[.]com
- medequip-supplies[.]net
- meddefense-benefits[.]org

**Sending IPs (4) — all HIGH confidence, recommend block:**
- 91[.]234[.]99[.]107 (meddefense-portal[.]com, E2)
- 51[.]38[.]42[.]17 (outlook-protection[.]com, E3)
- 185[.]176[.]43[.]22 (medequip-supplies[.]net, E5)
- 164[.]90[.]218[.]73 (meddefense-benefits[.]org, E7)

**Sender addresses (4) — HIGH confidence:**
- noreply@meddefense-portal[.]com (Reply-To: no-reply@)
- security@outlook-protection[.]com
- invoices@medequip-supplies[.]net (Reply-To: billing@)
- hr-notifications@meddefense-benefits[.]org (Reply-To: no-reply@)

**Harvesting URLs (5) — HIGH confidence:**
- hxxps://meddefense-portal[.]com/verify/staff?id={victim}&token={unique-per-victim}
- hxxps://outlook-protection[.]com/verify
- hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
- hxxps://medequip-supplies[.]net/portal/login
- hxxps://meddefense-benefits[.]org/enroll

**File artifact (1) — MEDIUM, verify before sharing:**
- INV-2026-04891[.]pdf — application/pdf, base64; producer wkhtmltopdf 0.12.6; embedded URI: hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891; SHA-256 pending recomputation from extracted sample (declared-but-unverified string: 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f)

**Campaign correlation notes (TLP:CLEAR):**
All four domains observed using PHPMailer 6.6.0 with PHP-{hex} Message-ID format and localhost injection hops; single-domain mail/web co-location; role-targeted lures (clinical, AP, HR, general M365); urgency deadlines of 24h-7d; delivery window 2026-04-14 through 2026-04-16; matches all four preliminary patterns described in HC3-2026-PRELIM-001. One confirmed victim interaction with the portal harvesting URL (per-victim token capture). Hostnames wp-admin and wp-portal observed on E3/E7 origin servers, suggesting WordPress-configured VPS images. Registration ages inferred from pattern match (not yet WHOIS-confirmed) — recommended verification: RDAP/WHOIS, passive DNS, certificate transparency.

================================================================================
