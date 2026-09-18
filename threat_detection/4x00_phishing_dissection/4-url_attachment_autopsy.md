# 4-url_attachment_autopsy.md

**Name:** URL and Attachment Autopsy

**Purpose:** Safely extract, defang and document URL and attachment indicators
          from suspicious emails E2, E3, E5, E7 without direct visitation

**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — URL AND ATTACHMENT AUTOPSY

Analysis targets: E2, E3, E5, E7 (plus E6 IP indicator for completeness)

Investigation method: Static extraction from raw email evidence batch only.

No URLs were visited, no attachments opened, no live DNS resolution performed.

All indicators are defanged for safe documentation.

================================================================================

## Indicator 1

- **Source email:** E2 (meddefense-portal.com credential phishing — the email Diane Marsh clicked)
- **Original value:** https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1
- **Defanged value:** hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- **Domain or IP:** meddefense-portal.com (sending IP 91.234.99.107)
- **Indicator type:** Credential harvesting URL (URL path with victim identifier and session token parameters)
- **Evidence from email:**
  - Same domain hosts the sending mail server (mail.meddefense-portal.com) — attacker operates both the mail infrastructure and the harvesting web server
  - URL embeds the victim's username (id=dmarsh) and a token value (token=a8f3e2d1), indicating server-side tracking of individual victims
  - Domain is a hyphen-append lookalike of meddefense.com
  - SPF fail, DKIM none, DMARC fail on the delivering message
- **Safe investigation method:**
  - `whois meddefense-portal.com` (check registration date for HC3 "under 30 days" pattern, registrar, registrant privacy)
  - `dig ANY meddefense-portal.com` / `nslookup meddefense-portal.com` (resolve hosting IP; compare against sending IP 91.234.99.107)
  - `curl -I https://meddefense-portal.com` **only from sandboxed VM via proxy** — check server banner without fetching content
  - VirusTotal search for domain and full URL; urlscan.io search for prior scans of the domain
  - Passive DNS via VirusTotal/SecurityTrails to enumerate subdomains and historical resolutions
- **Finding:** This is the highest-impact indicator in the batch. The URL structure (verify/staff with per-victim parameters) is a classic credential harvester pattern. The evidence batch states Diane Marsh clicked this link at 2026-04-14 15:02:33 CDT, meaning the attacker likely received her credentials if she submitted them. The embedding of the victim ID allows the attacker to map harvested credentials to specific individuals.
- **Risk rating:** CRITICAL

---

## Indicator 2

- **Source email:** E2 (branding asset reference)
- **Original value:** https://meddefense-portal.com/assets/logo.png
- **Defanged value:** hxxps://meddefense-portal[.]com/assets/logo.png
- **Domain or IP:** meddefense-portal.com (same host as Indicator 1)
- **Indicator type:** Hosted image asset (potential stolen logo on attacker infrastructure)
- **Evidence from email:**
  - Logo image hotlinked from the attacker's own domain rather than any MedDefense-controlled host
  - Image tag explicitly labels it as "MedDefense" branding (alt="MedDefense" width="180")
  - Same domain reuse as the credential harvesting URL and sending mail server
- **Safe investigation method:**
  - `whois meddefense-portal.com` (covered under Indicator 1 — domain-level intel applies to all assets)
  - urlscan.io lookup for the domain will render the phishing page screenshot without direct visitation
  - VirusTotal domain report may list additional URLs under /assets/ revealing the kit structure
- **Finding:** Attacker-hosted logo confirms deliberate impersonation kit built on a single domain serving mail, imagery, and harvesting pages. No legitimate MedDefense asset is referenced anywhere in the message.
- **Risk rating:** HIGH

---

## Indicator 3

- **Source email:** E3 (Microsoft brand impersonation)
- **Original value:** https://outlook-protection.com/verify
- **Defanged value:** hxxps://outlook-protection[.]com/verify
- **Domain or IP:** outlook-protection.com (sending IP 51.38.42.17)
- **Indicator type:** Credential harvesting URL (Microsoft 365 login phish)
- **Evidence from email:**
  - Sending domain (outlook-protection.com) is NOT a Microsoft property — Microsoft domains are microsoft.com, outlook.com, live.com
  - Message-ID pattern PHP-{hex}@domain and X-Mailer PHPMailer 6.6.0 match E2, E5, E7 infrastructure
  - Received chain shows origin from wp-admin.outlook-protection.com (wp- prefix suggests a WordPress-configured VPS)
  - SPF/DKIM/DMARC pass for outlook-protection.com — attacker properly configured authentication on their own deceptive domain
  - Microsoft logo referenced at https://outlook-protection.com/img/ms_logo.png (attacker-hosted)
- **Safe investigation method:**
  - `whois outlook-protection.com` (registration age, registrar — HC3 advises lookalike domains under 30 days old)
  - `dig outlook-protection.com` (compare resolution against sending IP 51.38.42.17; hosting provider ASN)
  - VirusTotal and urlscan.io domain lookups for screenshot rendering and community reports
  - `curl -I` from sandbox to capture server header (likely budget VPS per HC3 pattern: Hostinger/DigitalOcean tier)
- **Finding:** Brand impersonation URL attempting to harvest Microsoft 365 credentials. Despite passing authentication, the domain has no affiliation with Microsoft. The infrastructure fingerprint (PHPMailer 6.6.0, PHP Message-ID, localhost injection hop) ties this to the same campaign cluster as E2, E5, E7.
- **Risk rating:** HIGH

---

## Indicator 4

- **Source email:** E5 (invoice lure — payment portal links)
- **Original value:** https://medequip-supplies.net/invoices/pay?id=INV-2026-04891
- **Defanged value:** hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
- **Domain or IP:** medequip-supplies.net (sending IP 185.176.43.22)
- **Indicator type:** Fraudulent payment portal URL (BEC/payment redirection)
- **Evidence from email:**
  - Sending IP 185.176.43.22 is a softfail for the domain's own SPF record — mail server and web server may be same host or attacker-controlled infrastructure not authorized in public SPF
  - Amount demanded: USD 24,716.38 with 7-day deadline and 2% late fee threat
  - Invoice number INV-2026-04891 referenced in both body and attachment filename
  - Reply-To differs from From (billing@ vs invoices@) — reply interception pattern
- **Safe investigation method:**
  - `whois medequip-supplies.net` (check whether a real vendor exists under this name or was squatted)
  - `dig medequip-supplies.net` / `nslookup` (resolution and hosting ASN)
  - VirusTotal URL and domain lookups; urlscan.io for portal page screenshot
  - Compare MX and A records — `dig MX medequip-supplies.net` should confirm mail host matches 185.176.43.22 observed in Received header
- **Finding:** Payment portal URL for a fraudulent invoice. The dual-channel delivery (body link plus PDF attachment link) gives recipients two paths to the same fraudulent destination. No purchase order or contract reference exists in the message, which legitimate vendor invoicing would typically include.
- **Risk rating:** HIGH

---

## Indicator 5

- **Source email:** E5 (attachment — DO NOT OPEN; metadata only)
- **Original value:** Attachment "INV-2026-04891.pdf" (application/pdf, base64-encoded, multipart/mixed message)
- **Defanged value:** N/A (attachment reference; SHA-256 to be computed after safe extraction in sandbox)
- **Domain or IP:** Embedded URI action resolves to medequip-supplies.net (hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 per the PDF annotation object visible in the base64 stream)
- **Indicator type:** PDF attachment with embedded link annotation (no JavaScript or OpenAction observed in the visible object stream)
- **Evidence from email (visible in raw base64):**
  - PDF Producer string visible in decoded metadata: wkhtmltopdf 0.12.6 — the "invoice" was machine-rendered from HTML, not produced by any accounting system
  - Creation date D:20260416162834 matches the email send timestamp (2026-04-16 16:28:34) — invoice generated seconds before sending
  - Link annotation (/Subtype /Link, /Type /Action /S /URI) points to the same pay portal as the email body links
  - Filename and invoice ID intentionally mirror professional invoice conventions
- **Safe investigation method:**
  - Extract base64 block between MIME boundaries: `sed -e '1,/Content-Transfer-Encoding: base64/d' -e '/^------=_Part_INV_4891/,$d' email_batch.txt | tr -d '\n' | base64 -d > INV-2026-04891.pdf`
  - Verify file type and hash: `file INV-2026-04891.pdf && sha256sum INV-2026-04891.pdf`
  - Metadata only, never open in a reader: `exiftool INV-2026-04891.pdf`, `pdfid.py`, `pdf-parser.py -o 10`
  - Submit hash to VirusTotal; detonate only via online sandbox (ANY.RUN, Joe Sandbox, Hybrid Analysis)
- **Finding:** The attachment is a fabricated invoice PDF rendered from an HTML template using wkhtmltopdf within the same minute the email was dispatched. Its embedded link annotation duplicates the body's payment portal URL, indicating the attachment serves as a secondary click vector and false documentary support for the payment demand.
- **Risk rating:** HIGH

---

## Indicator 6

- **Source email:** E7 (HR benefits impersonation)
- **Original value:** https://meddefense-benefits.org/enroll
- **Defanged value:** hxxps://meddefense-benefits[.]org/enroll
- **Domain or IP:** meddefense-benefits.org (sending IP 164.90.218.73)
- **Indicator type:** Credential harvesting URL (benefits enrollment phish)
- **Evidence from email:**
  - Origin hostname wp-portal.meddefense-benefits.org (wp- prefix again suggesting WordPress/VPS setup, echoing E3's wp-admin hostname)
  - Sending IP 164.90.218.73 — SPF fail for its own domain
  - Lookalike domain substitutes .org TLD and hyphen for MedDefense's actual meddefense.com
  - Enrollment page likely collects credentials, SSNs, and benefits data given the "election" terminology in the lure
- **Safe investigation method:**
  - `whois meddefense-benefits.org` (registration age under 30 days would confirm HC3 pattern)
  - `dig meddefense-benefits.org` (hosting provider; 164.90.218.73 falls in a cloud provider range commonly used for budget VPS)
  - VirusTotal/urlscan.io domain lookups for page screenshots and passive DNS
  - Certificate transparency log search (crt.sh) for meddefense-benefits.org to find issuance date and subdomains
- **Finding:** Credential and potentially PII harvesting URL exploiting open enrollment timing. The harvesting page concealed behind a natural HR event window makes this lure highly plausible to non-technical staff, particularly in billing where enrollment deadlines carry real consequences.
- **Risk rating:** HIGH

---

## Indicator 7

- **Source email:** E6 (spam — included per evidence requirements as infrastructure indicator)
- **Original value:** http://203.0.113.228/shop?ref=pwhite
- **Defanged value:** hxxp://203[.]0[.]113[.]228/shop?ref=pwhite
- **Domain or IP:** 203.0.113.228 (raw IPv4, no domain — same IP as the sending server bulk-mail-07.canadian-pharma-discount.org)
- **Indicator type:** Raw IP shopping link (drug spam)
- **Evidence from email:**
  - Link bypasses domain naming entirely, connecting directly to the sending host IP
  - X-Spam-Status flags NORMAL_HTTP_TO_IP and NUMERIC_HTTP_ADDR tests triggered; X-Spam-Score 9.8 exceeded quarantine threshold 5.0
  - The URL embeds the victim email prefix (ref=pwhite) for spam affiliate tracking
  - The web server and mail server are the same physical host (203.0.113.228 sends and serves)
- **Safe investigation method:**
  - `whois -h whois.arin.net 203.0.113.228` (or appropriate RIR for ownership and abuse contacts)
  - VirusTotal IP lookup; urlscan.io for page reputation
  - No direct HTTP requests — the spam verdict is already established by gateway scoring and content
- **Finding:** Classic unsolicited pharmaceutical spam with an embedded affiliate tracker. Classified as noise rather than part of the phishing campaign: infrastructure (raw IP host, XPedia Bulk Mailer) and social engineering profile (broad advertisement, no personalization, no urgency pretext) diverge completely from the E2/E3/E5/E7 cluster. Retained in documentation because the ref=pwhite parameter demonstrates personal data leak into URLs, and IP-level indicators should be blocklisted.
- **Risk rating:** LOW (spam noise; not campaign-linked)

================================================================================

## Indicator Summary Table

| # | Email | Defanged Indicator | Type | Risk |
|---|-------|-------------------|------|------|
| 1 | E2 | hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 | Credential harvesting URL | CRITICAL |
| 2 | E2 | hxxps://meddefense-portal[.]com/assets/logo.png | Attacker-hosted impersonation asset | HIGH |
| 3 | E3 | hxxps://outlook-protection[.]com/verify | Credential harvesting URL (M365) | HIGH |
| 4 | E5 | hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 | Fraudulent payment portal | HIGH |
| 5 | E5 | INV-2026-04891.pdf (wkhtmltopdf 0.12.6, embedded URI) | Malicious attachment | HIGH |
| 6 | E7 | hxxps://meddefense-benefits[.]org/enroll | Credential/PII harvesting URL | HIGH |
| 7 | E6 | hxxp://203[.]0[.]113[.]228/shop?ref=pwhite | Spam shop link (raw IP) | LOW |

## Sending Infrastructure Correlation (from evidence only)

| Email | Domain | Sending IP | Mail/Web Co-location | PHPMailer |
|-------|--------|-----------|---------------------|-----------|
| E2 | meddefense-portal.com | 91.234.99.107 | Same domain serves mail + harvesting pages | 6.6.0 |
| E3 | outlook-protection.com | 51.38.42.17 | wp-admin origin host | 6.6.0 |
| E5 | medequip-supplies.net | 185.176.43.22 | Same domain serves mail + pay portal | 6.6.0 |
| E7 | meddefense-benefits.org | 164.90.218.73 | wp-portal origin host | 6.6.0 |
| E6 | canadian-pharma-discount.org | 203.0.113.228 | Single raw-IP host | Bulk Mailer (XPedia) |

Each suspicious domain serves as both mail origin and phishing web host, minimizing attacker infrastructure footprint. The domain keywords portal, protection, supplies, and benefits match the naming convention in the sector advisory carried in E8. Recommended immediate actions: blocklist all four domains and five sending IPs at mail gateway and DNS/proxy layers, retain the defanged URLs for IOC submission, and verify domain registration ages via whois to substantiate the newly-registered-domain attribution before submitting IOCs externally.

================================================================================
