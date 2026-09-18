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
- **Original value:** https[:]//meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- **Defanged value:** hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- **Domain or IP:** meddefense-portal[.]com (sending IP 91.234.99.107)
- **Indicator type:** Credential harvesting URL (path with victim identifier and session token parameters)
- **Evidence from email:**
  - Same domain hosts the sending mail server (mail.meddefense-portal.com) — attacker operates both the mail infrastructure and the harvesting web server
  - URL embeds the victim's username (id=dmarsh) and a token value (token=a8f3e2d1), indicating server-side tracking of individual victims
  - Domain is a hyphen-append lookalike of meddefense.com
  - SPF fail, DKIM none, DMARC fail on the delivering message
- **Safe investigation method (passive only):**
  - WHOIS database lookup for meddefense-portal[.]com via registrar RDAP service or web whois interface — check registration date against the HC3 "under 30 days" pattern, registrar, registrant privacy
  - Passive DNS via VirusTotal, SecurityTrails or RiskIQ — enumerate historical resolutions and compare against sending IP 91.234.99.107
  - VirusTotal domain and URL reputation lookup
  - urlscan.io search for prior community scans of the domain — screenshots of the phishing page are available without any direct visitation
  - Certificate transparency log search (crt.sh) for certificate issuance dates and subdomain enumeration
- **Finding:** This is the highest-impact indicator in the batch. The URL structure (verify/staff with per-victim parameters) is a classic credential harvester pattern. The evidence batch states Diane Marsh clicked this link at 2026-04-14 15:02:33 CDT, meaning the attacker likely received her credentials if she submitted them. The embedded victim ID allows the attacker to map harvested credentials to specific individuals.
- **Risk rating:** CRITICAL

## Indicator 2

- **Source email:** E2 (branding asset reference)
- **Original value:** https[:]//meddefense-portal[.]com/assets/logo[.]png
- **Defanged value:** hxxps://meddefense-portal[.]com/assets/logo[.]png
- **Domain or IP:** meddefense-portal[.]com (same host as Indicator 1)
- **Indicator type:** Hosted image asset (attacker-hosted impersonation imagery)
- **Evidence from email:**
  - Logo image referenced from the attacker's own domain rather than any MedDefense-controlled host
  - Image tag explicitly labels it as MedDefense branding (alt="MedDefense" width="180")
  - Same domain reuse as the credential harvesting URL and sending mail server
- **Safe investigation method (passive only):**
  - Domain-level intel applies from Indicator 1 (WHOIS/RDAP registration data)
  - urlscan.io lookup for the domain renders the phishing page screenshot without direct visitation
  - VirusTotal domain report may list additional URLs under /assets/ revealing the kit structure
- **Finding:** Attacker-hosted logo confirms a deliberate impersonation kit built on a single domain serving mail, imagery, and harvesting pages. No legitimate MedDefense asset is referenced anywhere in the message.
- **Risk rating:** HIGH

## Indicator 3

- **Source email:** E3 (Microsoft brand impersonation)
- **Original value:** https[:]//outlook-protection[.]com/verify
- **Defanged value:** hxxps://outlook-protection[.]com/verify
- **Domain or IP:** outlook-protection[.]com (sending IP 51.38.42.17)
- **Indicator type:** Credential harvesting URL (Microsoft 365 login phish)
- **Evidence from email:**
  - Sending domain outlook-protection.com is not a Microsoft property — Microsoft operates microsoft.com, outlook.com, and live.com
  - Message-ID pattern PHP-{hex}@domain and X-Mailer PHPMailer 6.6.0 match E2, E5, E7 infrastructure
  - Received chain shows origin from wp-admin.outlook-protection.com (wp- prefix suggests a WordPress-configured VPS)
  - SPF/DKIM/DMARC pass for outlook-protection.com — attacker properly configured authentication on their own deceptive domain
  - Microsoft logo referenced from attacker-hosted path (img/ms_logo.png)
- **Safe investigation method (passive only):**
  - WHOIS/RDAP lookup for outlook-protection[.]com — registration age against HC3 newly-registered-domain pattern
  - Passive DNS comparison of historical resolutions against sending IP 51.38.42.17 and hosting provider ASN
  - VirusTotal and urlscan.io domain lookups for screenshots and community reports
  - crt.sh certificate transparency search for issuance date and subdomains
- **Finding:** Brand impersonation URL attempting to harvest Microsoft 365 credentials. Despite passing authentication, the domain has no affiliation with Microsoft. The infrastructure fingerprint (PHPMailer 6.6.0, PHP Message-ID, localhost injection hop) ties this to the same campaign cluster as E2, E5, E7.
- **Risk rating:** HIGH

## Indicator 4

- **Source email:** E5 (invoice lure — payment portal link)
- **Original value:** https[:]//medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
- **Defanged value:** hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891
- **Domain or IP:** medequip-supplies[.]net (sending IP 185.176.43.22)
- **Indicator type:** Fraudulent payment portal URL (BEC/payment redirection)
- **Evidence from email:**
  - Sending IP 185.176.43.22 is a softfail for the domain's own SPF record — the sending host is not authorized in the public SPF record
  - Amount demanded: USD 24,716.38 with 7-day deadline and 2% late fee threat
  - Invoice number INV-2026-04891 referenced in both body and attachment filename
  - Reply-To differs from From (billing@ vs invoices@) — reply interception pattern
- **Safe investigation method (passive only):**
  - WHOIS/RDAP lookup for medequip-supplies[.]net — determine whether a real vendor exists under this name or the domain was squatted
  - Passive DNS comparison of MX and A record history against the 185.176.43.22 host observed in the Received header
  - VirusTotal URL and domain lookups; urlscan.io for portal page screenshot
- **Finding:** Payment portal URL for a fraudulent invoice. The dual-channel delivery (body link plus PDF attachment link) gives recipients two paths to the same fraudulent destination. No purchase order or contract reference exists in the message, which legitimate vendor invoicing would typically include.
- **Risk rating:** HIGH

## Indicator 5

- **Source email:** E5 (attachment — never opened; metadata extraction only)
- **Original value:** Attachment "INV-2026-04891.pdf" (application/pdf, base64-encoded, multipart/mixed message)
- **Defanged value:** N/A (attachment reference; file hash to be computed after safe extraction)
- **Domain or IP:** Embedded URI annotation resolves to medequip-supplies[.]net (per the decoded PDF object stream visible in the base64 payload)
- **Indicator type:** PDF attachment with embedded link annotation (no JavaScript or OpenAction observed in the visible object stream)
- **Evidence from email (visible in decoded base64 stream):**
  - PDF Producer string: wkhtmltopdf 0.12.6 — the invoice was machine-rendered from an HTML template, not produced by any accounting system
  - Creation date D:20260416162834 matches the email send timestamp (2026-04-16 16:28:34) — invoice generated seconds before sending
  - Link annotation (/Subtype /Link, /Type /Action /S /URI) points to the same pay portal as the email body links
  - Filename and invoice ID intentionally mirror professional invoice conventions
- **Safe investigation method:**
  - Extract the base64 block between MIME boundaries on an offline copy in an isolated VM: `awk '/Content-Transfer-Encoding: base64/{f=1;next} /^------=_Part_INV_4891/{f=0} f' email_batch.txt | tr -d '\n' | base64 -d > sample.pdf`
  - Verify file type and compute hash without opening: `file sample.pdf && sha256sum sample.pdf`
  - Metadata inspection only, never rendered in a reader: `exiftool sample.pdf`, `pdfid.py sample.pdf`, `pdf-parser.py --object 10 sample.pdf`
  - Submit the computed file hash to VirusTotal for reputation; submit the file itself to an online sandbox service (Joe Sandbox, Hybrid Analysis, ANY.RUN) if behavioral analysis is required — detonation happens only inside the provider's sandbox, never locally
- **Finding:** The attachment is a fabricated invoice PDF rendered from an HTML template using wkhtmltopdf within the same minute the email was dispatched. Its embedded link annotation duplicates the body's payment portal URL, indicating the attachment serves as a secondary click vector and false documentary support for the payment demand.
- **Risk rating:** HIGH

## Indicator 6

- **Source email:** E7 (HR benefits impersonation)
- **Original value:** https[:]//meddefense-benefits[.]org/enroll
- **Defanged value:** hxxps://meddefense-benefits[.]org/enroll
- **Domain or IP:** meddefense-benefits[.]org (sending IP 164.90.218.73)
- **Indicator type:** Credential harvesting URL (benefits enrollment phish)
- **Evidence from email:**
  - Origin hostname wp-portal.meddefense-benefits.org (wp- prefix again suggesting WordPress/VPS setup, echoing E3's wp-admin hostname)
  - Sending IP 164.90.218.73 fails SPF for its own domain
  - Lookalike domain substitutes .org TLD and hyphen for MedDefense's actual meddefense.com
  - Enrollment page likely collects credentials and benefits data given the "election" terminology in the lure
- **Safe investigation method (passive only):**
  - WHOIS/RDAP lookup for meddefense-benefits[.]org — registration age under 30 days would confirm HC3 pattern
  - Passive DNS to identify hosting provider ASN for 164.90.218.73
  - VirusTotal/urlscan.io domain lookups for page screenshots
  - crt.sh certificate transparency search for issuance date and subdomains
- **Finding:** Credential and potentially PII harvesting URL exploiting open enrollment timing. The harvesting page concealed behind a natural HR event window makes this lure highly plausible to non-technical staff, particularly in billing where enrollment deadlines carry real consequences.
- **Risk rating:** HIGH

## Indicator 7

- **Source email:** E6 (spam — included per evidence requirements as infrastructure indicator)
- **Original value:** http[:]//203[.]0[.]113[.]228/shop?ref=pwhite
- **Defanged value:** hxxp://203[.]0[.]113[.]228/shop?ref=pwhite
- **Domain or IP:** 203.0.113.228 (raw IPv4, no domain — same IP as the sending server bulk-mail-07.canadian-pharma-discount.org)
- **Indicator type:** Raw IP shopping link (drug spam)
- **Evidence from email:**
  - Link bypasses domain naming entirely, connecting directly to the sending host IP
  - X-Spam-Status flags NORMAL_HTTP_TO_IP and NUMERIC_HTTP_ADDR tests triggered; X-Spam-Score 9.8 exceeded quarantine threshold 5.0
  - The URL embeds the victim email prefix (ref=pwhite) for spam affiliate tracking
  - The web server and mail server are the same physical host (203.0.113.228 sends and serves)
- **Safe investigation method (passive only):**
  - RIR WHOIS lookup (whois.arin.net) for 203.0.113.228 — network ownership and abuse contacts
  - VirusTotal IP reputation lookup
  - No investigation of the hosted content required — the spam verdict is already established by gateway scoring and content
- **Finding:** Classic unsolicited pharmaceutical spam with an embedded affiliate tracker. Classified as noise rather than part of the phishing campaign: infrastructure (raw IP host, XPedia Bulk Mailer) and social engineering profile (broad advertisement, no personalization, no urgency pretext) diverge completely from the E2/E3/E5/E7 cluster. Retained in documentation because the ref=pwhite parameter demonstrates personal data leaking into URLs, and the IP should be blocklisted.
- **Risk rating:** LOW (spam noise; not campaign-linked)

================================================================================

## Indicator Summary Table

| # | Email | Defanged Indicator | Type | Risk |
|---|-------|-------------------|------|------|
| 1 | E2 | hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1 | Credential harvesting URL | CRITICAL |
| 2 | E2 | hxxps://meddefense-portal[.]com/assets/logo[.]png | Attacker-hosted impersonation asset | HIGH |
| 3 | E3 | hxxps://outlook-protection[.]com/verify | Credential harvesting URL (M365) | HIGH |
| 4 | E5 | hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 | Fraudulent payment portal | HIGH |
| 5 | E5 | INV-2026-04891.pdf (wkhtmltopdf 0.12.6, embedded URI) | Malicious attachment | HIGH |
| 6 | E7 | hxxps://meddefense-benefits[.]org/enroll | Credential/PII harvesting URL | HIGH |
| 7 | E6 | hxxp://203[.]0[.]113[.]228/shop?ref=pwhite | Spam shop link (raw IP) | LOW |

## Sending Infrastructure Correlation (from evidence only)

| Email | Domain | Sending IP | Mail/Web Co-location | PHPMailer |
|-------|--------|-----------|---------------------|-----------|
| E2 | meddefense-portal[.]com | 91.234.99.107 | Same domain serves mail + harvesting pages | 6.6.0 |
| E3 | outlook-protection[.]com | 51.38.42.17 | wp-admin origin host | 6.6.0 |
| E5 | medequip-supplies[.]net | 185.176.43.22 | Same domain serves mail + pay portal | 6.6.0 |
| E7 | meddefense-benefits[.]org | 164.90.218.73 | wp-portal origin host | 6.6.0 |
| E6 | canadian-pharma-discount[.]org | 203.0.113.228 | Single raw-IP host | XPedia Bulk Mailer |

Each suspicious domain serves as both mail origin and phishing web host, minimizing attacker infrastructure footprint. The domain keywords portal, protection, supplies, and benefits match the naming convention described in the sector advisory carried in E8.

Recommended immediate actions: blocklist the four domains and five sending IP addresses at the mail gateway and DNS/proxy layers, retain the defanged indicators for IOC submission, and verify domain registration ages via passive WHOIS/RDAP services to substantiate the newly-registered-domain attribution before submitting IOCs externally.

================================================================================
