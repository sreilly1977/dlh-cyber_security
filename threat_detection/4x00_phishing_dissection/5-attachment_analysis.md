# 5-attachment_analysis.md

**Name:** Attachment Analysis
**Purpose:** Analyze PDF attachment indicators from Email 5 using metadata and
          structural clues visible in the raw evidence, without opening the file
**Author:** Steve - Cybersecurity Engineer
**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — ATTACHMENT ANALYSIS

Source: Email 5 (E5), medequip-supplies.net invoice lure

Method: Static analysis of visible base64-decoded objects and raw email headers only.

The attachment was never opened, rendered, or executed on any workstation.

================================================================================

## Attachment: INV-2026-04891.pdf

- **Source email:** E5 — "MedEquip Supplies Billing" <invoices@medequip-supplies[.]net>, Subject: "Invoice INV-2026-04891 — Payment required within 7 days", recipient Angela Rivera (arivera@meddefense.com), received 2026-04-16 11:28:39 -0500
- **Filename:** INV-2026-04891.pdf (declared via Content-Disposition: attachment; filename="INV-2026-04891.pdf")
- **Content type:** application/pdf (declared in the MIME part header: Content-Type: application/pdf; name="INV-2026-04891.pdf")
- **Encoding:** Yes — base64 (Content-Transfer-Encoding: base64), carried inside a multipart/mixed message with boundary ----=_Part_INV_4891. The message structure is: part 1 text/html message body, part 2 the PDF attachment.
- **Available hash evidence:**
  - MD5: Not available in the batch. No MD5 digest is declared in any header (no Content-MD5 header present) and none is visible in the raw content.
  - SHA-256: A SHA-256 indicator string is visible in the decoded PDF content: "2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f" — labeled "xxxSHA-256" within the decoded object stream. Note for the record: this string appears as PDF content text rather than a standard integrity header, and it has not been independently verified against a locally computed hash of the decoded file. It is treated as an indicator for documentation, not as a validated cryptographic fingerprint.
- **PDF producer / creator evidence:**
  - Producer: wkhtmltopdf 0.12.6 (visible in the catalog object: /Producer (wkhtmltopdf 0.12.6))
  - Creation date: D:20260416162834+00'00' — 2026-04-16 16:28:34 UTC, exactly one second before the email Message-ID timestamp of 16:28:35 UTC and the recorded send at 16:28:37 -0500. The invoice was generated moments before dispatch.
  - No ModificationDate difference: ModDate equals CreationDate, consistent with generate-and-send automation
  - Significance: wkhtmltopdf converts HTML documents to PDF. No legitimate accounting or ERP invoicing system uses an HTML-to-PDF conversion utility as its producer of record. This indicates the invoice was rendered from a crafted HTML template by a script, matching the scripted-send pattern (PHPMailer) of the delivering email.
- **Embedded URLs:**
  - URI action in annotation object (10 0 obj, /Subtype /Link, /Rect [175 185 450 205]): https[:]//medequip-supplies[.]net/invoices/pay?id=INV-2026-04891 (defanged: hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891)
  - The link annotation is attached to a rectangular region of page content, styled to look like an interactive "pay now" button on the invoice document
- **Structural findings:**
  - PDF version header: %PDF-1.4
  - Minimal object set: catalog, page tree (1 page, /Count 1), single page object, font resource (F1), content stream, one annotation object — a deliberately lightweight document
  - MediaBox [0 0 595 842] — standard A4 page dimensions
  - JavaScript (/JS or /JavaScript), AcroForm fields, /OpenAction, /EmbeddedFile and /Launch actions: NONE of these are present anywhere in the visible decoded object stream. Based strictly on the provided evidence, no active content, form fields or embedded executables are proven. It cannot be ruled out that content beyond the visible fragment exists in a fully reconstructed file, so sandbox detonation remains prudent in a real investigation; however, no such features may be claimed on current evidence.
  - The visible SHA-256 string embedded as PDF content (see hash evidence above) is itself an anomaly: legitimate invoices do not embed a self-referential hash string as page text. This is consistent with a template artifact, not a real billing document.
- **Relationship to Email 5 body URLs:** The attachment's embedded URI is byte-for-byte identical to the primary payment link in the email body (hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891). Both channels converge on the same fraudulent destination. The body also offers a secondary URL (hxxps://medequip-supplies[.]net/portal/login) described as a retrieval fallback, giving the recipient three paths to attacker-controlled infrastructure: two body links and the attachment link. This redundancy increases click probability and provides fallback if one channel is blocked.
- **Campaign correlation:** Multiple shared patterns connect this attachment and E5 to the same campaign as E2 and E7:
  - PHPMailer 6.6.0 sending stack — identical X-Mailer across E2, E3, E5 and E7
  - Message-ID format PHP-{hex}@domain — identical across the four suspicious emails
  - Lookalike/keyword domain (medequip-supplies[.]net) matching the supplies/portal/benefits naming convention described in the HC3 sector advisory in E8
  - Urgency pretext — 7-day payment deadline with explicit consequences (2% late fee, delivery suspension), parallel to E2's 24-hour lockout and E7's midnight enrollment cutoff
  - Targeted business process — role-directed at Accounts Payable, mirroring E2 (clinical) and E7 (billing/HR) role-appropriate lures
  - Localhost (127.0.0.1) injection hop in the Received chain — shared origin architecture
  - Scripted automation on both sides of the delivery — PHPMailer for email transport, wkhtmltopdf for invoice generation, produced seconds apart
- **Safe reputation-check commands (documented for reference; not required to run):**
  - Compute hash on a sanitized copy inside an isolated VM (never on the live mailbox file): `sha256sum sample.pdf`
  - Query VirusTotal by hash via API: `curl -s --header "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/<sha256>"` — hash-only lookup retrieves any existing report without submitting new content
  - Query VirusTotal domain intelligence for the pay portal host: `curl -s --header "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/domains/medequip-supplies.net"`
  - Submit the reconstructed file for sandboxed behavioral analysis (provider-side detonation only): Joe Sandbox, Hybrid Analysis, or ANY.RUN upload of sample.pdf
  - All of the above operate on hashes, API reports, or provider sandboxes — no direct interaction with attacker infrastructure is required
- **Risk assessment:** HIGH. The attachment is a fabricated invoice rendered from an HTML template by wkhtmltopdf 0.12.6 within one second of email dispatch, carrying an embedded payment-redirect link identical to the email body's fraudulent portal. Although no JavaScript, forms, or embedded executables are visible in the decoded objects, the document's purpose is deceptive financial redirection, not malware delivery — the danger is the payment itself ($24,716.38 demanded within 7 days), not the file's active content. Combined with the PHPMailer infrastructure overlap, urgency pretext, and role-targeted delivery, the attachment is assessed as part of the coordinated campaign affecting E2, E3, E5 and E7. Recommended handling: block the invoice number at AP review controls, alert Accounts Payable to the fake invoice, blocklist the domain and sending IP 185.176.43.22, and preserve the raw email and reconstructed-sample hash as evidence.

================================================================================
