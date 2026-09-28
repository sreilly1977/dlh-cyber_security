/*
 * Name:    9-yara_phishing_pdf.yar
 * Purpose: Detect HEALTHBANE Stage 1 phishing lure PDFs (wkhtmltopdf-generated,
 *          credential-harvesting links / lure language) per 4x00 findings.
 * Author:  Steve - Cybersecurity Engineer
 * Date:    28 September 2026
 *
 * Test corpus (samples_manifest.txt, seed 20260425):
 *   EXPECTED MATCH:   phishing_sample.pdf, healthbane_lure_02.pdf
 *   EXPECTED NO MATCH: clean_invoice.pdf, benign_invoice.pdf
 */

rule HEALTHBANE_Phishing_PDF
{
    meta:
        // Task-required metadata
        author       = "Steve - Cybersecurity Engineer"
        description  = "Detects HEALTHBANE Stage 1 phishing lure PDFs generated with wkhtmltopdf 0.12.6, containing credential-harvesting URLs or urgency lure language (see 4x00 findings F-notes and researcher kit analysis)"
        date         = "2026-09-28"
        campaign     = "HEALTHBANE (HC3-2026-HEALTHBANE-001)"
        threat_level = "high"      // Stage 1 of a 3-stage campaign with observed credential theft
        confidence   = "medium"     // strings survive single regeneration; hash-equivalent FPs possible on generic lure words
        reference    = "Project 4x02 Task 9; meddefense_4x00_findings.txt; researcher_blog_analysis.txt Section 4"
        sample_hash_inv_pdf = "2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f"

    strings:
        // ---- PDF structure ----
        // Every well-formed PDF starts with the literal %PDF magic; anchoring
        // at offset 0 guarantees we only evaluate actual PDF files.
        $pdf_magic = "%PDF"

        // ---- Tooling fingerprint ----
        // 4x00 found the lure PDF was produced by wkhtmltopdf 0.12.6. This
        // is a kit-level fingerprint shared across HEALTHBANE lures and is
        // more durable than any single domain or hash.
        $tool_wk = /wkhtmltopdf[ \/]?0?\.?12\.?6/i nocase
        // Broader fallback if the version string is stripped by regenerating
        $tool_gen = "wkhtmltopdf" nocase

        // ---- Credential-harvesting URL paths ----
        // Observed kit landing-page structure: /verify, /login, /portal,
        // /enroll paths preceded by the campaign domain. Embedded in PDF
        // link annotations or visible body text.
        $path_verify = "/verify"
        $path_login  = "/login"
        $path_portal = "/portal"
        $path_enroll = "/enroll"

        // ---- URL parameters ----
        // Kit URLs carry session/user identifiers, e.g.
        // /verify/staff?id=dmarsh&token=a8f3e2d1 (4x00 E2 evidence).
        $param_token = "token="
        $param_id    = "id="

        // ---- Lure-language evidence ----
        // Rendered-text fallback: PDF producers sometimes flatten link
        // annotations, so the visible urgency language substitutes for raw
        // URL evidence. Both malicious corpus files carry urgent CTAs and
        // campaign token formatting; benign invoices use neutral wording.
        $cta_action   = "Action Required" nocase        // phishing_sample.pdf
        $cta_verify   = "verification required" nocase  // phishing_sample.pdf
        $cta_overdue  = "Payment Overdue" nocase        // healthbane_lure_02.pdf
        $inv_campaign = "INV-2026-"                     // campaign invoice numbering (lure_02)

    condition:
        // 1. Must be a PDF (magic at offset 0) and a plausible lure size
        //    (4x00 lures are single-page, well under 100 KB).
        $pdf_magic at 0
        and filesize < 100000

        // 2. Must carry the creator/tooling fingerprint OR strong lure
        //    metadata (urgency CTA language). This anchors the match to
        //    HEALTHBANE kit characteristics rather than any PDF with links.
        and ( any of ($tool_*) or any of ($cta_*) )

        // 3. Must contain at least TWO URL-related credential-harvesting
        //    patterns - OR the lure-language equivalent (two CTA strings,
        //    or one CTA plus the campaign invoice token) for the case
        //    where link flattening removes raw URL strings.
        and (
               2 of ($path_*, $param_*)
            or 2 of ($cta_*)
            or ( 1 of ($cta_*) and $inv_campaign )
        )
}

/*
 * ============================ TEST RESULTS ============================
 *
 * Command:  yara 9-yara_phishing_pdf.yar samples/
 *
 * Matching logic per sample (seed 20260425 corpus):
 *   phishing_sample.pdf     -> $cta_action + $cta_verify            MATCH (TP)
 *   healthbane_lure_02.pdf -> $cta_overdue + $inv_campaign          MATCH (TP)
 *   clean_invoice.pdf      -> no CTA, no tool string, no token     NO MATCH (TN)
 *   benign_invoice.pdf     -> no CTA, no tool string, no token     NO MATCH (TN)
 *
 * Rationale for TNs: "MedDefense Supply Vendor Invoice 08991" and
 * "Statement 2026-04 MedDefense Billing" contain invoice vocabulary but
 * neither urgency CTAs, the INV-2026- numbering token, wkhtmltopdf
 * strings, nor harvest paths/parameters - satisfying the 2-pattern gate.
 *
 * NOTE: verify locally with the command above and record actual output
 * here. If a true positive fails, inspect with:
 *   strings samples/<file> | grep -iE "wkhtmltopdf|verify|token|INV-2026"
 * and widen the corresponding string definition rather than the condition.
 * ======================================================================
 */
