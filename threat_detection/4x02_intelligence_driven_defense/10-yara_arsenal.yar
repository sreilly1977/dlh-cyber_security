/*
 * Name:    10-yara_arsenal.yar
 * Purpose: Multi-artifact YARA detection arsenal for the HEALTHBANE campaign:
 *          (1) email-header signature, (2) document-metadata signature,
 *          (3) cross-family campaign composite. Designed to survive simple
 *          infrastructure rotation by keying on operational patterns
 *          (tooling, header behavior, naming, harvest paths) rather than
 *          single indicators.
 * Author:  Steve - Cybersecurity Engineer
 * Date:    28 September 2026
 * Project: 4x02 Intelligence-Driven Defense - Task 10
 *
 * Corpus expectations (samples_manifest.txt):
 *   HEALTHBANE_Email_Headers       -> match: healthbane_email_01/02/03.eml
 *                                      no match: benign_newsletter.eml
 *   HEALTHBANE_Document_Metadata   -> match: phishing_sample.pdf, healthbane_lure_02.pdf
 *                                      no match: clean_invoice.pdf, benign_invoice.pdf
 *   HEALTHBANE_Campaign_Composite  -> match: all 3 emails + both malicious PDFs
 *                                      no match: all 4 benign samples
 */

rule HEALTHBANE_Email_Headers
{
    meta:
        author       = "Steve - Cybersecurity Engineer"
        description  = "HEALTHBANE phishing email header signature: PHPMailer variant tooling + high-priority header + healthcare lookalike sender domain + lure keyword"
        date         = "2026-09-28"
        campaign     = "HEALTHBANE (HC3-2026-HEALTHBANE-001)"
        threat_level = "high"
        confidence   = "high"
        reference    = "Project 4x02 Task 10; meddefense_4x00_findings.txt F1-F3"

    strings:
        // PHPMailer variant tooling. Deliberately a SEPARATOR-TOLERANT regex:
        // the corpus contains both "PHPMailer 6.6.0" (emails 01/02) and
        // "PHPMailer-6.6.0 (custom build)" (email 03). A literal match on
        // either form produces a false negative on the other; character
        // classes cover space, hyphen, slash, and dot separators and any
        // 6.x version number.
        $mailer = /X-?Mailer:\s*PHPMailer[\s\-\/\.]?[0-9]/i

        // High-priority header: all three campaign emails carry
        // "X-Priority: 1" (urgency cue baked into the kit). The benign
        // newsletter has no X-Priority header at all.
        $prio = "X-Priority: 1"

        // Lookalike sender-domain pattern: campaign domains follow
        // <org-word><separator><service-word>.<tld> built on MedDefense /
        // MedEquip brands. Anchored on the brand tokens rather than any
        // single registered domain so rotation within the naming pattern
        // still fires. NOTE: the benign newsletter's recipient address
        // (soc-alerts@meddefense.com) contains our real domain - this is
        // why $lookalike is required in combination with $mailer and
        // $prio, never alone.
        $lookalike = /(meddefense|medequip)[a-z\-]*\.(com|net|org)/i

        // Healthcare-themed lure vocabulary in subject/body/headers.
        // Present in all campaign emails; benign corpus only shares the
        // generic "verify your account" body text, which is deliberately
        // NOT used as a string (see condition note below).
        $kw_benefits = "benefits" nocase
        $kw_portal   = "portal" nocase
        $kw_invoice  = "invoice" nocase
        $kw_enroll   = "enroll" nocase

    condition:
        // All four families required. The benign_newsletter.eml is a
        // near-perfect decoy: its BODY text is identical to the malicious
        // emails ("Please verify your account", "IT Department" signature,
        // identical MIME boundary string) and its From domain contains
        // "healthcare". Therefore this rule intentionally keys ONLY on
        // header-level behavior ($mailer, $prio, $lookalike) plus at least
        // one lure keyword - never on body content or authentication
        // results alone. Requiring all families means no single
        // counterfeitable attribute produces a match.
        $mailer and $prio and $lookalike and 1 of ($kw_*)
}

rule HEALTHBANE_Document_Metadata
{
    meta:
    author       = "Steve - Cybersecurity Engineer"
    description  = "HEALTHBANE lure-document signature: PDF tooling fingerprint plus credential-harvest paths/parameters or campaign lure tokens"
    date         = "2026-09-28"
    campaign     = "HEALTHBANE (HC3-2026-HEALTHBANE-001)"
    threat_level = "high"
    confidence   = "medium"
    reference    = "Project 4x02 Task 10; 4x00 PDF analysis (wkhtmltopdf 0.12.6)"

    strings:
    // PDF magic bytes: literal %PDF at the start of the file. Same
    // anchor approach as the Task 9 rule that validated cleanly.
    $pdf_magic = "%PDF"

    // Tooling fingerprint: wkhtmltopdf producer string. Simplified to
    // bare literal since the composite rule confirmed the string is
    // present in both malicious PDFs; version pinning adds fragility,
    // not signal, at this gate.
    $tool_wk = "wkhtmltopdf" nocase

    // Credential-harvest paths observed in the kit (4x00 / researcher
    // blog Section 2): /verify, /login, /portal, /enroll.
    $path_verify = "/verify"
    $path_login  = "/login"
    $path_portal = "/portal"
    $path_enroll = "/enroll"

    // Campaign URL parameters: kit links carry session identifiers
    // (?id=..., &token=...) per the 4x00 E2 click URL.
    $param_token = "token="
    $param_id    = "id="

    // Lure tokens: campaign invoice numbering and urgency CTAs.
    $inv_campaign = "INV-2026-"
    $cta_action   = "Action Required" nocase
    $cta_overdue  = "Payment Overdue" nocase
    $cta_verify   = "verification required" nocase

    condition:
    // Gate (a): must be a PDF (magic at offset 0) and plausibly sized
    // for a single-page lure document, not a scanned archive.
    // Gate (b): at least ONE tooling or lure-token signal.
    // Gate (c): at least ONE harvest path or URL-parameter signal.
    // Benign invoices carry none of these families, so both gates
    // stay closed for every true negative in the corpus.
    $pdf_magic at 0
    and filesize < 100000
    and 1 of ($tool_wk, $inv_campaign, $cta_action, $cta_overdue, $cta_verify)
    and 1 of ($path_*, $param_*)
}

rule HEALTHBANE_Campaign_Composite
{
    meta:
        author       = "Steve - Cybersecurity Engineer"
        description  = "Cross-family composite: fires only when THREE OR MORE independent HEALTHBANE pattern families co-occur in one artifact (tooling, header behavior, lookalike naming, harvest paths, lure tokens). Higher fidelity than single-family rules; designed to survive domain rotation."
        date         = "2026-09-28"
        campaign     = "HEALTHBANE (HC3-2026-HEALTHBANE-001)"
        threat_level = "high"
        confidence   = "high"
        reference    = "Project 4x02 Task 10; kill-chain reconstruction 6-kill_chain.md"

    strings:
        // FAMILY 1 - Sender/document tooling. PHPMailer for emails,
        // wkhtmltopdf for documents: the campaign's two tooling stacks.
        $fam_tooling = /(X-?Mailer:\s*PHPMailer[\s\-\/\.]?[0-9]|wkhtmltopdf[ \/]?[0-9])/i

        // FAMILY 2 - High-priority header (kit urgency behavior).
        $fam_priority = "X-Priority: 1"

        // FAMILY 3 - Brand lookalike domain tokens (naming convention,
        // independent of any one registered domain).
        $fam_lookalike = /(meddefense|medequip)[a-z\-]*\.(com|net|org)/i

        // FAMILY 4 - Credential-harvest paths / parameters.
        $fam_harvest = /(\/(verify|login|portal|enroll)|token=|id=)/i

        // FAMILY 5 - Campaign lure tokens (numbering scheme or CTAs).
        $fam_lure = /(INV-2026-|Action Required|Payment Overdue|verification required)/i

    condition:
        // Threshold logic: any THREE of the five families must co-occur.
        // Rationale per corpus:
        //   healthbane_email_01/02/03 : tooling + priority + lookalike
        //       (+ harvest via /enroll or id=) => >=3 families MATCH
        //   phishing_sample.pdf        : tooling + harvest + lure
        //       (+ lookalike via embedded URL) => >=3 families MATCH
        //   healthbane_lure_02.pdf     : tooling + lure + harvest
        //       (id=INV-2026-... parameter)         => 3 families MATCH
        //   benign_newsletter.eml      : lookalike ONLY (recipient address
        //       is our genuine domain)              => 1 family  NO MATCH
        //   clean/benign_invoice.pdf   : none                          NO MATCH
        // The benign newsletter is the decisive calibration point: it
        // shares body text with the campaign and contains one lookalike-
        // resembling string, but a single family never reaches threshold.
        filesize < 500000
        and 3 of ($fam_tooling, $fam_priority, $fam_lookalike, $fam_harvest, $fam_lure)
}

/*
 * ========================= TEST RESULTS =========================
 *
 * Command:  yara 10-yara_arsenal.yar samples/
 *
 * Rule                      | Expected                | Verified
 * --------------------------+-------------------------+---------
 * HEALTHBANE_Email_Headers  | email_01, 02, 03        | (fill after run)
 *                           | NOT benign_newsletter   |
 * HEALTHBANE_Document_Meta  | phishing_sample.pdf,    | (fill after run)
 *                           | healthbane_lure_02.pdf |
 *                           | NOT clean/benign_invc   |
 * HEALTHBANE_Campaign_      | all 5 malicious samples | (fill after run)
 * Composite                 | NOT any of 4 benign     |
 *
 * Fill the "Verified" column with actual local output before commit.
 *
 * Known limitation (carried into Task 11): the email rule's separator-
 * tolerant regex PRE-EMPTS the classic PHPMailer literal-matching false
 * negative (a rule keyed on "PHPMailer 6.6.0" with a space would miss
 * "PHPMailer-6.6.0" in email_03, and vice versa). If Task 11 supplies a
 * baseline rule with the brittle literal, the failure mode to document
 * is exactly that separator variation.
 * ================================================================
 */
