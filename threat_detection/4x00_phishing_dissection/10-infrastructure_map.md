# 10-infrastructure_map.md

**Name:** Infrastructure Map

**Purpose:** Map the attack infrastructure behind the suspicious emails, connecting
          domains, IPs, hosting patterns, mailer fingerprints and targeting
          
**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — ATTACK INFRASTRUCTURE MAP

Evidence basis: Email evidence batch, reports 1-9 (header analysis, URL autopsy,

attachment analysis, campaign thread). No live DNS, certificate transparency or

SIEM access was used or required. All facts below derive from the raw batch and

prior documented analysis; anything inferred is labeled as such.

================================================================================

## 1. Campaign Infrastructure Table

| Domain | Source Email | Sender Address | IP (from Received headers) | Registration Timing | Registrar / Hosting | Mailer Software |
|--------|-------------|-----------------|---------------------------|---------------------|--------------------|------------------|
| meddefense-portal[.]com | E2 | noreply@meddefense-portal[.]com | 91.234.99.107 (mail.meddefense-portal.com) | Not provided by batch. INFERRED: newly registered — matches HC3 "<30 days" pattern (E8) and lookalike-construction logic | Not provided by batch. Sending profile (PHPMailer + localhost injection on single host serving mail AND harvesting pages) is consistent with budget VPS hosting per the HC3 alert description | PHPMailer 6.6.0 |
| outlook-protection[.]com | E3 | security@outlook-protection[.]com | 51.38.42.17 (mail.outlook-protection.com) | Not provided by batch. INFERRED: newly registered lookalike per same HC3 pattern | Not provided by batch. Origin hostname wp-admin.outlook-protection.com suggests a WordPress-configured VPS. Only campaign member that negotiated TLS (1.2) on the origin-to-MX hop | PHPMailer 6.6.0 |
| medequip-supplies[.]net | E5 | invoices@medequip-supplies[.]net | 185.176.43.22 (mail.medequip-supplies.net) | Not provided by batch. INFERRED: newly registered per HC3 pattern; consistent with wkhtmltopdf invoice generated 1 second before send | Not provided by batch. Same single-host mail/web co-location profile; budget VPS consistent with HC3 description | PHPMailer 6.6.0 |
| meddefense-benefits[.]org | E7 | hr-notifications@meddefense-benefits[.]org | 164.90.218.73 (mail.meddefense-benefits.org) | Not provided by batch. INFERRED: newly registered per HC3 pattern | Not provided by batch. Origin hostname wp-portal.meddefense-benefits.org echoes E3's wp- prefix, suggesting WordPress/VPS configuration | PHPMailer 6.6.0 |
| (reference) canadian-pharma-discount[.]org | E6 | deals@canadian-pharma-discount[.]org | 203.0.113.228 (bulk-mail-07) | Not relevant — classified as unrelated spam | Single raw-IP host acting as both mail and web server; irrelevant to campaign correlation | XPedia Bulk Mailer 4.2 (NOT PHPMailer) |
| (reference) hhs.gov | E8 | HC3@hhs.gov | 134.174.47.82 | N/A — legitimate government domain, used as the comparison baseline | HHS Secure Mail Gateway; TLS1.3 relay; full DKIM (selector hhs2026) | HHS Secure Mail Gateway (not PHPMailer) |

Note on registration data: the evidence batch contains no WHOIS records, so all registration timing above is INFERENCE from the HC3 advisory's newly-registered-domain pattern (E8) rather than documented fact. Live RDAP/WHOIS lookups remain the recommended follow-up to convert these inferences into confirmed data points.

---

## 2. Relationship Map

<pre>
                    SINGLE CAMPAIGN OPERATOR (PHPMailer 6.6.0 TEMPLATE FAMILY)
                                        |
        +-------------------------------+---------------------------+
        |                               |                           |
   CLUSTER A                      CLUSTER A                   CLUSTER A
  (MedDefense lookalikes)    (vendor fraud lookalike)   (brand impersonation)
        |                               |                           |
 meddefense-portal[.]com      medequip-supplies[.]net   outlook-protection[.]com
  E2, sent 04-14 14:47 CDT     E5, sent 04-16 11:28 CDT   E3, sent 04-15 09:13 CDT
  IP 91.234.99.107             IP 185.176.43.22           IP 51.38.42.17
  = meddefense-benefits[.]org  + INV-2026-04891.pdf        + wp-admin origin host
  E7, sent 04-16 15:22 CDT       (wkhtmltopdf 0.12.6,        + TLS 1.2 origin hop
  IP 164.90.218.73                embedded pay URI)          + SPF/DKIM/DMARC PASS
  + wp-portal origin host                                    for attacker's own domain
        |                          |                            |
        +-----------+--------------+------------+---------------+
                    |              |            |               |
              SHARED ATTRIBUTES ACROSS ALL FOUR DOMAINS:
              * X-Mailer: PHPMailer 6.6.0 (identical version string)
              * Message-ID format: PHP-{hex}@domain
              * Localhost (127.0.0.1) injection hop in Received chain
              * Mail and phishing web servers co-located on same domain
              * Lookalike/impersonation domains (portal/supplies/benefits/protection)
              * Urgency deadlines with threatened consequences (24h / 48h / 7d / midnight)
              * Role-targeted personalization (clinical, AP, HR, general M365)
                    |
              TARGET SEGMENTATION:
              E2 -> Diane Marsh, Clinical/Nursing (WS-NURSE-04)
              E5 -> Angela Rivera, Accounts Payable
              E7 -> Linda Patterson, Billing/HR
              E3 -> Rafael Mendez, general M365 user
                    |
       OUTSIDE THE CAMPAIGN (differentiator):
       E6 canadian-pharma-discount[.]org / 203.0.113.228
         - XPedia Bulk Mailer (not PHPMailer), raw-IP link, no lookalike
         - no urgency, no personalization, no role targeting => SPAM, unrelated
</pre>

---

## 3. Pattern Analysis

**Which domains are connected to the same campaign:**

meddefense-portal[.]com, medequip-supplies[.]net, meddefense-benefits[.]org and outlook-protection[.]com are connected by an identical low-level tooling signature that is very unlikely to arise by coincidence across independent actors: the same PHPMailer 6.6.0 version string, the same PHP-{hex} Message-ID construction, and the same localhost-injection Received hop. On top of the tooling fingerprint, all four share strategic patterns — lookalike or impersonation domains, urgency deadlines, role-segmented targeting, and single-domain mail/web co-location. Three of the four also fail authentication outright; the fourth (E3) passes authentication for its own attacker-controlled domain while impersonating Microsoft, a distinct technique within the same operation.

Within the four, the strongest bond is between the two MedDefense lookalikes (E2 and E7): both append a hyphen-keyword to the meddefense brand string, both use .com/.org variants, both impersonate internal MedDefense functions (IT security, HR benefits), and both target staff whose roles match their lures.

**Which domain may be less directly connected:**

outlook-protection[.]com (E3) is the least directly connected member. It impersonates an external brand (Microsoft) rather than MedDefense, it is the only campaign member that passed SPF/DKIM/DMARC (meaning its operator invested in configuring authentication, unlike the operators of E2/E5/E7 which show no authentication at all), and it is the only one that negotiated TLS on the origin-to-MX hop. Its link to the campaign rests on the PHPMailer 6.6.0 fingerprint, Message-ID format, localhost injection hop, urgency pretext, and the wp- prefix hostname echoing E7's wp-portal host. That is a strong tooling match but the divergence in authentication hygiene and branding could also fit a scenario where the same toolkit or kit seller supplied multiple operators. The evidence cannot definitively resolve one-operator versus kit-sharing; the moderate position is "same toolkit, likely same operation, lower confidence than the E2/E5/E7 core."

medequip-supplies[.]net (E5) sits in the middle: it is in the core PHPMailer cluster and its domain follows the "supplies" keyword pattern from the HC3 alert, but its lure genre (invoice fraud / BEC) differs from the credential-harvesting genre of E2 and E7. Its harvesting page URL structure (/portal/login, /invoices/pay) and the wkhtmltopdf-generated invoice nonetheless tie it to the same scripted, single-server infrastructure profile.

**Why timing, role targeting, urgency and mailer software matter:**

Tooling fingerprints (mailer software, Message-ID format, injection architecture) are the strongest connectors because they are incidental artifacts an attacker rarely varies and rarely fakes — two independent spammers hitting the exact same library version and header construction by chance is improbable. Timing establishes operational coherence: three waves across 57 hours (Day 1 clinical, Day 3 AP then HR) suggest a deliberate sequencing of target cohorts rather than simultaneous blast, consistent with an operator pacing deliveries to manage harvest queues. Role targeting shows intelligence investment: knowing that Diane Marsh uses the scheduling system and EHR gateway, that Angela Rivera processes invoices, and that Linda Patterson handles enrollment requires organizational knowledge (directory access, prior breach data, or LinkedIn/public scraping), which separates a targeted operation from commodity phishing. Urgency structures serve the same operational goal across all four domains — compressing the victim's decision window below the threshold where verification habits engage. Together, shared tooling plus shared tradecraft plus coherent sequencing is what distinguishes "coordinated campaign" from "similar-looking spam."

---

## 4. Final Assessment

**Classification of the infrastructure:**

Disposable, purpose-built attacker infrastructure. The evidence does NOT support compromised infrastructure (no hijacked legitimate domains: every campaign domain is a lookalike the attacker registered, and none of the sending mail servers correspond to any legitimate organization's known infrastructure). Nor does it support abuse of legitimate shared infrastructure (there is no evidence of a compromised marketing platform, ESP, or open relay; the mail origins are self-hosted PHPMailer stacks injected via localhost, and the HC3 alert independently describes this exact budget-VPS PHPMailer profile for the regional campaign).

**Confidence: HIGH that the infrastructure is disposable, attacker-owned, campaign-specific.**

Supporting evidence:

1. All four domains are lookalike or impersonation constructs — a registration pattern characteristic of attacker-purchased domains, not legitimate businesses or compromised accounts
2. Each domain co-locates its mail server and its phishing web content on the same host, a hallmark of single-purpose disposable servers rather than shared commercial infrastructure
3. The identical PHPMailer 6.6.0 / PHP-{hex} Message-ID / localhost-injection fingerprint across four domains reflects scripted stand-up of parallel disposable servers from a common template, not organic independent senders
4. The HC3 advisory (E8) independently corroborates the profile: newly-registered keyword domains, PHPMailer on budget VPS hosting, regionally targeting healthcare organizations — matching MedDefense's observed evidence on every element
5. The negative evidence is equally telling: no legitimate corporate mail platform fingerprints (no Exchange, M365, or Google Workspace signatures), no TLS discipline on three of four origin hops, and no authentication configuration on three of four domains — inconsistent with anyone operating production mail infrastructure they intended to keep

**Residual uncertainty, for honesty of record:** the registrar/hosting provider for each domain is not documented in the batch (the HC3 alert names budget-tier providers generically, and the sending IPs' allocations would need live RIR lookups to attribute). The registration dates are inferred from the HC3 pattern, not observed. The single-operator versus shared-kit question for E3 remains open. These gaps do not affect the disposable-infrastructure verdict but limit any finer-grained attribution.

**Recommended verification steps (passive, non-intrusive):** RDAP/WHOIS lookups for the four domains to confirm registration dates and registrars; passive DNS and ASN lookups for the four sending IPs to confirm hosting providers; certificate transparency (crt.sh) searches to establish TLS issuance timelines — all of which convert the inferences in the table above into confirmed evidence suitable for the HC3 IOC submission described in E8.

================================================================================
