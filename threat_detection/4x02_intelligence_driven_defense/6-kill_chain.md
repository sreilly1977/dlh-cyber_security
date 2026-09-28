================================================================================

  HEALTHBANE KILL CHAIN RECONSTRUCTION
  
  Project 4x02 - Intelligence-Driven Defense
  
================================================================================

Document ID:      MD-4x02-KILLCHAIN-001

Analyst:          Steve - Cybersecurity Engineer

Date:             2026-09-28

Classification:   INTERNAL

Input Sources:    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt,
                  researcher_blog_analysis.txt,
                  meddefense_4x00_findings.txt,
                  commercial_feed_extract.json

================================================================================

1. CAMPAIGN TIMELINE

================================================================================

The timeline below integrates direct observation dates from HC3 (victim-side
telemetry), researcher blog (attacker-side kit discovery), commercial feed
(metadata timestamps), and MedDefense internal findings (local incident).
Where dates overlap across sources, corroboration strengthens confidence.

<pre>
+--------------------------------------------------------------------------+
|                        HEALTHBANE CAMPAIGN TIMELINE                       |
+--------------------------------------------------------------------------+

2026-03-24  | EARLIEST KNOWN INFRASTRUCTURE
            | Commercial feed shows 51.38.42.191 first_seen date
            | Confirmed as C2 IP by HC3 and researcher
            | [CONFIDENCE: HIGH] Source: commercial_feed metadata

2026-03-28  | PREVIOUS CAMPAIGN ACTIVITY (POSSIBLE)
            | rx-benefits-portal.com registered/active
            | Commercial feed notes "predates HEALTHBANE window by 16 days"
            | Same Namecheap+OVH pattern as main campaign
            | [CONFIDENCE: LOW] Single-source clustering; unconfirmed

2026-03-30  | ANOTHER PREVIOUS CAMPAIGN DOMAIN
            | healthcare-login.com first_seen per commercial feed
            | Sinkholed 2026-04-18 per Acme metadata
            | [CONFIDENCE: LOW] Historical correlation only

2026-04-02  TO  2026-04-10  | PHISHING DOMAIN REGISTRATION BURST
            | Namecheap registration window for primary domains
            | 2026-04-08: medequip-supplies.net registered (Internal 4x00 F2)
            | 2026-04-09: meddefense-portal.com registered (Internal 4x00 F2)
            | 2026-04-10: meddefense-benefits.org registered (Internal 4x00 F2)
            | Let's Encrypt certificates issued 1-7 days before first use
            | [CONFIDENCE: HIGH] Four-way corroboration (HC3 + Researcher
            |                   + Commercial + Internal 4x00)

2026-04-05  | VERIFY-HEALTH-PORTAL.NET REGISTERED
            | Matches naming pattern but no observed phishing activity
            | Commercial feed only; single-source
            | [CONFIDENCE: LOW] Contextual, not operationalized

2026-04-08  TO  2026-04-10  | LET'S ENCRYPT CERTIFICATE ISSUANCE
            | Certificates issued for phishing LP domains
            | Pattern: issued shortly before domain registration completed
            | Researcher confirms certificate pattern in Section 4
            | [CONFIDENCE: MEDIUM] Single-source (researcher blog)

2026-04-14  TO  2026-04-16  | STAGE 1: INITIAL PHISHING WINDOW
            | Earliest phishing email observed by HC3 (Section 1.2)
            | MedDefense receives cluster of 8 inbound emails (Internal 4x00)
            | 2026-04-14 15:02:33 UTC: dmarsh clicks phishing link (Internal 4x00)
            | 2026-04-14 15:02:58 UTC: credential submission assessed (Internal 4x00)
            | Emails E2, E5, E7 identified as campaign-related (Internal 4x00)
            | 3 of 8 emails = coordinated phishing campaign (Internal 4x00)
            | [CONFIDENCE: HIGH] Direct MedDefense observation; HC3 corroboration

2026-04-14  15:02:33 UTC  | MEDI DEFENSE SPECIFIC INCIDENT
            | Nurse Diane Marsh (WS-NURSE-04, 10.10.2.15) clicks email E2
            | URL: https://meddefense-portal.com/verify/staff?id=dmarsh
            | SIEM log shows 47-second HTTPS session to landing page
            | [CONFIDENCE: HIGH] Direct observation
            | [NOTE] Credential submission "LIKELY" but NOT confirmed via
            |        packet capture at time of 4x00 closure (deferred to 4x01)

2026-04-15  TO  2026-04-16  | ADDITIONAL PHISHING EMAILS DELIVERED
            | Email E5 sent to arivera (accounts payable) - did NOT click
            | Email E7 sent to lpatterson (billing) - did NOT click
            | [CONFIDENCE: HIGH] Internal 4x00 header analysis

2026-04-16  TO  2026-04-22  | STAGE 2: MALWARE DELIVERY WINDOW (HC3-VISIBLE ORGS)
            | Attacker uses stolen credentials to authenticate to cloud email
            | Follow-up emails sent FROM compromised accounts to colleagues
            | Attachments: .docm file (HEALTHBANE_S2_invoice.docm)
            | Macro pulls Windows executable (svchost_update.exe) from C2
            | Persistence via scheduled task "HealthSync Update Service"
            | Persistence via Registry Run key
            | Observed at 2 of 6 HC3-visible organizations (33% conversion)
            | [CONFIDENCE: HIGH] HC3 sandbox analysis + 2 org packet captures
            | [CONFIDENCE: LOW] Not observed at MedDefense (stopped at Stage 1)

2026-04-16  | FIRST MACRO DOCUMENT HASH APPEARANCE
            | a1b2c3d4... (HEALTHBANE_S2_invoice.docm) first_seen per commercial feed
            | b9c8a7d6... (svchost_update.exe) first_seen per commercial feed
            | [CONFIDENCE: MEDIUM] Commercial feed metadata; corroborated by HC3
            |                    but not by MedDefense local telemetry

2026-04-18  | POWERSHELL EXFIL SCRIPT HASH APPEARANCE
            | c7d6e5f4... (sync_healthdata.ps1) first_seen per commercial feed
            | Researcher extracts from kit's tools/ directory
            | [CONFIDENCE: MEDIUM] Cross-source (HC3 + Commercial + Researcher)

2026-04-22  TO  2026-04-24  | STAGE 2 ENDPOINTS OBSERVED
            | 45.77.218.9 (Brazil) active 2026-04-16 to 2026-04-24
            | update-healthbane.net active 2026-04-16 to 2026-04-24
            | [CONFIDENCE: MEDIUM] Single-partner observation at HC3

2026-04-23  TO  2026-04-26  | STAGE 3: DATA EXFILTRATION WINDOW
            | DNS TXT-record tunneling begins (HC3 Section 2)
            | Exfiltration to data-sync.healthbane-c2.net
            | Base32 subdomain labels 44-60 characters
            | Query interval 10-15 seconds
            | Patient and insurance records targeted
            | Insurance claims data targeted
            | Observed at 2 of 6 HC3-visible organizations (33%)
            | [CONFIDENCE: HIGH] Packet captures from 2 compromised orgs
            | [CONFIDENCE: LOW] Not observed at MedDefense

2026-04-23  | DATA-SYNC SUBDOMAIN ACTIVE
            | data-sync.healthbane-c2.net first_seen per commercial feed
            | [CONFIDENCE: HIGH] HC3 confirms DNS tunnel endpoint in Section 3

2026-04-24  | RESEARCHER BLOG PUBLISHED
            | Marcus Weller posts kit analysis (Section 1)
            | Delays publication 72 hours per HC3 request
            | Discovers kit via directory traversal on misconfigured endpoint
            | [CONFIDENCE: HIGH] Public documentation; HC3 coordination confirms
            |                    researcher notified HC3 2026-04-22

2026-04-24  TO  2026-04-26  | PORTAL-SECURE-MEDEFENSE.COM STAGING
            | Researcher discovers same kit staged on portal-secure-meddefense.com
            | Not yet active at time of blog post
            | [CONFIDENCE: MEDIUM] Single-source (researcher); not yet observed

2026-04-25  | HC3 ADVISORY PUBLISHED
            | HC3-2026-HEALTHBANE-001 released TLP:CLEAR
            | Designates campaign HEALTHBANE
            | Does not endorse commercial VITALSCORE label
            | Attribution: UNCONFIRMED
            | 23 indicators published (HC3 Section 3)
            | [CONFIDENCE: HIGH] Government sector advisory; TLP:CLEAR

2026-04-26  | COMMERCIAL FEED EXTRACT
            | Acme feed extract ACME-HEALTH-2026-0426-117
            | 41 indicators tagged VITALSCORE
            | Explicit noise flags included
            | [CONFIDENCE: MEDIUM] Proprietary feed; SAMPLED analyst review

2026-04-26  | MOST RECENT REPORTED EVENT
            | Latest last_seen date across all indicators (per commercial feed)
            | Campaign still active at time of extract
            | Next HC3 update scheduled 2026-05-09 (Section 8)

2026-05-09  | ANTICIPATED HC3 UPDATE
            | Next scheduled advisory update per Section 8
            | May incorporate additional partner observations
            | May address attribution if new evidence emerges
            | [CONFIDENCE: MEDIUM] Scheduled date; content uncertain
</pre>

================================================================================

2. ATTACK PHASE ANALYSIS

================================================================================

--------------------------------------------------------------------------------

2.1 STAGE 1: CREDENTIAL HARVESTING

--------------------------------------------------------------------------------

PHISHING OPERATION

------------------

Method:           Spear-phishing emails impersonating healthcare-adjacent senders
                  (staff portal, insurance, HR benefits)
                  
Delivery Vector:  Email to targeted individuals within victim organizations

Initial Access:   T1566.002 Spearphishing Link (primary)
                  T1566.001 Spearphishing Attachment (for PDF lure variant)

Targeting Pattern:

-----------------

Geographic Focus: US healthcare providers, strongest signal in Midwest ISAC

Sector Breakdown: Hospital systems, outpatient clinics, medical billing services,
                  regional insurance administrators
                  
NOT Observed:     Medical device manufacturers, pharmacies, public health depts

Lookalike Domain Strategy:

  - Namecheap registrar (low-cost, widely accepted)
  
  - Naming pattern: <org-name>-<service>.(com/net/org)
  
  - Registration burst: 4-10 days before first email (Internal 4x00 F2)
  
  - Let's Encrypt certificates issued 1-7 days pre-use (Researcher Section 4)
  
  - PHPMailer 6.6.0 X-Mailer header (consistent across all three 4x00 emails)

Two Variants Observed:

Variant A - Standard Lookalike (3 emails in 4x00):

  - meddefense-portal.com (E2, clicked)
  
  - medequip-supplies.net (E5, not clicked)
  
  - meddefense-benefits.org (E7, not clicked)
  
  - SPF fail / softfail, DKIM none, DMARC fail
  
  - PHPMailer 6.6.0 X-Mailer header (with minor formatting variation in E7)

Variant B - High-Sophistication Impersonation (4x00 F3):

  - outlook-protection.com
  
  - Passes SPF/DKIM/DMARC (attacker correctly configured DNS for lookalike)
  
  - Microsoft visual impersonation
  
  - Higher-sophistication technique per researcher config.php recovery
  
  - Kit SMTP exfil route via handler/post.php

Infrastructure Used (Stage 1):

-------------------------------

<pre>
Domain            | Registrar | Host / ASN             | Role
------------------|-----------|------------------------|--------------------
meddefense-       | Namecheap | 91.234.99.107          | Phishing LP + SMTP
portal.com        |           | AS47583 (Hostinger)    |
medequip-         | Namecheap | 185.176.43.22          | Phishing LP + SMTP
supplies.net      |           | AS47583 (Hostinger)    |
meddefense-       | Namecheap | 164.90.218.73          | Phishing LP + SMTP
benefits.org      |           | AS14061 (DigitalOcean) |
outlook-          | Njalla    | 51.38.42.17            | MS-impersonation LP
protection.com    |           | AS16276 (OVH)          |
portal-secure-    | Namecheap | 92.118.232.14          | Staged rotation LP
meddefense.com    | (inferred)| AS47583 (Hostinger)    | (kit staged, not live)
</pre>

Known Victims:

---------------

HC3 Sector Reporting (Section 1):

  - At least 14 US healthcare organizations targeted
  
  - 6 of 14 with HC3 direct/partner visibility
  
  - Stage 1 observed at ALL 6 HC3-visible organizations (100%)

MedDefense Internal (4x00):

  - Three staff received campaign emails: dmarsh (nurse), arivera
    (accounts payable), lpatterson (billing)
    
  - One credential exposure event (dmarsh)

Success Rate Across Reported Victims:

--------------------------------------

Data available:

  - HC3: Stage 1 occurred at 6 of 6 visible orgs (100% reach)
  
  - HC3: Stage 1 -> Stage 2 progression at 2 of 6 orgs (33%)
  
  - MedDefense: 1 click of 3 recipients (33% user click rate)
  
  - MedDefense: 0 of 1 exposures progressed to Stage 2 (stopped by user
    report + fast investigation)

Assessment (ASSESSMENT, not fact): The 33% click rate observed at
MedDefense over a small sample (3 emails) is consistent with typical
healthcare spear-phishing click rates, but the sample size is far too
small for statistical inference. The HC3-visible cohort shows a 33%
Stage 1 -> Stage 2 conversion rate, which is the more operationally
meaningful figure.

MedDefense Evidence:

--------------------

  - 8 inbound emails reviewed, 3 determined part of campaign (4x00)
  
  - Header analysis: shared PHPMailer 6.6.0 X-Mailer, Namecheap domains,
    authentication failures (Internal F1)
    
  - Registration timing 4-10 days pre-email (Internal F2)
  
  - Variant B (outlook-protection.com) identified as higher sophistication
    (Internal F3)
    
  - Recipient analysis: dmarsh (clicked E2), arivera (did not click E5),
    lpatterson (did not click E7) (Internal F4)
    
  - Credential submission LIKELY for dmarsh: 47-second HTTPS session,
    no Sysmon Event 11 (no file download), user self-report; NOT confirmed
    by packet capture at 4x00 close (Internal F5)
    
  - No post-compromise authentication observed for dmarsh in window
    (Internal F6)

--------------------------------------------------------------------------------

2.2 STAGE 2: MALWARE DELIVERY

--------------------------------------------------------------------------------

Transition From Stolen Credentials to Follow-Up Emails:

-------------------------------------------------------

Method: Stage 1 credentials used to AUTHENTICATE TO CLOUD EMAIL ACCOUNTS.

Follow-up emails sent FROM the compromised legitimate account to internal
colleagues. This makes the follow-up email:

  - Originate from a trusted internal address
  
  - Potentially pass email authentication (sent via the real tenant)
  
  - Bypass sender-reputation and domain-blocklist controls

(AT MedDefense: this transition was PREVENTED. No attacker login observed
with dmarsh credentials in the 4x00 window; rule 100082 monitors for
external-IP authentication by dmarsh for 30 days.)

Document Type:

--------------

Filename:    HEALTHBANE_S2_invoice.docm

SHA-256:     a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

Format:      Microsoft Word macro-enabled document (.docm)

Role:        Stage 2 carrier; macro executes on user interaction
             (T1204.002 User Execution: Malicious File)

Malware / Script Artifacts:

---------------------------

<pre>
Artifact              | SHA-256 (prefix) | Role                    | Source
----------------------|------------------|-------------------------|---------
HEALTHBANE_S2_        | a1b2c3d4...      | Macro dropper document  | HC3,
invoice.docm          |                  |                         | Commercial,
                      |                  |                         | Researcher
svchost_update.exe    | b9c8a7d6...      | RAT payload; scheduled  | HC3,
                      |                  | task + run key persist  | Commercial
sync_healthdata.ps1   | c7d6e5f4...      | Exfiltrator script      | HC3,
                      |                  | (deploys Stage 2,       | Commercial,
                      |                  | executes Stage 3)       | Researcher
dropper variant       | dd5efb6d...      | Variant observed at ONE | HC3(MED),
                      |                  | partner org; weakly     | Commercial
                      |                  | sourced                 |
update_service_v2.exe | ee112233...      | Variant, commercial     | Commercial
                      |                  | feed only, contextual   | only
</pre>

Download Infrastructure:

------------------------

Primary C2 domain:     healthbane-c2.net (IP 51.38.42.191, OVH)

Secondary C2 domain:   update-healthbane.net (HC3 MEDIUM)

Secondary host:        45.77.218.9 (AS20473, Brazil; HC3 MEDIUM)

Download endpoint:     https://healthbane-c2.net/update/svchost_update.exe
                       (confirmed by HC3 Section 3.4 and commercial feed)
                       
Bridge artifact:       kit config.php references EXFIL_ENDPOINT =
                       https://healthbane-c2.net/api/ingest and OPS_CONTACT =
                       ops@healthbane-c2.net (Researcher Section 2), linking
                       Stage 1 kit infrastructure to Stage 2/3 C2

Persistence Mechanisms:

------------------------

1. Scheduled task named "HealthSync Update Service" (T1053.005)

   - Detected by: task name containing Sync/Update/Service created by
     non-administrative users (HC3 Section 5.3)
     
2. Registry Run key (T1547.001)

   - Detected by: run-key additions outside installer context
     (HC3 Section 5.3)

Evidence Source:

---------------

  - HC3 sandbox detonation + telemetry from 2 compromised organizations
    (HIGH confidence per Section 6)
    
  - Commercial feed hashes corroborate the three primary artifacts
  
  - Researcher recovered sync_healthdata.ps1 from kit tools/ directory
    (attacker-side corroboration of the exfil script)
    
  - MedDefense: NO local Stage 2 evidence (mass EDR hash scan on
    2026-04-16 found no matches - Internal Q4)

--------------------------------------------------------------------------------

2.3 STAGE 3: DATA EXFILTRATION

--------------------------------------------------------------------------------

Data Targeted:

--------------

  - Patient records
  
  - Insurance claims data
  
(from HC3 Section 2, Stage 3 description; observed in packet captures
at 2 compromised organizations)

Protocol / Tool Used:

---------------------

  - RAT (deployed in Stage 2) encodes data as base32 subdomain labels
  
  - DNS TXT-record queries to data-sync.healthbane-c2.net
  
  - Query interval: 10-15 seconds
  
  - Label length: 44-60 characters
  
  - C2 responses delivered in TXT records with base64-encoded commands
  
  (all parameters from HC3 Section 2, Stage 3; HIGH confidence, direct
  packet capture evidence from 2 orgs)

Exfiltration Infrastructure:

----------------------------

  - data-sync.healthbane-c2.net (subdomain of Njalla-registered operator
    domain)
    
  - 51.38.42.191 (OVH, AS16276) - hosts both parent C2 and exfil endpoint
  
  - Note: the same single IP serves Stage 2 C2 and Stage 3 exfil functions,
    making 51.38.42.191 the highest-value network-layer containment target

Evidence Source:

---------------

  - HC3 packet captures from 2 compromised organizations (HIGH)
  
  - Commercial feed corroborates data-sync.healthbane-c2.net (94% confidence,
    2 external sources) and the dns-tunneling tag on 51.38.42.191
    
  - Researcher's kit evidence bridges the C2 domain but NOT the exfil
    mechanism (no packet or victim-side visibility)

What Is Confirmed vs Unclear (Stage 3):

---------------------------------------

CONFIRMED:

  - DNS TXT tunneling occurred at 2 orgs (pcap)
  
  - Target data classes: patient records, insurance claims
  
  - Exfil endpoint: data-sync.healthbane-c2.net at 51.38.42.191
  
  - Encoding (base32), label lengths (44-60), interval (10-15s)

UNCLEAR:

  - Total volume of records exfiltrated (not reported by any source)
  
  - Whether exfiltration occurred at the other 12 of 14 organizations
    (HC3 visibility is 6 of 14; Stage 3 observed at 2 of 6)
    
  - Whether dmarsh's exposed credentials led to any exfil at MedDefense
    (assessment: no; no follow-on auth observed, no Stage 2 artifacts
    on endpoints, no Stage 3 timeline overlap with our telemetry)
    
  - Whether update-healthbane.net also served exfil functions (only
    tagged "second-stage" in available sources)

================================================================================

3. EVIDENCE QUALITY ASSESSMENT BY PHASE

================================================================================

Legend:

  CONFIRMED   - direct observation by 2+ independent sources incl. at least
                one with first-party telemetry
                
  CORROBORATED - multiple sources agree, but all derive from secondhand
                or summarized reporting
                
  INFERRED     - logical conclusion from patterns; not directly observed
  
  UNKNOWN      - not reported by any available source

<pre>
+------------------+---------------------------+--------------------------------+
| Phase / Claim    | Evidence Class            | Basis                          |
+------------------+---------------------------+--------------------------------+
| Stage 1          |                           |                                |
+------------------+---------------------------+--------------------------------+
| Phishing emails  | CONFIRMED                 | MedDefense 4x00 headers        |
| sent to HC3      |                           | (first-party) + HC3 partner    |
| orgs (14+)       |                           | observations                   |
| Domain reg       | CONFIRMED                 | WHOIS (4x00) + researcher      |
| timing 4-10d     |                           | + HC3 narrative agreement      |
| pre-email        |                           |                                |
| PHPMailer 6.6.0  | CONFIRMED                 | 4x00 header analysis + kit     |
| tooling          |                           | config.php (researcher)        |
| Variant B passes | CONFIRMED                 | 4x00 F3 + researcher kit       |
| SPF/DKIM/DMARC   |                           | SMTP route analysis            |
| Credential       | CONFIRMED (sector-wide)   | HC3: creds posted to VPS;      |
| harvesting works |                           | 2 orgs saw credential abuse    |
| dmarsh submitted | INFERRED                  | 47s HTTPS session + user       |
| credentials      | (LIKELY, not confirmed    | self-report only; pcap         |
|                  | at 4x00 close)            | deferred to 4x01               |
+------------------+---------------------------+--------------------------------+
| Stage 2          |                           |                                |
+------------------+---------------------------+--------------------------------+
| .docm emailed    | CONFIRMED                 | HC3 sandbox + 2-org telemetry  |
| from compromised |                           | + commercial hash + researcher |
| accounts         |                           |  kit overlap                   |
| svchost_update   | CONFIRMED                 | HC3 sandbox; commercial feed   |
| .exe payload     |                           | hash, 2 external sources       |
| Scheduled task   | CONFIRMED                 | HC3 sandbox + endpoint         |
| + run key        |                           | telemetry                      |
| Dropper variant  | CORROBORATED              | HC3 single partner + commercial|
| (dd5efb6d...)    | (weakly sourced)          | feed; no second independent    |
|                  |                           | observation                    |
| Stage 2 occurred | UNKNOWN (at MedDefense)   | EDR scan negative; no login    |
| locally          |                           | with stolen creds observed     |
+------------------+---------------------------+--------------------------------+
| Stage 3          |                           |                                |
+------------------+---------------------------+--------------------------------+
| DNS TXT tunneling| CONFIRMED                 | PCAP from 2 compromised orgs   |
| to data-sync.    |                           | (HC3) + commercial feed corrob |
| healthbane-c2.net|                           |                                |
| Patient/insurance| CONFIRMED                 | Same pcap evidence             |
| data targeted    |                           |                                |
| Exfil volume     | UNKNOWN                   | Not reported by any source     |
| Stage 3 at other | UNKNOWN                   | HC3 sees 6 of 14 orgs          |
| orgs             |                           |                                |
+------------------+---------------------------+--------------------------------+
| Cross-phase      |                           |                                |
+------------------+---------------------------+--------------------------------+
| Stage 1 -> C2    | CONFIRMED                 | kit config.php (researcher)    |
| linkage          |                           | references healthbane-c2.net   |
|                  |                           | + HC3 victim telemetry         |
| Single operator  | INFERRED                  | Consistent registrar split,    |
|                  |                           | tooling, naming patterns;      |
|                  |                           | no direct actor evidence       |
| APT-MEDAGENT     | INFERRED (MEDIUM at best) | Researcher tooling overlap     |
| attribution      |                           | across 3 prior campaigns;      |
|                  |                           | HC3: UNCONFIRMED               |
| VITALSCORE =     | PARTIALLY CORROBORATED    | Core indicators overlap with   |
| HEALTHBANE       |                          | HC3 set; noise items prove      |
|                  |                           | over-inclusion                 |
+-----------------+---------------------------+---------------------------------+
</pre>

================================================================================

4. WHAT IS NOT KNOWN

================================================================================

4.1 ATTRIBUTION GAPS

--------------------

Known:

  - Infrastructure fingerprint (Namecheap + Njalla, Hostinger/DO/OVH,
    PHPMailer 6.6.0, wkhtmltopdf 0.12.6, <word>-c2.net naming)
    
  - Financially motivated mid-tier cybercrime actor (HC3 MODERATE
    confidence assessment)
    
  - Tooling overlap with RXBRIDGE (2024-07), CLAIMBRIDGE (2024-11),
    MEDNEXUS (2025-09) per researcher
    
Not known:

  - Actor identity, location, or motive beyond financial
  
  - Whether APT-MEDAGENT, VITALSCORE and HEALTHBANE describe one entity
  
  - Whether the kit is operator-built or kit-vendor-sold (researcher
    cannot resolve provenance of kit_v2_healthbane.zip)
    
  - Whether multiple operators share the same kit (defeats the
    single-operator inference from infrastructure patterns)

Collection that would fill the gap:

  - Kit source-code provenance analysis (compare against known kit-market
    variants)
    
  - Law-enforcement-side data (outside MedDefense reach; HC3/FBI channel)
  
  - Victim-side telemetry converging on identical TTPs across
    jurisdictions

4.2 MISSING VICTIM TELEMETRY

-----------------------------

Known:

  - 14 organizations targeted; HC3 has direct visibility on 6
  
  - MedDefense: 1 likely credential exposure, no Stage 2/3 locally
  
Not known:

  - Status of the 8 non-visible organizations (stage reached?)
  
  - Whether credential lists from creds.log were used beyond the
    2 known Stage 2 orgs
    
  - Whether dmarsh credentials were attempted/used after 4x00 window
    (rule 100082 monitors; no alert as of last report)

Collection that would fill the gap:

  - HC3 follow-up survey of all 14 affected orgs (next update
    2026-05-09 could incorporate)
    
  - Credentialed access logs beyond 30-day watch window
  
  - Dark-web monitoring for sale of MedDefense credential dumps

4.3 INCOMPLETE STAGE 3 VISIBILITY

---------------------------------

Known:

  - Exfil mechanism, endpoint, encoding, interval (pcap at 2 orgs)
  
Not known:

  - Volume and sensitivity of exfiltrated records (breach-notification
    obligations under HHS OCR may depend on this - HC3 Section 8 ref [3])
    
  - Whether alternate exfil channels existed in parallel (DNS tunnel
    may be one of several)
    
  - Duration beyond the 04-23 to 04-26 observation window
  
  - Whether the 10-15s interval / 44-60 char labels are representative
    of the tool or tuned per victim

Collection that would fill the gap:

  - Full-session pcaps at affected orgs (duration-complete, not windowed)
  
  - C2 server-side logs (unobtainable without law-enforcement action)
  
  - DNS-query anomaly reconstruction at the other 4 HC3-visible orgs

4.4 COMMERCIAL-FEED UNCERTAINTY

--------------------------------

Known:

  - Acme's 41 indicators include 15 our triage classified NOISE and 5
    CONTEXTUAL; the HEALTHBANE core overlaps HC3/researcher almost exactly
    
Not known / unresolved:

  - Whether rx-benefits-portal.com and healthcare-login.com are truly
    prior-campaign infrastructure of the same operator
    
  - Whether verify-health-portal.net will go live as a rotation domain
  
  - The true precision of Acme's ML clustering (only externally
    corroborated items are verifiable from our vantage point)
    
  - Whether the VITALSCORE cluster includes victims/targets outside
    the healthcare sector (feed tags suggest related Acme financial-
    sector reports exist: ACME-FINSECTOR-2026-0402)

Collection that would fill the gap:

  - Independent enrichment (live WHOIS/pDNS/crt.sh queries when
    permitted) on the uncorroborated domains
    
  - Request to Acme for the cluster methodology (TLP:AMBER engagement)
  
  - Cross-reference with the two related Acme reports cited in metadata

4.5 ANALYTICAL POSTURE

-----------------------

Per the Task 2 weighting rules: campaign facts defer to HC3; technical
detail to the researcher; MedDefense exposure to our own 4x00/4x01
findings; Acme is consumed per-item, never wholesale. Attribution is
recorded as unconfirmed with aliases preserved. Every OPEN question
above is a candidate input for the detection-gap analysis and the
final intelligence brief.

================================================================================

END OF KILL CHAIN RECONSTRUCTION        MD-4x02-KILLCHAIN-001

================================================================================
