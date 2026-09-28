================================================================================

  HEALTHBANE INFRASTRUCTURE ARCHAEOLOGY
  
  Project 4x02 - Intelligence-Driven Defense
  
================================================================================

Document ID:      MD-4x02-INFRA-ARCH-001

Analyst:          Steve - Cybersecurity Engineer

Date:             2026-09-28

Classification:   INTERNAL

Input Sources:    meddefense_4x00_findings.txt, HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt,
                  researcher_blog_analysis.txt, commercial_feed_extract.json

================================================================================

1. EXECUTIVE SUMMARY

================================================================================

This document synthesizes infrastructure evidence from all four intelligence
sources to reconstruct the HEALTHBANE campaign's operational topology. The
original 4x00 investigation identified three Stage 1 phishing domains and
their hosting infrastructure. This expanded analysis adds Stage 2/3 C2 and
exfiltration infrastructure, identifies clustering patterns indicating
shared ownership, and separates confirmed campaign infrastructure from
weakly attributed or noise indicators.

Summary findings:

<pre>
| Cluster Type                    | Count | Confidence | Operational Status |
|---------------------------------|-------|------------|--------------------|
| Core Campaign (Stage 1-3)       | 20    | HIGH       | Block immediately  |
| Rotation Candidates             | 3     | MEDIUM     | Hunt aggressively  |
| Unconfirmed (Single Source)     | 8     | LOW        | Monitor only       |
| Likely Noise (Shared/CDN)       | 15    | NOISE      | Discard            |
| Unrelated Clusters              | 3     | UNRELATED  | Discard            |
</pre>

Total infrastructure items analyzed: 49 unique indicators

Core confirmed infrastructure: 20 domains/IPs/hashes

Noise discarded: 15 (CDN/shared hosting, already classified NOISE in Task 1)

================================================================================

2. ORIGINAL 4x00 INFRASTRUCTURE MAP (BASELINE)

================================================================================

From meddefense_4x00_findings.txt:

Stage 1 Phishing Infrastructure:

---------------------------------

Domain:             meddefense-portal.com

Registered:         2026-04-09

Registrar:          Namecheap

Hosting IP:         91.234.99.107 (AS47583 = Hostinger)

X-Mailer Header:    PHPMailer 6.6.0

Authentication:     SPF fail, DKIM none, DMARC fail

Observed Emails:    E2 (dmarsh), E5 (arivera), E7 (lpatterson)

Click Impact:       dmarsh clicked at 2026-04-14 15:02:33 UTC

---------------------------------

Domain:             medequip-supplies.net

Registered:         2026-04-08

Registrar:          Namecheap

Hosting IP:         185.176.43.22 (AS47583 = Hostinger)

X-Mailer Header:    PHPMailer 6.6.0

Authentication:     SPF softfail, DKIM none, DMARC fail

---------------------------------

Domain:             meddefense-benefits.org

Registered:         2026-04-10

Registrar:          Namecheap

Hosting IP:         164.90.218.73 (AS14061 = DigitalOcean)

X-Mailer Header:    PHPMailer-6.6.0 (custom build)

Authentication:     SPF fail, DKIM none, DMARC fail

---------------------------------

4x00 Findings Summary:

- 3 domains registered within 4-day window (April 8-10, 2026)

- 3 IPs across 2 ASNs (Hostinger x2, DigitalOcean x1)

- Common tooling: PHPMailer 6.6.0

- Single-stage campaign observed (no Stage 2/3 at MedDefense)

================================================================================

3. EXPANDED INFRASTRUCTURE FROM ALL SOURCES

================================================================================

3.1 DOMAIN CLUSTERS

-------------------

CLUSTER 1: PRIMARY PHISHING DOMAINS (Stage 1, CONFIRMED)

Domains:        meddefense-portal.com, medequip-supplies.net, meddefense-benefits.org

Registrar:      Namecheap (all three)

Registration Window:  2026-04-08 through 2026-04-10 (3-day burst)

Hosting Provider:     Hostinger (91.234.99.107, 185.176.43.22), DigitalOcean (164.90.218.73)

ASN:                  AS47583 (Hostinger), AS14061 (DigitalOcean)

Naming Convention:    <org-name>-<service>.(com/net/org)

Certificate:    Let's Encrypt (per researcher note: issued 1-7 days before first use)

Tooling:        PHPMailer 6.6.0 (X-Mailer header)

Sources:        HC3, Commercial, Researcher, Internal 4x00

Confidence:     HIGH (four-source corroboration)

-------------------

CLUSTER 2: OPERATOR C2 DOMAIN (Stage 2/3, CONFIRMED)

Domains:        healthbane-c2.net

Subdomain:      data-sync.healthbane-c2.net

Registrar:      Njalla (per researcher Section 4; operator domain, not victim-targeted)

Registration Window:  Not explicitly dated (per researcher: predates campaign)

Hosting Provider:     OVH

IP Address:           51.38.42.191 (AS16276 = OVH)

Naming Convention:    <word>-c2.net (researcher notes this pattern across prior campaigns)

Config Reference:     OPS_CONTACT = "ops@healthbane-c2.net" (kit config.php)

Function:       C2 control + DNS-tunnel exfiltration (Stage 2/3)

Sources:        HC3, Commercial, Researcher

Confidence:     HIGH (kit artifact + victim telemetry cross-corroborate)

-------------------

CLUSTER 3: SECONDARY PHISHING/LP DOMAINS (CONFIRMED, MEDIUM)

Domains:        outlook-protection.com
                portal-secure-meddefense.com (staged, not yet active)
                update-healthbane.net
                
Registrar:      outlook-protection.com = Njalla (researcher Section 3)
                portal-secure-meddefense.com = Namecheap (naming pattern inference)
                
Hosting Provider:     outlook-protection.com = OVH (51.38.42.17)

Function:       outlook-protection.com = Microsoft impersonation phishing (passes DMARC)
                portal-secure-meddefense.com = rotation candidate (same kit staged)
                update-healthbane.net = Stage 2 second-stage download host
                
Sources:        HC3 (all three, MEDIUM on update-healthbane.net),
                Researcher (confirmed kit staging on portal-secure-meddefense.com),
                Commercial (VITALSCORE tags)
                
Confidence:     MEDIUM for all three (single-source or limited corroboration)

-------------------

CLUSTER 4: PREVIOUS CAMPAIGN / ROTATION CANDIDATES (CONTEXTUAL)

Domains:        rx-benefits-portal.com
                healthcare-login.com
                
Registrar:      Namecheap (per commercial feed naming pattern)

Registration Window:  2026-03-28 (rx-benefits) predates main campaign by 16 days

Status:         rx-benefits-portal.com = possibly earlier same-operator activity
                healthcare-login.com = sinkholed 2026-04-18
                
Function:       Historical correlation only; not for blocking

Sources:        Commercial feed only

Confidence:     LOW (single-source clustering; rx-benefits predates window)

-------------------

CLUSTER 5: WEAKLY ATTRIBUTED / SIMILARITY-CLUSTERED (NOISE)

Domains:        verify-health-portal.net
                secure-insurance-login.com
                claims-verify-portal.net
                
Clustering Method: ML name-similarity or healthcare keyword match only

Human Review:   None (Acme notes "SAMPLED" analyst review, not exhaustive)

Evidence Level: Zero external corroboration (source_count_external = 0)

Decision:       Discard; not operationalized without independent confirmation

---

3.2 IP CLUSTERS

----------------

CLUSTER A: CORE HOSTING INFRASTRUCTURE (CONFIRMED)

IPs:            91.234.99.107, 185.176.43.22, 51.38.42.17, 51.38.42.191, 164.90.218.73, 45.77.218.9

ASN Distribution:

  AS47583 (Hostinger):      91.234.99.107, 185.176.43.22
  
  AS16276 (OVH):            51.38.42.17, 51.38.42.191
  
  AS14061 (DigitalOcean):   164.90.218.73
  
  AS20473 (Ascenty):        45.77.218.9 (Brazil, anomalous)
  
Geographic Spread:      Europe (Hostinger, OVH), US (DigitalOcean), South America (Ascenty)

Hosting Model:        Dedicated VPS (not shared CDN); safe to block

Sources:              HC3 + Researcher + Commercial + Internal (multi-way corroboration)

Confidence:           HIGH

----------------

CLUSTER B: SHARED CDN / BROAD HOSTING (NOISE)

IPs:            159.89.112.45, 192.99.207.114, 20.83.144.56, 13.107.42.14, 172.67.192.40, 104.21.35.7

Issue:          Shared infrastructure (DigitalOcean shared VPS, OVH CDN, Azure CDN, Microsoft Outlook.com, Cloudflare)

Acme Warning:   "DO NOT BLOCK", "LIKELY NOISE", "hosting 200+ unrelated websites"

Decision:       Discard from perimeter blocks; may be useful for historical correlation

----------------

CLUSTER C: SUSPICIOUS BUT UNCORROBORATED (MONITOR)

IPs:            23.94.138.222, 104.168.34.58, 167.71.222.30

ASN:            AS36352 (bulletproof hosting), AS14061 (DigitalOcean)

Reasoning:      Bulletproof-hosting or ML-clustered similarity only; no corroboration

Confidence:     LOW

Decision:       Hunt-only; do not block without additional evidence

================================================================================

4. CLUSTER ANALYSIS AND OWNERSHIP PATTERNS

================================================================================

4.1 REGISTRAR PATTERN ANALYSIS

------------------------------

Observation: Two distinct registrar strategies observed

LURE DOMAINS (victim-facing):           Namecheap
                                        meddefense-portal.com
                                        medequip-supplies.net
                                        meddefense-benefits.org
                                        portal-secure-meddefense.com

OPERATOR DOMAINS (C2/admin):            Njalla (anonymous-by-design)
                                        healthbane-c2.net
                                        outlook-protection.com

Interpretation: Operator uses Namecheap for phishing domains (cost-effective,
widely accepted) but switches to Njalla for operator-owned infrastructure
requiring anonymity. This two-tier registrar strategy is a QUALITY INDICATOR
suggesting experienced operators, not commodity kit users.

Supporting Evidence: Researcher Section 4 notes "Njalla registrar for operator
domains (healthbane-c2.net)" while "Namecheap registrar for all phishing-LP
domains." This split is consistent across the campaign.

---

4.2 HOSTING PROVIDER PATTERN ANALYSIS

------------------------------------

Provider Distribution:

<pre>
| Provider          | IP Count | Role                       | Risk Profile   |
|-------------------|----------|----------------------------|----------------|
| Hostinger         | 2        | Stage 1 phishing LPs       | Safe to block  |
| OVH               | 2        | Stage 1 LPs + Stage 2/3 C2 | Safe to block  |
| DigitalOcean      | 1        | Stage 1 phishing LP        | Safe to block  |
| Ascenty (Brazil)  | 1        | Stage 2 secondary host     | Safe to block  |
| CDN/Cloud Shared  | 6        | NOISE                      | Do not block   |
</pre>

Observation: All confirmed infrastructure uses dedicated VPS (not shared CDN).
The operator rotates across providers to avoid single-point blocking, but
each IP is individually actionable without collateral damage.

Anomaly: 45.77.218.9 (Brazil) stands out geographically from the Europe-based
cluster. Possible explanations:

1. Operator uses geographic diversity for redundancy

2. Test deployment at different hosting provider

3. Different operator segment for regional targeting

Action: Include in hunt queries; escalate to block if observed.

---

4.3 TOOLING FINGERPRINT ANALYSIS

--------------------------------

PHPMailer Version:    6.6.0 (consistent across all three 4x00 emails)
                      X-Mailer header variations:
                        - "PHPMailer 6.6.0" (emails 01, 02)
                        - "PHPMailer-6.6.0 (custom build)" (email 03 - hyphen variation)
                        
WKHTMLTOPDF Version:  0.12.6 (per researcher PDF analysis)
                      Producer metadata in lure PDFs

Significance: PHPMailer 6.6.0 is NOT the latest version (6.7+ exists as of
2024 training cutoff). This version freeze is an OPERATIONAL SIGNATURE
suggesting the kit hasn't been updated since 0.12.6 shipped. The
wkhtmltopdf 0.12.6 version string appears in ALL three PDF lures examined
by the researcher (Section 4).

Defensive Application: Alert on X-Mailer containing "PHPMailer" combined with
SPF failure. This behavioral signature survives domain rotation better than
pure IOC blocking.

---

4.4 CERTIFICATE TRANSPARENCY PATTERNS

-------------------------------------

Observation: Let's Encrypt certificates issued 1-7 days before first use (per
researcher Section 4). No organizational validation (subject = domain only).

Related Certificates: Same issuer issued certs to meddefense-portal.com,
medequip-supplies.net, meddefense-benefits.org (clustering signal).

Operational Value: Certificate fingerprinting could predict future rotation
domains if they share the same issuance chain; however, this is more suited
to hunting than blocking.

================================================================================

5. PIVOT POINTS BRIDGING CAMPHASES

================================================================================

5.1 DOMAIN-TO-IP CORRELATION MATRIX

-----------------------------------

<pre>
| Domain                      | IP            | Stage | Bridge To |
|-----------------------------|---------------|-------|-----------|
| meddefense-portal.com       | 91.234.99.107 | 1     | None      |
| medequip-supplies.net       | 185.176.43.22 | 1     | None      |
| meddefense-benefits.org     | 164.90.218.73 | 1     | None      |
| outlook-protection.com      | 51.38.42.17   | 1     | None      |
| healthbane-c2.net           | 51.38.42.191  | 2/3   | C2        |
| data-sync.healthbane-c2.net | 51.38.42.191  | 3     | Exfil     |
| update-healthbane.net       | Unknown       | 2     | None      |
</pre>

Pivot Point 1: healthbane-c2.net appears in BOTH kit config.php (EXFIL_ENDPOINT)
AND HC3 advisory victim telemetry (Stage 2/3 DNS tunnel destination). This
is the primary bridge between attacker-side and victim-side infrastructure.

Pivot Point 2: 51.38.42.191 (OVH) hosts BOTH healthbane-c2.net AND
data-sync.healthbane-c2.net. This IP handles both Stage 2 C2 commands AND
Stage 3 exfiltration responses, making it a high-value blocking target.

Pivot Point 3: 51.38.42.17 (OVH) hosts outlook-protection.com, which the
researcher identified as the SMTP exfil route in config.php (handler/post.php
forwards credentials to attacker mailbox on this domain). This connects
Stage 1 credential harvesting to operator receipt mechanism.

---

5.2 HASH-TO-DOMAIN CORRELATION MATRIX

-------------------------------------

<pre>
| Hash                                     | File              | Stage | Downloaded From   |
|----------------------------------------- |-------------------|-------|-------------------|
| a1b2c3d4... (HEALTHBANE_S2_invoice.docm) | Macro doc         | 2     | Email attachment  |
| b9c8a7d6... (svchost_update.exe)         | Trojan payload    | 2     | healthbane-c2.net |
| c7d6e5f4... (sync_healthdata.ps1)        | PowerShell exfil  | 2/3   | kit tools/        |
| dd5efb6d... (dropper variant)            | Dropper           | 2     | Unknown           |
| 2f4a6c8e... (INV-2026-04891.pdf)         | Lure PDF          | 1     | Email attachment  |
</pre>

Critical Pivot: svchost_update.exe (b9c8a7d6...) is downloaded from
https://healthbane-c2.net/update/svchost_update.exe per HC3 Section 3.4.
This directly links the Stage 1 domain cluster (phishing) to Stage 2 C2
infrastructure. Blocking healthbane-c2.net severs the malware delivery chain.

---

5.3 CONFIG.PHP ARTIFACT BRIDGE (RESEARCHER ONLY)

------------------------------------------------

From researcher Section 2, config.php contents:

  MAILER_VERSION = "PHPMailer 6.6.0"
  
  SMTP_HOST      = "smtp.<harvester-domain>"
  
  TARGET_LOG     = "/var/www/kit/logs/creds.log"
  
  OPS_CONTACT    = "ops@healthbane-c2.net"      <-- Bridges to Stage 2/3!
  
  EXFIL_ENDPOINT = "https://healthbane-c2.net/api/ingest"

Significance: The config.php file physically exists on the attacker server
and contains both Stage 1 infrastructure (MAILER_VERSION, SMTP_HOST) AND
Stage 2/3 endpoints (OPS_CONTACT, EXFIL_ENDPOINT). This is a HARD LINK
between phases that researchers discovered via directory traversal.

Defensive Value: Any email from healthbane-c2.net (even if SPF/DKIM passes)
should be flagged as HIGH-risk because this domain serves dual purposes
(operator contact + exfiltration endpoint).

================================================================================

6. COMMERCIAL FEED ADDITIONS ASSESSMENT

================================================================================

Per Task 1 triage, the commercial feed's 41 indicators decompose as:

6.1 CONFIRMED CAMPAIGN INDICATORS (HC3-CORROBORATED)

--------------------------------------------------

Domains:        meddefense-portal.com, medequip-supplies.net, meddefense-benefits.org
                outlook-protection.com, healthbane-c2.net, data-sync.healthbane-c2.net
                (6 domains also in HC3 advisory)

IPs:            91.234.99.107, 185.176.43.22, 164.90.218.73, 51.38.42.17, 51.38.42.191, 45.77.218.9
                (6 IPs also in HC3 advisory)

Hashes:         a1b2c3d4..., b9c8a7d6..., c7d6e5f4..., dd5efb6d..., 2f4a6c8e...
                (5 hashes also in HC3 advisory, with 4.4 having single-partner caveat)

URLs:           https://meddefense-portal.com/verify/staff
                https://healthbane-c2.net/update/svchost_update.exe
                (both in HC3 advisory)

Email Addresses: noreply@meddefense-portal.com, invoices@medequip-supplies.net,
                hr-notifications@meddefense-benefits.org

Verdict:        THESE BELONG TO THE SAME CAMPAIGN (HC3 corroboration confirms
                the VITALSCORE label matches HEALTHBANE core infrastructure)
                
Action:         OPERATIONALIZE (block at perimeter)

---

6.2 PLAUSIBLE BUT UNCONFIRMED INDICATORS

----------------------------------------

Domains:        rx-benefits-portal.com, healthcare-login.com, verify-health-portal.net,
                update-healthbane.net, portal-secure-meddefense.com
                (update-healthbane.net and portal-secure-meddefense.com have HC3 MEDIUM
                confidence; others are single-source clustering)

Verdict:        PLAGUSIBLE BUT UNCONFIRMED

Action:         HUNT/monitor; do not block unless observed internally

Justification:

  - rx-benefits-portal.com: predates campaign window (March 28 vs April 14 start)
  
  - healthcare-login.com: sinkholed, historical correlation only
  
  - verify-health-portal.net: matching naming pattern but no observed phishing
  
  - update-healthbane.net: HC3 MEDIUM confidence, single-source observation
  
  - portal-secure-meddefense.com: researcher-staged kit, not yet live

---

6.3 LIKELY NOISE INDICATORS (SHARED INFRASTRUCTURE)

-------------------------------------------------

IPs:            159.89.112.45 (DigitalOcean shared hosting, 200+ websites)
                192.99.207.114 (OVH shared CDN, "LIKELY NOISE")
                20.83.144.56 (Azure CDN, "DO NOT BLOCK")
                13.107.42.14 (Microsoft Outlook.com cloud IP)
                172.67.192.40 (Cloudflare front IP)
                104.21.35.7 (Cloudflare front IP)

Hashes:         1122aabb..., 33445566... (marked "unrelated-cluster")
                55667788..., 77889900... (ML-similarity only)

Verdict:        DEFINITELY NOISE (Acme's own metadata flags these)

Action:         DISCARD; do not operationalize

Risk:           Blocking any of these would cause false positives across
                hundreds of legitimate enterprises sharing the same cloud/CDN.

                
---

6.4 WEAKLY CLUSTERED INDICATORS (NEED MORE EVIDENCE)

--------------------------------------------------

Domains:        secure-insurance-login.com, claims-verify-portal.net

Clustering:     ML name-similarity and healthcare keyword match only

Human Review:   None (source_count_external = 0 for both)

Verdict:        WEAKLY CLUSTERED; insufficient evidence

Action:         DO NOT OPERATIONALIZE without additional confirmation

================================================================================

7. UPDATED INFRASTRUCTURE DIAGRAM (ASCII)

================================================================================

Legend:
  [HIGH]   = Corroborated by 2+ independent sources (HC3 + others)
  
  [MED]    = Single credible source or limited corroboration
  
  [LOW]    = Weakly attributed; single source with uncertainty
  
  [NOISE]  = Shared/CDN infrastructure; unsafe to block
  
  [UNREL]  = Unrelated cluster; discard

================================================================================

                          HEALTHBANE CAMPAIGN INFRASTRUCTURE MAP
                          
================================================================================

<pre>
                              +--------------------------+
                              |   STAGE 1: CREDENTIAL    |
                              |     HARVESTING PHASE     |
                              |  (2026-04-14 to 04-16)   |
                              +------------+-------------+
                                           |
         +---------------------------------+----------------------------------+
         |                                |                                   |
    +----v-----+                    +-----v------+                     +------+------+
    | DOMAIN   |                    | DOMAIN     |                     | DOMAIN      |
    | PORTAL   |                    | SUPPLIES   |                     | BENEFITS    |
    |[HIGH]    |                    |[HIGH]      |                     |[HIGH]       |
    +----+-----+                    +-----+------+                     +------+------+
         |                                |                                   |
    meddefense-portal.com           medequip-supplies.net            meddefense-benefits.org
         |                                |                                   |
         |                                |                                   |
    +----v--------------------------+     |                              +----+--------------+
    | Hosting: Hostinger            |     |                              | Hosting:          |
    | IP: 91.234.99.107             |     |                              | DigitalOcean      |
    | ASN: AS47583                  |     |                              | IP: 164.90.218.73 |
    | X-Mailer: PHPMailer 6.6.0     |     |                              | ASN: AS14061      |
    +-------------------------------+     |                              +-------------------+
                                          |
                                         +|+---+                                  |
    +------------------------------------|-----+                                  |
    |                                    |                                       |
+---v-------+                         +--v-------+                           +--v-------+
| PHISHING  |                         | PHISHING |                           | PHISHING |
| DOMAIN #4 |                         | DOMAIN 5 |                           | DOMAIN 6 |
|[HIGH]     |                         |[HIGH]    |                           |[MED]     |
+---+-------+                         +----+-----+                           +----+-----+
    |                                      |                                    |
    |  outlook-protection.com         | portal-secure-meddefense.com  | update-healthbane.net
    | (Microsoft impersonation)       | (staged kit, not live)        | (Stage 2 secondary) |
    | Passes SPF/DKIM/DMARC           | Same kit as primary cluster   | HC3 MEDIUM conf     |
    | C2 exfil route per config.php   | Rotate when primaries burn    | Single partner obs  |
    | IP: 51.38.42.17 (OVH)           | IP: Unknown                   | IP: Unknown         |
    +---------------------------------+                               +---------------------+

                                          |
                                          v
                              +-----------+------------+
                              |   STAGE 2: MALWARE     |
                              |     DELIVERY PHASE     |
                              | (2026-04-16 to 04-22)  |
                              +-----------+------------+
                                          |
                          +---------------+---------------+
                          |                               |
             +------------v------------+      +-----------v------------+
             | C2 DOMAIN               |      | MACRO DOC ATTACK VECTOR|
             | healthbane-c2.net       |      | (HEALTHBANE_S2_invoice)|
             | [HIGH]                  |      | [HIGH]                 |
             +------------+------------+      +-----------+------------+
                          |                               |
             +------------v------------+                  v
             | C2 IP: 51.38.42.191     |         +----------+------------------+
             | OVH (AS16276)           |         | Payload: svchost_update.exe |
             | Config.php EXFIL_ENDPT  |         | Hash: b9c8a7d6...           |
             +------------+------------+         +-----------------------------+
                          |
                          | Payload download endpoint
                          | https://healthbane-c2.net/update/svchost_update.exe
                          |
                          v
            +---------------------------------------------+
            | PERSISTENCE MECHANISM                       |
            | Scheduled Task: "HealthSync Update Service" |
            | Registry Run Key                            |
            +---------------------------------------------+
                          |
                          v
            +---------------------------+
            | PS1 EXFIL SCRIPT          |
            | sync_healthdata.ps1       |
            | Hash: c7d6e5f4...         |
            +---------------------------+

                                          |
                                          v
                              +-----------+------------+
                              |   STAGE 3: DATA        |
                              |   EXFILTRATION PHASE   |
                              | (2026-04-23 to 04-26)  |
                              +-----------+------------+
                                          |
                          +---------------+---------------+
                          | DNS-TUNNEL SUBDOMAIN          |
                          | data-sync.healthbane-c2.net   |
                          | [HIGH]                        |
                          +---------------+---------------+
                                          |
                                          v
                          +---------------+---------------+
                          | C2 IP: 51.38.42.191 (OVH)     |
                          | Base32 subdomain encoding     |
                          | 44-60 character labels        |
                          | Query interval: 10-15 sec     |
                          +-------------------------------+
</pre>

================================================================================

UNCERTAIN / LOW-CONFIDENCE CLUSTER (HUNT ONLY)

================================================================================

<pre>
+--------------------------------------------------------------------------+
|                                                                          |
|  PREVIOUS CAMPAIGN CANDIDATES                                            |
|  ----------------------------------------------------------------------  |
|  rx-benefits-portal.com     [LOW] - March 28 registration, predates      |
|  healthcare-login.com       [LOW] - sinkholed April 18, historical       |
|                                                                          |
|  WEAKLY CLUSTERED (SIMILARITY-ONLY)                                      |
|  ----------------------------------------------------------------------  |
|  verify-health-portal.net   [LOW] - pattern match, no observed phishing  |
|  secure-insurance-login.com [NOISE] - ML clustering, 0 external sources  |
|  claims-verify-portal.net   [NOISE] - keyword match only, Acme warns     |
|                                                                          |
|  GEOGRAPHIC ANOMALY                                                      |
|  ----------------------------------------------------------------------  |
|  45.77.218.9 (Brazil)       [MED] - Stage 2 secondary host, single       |
|                              partner observation, geographic outlier     |
|                                                                          |
|  DROPPER VARIANT (WEAKLY SOURCED)                                        |
|  ----------------------------------------------------------------------  |
|  dd5efb6d... (SHA-256)      [MED] - observed at one HC3 partner only     |
|                                                                          |
+--------------------------------------------------------------------------+
</pre>

================================================================================

NOISE / UNSAFE TO BLOCK

================================================================================

<pre>
+--------------------------------------------------------------------------+
|                                                                          |
|  SHARED CDN / CLOUD INFRASTRUCTURE (BLOCKING CAUSES FALSE POSITIVES)     |
|  ----------------------------------------------------------------------  |
|  192.99.207.114 (OVH CDN)       - Acme: "LIKELLY NOISE"                  |
|  20.83.144.56 (Azure CDN)       - Acme: "DO NOT BLOCK"                   |
|  13.107.42.14 (Microsoft)       - Acme: "Outlook.com cloud, noise"       |
|  172.67.192.40 (Cloudflare)     - Acme: "Not actionable"                 |
|  104.21.35.7 (Cloudflare)       - Acme: "Not actionable"                 |
|  159.89.112.45 (DigitalOcean)   - Acme: "hosts 200+ unrelated websites"  |
|                                                                          |
|  BULLETPROOF / ML-CLUSTERED                                              |
|  ----------------------------------------------------------------------  |
|  23.94.138.222 (AS36352)        - BPH, zero corroboration                |
|  104.168.34.58 (AS36352)        - ML similarity, zero corroboration      |
|  167.71.222.30 (DigitalOcean)   - LOW conf, researcher notes hypothesis  |
|                                                                          |
|  UNRELATED MALWARE CLUSTERS                                              |
|  ----------------------------------------------------------------------  |
|  1122aabb... (SHA-256)          - Acme: "unrelated-cluster"              |
|  33445566... (SHA-256)          - Acme: "unrelated-cluster"              |
|  55667788... (SHA-256)          - Acme: ML clustering, zero corroboration|
|  77889900... (SHA-256)          - Acme: ML clustering, zero corroboration|
|                                                                          |
+--------------------------------------------------------------------------+
</pre>

================================================================================

8. OWNERSHIP CONCLUSIONS

================================================================================

Based on clustering patterns across all four intelligence sources:

1. SINGLE OPERATOR ASSESSMENT: HIGH CONFIDENCE

   All confirmed Stage 1-3 infrastructure exhibits consistent patterns:
   
   - Two-tier registrar strategy (Namecheap + Njalla)
   
   - PHPMailer 6.6.0 across all phishing LPs
   
   - Let's Encrypt certificate issuance pattern (1-7 days pre-use)
   
   - Named C2 infrastructure matching researcher's prior campaign patterns
   
   - config.php linking Stage 1 to Stage 2/3 endpoints

2. CROSS-CAMPAIGN CONSISTENCY (APT-MEDAGENT HYPOTHESIS): MEDIUM CONFIDENCE

   Researcher documents matching infrastructure/tooling across:
   
   - RXBRIDGE (2024-07, pharmacies)
   
   - CLAIMBRIDGE (2024-11, insurance processors)
   
   - MEDNEXUS (2025-09, hospital billing)
   
   - HEALTHBANE (2026-04, healthcare)
   
   However, attribution relies entirely on tooling/infrastructure overlap,
   not victim-side telemetry or signals intelligence. HC3 does not endorse
   any named actor attribution.

3. ALIAS RECONCILIATION:

   HEALTHBANE:     HC3 campaign designation (authoritative)
   
   VITALSCORE:     Acme commercial cluster label (matches HEALTHBANE core)
   
   APT-MEDAGENT:   Researcher's private actor hypothesis (MEDIUM confidence)

   Recommendation: Use HEALTHBANE as primary designation; record VITALSCORE
   and APT-MEDAGENT as secondary aliases with provenance documented.

================================================================================

END OF INFRASTRUCTURE ARCHAEOLOGY          MD-4x02-INFRA-ARCH-001

================================================================================
