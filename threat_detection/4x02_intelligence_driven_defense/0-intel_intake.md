================================================================================
  HEALTHBANE INTELLIGENCE INTAKE SUMMARY
  Project 4x02 - Intelligence-Driven Defense
================================================================================

Document ID:        MD-4x02-INTEL-INTAKE-001
Analyst:            Steve - Cybersecurity Engineer
Date:               2026-09-28
Classification:     INTERNAL  (contains TLP:CLEAR material marked appropriately)
Purpose:            Structured intake of four intelligence sources about HEALTHBANE

================================================================================
SOURCE 1: HC3 SECTOR ADVISORY
================================================================================

1. Source name:              HC3 Advisory HEALTHBANE
2. Source type:              Government advisory
3. Date published:           2026-04-25
4. TLP classification:       TLP:CLEAR
5. Number of indicators:     23 (per Section 3)
   - Domains:                8
   - IPs:                    6
   - File hashes (SHA-256):  5
   - URLs:                   4
6. One-line summary:         Multi-stage campaign targeting 14 US healthcare 
                             organizations via credential harvesting, malware 
                             delivery, and DNS-tunnel exfiltration
7. Key limitations:          Attribution UNCONFIRMED; direct visibility on only 
                             6 of 14 organizations; Stage 2/3 observed at only 
                             2 of 6 visible orgs; does not adopt "VITALSCORE" 
                             label used by commercial providers

================================================================================
SOURCE 2: COMMERCIAL FEED (ACME)
================================================================================

1. Source name:              Acme CTI Commercial Feed Extract
2. Source type:              Commercial feed
3. Date published:           2026-04-26T08:14:00Z
4. TLP classification:       TLP:AMBER (internal use only)
5. Number of indicators:     41 (per metadata.indicator_count)
   - Domains:                12
   - IPs:                    13
   - File hashes (SHA-256):  10
   - URLs:                   5
   - Email addresses:        1
6. One-line summary:         Proprietary VITALSCORE campaign cluster with auto-
                             generated indicators; includes explicit noise flags
                             for CDN/shared infrastructure (Microsoft, Cloudflare, 
                             Azure)
7. Key limitations:          Indicators auto-tagged with SAMPLED (not fully 
                             human-reviewed); proprietary VITALSCORE label does 
                             not correspond to external threat actor names; 
                             confidence ranges 15%-96%; explicit notes warn that 
                             some indicators are "LIKLEY NOISE" or "DO NOT BLOCK"

================================================================================
SOURCE 3: RESEARCHER BLOG ANALYSIS
================================================================================

1. Source name:              Marcus Weller Technical Analysis
2. Source type:              Open-source research
3. Date published:           2026-04-24
4. TLP classification:       N/A (public post)
5. Number of indicators:     14 (per Section 5)
   - Domains:                5
   - IPs:                    3
   - File hashes (SHA-256):  4
   - URLs:                   2
6. One-line summary:         Technical walkthrough of phishing kit recovered 
                             via directory traversal; attributes to APT-MEDAGENT 
                             based on tooling and infrastructure fingerprint
7. Key limitations:          Solo analyst with no victim telemetry; attribution 
                             MEDIUM confidence based entirely on tooling overlap; 
                             delayed publication by 72 hours per HC3 request; 
                             does not share kit source code publicly

================================================================================
SOURCE 4: MEDEFENSE INTERNAL INVESTIGATION (4x00)
================================================================================

1. Source name:              MedDefense Internal Investigation Summary
2. Source type:              Internal investigation
3. Date published:           2026-04-16
4. TLP classification:       INTERNAL (TLP not applicable)
5. Number of indicators:     11 (per "INDICATORS OF COMPROMISE" section)
   - Domains:                3
   - IPs:                    3
   - File hashes (SHA-256):  1
   - URLs:                   1
   - Email addresses:        3
6. One-line summary:         Three phishing emails caught internally; one nurse 
                             clicked and likely submitted credentials; no 
                             Stage 2/3 activity observed
7. Key limitations:          No packet capture confirmation of credential 
                             submission; only 3 emails analyzed; Stage 1 only 
                             (no malware or exfiltration evidence at MedDefense)

================================================================================
CONSOLIDATED INDICATOR COUNTS
================================================================================

| Source                    | Raw Indicators | Deduped Unique |
|---------------------------|----------------|----------------|
| HC3 Advisory              | 23             | TBD            |
| Commercial Feed           | 41             | TBD            |
| Researcher Blog           | 14             | TBD            |
| MedDefense 4x00           | 11             | TBD            |
| **TOTAL RAW**             | **89**         | **TBD**        |

Reference expectation from lab materials:
- Total raw indicators:      89
- Unique deduped indicators: 64

Note: Actual deduplication will be performed programmatically against the full 
indicator value set; the above represents expected counts from lab documentation.

================================================================================
CROSS-SOURCE OVERLAP ANALYSIS
================================================================================

Indicators appearing in MULTIPLE SOURCES (high-confidence, corroborated):

Domains:
- meddefense-portal.com     | HC3 | Commercial | Researcher | Internal
- medequip-supplies.net     | HC3 | Commercial | Researcher | Internal
- outlook-protection.com    | HC3 | Commercial | Researcher | -
- healthbane-c2.net         | HC3 | Commercial | Researcher | -
- meddefense-benefits.org   | HC3 | Commercial | Internal   | -
- portal-secure-meddefense.com | HC3 | Researcher | -       | -

IPs:
- 91.234.99.107             | HC3 | Commercial | Researcher | Internal
- 185.176.43.22             | HC3 | Commercial | -          | Internal
- 164.90.218.73             | HC3 | Commercial | -          | Internal
- 51.38.42.191              | HC3 | Commercial | Researcher | -
- 51.38.42.17               | HC3 | Commercial | -          | -
- 45.77.218.9               | HC3 | Commercial | -          | -

Hashes:
- a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
                              | HC3 | Commercial | Researcher | -
- c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6
                              | HC3 | Commercial | Researcher | -
- 2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f
                              | HC3 | Commercial | Researcher | Internal
- b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654
                              | HC3 | Commercial | -          | -
- dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678
                              | HC3 | Commercial | -          | -

URLs:
- https://meddefense-portal.com/verify/staff
                              | HC3 | Commercial | Researcher | Internal
- https://healthbane-c2.net/update/svchost_update.exe
                              | HC3 | Commercial | -          | -

Email addresses:
- noreply@meddefense-portal.com | - | Commercial | -        | Internal
- invoices@medequip-supplies.net | - | Commercial | -       | Internal
- hr-notifications@meddefense-benefits.org | - | Commercial | - | Internal

Indicators appearing in SINGLE SOURCE (requires credibility assessment):

From Commercial Feed only (not corroborated by HC3/researcher/internal):
- Domains: meddefense-benefits.org, update-healthbane.net, rx-benefits-portal.com,
           healthcare-login.com, verify-health-portal.net, secure-insurance-login.com,
           claims-verify-portal.net
- IPs: 104.21.35.7, 159.89.112.45, 167.71.222.30, 192.99.207.114, 20.83.144.56,
       23.94.138.222, 172.67.192.40, 20.83.144.56, 13.107.42.14
- Additional SHA-256 hashes flagged as "unrelated-cluster" or with confidence < 50

From Researcher Blog only:
- Domain: portal-secure-meddefense.com (marked MEDIUM confidence, "staged kit not yet live")
- IP: 167.71.222.30 (marked LOW confidence, "operator-overlap hypothesis")
- Hash: ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899 (kit ZIP, MEDIUM)
- URL: https://healthbane-c2.net/api/ingest

From Internal (4x00) only:
- Email addresses: noreply@meddefense-portal.com, invoices@medequip-supplies.net,
                   hr-notifications@meddefense-benefits.org

================================================================================
SOURCE CONFLICTS TO RESOLVE IN LATER TASKS
================================================================================

1. Attribution labels:
   - HC3: UNCONFIRMED attribution; explicitly states "commercial tracking names 
          circulating in industry channels are noted but not endorsed"
   - Commercial Feed (Acme): VITALSCORE (proprietary label); notes "does not 
                            necessarily correspond to externally-tracked threat 
                            actor names"
   - Researcher: APT-MEDAGENT (MEDIUM confidence, based on tooling overlap from 
                2024-2025 campaigns)
   - Internal (4x00): No attribution attempted

2. Confidence level inconsistencies:
   - HC3 uses binary HIGH/MEDIUM for individual indicators
   - Commercial Feed uses numeric confidence (15%-96%); explicitly includes 
     indicators with confidence < 30 flagged as noise
   - Researcher uses HIGH/MEDIUM/LOW per indicator
   - Internal uses HIGH/MEDIUM per indicator

3. Commercial feed noise:
   - Multiple IPs flagged by Acme as "DO NOT BLOCK" or "LIKELY NOISE":
     * 13.107.42.14 (Microsoft Outlook.com cloud IP)
     * 172.67.192.40 / 104.21.35.7 (Cloudflare front IPs)
     * 20.83.144.56 (Azure CDN)
     * 192.99.207.114 (OVH shared CDN)
   - These would cause false positives if blocked indiscriminately

4. Timeline discrepancies:
   - HC3 states earliest activity: 2026-04-14
   - Researcher notes rx-benefits-portal.com active 2026-03-28 (16 days earlier)
   - Commercial feed shows some domains dating to 2026-03-24

5. Scope disagreement:
   - HC3: 14 organizations impacted, 6 with direct visibility, 2 with full 
          Stage 1→2→3 progression
   - Commercial Feed: 41 indicators implies broader operational footprint
   - Internal: Only 3 phishing emails observed at MedDefense; no Stage 2/3

6. Missing indicators from HC3 (present in other sources):
   - update-healthbane.net (Commercial, Researcher) — marked MEDIUM by HC3 but 
                           not included in HC3's final 23
   - portal-secure-meddefense.com (Researcher, Commercial) — marked MEDIUM by HC3 
                                  but not in final indicator list
   - data-sync.healthbane-c2.net (HC3) — subdomain of C2, not in Commercial or Researcher

7. Methodology conflicts:
   - HC3: Evidence-based (direct observation at 6 partner organizations)
   - Commercial: Machine-learning clustering + sampled human review
   - Researcher: Single-endpoint kit recovery + historical tooling correlation
   - Internal: Single-incident header analysis

================================================================================
ANALYTICAL JUDGMENTS REQUIRED IN SUBSEQUENT TASKS
================================================================================

1. Which attribution label should be applied to unified IOC database?
   Recommendation: HC3 designation (HEALTHBANE) as primary; VITALSCORE and 
   APT-MEDAGENT as secondary aliases with source attribution preserved

2. How to handle commercial feed noise indicators?
   Recommendation: Apply actionability filter (BLOCK/HUNT/MONITOR/CONTEXTUAL);
   flag CDNs and shared infrastructure as CONTEXTUAL only

3. How to resolve timeline conflict?
   Recommendation: Record earliest observed date from all sources (2026-03-24);
   document discrepancy in methodology

4. Confidence standardization?
   Recommendation: Map all sources to unified HIGH/MEDIUM/LOW scale using 
   source reliability × information credibility matrix (Admiralty/NATO style)

================================================================================
END OF INTELLIGENCE INTAKE
================================================================================
