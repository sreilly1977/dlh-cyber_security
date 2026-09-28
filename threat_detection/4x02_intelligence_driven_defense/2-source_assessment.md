================================================================================

  HEALTHBANE SOURCE CREDIBILITY MATRIX
  
  Project 4x02 - Intelligence-Driven Defense
  
================================================================================

Document ID:      MD-4x02-SOURCE-ASSESSMENT-001

Analyst:          Steve - Cybersecurity Engineer

Date:             2026-09-28

Classification:   INTERNAL

Inputs:           HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt (TLP:CLEAR),

                  commercial_feed_extract.json (TLP:AMBER),
                  
                  researcher_blog_analysis.txt (public),
                  
                  meddefense_4x00_findings.txt (INTERNAL)

================================================================================

1. METHODOLOGY

================================================================================

This assessment adapts the Admiralty Code (NATO system) for cyber threat
intelligence, as commonly operationalized in intelligence community practice.

1.1 Source Reliability (A-F)

   A - Completely reliable: Authoritative, established track record,
       direct authority over the domain, verifiable institutional backing.
       
   B - Usually reliable: Generally dependable, minor lapses possible.
   
   C - Fairly reliable: May be dependable; methodology has known gaps;     
       claims require corroboration.
       
   D - Not usually reliable: Frequent errors, weak methodology, or
       strong incentives/distortions.
       
   E - Unreliable: Consistent errors or fabrication suspected.
   
   F - Reliability cannot be judged: New or opaque source, no track record.

   Adaptation for CTI: reliability reflects the SOURCE'S track record and
   production methodology, not whether any single indicator is correct.

1.2 Information Credibility (1-6)

   1 - Confirmed by other independent sources or direct observation.
   
   2 - Probably true: logical, consistent with other reporting, but not
       independently confirmed.
       
   3 - Possibly true: plausible, partially corroborated.
   
   4 - Doubtfully true: weak support, relies on inference or automated
       processing.
       
   5 - Improbable: contradicts stronger reporting.
   
   6 - Truth cannot be judged: unverifiable either way.

1.3 Confidence Levels (used in downstream IOC database)

   HIGH   - Multiple independent, credible sources or direct observation.
   
   MEDIUM - Single credible source, or corroborated by weaker sources only.
   
   LOW    - Weak sourcing, automated inference, or internal contradiction.

1.4 Assessment dimensions beyond Admiralty

   - Timeliness: age of the intelligence relative to campaign activity.
   
   - Relevance: applicability to MedDefense's sector and exposure.
   
   - Visibility constraint: what the source can and cannot see.

Rule applied throughout: FACT (directly evidenced) vs ASSESSMENT (inferred)
are labeled. Conclusions cite the specific evidence supporting them.

================================================================================

2. PER-SOURCE ASSESSMENT

================================================================================

--------------------------------------------------------------------------------

2.1 HC3 SECTOR ADVISORY (HC3-2026-HEALTHBANE-001)

--------------------------------------------------------------------------------

Source reliability: A

   FACTS: HC3 is a government (HHS) sector coordination center. Advisory has a
   document ID, POC channel, update schedule and sourcing statement (Section 6:
   6 partner organizations, 2 ISAO sensors, abuse.ch corroboration).
   
   ASSESSMENT: Institutional accountability, regulated publication process and
   multisector data collection justify an A rating.

Information credibility: 1-2 (varies by claim)

   1 - Stage 1/2/3 mechanics (direct observation, sandbox, packet captures).
   
   2 - Scope claims (14 organizations, only 6 with visibility - extrapolated).
   
   Actor attribution statements are appropriately conservative ("UNCONFIRMED").

Timeliness: GOOD

   Published 2026-04-25, after campaign peak windows for each stage.
   
   Next update scheduled 2026-05-09.

Relevance to MedDefense: VERY HIGH

   Targets Midwest ISAC-region healthcare providers (MedDefense profile),
   and incorporates MedDefense's own contributed indicators.

Limitations:

   - Visibility on only 6 of 14 affected organizations (Section 1.1/6).
   
   - Stage 2/3 evidence limited to 2 compromised organizations.
   
   - Indicators derived from the HC3-visible subset only.

Bias / visibility constraints:

   - Government bias toward caution: will not adopt commercial labels or
     attribute without high confidence. This understates but does not distort.
     
   - No visibility into actor-side infrastructure beyond victim telemetry
     and open-source corroboration.

--------------------------------------------------------------------------------

2.2 ACME COMMERCIAL FEED (ACME-HEALTH-2026-0426-117)

--------------------------------------------------------------------------------

Source reliability: C

   FACTS: Provider's own metadata admits:
   
     - "Acme internal analyst review: SAMPLED (not all items human-reviewed)"
     
     - Attribution layer uses a proprietary label (VITALSCORE) that "does not
       necessarily correspond to externally-tracked threat actor names"
       
     - The 41-indicator extract contains items the provider itself flags as
       "LIKELY NOISE", "DO NOT BLOCK" and clustering false positives.
       
   ASSESSMENT: Commercial incentive to maximize indicator volume drives
   inclusion of weakly clustered items. Broad automated collection is genuine
   value, but production methodology is inconsistent item-to-item: C.

Information credibility: 3-4 (varies sharply by item)

   3 - Items corroborated by HC3/researcher (the HEALTHBANE core set).
   
   4 - ML-clustered-only items (confidence 15-48, source_count_external 0):
       keyword-similarity items, shared CDN IPs, unrelated malware hashes.
       
   Attributing these item-level differences to credibility grades is the
   central contribution of the Task 1 triage: 15 of 41 feed items
   classified NOISE.

Timeliness: GOOD

   Extract dated 2026-04-26, latest of all four sources.

Relevance to MedDefense: MEDIUM-HIGH

   Broadest indicator coverage (rotation domains, variant hashes, prior
   campaign candidates) but heavily diluted. Useful for hunting breadth,
   not for blocking decisions.

Limitations:

   - Numeric confidence (15-96) is not comparable across items or to
     other sources' HIGH/MEDIUM/LOW scales.
     
   - No victim-telemetry basis disclosed for the clustering engine.
   
   - The 30.2% NOISE rate in this extract (per Task 1) is a concrete,
     measured false-positive cost of blind consumption.

Bias / visibility constraints:

   - Volume-maximization bias: publishing more indicators appears more
     valuable to subscribers regardless of precision.
     
   - Label bias: VITALSCORE applied at cluster level, mixing confirmed
     HEALTHBANE core with weakly related items.

--------------------------------------------------------------------------------

2.3 RESEARCHER BLOG (Marcus Weller, @mwresearch)

--------------------------------------------------------------------------------

Source reliability: C+

   FACTS: Solo researcher, self-hosted blog, no institutional review.
   
     Mitigating factors, all documented in the post itself:
     
     - Demonstrated method: recovered the phishing kit via an exposed
       directory listing on misconfigured attacker infrastructure, quoted
       actual config.php contents (OPS_CONTACT, EXFIL_ENDPOINT keys).
       
     - Coordinated with HC3: notified 2026-04-22, honored a 72-hour delay
       request. HC3's acknowledgment implies HC3 found him credible enough
       to coordinate with.
       
     - Self-declared limitations and honest separation of confidence tiers
       (HIGH for kit-confirmed, MEDIUM for fingerprint, LOW for artifacts).
       
   ASSESSMENT: Rigorous tradecraft and transparency, but a single
   unaccountable analyst whose claims rest on artifacts we cannot
   independently verify. C with a positive qualifier.

Information credibility: 2-3 (varies by claim)

   2 - Kit internals, config.php contents, infrastructure mappings:
       specific, internally consistent, corroborated where checkable
       (HC3 advisory and our own 4x00 headers match PHPMailer 6.6.0).
       
   3 - APT-MEDAGENT attribution: resting on three prior campaigns'
       tooling overlap, explicitly labeled MEDIUM by the author himself,
       with no telemetry basis.
       
   The attribution is the weakest link, and he says so.

Timeliness: VERY GOOD

   Published 2026-04-24, one day before HC3, with kit-level detail that
   predates the advisory.

Relevance to MedDefense: HIGH

   The kit fingerprint and rotation indicators (portal-secure-meddefense.com
   staged with the same kit) are uniquely actionable for anticipating
   infrastructure rotation, which is MedDefense's stated concern.

Limitations:

   - No victim telemetry (author's own admission).
   
   - Kit provenance (vendor-shipped vs operator-built) unresolved for the
     ZIP hash he publishes.
     
   - Single-analyst chain of custody for the kit artifacts.

Bias / visibility constraints:

   - Reputation incentive to publish first and to be the one who names
     the actor. He mitigates this with caveats, but the APT-MEDAGENT
     label serves his private tracking narrative.
     
   - Visibility stops at attacker-side infrastructure; he sees the weapon,
     not the victims.

--------------------------------------------------------------------------------

2.4 MEDEFENSE INTERNAL FINDINGS (MD-2026-IR-0414-001, 4x00)

--------------------------------------------------------------------------------

Source reliability: B

   FACTS: Our own investigation, reviewed by SOC lead (J. Chen) and CISO
   (Dr. Morales), documented methodology, verified against raw email
   headers we still possess.
   
   ASSESSMENT: First-party evidence, but produced by a small team during
   an active incident with narrow scope. B rather than A because the
   investigation had known open questions at close (Q1-Q5).

Information credibility: 1-2

   1 - Email headers, domain registrations, authentication results,
       user click/impact: directly observed in our own environment.
       
   2 - The credential-submission judgment ("LIKELY" for dmarsh): based on
       a 47-second HTTPS session and user self-report, not packet
       confirmation (explicitly deferred to 4x01).

Timeliness: FAIR

   Report dated 2026-04-16, covers only the 04-14 to 04-16 window.
   Predates all Stage 2/3 sector intelligence.

Relevance to MedDefense: MAXIMUM (by definition)

   This is our ground truth for what happened inside our network.

Limitations:

   - Stage 1 only; three emails; single-user impact assessment.
   
   - No follow-on authentication correlation at time of writing.
   
   - Attribution deliberately not attempted (correct posture for a
     single-site IR report).

Bias / visibility constraints:

   - Institutional self-interest is low, but scope blindness is total:
     we see one organization's slice of a 14-organization campaign.

================================================================================

3. SOURCE COMPARISON MATRIX

================================================================================

<pre>
Dimension              | HC3            | Acme Feed      | Researcher     | Internal 4x00
-----------------------|----------------|----------------|----------------|---------------
Reliability (A-F)      | A              | C              | C+             | B
Credibility (1-6)      | 1-2            | 3-4 (per item) | 2-3            | 1-2
Type                   | Gov advisory   | Commercial     | OSINT research | Internal IR
Published              | 2026-04-25     | 2026-04-26     | 2026-04-24     | 2026-04-16
TLP                    | CLEAR          | AMBER          | N/A (public)   | INTERNAL
Indicators (raw)       | 23             | 41             | 14             | 11
Indicators (unique,    | 23             | ~30 (15 NOISE  | 10             | 11
in deduped 48)         |                |  flagged)      |                |
Evidence base          | Victim         | Automated      | Attacker-side  | Own victim
                       | telemetry (6   | clustering +   | artifact       | telemetry
                       | orgs),         | sampled review | recovery       | (1 org)
                       | sandbox, pcap  |                | (kit)          |
Sector fit             | Healthcare     | Multi-sector   | Healthcare     | MedDefense
                       | (Midwest ISAC) |                | focus          | itself
Stage coverage         | 1, 2, 3        | 1, 2, 3        | 1 (+bridge to  | 1 only
                       |                | (diluted)      | 2/3 via kit)   |
Attribution stance     | UNCONFIRMED    | VITALSCORE     | APT-MEDAGENT   | none attempted
                       |                | (proprietary)  | (MEDIUM conf)  |
Noise burden           | None evident   | 31% of unique  | Low;           | None
                       |                | items NOISE    | self-labeled   |
Track record basis     | Institutional  | Partial        | 2024-25        | Prior 4x00
                       |                | (sampled)      | campaign docs  | work
Key unique value       | Campaign       | Breadth,       | Kit internals, | Ground truth
                       | designation,   | rotation/      | rotation       | for MedDefense
                       | authoritative  | variant IOCs   | prediction     | exposure
                       | staging facts  |                |                |
Primary weakness       | Victim-side    | Precision;     | Single analyst;| Single-org
                       | visibility     | unlabeled mix  | no telemetry   | scope
</pre>

================================================================================

4. ANALYTICAL NOTE: THE ATTRIBUTION CONFLICT

================================================================================

THE CLAIM UNDER DISPUTE: whether HEALTHBANE / VITALSCORE / APT-MEDAGENT refer
to one threat actor, and whether that actor can be named.

WHAT EACH SOURCE ACTUALLY SAYS (facts):

   - HC3: attribution UNCONFIRMED; will not endorse any commercial label.
   
   - Acme: VITALSCORE is a proprietary CLUSTER label that "does not
     necessarily correspond to externally-tracked threat actor names."
     The feed itself disclaims the equivalence.
     
   - Researcher: APT-MEDAGENT is HIS private tracking name, MEDIUM
     confidence, tooling/infrastructure overlap only, no telemetry. He
     explicitly states he does not know if VITALSCORE maps 1:1 to
     APT-MEDAGENT.
     
   - Internal 4x00: no attribution claim made.

ANALYSIS (assessment):

   The three labels are not actually in factual conflict, because they
   describe different objects:
   
     - HEALTHBANE is a CAMPAIGN designation (an activity cluster).
     
     - VITALSCORE is a PROVIDER-SIDE cluster tag over indicators, of which
       only the HC3-corroborated subset is confirmed HEALTHBANE.
       
     - APT-MEDAGENT is an ACTOR hypothesis built on tooling continuity
       across RXBRIDGE (2024-07), CLAIMBRIDGE (2024-11), MEDNEXUS (2025-09)
       and HEALTHBANE.
       
   Treating any pair as synonymous would be an analytical error. The
   
   strongest statement supported by all four sources: ONE OPERATIONAL
   
   INFRASTRUCTURE SET (Namecheap + Hostinger/DigitalOcean/OVH, PHPMailer
   
   6.6.0, Njalla for operator domains) underlies the confirmed campaign
   
   activity. Whether that set is one actor, one kit resold to multiple
   
   operators, or a crew using shared builders CANNOT BE DETERMINED from
   
   available evidence.

   Evidence specifically weakening the single-actor claim:
   
     - The researcher himself cannot determine whether the kit ZIP is
       "operator-signed or shipped by a kit vendor."
       
     - Acme's VITALSCORE cluster demonstrably over-includes (15 NOISE
       items in our triage), so cluster-label equality is unreliable.
       
   Evidence supporting (weakly) a persistent single operator:
   
     - Consistent kit structure across three years of campaigns
       (researcher's prior documentation).
       
     - Njalla registrar specifically for operator (vs lure) domains
       suggests operational security discipline typical of an individual
       or small crew, not commodity kit resale.

RECOMMENDED HANDLING (assessment):

   Use HEALTHBANE as the campaign name (HC3-designated, most authoritative,
   
   TLP:CLEAR shareable). Record VITALSCORE and APT-MEDAGENT as ALIASES with
   
   explicit provenance: "commercial cluster label" and "solo-researcher
   
   actor hypothesis (MEDIUM confidence)" respectively. Assign overall
   
   attribution confidence: LOW-MEDIUM. Revisit if victim-side telemetry
   
   or kit-signature evidence emerges. Do not put any actor name in the
   
   board-facing brief except as "unconfirmed attribution".

================================================================================

5. WEIGHTING RECOMMENDATION

================================================================================

5.1 Primary for confirmed healthcare-sector facts:

    HC3 ADVISORY - weight HIGHEST.
    
    Reason: A-rated source, victim-telemetry evidence base, healthcare-
    specific scope, explicit confidence methodology. All campaign facts
    (staging, timelines, victimology) in downstream products defer to
    HC3 unless contradicted by our own first-party observation.

5.2 Primary for technical details:

    RESEARCHER BLOG - weight HIGH for attacker-side tradecraft.
    
    Reason: only source with kit-level artifacts (config.php, kit
    structure, wkhtmltopdf fingerprint, staged rotation domain). His
    technical claims that intersect checkable evidence all verified
    (PHPMailer 6.6.0 matches our 4x00 headers; domain/IP overlaps match
    HC3). Weight his ATTRIBUTION lower than his TECHNICAL findings -
    they rest on different evidence bases.

5.3 For MedDefense-specific ground truth:

    INTERNAL 4x00 (and 4x01) - weight HIGHEST for our own exposure.
    
    First-party observation outranks any external source regarding what
    occurred in our environment; external sources contextualize it.

5.4 Treat carefully:

    ACME FEED - weight per-item, never wholesale.
    
    - BLOCK: only items corroborated by HC3 or the researcher
      (equivalently: only items that survived Task 1 triage as
      ACTIONABLE).
      
    - HUNT/MONITOR: uncorroborated items with structural indicators
      (naming-pattern domains, prior-campaign candidates such as
      rx-benefits-portal.com).
      
    - DISCARD: provider-flagged noise (CDN/shared IPs, ML-cluster-only
      hashes) - 15 items already excluded in Task 1.
      
    Never treat Acme's numeric confidence as directly comparable to
    HC3 or researcher confidence scales.

5.5 Rule for conflicting claims:

    1. Conflict between a factual claim and an assessment: the factual
       claim governs; the assessment is recorded with its confidence.
       
    2. Conflict between sources of different reliability grades: the
       higher-reliability source governs; the disagreement is documented
       in the IOC database provenance.
       
    3. Conflict involving our own first-party observation: our
       observation governs for our environment, and the discrepancy is
       reported back to the source (per HC3 Section 7.2 procedure).
       
    4. Attribution claims: no actor name is adopted on a single
       MEDIUM-confidence source. Aliases are recorded, decision deferred
       pending convergent evidence from at least two independent
       methodologies (telemetry + artifact, not two flavors of
       infrastructure analysis).
       
    5. Silence is not conflict: absence of an indicator from HC3 does
       not falsify it; HC3 derives indicators only from its 6 visible
       organizations (documented in 0-intel_intake.md conflict log).

================================================================================

END OF SOURCE ASSESSMENT                 MD-4x02-SOURCE-ASSESSMENT-001

================================================================================
