# Introduction

> "The goal is to turn data into information, and information into insight." 
>
> — Carly Fiorina

You have spent the past two projects doing what SOC analysts do every day: investigating evidence. In 4x00, you analyzed phishing emails and extracted campaign indicators. In 4x01, you analyzed network packet captures and reconstructed what happened on the wire. Both projects were incident-response driven: evidence arrived, you analyzed it, and you reported findings.

But the best defenders do not only react.

Intelligence-driven defense starts before the next alert arrives. Instead of waiting for the attacker to appear in logs or packet captures, defenders study the adversary's infrastructure, behavior, tooling and targeting patterns. They consume threat intelligence from sector partners, government advisories, commercial feeds and open-source researchers. They assess what is reliable, enrich what is useful, discard what is noisy and turn the final intelligence into detection logic.

In this project, MedDefense receives multiple intelligence sources about a campaign now tracked as HEALTHBANE. The sources do not fully agree. HC3 publishes a TLP:CLEAR advisory with confirmed healthcare-sector intelligence. A commercial feed labels related activity as VITALSCORE but includes intentional noise and weakly clustered indicators. A public researcher claims overlap with APT-MEDAGENT but admits the attribution is only medium confidence. MedDefense also has its own internal findings from 4x00.

Your job is to turn those raw sources into intelligence.

You will parse the sources, triage indicators, assess source credibility, enrich IOCs, map infrastructure, produce an indicator database, reconstruct the campaign kill chain, map ATT&CK techniques, identify detection gaps, write YARA rules, test them and produce a final intelligence brief.

This project is independent. No live SIEM, Wazuh server, Suricata sensor or previous Module 2/3 infrastructure is required. When a task asks for detection rules or operationalization, you will write rules, detection logic, JSON outputs or documentation artifacts locally. The work should be evidence-based and reproducible using the provided materials.

## Why This Matters

Every SOC beyond Tier 1 requires intelligence operationalization. Tier 2 analysts, threat intelligence analysts and detection engineers all need to consume intelligence, evaluate sources, enrich indicators, map adversary behavior and translate findings into detection.

The difference between an analyst who reads a threat report and an analyst who operationalizes intelligence is this:

    one knows what happened somewhere else
    the other prepares their organization to detect what may happen next

The HEALTHBANE campaign is built to teach this skill. Some indicators are high-confidence and actionable. Some are only contextual. Some are noisy, broad or weakly attributed. Some sources agree. Others conflict. The work is not simply copying IOCs into a list. The work is deciding what to trust, what to block, what to monitor, what to hunt for and what still needs collection.

The skills you build here directly support later threat hunting, malware analysis, detection engineering and executive reporting.

## Context

Week twelve at MedDefense Health Systems. Monday morning.

Three weeks have passed since the phishing investigation.

The IOCs MedDefense submitted to HC3 were useful. HC3 has now published a comprehensive TLP:CLEAR advisory describing a coordinated campaign targeting healthcare organizations. The advisory designates the campaign HEALTHBANE and includes indicators from multiple affected organizations.

James Chen calls a meeting. Dr. Patricia Morales is on the call.

"HC3 published the advisory Friday. It confirms what we suspected but goes further than our internal investigation. The phishing emails we caught were Stage 1. Two other organizations did not stop the campaign early enough. They saw Stage 2 malware delivery and Stage 3 data exfiltration."

He pauses.

"We stopped the campaign at MedDefense before later-stage compromise, but only because a user reported the email and the team investigated quickly. If the attacker returns with new infrastructure, our old domain and IP blocklists may not help. We need to understand the adversary's behavior, not just yesterday's IOCs."

Dr. Morales adds:

"The board meeting is in 10 days. I need to explain our defensive posture against HEALTHBANE. I do not need a list of random indicators. I need to know what we trust, what we can detect, what we cannot detect and what we are doing about it."

You receive the 4x02 intelligence package.

It includes:

    an HC3 sector advisory
    a commercial CTI feed extract
    a researcher's technical blog analysis
    MedDefense's internal 4x00 findings
    a YARA sample corpus with benign and malicious files

The sources disagree in important ways.

HC3 calls attribution unconfirmed.
The commercial feed uses the proprietary label VITALSCORE.
The researcher uses APT-MEDAGENT with medium confidence.
MedDefense's internal report avoids attribution entirely.

Your task is to produce a disciplined intelligence analysis that separates facts from assessments, indicators from noise and confirmed behavior from inference.

---

# [0. The Intelligence Intake](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/0-intel_intake.md)

## Goal: 

Parse four intelligence sources about the HEALTHBANE campaign, extracting structured data from each and producing a normalized collection of raw intelligence items.

## Context: 

Intelligence does not arrive in a single format. An HC3 advisory is a structured narrative document. A commercial threat feed is a JSON array of indicators. A researcher's blog post mixes technical analysis with opinion. Your own investigation findings are organized around a specific incident. Before any analysis can begin, the raw intelligence must be parsed, extracted and organized into a consistent format that allows comparison.

Materials:

    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    commercial_feed_extract.json
    researcher_blog_analysis.txt
    meddefens_4x00_findings.txt

## Instructions: 

Produce 0-intel_intake.md that processes the four intelligence sources and produces a structured intake summary.

For each source, identify:

1. Source name

2. Source type:

    government advisory
    commercial feed
    open-source research
    internal investigation

3. Date published or report date

4. TLP classification or distribution marking

5. Number of indicators provided

6. Types of indicators:

    domains
    IPs
    hashes
    URLs
    email addresses

7. One-line summary of the intelligence claim

8. Key limitations or caveats stated by the source

Produce a consolidated view showing:

1. Total raw indicators across all sources

2. Total unique indicators after deduplication

3. Indicators that appear in multiple sources

4. Indicators that appear in only one source

5. Source conflicts that must be resolved later, especially:

    attribution labels
    confidence differences
    commercial-feed noise
    indicators present in one source but missing from stronger sources

**Expected reference counts from the lab materials:**

HC3 advisory:       23 indicators
Commercial feed:    41 indicators
Researcher blog:    14 indicators
MedDefense 4x00:    11 indicators
Total raw:          89 indicators
Unique deduped:     64 indicators

---

# [1. Signal vs Noise](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/1-indicator_triage.sh)

## Goal: 

Triage the 64 unique indicators from the intake by categorizing each as ACTIONABLE, CONTEXTUAL or NOISE, with written justification.

## Context: 

Not every indicator in a threat feed belongs in your firewall. An attacker's C2 domain may be actionable. The registrar they used may be contextual. A shared-hosting IP or a broad cloud provider range may be noise if used for blocking. The analyst must triage indicators before operationalizing them, or risk flooding the SOC with false positives.

The commercial feed intentionally includes noisy indicators. Your job is to separate defensible security actions from overbroad or weakly supported intelligence.

Materials:

    commercial_feed_extract.json
    Use your 0-intel_intake.md output

## Instructions: 

Write 1-indicator_triage.sh that reads the consolidated indicator list from Task 0 and classifies each indicator.

For each indicator, include:

1. Indicator type

2. Indicator value

3. Source or sources

4. Category:

    ACTIONABLE
    CONTEXTUAL
    NOISE

5. One-line justification

6. Confidence level

7. Uncertainty flag if the category assignment is not straightforward

Pay special attention to:

    IPs that belong to shared hosting
    domains that are expired, sinkholed or only historically useful
    hashes from the commercial feed that are not corroborated by other sources
    broad infrastructure labels such as hosting provider or registrar
    the commercial feed's attribution to VITALSCORE
    indicators clustered by weak ML similarity only

Produce summary statistics:

1. Total indicators reviewed

2. Count and percentage ACTIONABLE

3. Count and percentage CONTEXTUAL

4. Count and percentage NOISE

5. Top reasons indicators were downgraded

6. Top indicators that should be used for immediate detection

**Expected output** should clearly show that not all 64 unique indicators are operationally safe to block.

---

# [2. The Source Credibility Matrix](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/2-source_assessment.md)

## Goal: 

Assess the reliability of each intelligence source and the credibility of its content using a structured methodology.

## Context: 

Intelligence analysts use structured frameworks to avoid bias. The Admiralty Code, also called the NATO system, rates sources from A to F and information from 1 to 6. This matters when sources contradict each other. When one source makes an extraordinary claim, such as threat actor attribution, your assessment determines how much confidence to assign.

Materials:

    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    commercial_feed_extract.json
    researcher_blog_analysis.txt
    meddefense_4x00_findings.txt

## Instructions: 

Produce 2-source_assessment.md containing:

1. A brief explanation of the assessment methodology used:

    Admiralty Code adapted for cyber intelligence
    source reliability A-F
    information credibility 1-6
    confidence levels HIGH, MEDIUM, LOW

2. For each of the 4 sources, assess:

    source reliability
    information credibility
    timeliness
    relevance to MedDefense
    limitations
    bias or visibility constraints

3. A source comparison matrix showing all four sources side by side

4. An analytical note addressing the key attribution conflict:

    HC3 uses HEALTHBANE and does not endorse VITALSCORE
    commercial feed uses VITALSCORE
    researcher uses APT-MEDAGENT with medium confidence
    MedDefense 4x00 avoids attribution

5. A weighting recommendation:

    which source should be prioritized for confirmed healthcare-sector facts
    which source is useful for technical details
    which source should be treated carefully because of noise or weak clustering
    how conflicting claims should be handled

---

# [3. The OSINT Enrichment]((https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/3-osint_enrichment.md)
### advanced

## Goal: 

Enrich the actionable indicators from Task 1 using OSINT methods, adding context that transforms raw IOCs into intelligence-grade indicators.

## Context: 

A domain name by itself is an indicator. A domain name with registration date, registrar, hosting provider, certificate details, passive DNS history and reputation context is intelligence. Enrichment is how raw IOCs become defensible security actions.

This lab does not require live external queries. If live tools are unavailable, document the command that would be used and use the simulated or provided evidence from the intelligence sources.

Materials:

    Use your actionable indicators from Task 1
    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    researcher_blog_analysis.txt
    commercial_feed_extract.json

## Instructions: 

Write 3-osint_enrichment.md that enriches each actionable indicator.

For each domain, document:

1. WHOIS:

    registration date
    registrar
    registrant if available

2. DNS resolution:

    current resolution
    historical resolution if available

3. Certificate transparency:

    crt.sh query or documented equivalent
    certificate subject
    related certificates

4. Reputation:

    VirusTotal or equivalent result
    detection ratio or community score if available

5. Defensive meaning:

    block
    alert
    hunt
    monitor

For each IP, document:

    ASN
    hosting provider
    geolocation
    reverse DNS
    reputation
    whether blocking is safe or risky

For each hash, document:

1. file type

2. file size if available

3. first seen date

4. detection ratio if available

5. behavioral tags

6. whether the hash is campaign-specific or weakly sourced

For each enrichment type, document:

1. command or method used

2. what the result means defensively

3. whether enrichment changes confidence level

4. whether the indicator remains actionable

---

# [4. Infrastructure Archaeology](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/4-infra_archaeology.md)
### advanced

## Goal: 

Extend the infrastructure map from 4x00 by incorporating indicators from all four intelligence sources, revealing the full scope of the HEALTHBANE campaign's operational infrastructure and identifying clusters that suggest shared ownership.

## Context: 

In 4x00, MedDefense mapped the infrastructure for three phishing domains. The HC3 advisory expands the campaign to Stage 2 and Stage 3. The researcher's blog identifies kit infrastructure and operational tooling. The commercial feed adds possible related infrastructure, but also includes noise.

Your job is to extend the map, identify clusters and decide whether additional indicators belong to the same campaign or only share superficial similarities.

Materials:

    meddefense_4x00_findings.txt
    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    researcher_blog_analysis.txt
    commercial_feed_extract.json

## Instructions: 

Write 4-infra_archaeology.md that:

1. Combines the 4x00 infrastructure map with indicators from all sources

2. Groups infrastructure into clusters based on:

    same registrar
    registration window
    hosting provider
    ASN
    certificate patterns
    email-sending software
    document-generation tooling
    domain naming conventions

3. Identifies pivot points:

    domains that bridge Stage 1 and Stage 2/3
    IPs shared across multiple sources
    certificate or hosting overlaps
    config references such as C2 endpoints

4. Assesses commercial feed additions:

    which belong to the same campaign
    which are plausible but unconfirmed
    which are likely noise
    which should not be operationalized without more evidence

5. Produces an updated ASCII infrastructure diagram showing:

    Stage 1 credential-harvest infrastructure
    Stage 2 malware-delivery infrastructure
    Stage 3 DNS-exfiltration infrastructure
    uncertain or low-confidence cluster
    source attribution for each cluster

---

# [5. The Indicator Database](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/5-indicator_database.sh)
### advanced

## Goal: 
Produce a structured, deduplicated indicator database in JSON format containing every validated indicator from the investigation.

## Context: 

The final indicator database is the foundation for ATT&CK mapping, YARA rules, detection engineering and the intelligence brief. It must be structured, machine-readable and annotated with enough metadata to support automated ingestion into a detection system or threat intelligence platform.

This project does not require ingesting the database into Wazuh or any live system. The deliverable is the local JSON database and validation summary.

Materials:

    Use outputs from Tasks 0-4
    commercial_feed_extract.json
    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    researcher_blog_analysis.txt
    meddefense_4x00_findings.txt

## Instructions: 

Write a script 5-indicator_database.sh that produces indicator_database.json.

The JSON must contain an array of indicator objects. Each object must include:

1. type

    domain
    ip
    hash
    url
    email

2. value

3. first_seen

4. last_seen

5. sources

6. confidence

    HIGH
    MEDIUM
    LOW

7. category

    ACTIONABLE
    CONTEXTUAL

8. cluster

9. enrichment_summary

10. attack_phase

- Stage 1
- Stage 2
- Stage 3
- Unknown

11. recommended_action

- BLOCK
- ALERT
- MONITOR
- NONE

The script must also print summary statistics:

BY TYPE
BY CONFIDENCE
BY ATTACK PHASE
BY RECOMMENDED ACTION
Database validation

**Expected Output:**

```bash
$ ./5-indicator_database.sh
[*] Database written to: indicator_database.json
[*] Total indicators: 47 (after deduplication and noise removal)

BY TYPE:
  Domains: 13  |  IPs: 11  |  Hashes: 9  |  URLs: 8  |  Emails: 6

BY CONFIDENCE:
  HIGH: 22  |  MEDIUM: 18  |  LOW: 7

BY ATTACK PHASE:
  Stage 1 (Credential Harvest): 28
  Stage 2 (Malware Delivery):   11
  Stage 3 (Data Exfiltration):   4
  Unknown:                        4

BY RECOMMENDED ACTION:
  BLOCK: 19  |  ALERT: 15  |  MONITOR: 10  |  NONE: 3

[*] Database validation: PASS
```

---
