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

# [3. The OSINT Enrichment](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/3-osint_enrichment.md)
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

# [6. The Kill Chain Reconstruction](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/6-kill_chain.md)

## Goal: 

Reconstruct the full HEALTHBANE campaign across its attack phases using intelligence from all sources.

## Context: 

Intelligence from multiple sources describes different parts of the same campaign. HC3 describes all three stages but summarizes many details. The researcher's blog provides deep technical detail on Stage 1 and infrastructure. MedDefense's internal findings cover Stage 1 locally. The commercial feed contains many indicators but does not clearly map all of them to phases.

Your job is to reconstruct the complete story: what happened, in what order, using what tools, against which targets and with what evidence quality.

Materials:

    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    researcher_blog_analysis.txt
    meddefense_4x00_findings.txt
    commercial_feed_extract.json

## Instructions: 

Produce 6-kill_chain.md containing:

1. A timeline of the HEALTHBANE campaign:

    earliest known activity
    MedDefense Stage 1 event
    HC3 reporting window
    Stage 2 malware delivery window
    Stage 3 exfiltration window
    most recent reported event

2. For each attack phase:

Stage 1: Credential Harvesting

    phishing operation
    targeting pattern
    infrastructure used
    known victims
    MedDefense evidence
    success rate across reported victims if available

Stage 2: Malware Delivery

    transition from stolen credentials to follow-up emails
    document type
    malware or script artifacts
    download infrastructure
    persistence mechanisms
    evidence source

Stage 3: Data Exfiltration

    data targeted
    protocol or tool used
    exfiltration infrastructure
    evidence source
    what is confirmed and what remains unclear

3. Evidence quality assessment for each phase:

    confirmed evidence
    corroborated evidence
    inferred evidence
    unknowns

4. A section addressing what is not known:

    attribution gaps
    missing victim telemetry
    incomplete Stage 3 visibility
    commercial-feed uncertainty
    what collection would fill the gaps

---

# [7. The ATT&CK Navigator](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/7-attack_navigator.md)

## Goal: 

Map the HEALTHBANE campaign to MITRE ATT&CK techniques, distinguishing OBSERVED techniques from INFERRED techniques, and export the mapping as an ATT&CK Navigator layer file.

## Context: 

ATT&CK mapping connects adversary behavior to defensive planning. But a mapping is only useful if it is honest about what is observed and what is inferred. Marking every plausible technique as observed creates false confidence. Marking only confirmed techniques may miss useful hunting hypotheses.

The solution is a two-tier mapping: OBSERVED and INFERRED.

Materials:

    Use your findings from Tasks 0-6
    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    meddefense_4x00_findings.txt

## Instructions: 

Produce 7-attack_navigator.md and healthbane_layer.json.

Your Markdown file must:

1. List every ATT&CK technique identified in the campaign

2. Organize techniques by tactic

3. For each technique, provide:

    technique ID
    technique name
    OBSERVED or INFERRED classification
    evidence or reasoning
    source
    attack phase

Your ATT&CK Navigator JSON layer file must:

1. Include OBSERVED techniques with score 100

2. Include INFERRED techniques with score 50

3. Include comments explaining evidence or inference

4. Use red or high-priority styling for OBSERVED

5. Use amber or medium-priority styling for INFERRED

6. Be valid JSON

Your summary must include:

1. total techniques identified

2. observed vs inferred ratio

3. tactics with most coverage

4. tactics with least coverage

5. techniques that are most important for detection planning

---

# [8. The Detection Gap Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/8-detection_gaps.md)

## Goal: 

Compare the ATT&CK mapping from Task 7 against MedDefense's current documented detection capability, identifying detected, partially detected and undetected techniques.

## Context: 

An ATT&CK mapping tells you what the adversary does. A detection gap analysis tells you what you might miss.

Examples of acceptable evidence:

    4x00 documented IOC and email-focused detection rules
    4x01 packet-based detection recommendations
    local YARA rules from Tasks 9-10
    indicator database actions from Task 5
    documented telemetry that would be needed to close a gap

The goal is to produce a realistic gap analysis without requiring live infrastructure.

Materials:

    Use 7-attack_navigator.md
    Use healthbane_layer.json
    Use meddefense_4x00_findings.txt
    Use your 4x01 findings if available
    Use local outputs from Tasks 5, 9 and 10 after they are created

## Instructions: 

Produce 8-detection_gaps.md that:

1. Lists every technique from the Task 7 ATT&CK mapping

2. For each technique, assesses detection capability:

    DETECTED: A documented detection, YARA rule, IOC action or local analytic directly covers this technique
    PARTIALLY DETECTED: telemetry or indicators exist, but the detection is incomplete, too narrow or requires analyst review
    NOT DETECTED: no documented detection or reliable telemetry covers this technique

3. For each technique, include:

    ATT&CK ID
    technique name
    observed or inferred status
    current detection status
    evidence for that status
    gap explanation
    recommendation to close the gap

4. Prioritize gaps:

    Priority 1: OBSERVED and NOT DETECTED
    Priority 2: INFERRED and NOT DETECTED
    Priority 3: PARTIALLY DETECTED

5. Produce a prioritized gap list with:

    why the gap matters
    detection idea
    required data source
    suggested owner or implementation path

---

# [9. YARA Foundations](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/9-yara_phishing_pdf.yar)

## Goal: 

Write your first YARA rule targeting the phishing PDF structure identified in 4x00, learning YARA syntax, string definitions, conditions and metadata through a rule derived from campaign evidence.

## Context: 

In 4x00, you analyzed the PDF attachment from Email 5. You found it was generated by wkhtmltopdf 0.12.6, contained embedded URLs pointing to credential-harvesting infrastructure and followed a single-page lure-document pattern. The sample corpus for this project includes malicious and benign PDFs so you can test this detection locally.

This task does not require live infrastructure. You only need the local sample files and the yara command-line tool.

Materials:

    phishing_sample.pdf
    healthbane_lure_02.pdf
    clean_invoice.pdf
    benign_invoice.pdf
    samples_manifest.txt

## Instructions: 

Write a YARA rule file 9-yara_phishing_pdf.yar that detects PDFs matching the HEALTHBANE phishing-kit pattern.

Your rule must:

1. Include metadata:

    author
    description
    date
    reference to HEALTHBANE
    threat_level
    confidence

2. Define string patterns for:

    PDF magic bytes: %PDF
    wkhtmltopdf
    credential-harvesting paths such as /verify, /login, /portal, /enroll
    URL parameters such as token= or id=
    campaign-related domain fragments if appropriate

3. Define a logical condition:

    file must be a PDF
    must contain the creator/tooling string or strong lure metadata
    must contain at least two URL-related credential-harvesting patterns

4. Include comments explaining each string and condition choice

5. Compile and test the rule against the sample files:

    phishing_sample.pdf should match
    healthbane_lure_02.pdf should match
    clean_invoice.pdf should not match
    benign_invoice.pdf should not match

6. Document test results in comments at the bottom of the file or a short accompanying note.

**Expected Output:**

```bash
$ yara 9-yara_phishing_pdf.yar samples/
HEALTHBANE_Phishing_PDF samples/phishing_sample.pdf
HEALTHBANE_Phishing_PDF samples/healthbane_lure_02.pdf

$ echo "True positives: phishing samples detected"
$ echo "True negatives: clean invoice samples not detected"
```

---

# [10. The Pattern Arsenal](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/10-yara_arsenal.yar)
### advanced

## Goal: 

Write a set of YARA rules targeting multiple campaign artifacts: email header patterns, document metadata signatures and campaign-level variants.

## Context: 

The PDF rule in Task 9 detects one artifact type. A real detection arsenal covers multiple artifact types.

The HEALTHBANE campaign used a consistent operational pattern:

    PHPMailer sender tooling
    high-priority phishing headers
    healthcare-themed lookalike domains
    wkhtmltopdf-generated documents
    credential-harvesting paths
    reusable lure structure

YARA rules that detect these patterns can survive simple infrastructure rotation. Even when the attacker changes domains and IPs, operational patterns often remain.

Materials:

    healthbane_email_01.eml
    healthbane_email_02.eml
    healthbane_email_03.eml
    benign_newsletter.eml
    phishing_sample.pdf
    healthbane_lure_02.pdf
    clean_invoice.pdf
    benign_invoice.pdf
    samples_manifest.txt

## Instructions: 

Write a YARA rule file 10-yara_arsenal.yar containing at least three rules:

1. HEALTHBANE_Email_Headers

    Detects EML files containing characteristic email-header patterns:
        PHPMailer or PHPMailer variant
        high priority header
        healthcare or benefits/invoice/portal keyword
        lookalike sender domain pattern
    Must handle minor variation such as PHPMailer-6.6.0 vs PHPMailer 6.6.0

2. HEALTHBANE_Document_Metadata

    Detects PDFs or documents with tooling and lure metadata:
        wkhtmltopdf
        embedded credential-harvesting paths
        healthcare-themed lure text
        campaign-style URL parameters

3. HEALTHBANE_Campaign_Composite

    Detects stronger campaign-level evidence when multiple pattern families appear together in a file
    Example: document metadata + credential path, or email header + healthcare lure keyword
    This does not need to import other rules. It can independently combine strings representing multiple campaign behaviors.

For each rule:

1. Include metadata

2. Include comments

3. Use logical conditions

4. Avoid matching benign samples where possible

5. Document expected true positives and true negatives

Test all rules against the samples directory and document results.

---

# [11. Testing the Arsenal](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/11-yara_testing.sh)

## Goal: 

Systematically test all YARA rules from Tasks 9 and 10 against a controlled test set, measuring true positive rate, false positive rate and false negative rate.

## Context: 

A YARA rule that compiles is not automatically a production-ready rule. Detection rules must be tested against both malicious and benign samples to understand operational characteristics. A rule with high true positives but many false positives will flood analysts. A rule with no false positives but low true positives will miss variants.

This task teaches rule validation and deployment decision-making.

Materials:

    samples_manifest.txt
    Use all files in the provided sample corpus
    Use your 9-yara_phishing_pdf.yar
    Use your 10-yara_arsenal.yar

## Instructions: 

Write a script 11-yara_testing.sh that:

1. Runs each YARA rule from Tasks 9 and 10 against every file in the samples directory

2. Uses the manifest or task instructions to determine expected results:

    phishing PDFs: true positives
    healthbane emails: true positives
    benign invoices/newsletter: true negatives
    known variant samples: should be handled when possible

3. Records for each rule:

    true positives
    true negatives
    false positives
    false negatives

4. Calculates:

    detection rate: TP / (TP + FN)
    false positive rate: FP / (FP + TN)
    precision: TP / (TP + FP)

5. For each false negative:

    explain why the rule missed
    propose a modification

6. For each false positive:

    explain why the rule triggered
    propose a safe tuning change

7. Produces a deployment recommendation:

    DEPLOY
    TUNE
    MONITOR

**Expected Output:**

```bash
$ ./11-yara_testing.sh

=== YARA TESTING SUMMARY ===
Rule: HEALTHBANE_Phishing_PDF
TP: 2 | TN: 2 | FP: 0 | FN: 0
Detection rate: 100%
False positive rate: 0%
Precision: 100%
Recommendation: DEPLOY

Rule: HEALTHBANE_Email_Headers
TP: 3 | TN: 1 | FP: 0 | FN: 0
Detection rate: 100%
False positive rate: 0%
Precision: 100%
Recommendation: DEPLOY

Rule: HEALTHBANE_Campaign_Composite
TP: [calculated]
TN: [calculated]
FP: [calculated]
FN: [calculated]
Recommendation: DEPLOY / TUNE / MONITOR

---

# [12. The Adversary Profile](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/12-adversary_profile.md)
### advanced

## Goal: 

Produce a structured threat actor profile for the HEALTHBANE campaign operator, synthesizing intelligence from all sources into an assessment of capability, intent, infrastructure preferences and operational patterns.

## Context: 

The intelligence brief needs an adversary section. But profiling a threat actor requires discipline. You must separate what you know from what you infer and from what you do not know.

This project includes conflicting attribution labels. Do not overclaim. The recommended working designation is HEALTHBANE campaign operator unless stronger attribution evidence is presented.

Materials:

    HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt
    commercial_feed_extract.json
    researcher_blog_analysis.txt
    meddefense_4x00_findings.txt

## Instructions: 

Produce 12-adversary_profile.md containing:

1. Identity and Attribution

    names or designations used:
        HEALTHBANE
        VITALSCORE
        APT-MEDAGENT
    confidence in each claim
    supporting evidence
    caveats
    final working designation recommendation

2. Capability Assessment

    technical sophistication
    tooling quality
    infrastructure management
    resource level
    whether the actor appears APT-level, mid-tier cybercrime or opportunistic

3. Intent and Targeting

    sector focus
    geographic focus
    likely objectives:
        credentials
        patient data
        insurance data
        malware delivery
        financial gain
    targeting methodology

4. Operational Signature

    infrastructure pattern
    registrars and hosting
    domain naming
    TLS certificate usage
    tooling such as PHPMailer and wkhtmltopdf
    urgency-based social engineering
    multi-department targeting

5. Predictive Assessment

    what will likely change:
        domains
        IPs
        hashes
    what will likely stay the same:
        tooling
        naming patterns
        healthcare targeting
        credential-harvesting playbook
    what would indicate the actor has retooled

6. Confidence and Unknowns

    what is known
    what is inferred
    what remains unknown

---

# [13. The Intelligence Brief](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/13-intelligence_brief.md)

## Goal: 

Produce the final professional intelligence brief on the HEALTHBANE campaign, suitable for MedDefense leadership and healthcare-sector partners.

## Context: 

This is the deliverable James Chen asked for. It synthesizes every finding from Tasks 0-12 into a single document for two audiences:

    MedDefense leadership, who need to understand risk and make decisions
    Healthcare-sector partners, who need actionable intelligence

The brief must be technically rigorous but accessible in its executive section.

Materials:

    Use all outputs from Tasks 0-12
    Use all provided source files

## Instructions: 

Produce 13-intelligence_brief.md containing:

1. Executive Summary

    maximum 8 sentences
    written for Dr. Morales and the board
    explain:
        what HEALTHBANE is
        what happened to MedDefense
        what happened at other organizations
        current detection posture
        top 3 recommended actions

2. Adversary Profile

    summary from Task 12

3. Campaign Analysis

    three-stage breakdown from Task 6
    timeline
    evidence confidence

4. ATT&CK Mapping

    observed vs inferred distinction
    key techniques
    detection relevance

5. Detection Gap Assessment

    prioritized gaps from Task 8
    focus on observed-not-detected and inferred-not-detected items

6. Indicator of Compromise Table

    from Task 5
    organized by attack phase
    include confidence and recommended action

7. YARA Rule Summary

    rules developed
    test results
    deployment status

8. Recommendations

    Immediate (48 hours)
    Short-term (2 weeks)
    Medium-term (30 days)

9. Intelligence Gaps and Collection Priorities

    what remains unknown
    what collection would answer it
    who should be asked or what data should be reviewed

---

# [14. Closing the Loop](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x02_intelligence_driven_defense/14-closing_the_loop.sh)
### advanced

## Goal: 

Operationalize the intelligence locally by producing deployable detection artifacts, updated IOC lists and unanswered intelligence questions.

## Context: 

An intelligence brief that sits on a shelf is not intelligence. The loop is closed only when intelligence changes defensive posture.

You will create local artifacts that could be handed to a detection engineering team:

    YARA rules
    local detection-rule drafts
    IOC list exports
    before/after coverage summary
    unanswered intelligence questions
    recommended collection actions

Materials:

    Use indicator_database.json
    Use 9-yara_phishing_pdf.yar
    Use 10-yara_arsenal.yar
    Use 8-detection_gaps.md
    Use 13-intelligence_brief.md

## Instructions: 

Write a script 14-closing_the_loop.sh that produces a local operationalization package.

The script must:

1. Validate YARA rules load without syntax errors:

    9-yara_phishing_pdf.yar
    10-yara_arsenal.yar

2. Create a local directory:

operational_package/

3. Copy or generate:

    YARA rules into operational_package/yara/
    high-confidence IOC list into operational_package/iocs/healthbane_high_confidence_iocs.txt
    full IOC JSON into operational_package/iocs/indicator_database.json
    detection rule drafts into operational_package/detections/
    coverage summary into operational_package/coverage_summary.md
    unanswered questions into operational_package/intel_gaps.md

4. Create at least 2 local detection-rule drafts addressing Priority 1 gaps from Task 8. These may be:

    Sigma-style YAML
    Wazuh-style XML draft
    pseudocode rule
    YARA rule reference
    DNS analytic pseudocode

5. Produce a before/after comparison:

    detection posture before 4x02:
        4x00 IOC-focused rules
        limited file-pattern detection
    detection posture after 4x02:
        validated indicator database
        YARA rules
        ATT&CK gap-driven detection recommendations
        high-confidence IOC export

6. Document 3-5 unanswered intelligence questions and propose specific collection actions.

**Expected Output:**

```bash
$ ./14-closing_the_loop.sh

================================================================
   CLOSING THE LOOP - Intelligence Operationalization
================================================================

[*] YARA validation: 4 rules, 0 errors                    [OK]

[*] Operational package created:
    operational_package/yara/
    operational_package/iocs/
    operational_package/detections/
    operational_package/coverage_summary.md
    operational_package/intel_gaps.md

[*] High-confidence IOC export created                    [OK]
[*] Detection drafts created: 2                            [OK]

=== BEFORE vs AFTER ===
Before 4x02:
  IOC-focused detection from 4x00
  limited coverage for campaign variants

After 4x02:
  enriched indicator database
  YARA coverage for PDF and email artifacts
  ATT&CK-driven detection gap plan
  local operational package ready for handoff

=== UNANSWERED INTELLIGENCE QUESTIONS ===
  1. Stage 3 exfiltration details across non-MedDefense victims
     -> Collection action: request additional partner telemetry through HC3
  2. Whether VITALSCORE maps exactly to HEALTHBANE
     -> Collection action: request clarification from commercial provider
  3. Stage 2 malware family classification
     -> Collection action: sandbox Stage 2 samples from trusted source
  4. Campaign resumption timeline
     -> Collection action: monitor registrations matching domain patterns

INTELLIGENCE LOOP STATUS: READY FOR DEFENSIVE HANDOFF
================================================================
```

---
