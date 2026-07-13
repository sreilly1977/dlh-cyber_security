# [0. The Intelligence Briefing](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/0-threat_landscape_summary.md)

## Goal
Extract a structured threat landscape overview from raw intelligence sources specific to the healthcare sector.

## Context
Marcus's laptop contains a folder of threat intelligence files he collected but never synthesized. Some are annotated. Some are just raw downloads. Together, they paint a picture of who targets hospitals and why.

Your job is to turn raw intelligence into structured analysis. Read everything. Then produce a summary that answers three questions:
1. Who attacks healthcare organizations?
2. Why?
3. What does the data tell us about trends?

## Provided Files
- [`marcus-intelligence-dossier.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/marcus-intelligence-dossier.txt)

## Instructions
Review the entire intelligence dossier. Produce a **Healthcare Threat Landscape Summary** organized into:

### 1. Threat Actor Overview
For each major actor category identified in the dossier (expect 4–5 categories), summarize:
- Who they are
- Their primary motivation for targeting healthcare
- Their typical level of sophistication

### 2. Healthcare Targeting Logic
Why is healthcare a preferred target sector? Identify at least **4 distinct reasons** cited or implied in the intelligence sources. Do not just list them—explain the mechanism:
- Why does each factor make hospitals attractive?

### 3. Trend Analysis
Based on the dossier data, what is changing?
- Are attacks increasing?
- Shifting in method?
- Targeting different assets?

Identify at least **2 trends** with supporting evidence from the sources.

### 4. MedDefense Relevance
For each actor category, write **one sentence** assessing whether this type of actor is likely to target an organization of MedDefense's profile:
- Regional hospital
- 2,000 staff
- No research programs
- Regulated patient data

---

# [1. The Threat Actor Taxonomy](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/1-threat_actor_taxonomy.md)

## Goal
Classify threat actors by type, attributes and motivation from observed behavior alone.

## Context
Intelligence analysts rarely know who attacked an organization at the time of investigation. What they have is behavior: what the attacker did, how they did it, what they targeted and what they left behind. From behavior, you infer the actor type. From the actor type, you predict their next move.

Frameworks define six threat actor categories:

1. **Nation-state**
2. **Organized crime**
3. **Hacktivist**
4. **Insider threat**
5. **Unskilled attacker**
6. **Shadow IT**

Each has characteristic attributes:

- **Internal vs External:** Does the actor operate from inside or outside the organization?
- **Resources and Funding:** Does the actor have significant financial backing, or are they working with freely available tools?
- **Sophistication:** Does the actor develop custom tools and techniques, or rely on publicly available exploits?

Motivations vary: data exfiltration, espionage, service disruption, blackmail, financial gain, philosophical or political beliefs, ethical motivations, revenge, chaos, war.

## Provided Files
- [`threat-actor-reports.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/threat-actor-reports.txt) (8 anonymized intelligence reports, each 3–4 sentences describing an attack)

## Instructions
For each of the 8 reports, produce a structured classification:


```
Report [Letter]:
  Actor Type: [One of the 6 categories]
  Internal/External: [Internal / External / Could be either - justify]
  Resources: [High / Medium / Low - justify]
  Sophistication: [High / Medium / Low - justify]
  Primary Motivation: [One from the Sec+ motivation list - justify]
  Confidence Level: [How certain are you? High/Medium/Low and why]
```

> For Report G, which is deliberately ambiguous, explain why multiple actor types could fit and which evidence would help you distinguish between them.
