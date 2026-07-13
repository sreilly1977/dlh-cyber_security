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

# [2. The Ransomware Dossier](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/2-ransomware_assessment.md)

## Goal
Analyze the operational model of a ransomware-as-a-service group and evaluate its specific threat to MedDefense.

## Context
Three regional hospitals within 200 miles of MedDefense have been hit by ransomware in the past 8 months. Two paid. The third lost 3 weeks of data and diverted ambulances for 11 days. James Chen is not sleeping well.

Ransomware is not a monolithic threat. It is an industry. Developers build the tools. Affiliates deploy them. Initial access brokers sell the entry points. Negotiators handle the extortion. Understanding this ecosystem is the difference between a generic "ransomware is bad" slide and a specific, actionable assessment of MedDefense's exposure.

## Provided Files
- [`blackreef-ransomware-profile.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/blackreef-ransomware-profile.txt) (a detailed profile of a fictional but realistic RaaS group)

## Instructions
Read the BlackReef profile. Then produce a **Ransomware Threat Assessment** for MedDefense with four sections:

### 1. Operational Model Summary
Describe how BlackReef operates. Cover:
- The RaaS model (developer vs affiliate roles)
- The attack lifecycle (from initial access to extortion)
- The double extortion mechanism

Keep it factual and concise.

### 2. Healthcare Targeting Logic
Using the BlackReef profile AND the intelligence dossier from Task 0, explain in one substantive paragraph why hospitals are structurally ideal targets for ransomware groups. Identify at least **3 specific factors**.

### 3. MedDefense Exposure Assessment
Reference your Gap Analysis from Project 0x00 directly. Identify the **4 gaps** that a BlackReef-style group would exploit, in order of their likely attack sequence. For each gap:
- Name the gap (with Gap ID if possible)
- Explain how it enables the next step in the attack chain
- Assess what happens if that gap is not closed

### 4. Likelihood Assessment
On a scale of **Critical / High / Medium / Low**, how likely is it that MedDefense faces a ransomware attack within the next 12 months? Justify your assessment using:
- Sector statistics (from the dossier)
- MedDefense-specific factors (from your posture assessment)

# [3. The Insider File](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/3-insider_assessment.md)

## Goal
Distinguish malicious from negligent insider threats, identify behavioral indicators and connect each scenario to existing control gaps.

## Context
Not every threat comes through the firewall. James Chen brings this up over coffee:

> "When the Board hears 'cybersecurity,' they picture a hoodie-wearing hacker in a dark room. They do not picture a billing clerk who copies patient records to a USB drive because she's angry about being passed over for a promotion. But our incident log from last year tells a different story."

The insider threat is particularly dangerous in healthcare because clinical staff need broad access to patient data to do their jobs. The challenge is not restricting access—it is detecting when legitimate access becomes illegitimate use.

## Instructions
You are given **5 insider scenarios** drawn directly from the MedDefense environment. For each one, produce a structured analysis:

### Scenario 1 - The Shared Login
The Radiology department uses a shared account (`raduser/radiology1`) for the PACS workstation. Multiple technicians use the same credentials throughout the day. Nobody logs out between patients.

### Scenario 2 - The Ghost Account
An IT support contractor's VPN account remained active for **47 days** after their contract ended. Network logs show the account authenticated **3 times** during off-hours in the weeks after termination. *(Reference: this mirrors Incident F from your 1x00 incident analysis.)*

### Scenario 3 - The Personal NAS
Dr. Patel in Cardiology connected a personal NAS device to his office network port. He stores research data and "convenience copies" of patient files he consults frequently. The NAS is:
- Not encrypted
- Not backed up
- Not visible to IT

*(Reference: the shadow IT finding from 1x00 Task 11.)*

### Scenario 4 - The Curious Employee
A registration clerk at the front desk accesses the EHR records of a local politician who was treated at MedDefense Central. She does not modify anything. She tells a friend about the visit. The friend posts it on social media.

### Scenario 5 - The Overworked Admin
A sysadmin, overwhelmed by tickets, writes a script to automate password resets. The script stores **Active Directory admin credentials in plaintext** in a file on his desktop. He shares the script with a colleague via email so they can "help with the backlog."

## For Each Scenario:

```
Scenario [N]:
  Classification: [Malicious / Negligent - justify]
  Behavioral Indicators: [What observable signs could have flagged this before damage occurred? List 2-3]
  Existing Control (from 1x00): [Which control from your Control Matrix covers or should cover this? If none, say so]
  Gap Exploited (from 1x00): [Which gap from your Gap Analysis enabled this scenario? Reference Gap ID if possible]
  Recommended Mitigation: [One specific control - Technical or Administrative - that would reduce this risk]
```

After completing the 5 individual analyses, write a **Pattern Assessment** answering:

**What systemic weakness at MedDefense makes insider threats particularly dangerous?**

Connect your answer to at least **2 findings from Project 1x00**. Explain how existing control gaps create an environment where insider threats can flourish undetected.

# [4. The Human Vector](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x01_know_your_enemy/4-social_engineering_analysis.md)

## Goal
Identify, classify and analyze social engineering attack vectors in a healthcare context, including red flags and countermeasures.

## Context
The most sophisticated firewall in the world is useless if an attacker can call the front desk and talk their way into a password reset. Social engineering exploits the one system you cannot patch: human psychology. In healthcare, the exploitation surface is enormous. Clinical staff are trained to be helpful. Administrative staff handle urgent requests all day. Everyone is busy, stressed and inclined to take shortcuts.

The Security+ framework (2.2) defines these human-targeted vectors:
- Phishing (email)
- Vishing (voice/phone)
- Smishing (SMS)
- Pretexting (fabricated scenarios)
- Business Email Compromise (BEC)
- Impersonation
- Watering Hole Attacks
- Brand Impersonation
- Typosquatting

Each exploits a different psychological lever: urgency, authority, familiarity, fear or helpfulness.

## Instructions
Analyze the following **7 social engineering scenarios** targeting MedDefense. For each one, produce:

```
Scenario [N]:
  Vector Type: [Exact Sec+ 2.2 term]
  Target: [Role at MedDefense + why this person is vulnerable]
  Psychological Lever: [Urgency / Authority / Familiarity / Fear / Helpfulness / Curiosity]
  Red Flags: [3 specific indicators the target should notice]
  Technical Control: [One control that would reduce the risk]
  Administrative Control: [One policy or procedure that would reduce the risk]
```

## The Scenarios

### Scenario 1 - Vendor Impersonation
An email arrives in the inbox of Sarah Park (IT Director), appearing to come from FortiGate support: *"Critical firmware vulnerability detected on your FortiGate 100F. Click here to download the emergency patch. Failure to patch within 24 hours may result in service termination."* The sender domain is `fortinet-support.net`.

### Scenario 2 - BEC (Business Email Compromise)
The CFO (Robert Kim) receives an email from what appears to be Dr. Patricia Morales (CEO): *"Robert, I need you to process a wire transfer of $85,000 to the account below immediately. This is for a confidential equipment acquisition. Do not discuss with anyone until the deal closes. I am in meetings all day, email only."* The sender address has a subtle difference from the real CEO email.

### Scenario 3 - Vishing (Voice Phishing)
A nurse at MedDefense Central answers the phone. The caller identifies themselves as *"Mike from IT"* and says: *"We're doing an emergency security audit after the billing server incident. I need to verify your login works correctly. Can you read me your username and the password you use for the EHR system?"*

### Scenario 4 - Smishing (SMS Phishing)
All MedDefense employees receive a text message: *"MedDefense Parking: Your staff parking permit expires tomorrow. Renew immediately to avoid towing: [link]."* The link leads to a page that looks like MedDefense's internal HR portal and asks for AD credentials.

### Scenario 5 - Watering Hole Attack
The website of the Regional Healthcare Association (an industry group that MedDefense physicians visit monthly for CME credits) is compromised. Visitors who browse specific pages are silently redirected to a site that attempts to exploit a browser vulnerability to install malware.

### Scenario 6 - Typosquatting / Brand Impersonation
Someone registers the domain `meddefence-portal.com` (note: "defence" instead of "defense"). They create a pixel-perfect copy of MedDefense's patient portal. Google Ads are purchased so this fake portal appears above the real one in search results for "MedDefense patient portal."

### Scenario 7 - Physical Impersonation / Tailgating
A person in scrubs carrying a stethoscope and a hospital-branded coffee cup approaches the restricted corridor leading to the IT department. They follow a staff member through the badge-controlled door, saying warmly: *"Thanks! My badge is in my locker, I'm just running back to grab something from my desk."* Their visitor badge, partially hidden by the stethoscope, expired two days ago.
