# Introduction

> "The human factor is truly security's weakest link."
> 
> — Kevin Mitnick

You have spent weeks looking at phishing from the defender's side. In Module 4 you dissected a phishing kit, reconstructed a campaign from headers and payload, and mapped the attacker's infrastructure. You have triaged alerts that fired because someone clicked. You followed the forensic trail that began with a single phishing email and ended with an LSASS dump, a beacon, and a full incident response activation.

Now you design the program that catches the humans before the attacker does.

The post-incident review documented the fact that 23 of 41 phishing emails delivered to MedDefense employees were clicked. The SIEM detected the C2 beacon. The IR team contained the damage. But a click rate of 56% means every technical control downstream of the human layer was carrying weight that a behavior change program should have reduced. No detection rule catches a credential handed over willingly. No playbook contains a compromise that never happened.

This will builds the complete security awareness program for MedDefense: a phishing simulation campaign grounded in real attacker behavior, role-targeted guidance that clinical and administrative staff will actually read, vishing scenarios for live social engineering exercises, an insider threat awareness framework that protects the organization without creating a surveillance culture, an annual program calendar with budget justification, and the metrics infrastructure that tells leadership whether any of it is working.

The test for every artifact in this project is the same: would a nurse coming off a 12-hour shift read this and do something differently? Would a finance analyst hesitate before wiring money based on a phone call? If the answer is no, redesign it.

## Why this matters

Most security awareness programs fail for the same reason: they are designed to satisfy a compliance requirement rather than change behavior. Annual training courses generate completion certificates. Completion certificates satisfy auditors. Auditors leave. The click rate stays at 38%.

The organizations that actually move the needle run something different: continuous simulations calibrated to real attacker behavior, immediate post-failure interventions that teach rather than shame, content segmented by role and risk profile, and metrics that measure what employees do rather than what they know. The analyst who can design and run this kind of program is doing three jobs simultaneously: threat intelligence (what is the attacker actually doing?), operational security (how do we simulate it safely?) and organizational communication (how do we change what 1,200 people do under pressure?).

Security awareness program design appears in GRC analyst job descriptions, security program manager roles and CISO portfolios. Every skill in this project is transferable the day you walk into your first security role.

## Context

Three weeks after the IAM audit and the SOC automation rollout, Dr. Patricia Morales calls a meeting that nobody wanted to have. She puts a single number on the whiteboard: 23.

Twenty-three MedDefense employees clicked the phishing link that initiated the Cobalt Strike compromise documented in Module 5. Out of 41 phishing emails delivered, 23 were clicked. The SIEM caught the beacon within four minutes. The IR team contained the damage. But the humans failed first, and they failed at a rate that is not acceptable for a healthcare organization handling ePHI at scale.

James Chen speaks first: "We can automate enrichment. We can write playbooks. We cannot automate judgment. We need a program that changes behavior, not a training calendar that satisfies a checkbox."

Sarah Park flags the operational constraint: clinical staff at MedDefense are already carrying 14 mandatory training modules from regulatory and accreditation requirements. Any security content that lands on top of that stack must earn its place by being relevant, brief and actionable. "If it reads like a compliance document," she says, "it will not be read."

HR Director Maria Santos adds one firm boundary: simulation results are not to be used in performance reviews. The program's purpose is training, not accountability enforcement.

Dr. Morales assigns you the full build. Ninety days to first wave. The deliverable is a complete, operational security awareness program.

---

# 0. Quiz

---

# [1. Social Engineering Threat Profile](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/social_engineering_threat_profile.md)

## Goal: 

Produce an adversary-perspective threat profile for social engineering attacks targeting healthcare organizations that serves as the factual design brief for every simulation artifact in this project.

## Context: 

James Chen's requirement before approving any phishing template: it must be based on actual attack patterns documented in healthcare sector threat intelligence, not generic best-guess scenarios. The phishing kit and email headers you analyzed in Module 4 documented one campaign in detail. This profile documents the broader pattern: who attacks healthcare organizations, through which vectors, with which lures, and where the detection or disruption opportunity sits in each attack chain.

This profile is not background reading. It is the design constraint that governs every phishing template in Task 3 and every vishing script in Task 6. A simulation that does not model real attacker behavior produces employees who can spot simulations, not actual attacks.

## Instructions: 

Create social_engineering_threat_profile.md. Base the profile on documented healthcare social engineering patterns. Do not describe generic phishing theory. Describe specific, healthcare-targeted attack patterns with named lure categories, delivery mechanisms and observed behavioral outcomes.

### Use These Materials

Use the following files from the provided material folder:

threat_intel/phishing_kit_analysis_summary.md
threat_intel/email_header_inspection_results.md
threat_intel/campaign_reconstruction.md
threat_intel/healthcare_social_engineering_patterns.md
threat_intel/lure_effectiveness_benchmarks.md
incident_context/module5_incident_summary.md
incident_context/post_incident_click_rate_review.md
incident_context/cobalt_strike_phishing_path.md
campaign_design/clinical_schedule_constraints.md

The threat profile must be grounded in these materials. Do not write generic phishing theory. When describing populations, vectors, lure effectiveness, timing and simulation constraints, use MedDefense-specific systems, workforce conditions and incident facts from the materials.

### Required sections:

1. Target analysis. Describe the three MedDefense employee populations most frequently targeted in healthcare sector social engineering campaigns, ranked by targeting frequency. For each population include: role characteristics that increase susceptibility, the attacker's likely access objective if they succeed, and the workflow timing that makes phishing most exploitable (shift start, EHR authentication cycles, system maintenance windows).

2. Attack vector inventory. Document four distinct social engineering vectors observed in healthcare-sector threat intelligence. For each vector include: attack description, a concrete example lure drawn from documented campaigns, attacker objective, and the MedDefense system or data asset most likely targeted.

3. Lure effectiveness analysis. Rank the five most effective phishing lure categories for healthcare targets. For each lure include: the psychological mechanism being exploited (authority, urgency, familiarity, scarcity or social proof), why it is specifically effective in clinical or administrative healthcare environments, and the approximate click-rate range observed in healthcare simulation data.

4. Detection and disruption opportunities. For each attack vector in section 2, identify the specific point in the attack chain where user behavior could disrupt the attack: what the employee should notice, what action they should take, and what makes that disruption difficult in practice.

5. Simulation design requirements. Based on sections 1 through 4, state five specific design constraints for the MedDefense phishing simulation campaign derived from this threat analysis. These must be actionable design constraints, not general principles.

Length: 3 pages rendered. Every claim must be traceable to documented healthcare threat patterns or simulation program data.

**Expected output**

<pre>
# Social Engineering Threat Profile: MedDefense Health Systems

**Prepared by:** <name>
**Date:** <date>
**Distribution:** Security Team, CISO, HR (Section 5 only)

---

## 1. Target Analysis

### Population A: Clinical Staff (Nurses, Patient Care Technicians, Clinical Assistants)
**Targeting frequency:** Highest. Clinical staff receive the greatest volume of targeted
social engineering lures in healthcare sector phishing data.
**Attacker access objective:** EHR credential capture for ePHI access or lateral movement
into clinical network segments.
**Exploitation timing:** Shift-start windows (07:00-08:30 and 19:00-20:30). Staff are
authenticating to Epic, reviewing handoff notes, and operating under shift-transition
cognitive load. Credential prompts during this window are processed with reduced scrutiny.

### Population B: ...
**Targeting frequency:** ...
**Attacker access objective:** ...
**Exploitation timing:** ...

### Population C: ...
**Targeting frequency:** ...
**Attacker access objective:** ...
**Exploitation timing:** ...

## 2. Attack Vector Inventory

### Vector 1: EHR System Impersonation (Email)
**Description:** Email lure mimicking Epic EHR system notifications...
**Example lure:** "Your Epic account will be suspended in 24 hours due to a failed
security verification. Click here to restore access before your next shift."
**Attacker objective:** EHR credential capture for ePHI access.
**Targeted asset:** Epic EHR, downstream ePHI repositories.

### Vector 2: ...
**Description:** ...
**Example scenario:** ...
**Attacker objective:** ...
**Targeted asset:** ...

### Vector 3: ...
**Description:** ...
**Example scenario:** ...
**Attacker objective:** ...
**Targeted asset:** ...

### Vector 4: ...
**Description:** ...
**Example scenario:** ...
**Attacker objective:** ...
**Targeted asset:** ...

## 3. Lure Effectiveness Analysis

| Rank | Lure Category | Mechanism | Healthcare Factor | Click Rate Range |
|---|---|---|---|---|
| 1 | EHR system authority/urgency | Authority + Urgency | Blocking EHR access stops patient care | 45-62% |
| ... | ... | ... | ... | ... |

## 5. Simulation Design Requirements

1. All templates must reference MedDefense-specific systems by name (Epic, not "your EHR").
2. Delivery timing for clinical segments must exploit shift-start windows (07:00-08:30).
3. At least one template per wave must combine authority with an operational consequence
   (not just account status but a workflow impact on patient care).
4. Executive-targeted templates must use named internal personnel, not generic titles.
5. Lure difficulty must increase across waves: baseline lures first, advanced BEC variants
   only after employees have been exposed to and trained on simpler patterns.
</pre>

---

# [2. Phishing Simulation Campaign Plan](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/phishing_campaign_plan.md)

## Goal: 

Design a structured phishing simulation campaign for MedDefense with targeting strategy, wave schedule, escalation criteria and a metrics framework that measures behavior rather than completion.

## Context: 

The threat profile from Task 1 is the design brief. The campaign plan is the operational document. Sarah Park has approved a 90-day initial rollout window. HR Director Maria Santos has confirmed one firm constraint: individual click results are not to appear in performance reviews and are not to be shared with department managers without a second confirmed offense and a formal HR escalation trigger. Managers receive aggregate team data only.

## Instructions: 

Create phishing_campaign_plan.md. This is an operational planning document. A simulation campaign manager must be able to run the program from this document without asking you to clarify anything verbally.

### Use These Materials

social_engineering_threat_profile.md
iam_context/role_inventory.csv
iam_context/employee_segments.csv
iam_context/iam_audit_summary_6x02.md
campaign_design/hr_privacy_rules.md
campaign_design/workforce_population_breakdown.csv
campaign_design/clinical_schedule_constraints.md
campaign_design/simulation_ethics_guidelines.md
program_governance/metrics_baseline.csv

The six employee segments in the campaign plan must map to the provided role and population materials. HR privacy boundaries must follow hr_privacy_rules.md; do not create escalation or manager-reporting rules that conflict with it.

### Required sections:

1. Campaign overview. Scope (total employee population, simulation platform), program objectives (click rate target, report rate target, 18-month improvement trajectory), and governance (who approves templates, who reviews results, how findings escalate to HR).

2. Employee segmentation. Divide the MedDefense workforce into targeting segments based on role and risk profile. Use the six role categories from the IAM audit in 6x02 as the basis. For each segment include: estimated population, primary risk vectors from the threat profile, template assignment rationale and exclusion criteria.

3. Wave schedule. Design a four-wave schedule across the 90-day initial window. For each wave specify: delivery window, target segments, templates assigned by difficulty tier (baseline, intermediate or advanced), delivery time-of-day and day-of-week rationale, and the minimum cool-down period before the same population is targeted again.

4. Metrics framework. Define every metric the program tracks. For each metric specify: metric name, formula, measurement interval, 90-day target, 18-month target and what a deteriorating result means operationally.

Required metrics: click rate, report rate, repeat clicker rate (same employee clicking in two consecutive waves), mean time to report (from delivery timestamp to report action), post-simulation training completion rate, false-positive report rate (real emails reported as phishing).

5. Escalation criteria. Define the conditions that escalate a simulation result from a training event to a security team investigation: at what point does a failure pattern become a potential insider threat or security hygiene risk requiring HR coordination?

6. Exclusion and ethics policy. Document exclusion criteria and the program's ethical obligations: aggregate vs. individual disclosure framework, post-simulation support for employees who experience distress, and the governance sign-off required before any template is deployed.

---

# [3. Phishing Email Templates](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/phishing_templates.md)

## Goal: 

Write four complete, deployable phishing simulation email templates calibrated to documented healthcare attacker behavior patterns and the MedDefense targeting segments defined in the campaign plan.

## Context: 

James Chen's approval rule for any template: it must pass the "would I have clicked this?" test from the perspective of a MedDefense employee in the target segment, operating under normal shift conditions. Generic IT password expiration emails produce 18% click rates. Epic EHR authority emails produce 54%. The difference is specificity, operational consequence and timing precision. Each template exploits a different psychological mechanism, targets a different segment and is immediately usable in the wave schedule from Task 2.

## Instructions: 

Create phishing_templates.md. Each template must be a complete, deployable simulation email: sender display name, spoofed From address, subject line, full email body and a call-to-action link placeholder ([SIMULATION_LINK]). Include a header block for each template describing targeting rationale, psychological mechanism, expected click-rate range and deployment constraints.

### Use These Materials

social_engineering_threat_profile.md
phishing_campaign_plan.md
threat_intel/phishing_kit_analysis_summary.md
threat_intel/email_header_inspection_results.md
threat_intel/healthcare_social_engineering_patterns.md
templates/phishing_template_constraints.md
campaign_design/clinical_schedule_constraints.md
campaign_design/simulation_ethics_guidelines.md

Templates must use [SIMULATION_LINK] only. Do not include real credential-harvesting URLs, real domains intended for deception, or instructions for collecting passwords. Every template must be usable only inside an approved internal simulation campaign. Required templates:

T-EPIC-01: Epic EHR Account Management (Baseline). Target: SEG-B (general clinical floor staff). Mechanism: authority + urgency. Lure: account suspension due to failed security verification will block patient record access within 48 hours. Must reference Epic by name, use a credible internal notification format and create urgency without being obviously fabricated.

T-MFA-02: IT Helpdesk MFA Enrollment (Baseline). Target: SEG-C (administrative and billing staff). Mechanism: familiarity + authority. Lure: mandatory MFA enrollment required before a compliance deadline. Exploits the timing of MedDefense's actual MFA rollout from 6x02 and the familiarity of receiving IT compliance communications.

T-HR-03: HR Open Enrollment Benefits Deadline (Intermediate). Target: SEG-C and SEG-E (administrative and finance staff). Mechanism: urgency + scarcity. Lure: benefits enrollment deadline with financial consequence for missing the window. A cross-departmental lure that exploits a process every employee has experienced and trusts.

T-BEC-04: Executive Wire Fraud (Advanced). Target: SEG-F and SEG-E (executive and finance staff). Mechanism: authority + social proof. Lure: CFO impersonation requesting urgent document review or financial action. The highest-damage scenario in healthcare and the hardest to detect because no technical indicator distinguishes it from a legitimate executive request.

For each template include: a complete header block (segment, tier, mechanism, expected click-rate range and deployment timing constraints), the full email formatted as the recipient would see it, and an attacker notes section explaining what a real threat actor would add to make this more dangerous.

**Expected output**

<pre>
# Phishing Email Templates: MedDefense Health Systems

**Inventory:** T-EPIC-01 (Baseline), T-MFA-02 (Baseline), T-HR-03 (Intermediate),
T-BEC-04 (Advanced)
**Ethics review completed:** 2026-05-01
**Approved by:** Dr. Patricia Morales, CISO
Do not deploy without campaign plan sign-off. See phishing_campaign_plan.md.

---

## T-EPIC-01: Epic EHR Account Management (Baseline)

**Target segment:** SEG-B (General clinical floor staff)
**Tier:** Baseline
**Mechanism:** Authority + Urgency
**Expected click rate (first exposure):** 40-58%
**Deployment:** Weekdays 07:15-08:30. Do not deploy during ICU or OR shift windows.

---

From:    Epic Health Systems Notifications <notifications@epic-healthsystems.net>
To:      [First Name Last Name] <[employee@meddefense.org]>
Subject: ACTION REQUIRED: Epic account security verification required —
         access suspended in 48 hours

---

Dear [First Name],

A failed security verification has been recorded against your Epic EHR account.

Per MedDefense IT Security Policy, accounts with failed verifications are suspended
after 48 hours to protect patient data. Your access to patient records, medication
administration logs and clinical documentation will be unavailable during suspension.

To complete verification and maintain uninterrupted access, click the secure link
below before 11:59 PM on [DATE+2]:

    [SIMULATION_LINK]

If you believe this message was sent in error, contact the IT helpdesk at ext. 4-HELP
or help@meddefense.org before the deadline to request a manual review.

Epic Health Systems | Account Security
Sent on behalf of MedDefense Health Systems Information Security

---

**Attacker notes:** A real attacker registers epic-healthsystems.net 72 hours before
launch and adds DKIM signing to pass spam filters. The credential harvest page matches
the actual Epic login interface pixel-for-pixel. The attacker embeds the target's actual
username in the URL to pre-populate the login form, removing one friction point between
click and credential submission. A pixel tracker in the email header confirms delivery
before the campaign wave is sent, so the attacker knows the email was opened.

---

.....
</pre>

---

# [4. Post-Click Intervention Design](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/post_click_intervention.md)

## Goal: 

Design the moment-of-failure intervention that converts a simulated phishing click into a durable learning event rather than a negative emotional experience that produces anxiety without behavior change.

## Context: 

Most phishing simulation programs deliver a landing page that says "You were phished." Research consistently shows this produces negative affect, not behavior change. The click rate declines slightly in the next wave because employees are more anxious, not because they know what to look for. Programs that produce durable click-rate reduction deliver something different at the moment of failure: immediate, specific, non-blaming content that shows the employee exactly what they missed and exactly what to do next time.

MedDefense will implement immediate post-click microtraining: a landing page that does not shame the employee, explains precisely what made this email a phishing lure using the actual template as the teaching example, and delivers a 5-minute role-appropriate intervention within the same browser session. This is the component that separates programs that work from programs that audit well.

## Instructions: 

Create post_click_intervention.md. Design the complete post-click experience for all four simulation templates.

### Use These Materials

phishing_templates.md
phishing_campaign_plan.md
templates/post_click_microtraining_reference.md
campaign_design/hr_privacy_rules.md
campaign_design/simulation_ethics_guidelines.md
program_governance/metrics_baseline.csv

Landing pages and microtraining must be non-shaming. Repeat-click escalation must follow the HR privacy boundary: individual results are not shared with department managers unless the formal escalation threshold is met.

### Required components:

1. Landing page variants. Write the full text content for the simulation landing page for each of the four templates (LPV-01 through LPV-04). Requirements: no shaming language, acknowledge the training context explicitly, explain specifically what made this email suspicious using the actual template signals as the teaching material, pivot immediately to the learning content. One variant per template.

2. Microtraining module structure. For each landing page variant, design a 5-minute microtraining module structured as: (a) what you saw: specific red flags in that template with annotations, (b) what a real attacker gains: concrete operational consequence for this specific lure type, (c) what to do next time: three specific pre-click verification steps the employee should take with any similar email, (d) how to report: 30-second walkthrough of the MedDefense phishing reporting mechanism.

3. Repeat-click escalation protocol. Define the escalating response for employees who click in two or more consecutive simulation waves. At what point does repeated simulation failure escalate from a training program event to an HR-coordinated coaching intervention? Specify the escalation path, who is notified at each stage and what the employee is told.

4. Positive reinforcement design. Design the immediate automated response an employee receives within 60 seconds of correctly reporting a simulation email using the phishing report button. The reinforcement must be immediate, specific and proportional. Describe exactly what the employee sees or receives.

---

# [5. Role-Based Security Guidance](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/guidance_clinical_staff.md)

## Goal: 

Produce four one-page security guidance documents that four distinct MedDefense employee populations will actually read, retain and act on within their existing daily workflows.

## Context: 

Sarah Park's constraint is real: clinical staff carry 14 mandatory training modules. Adding a 20-page security policy binder produces resentment, not behavior change. The answer is four audience-specific documents: 90 seconds to read, three threats specific to this role, three actions specific to this workflow, one reporting path. The language must match how each audience actually communicates at work. Not security language. Their language.

Robert Kim notes that the executive guidance specifically needs to address business email compromise. Three finance-sector executives at peer organizations were targeted with wire fraud attempts in Q1 2026 using a near-identical scenario to T-BEC-04 from Task 3.

## Instructions: 

Create four separate files: [guidance_clinical_staff.md](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/guidance_clinical_staff.md), [guidance_it_staff.md](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/guidance_it_staff.md), [guidance_executives.md](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/guidance_executives.md) and [guidance_remote_workers.md](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/guidance_remote_workers.md).

### Use These Materials

threat_intel/healthcare_social_engineering_patterns.md
incident_context/security_awareness_gap_notes.md
iam_context/privileged_account_findings.md
iam_context/iam_audit_summary_6x02.md
templates/role_based_guidance_style_guide.md
campaign_design/workforce_population_breakdown.csv
campaign_design/clinical_schedule_constraints.md

Each one-page guide must use the language of its audience. IT staff guidance must specifically reflect the 6x02 IAM findings: dormant service accounts, over-privileged roles and service-account hygiene.

Each document follows the same one-page structure:

    Header: "Security Quick Reference: [Audience]" with MedDefense branding placeholder, version number and date

    Your biggest threats (3 bullets): specific threat scenarios for this role, not generic categories; each bullet names the threat, describes how it targets this specific role and gives a one-sentence behavioral signal to watch for

    What to do right now (3 bullets): specific, immediate actions the employee can take this week to reduce actual risk; no general advice

    When something looks wrong (1 action): a single, unambiguous reporting action with contact information

    What not to do (3 bullets): the three highest-frequency mistakes this specific audience makes, stated plainly without condescension

    Footer: Security team contact (ext. 4-SECURITY, security@meddefense.org) and phishing report button location in Outlook

Audience-specific content requirements:

### Clinical staff: 

Use nursing and clinical workflow language. Reference Epic by name. Address EHR credential phishing, USB drops in clinical areas, shoulder surfing at workstations and fake vendor support calls during equipment issues.

### IT staff: 

Assume technical proficiency. Address privileged access discipline (no admin actions from personal email or personal devices), insider threat indicators that IT staff are uniquely positioned to observe, service account hygiene and the specific failure modes documented in the 6x02 IAM audit (dormant service accounts, over-privileged roles).

### Executives: 

Use board-level language, not IT language. Address spear phishing targeting executives (BEC and wire fraud specifically), travel security and the operational impact of an executive credential compromise on MedDefense operations. Authoritative tone. Concise.

### Remote workers: 

Address the home environment specifically. Home WiFi security, VPN discipline before any work system access, shoulder surfing in public spaces, device separation between personal and work machines, and the risk of using personal email or personal cloud storage for work documents.

---

# [6. Vishing and Social Engineering Scenario Scripts](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/vishing_scenarios.md)
### advanced

## Goal: 

Produce three complete vishing simulation scenario scripts with caller guides, employee assessment rubrics and post-exercise debrief protocols usable for live simulation exercises or tabletop training sessions.

## Context: 

The Module 5 incident began with a phishing email, but the post-incident review documented a second failure: a helpdesk verification call was misdirected because the receiving employee had no framework for verifying a caller's identity. Vishing is the social engineering vector most organizations simulate least but that carries the highest per-incident impact. A successful vishing call bypasses every technical control by getting a trained employee to take the action on behalf of the attacker.

Mike Torres notes that two peer healthcare organizations reported vishing incidents in Q1 2026. Both targeted clinical supervisors and finance staff. Both began with publicly available information from LinkedIn and facility websites.

## Instructions: 

Create vishing_scenarios.md. Produce three complete scenario scripts each usable for live simulation exercises, tabletop training or onboarding awareness sessions.

### Use These Materials

threat_intel/healthcare_social_engineering_patterns.md
incident_context/module5_incident_summary.md
incident_context/cobalt_strike_phishing_path.md
templates/vishing_facilitator_notes.md
campaign_design/simulation_ethics_guidelines.md
campaign_design/hr_privacy_rules.md

Vishing scenarios must be safe for controlled internal simulation. Each script must include verification opportunities, scoring guidance and debrief notes. Do not write scripts that normalize unsafe behavior such as installing unauthorized remote support tools or sharing passwords. Each scenario must include:

    Scenario header: scenario ID, target role, attack objective, psychological mechanisms and success criteria from the attacker's perspective

    Caller script: exact dialogue the simulation caller uses, with three response branches (compliance, hesitation and verification request)

    Assessment rubric: what the employee must do at each decision point to pass, partially pass or fail; definition of a full pass

    Debrief notes: what to explain after the exercise, what made this scenario realistic and what a real attacker would have accessed if they succeeded

### Required scenarios:

V-01: IT Helpdesk Impersonation. Target: general clinical or administrative staff. Objective: get the employee to provide their current password or accept an attacker-initiated password reset.

V-02: Vendor Support Escalation. Target: clinical staff or clinical supervisor. Objective: get the employee to install a remote support tool or grant screen access for an "emergency Epic patch."

V-03: Executive Authority Impersonation. Target: administrative or finance staff. Objective: get the employee to initiate a financial action or send a sensitive document based solely on a phone call from someone impersonating an executive by name.

---

# [7. Insider Threat Awareness Program](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/insider_threat_program.md)
### advanced

## Goal: 

Design an insider threat awareness framework that gives MedDefense employees and managers actionable behavioral indicators without creating a surveillance culture or chilling legitimate workplace communication.

## Context: 

The forensic investigation revealed that svc_helpdesk, a service account identified in the IAM audit as holding Domain Admin rights with no current business justification and a dormancy period of over 300 days, was used as a lateral movement pivot point. Whether that account was compromised externally or misused by a trusted insider, the access patterns were visible before the incident: dormant account activating at 02:00, LSASS dump executed from a privileged context, lateral movement to systems outside the account's documented function.

James Chen's position: "We are not building a surveillance program. We are building a framework for recognizing when something is wrong before it becomes a breach. There is a difference."

HR Director Maria Santos requires that any program document distributed to managers be reviewed by legal before deployment, and that any anonymous reporting path have documented triage procedures before going live.

## Instructions: 

Create insider_threat_program.md.

### Use These Materials

iam_context/privileged_account_findings.md
iam_context/iam_audit_summary_6x02.md
insider_threat/insider_threat_case_notes.md
insider_threat/technical_indicators_reference.md
insider_threat/reporting_and_triage_model.md
insider_threat/manager_reference_constraints.md
campaign_design/hr_privacy_rules.md
campaign_design/simulation_ethics_guidelines.md

The insider threat program must not become a surveillance program. Reporting, triage and escalation must follow the provided HR/legal constraints and must include non-retaliation language. Required sections:

1. Behavioral indicator framework. Define three categories of indicators: access-based, behavioral and contextual. For each category, list five specific observable indicators appropriate for MedDefense's healthcare environment. Each indicator must be specific and observable, not psychological speculation. For each indicator, note who is positioned to observe it: manager, IT, HR, SOC or coworker.

2. Technical indicator framework. Define five specific technical indicators the MedDefense SOC should monitor for insider threat signals. Reference specific log sources and detection logic from the Module 3 detection pipeline. Cross-reference IAM audit findings from 6x02 where directly relevant.

3. Reporting process. Design a reporting path for employees and managers to raise concerns without triggering premature investigation or confronting the subject. Include: anonymous reporting option with documented triage steps, the threshold that escalates to HR and legal, and a non-retaliation statement with enforcement reference.

4. Manager reference guide. Write a one-page guide for department managers: what they are responsible for observing, what to document before escalating, when to escalate and specifically what not to do.

5. Culture and ethics statement. Write the 200-word program statement distributed to all MedDefense employees explaining why this program exists, how employee privacy is protected and what this program is not.

---

# [8. Annual Security Awareness Program Plan](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/awareness_program_plan.md)
### advanced

## Goal: 

Produce a 12-month operational plan for MedDefense's security awareness program with a campaign calendar, budget justification and governance framework that Dr. Morales can present to the board of directors.

## Context: 

Dr. Morales's board presentation is scheduled for Q3 2026. She needs three things from this project: a plan that shows what will happen and when, a budget that justifies every line against measurable risk reduction, and a governance structure that answers the board's fundamental question: who is responsible and how will we know it is working?

Sarah Park adds one scheduling constraint: no new training content during the Joint Commission accreditation window in Q4 or during the flu season peak between November and January, when clinical staff coverage is at minimum and training availability drops significantly. Existing content may be delivered; new campaigns targeting clinical staff are paused during these windows.

## Instructions: 

Create awareness_program_plan.md.

### Use These Materials

phishing_campaign_plan.md
post_click_intervention.md
guidance_clinical_staff.md
guidance_it_staff.md
guidance_executives.md
guidance_remote_workers.md
program_governance/annual_calendar_constraints.md
program_governance/budget_assumptions.md
program_governance/metrics_baseline.csv
program_governance/program_governance_roles.md
campaign_design/workforce_population_breakdown.csv
campaign_design/clinical_schedule_constraints.md

The annual plan must respect healthcare scheduling constraints, including accreditation windows and flu season pressure. Budget lines must be justified against measurable risk reduction, not generic training value. Required sections:

1. Executive summary. Three paragraphs: problem statement (the Q1 2026 incident, estimated cost, root cause at the human layer), program approach (what this program does and why this approach produces behavior change rather than compliance artifacts), and expected outcomes at 12 months and 36 months with specific metric targets.

2. Annual campaign calendar. Month-by-month schedule for the first 12 months. For each month specify: campaign type, target audience, delivery method and success metric for that campaign. Account for healthcare seasonality and the scheduling constraints above.

3. Budget justification. Year 1 line-item budget. Categories: simulation platform licensing, content development, training delivery time (opportunity cost calculation), external benchmarking, program management overhead. For each line item: estimated cost, what it purchases and the cost of not having it.

4. Governance framework. Roles and responsibilities (program owner, content approver, simulation operator, metrics reviewer, escalation authority), reporting cadence (what metrics go to whom and how often) and review cycle (when templates are retired, when targeting strategy updates, how the program responds to a real phishing incident during an active simulation wave).

5. Success criteria. Specific measurable outcomes that constitute program success at 12 months, 24 months and 36 months. These must be the exact metrics Dr. Morales reports to the board: specific enough that a board member with no security background can assess whether the program is working.

---

# [9. Program Effectiveness Brief](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x04_security_awareness/program_effectiveness_brief.md)
### advanced

## Goal: 

Produce the CISO-ready effectiveness brief and the quarterly metrics dashboard template that operationalize program governance and close the feedback loop between security operations and executive leadership.

## Context: 

Six months into the program, Dr. Morales presents results to the MedDefense board. She needs two artifacts: a written brief she can present without a security engineer in the room to translate it, and a metrics dashboard template she can update each quarter without commissioning a new report every time.

This is the final artifact in the awareness program build. You designed the program, built the components, wrote the calendar and justified the budget. Now you instrument the feedback mechanism that tells leadership whether any of it is working. A program with no feedback loop cannot improve and cannot defend its budget at renewal time.

James Chen's framing for the brief: "Three questions. Are we safer? Are we improving? What changes next?"

## Instructions: 

Create program_effectiveness_brief.md.

### Use These Materials

awareness_program_plan.md
phishing_campaign_plan.md
program_governance/metrics_baseline.csv
program_governance/board_reporting_template.md
program_governance/program_governance_roles.md
incident_context/post_incident_click_rate_review.md
incident_context/security_awareness_gap_notes.md

The effectiveness brief must be board-ready and honest about attribution limits. Do not claim the awareness program alone caused incident reduction if other security improvements occurred at the same time. Use trend language, confidence limits and caveats where appropriate.

### Required components:

1. Board-ready effectiveness brief template (6-month). A 2-page brief template Dr. Morales fills with actual data at the 6-month mark. Structure for a board audience: non-technical language, numbers with context (not just percentages), comparison to baseline and to industry benchmark, and a single bottom-line sentence. Sections: program summary, metrics table (current vs. target vs. industry benchmark), key findings (what the data shows about employee behavior), recommendations for the next 6 months, and the one-sentence bottom line.

2. Quarterly metrics dashboard template. A structured tracking template a program manager fills in each quarter. Must track every metric from the campaign plan, show trend direction using delta notation (+ or - percentage points between quarters), flag metrics outside target range with explicit status (Green/Yellow/Red), and produce a single overall program status per quarter.

3. Incident correlation methodology. Design a methodology for evaluating whether the awareness program is influencing real security incident frequency. Address the core challenge directly: you cannot run a controlled experiment on a live workforce. Define what data to collect, how to attribute or honestly fail to attribute incident reduction to the awareness program vs. concurrent security improvements, and how to present this analysis honestly to a board that wants ROI numbers.

4. Program improvement triggers. Define the specific metric thresholds that initiate a formal program review. What does a deteriorating trend look like across three consecutive quarters? Who initiates the review, what data is assessed and who has authority to pause a simulation wave if an employee welfare concern is raised mid-campaign?

---
