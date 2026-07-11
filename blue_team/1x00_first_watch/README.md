# Introduction

> "The best security professionals I know are not the ones who find the most vulnerabilities. They are the ones who understand the business well enough to know which ones matter."
>
> — Wendy Nather, Head of Advisory CISOs, Cisco

Before you touch a firewall, before you write a detection rule, before you investigate your first alert, you need to answer one question that most security teams never ask properly:

**What exactly are we protecting?**

It sounds obvious. It is not. The 2024 Change Healthcare breach paralyzed medical billing across the United States for weeks. Not because the attackers were exceptionally skilled. Because nobody had a complete picture of how one system connected to everything else. When that system went down, the entire chain collapsed. A $22 billion company brought to its knees because the asset inventory was incomplete and the dependencies were undocumented.

This is not an edge case. This is the norm. Most organizations cannot tell you how many systems they have, where their sensitive data lives, which controls are actually in place or what gaps exist between what they think they have and what they actually have. The 2023 HHS cybersecurity report found that 93% of healthcare organizations experienced a data breach in the previous 3 years. Not because hospitals lack budgets. Because they lack visibility.

This project will not teach you to "use security tools." You will not scan anything. You will not exploit anything. You will do something harder and more valuable: you will learn to see an organization the way a security professional sees it. To read a messy environment and produce a structured, actionable assessment that drives real decisions. To look at a server room door propped open with a wooden wedge and understand exactly what that means in terms of risk.

## Why It Matters

Every security role you will ever hold starts with this skill. The SOC analyst who receives an alert needs to know which asset is affected and how critical it is. The incident responder who contains a breach needs to know which systems to prioritize. The penetration tester who finds a vulnerability needs to understand its business impact. The GRC consultant who prepares a compliance audit needs a complete inventory of controls and gaps.

The report you produce at the end of this project is not an exercise. It is the exact document a security consultant delivers at the start of every engagement. It is the foundation that every subsequent project in this program will build on. Your threat analysis, your vulnerability assessment, your defense strategy, your incident response plans, all of them depend on the quality of the work you do here.

Get this right, and everything that follows has a solid foundation. Get this wrong, and you are building on sand.

---

**Context:** You are starting your first day as Junior Security Analyst at **MedDefense Health Systems**.

MedDefense is a regional hospital group operating 3 sites:

- **MedDefense Central** — a 350-bed downtown hospital
- **Westside Clinic** — a suburban outpatient facility
- **Corporate HQ** — administrative offices in a business park 15 minutes from Central

The organization employs approximately 2,000 people across clinical, administrative, and IT functions. The IT department has 12 staff members, managed by **Sarah Park, IT Director**.

Your position reports to **James Chen, Deputy CISO**. James was hired 8 months ago to build a security program. His challenge: MedDefense has never had a dedicated security function. Security was handled "on the side" by IT, and the results are what you would expect. James hired his first security analyst, Marcus Webb, six months ago. Marcus lasted three months before leaving. Officially, for a better opportunity. Unofficially, James suspects Marcus was frustrated by the pace of change and the constant pushback from leadership on security spending.

Marcus has been gone for three months. During that time, no one has managed security. The position sat vacant while HR went through the hiring process. You are Marcus's replacement.

On your first morning, James meets you at reception. He walks you to your desk, which is still Marcus's desk, mostly cleared out but not entirely. A few folders remain in the drawer. A sticky note on the monitor reads: *"Check billing-srv-01, something is wrong. -M"*

> "This is everything we have. Marcus started documenting the environment but never finished. IT has their own records but they are scattered across ticketing systems, spreadsheets and people's heads. The Board of Directors has asked me for a full security posture assessment by the end of the week. They are nervous. They read about the Change Healthcare breach and want to know if we are exposed."
>
> "I need you to assess our current security posture from scratch. What assets do we have, how critical are they, what controls are in place, where are the gaps and what should we fix first. I need a professional document I can put in front of the Board. Not a list of problems. A structured assessment with clear priorities."
>
> "Welcome to MedDefense. The clock is ticking."

---

# [0. The Onboarding Packet](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x00_first_watch/0-environment_summary.md)

**Goal:** Extract a structured understanding of an organization from incomplete and disorganized documentation.

**Context:** James Chen hands you a folder labeled "MedDefense, Security Documentation." It contains everything the organization has:

- A partial IT asset list exported from the ticketing system
- An outdated network diagram that Marcus started but never finished
- A one-page org chart
- Site descriptions from the HR onboarding guide
- Notes Marcus left in a text file on the shared drive
- A summary of IT service contracts

None of it is complete. Some of it contradicts itself. Welcome to reality.

## Provided Files

[`onboarding_packet.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x00_first_watch/onboarding_packet.txt)

## Instructions

Your first task is to make sense of this information. Read the entire onboarding packet carefully. Then produce a **Structured Environment Summary** organized into the following four sections:

1. **Organization Overview:** Sites (name, location type, function, approximate headcount), departments, and reporting structure relevant to security.

2. **IT Infrastructure Identified:** Every system, server, network device, and endpoint category mentioned or implied in the documentation. For each: name/type, function, location (which site), and any technical details available.

3. **Data and Services:** What types of data does MedDefense handle? What critical services depend on IT infrastructure? Who uses them?

4. **Known Unknowns:** What information is missing, incomplete, or contradictory in the documentation? List specific gaps. This section is as important as the others — knowing what you do not know is the first step toward a complete assessment.

*Be precise. Do not invent information that is not in the packet. If something is ambiguous, flag it in the Known Unknowns section.*

---

# [1. The First Incidents](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x00_first_watch/1-incident_classification.md)

**Goal:** Learn to classify security events using the CIA Triad as an analytical framework.

**Context:**: While reading Marcus's notes from the onboarding packet, you find a section titled "Incident Log, Last 6 Months." It is a rough list of security-relevant events that occurred at MedDefense. Some were handled. Some were not. None were formally classified.

Before you can assess the security posture, you need to understand what has already gone wrong. More importantly, you need a framework to describe how it went wrong. That framework is the **CIA Triad**:

- **Confidentiality:** Information was accessed by someone who should not have seen it.
- **Integrity:** Information or a system was modified without authorization.
- **Availability:** A service, system, or data became inaccessible when it was needed.

Every security incident impacts at least one of these pillars. Some impact more than one.

## The Incident Log

**Incident A — January 15:** A ransomware payload encrypted the billing server (`billing-srv-01`) over the weekend. The finance team could not process insurance claims for 4 days. The backup was 3 weeks old due to a misconfigured cron job.

**Incident B — February 2:** A nurse in the Westside Clinic reported that a patient asked about test results that had not been shared yet. Investigation revealed that the patient portal had a broken access control that allowed any authenticated patient to view other patients' lab results by modifying the URL parameter.

**Incident C — March 18:** The pharmacy management system displayed incorrect dosages for a specific medication across all three sites for approximately 6 hours. A database update script had a bug that overwrote dosage values. The error was caught by a pharmacist who noticed the numbers did not match the printed reference.

**Incident D — April 5:** MedDefense Central's public-facing website was defaced. The homepage was replaced with a political message. The website does not contain patient data. It was restored from a backup within 2 hours.

**Incident E — May 22:** The EHR system experienced a 9-hour outage during a planned database migration. The migration took longer than expected and the rollback procedure had never been tested. Physicians resorted to paper records during the outage.

**Incident F — June 10:** An IT intern's personal laptop, which he had connected to the corporate WiFi, was found to be running a torrent client that was sharing files. Network logs showed the laptop had been on the internal network (not the guest network) for 3 weeks. The laptop had access to the same network segment as the HR file share.

## Instructions

Analyze the following 6 incidents from Marcus's log. For each one, identify:

1. The **primary CIA pillar** impacted
2. A **one-sentence justification** explaining why
3. If a **secondary pillar** is also impacted, identify it and explain the connection
4. Produce a **formatted incident classification table**

---

# [2. The Symptom Trap](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x00_first_watch/2-root_cause_analysis.md)

**Goal:** Develop the analytical reflex to look beyond visible symptoms and identify root causes in security events.

**Context:** Remember the sticky note on Marcus's monitor? "Check billing-srv-01, something is wrong." This is the server that got hit by ransomware in January (Incident A). It was rebuilt, but the performance issues Marcus noticed started before the ransomware and have returned after the rebuild.

The IT team has flagged `billing-srv-01` three times in the last two months for "performance degradation." Each time, the sysadmin restarted the server, which temporarily resolved the issue. The sysadmin's latest ticket reads: *"Recurring CPU saturation on billing-srv-01. Probably undersized for the billing workload. Recommend hardware upgrade or migration to a more powerful VM."*

James Chen is not convinced. Neither was Marcus. James asks you to take a closer look.

**Provided Files:** [`billing-srv-01_diagnostics.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x00_first_watch/billing-srv-01_diagnostics.txt) (contains a top output snapshot and a netstat excerpt from the server)

## Excerpt from the Diagnostics File

```bash
top - 14:22:07 up 12 days, 3:47, 2 users
PID    USER      PR  NI  %CPU  %MEM    COMMAND
8834   www-data  20   0  94.2   3.1    ./kworker -o stratum+tcp://pool.monero.org:4443
1102   root      20   0   2.1   8.4    /usr/sbin/apache2 -k start
1455   mysql     20   0   1.3  12.6    /usr/sbin/mysqld
```

```bash
Active Internet connections:
Proto  Local Address      Foreign Address        State
tcp    10.10.2.15:45892   185.243.115.89:4443    ESTABLISHED
tcp    10.10.2.15:45901   91.121.87.10:8080      ESTABLISHED
tcp    10.10.2.15:80      10.10.1.0/24:*         LISTEN
```

## Instructions

The sysadmin says this is a hardware capacity problem. You need to determine what is actually happening and why the sysadmin's diagnosis is wrong.

1. **Identify the process:** What is `kworker` doing? What does the `stratum+tcp://pool.monero.org` connection tell you? What is the purpose of this process?

2. **Classify the real compromise:** The visible symptom is performance degradation (Availability impact). But what are the actual primary security violations? Identify the **two CIA pillars** that are compromised **before** Availability is affected, and explain each.

3. **Explain why the sysadmin's solution fails:** If MedDefense follows the recommendation to upgrade the server hardware, does the security problem go away? Why or why not?

4. **Connect to the January incident:** The ransomware in January and this crypto-miner are on the same server. What does this suggest about the server's security posture? What question should you be asking about how both incidents were possible?

---

## 3. The Walk-Through

**Goal:** Apply structured risk reasoning (Vulnerability, Threat, Impact) to physical observations in a real environment.

**Context:** James Chen takes you on a tour of MedDefense Central. *"Walk through with fresh eyes,"* he says. *"Marcus told me at least twice that the server room access was a problem. I flagged it to Sarah Park in IT. She said it was 'on the roadmap.' That was five months ago."*

As you walk the facility, you observe details that a non-security professional would overlook. Each observation represents a potential security weakness. Your job is to decompose each one into its formal risk components.

### Risk Components Framework

A risk exists when three elements converge:

| Component | Definition |
|-----------|------------|
| **Vulnerability** | A specific weakness or gap in a system, process or physical setup. |
| **Threat** | An event, actor or circumstance that could exploit the vulnerability. |
| **Impact** | The consequence to the organization if the threat materializes, measured against the CIA pillars. |

---

### Observation 1: Server Room Access

The server room is on the ground floor, accessed from a corridor shared with the cafeteria. The door uses the same generic badge that every employee (clinical, administrative, custodial) receives on their first day. There is no camera covering the door. There is no visitor log.

### Observation 2: Network Closet

A network closet on the second floor (containing switches and patch panels) has no lock. The door is ajar. Inside, taped to the wall next to the switch stack, is a laminated sheet labeled *"Network Maintenance Credentials"* with a username and password for the switch management interface.

### Observation 3: Nurse Station

At the third-floor nurse station, a workstation is logged into the EHR system with a patient's record visible on screen. No staff member is present. The session appears to have been idle for at least 15 minutes. A sign above the station reads *"For efficiency, please do not log out between shifts."*

### Observation 4: Medical IoT

In a patient room, a connected vital signs monitor displays diagnostic information including the device's IP address (`10.10.3.47`) and firmware version (v2.1.3, last updated 2019). The network cable runs to a wall port labeled `MED-3F-12`. You notice this is the same IP range as the workstations you saw at the nurse station.

### Observation 5: Emergency Exit

A fire exit door between the public waiting area and the restricted administrative wing is propped open with a wooden wedge. A handwritten sign taped to the door reads: *"Please do not close, staff passage."* Through the open door, you can see the hallway leading to the IT department and James Chen's office.

---

### Instructions

You observe the following during your walk-through of MedDefense Central. For each observation, produce a structured risk decomposition.

For each observation, deliver:


```
Observation [N]:
  Vulnerability: [The specific weakness]
  Threat: [A plausible scenario that exploits this weakness]
  Impact: [What happens if the threat materializes - specify CIA pillar(s)]
  Severity: [Critical / High / Medium / Low - justified in one sentence]
```
