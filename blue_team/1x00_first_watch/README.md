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

## Context

You are starting your first day as Junior Security Analyst at **MedDefense Health Systems**.

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
