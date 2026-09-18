# Introduction

> "The attacker doesn't hack the firewall. The attacker sends an email."
>
> — Adapted from Kevin Mitnick

You have spent weeks learning Linux, networking, logging, scripting and security analysis. Now the focus shifts to one of the most common real-world attack vectors: phishing emails.

An attacker does not always need malware exploits or advanced infrastructure. Sometimes a convincing email is enough.

The email arrives looking like a routine portal notification, invoice or verification request, and someone clicks the link because they are tired, distracted or under pressure. This is the reality of modern attacks: phishing campaigns target people before they target systems.

This project focuses on investigating suspicious emails, identifying phishing indicators, analyzing authentication results and documenting evidence using safe investigation techniques.

The 2025 Verizon DBIR found that phishing and pretexting accounted for over 40% of initial access vectors across all industries, rising to 56% in healthcare. Understanding how to investigate suspicious emails safely and methodically is therefore a critical security skill.

## Why This Matters

The investigation you perform here builds the foundation for later threat analysis projects. The indicators, domains, URLs and evidence you extract in this project will later be reused for IOC analysis, malware investigation and threat hunting workflows. This project sets the analytical foundation for the entire module.

## Context

Week eleven at MedDefense Health Systems. Tuesday morning.

Mike Torres stops by the security operations area. He has a USB drive.

"We have a problem. Or maybe we don't. That's your job to figure out."

Over the past 72 hours, the helpdesk received 6 reports of suspicious emails from staff across three departments. Two additional emails were caught by the mail gateway's automated quarantine. Mike collected all 8 emails in their raw format (full headers preserved) and saved them to the shared drive.

"Some of these are probably spam. But Linda in Billing says she never signed up for anything. Angela in Accounts Payable says the invoice looks wrong. And Diane at Westside Clinic…" He pauses. "Diane says she clicked a link in one of the emails. About 36 hours ago. She thought it was a portal verification."

James Chen joins the conversation. His expression is measured.

"I received an alert from HC3 this morning. The Health Sector Cybersecurity Coordination Center is tracking a phishing campaign targeting healthcare organizations in our region. Credential harvesting using lookalike domains. They do not have IOCs yet, which means nobody has submitted them. If we are being targeted, we could be the first to report."

He outlines three priorities:

    "Analyze every email. Determine which are threats and which are noise."

    "Figure out if the malicious ones are connected. A coordinated campaign against MedDefense is a different risk level than random spam."

    "Diane clicked a link 36 hours ago. Find out if her credentials were compromised and whether anything happened on her workstation."

Sarah Park adds one more concern: "The email Diane clicked claimed to be from our patient portal. The domain looks almost right. If other staff received similar emails, we might have more clicks that nobody reported."

The email evidence batch can be downloaded here: [email batch](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/email_batch.txt)

---

# [0. The Initial Email Triage](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/0-initial_triage.md)

## Goal: 

Perform initial triage on all 8 reported emails, classifying each as Spam, Suspicious or Legitimate based on a rapid first-pass assessment.

## Context: 

A security analyst does not start by deep-diving into the first email. With 8 emails in the queue, the first step is rapid triage: scan each email quickly, flag the ones that need deeper investigation and set aside obvious noise.

## Instructions: 

Create a file named 0-initial_triage.md.

In this file, produce an initial triage table for all 8 emails.

For each email, include:

    Email ID: E1 through E8
    From address
    Subject line
    SPF result
    DKIM result
    DMARC result
    Initial classification: SPAM, SUSPICIOUS or LEGITIMATE
    Priority: P1-URGENT, P2-HIGH, P3-MEDIUM or P4-LOW
    A short justification based on evidence from the email

Use rapid triage logic. Your classification does not need to be a full final investigation, but it must be evidence-based.

Guidance:

    Emails with failed authentication, lookalike domains, urgency, targeted language or suspicious links should be treated as suspicious.
    Obvious unsolicited bulk advertising should be treated as spam.
    Legitimate-looking internal or trusted-sector communication should still be documented with evidence.
    E2 must be treated as P1-URGENT because the evidence batch states that Diane Marsh clicked the link.

Expected Output Format:

| Email | From | Subject | SPF | DKIM | DMARC | Class | Priority | Evidence |
|---|---|---|---|---|---|---|---|---|
| E1 | ... | ... | ... | ... | ... | SPAM | P4-LOW | ... |
| E2 | ... | ... | ... | ... | ... | SUSPICIOUS | P1-URGENT | ... |

At the end of the file, include a short summary:

<pre>
## Triage Summary

- SPAM:
- SUSPICIOUS:
- LEGITIMATE:
- Highest priority:
</pre>

---

# [1. The Header Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/1-header_analysis.md)

## Goal: 

Parse the SMTP header chain of the suspicious emails and identify the true origin and routing indicators for each message.

## Context: 

The From: field in an email can be misleading. The technical truth is usually found in headers such as Received:, Return-Path:, Authentication-Results:, Message-ID: and X-Mailer:.

In this task, analyze the suspicious emails identified during triage: E2, E3, E5 and E7.

## Instructions: 

Create a file named 1-header_analysis.md.

For each suspicious email E2, E3, E5 and E7, document:

    The visible From: address
    The Return-Path: address
    The sending IP address from the external Received: hop
    The mailer or sending software from X-Mailer
    The Message-ID format
    Any mismatch between the claimed sender and the sending infrastructure
    Header anomalies that support suspicion

Do not rely on live Wazuh, Sysmon, Suricata or endpoint telemetry. This task must be completed using the email evidence batch only.

**Expected Output Format:**

<pre>
## Email 2 — meddefense-portal.com

### Header Evidence

- From:
- Return-Path:
- Sending IP:
- X-Mailer:
- Message-ID:

### Received Chain Summary

1.
2.
3.

### Anomalies

- [HIGH] ...
- [MEDIUM] ...

### Conclusion

...
</pre>

---

# [2. The Email Authentication Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/2-authentication_analysis.md)

## Goal: 

Validate the SPF, DKIM and DMARC results for all 8 emails and explain what each result means for the investigation.

## Context: 

Email authentication helps determine whether the sending infrastructure is authorized for the claimed domain. SPF checks sending IP authorization. DKIM checks whether the message was cryptographically signed by a domain. DMARC connects authentication results to the visible From: domain.

However, authentication does not prove that an email is safe. A malicious sender can register a lookalike domain and configure SPF, DKIM and DMARC correctly.

## Instructions: 

Create a file named 2-authentication_analysis.md.

For each of the 8 emails, document:

    SPF result and what it means
    DKIM result and what it means
    DMARC result and action or policy shown in the header
    Whether authentication supports or contradicts the apparent legitimacy of the email
    A short final verdict

For Email 3, explain why passing SPF, DKIM and DMARC does not make the email legitimate. Your explanation must mention that outlook-protection.com is not the same as microsoft.com or outlook.com.

Avoid hardcoded dramatic notes such as “CRITICAL NOTE”. Use clear analyst language instead.

**Expected Output Format:**

<pre>
## Email 3 — outlook-protection.com

- SPF:
- DKIM:
- DMARC:
- Authentication verdict:
- Investigation meaning:
</pre>

---

# [3. The Social Engineering Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/3-social_engineering.md)

## Goal: 

Analyze the content of the suspicious emails and identify the psychological manipulation techniques used.

## Context: 

Header and authentication analysis explain how an email was sent. Content analysis explains how the sender tries to influence the recipient.

A generic phishing email may rely on broad fear or urgency. A targeted phishing email may reference a person, department, workflow, invoice, benefits process or internal system.

## Instructions: 

Create a file named 3-social_engineering.md.

Analyze E2, E3, E5 and E7.

For each email, include:

    Primary psychological lever: urgency, authority, fear, scarcity, financial pressure or impersonation
    Pretext: the story the email uses
    Requested action: click, login, verify, pay, download, open attachment or provide information
    Targeting level: GENERIC, SEMI-TARGETED or TARGETED
    Content red flags
    What information the attacker likely needed to craft the lure

**Expected Output Format:**

<pre>
## Email 5 — Invoice lure

- Psychological lever:
- Pretext:
- Requested action:
- Targeting level:
- Content red flags:
- Attacker knowledge required:
- Conclusion:
</pre>

---

# [4. The URL and Attachment Autopsy](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/4-url_attachment_autopsy.md)

## Goal: 

Safely investigate URLs and attachment indicators found in the suspicious emails without opening suspicious links or files directly.

## Context: 

A suspicious URL is often the bridge between an email and a real compromise. Investigating it safely means extracting the URL, defanging it and documenting what the evidence tells you without directly visiting it.

Some evidence may also appear inside attachment metadata. Do not open attachments on your workstation. Only document metadata and indicators visible in the raw email evidence.

## Instructions: 

Create a file named 4-url_attachment_autopsy.md.

Analyze the suspicious emails E2, E3, E5 and E7.

For each suspicious URL or attachment indicator:

    Extract the original URL or attachment reference from the evidence
    Defang the URL by replacing http with hxxp and . with [.]
    Identify the domain or IP address
    Identify the email where it appeared
    Describe why the URL or attachment is suspicious
    Document safe investigation commands that could be used, such as whois, dig, nslookup, curl -I, VirusTotal or urlscan.io lookups
    Record findings from the email evidence itself, such as sending IP reuse, lookalike domains, suspicious file names, invoice pretexts or embedded PDF links

Do not require live DNS, SIEM, Wazuh, Sysmon or Suricata data. If a live lookup does not work, document the method and use the evidence file for your conclusion.

**Expected Output Format:**

<pre>
## Indicator 1

- Source email:
- Original value:
- Defanged value:
- Domain or IP:
- Indicator type:
- Evidence from email:
- Safe investigation method:
- Finding:
- Risk rating:
</pre>

Your file must include the following suspicious domains or IP indicators:

    meddefense-portal.com
    outlook-protection.com
    medequip-supplies.net
    meddefense-benefits.org
    203.0.113.228

---

# [5. The Attachment Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/5-attachment_analysis.md)
### advanced

## Goal: 

Analyze the PDF attachment indicators from Email 5 using metadata and structural clues visible in the raw evidence, without opening the file.

## Context: 

The evidence batch includes a stripped PDF attachment embedded in Email 5. In this project, you do not need the original file and must not open suspicious attachments on your workstation. Use only metadata and indicators visible in the raw email source, including the attachment filename, MIME type, PDF producer string, embedded URI and hash string visible in the encoded content.

## Instructions: 

Create a file named 5-attachment_analysis.md.

Analyze the Email 5 attachment INV-2026-04891.pdf using evidence visible in the raw email source.

Include:

    Attachment filename and content type
    Whether the attachment is base64 encoded
    Available hash evidence from the raw content. If MD5 is not provided, state that it is not available in the batch instead of inventing one
    The visible SHA-256 indicator from the PDF text
    PDF creator or producer evidence, including wkhtmltopdf 0.12.6
    Embedded URL evidence from the PDF annotation or URI string
    Whether JavaScript, forms or embedded executable files are proven by the provided evidence. Do not claim features that are not shown
    Relationship between the attachment URL and the Email 5 body URLs
    Whether the attachment appears connected to the same campaign as E2 and E7, based on shared patterns such as PHPMailer, urgency, lookalike domains, targeted business process and suspicious infrastructure
    Safe hash or file reputation commands that could be used in a real investigation, such as VirusTotal API lookup, without requiring the student to run them
    A final risk assessment

**Expected Output Format:**

<pre>
## Attachment: INV-2026-04891.pdf

- Source email:
- Filename:
- Content type:
- Encoding:
- Available hash evidence:
- PDF producer / creator evidence:
- Embedded URLs:
- Structural findings:
- Campaign correlation:
- Safe reputation-check commands:
- Risk assessment:
</pre>

---

# [6. The IOC Correlation Plan](https://github.com/sreilly1977/dlh-cyber_security/blob/main/threat_detection/4x00_phishing_dissection/6-ioc_correlation.md)
### advanced

## Goal: 

Correlate the phishing indicators from the email batch and document how a SOC analyst would search local logs or security tools if available.

## Context: 

This module must be independent and must not require Wazuh, Sysmon, Suricata or earlier module environments. Instead of querying a live SIEM, create an IOC correlation plan using the indicators from the evidence batch and the provided click note for Diane Marsh. The goal is to show what should be searched, why it matters and what evidence is already confirmed by the batch.

## Instructions: 

Create a file named 6-ioc_correlation.md.

Your report must include:

    A normalized IOC list containing domains, URLs, sending IPs, recipient accounts and relevant timestamps from the evidence batch
    A short exposure timeline from first suspicious delivery through the reported click
    A section for DNS, proxy/web, endpoint and authentication logs explaining what queries would be performed if those logs were available
    A clear distinction between evidence confirmed by the batch and evidence that would require additional logs
    Specific mention of Diane Marsh, WS-NURSE-04, 10.10.2.15, Email 2 and the click timestamp 2026-04-14 15:02:33 CDT
    A detection gap analysis explaining what a team should monitor for in future phishing investigations

Do not write a script and do not require a live SIEM. This is a local investigation report based on the provided evidence.

**Expected Output Format:**

<pre>
## IOC Correlation Report

### Normalized IOC List

### Exposure Timeline

### Confirmed Evidence From Batch

### Queries To Run If Logs Are Available

### Detection Gaps

### Conclusion
</pre>

---
