# [0. The Advisory Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x05_board_briefing/0-advisory_analysis.md)

Goal: Translate the CISA advisory into a MedDefense-specific impact assessment, proving you can apply threat intelligence to your own environment in real time.

Context: The CISA advisory describes a generic attack chain. Your job is to make it specific. Every step in Crimson Tide's playbook must be mapped to a specific MedDefense system, vulnerability and gap. The question is not "could this happen to hospitals ?" The question is "could this happen to MedDefense, with our specific infrastructure, and if so, how exactly ?"

Provided Files: [`cisaadvisorycrimson_tide.txt`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x05_board_briefing/cisaadvisorycrimson_tide.txt)

Instructions: Read the entire advisory. Then produce a MedDefense Impact Assessment that maps every phase of the Crimson Tide attack chain to MedDefense's specific environment:

For each of the 7 phases in the advisory:

After all 7 phases, produce:

```
Phase [N]: [Name from advisory]
Advisory Description: [1-sentence summary of what the attacker does]

MedDefense Mapping:
  Target System: [Specific MedDefense hostname/system]
  Vulnerability Reference: [Finding ID from 1x02, or OSINT finding from 1x04, or new CVE]
  Gap Reference: [Gap ID from 1x00 or control gap from 1x03]
  Crypto Weakness: [From 1x04 if applicable]
  Current Protection: [What control, if any, currently blocks this phase?]
  Verdict: [EXPOSED / PARTIALLY PROTECTED / PROTECTED]
```

Overall Exposure Score: How many of the 7 phases is MedDefense currently EXPOSED to ? (Express as X/7.)

Critical Finding: In one sentence, what is the single most urgent action MedDefense must take in the next 4 hours based on this analysis ?

---

# [1. The CVE Deep Dive](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x05_board_briefing/1-cve_deep_dive.md)

## Goal

Research CVE-2023-27997 on NVD and assess its exploitability using the tools you mastered in Projects 0x02 and 0x04.

## Context

The advisory names CVE-2023-27997 as the initial access vector. You have the tools and the skills to research this CVE with the same rigor you applied to the scan findings in 1x02. This time, the urgency is not academic. This CVE is being actively exploited against hospitals in your region right now.

## Instructions

### Part 1 — NVD Research

Go to nvd.nist.gov and research CVE-2023-27997. Document:

1. **Full description**
2. **CVSS v3.1 vector string and base score**
3. **CWE classification**
4. **Affected products and versions**
5. **References** (vendor advisory, patches)

### Part 2 — Exploit Assessment

Using searchsploit and Exploit-DB, assess exploit availability:

1. **Is there a public exploit?**
2. **Is this CVE in the CISA KEV catalog?**
3. **What is your Exploitability Score (1–5, using the scale from 1x02 T4)?**

### Part 3 — MedDefense CVSS Contextualization

Using the NIST CVSS Calculator, apply Environmental Metrics specific to MedDefense's FortiGate. Consider:

- The FortiGate is the **ONLY perimeter defense** (no redundancy)
- It **terminates all VPN tunnels** (all 3 sites depend on it)
- It sits on **kill chain #1, #2 and #3** from 1x01
- The **support contract has expired** (patching requires renewal first)

What is the adjusted CVSS score for MedDefense? Is it higher or lower than the base score?

---
