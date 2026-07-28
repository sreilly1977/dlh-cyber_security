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

# [2. The Kill Chain Overlay](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x05_board_briefing/2-kill_chain_overlay.md)

Goal: Overlay the Crimson Tide attack chain onto the kill chains you built in 1x01, identifying where they converge and where MedDefense's planned controls would intercept.

Context: You built 5 kill chains for MedDefense in Project 1x01. Crimson Tide's attack chain is a real-world instance of those theoretical models. How accurately did your threat modeling predict this attack ? Where does the Crimson Tide chain match your kill chains, and where does it diverge ?

Instructions:

Part 1 - The Overlay

Take your Kill Chain #1 (ransomware) from 1x01 T10. Lay it alongside the Crimson Tide 7-phase attack chain. For each step, identify:

    Whether your predicted step matches the Crimson Tide step

    Where your prediction was accurate

    Where Crimson Tide does something your model did not anticipate

Part 2 - Control Interception Map

From your Security Strategy (1x03), identify which planned controls would intercept the Crimson Tide chain and at which phase:

```
Phase [N] | Planned Control [from 1x03] | Status [Funded/Not Deployed, Deployed, Not Funded] | Would It Stop This Phase? [Yes/Partially/No]
```

Part 3 - The Gap Between Plan and Reality

In one paragraph, assess: If MedDefense had fully implemented the Security Strategy from 1x03, how many of the 7 Crimson Tide phases would have been blocked ? How many would still succeed ? What does this tell you about the residual risk even after full strategy implementation ?

---

# 3. The 72-Hour Plan

## Goal

Design an emergency response plan prioritizing the actions MedDefense must take in the next 72 hours to reduce exposure to Crimson Tide.

## Context

The Security Strategy was a 6-month roadmap. Crimson Tide has compressed the timeline to 72 hours. You cannot implement the full strategy overnight. You must choose the actions that provide the maximum risk reduction in the minimum time, with the resources available right now.

The constraints are real:

- Sarah Park has 2 IT staff available tonight (plus herself)
- FortiGate firmware requires a support contract renewal ($2,400) before download
- The segmentation project requires new switch configurations (2-3 days minimum)
- Backup isolation can be done tonight (physical disconnect of NAS from network)
- AD Kerberos configuration changes require a maintenance window (risk of breaking authentication)

## Instructions

Produce a 72-Hour Emergency Response Plan organized into 3 tiers:

**Tier 1 — Tonight (0–12 hours):** Actions that can be taken immediately with no budget approval, no procurement and minimal risk of service disruption. These are the things you do before you sleep.

**Tier 2 — Tomorrow (12–36 hours):** Actions that require some coordination, possibly a brief service window, and may need emergency budget approval from the Board meeting.

**Tier 3 — This Week (36–72 hours):** Actions that require procurement, vendor involvement or configuration changes that need testing.

For each action:

```
Action: [Specific description]
Phase Blocked: [Which Crimson Tide phase does this address?]
Owner: [James / Sarah / You / External vendor]
Prerequisites: [What must happen first?]
Risk of Action: [What could go wrong?]
Risk of Inaction: [What happens if this is not done?]
```

End with a **Resource Conflict Assessment**: Are any Tier 1 and Tier 2 actions in conflict (same person needed for multiple tasks, same system needing multiple changes)? How do you resolve the conflicts?
