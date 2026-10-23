# After-Action Report: Nexus Supply Chain Compromise Tabletop

**Exercise date:** 23 October 2026
**Report date:** 28 October 2026
**Facilitator:** Steve - Cybersecurity Engineer
**Participants:** Dr. Patricia Morales (CEO), Sarah Park (IT Director), James Chen (SOC Lead), Robert Kim (Infrastructure Lead), Mike Torres (Network Engineer), Helena Reyes (General Counsel), Marcus Webb (Communications Director), Clinical Director representative
**Classification:** Internal

---

## Executive summary

This exercise tested eight organizational capabilities across seven injects, using a supply chain compromise of Nexus Patient Scheduling in which a malicious update signed with the vendor's valid code-signing certificate delivered a backdoor to MedDefense's scheduling infrastructure at all three sites. The exercise was designed to test decision-making under incomplete facts, not technical response, and it produced findings in both categories.

The most significant gaps clustered in two areas. First, decision authority: no participant could name who holds the authority to take a vendor-operated, business-critical clinical support system offline, and the resulting deadlock was resolved by executive arbitration rather than by a recommendation from the leads responsible for the trade-off. Second, continuity planning: no manual scheduling fallback exists at any of the three sites, so the clinical objection to isolation had no counter-proposal attached to it.

Legal performance was stronger than expected on the covered-entity obligation question, but the BAA's 24-hour notification clause was identified and never invoked in writing, and a vendor discovery-date discrepancy was queried rather than formally challenged.

**Single most important recommended action:** establish and publish a named decision authority for isolating vendor-operated business-critical systems, with a documented escalation path and a tested manual scheduling fallback for all three sites. This gap blocked the continuity decision chain at INJ-01 and INJ-03 and is the prerequisite for every other continuity improvement.

---

## Findings table

| ID | Inject | Capability | Gap | Severity | Recommended Action | Owner | Deadline | Validation |
|---|---|---|---|---|---|---|---|---|
| F-001 | INJ-00 | CAP-01 | Evidence preservation was not sequenced before containment discussion; firewall block proposed before any collection step was formally named | P1 | Amend IR playbooks so evidence preservation is the first named action, and add a preservation-first checkpoint to the severity matrix | SOC Lead | 14 days | Playbook revision reviewed by IT Director; re-tested at next tabletop |
| F-002 | INJ-00 | CAP-01 | Vendor update channel not raised as a possible vector at detection, despite the signed binary executing from its expected path | P2 | Add "vendor-origin binary" as a standing hypothesis in the malware triage checklist | SOC Lead | 21 days | Checklist field present and completed in next three live triages |
| F-003 | INJ-01 | CAP-03 | No named decision authority for isolating a vendor-operated critical system; decision deferred with no owner and no deadline | P1 | Define and publish decision authority for vendor-system isolation in the IR plan, including who may authorize and who must be consulted | IT Director | 21 days | Authority documented and confirmed by CEO; exercised in a follow-up tabletop |
| F-004 | INJ-01 | CAP-03 | No manual scheduling fallback exists at any of the three sites; clinical objection to isolation carried no counter-proposal | P1 | Document a minimum viable manual scheduling procedure covering pre-registration, eligibility, and appointment verification for all three sites | IT Director (co-owner: Clinical Director) | 60 days | Procedure exists, is printed at each site, and is walked through in a functional drill |
| F-005 | INJ-02 | CAP-02 | BAA 24-hour notification clause was identified but never invoked in writing to the vendor | P1 | Create a standing BAA invocation template and require written citation of the clause in any vendor incident correspondence | General Counsel | 21 days | Template approved; used in next vendor incident or exercise |
| F-006 | INJ-02 | CAP-02 | Vendor escalation path untested beyond the account executive; no attempt to reach the vendor CISO or legal counsel | P2 | Validate all four vendor contact paths (24x7 line, AE, CISO, legal) and record which produce a human response | IT Director | 30 days | Contact test log completed with timestamps and outcomes |
| F-007 | INJ-03 | CAP-03 | Security-versus-clinical conflict was resolved by executive arbitration rather than a recommendation from the responsible leads | P2 | Require leads to present a specific recommendation with stated trade-offs before executive arbitration is invoked | CEO Office (co-owner: IT Director) | 45 days | Requirement documented in IR plan; rehearsed in a follow-up tabletop |
| F-008 | INJ-03 | CAP-03 | Continuity decision carried no re-evaluation trigger or time, becoming permanent by inertia | P3 | Add a mandatory re-evaluation trigger and review interval to the continuity decision record template | IT Director | 30 days | Template field present and populated in next continuity decision |
| F-009 | INJ-05 | CAP-05 | Vendor discovery-date discrepancy was queried but not formally challenged as a BAA compliance issue | P2 | Establish a documented process for asserting BAA non-compliance in writing when vendor timelines are inconsistent | General Counsel | 21 days | Process documented; letter template approved |

---

## P1 Finding narratives

### F-001: Evidence preservation was not sequenced before containment discussion

During INJ-00, the IT Director proposed blocking the external destination at the firewall before any participant had named an evidence collection step. The SOC Lead subsequently directed forensic imaging and log export, which recovered the situation, but the ordering was accidental rather than procedural. This matters because the local logs on SCHED-SVR-01 overwrite within 72 hours, as the Infrastructure Lead confirmed at INJ-04, and the scope of PHI exposure — the fact that determines notification obligations and their cost — is reconstructed entirely from evidence that survives the first hour of response. The recommended action is to amend the incident response playbooks so that evidence preservation is the first named action in both the credential exposure and malware paths, and to add a preservation-first checkpoint to the severity matrix so that containment proposals cannot be actioned ahead of it. Owner: SOC Lead, 14 days, validated by playbook revision reviewed by the IT Director and re-tested at the next tabletop.

### F-003: No named decision authority for isolating a vendor-operated critical system

At INJ-01, the team recognized the signed-update paradox and understood that isolation was the logical containment step, but no participant could state who held the authority to authorize it. The decision was deferred without an owner and without a deadline, and it remained unresolved until INJ-03, when the clinical director representative challenged the IT Director's standing to make it at all. The absence of a named authority is what converted a thirty-minute decision into a fifty-minute argument, and in a real event that interval is spent with a backdoor actively receiving commands. This gap is not a knowledge gap — the participants understood the risk — it is a governance gap, and it is the reason the continuity decision chain failed twice in the same exercise. The recommended action is to define and publish, in the incident response plan, who may authorize isolation of a vendor-operated business-critical system, who must be consulted beforehand, and what compensating controls apply when isolation is declined. Owner: IT Director, 21 days, validated by documented authority confirmed by the CEO and exercised in a follow-up tabletop.

### F-004: No manual scheduling fallback exists at any of the three sites

At INJ-01, the clinical director representative objected to isolation on the grounds that roughly 500 patients are booked the following morning across three sites and that pre-registration and insurance eligibility would fail. At INJ-03, when pressed directly on what happens at 7 a.m. if the system is taken offline, the same participant could not describe a fallback procedure. The objection was legitimate and the absence of an alternative was total, which placed the security function in the position of choosing between overriding clinical judgment and accepting continued compromise. This matters beyond the exercise: the objection will be raised identically in a real event, and without a documented manual procedure the organization will default to running a known-compromised system, which is precisely the outcome the attacker's persistence depends on. The recommended action is to document a minimum viable manual scheduling procedure covering pre-registration, eligibility verification, and appointment confirmation for all three sites, and to walk it through in a functional drill rather than a discussion. Owner: IT Director, co-owner Clinical Director, 60 days, validated by a printed procedure held at each site and exercised in a drill.

### F-005: BAA 24-hour notification clause identified but never invoked in writing

At INJ-02, General Counsel correctly identified the 24-hour breach notification clause in the executed Business Associate Agreement, and the IT Director correctly claimed ownership of vendor communication. Neither translated that into written correspondence citing the clause. The vendor remained unresponsive beyond a tier-1 ticket number and an account executive with no technical information, and the team absorbed that delay rather than converting the contractual obligation into pressure. This matters because the clause is the only lever MedDefense holds over a vendor's incident disclosure timeline, and an unexercised lever has no effect on the vendor's behavior or on the evidentiary record of MedDefense's diligence. The recommended action is to create a standing BAA invocation template and require that written citation of the clause accompany any vendor incident correspondence. Owner: General Counsel, 21 days, validated by template approval and use in the next vendor incident or exercise.

---

## What worked

**Scoping discipline at INJ-04.** The team produced an actual scoping methodology rather than an assertion: the SOC Lead converted the 2.1 GB figure to an estimated record range while stating the uncertainty explicitly, the Infrastructure Lead supplied concrete retention periods for both firewall and host logs, and the disclosed subprocessors Twilio and SendGrid entered the assessment scope without prompting. The known-versus-unknown distinction was maintained throughout, which is the behavior that keeps a breach assessment defensible.

**Legal and communications coordination at INJ-05.** The Communications Director drafted a holding statement acknowledging awareness without confirming unverified specifics, and showed it to General Counsel before it went to the reporter. General Counsel stated explicitly that MedDefense's covered-entity notification duty runs independently of the Business Associate's conduct. This is the coordination pattern the exercise was designed to test, and it held under a same-day media deadline.

**Honest uncertainty at INJ-06.** When the CEO asked directly whether patient data was confirmed exfiltrated, the SOC Lead answered that it was not yet confirmed and that the team was proceeding on the assumption it was. The clinical director representative then committed to contacting the forty affected patients directly and proposed extended front-desk hours for manual verification. Distinguishing confirmed from assumed in a board-level answer is the single hardest behavior this exercise tests, and it was demonstrated without prompting.

---

## Exercise design feedback

**DF-01 — CEO arbitration at INJ-03.** The CEO resolved the security-versus-clinical conflict within two minutes, bypassing the lead-level recommendation the inject was designed to elicit. Change made: added a pre-read instruction to the CEO participant guide directing her not to arbitrate directly, and revised the INJ-03 probing question to ask what the leads recommend rather than what she needs to decide.

**DF-02 — SMS modification detail arriving too late.** The patient SMS reminders quoting modified appointment times did not surface until INJ-06, leaving the Communications Director without the patient-contact dimension while the legal exposure was being scoped at INJ-04 and INJ-05. Change made: moved the SMS modification detail earlier in the inject sequence so communications and clinical have it before the notification decision is made.

**DF-03 — Capability map referenced injects that do not exist.** The capability map created during design referenced INJ-07 and INJ-08 for CAP-05 and CAP-08, but the final schedule contains only INJ-00 through INJ-06. Change made: corrected the capability map so CAP-05 and CAP-07 map to INJ-05 and CAP-08 maps to INJ-06, and added a consistency check between the capability map and the inject schedule before release.
