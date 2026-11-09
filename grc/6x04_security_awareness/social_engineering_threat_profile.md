# Social Engineering Threat Profile: MedDefense Health Systems

**Prepared by:** Steve, Cybersecurity Engineer
**Date:** 2026-11-09
**Distribution:** Security Team, CISO, HR (Section 5 only)
**Evidence base:** `phishing_kit_analysis_summary.md`, `email_header_inspection_results.md`, `campaign_reconstruction.md`, `healthcare_social_engineering_patterns.md`, `lure_effectiveness_benchmarks.md`, `module5_incident_summary.md`, `post_incident_click_rate_review.md`, `cobalt_strike_phishing_path.md`, `clinical_schedule_constraints.md`

---

## 1. Target Analysis

This section ranks the three MedDefense employee populations most frequently targeted by healthcare-sector social engineering, based on delivery and click data from the Q1 2026 campaign reconstruction (`campaign_reconstruction.md`, `post_incident_click_rate_review.md`) and the sector patterns in `healthcare_social_engineering_patterns.md`.

### Population A: Clinical Staff (Nurses, Patient Care Technicians, Clinical Assistants)

**Targeting frequency:** Highest. Clinical staff received the largest single share of delivered lures in the Q1 2026 campaign (15 of 41 messages) and produced the highest click rate of any group at 67% (10 of 15 clicked) (`post_incident_click_rate_review.md`). Sector lure benchmarks rank EHR account suspension and secure patient message lures as the two most effective categories overall (`lure_effectiveness_benchmarks.md`).

**Role characteristics that increase susceptibility:** Clinical work is continuity-of-care work. Epic access, medication administration records, and secure patient messaging are not optional tools; a blocked account stops care delivery. Staff operate under compressed cognitive load at shift transitions, and the Q1 campaign showed most clinical clicks occurred within 20 minutes of delivery, concentrated at shift-start windows. Employee feedback confirmed the pressure point directly: "If Epic access is blocked, I cannot do my job" and "Everything in clinical work feels urgent" (`post_incident_click_rate_review.md`).

**Attacker access objective:** EHR credential capture for ePHI access, or session/workstation context enabling lateral movement. In the Q1 incident, the Epic-themed lure produced the first credential submission within 14 minutes of delivery, and the compromise escalated through service-account misuse to Cobalt Strike beacon activity and IR activation (`campaign_reconstruction.md`, `module5_incident_summary.md`, `cobalt_strike_phishing_path.md`).

**Exploitation timing:** Shift-start windows. Day-shift clinical lures were delivered at 06:58 with the first click at 07:07, before shift handoff completed; the evening wave delivered at 19:05 produced multiple clicks within 16 minutes (`campaign_reconstruction.md`). The safe clinical delivery windows defined by Clinical Operations (07:15–08:30 and 19:15–20:30 for general floor nurses) confirm these are precisely the windows staff are authenticating to Epic and processing handoff notes (`clinical_schedule_constraints.md`). Medication pass peaks and active code events are the counter-windows attackers implicitly rely on, because attention is elsewhere.

### Population B: Administrative and Billing Staff

**Targeting frequency:** Second highest. Billing and administrative staff received 8 of 41 delivered messages in Q1 with a 63% click rate (5 of 8) (`post_incident_click_rate_review.md`). Sector patterns identify MFA/compliance enrollment and HR benefits deadline lures as categories 3 and 4 in click effectiveness (`lure_effectiveness_benchmarks.md`), and the phishing kit itself carried alternate page copy referencing "policy review" aimed at administrative targets (`phishing_kit_analysis_summary.md`).

**Role characteristics that increase susceptibility:** Administrative staff process compliance tasks, deadlines, and policy language as routine work. They were less influenced by patient-care urgency but strongly influenced by task completion pressure: billing users clicked when the message referenced compliance or portal access (`post_incident_click_rate_review.md`). HR and benefits lures add a personal financial dimension — fear of losing benefits or pay — which increases action bias (`healthcare_social_engineering_patterns.md`, Pattern 3).

**Attacker access objective:** Portal and HRIS credential capture, payment data, and downstream access to ePHI handled through billing and registration workflows. Registration staff hold patient identity context; billing staff hold financial and insurance records.

**Exploitation timing:** Business-hours compliance windows. The billing wave in Q1 was delivered at 09:44 on a weekday, matching the campaign design rule that administrative lures arrive during expected task-processing hours. Benefits and payroll-adjacent lures exploit open-enrollment and month-end periods (`healthcare_social_engineering_patterns.md`). Per `clinical_schedule_constraints.md`, billing/admin simulations for MedDefense must avoid payroll close and month-end — attackers face no such constraint, which is exactly why these windows need trained skepticism.

### Population C: Finance and Executive Personnel (Including Executive Assistants)

**Targeting frequency:** Third most targeted by volume, but first by impact. Finance received 5 delivered messages (2 clicked, 40%) and executives/assistants received 4 (2 clicked, 50%, zero reports) in Q1 (`post_incident_click_rate_review.md`). Sector intelligence is explicit that executive/BEC lures produce a lower click rate (8–22%) but the highest-impact outcomes when action is taken (`lure_effectiveness_benchmarks.md`).

**Role characteristics that increase susceptibility:** The risk driver is not gullibility but deference to authority and confidentiality norms. Finance users opened messages more often than they clicked but were more likely to reply or consider offline action (`post_incident_click_rate_review.md`). Executive feedback captured the core vulnerability: "If a director asks for something, you don't want to slow them down." Email header analysis found the finance lure used a display name resembling the CFO office with replies routed to an unrelated mailbox — a reply-to mismatch invisible to a busy recipient (`email_header_inspection_results.md`, Finding 3).

**Attacker access objective:** Direct financial action (fraudulent payment or banking change), or confidential document access (board packets, acquisition/legal material). The Q1 finance/executive wave used document review and payment approval themes delivered 13:15 on a Friday before vendor payment runs (`campaign_reconstruction.md`) — timing calculated to land when payment action is imminent.

**Exploitation timing:** Late business week, pre-payment-run mornings, and board-cycle periods. Executives are additionally exposed during travel (`healthcare_social_engineering_patterns.md`, Pattern 5), and simulation scheduling must avoid board meeting days (`clinical_schedule_constraints.md`).

---

## 2. Attack Vector Inventory

Four distinct vectors, each drawn from the documented healthcare patterns (`healthcare_social_engineering_patterns.md`), the Module 4 header analysis (`email_header_inspection_results.md`), and the reconstructed Q1 campaign (`campaign_reconstruction.md`).

### Vector 1: EHR System Impersonation (Email)

**Description:** Email posing as Epic or clinical portal notification, demanding verification under threat of account hold. The Q1 kit copied the clinical portal sign-in layout with familiar header and badge colors, pre-filled a user identifier, and applied countdown language ("access verification required before next shift") (`phishing_kit_analysis_summary.md`).
**Example lure:** "Your Epic account is subject to a temporary access hold pending security verification. Complete Epic verification before your next scheduled shift." (Link-label language per `email_header_inspection_results.md`, Finding 5; MSG-001, claimed sender "Epic Account Services," actual domain `epic-healthsystems.net`.)
**Attacker objective:** EHR credential capture, escalating to ePHI access and clinical-network lateral movement.
**Targeted asset:** Epic EHR and downstream ePHI repositories; observed follow-on path reached privileged service accounts (`cobalt_strike_phishing_path.md`).

### Vector 2: Compliance and MFA Enrollment Fraud (Email)

**Description:** Message impersonating MedDefense IT requiring urgent MFA enrollment or compliance-portal task completion. Q1 sample MSG-002 claimed sender "MedDefense IT Compliance" from the lookalike domain `meddefense-it-support.org`; it passed some technical authentication checks while failing organizational legitimacy, meaning employees cannot rely on technical signals alone (`email_header_inspection_results.md`, Finding 2).
**Example lure:** "Mandatory MFA re-enrollment must be completed before the compliance deadline. Open compliance task to avoid access interruption." (`email_header_inspection_results.md`; `healthcare_social_engineering_patterns.md`, Pattern 2.)
**Attacker objective:** Credential and MFA-adjacent capture, enabling SSO bypass and VPN/portal access.
**Targeted asset:** Billing portal, HRIS, email, and identity infrastructure used by SEG-C staff (`role_inventory.csv`).

### Vector 3: Vendor Support Impersonation (Phone and Remote-Access Request)

**Description:** Live phone or message contact posing as an application vendor or patch coordinator demanding urgent remote access during a clinical equipment issue. Sector data ranks vendor emergency support as an 18–35% click-rate category in simulations, and Q1 sample MSG-005 ("Vendor Patch Coordination" from `nexus-updates-support.net`) targeted IT helpdesk with vendor-support framing (`email_header_inspection_results.md`; `lure_effectiveness_benchmarks.md` rank 5). The 6x02 IAM audit showed this vector converts directly into privilege abuse: helpdesk automation and vendor installs produced Domain Admin-level service accounts (IAM-001, IAM-002) (`iam_audit_summary_6x02.md` context in this profile's evidence base).
**Example scenario:** "This is vendor support for the imaging system fault on your unit. We need temporary elevated access now to apply the emergency Epic patch." (`healthcare_social_engineering_patterns.md`, Pattern 4; `insider_threat_case_notes.md`, Case C — vendor requesting domain admin without ticket justification or expiration.)
**Attacker objective:** Remote access grant or privileged escalation under the cover of an operational emergency.
**Targeted asset:** Remote support tooling, IAM infrastructure, and privileged service accounts.

### Vector 4: Executive Impersonation / Business Email Compromise (Email)

**Description:** Message appearing to come from a named executive, requiring urgent payment action or confidential document review, with the reply channel secretly diverted. Q1 sample MSG-003 claimed "CFO Office" from `meddefense-exec-mail.com` and exhibited the reply-to mismatch documented in Finding 3 (`email_header_inspection_results.md`). BEC is a lower-volume, high-consequence vector: 8–22% expected click rate with the highest dollar and sensitivity impact per successful action (`lure_effectiveness_benchmarks.md`).
**Example lure:** "Confidential board document review — approve payment authorization before vendor payment run. Reply to confirm." (`campaign_reconstruction.md`; `healthcare_social_engineering_patterns.md`, Pattern 5.)
**Attacker objective:** Fraudulent financial transfer or disclosure of confidential documents; deliberate avoidance of click-based telemetry.
**Targeted asset:** ERP payment workflows, banking portal, board portal, and confidential documents held by SEG-E and SEG-F staff.

---

## 3. Lure Effectiveness Analysis

Ranked by observed click-rate ranges in healthcare simulation planning data (`lure_effectiveness_benchmarks.md`). Ranges are planning anchors, not guarantees.

| Rank | Lure Category | Mechanism | Why It Works in Healthcare | Click Rate Range |
|---:|---|---|---|---:|
| 1 | EHR account suspension | Authority + Urgency | Blocked Epic access stops patient care; staff authenticate under shift-start cognitive load and cannot tolerate an access hold | 40–62% |
| 2 | Secure patient message | Familiarity + Urgency | Patient-context alerts are routine; a familiar workflow shape bypasses scrutiny even though the correct action (open in Epic) requires no email link | 34–50% |
| 3 | MFA/compliance enrollment | Familiarity + Authority | Periodic IT compliance tasks are expected, so the request pattern itself feels legitimate; MedDefense billing users specifically clicked on compliance/portal framing | 25–42% |
| 4 | HR benefits deadline | Scarcity + Urgency | Consequences are personal and financial (benefits, pay, dependent verification), producing action bias identical to deadline pressure | 22–38% |
| 5 | Vendor emergency support | Authority + Urgency | Vendors and urgent support calls are a normal part of clinical operations; the request targets the desire to restore patient-care workflow | 18–35% |

Two behavioral caveats from the source data govern interpretation. First, a lower click rate does not mean lower risk: executive/BEC lures rank 6th by clicks (8–22%) but carry the highest impact when complied with, which is why finance and executive targets require their own verification training rather than exemption from simulation. Second, the kit's lure language was deliberately neutral and error-free — "verification required," "patient record access," "manual review" — so simulations must teach verification of unexpected workflow-impacting requests, not grammar-spotting (`phishing_kit_analysis_summary.md`).

---

## 4. Detection and Disruption Opportunities

For each vector in Section 2, the specific behavioral disruption point, mapped against the human-layer decision points in `cobalt_strike_phishing_path.md` and the training cues in `email_header_inspection_results.md`.

### Vector 1: EHR Impersonation

**What to notice:** The sender domain is not the real Epic relationship — "the name can be typed by anyone; check whether the domain fits the real process" (display-name versus domain distinction, Finding 1). The message demands action through the email itself rather than Epic's own interface, and imposes a deadline tied to a shift.
**Action:** Do not enter Epic credentials from an email link; open Epic via the known bookmark and use the Outlook report button.
**Why disruption is difficult:** The page rendered the organization's real authentication flow with a pre-filled identifier, and staff are taught that urgency in clinical work is normal. Employees feared blame after clicking, which suppressed reporting — in Q1 only 2 reports arrived before the SOC alert, with a mean time to report of 74 minutes (`module5_incident_summary.md`).

### Vector 2: Compliance/MFA Fraud

**What to notice:** MedDefense IT does not deliver login or enrollment tasks from external, newly registered domains, even when technical authentication checks pass (Finding 2). A link label like "Open compliance task" is a process-shaped instruction, not proof of legitimacy.
**Action:** Reach the compliance portal only through the known intranet bookmark; verify with IT through the known help channel; report the message.
**Why disruption is difficult:** "Passing technical checks" creates false confidence, and compliance deadlines are a genuine recurring feature of administrative work, so the pattern rarely triggers suspicion until after the link.

### Vector 3: Vendor Support Impersonation

**What to notice:** An urgent privilege request with no ticket, no change reference, and no expiration — the defining features of Case C in `insider_threat_case_notes.md`. Caller identity is unverifiable from the call itself.
**Action:** Terminate and call back using the approved vendor contact list; treat any request for elevated or remote access without a ticket as reportable.
**Why disruption is difficult:** Clinical operations genuinely depend on vendor responsiveness, so refusal feels like obstructing patient care. IT staff were suspicious of generic lures but responded to vendor-support framing (`post_incident_click_rate_review.md`), meaning the realistic vector defeats their trained suspicion.

### Vector 4: Executive Impersonation / BEC

**What to notice:** A request for money, credentials, or confidential documents that arrives with pressure to stay inside the email thread — and a reply-to that routes outside the organization (Finding 3).
**Action:** Independently verify by voice through a known channel; never resolve payment or document requests by replying to the message.
**Why disruption is difficult:** Reluctance to challenge perceived authority is the documented failure mode ("you don't want to slow them down"), and the low click rate masks the severity, so these messages attract less scrutiny rather than more.

---

## 5. Simulation Design Requirements

Five actionable constraints derived from Sections 1–4. These govern every template in Task 3 and every vishing script in Task 6.

1. **Name the real systems and shape the lures on documented kit behavior.** Every template must reference MedDefense workflow systems explicitly (Epic, billing portal, HRIS, board portal) and use neutral, error-free operational language — "verification required," "access review," "next scheduled shift" — never spelling errors or cartoonish threats. The learning objective is verification of unexpected workflow-impacting requests, not spotting bad grammar (`phishing_kit_analysis_summary.md`).

2. **Time clinical deliveries to the documented shift-start pressure windows, with clinical safety exclusions.** Clinical waves deliver only within 07:15–08:30 or 19:15–20:30, never during medication pass peaks, active code events, ICU/OR critical coverage, the Joint Commission accreditation window, or flu-season peak November–January (`clinical_schedule_constraints.md`). The same windows that make phishing dangerous are the windows in which training must occur — but never at the cost of patient-care distraction.

3. **Every clinical and administrative template must pair authority with an operational consequence, not an account-status abstraction.** The effective clinical lure threatens "a temporary access hold on patient records before your next shift," not "your password expires." Administrative templates must attach the compliance/benefits frame to a concrete deadline and financial consequence, matching Mechanisms 1–4 of the effectiveness table in Section 3 (`lure_effectiveness_benchmarks.md`; `healthcare_social_engineering_patterns.md`).

4. **Every template must contain exactly one clear, reportable signal, and BEC templates must make reply-channel verification the trained behavior.** Header findings supply the signals: external domain mismatch (Vectors 1–2), request-for-access-without-ticket (Vector 3), and reply-to divergence from the displayed sender (Vector 4) (`email_header_inspection_results.md`). Employee-facing teaching cues must express these as the employee-friendly language from the header findings, not raw header analysis.

5. **Difficulty must escalate across waves in segment-appropriate tiers, and every template must carry a feasible disruption action.** Baseline lures (recognizable cue) first for SEG-B and SEG-C; intermediate personal/financial pressure (T-HR class) second; advanced BEC variants for SEG-E and SEG-F only after verification behavior has been taught and practiced. Advanced templates deliberately minimize technical indicators, so their landing pages must train the verification action — independent callback, known-portal path, report button — rather than link inspection (`phishing_template_constraints.md` tier model; `cobalt_strike_phishing_path.md` training message: make the safe action easier than the unsafe action).
