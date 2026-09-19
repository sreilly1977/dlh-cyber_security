# 14-threat_intel_enrichment_plan.md

**Name:** Threat Intelligence Enrichment Plan

**Purpose:** Design an offline enrichment plan defining where the extracted IOCs
          should be operationalized, how matches should behave, and how the
          program should be validated and maintained over time

**Author:** Steve - Cybersecurity Engineer

**Date:** 19 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — THREAT INTELLIGENCE ENRICHMENT PLAN

Evidence basis: IOC extraction (report 11), detection recommendations (report 12),

investigation report (13). No live enrichment, SIEM integration, or service

restarts were performed — this is the operationalization design for the IOCs

once tooling access is available.

================================================================================

## 1. IOC Destinations and Operational Behavior

### Destination 1 — Email Gateway Block / Quarantine List

**Which IOC types belong here:** Domains (meddefense-portal[.]com, outlook-protection[.]com, medequip-supplies[.]net, meddefense-benefits[.]org), sender addresses and their Reply-To variants, the attachment filename pattern (INV-2026-04891.pdf and generic INV-{date}-{seq}.pdf from external senders), and the campaign's header fingerprint (PHPMailer 6.6.0 + PHP-{hex} Message-ID) as a scoring input only, never a block key.

**Why appropriate:** The gateway is where every inbound email passes a policy decision point. All four malicious emails entered through mx01.meddefense.com, so gateway-level enforcement is the earliest and cheapest interception point — blocking here stops delivery before any human can click.

**Alert or action on match:** Hard block (reject at SMTP) for the four confirmed-malicious domains and sender addresses. Quarantine-with-analyst-review for the attachment filename pattern and lookalike-domain heuristic (Detection 1 from report 12), since those are pattern matches rather than confirmed-bad exact values. Alerts route to the SOC phishing queue with the matched IOC and original message context attached.

**False-positive risk:** LOW for the four exact domains (nothing legitimate operates on them). MEDIUM for the filename and lookalike patterns — legitimate vendors send invoice PDFs and legitimate partners may register meddefense-adjacent names. Mitigation: pattern matches quarantine rather than reject, with a documented 4-hour analyst review SLA, and a whitelist for verified suppliers and *.meddefense.com subdomains baked into the rule logic.

**Owner/team:** Messaging/Email team owns rule deployment; SOC owns alert triage; James Chen approves exceptions and releases from quarantine.

---

### Destination 2 — DNS Filtering

**Which IOC types belong here:** The four campaign domains (as sinkhole/block entries) and the four sending IPs. Longer term, newly-registered-domain category feeds with healthcare-brand keyword components.

**Why appropriate:** DNS is the mandatory first hop for any click. Whether a user clicks a link in an email already delivered, follows a link in a webmail view, or mistypes a portal address, the resolver sees it. DNS filtering provides defense-in-depth behind the gateway — exactly the second line that was missing when Diane Marsh clicked.

**Alert or action on match:** Sinkhole the four confirmed domains (NXDOMAIN or block-page redirect) immediately. Alert (do not block) on resolutions of newly-registered keyword domains from workstation subnets, per Detection 4 in report 12, with the alert carrying the client IP for correlation against the endpoint watchlist (Destination 4). A resolution of a confirmed campaign domain by any internal host should page the SOC immediately — it indicates a delivered-but-unreported lure or an already-infected machine.

**False-positive risk:** LOW for the four exact domains. MEDIUM for age-based heuristics — legitimate new businesses, recently migrated vendors, and rebranded suppliers all live on young domains. Mitigation: age/keyword heuristics alert-only; blocking restricted to the confirmed IOC list; whitelist process for verified new partners.

**Owner/team:** Network engineering (Mike Torres' team) owns resolver configuration; SOC consumes the alerts; jointly owns the whitelist.

---

### Destination 3 — Web Proxy Filtering

**Which IOC types belong here:** The five harvesting/payment URLs (exact-match block), the four domains (category: phishing), the four IPs, and the per-victim parameter pattern (verify/login/enroll/pay paths carrying id=/token= parameters) as a detection rule per Detection 5.

**Why appropriate:** The proxy sees the actual HTTP request after DNS resolves — the final gate before the harvesting form loads. It is also the only destination that can observe the POST that follows a click, which is the single most important missing fact of this investigation (did Diane submit credentials?).

**Alert or action on match:** Block all five exact URLs and the four domains outright. For pattern matches (harvesting-path heuristics), block the request and raise a CRITICAL alert. Critically: any GET→POST sequence from an internal host to a flagged or heuristic-matched domain should trigger immediate IR paging — a POST is the signature of a submitted credential form.

**False-positive risk:** LOW for exact IOC matches. MEDIUM for path/parameter heuristics — legitimate SSO and enterprise app flows use similar URL structures. Mitigation: whitelist SSO provider domains (and any MedDefense SaaS portals using parameterized login URLs) inside the rule; confine the heuristic to external, non-whitelisted domains.

**Owner/team:** Network/security engineering owns proxy policy; SOC owns alerting and IR paging; the proxy administrator maintains the SSO whitelist.

---

### Destination 4 — EDR / Endpoint Watchlist

**Which IOC types belong here:** The attachment filename (INV-2026-04891.pdf), the SHA-256 indicator once recomputed and verified from the extracted sample, the meddefense-portal[.]com and other campaign domain strings for browser-history/artifact scanning, and the hostname strings of the click-bearing machines (WS-NURSE-04 as a priority-monitor entry).

**Why appropriate:** Endpoint telemetry closes the visibility gap this investigation exposed most sharply — the confirmed click was discovered through a helpdesk report, not tooling. EDR watchlists allow retrospective scans across the fleet ("which machines have browser history containing meddefense-portal.com") answering Sarah Park's unanswered question about unreported clicks.

**Alert or action on match:** On-demand fleet-wide retro-hunt for the domain strings and hash across the entire 2026-04-14-to-present window; standing alert on any new file write matching the invoice filename or hash; WS-NURSE-04 placed under elevated monitoring for 30 days per report 13's recommendations.

**False-positive risk:** MEDIUM — filename matches are weak signals (any document could share the name); hash matches are strong but the current SHA-256 is self-declared in the PDF content and unverified, so it must be recomputed from the sandbox-extracted sample before ANY hash-based rule ships, or the rule could hunt for an indicator that does not exist. Domain-string matches in browser caches could hit security staff who intentionally visited the harvesting page for analysis — the SOC team's own machines need a documented exemption or process-context filter.

**False-positive mitigations recap:** recomputed hash only; filename + domain-string matches alert-only; SOC analyst machines whitelisted for research visits.

**Owner/team:** SOC owns watchlist curation and the retro-hunt; desktop/endpoint engineering owns agent coverage verification; IR owns WS-NURSE-04 elevated monitoring.

---

### Destination 5 — SIEM Threat Intelligence Lookup

**Which IOC types belong here:** ALL IOCs, as a correlation dataset: domains, IPs, URLs, sender addresses, the file hash, plus the context-only entries (PHPMailer fingerprint, wp-admin/wp-portal hostname pattern, urgency/role-targeting behavioral pattern, budget-VPS hosting tier).

**Why appropriate:** The SIEM is the correlation layer where indicators meet events — DNS logs, proxy logs, mail gateway logs, and authentication events all join here. This is where campaign linkage happens: a future alert on a NEW domain can still fire the PHPMailer-plus-lookalike correlation even though the new domain is not on any blocklist. It is also where the investigation's unanswered questions (POST after click, anomalous authentications, unreported resolutions) finally become answerable once telemetry flows in.

**Alert or action on match:** IOC matches correlate into a single campaign-tagged incident rather than scattered alerts (critical for attribution continuity — every event touching these IOCs should inherit the case tag for this investigation). New-message matches on context patterns (PHPMailer + lookalike, urgency + role-targeting) generate MEDIUM-correlation alerts for analyst review rather than automated action.

**False-positive risk:** MEDIUM overall. The exact-value IOCs are low-risk in the SIEM (alerting, not blocking). The pattern/context entries are the risk zone: PHPMailer and budget-VPS signals alone would drown analysts. Mitigation: context entries are weighted inputs to correlation rules, never standalone triggers; each fires only in combination with at least one other campaign attribute (per report 12's stacked-detection design).

**Owner/team:** SOC detection engineering owns correlation rules and case tagging; SIEM/platform admin manages feed ingestion; analysts own triage of correlation alerts.

---

### Destination 6 — HC3 / ISAC Submission

**Which IOC types belong here:** The HC3-ready summary set from report 11: four domains, four IPs, four sender addresses, five URLs, the file artifact (hash pending recomputation), and the TLP:CLEAR correlation notes — campaign timing, tooling fingerprint, targeting pattern, and the wp-hostname observations.

**Why appropriate:** E8 explicitly states HC3 has no IOCs yet for this campaign because nobody has submitted them, and requests submissions via the HC3 portal through the ISAC liaison. MedDefense reporting first both contributes to sector defense (other hospitals gain blocking material days earlier) and positions MedDefense to receive the forthcoming named-campaign advisory's intelligence as an early contributor.

**Alert or action on match:** Outbound, not inbound — no local alerting. Track the submission reference; when HC3 publishes the formal advisory with confirmed IOCs, ingest THEIR indicator set back into Destinations 1-5, which will validate or expand our list (HC3 may have IOCs from other victims' emails we never saw — our batch showed only 8 emails of what may be a larger campaign).

**False-positive risk:** MINIMAL (reputational rather than technical): submissions must be verified before sending to avoid polluting the shared intelligence pool. The SHA-256 must NOT be submitted until recomputed; the victim's identity (dmarsh, WS-NURSE-04, 10.10.2.15) must be EXCLUDED from the external submission — that is case data, not attacker infrastructure, and sharing it could harm the employee and violate her privacy.

**Owner/team:** SOC lead (James Chen) authors the submission; the ISAC liaison transmits it; compliance reviews before external release.

---

## 2. Prioritization Plan

**Enrich immediately (deploy within 24 hours, block-grade):**
- The four domains and four sending IPs — highest-confidence, zero-legitimate-use indicators; block at gateway, DNS, and proxy simultaneously
- The five exact URLs — confirmed harvesting endpoints, including the one that captured the click
- The four sender addresses — gateway-level rejects
- WS-NURSE-04 elevation and the dmarsh account protections (this is incident response, but it shares the timeline)

**Deploy within the week (detect-grade, alert-and-review):**
- The attachment filename pattern and lookalike-domain heuristic at the gateway
- Per-victim parameter URL detection (Detection 5) at the proxy
- DNS alerting on newly-registered keyword domains
- SIEM correlation rules tagged to this campaign (including pattern/context entries as weighted inputs)
- Fleet-wide EDR retro-hunt for the campaign domain strings

**Monitor only (context entries, never standalone triggers):**
- PHPMailer 6.6.0 fingerprint, PHP-{hex} Message-ID format, localhost injection hop — correlation inputs only
- wkhtmltopdf 0.12.6 producer string — hunt hypothesis when paired with invoice pretexts
- wp-admin/wp-portal hostname pattern — observation for the investigation record
- The budget-VPS hosting tier — never actionable; millions of legitimate sites share those providers

**Remain context-only permanently (internal documentation, not distributed):**
- Victim identifiers (dmarsh, WS-NURSE-04, 10.10.2.15) — excluded from every external feed; retained in the internal case record only
- HC3@hhs.gov — verification baseline, whitelisted, never blocked
- The campaign's strategic tradecraft analysis (role segmentation, sequencing) — awareness and detection-engineering material, not machine-enforceable indicators

---

## 3. Validation Plan

**Testing that enrichment works (controlled, safe):**
- Send test emails from an external test account that carry the four malicious domains in the From and body (defanged text in headers of a benign message, constructed in the lab) — verify each is blocked/quarantined by the gateway and logged to the SIEM with the campaign tag
- Attempt DNS resolution of the four domains from a test workstation — verify sinkhole response and SOC alert generation
- Request one of the five exact URLs through the proxy from a test machine — verify the block page and the CRITICAL alert
- Submit a honeypot URL matching the per-victim parameter pattern (verify/login path with id=/token= parameters) to a test domain on the SSO-whitelist exclusion list's complement — verify the heuristic fires without touching real infrastructure
- Place a copy of the extracted invoice PDF (verified hash) on a test machine — verify the EDR watchlist alerts on the write

None of these tests touch live attacker infrastructure; all use the documented IOCs against internal enforcement points.

**Historical events to check (retrospective):**
- DNS logs: every internal host that resolved any of the four campaign domains between 2026-04-14 and present — the direct answer to Sarah Park's unreported-clicks question
- Proxy logs: any GET or POST to the five URLs, especially the expected GET from 10.10.2.15 at 2026-04-14 15:02:33 CDT and any POST that followed it — the deciding evidence for the compromise decision matrix (report 7)
- Gateway logs: total delivery count of E2/E3/E5/E7 beyond the eight collected — establishing true campaign scope
- Authentication logs: dmarsh sign-ins from unexpected sources, off-shift hours, or new devices; rmendez M365 sign-ins against the E3 lure window
- EHR audit trail: dmarsh patient-record access from the click time forward — the HIPAA exposure determination

**What success looks like:**
- Functional: every validated test IOC triggers its designated action at each destination; SIEM consolidates matches into campaign-tagged incidents; no legitimate mail quarantined in a 72-hour post-deployment window (whitelist effectiveness)
- Investigative: the retrospective log review converts the decision matrix from "unknown" to a documented outcome (no compromise / possible exposure / confirmed compromise) for the click incident
- Programmatic: the time from a new phishing report to IOC deployment across all destinations drops from days (this incident: click-to-investigation alone was 36+ hours) to under one business day; the retro-hunt returns a complete list of unreported clicks; and the HC3 submission is acknowledged with a reference number

---

## 4. Feedback Loop

**Ingestion — updating the IOC list from new inputs:**
- New user reports and gateway quarantines feed the same pipeline this investigation followed (triage → header/authentication analysis → IOC extraction), with the campaign correlation checks (PHPMailer fingerprint, lookalike construction, urgency/role pattern) applied automatically to determine whether a new email extends THIS campaign or starts a new one; new campaign members inherit the campaign tag and enter all destinations at the appropriate tier
- Future HC3 advisories (and the named-campaign advisory promised in E8) are ingested on arrival as standing SOC intake per report 13's medium-term recommendation: their confirmed IOCs are diffed against our deployed list — matches validate our attribution, differences (IOCs from other victims' emails we never saw) are added, extending coverage beyond our 8-email visibility window
- Detection engineering feedback: every alert fired on a context pattern (e.g., a new PHPMailer lookalike) that analyst review confirms as malicious becomes a promoted, exact-value IOC — pattern detections are the campaign-extension sensors; their confirmations grow the blocklist
- The ISAC/HC3 relationship is bidirectional: our submissions strengthen the sector feed we subsequently consume

**Maintenance — reviewing and retiring indicators:**
- Scheduled quarterly review of the entire IOC list, with each entry graded on continued relevance: has the indicator been seen in the wild since the campaign window? Has the hosting been taken down (re-verify via passive DNS, without direct contact)? Is the domain expired or re-registered to a legitimate party?
- High-confidence exact IOCs (domains, IPs, URLs) retire on a 12-month no-observation schedule, or earlier if intelligence confirms infrastructure seizure/takedown — attacker IPs in particular churn rapidly on budget VPS providers, and stale IP entries eventually get reallocated to innocent customers, converting yesterday's IOC into tomorrow's false positive
- Pattern/context entries (PHPMailer, lookalike heuristics, urgency profiles) never expire on a timer; they retire only when review shows the attacker tradecraft has shifted, and each retirement is documented with the evidence
- Every addition, promotion, retirement, and expiry is logged with rationale and reviewer — the IOC list's integrity is itself auditable evidence, which matters both for internal trust in the blocklists and for the quality of anything shared externally
- Retired indicators remain archived (not deleted) in the SIEM's historical lookup context, so that legacy SIEM searches or reopened incidents can still resolve them — an IOC can stop being blocked while remaining known

================================================================================
