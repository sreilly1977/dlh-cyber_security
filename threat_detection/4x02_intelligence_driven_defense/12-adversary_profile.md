# Adversary Profile - HEALTHBANE Campaign Operator

**Analyst:** Steve - Cybersecurity Engineer

**Project:** 4x02 Intelligence-Driven Defense - Task 12

**Date:** 28 September 2026

**Sources:** HC3-2026-HEALTHBANE-001 (TLP:CLEAR), Acme commercial feed extract (TLP:AMBER), researcher blog (Marcus Weller, 2026-04-24), MedDefense 4x00 findings (MD-2026-IR-0414-001), Tasks 1-11 project deliverables.

**Discipline note:** Every claim below is tagged FACT (directly stated in a source, with citation), INFERRED (analyst reasoning, with rationale), or UNKNOWN (not documented in any source). Confidence language follows the source's own assessment where available.

---

## 1. Identity and Attribution

### 1.1 Designation Inventory

| Designation | Origin | Nature of Claim | Evidence Offered | Assessment |
|-------------|--------|-----------------|------------------|------------|
| HEALTHBANE | HC3 (advisory §1.1) | Official HC3 campaign designation | 6 partner orgs with full telemetry, 2 ISAO sensors, URLhaus corroboration (§6) | Campaign designation: HIGH confidence. Attribution: LOW (§1.5, §6) — explicitly unconfirmed to any named group |
| VITALSCORE | Acme commercial feed (_metadata, campaign_tag) | Proprietary clustering label on overlapping indicators | ML-based clustering; Acme's own disclaimer states the label "does not necessarily correspond to externally-tracked threat actor names" | Cluster alias only. Signals activity overlap, not actor identity. Researcher (blog §6) advises treating it as an alias and not over-weighting its ML-clustered indicators |
| APT-MEDAGENT | Researcher (blog §6) | Private tracking label, MEDIUM confidence | Tooling + infrastructure overlap with three prior campaigns he documented (RXBRIDGE 2024-07, CLAIMBRIDGE 2024-11, MEDNEXUS 2025-09); explicitly NOT based on telemetry, SIGINT, or insider reporting | Actor-continuity hypothesis: MEDIUM. Critically, the researcher makes no state-sponsorship claim — the "APT-" prefix is a label choice, not an assessed sponsorship finding |

### 1.2 Attribution Analysis

**FACT (HC3 §1.5):** Attribution is UNCONFIRMED. HC3 assesses (MODERATE confidence, Exec Summary) the operator is a **financially motivated mid-tier cybercrime actor**. Infrastructure fingerprints are "consistent with" a mid-tier operator but match no previously named group with high confidence.

**FACT (HC3 §1.1):** HC3 has explicitly NOT adopted the VITALSCORE label. Commercial tracking names are "noted but not endorsed."

**FACT (researcher §6):** The researcher's attribution rests entirely on kit fingerprint continuity: PHPMailer 6.6.0, Njalla registration of operator domains, and the config.php structure (EXFIL_ENDPOINT / OPS_CONTACT keys) recurring across three 2024-2025 campaigns against adjacent healthcare subsectors (pharmacies, insurance processors, hospital billing vendors). He states he has no visibility into whether Acme's VITALSCORE corresponds 1:1 to his APT-MEDAGENT.

**INFERRED (analyst):** The three designations almost certainly describe the same operational activity — all three enumerate the same core infrastructure (meddefense-portal.com, healthbane-c2.net, etc.) within the same April 2026 window. However, "same activity" is a lower bar than "same identified actor," and none of the sources offers primary attribution evidence (telemetry, signals, insider reporting, or legal attribution).

### 1.3 Working Designation Recommendation

**HEALTHBANE campaign operator.**

Rationale: it is source-neutral, implies no sponsorship or group identity, and anchors to the authoritative campaign designation. VITALSCORE should be recorded as a commercial cluster alias; APT-MEDAGENT as a researcher continuity hypothesis (medium confidence), with an explicit note that its "APT" prefix does not reflect any state-sponsorship evidence in the corpus. Adopting either as the working designation would overclaim.

---

## 2. Capability Assessment

### 2.1 Technical Sophistication: Mid-tier, competent, with notable strengths and visible failures

**Strengths (FACT-based):**

- Executed a complete three-stage intrusion pipeline — credential harvesting, macro malware delivery, DNS tunnel exfiltration — reaching full completion at 2 of 6 HC3-visible organizations (HC3 §2).
- DNS TXT tunneling with base32-encoded subdomains at 10-15 second intervals, 44-60 character labels, and base64-encoded command strings in responses (HC3 §2 Stage 3) — protocol-aware, bandwidth-conscious covert channel design.
- Correctly configured SPF, DKIM, and DMARC on an owned lookalike domain (outlook-protection.com), producing a fully authenticated phishing email — 4x00 F3 assesses this as "a higher-sophistication variant."
- Automated per-target branding: kit logos/text scraped from victim websites applied via templating, not manual customization — the researcher calls this "mass production" quality (blog §2).

**Failures (FACT-based):**

- Directory autoindex left enabled on the kit's static path, exposing the full kit including config.php and an operator install log (blog §1). The researcher walked the tree on 2026-04-18 and the kit survived until ~2026-04-22 despite it.
- Hardcoded X-Mailer header broadcasting PHPMailer 6.6.0 (blog §4) — a self-inflicted single-string fingerprint the researcher rates "high-fidelity."
- Outdated wkhtmltopdf 0.12.6 producer metadata persisting across all sampled lures (blog §4).
- Masquerade naming (svchost_update.exe, "HealthSync Update Service") is generic and covered by basic EDR alerting guidance (HC3 §5.3).

### 2.2 Tooling Quality: Assembled, not developed

**FACT:** All identified tooling is off-the-shelf — PHPMailer 6.6.0 (SMTP), wkhtmltopdf 0.12.6 (PDF generation, itself indicative of a reused cheap "PDF-as-a-service" container per blog §4), Let's Encrypt certificates, and a PHP single-page credential harvester. The PowerShell exfiltrator (sync_healthdata.ps1) and macro dropper are campaign-scoped wrappers, not novel malware.

**UNKNOWN:** Whether the kit itself is operator-built or vendor-shipped. The researcher published the kit ZIP hash (ffaabb…) at MEDIUM confidence precisely because "I do not know if it is operator-signed or shipped by a kit vendor" (blog §5.3). This materially affects the capability ceiling: a kit-buyer is a lower-capability actor than a kit-author.

### 2.3 Infrastructure Management: Disciplined separation, sloppy execution

**FACT:** Two-tier registrar strategy — Namecheap for phishing landing pages, Njalla for operator/C2 domains (blog §4). Hosting spread across Hostinger, OVH, and DigitalOcean for lure tier (blog §3; HC3 §1.5), plus an AS20473 secondary node (45.77.218.9) carrying a geographic anomaly note at HC3 MEDIUM confidence (indicator DB, from HC3 feed data). Operator tier sits on OVH (51.38.42.191). Let's Encrypt certificates issued 1-7 days before first use (blog §4).

**FACT:** A pre-staged rotation domain (portal-secure-meddefense.com) with the same kit deployed, awaiting rotation-in (blog §3) — evidence of a planned burn-and-replace lifecycle, not ad hoc provisioning.

### 2.4 Resource Level: Modest

**FACT:** No zero-day exploitation, no supply-chain compromise, no custom implants appear anywhere in the corpus. Attack economics are cheap-VPS and free-certificate scale. The campaign's scale: 14 target organizations, 8 lure domains, roughly a dozen infrastructure endpoints, three-month-old disposable domains. Continuity since at least mid-2024 (if the researcher's three prior campaigns are the same operator) suggests sustainable, repeatable operation rather than one-off effort.

### 2.5 Classification: **Mid-tier cybercrime, financially motivated**

This matches HC3's own MODERATE-confidence assessment (Exec Summary) independently reached here: the actor is above opportunistic scattershot phishing (sector focus, multi-stage pipeline, rotation planning, authentication-aware domain configuration, 2024-2025 continuity per the researcher's hypothesis) but below APT tier (no zero-days, commodity tooling, repeated OPSEC failures, cheap infrastructure). No evidence in any source supports state sponsorship.

---

## 3. Intent and Targeting

### 3.1 Sector Focus

**FACT (HC3 §1.4):** Observed targets: hospital systems, outpatient clinics, medical billing services, regional insurance administrators. Explicitly not observed: medical device manufacturers, pharmacies, public health departments.

**INFERRED:** Combined with the researcher's prior-campaign targets (pharmacies 2024-07, insurance processors 2024-11, hospital billing vendors 2025-09 — blog §6), the consistent selection criterion is organizations holding or processing patient/claims/payment data, not clinical infrastructure. This is a data-theft targeting philosophy, not a disruption one.

### 3.2 Geographic Focus

**FACT (HC3 §1.3):** US healthcare providers, strongest signal in the Midwest ISAC region; two organizations outside the Midwest received phishing but showed no confirmed follow-on activity. Non-US infrastructure placement (Brazil-anomalous AS20473 node) reflects hosting economics, not targeting.

### 3.3 Likely Objectives

| Objective | Status | Evidence |
|-----------|--------|----------|
| Credential acquisition | **FACT (observed)** | Form-POST harvest to creds.log, forwarded via PHPMailer to an attacker mailbox (blog §2); captured dmarsh's credentials (4x00 F5) |
| Patient data theft | **FACT (observed)** | Patient records exfiltrated via DNS TXT tunnel at 2 orgs (HC3 §2 Stage 3) |
| Insurance data theft | **FACT (observed)** | Insurance claims data among exfiltrated records (HC3 §2 Stage 3) |
| Malware delivery | **FACT (observed)** | Stage 2 .docm → svchost_update.exe at 2 of 6 orgs (HC3 §2) |
| Financial gain | **INFERRED (Moderate)** | HC3's own assessment is "financially motivated" (Exec Summary, Moderate confidence). The stolen data types (credentials, PHI, insurance claims) align with monetizable categories. **UNKNOWN:** the actual monetization channel — no source documents where the data goes or how it converts to revenue. This profile deliberately does not assume a specific resale model the sources never describe |

### 3.4 Targeting Methodology

**FACT:** Multi-department, role-tailored lures — at MedDefense alone: a nurse (dmarsh), accounts payable (arivera), billing (lpatterson) received distinct lures (4x00 F4); across the sector, emails impersonated staff-portal, insurance, and HR-benefits senders (HC3 §2 Stage 1). Per-target automated branding harvested from victim websites (blog §2). Urgency language in lures ("Action Required," "Payment Overdue," "verification required" — Tasks 9-10 sample corpus). Stage 2 weaponizes internal trust: follow-up emails sent from compromised colleague accounts (HC3 §2 Stage 2).

---

## 4. Operational Signature

| Dimension | Signature | Durability |
|-----------|-----------|------------|
| Infrastructure tiers | Lure tier (Namecheap + Hostinger/DigitalOcean, disposable) vs operator tier (Njalla + OVH, protected) | High |
| Registrar pattern | Namecheap for lures, Njalla for operator/C2 domains | High (deliberate economic separation) |
| Hosting providers | Hostinger, OVH, DigitalOcean (lure); OVH + AS20473 node (operator/secondary) | Medium |
| Domain lifecycle | Registration 4-10 days pre-use (4x00 F2; HC3: "within 14 days" of activity) | High |
| Domain naming | Compound healthcare composites (`med*-portal`, `*-supplies`, `*-benefits`, reversed `portal-secure-med*`); operator domains follow `<word>-c2.net` | High |
| TLS certificates | Let's Encrypt, issued 1-7 days before first use | Medium (indicates scripted cheap automation) |
| Email tooling | PHPMailer 6.6.0, hardcoded X-Mailer header; X-Priority: 1 | High |
| Document tooling | wkhtmltopdf 0.12.6 producer string on all lure PDFs | High |
| Credential capture | Single-page PHP kit; POST → creds.log → PHPMailer forward to operator mailbox | High |
| Exfiltration channel | DNS TXT tunneling, base32 subdomains 44-60 chars, 10-15s interval; base64 C2 responses | High |
| Social engineering | Urgency CTAs; role-tailored (nurse/AP/billing) lures; Stage 2 from compromised internal accounts | High |
| Operational cadence | Staged rotation domains prepared before current set burns | High |

The tasking note about "TLS certificate usage" is now answered from the re-read sources: Let's Encrypt with 1-7 day pre-use issuance (researcher §4). My earlier note that this was undocumented was wrong — the detail exists in blog Section 4.

---

## 5. Predictive Assessment

### 5.1 What Will Likely Change

- **Domains:** Highest-certainty churn. The researcher rates indicator-based domain/IP blocking effective for "about one week" (blog §7), and a pre-staged replacement domain (portal-secure-meddefense.com) has already been observed (blog §3).
- **IPs:** Cheap-VPS churn follows domain rotation by definition.
- **Hashes:** Per-attack recompilation is trivial; variant hashes are already observed in the corpus (dropper variant dd5efb… at HC3 MEDIUM; update_service_v2.exe ee11… commercial-only).

### 5.2 What Will Likely Stay the Same

- **Kit architecture:** PHP single-page harvester, config.php structure, creds.log → PHPMailer forwarding chain (three campaigns of continuity per blog §6).
- **Tooling:** PHPMailer, wkhtmltopdf, Let's Encrypt, Namecheap/Njalla — all cheap, familiar, and functionally sufficient.
- **Naming grammar:** Compound healthcare composites and `<word>-c2.net` operator domains.
- **Sector targeting:** Healthcare payment/PHI holders, four consecutive years per the researcher's continuity hypothesis.
- **Exfiltration channel:** DNS TXT tunneling pattern (subdomain length 44-60 chars, base32) — the single most detectable durable behavior, and the basis for the length/charset anomaly detection recommended in HC3 §5.2.
- **Social engineering playbook:** Role-tailored urgency lures; internal-account Stage 2 delivery.

This durability ranking directly validates the Task 9-10 YARA arsenal design: the rules key exactly on the stable layer (tooling fingerprints, header behavior, naming grammar, harvest paths), while Task 8's gap analysis flags the durable behaviors that IOC blocks cannot cover.

### 5.3 Retooling Indicators (signs the operator has changed capability or approach)

1. **wkhtmltopdf version change** — especially to 0.12.7, which would indicate abandoning the reused PDF-generation container (blog §4's specific reasoning).
2. **Registrar migration** away from the Namecheap/Njalla pair.
3. **Kit structure changes** — disappearance of the config.php EXFIL_ENDPOINT/OPS_CONTACT keys, or the X-Mailer header no longer hardcoded.
4. **Exfiltration channel change** away from DNS TXT tunneling (e.g., switching to HTTPS exfil), which would also neutralize the §5.2 detection guidance.
5. **Longer infrastructure lead times** (registration > 14 days pre-use, certificates issued earlier) — would indicate reaction to new-domain and new-cert monitoring.
6. **Naming grammar departure** — abandonment of compound healthcare naming or the `-c2.net` operator pattern.

Any two of these appearing together should trigger a fresh attribution and detection review, since the entire YARA arsenal and the HC3 mitigations assume the current operational signature.

---

## 6. Confidence and Unknowns

### 6.1 Known (directly evidenced)

- Campaign scope and progression: 14 targeted orgs, 6 with HC3 visibility, 2 reaching full Stage 3 (HC3 §1, §2)
- Complete stage-by-stage tradecraft with IOCs at HIGH confidence across four corroborating sources (Tasks 1-7 deliverables; indicator DB, 33 vetted indicators)
- Kit internals: structure, config values, SMTP route, exfil endpoint (blog §2, §4)
- Prior campaign continuity (2024-2025, researcher MEDIUM)
- MedDefense specifics: one likely credential exposure, no Stage 2/3 activity, no attempted post-compromise authentication within the 4x00 window (4x00 F4-F6, Q1-Q4)
- Operator type assessment: financially motivated mid-tier cybercrime (HC3, Moderate confidence)

### 6.2 Inferred (reasoned, labeled)

- The three designations describe the same operational activity (infrastructure identity across sources)
- Rotation-staged domain indicates a standing replacement playbook (single observation, strong pattern)
- Mass-production templating is scripted, not manual (quality-of-execution inference from blog §2)
- Kit is assembled from commodity components rather than custom-developed (tooling inventory)
- Financial motivation model from stolen data types (HC3-aligned, monetization channel unseen)

### 6.3 Unknown (not documented in any source — stated plainly)

- Operator identity, location, team size, and any group nexus
- Whether Acme's VITALSCORE and the researcher's APT-MEDAGENT map 1:1 (both sources explicitly disclaim this)
- Monetization channel for the exfiltrated patient/insurance data
- Whether the phishing kit is operator-authored or purchased from a kit vendor (blocks attribution refinement)
- Whether organizations beyond the 14 reported (or beyond HC3's 6 visible) were affected
- Whether the 2-of-6 Stage 2 progression rate reflects attacker selectivity, victim defenses, or chance
- Whether credential sets beyond the six observed orgs were collected and sold/accessed independently of the observed campaign stages

---
