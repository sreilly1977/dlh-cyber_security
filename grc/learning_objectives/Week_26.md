# Learning Objectives

---

## Identity at Scale

---

### Technical

**Q: How do you analyze a SAML 2.0 SSO configuration?**

**A:** Inspect each realm/tenant for isolated bindings, verify client ACS URLs and encryption, confirm NameID format/persistence, validate signed assertions and signature algorithms, and map role attributes to intended authorizations.

**Q: How do you identify AWS IAM over-privilege and correct it?**

**A:** Compare granted actions against actual CloudTrail usage, flag unused or wildcard (*:*) permissions, then rewrite policies with least privilege scoped by service, action, resource ARN and condition keys.

**Q: What does the Vault database secrets engine do?**

**A:** It brokers short-lived, per-request database credentials with lease TTLs, shown in transcript outputs as `lease_id`, `lease_duration` and `renewable`, revoking access when leases expire or are explicitly revoked.

**Q: What should a Python account-inventory script produce?**

**A:** Parse the inventory, apply rule-based checks (stale creds, admin sprawl, missing MFA) with weighted scoring, and emit JSON findings with id, account, evidence, and a numeric severity rating.

---

### Conceptual

**Q: How does SAML federation differ from password delegation?**

**A:** SAML delegates only the identity assertion to a trusted IdP while the user's password stays with the home IdP, whereas password delegation (e.g., OAuth legacy flows) shares or proxies actual credentials.

**Q: What distinguishes IAM from PAM, and why are standing privileged credentials risky?**

**A:** IAM governs who has which identities and entitlements while PAM manages, vaults and controls elevated credential use, and standing privileged access is risky because a single theft yields immediate, persistent admin control.

**Q: How do JIT access and TTL-based credentials reduce blast radius?**

**A:** Just-in-time elevation grants privileges only for an approved window and TTL credentials auto-expire, so stolen tokens or passwords become useless outside a narrow time-and-scope envelope.

**Q: How do IAM and cloud misconfigurations connect to ePHI exposure and patient safety?**

**A:** Over-broad roles, public buckets and weak federation controls allow unauthorized access to ePHI, breaching HIPAA safeguards and risking tampered or unavailable records that can compromise clinical care.

---

### Transversal

**Q: What makes a good IAM audit finding?**

**A:** One that cites verifiable evidence (policy JSON, logs, transcripts), assigns a justified severity, and specifies actionable remediation with an owner and validation step.

**Q: How do you write identity-risk language for a CISO and Board Risk Committee?**

**A:** Translate technical gaps into business terms, quantify exposure in likelihood and impact, tie findings to regulatory obligations, and frame investment as risk reduction rather than tooling cost.

**Q: How do you preserve traceability across artifacts?**

**A:** Tag every item with a stable ID that flows unchanged from source evidence, through script-generated findings, into the management report, enabling any stated risk to be traced back to raw data.

---

## The SOC Playbook

---

### Technical

**Q: What does the IOC enrichment module do?**

**A:** Auto-classifies each IOC by type (IP, domain, URL, hash, email), checks it against a bundled local threat intel feed, applies standard-library-only DNS/IP heuristics (RFC1918, loopback, bogon ranges), and emits a structured verdict with additive scoring.

**Q: How is the SQLite case manager designed?**

**A:** A normalized schema with cases, notes, iocs and case_iocs tables (foreign-keyed), exposing functions to create cases, append timestamped notes, transition status, and link IOCs many-to-many.

**Q: What do the two automation playbooks do?**

**A:** Each imports the shared modules, runs scenario alerts through the enrichment verdict, applies threshold decision logic to pick verdict, severity and action (block, monitor, close), writes structured case output, and appends a full audit-log trail.

**Q: What does the end-to-end integration test verify?**

**A:** That each of the five alert scenarios flows through enrichment into a case with the expected verdict, severity and action asserted against pre-defined expectations, confirming the full pipeline works as one system.

---

### Conceptual

**Q: Why separate enrichment actions from response actions?**

**A:** Enrichment is read-only and safe to fully automate, while response actions (blocking, quarantining) carry disruption risk, so they require measured false-positive rates and human override before automating.

**Q: Why is deduplication a prerequisite for alert-to-ticket integration?**

**A:** At SOC volume, recurring detections or mass campaigns of the same IOC would otherwise spawn one ticket per alert, creating ticket storms that drown analysts and destroy queue triage, so identical signals must collapse into one tracked case.

**Q: Why is TTL-based caching the standard answer to rate limiting?**

**A:** Most threat intel APIs throttle by request count, and TTL caches serve repeat lookups of the same IOC from memory until expiry, cutting API calls while keeping results acceptably fresh.

---

### Transversal

**Q: What goes into the automation strategy document?**

**A:** Quantified current manual effort (analyst hours per enrichment and triage task), projected ROI from automating those hours, and explicit naming of over-automation risks, which in a healthcare setting include automated blocking disrupting clinical systems and patient-safety impact.

**Q: How long should the strategy document be?**

**A:** Two to three pages, not twenty: lead with effort numbers, ROI estimate and risk caveats, keeping it decision-ready for leadership rather than exhaustive documentation.
