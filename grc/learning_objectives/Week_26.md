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

