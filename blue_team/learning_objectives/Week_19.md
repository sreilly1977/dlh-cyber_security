# Learning Objectives

---

## Phishing Dissection

---

### Email Security Architecture

**Q: How do SMTP headers record the routing path of an email from sender to recipient?**

**A:** Each hop appends a `Received:` header (bottom-up chronological order), tracing the message through relay servers from origin to destination.

**Q: How does SPF validate sender IP authorization, and what does each result mean?**

**A:** The receiving server checks the connecting IP against the sender domain's DNS TXT record: pass = authorized, fail = unauthorized, softfail = probably unauthorized (soft penalty), none = no SPF record published.

**Q: How does DKIM provide cryptographic message integrity, and what does a valid signature prove?**

**A:** A public/private key pair signs the message; a valid signature proves the message was not altered in transit and came from a holder of the domain's private key, but does not prove the human sender's identity nor the legitimacy of intent.

**Q: How does DMARC tie SPF and DKIM to the visible From domain and enforce policy?**

**A:** DMARC requires either SPF or DKIM to "align" with the visible From domain, then enforces the published policy (none/quarantine/reject) and sends reports back to the domain owner.

**Q: Why can an email pass all authentication checks and still be malicious?**

**A:** Attackers can register their own domains with valid SPF, DKIM, and DMARC, so authentication proves domain ownership, not benign intent (e.g., lookalike domains).

---

### Threat Investigation Methodology

**Q: How do you safely investigate suspicious URLs without navigating to them?**

**A:** Use online analyzers (VirusTotal, urlscan.io), WHOIS/DNS lookups, URL expansion/de-obfuscation, and sandboxed or isolated environments instead of direct browsing.

**Q: How do you analyze email attachments without executing them?**

**A:** Extract metadata, hash the file ( VirusTotal lookup), inspect in a static disassembler or detonate only in an isolated sandbox.

**Q: How do you identify social engineering techniques in email content?**

**A:** Look for urgency ("act now"), manufactured authority (CEO/C-suite spoofing), fear/intimidation threats, and impersonation of trusted brands or colleagues.

**Q: How do you distinguish a coordinated campaign from unrelated phishing attempts?**

**A:** Infrastructure analysis: campaigns share TTPs, hosting, ASN patterns, registrar history, and near-identical payloads, unlike opportunistic scattergun phishing.

**Q: How do you correlate multiple phishing emails using shared infrastructure?**

**A:** Pivot on common IOCs: sender domains, IP addresses, URL patterns, TLS certificates, and reused payload hashes across messages.

---

### Evidence-Based Analysis

**Q: How do you extract, categorize and structure indicators of compromise from artifacts?**

**A:** Pull hostnames, IPs, URLs, hashes, and email addresses from headers/attachments, then classify by type and map to a framework like MITRE ATT&CK.

**Q: How do you assess IOC quality?**

**A:** Strong indicators (unique hashes, novel domains) offer high confidence and low false-positive rates; weak indicators (common IPs, generic user agents) are easily abused by adversaries and require corroboration.

**Q: How do you produce professional investigation reports that support downstream decisions?**

**A:** Structure as executive summary, timeline, findings, IOC table, impact assessment, and actionable recommendations, with evidence attached and chain of custody preserved.

**Q: How do you translate investigation findings into new detection rules?**

**A:** Convert validated IOCs and behavioral TTPs into SIEM rules, email gateway filters, IDS signatures, or YARA rules, then tune for false positives.
