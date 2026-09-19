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

---

## Wire Shark Territory

---

### Network Traffic Analysis Fundamentals

**Q: How do you establish a traffic baseline?**

**A:** Collect normal network metrics over time to define expected behavior patterns.

**Q: How do you identify deviations from a baseline?**

**A:** Compare current traffic metrics against established baselines to spot anomalies.

**Q: How do you interpret TCP session behavior?**

**A:** Analyze handshake sequences, flag usage, and termination patterns for irregularities.

**Q: How does legitimate DNS activity differ from malicious tooling?**

**A:** Malicious DNS often shows unusual query volumes, random subdomains, or TXT record abuse.

**Q: How can you analyze TLS traffic without decryption?**

**A:** Examine certificate details, handshake patterns, packet sizes, and timing metadata.

**Q: What suspicious timing patterns indicate compromise?**

**A:** Regular intervals, off-hours activity, or consistent beaconing cadences suggest automation.

**Q: How do you measure bytes transferred in sessions?**

**A:** Calculate total payload size per flow using packet capture analysis tools.

**Q: How is session duration measured?**

**A:** Subtract the initial SYN timestamp from the final FIN/RST timestamp.

**Q: How are connection intervals analyzed?**

**A:** Measure time gaps between successive connections to the same destination.

**Q: How are DNS query rates measured?**

**A:** Count queries per second or minute against known normal thresholds.

**Q: How is traffic distribution evaluated?**

**A:** Map source-destination pairs and port usage to detect concentration anomalies.

---

### Attack Pattern Recognition

**Q: What does C2 beaconing look like in PCAPs?**

**A:** Periodic, uniform-sized packets sent at regular intervals to external IPs (unless they use jitter, randomized offsets, for evasion. See Cobalt Strike).

**Q: Why is beaconing invisible to signature-based IDS?**

**A:** It mimics legitimate traffic patterns and lacks known malicious signatures.

**Q: How does DNS tunneling enable exfiltration?**

**A:** Encoded data is hidden within DNS query labels or TXT response payloads.

**Q: How do attackers encode data into DNS labels?**

**A:** They base64 or hex-encode stolen data into subdomain strings.

**Q: How does lateral movement appear on the wire?**

**A:** Unexpected SMB, RDP, or WMI connections between internal hosts.

**Q: How do authentication flows reveal pivots?**

**A:** New credential usage from unfamiliar IPs or rapid sequential logins.

**Q: How do you distinguish human browsing from malware?**

**A:** Humans show variable timing and diverse headers; malware is rigid and repetitive.

---

### Forensic Methodology

**Q: How do you investigate incidents from PCAP evidence?**

**A:** Filter by suspicious IPs, reconstruct streams, and trace attack timelines.

**Q: How do you correlate multiple PCAPs into a timeline?**

**A:** Synchronize timestamps and merge events by source/destination IP and port.

**Q: How do you extract network IOCs?**

**A:** Identify malicious IPs, domains, hashes, and abnormal protocol behaviors.

**Q: How do you reconstruct attacker activity chronologically?**

**A:** Order events by packet timestamps to build a step-by-step attack narrative.

**Q: How do you produce a professional forensics report?**

**A:** Document methodology, evidence, IOCs, and conclusions with clear timestamps.

**Q: How do you support conclusions with packet evidence?**

**A:** Cite specific packet numbers, timestamps, and protocol fields as proof.

---
