# Learning Objectives

## Perimeter and Network Defense

### Network Security

**Q: How do zones and segmentation reduce the blast radius of a compromise and why is default-deny inbound the baseline?**

**A:** Zones isolate critical assets to limit lateral movement, while default-deny ensures only explicitly authorized traffic flows, minimizing exposure.

**Q: What distinguishes host-based from network-based firewalls, and when are stateful versus stateless filtering appropriate?**

**A:** Host-based firewalls protect individual endpoints with granular application control, whereas network-based firewalls secure perimeter traffic; stateful filtering is standard for connection-aware security, while stateless is reserved for high-throughput, simple packet filtering.

**Q: How do nftables tables, chains, rules, and sets compose into a readable, maintainable ruleset?**

**A:** Tables organize protocols, chains define hook points and priorities, rules enforce logic, and sets enable efficient grouping of addresses or ports for scalable management.

**Q: How do IDS and IPS differ, and why is offline replay mode preferred for post-incident analysis while inline mode carries higher operational risk?**

**A:** IDS monitors and alerts without blocking, while IPS actively blocks threats; offline replay allows safe forensic analysis of captured traffic without risking service disruption, whereas inline IPS introduces potential latency and false-positive outages.

---

### Secure Protocols

**Q: How can insecure protocols like telnet, FTP, cleartext HTTP, SNMPv1/v2c, and plain LDAP be detected and replaced with secure equivalents?**

**A:** Network scans and log analysis identify cleartext traffic, which should be migrated to SSH, SFTP/FTPS, HTTPS, SNMPv3, and LDAPS respectively to ensure encryption and authentication.

**Q: How do DNS filtering and query validation reduce the attack surface exposed by resolver infrastructure?**

**A:** Filtering blocks malicious domains and query validation prevents spoofing and tunneling, reducing the risk of command-and-control communication and data exfiltration via DNS.

---

### Enterprise Capabilities

**Q: How do you write and apply nftables rules for default-deny, zone-based allow, connection tracking, and logging?**

**A:** Define default-drop policies on input chains, permit specific inter-zone traffic via accept rules, leverage conntrack for stateful inspection, and append log statements before drop actions for visibility.

**Q: How do you align Windows Firewall configuration to the same zone model via PowerShell?**

**A:** Use `New-NetFirewallRule` and `Set-NetFirewallProfile` to create inbound/outbound rules scoped by interface or subnet, enforcing default-deny and allowing only validated zone-to-zone traffic.

**Q: How do you run Suricata against a captured PCAP, parse eve.json output, and classify alerts by severity and kind?**

**A:** Execute `suricata -r capture.pcap --log-dir ./logs`, then parse `eve.json` using jq or Python to group alerts by `alert.severity` and `alert.signature` for incident triage.

**Q: How do you write custom Suricata rules for MedDefense-specific threats and validate that each rule fires against a target capture?**

**A:** Craft rules matching unique payload signatures or behavioral patterns in `rules.local`, then test with `suricata -r target.pcap -T` to confirm alert generation without live traffic.

**Q: How do you investigate a PCAP with tshark and tcpdump to extract conversation metadata, DNS queries, file transfers, and protocol anomalies?**

**A:** Use `tshark -r file.pcap -Y "dns"` for queries, `-Y "tcp.analysis.flags"` for anomalies, and `tcpdump -nn -r file.pcap` for quick stream inspection of transfers and handshakes.

**Q: How do you package network evidence (firewall logs, Suricata alerts, PCAP summaries, connection metadata) as a structured artifact bundle for downstream analysts?**

**A:** Aggregate logs into a dated tarball with a manifest index, normalize timestamps to UTC, and include README documentation detailing data sources, collection times, and relevant IOCs.

---

## The Defensible Endpoint Package

### Cross-Project Synthesis

**Q: How to apply Linux hardening, Windows hardening, telemetry engineering, patch management, and perimeter defense as a single integrated workflow on one environment?**

**A:** Orchestrate each module's hardening scripts through a unified pipeline runner that executes them in dependency order (baseline first, then OS hardening, then patches, then telemetry, then perimeter), sharing a common evidence store and producing a consolidated compliance report so the environment is hardened holistically rather than in silos.

**Q: How to produce a professional handoff package that a peer engineer can verify and operate without further briefing?**

**A:** Bundle all scripts, configuration files, the compliance report, an executable runbook, a hash-verified manifest, and a binary acceptance checklist into a single versioned archive, so the receiving engineer can validate integrity, re-run the pipeline, and confirm every control passes without needing additional context or verbal explanation.

### Defensible Engineering

**Q: How to intake a raw environment and capture its unhardened baseline as structured evidence?**

**A:** Run an automated discovery scan (host inventory, open ports, services, configurations, patch levels) and export the results as structured data (JSON/CSV) into version-controlled evidence storage, timestamped and tagged for traceability.

**Q: How to define a target state in data (not prose) that every subsequent task can be measured against?**

**A:** Encode the desired configuration as a machine-readable policy file (JSON/YAML schema) specifying exact expected values for each control, so every hardening script can diff current state against target and report pass/fail.

**Q: How to compose individual hardening, instrumentation and defense scripts into one end-to-end pipeline that is idempotent and auditable?**

**A:** Chain scripts through a pipeline runner (e.g., Makefile or Bash orchestrator) where each step checks desired state before acting, logs every action to a structured audit log, and can be re-run safely without side effects.

**Q: How to produce a single machine-readable compliance report covering every control in scope?**

**A:** Aggregate the pass/fail results from all control checks into a single JSON or CSV report keyed by control ID, including status, evidence reference, and timestamp for each item.

**Q: How to package telemetry and validation evidence in the exact format Module 3 consumes?**

**A:** Normalize all outputs to a shared schema (consistent field names, data types, and directory structure) defined by Module 3's input contract, bundling logs, configs, and scan results into a versioned archive with a manifest.

### Professional Handoff

**Q: How to write a runbook that is executable, not narrative?**

**A:** Write the runbook as a shell script (or sequence of explicit, copy-pasteable commands) with guard rails, error handling, and exit codes, so that execution is deterministic rather than dependent on human interpretation.

**Q: How to produce a manifest with file hashes so that the receiver can verify the integrity of the handoff?**

**A:** Generate SHA-256 hashes for every file in the handoff package and write them to a manifest file (e.g., `manifest.txt` or `manifest.json`) that the receiver validates with `sha256sum -c` before trusting any artifact.

**Q: How to design evaluation criteria that are binary and countable, so that the quality of the handoff is not a matter of taste?**

**A:** Define each acceptance criterion as a testable condition with a boolean outcome (e.g., "manifest validates: yes/no," "all scripts pass shellcheck: yes/no," "no control returns 'unknown'"), counted as pass/fail out of a total checklist.
