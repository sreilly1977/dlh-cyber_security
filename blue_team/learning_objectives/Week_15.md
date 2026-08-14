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
