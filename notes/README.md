# DLH Cyber Security Notes

A practical collection of security monitoring queries, detection rules, and open-source security stack documentation for SOC operations and incident response.

## Repository Structure

### `/notes` Directory

| File | Purpose | Platform |
|------|---------|----------|
| [`Open-Source_Security_Stack.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Open-Source_Security_Stack.md) | Reference architecture for a complete open-source security platform | Infrastructure |
| [`Top_25_SPL_Queries.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Top_25_SPL_Queries.md) | Essential Splunk search queries for threat detection | Splunk SIEM |
| [`Top_25_Wazuh_Queries.md`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/notes/Top_25_Wazuh_Queries.md) | Core detection rules for security monitoring | Wazuh SIEM |

## Open-Source Security Stack Architecture

The referenced architecture documents a production-ready integration of:

| Layer | Tool | Role |
|-------|------|------|
| Perimeter Defense | OPNsense | Firewall, routing, IDS/IPS, VPN |
| Detection & Monitoring | Security Onion 3.x | SIEM, NIDS, host visibility, packet capture, cases |
| Orchestration & Automation | Shuffle | SOAR, workflow automation, cross-tool integration |
| Governance & Compliance | Eramba | GRC, policy management, compliance mapping |

Key benefits: Full detection-prevention-response-compliance coverage with zero vendor lock-in and minimal licensing costs.

## Detection Query Categories

Both SPL and Wazuh query sets cover:

- **Authentication & Access Control** – Brute force, unusual logins, privilege escalation
- **Endpoint & Process Monitoring** – Suspicious execution, credential dumping, malware indicators
- **Network & Threat Detection** – C2 beaconing, data exfiltration, non-standard ports
- **Persistence Techniques** – Cron modifications, SSH key changes, group additions
- **Anti-Forensics** – Log clearing, shell history deletion

## Use Cases

- SOC analyst hunting playbook
- Blue team detection engineering reference
- Security architecture planning
- Training material for security analysts
- Compliance auditing support (CIS, PCI-DSS, HIPAA)

---

*Built for practical security operations. Always test and tailor detections to your environment.*# Cybersecurity Notes
Detection queries can be copied and adapted to match your environment's index names, sourcetypes, and rule IDs. Review and test each query before deploying in production. The architecture guide serves as a reference for designing and sizing an open-source security operations stack.
