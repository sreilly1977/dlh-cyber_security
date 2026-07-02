# Cybersecurity Notes

A collection of practical detection queries and architecture guidance for SIEM, SOAR, and security monitoring tools.

## Contents

| File | Topic | Description |
|------|-------|-------------|
| [`Open-Source_Security_Stack.md`](Open-Source_Security_Stack.md) | Architecture | Blueprint for building an open-source security stack covering SIEM (Wazuh, Security Onion), SOAR (Shuffle), NIDS (Suricata, Zeek), HIDS (Wazuh), and firewall/WAF (OPNsense). Includes key infrastructure and tuning considerations. |
| [`Top_25_SPL_Queries.md`](Top_25_SPL_Queries.md) | Splunk | 25 SPL queries for threat detection across authentication, endpoint monitoring, network security, file integrity, privilege escalation, and more. |
| [`Top_25_Wazuh_Queries.md`](Top_25_Wazuh_Queries.md) | Wazuh | 25 Wazuh detection rules covering brute-force detection, privilege escalation, persistence techniques, malware/IOC detection, and SOC compliance auditing. |

## Categories Covered

- **Authentication & Access Control** — Brute-force detection, suspicious logins, new account creation
- **Endpoint & Process Monitoring** — Suspicious PowerShell, credential dumping, reverse shells
- **Network Security** — Beaconing, data exfiltration, Tor traffic, non-standard ports
- **Privilege Escalation** — Sudo abuse, SUID binaries, privileged group changes
- **Persistence** — Scheduled tasks, SSH key modifications, cron job tampering
- **Malware & IOC Detection** — Known hashes, ransomware indicators, DNS tunneling
- **Compliance** — User group changes, log clearing, audit-ready queries
- **Architecture & Tooling** — Open-source stack design, infrastructure sizing, log pipeline planning, and tuning guidance

## Usage

Detection queries can be copied and adapted to match your environment's index names, sourcetypes, and rule IDs. Review and test each query before deploying in production. The architecture guide serves as a reference for designing and sizing an open-source security operations stack.
