# Notes

A collection of ready-to-use detection queries for common SIEM and security monitoring platforms.

## Contents

| File | Platform | Description |
|------|----------|-------------|
| [`Top_25_SPL_Queries.md`](Top_25_SPL_Queries.md) | Splunk (SPL) | 25 essential Splunk searches covering authentication anomalies, endpoint monitoring, network threats, file integrity, privilege escalation, and anti-forensics. |
| [`Top_25_Wazuh_Queries.md`](Top_25_Wazuh_Queries.md) | Wazuh | 25 Wazuh detection rules covering brute-force detection, privilege escalation, malware/IOC matching, reverse shell detection, compliance auditing, and persistence techniques. |

## Categories Covered

files share overlapping detection themes organized into:

- **Authentication & Access Control** — brute force, anomalous logins, new account creation
- **Privilege Escalation** — sudo abuse, SUID binaries, privileged group changes
- **Network & Connection Monitoring** — beaconing, DNS exfiltration, non-standard ports, Tor traffic
- **File Integrity & Data Access** — mass file access, ransomware indicators, binary replacement
- **Malware & IOC Detection** — known hashes, suspicious processes, encoded PowerShell
- **Persistence & Anti-Forensics** — cron modifications, SSH key changes, log clearing
