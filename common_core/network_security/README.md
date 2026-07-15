# Network Security

A collection of hands-on bash scripting exercises focused on network reconnaissance and traffic analysis — covering passive and active reconnaissance, host discovery scanning, and network traffic monitoring with CTF-style challenges.

## Modules

| Module | Description |
|--------|-------------|
| [`0x01_passive_reconnaissance`](./0x01_passive_reconnaissance) | WHOIS lookup, DNS record enumeration (A, MX, TXT), dig queries, subdomain discovery using Subfinder |
| [`0x02_active_reconnaissance`](./0x02_active_reconnaissance) | Port enumeration, web server identification, vulnerability assessment flags from CTF exercises |
| [`0x04_nmap_live_hosts_discovery`](./0x04_nmap_live_hosts_discovery) | Various host discovery techniques — ARP scan, ICMP echo/timestamp/address mask scans, TCP SYN/ACK ping, UDP ping |
| [`0x05_network_traffic_monitoring_analysis`](./0x05_network_traffic_monitoring_analysis) | Wireshark/tcpdump CTF challenges — source IP/port identification, HTTP header decoding, suspicious DNS, TCP stream analysis, FTP credentials, C2 detection, RDP attack forensics |

## Requirements

- Linux environment
- Bash
- `whois`, `nslookup`, `dig`
- Subfinder (Go-based recon tool)
- Nmap / Scan (`sudo` privileges recommended)
- Tcpdump / Wireshark
- Burp Suite or browser DevTools (for HTTP analysis)
