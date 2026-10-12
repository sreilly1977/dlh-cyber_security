# Containment Execution: IR-2026-0414-01

- 2026-04-14T03:16:04Z | Steve, on-call SOC | Switchport VLAN reassign WST-WS-031 → VLAN 999 (quarantine), via NAC API: `POST /devices/WST-WS-031/vlan assign:999` | Host reachable only from IR jumpbox on management subnet; blocked from production VLAN and internet | Confirmed via ping from SOC jumpbox (10.42.1.10) succeeds; ping from user VLAN (10.42.118.0/24) times out; ARP table shows port 17 on switch WS-SW-03 moved to VLAN 999 | No deviation

- 2026-04-14T03:17:21Z | Steve, on-call SOC | Firewall deny rule added at perimeter FW-PERIM-01: `deny outbound ip 185.220.101[.]47 any` with logging enabled | No new netflow packets to 185.220.101[.]47 from WST-WS-031 after rule application | Netflow verification at 03:22:00Z shows zero packets to 185.220.101[.]47 from 03:17:21Z onward; last packet timestamp 03:17:18Z (TCP FIN) | No deviation

- 2026-04-14T03:18:47Z | Steve, on-call SOC | Endpoint device containment flag SET on WST-WS-031 via Wazuh console: `device WST-WS-031 action=set_containment=true` | Only analyst tooling permitted outbound from host; standard user/application traffic blocked at endpoint firewall level | Confirmed in Wazuh dashboard: device WST-WS-031 status=contained, containment_mode=strict, allowed_destinations=["10.42.1.0/24","127.0.0.1"] | No deviation

- 2026-04-14T03:20:13Z | Steve, on-call SOC | Egress severance verification: tcpdump capture on WST-WS-031 for 60 seconds: `tcpdump -i eth0 host 185.220.101[.]47 -w /tmp/verify_c2_blocked.pcap` | Zero packets to/from 185.220.101[.]47 in capture window | pcap analyzed with tshark: no frames matching host 185.220.101[.]47 found; capture duration 2026-04-14T03:20:13Z to 2026-04-14T03:21:13Z | No deviation

- 2026-04-14T03:22:04Z | Steve, on-call SOC | Isolation verification from jumpbox and user VLAN: `ping -c 3 10.42.118.31` from SOC jumpbox (10.42.1.10); `ping -c 3 10.42.118.31` from test workstation on user VLAN (10.42.118.50) | Jumpbox ping succeeds (ICMP allowed in quarantine); user VLAN ping fails (blocked by VLAN isolation) | Jumpbox: 3/3 packets received; user VLAN: 0/3 packets received, ICMP unreachable from gateway | No deviation

- 2026-04-14T03:23:41Z | Steve, on-call SOC | LIS access verification: test HTTP GET to https://lis.meddefense.local/reports/daily from WST-WS-031 via jumpbox SSH session | LIS unreachable from quarantine (outbound blocked except to jumpbox) | Connection timeout confirmed; netstat on WST-WS-031 shows no new ESTABLISHED connections to 10.42.118.17 (LIS server) post-containment | No deviation

## Summary of containment state

| Item | Status | Time |
|---|---|---|
| VLAN 999 assignment | ACTIVE | 03:16:04Z |
| Firewall deny 185.220.101.47 | ACTIVE | 03:17:21Z |
| Wazuh device containment flag | ACTIVE | 03:18:47Z |
| C2 egress verified (tcpdump) | VERIFIED | 03:20:13Z |
| Jumpbox reachability | VERIFIED | 03:22:04Z |
| User VLAN isolation | VERIFIED | 03:22:04Z |
| LIS connectivity blocked | CONFIRMED | 03:23:41Z |

No deviations recorded. All steps executed within 7 minutes 37 seconds of containment authorization window (03:16Z to 03:23Z).

---

## ACTION entries to append to incident_timeline.md

- 2026-04-14T03:16:04Z | ACTION | Steve | Switchport VLAN reassign WST-WS-031 → VLAN 999 via NAC API | source=containment_execution.md | certainty=confirmed

- 2026-04-14T03:17:21Z | ACTION | Steve | Firewall deny rule added at perimeter FW-PERIM-01 blocking outbound ip 185.220.101[.]47 | source=containment_execution.md | certainty=confirmed

- 2026-04-14T03:18:47Z | ACTION | Steve | Wazuh endpoint device containment flag SET on WST-WS-031 | source=containment_execution.md | certainty=confirmed

- 2026-04-14T03:20:13Z | ACTION | Steve | Egress severance verification via tcpdump capture (zero packets to 185.220.101[.]47 in 60-second window) | source=containment_execution.md | certainty=confirmed

- 2026-04-14T03:22:04Z | ACTION | Steve | Isolation verification: jumpbox ping succeeds, user VLAN ping fails | source=containment_execution.md | certainty=confirmed

- 2026-04-14T03:23:41Z | ACTION | Steve | LIS access blocked from quarantine; netstat confirms no new connections to LIS server | source=containment_execution.md | certainty=confirmed
