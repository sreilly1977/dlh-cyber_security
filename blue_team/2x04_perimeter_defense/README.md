# Introduction

>"The network is the only place where you can see an attacker before they are inside a machine. Lose that view and you lose the first move." 
>
> — Richard Bejtlich, The Practice of Network Security Monitoring

Every endpoint in MedDefense is now hardened. auditd is loaded on every Linux host. Sysmon and Script Block Logging cover every Windows host. PAM, AppArmor, sysctl, audit policy: the host layer is in place. Then at 10:22 on Tuesday, Mike Torres walks over with a single observation that undoes half the work. Between the hardened endpoints, the network is flat. Anything that reaches one machine can reach every other machine. There is nothing on the wire between them.

This project builds the control plane that lives between hosts. You will map what the host sees from its own interface, enumerate the attack surface it presents, design zones with intent, write nftables rules that enforce default-deny, validate every rule with real connection tests, audit and remediate insecure protocols, parse firewall logs for scan patterns, replay packet captures through Suricata in offline mode, write custom Suricata rules against MedDefense-specific threats, investigate a suspicious PCAP byte by byte and package the resulting network evidence in the exact format Module 3 will consume. No live monitoring stack. No SIEM daemon. No collector. Every deliverable is a script, a rule file or a structured JSON artifact.

## Why this matters

A hardened host on a flat network is a solved problem sitting next to an unsolved one. The attacker who cannot defeat your sshd configuration can still scan your subnet, move laterally over SMB, tunnel data over DNS or pivot through a forgotten Telnet listener on a medical device. The defenses in this project cover the space between hosts. And because the evidence you produce (firewall logs, PCAP summaries, Suricata alerts, connection metadata) is the same evidence a Tier 1 SOC analyst reads every shift, the artifacts you ship at the end of this project become the input dataset for the analyst work in Module 3. Build them as if a junior analyst will read them next week, because one will.

## Context

***Week nine at MedDefense Health Systems. Tuesday morning.***

Mike Torres, the network engineer, drops a printed arp -a dump and a manual traceroute on your desk.

"I ran a few probes between billing-srv-01, web-srv-01 and log-srv-01. Everything talks to everything on every port. The clinical workstations talk to the medical device VLAN. The guest Wi-Fi can reach the billing database. There is a lab PC in radiology still running Telnet. I hardened nothing because my job is network plumbing, not endpoint configuration, but this is the part nobody can fix with Sysmon."

He sketches a diagram on a legal pad.

<pre>
  [ guest wifi ]  ─┐
                   │
  [ clinical ws ]  ┼── flat L2 ──┬── [ server zone ]
                   │             │
  [ mgmt ws ]  ────┘             └── [ medical device zone ]
</pre>

"Every line is an allowed path. Not because we chose to allow it. Because we never chose to block it. That is the problem."

James Chen adds the operational constraint.

"We do not run a live IDS. We do not run a central manager. We do not run Splunk. What we do run is nftables on every Linux host, Windows Firewall on every Windows host and a Suricata binary that we point at captured PCAPs offline when we need to investigate something. So everything you build this week has to fit that footprint. No daemons that expect a collector. No rules that expect a manager. Local enforcement, local evidence, local validation."

Sarah Park adds one more thing.

"And whatever evidence you produce at the end, package it so the Module 3 analysts can read it without calling you. They get the same JSON, same directory layout, same field names every week. If you can make it boring, you have done it right."

---

# [0. The Network Baseline](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/0-network_baseline.sh)

## Goal: 

Discover the current network topology from the hardened endpoint's perspective and capture it as a structured baseline that later tasks can compare against.

## Context: 

Mike Torres said the network is flat, but the first thing you need is not his opinion. It is the data. Before you write a single firewall rule, the host must answer five questions for itself: which interfaces are up, where do packets go, which neighbors can I see, which sockets am I listening on and which connections are currently established. This baseline is the evidence that justifies every rule you write afterwards.

## Instructions: 

Write a script 0-network_baseline.sh that runs on the hardened endpoint and captures the local network view. The script must:

    Enumerate active network interfaces with ip -j addr show and retain name, MAC, link state and all assigned addresses

    Capture the routing table with ip -j route show including the default gateway

    Capture the ARP neighbors table with ip -j neigh show and retain IP, MAC and state

    Enumerate listening TCP and UDP sockets with ss -tulnpH and resolve each socket to its owning process and PID

    Enumerate established outbound connections with ss -tnpH state established and resolve each to its owning process

    Capture the DNS resolver configuration from /etc/resolv.conf and resolvectl status --no-pager if systemd-resolved is active

    Emit network_baseline.json with top-level keys: timestamp, hostname, interfaces, routes, neighbors, listening_sockets, established_connections, dns_resolvers

Hint: ss supports JSON output with -j on recent versions. Fall back to field parsing if the feature is missing and keep the schema stable.

**Expected Output:**

```bash
$ sudo ./0-network_baseline.sh

$ cat network_baseline.json
{
  "hostname": "billing-srv-01",
  "up_interfaces": ["lo", "eth0", "eth1"],
  "listeners": 15
}
```

---

# [1. The Attack Surface Map](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/1-attack_surface.sh)

## Goal: 

Enumerate every network-reachable service on the endpoint, map each one to its function and criticality and flag the ones that should not be exposed at all.

## Context: 

The baseline tells you which ports are open. It does not tell you which ones should be open. A listener on tcp/3306 is normal on a database server and hostile on a workstation. The attack surface map answers the "should it be here" question, package by package, socket by socket. It is the input to the segmentation design in T2.

## Instructions: 

Write a script 1-attack_surface.sh that classifies every listening socket captured in network_baseline.json and produces a machine-readable attack surface report. The script must:

    Read network_baseline.json from T0 as its primary input

    For each listening socket, resolve the owning binary, the owning package via dpkg -S and the configured service unit via systemctl show when the owner is a systemd service

    Tag each socket with a function label drawn from a provided service_catalog.json (values include database, web, ssh, dns, ntp, rpc, smb, print, telemetry, unknown)

    Tag each socket with a criticality label from a provided service_criticality.json (values: critical, high, medium, low)

    Flag every socket that matches at least one "should not be exposed" rule: bound to 0.0.0.0 on a service tagged database or rpc, or on any socket whose function is telnet, ftp, snmpv1, snmpv2c, rlogin, or nfs v2/v3

    Emit attack_surface.json with generated_at, hostname, sockets (array with proto, port, bind_addr, process, package, function, criticality, exposure_flags) and a summary block counting flagged sockets by severity

Note: unknown functions are allowed in the output but must be counted separately in the summary so that the analyst can triage them later.

**Expected Output:**

```bash
$ sudo ./1-attack_surface.sh

$ cat attack_surface.json
{
  "port": 3306,
  "process": "mysqld",
  "exposure_flags": ["bound_0.0.0.0", "database_exposed"]
}
{
  "port": 161,
  "process": "snmpd",
  "exposure_flags": ["insecure_protocol_snmpv2c"]
}
```

---

# [2. The Segmentation Design](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/2-segmentation_rules.sh)

## Goal: 

Translate the MedDefense zone model into a structured rule set that the firewall implementation tasks will consume as their source of truth.

## Context: 

The MedDefense topology has four zones that every downstream task needs to agree on: DMZ for public-facing services, INTERNAL for clinical applications and databases, MGMT for administration, MEDDEV for the medical device VLAN. Each zone has an IP range, a purpose and a small list of flows that must be allowed across its boundary. This task does not implement anything. It produces the data file that every other block reads.

## Instructions: 

Write a script 2-segmentation_rules.sh that emits the structured rule set. The script must:

    Define four zones with name, cidr, purpose, default_inbound (drop) and default_outbound (accept with specific restrictions)

    Define each cross-zone allow flow with src_zone, dst_zone, proto, dport, justification and exception_for (optional tag used by the change log if a flow was granted as a temporary exception)

    Include the following minimum flows at a minimum:

        MGMT to INTERNAL on tcp/22 for administration

        MGMT to DMZ on tcp/22 for administration

        INTERNAL clinical workstations to INTERNAL server hosts on tcp/443 and tcp/3306

        DMZ to INTERNAL databases on tcp/3306 only from named DMZ application hosts

        MEDDEV to INTERNAL hosts on tcp/4242 (DICOM) and tcp/443 (EHR web) only

        ALL to MGMT resolver on udp/53 and tcp/53

        No flows from MEDDEV to DMZ or the public Internet

        No flows from any zone into MEDDEV except MGMT on tcp/22 and tcp/4242

    Define an explicit deny_all at the end of each zone pair that has no allow flows

    Emit segmentation_rules.json with zones (array), flows (array) and summary (flow count, allow count, deny count, cross-zone pairs)

Hint: this is the contract. Both the nftables task and the Windows Firewall task must be able to consume this file and produce matching rules.

**Expected Output:**

```bash
$ ./2-segmentation_rules.sh

$ cat segmentation_rules.json
{
  "dst_zone": "INTERNAL",
  "proto": "tcp",
  "dport": 4242,
  "justification": "DICOM imaging to PACS"
}
{
  "dst_zone": "INTERNAL",
  "proto": "tcp",
  "dport": 443,
  "justification": "EHR web integration for device display"
}
```

---

# [3. The Protocol Exposure Evidence Map](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/3-protocol_audit.sh)
### advanced

## Goal: 

Probe every high-risk listener identified by the attack surface map and produce a structured evidence record showing which protocols are safe, insecure, accepted exceptions or remediation candidates.

## Context: 

The attack surface map tells you which ports are open. It does not prove what is happening on those ports. A listener on tcp/21 might be plain FTP leaking credentials or an FTPS service with TLS. A listener on tcp/389 might reject anonymous simple bind or accept cleartext LDAP. A listener on tcp/80 might be harmless public HTTP or a forgotten administrative panel.

## Instructions: 

Write a script 3-protocol_audit.sh.

The script must read network_baseline.json and attack_surface.json, then probe only local or project-defined targets. It must not modify system state.

The script must audit candidate ports:

    21 FTP
    23 Telnet
    25 SMTP banner
    80 HTTP administrative surfaces
    110 POP3
    143 IMAP
    161 SNMP
    389 LDAP
    512, 513, 514 r-services
    636 LDAPS certificate/signature check
    3389 RDP encryption level

For each candidate protocol, run a non-destructive probe:

1. FTP, Telnet, POP3, IMAP, SMTP and r-services:

    connect with nc -w 3
    capture only a short banner or connection result
    classify cleartext service exposure

2. SNMP:

    run snmpget -v1 -c public and snmpget -v2c -c public
    use a short timeout
    mark community as guessable if either returns data

3. LDAP:

    run ldapsearch -x -H ldap://... against RootDSE
    mark insecure if simple bind succeeds without STARTTLS

4. LDAPS:

    verify TLS certificate availability using openssl s_client
    record failure if the TLS handshake fails

5. HTTP administrative surface:

    read /home/analyst/MedDefense_Lab/protocols/admin_surfaces.json
    request only configured admin URLs
    mark insecure if the admin surface returns 200 over cleartext HTTP

6. RDP:

    check whether the port is reachable
    record that encryption posture requires Windows-side validation if not locally testable

Each finding must include:

    protocol
    port
    target
    status (secure, insecure, accepted_exception, not_present, not_testable)
    severity
    evidence
    secure_alternative
    remediation_command
    exception_accepted
    source_task

Emit protocol_audit.json with:

    generated_at
    hostname
    findings
    summary
    high_unaccepted_count

**Expected Output:**

```bash
$ sudo ./3-protocol_audit.sh
[*] Loading network_baseline.json and attack_surface.json...
[*] Candidate listeners: 4
[HIGH] telnet on tcp/23: cleartext banner observed
[HIGH] snmpv2c on udp/161: public community returned sysDescr
[MEDIUM] http-admin on tcp/80: /admin returned 200 without TLS
[INFO] ldaps on tcp/636: TLS handshake OK

Findings: 4
High unaccepted: 2
Report saved to: protocol_audit.json
```

---

# [4. The nftables Ruleset](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/4-nftables_config.sh)

## Goal: 

Compile the segmentation rules into a working nftables configuration, apply it safely and emit evidence of the transition.

## Context: 

T2 defined the rules. This task enforces them. nftables is the modern Linux filtering engine and the default on Ubuntu 22.04. It is also less forgiving than the old iptables front end: a wrong atomic ruleset update can lock you out of your own SSH session in one second. The script must produce a ruleset, load it as an atomic transaction and leave a rollback path behind.

## Instructions: 

Write a script 4-nftables_config.sh that renders segmentation_rules.json into a runnable nftables configuration and applies it. The script must:

    Render a nftables.conf file containing:

        table inet meddefense with chains input, forward and output

        input chain with policy drop, connection tracking accept (ct state established,related accept), loopback accept, ICMP minimal accept and explicit allow rules for each flow that terminates on the local host

        forward chain with policy drop and cross-zone allow rules rendered from the flow matrix

        output chain with policy accept and explicit drops for the zones that must not receive outbound traffic from this host

        A named set per zone containing its CIDR (so that rule expressions reference sets rather than literal prefixes)

        A log prefix on the drop terminal rule so that denied packets appear in /var/log/ufw.log or /var/log/syslog depending on logger configuration

    Save a rollback of the current ruleset before applying: nft list ruleset > /var/backups/nftables-rollback-<timestamp>.nft

    Apply the new ruleset atomically: nft -f nftables.conf

    Verify the load with nft list ruleset and count the rules that match the expected total

Hint: test the render step before the apply step. nft -c -f nftables.conf performs a check-only parse.

---

# [5. The Firewall Validation Suite](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/5-firewall_test.sh)
### advanced

## Goal: 

Prove that every rule in the new nftables configuration behaves as designed by attempting the allowed and forbidden flows and recording the outcome.

## Context: 

An unverified firewall rule is an assumption. A verified firewall rule is a control. This task builds the evidence that converts the first into the second. It attempts every flow from segmentation_rules.json (both the allowed ones and representative denied ones) and records whether the result matches intent.

## Instructions: 

Write a script 5-firewall_test.sh that executes connection tests against the loaded ruleset. The script must:

    Read segmentation_rules.json as the source of truth

    For each allow flow with dst_zone equal to the local host's own zone, issue a test connection from a provided test source (either a loopback-mapped alias or a controlled external probe registered in /home/analyst/MedDefense_Lab/probes.json). Use nc -z -w 3 for TCP checks and nc -uzv -w 3 for UDP checks. Record expected=allow, observed=pass if the connection succeeds

    For each denied flow in the test probe matrix (hosts that MUST be refused), issue the same test and expect failure. Record expected=deny, observed=pass if the connection is refused

    For each protocol probe (ICMP reachability, loopback reachability), verify that the rules did not accidentally break baseline connectivity

    For every test, compute a boolean result=pass|fail by comparing expected and observed

    If any test fails, exit with code 1 and print the failing tests. Otherwise exit with code 0.

Note: the probes file is shipped with the project. Students do not invent the test topology.

---

# [6. The Windows Firewall Alignment](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/6-windows_firewall.ps1)

## Goal: 

Translate the same segmentation_rules.json into a Windows Firewall ruleset on a domain-joined host and emit the rules as structured JSON for downstream comparison.

## Context: 

MedDefense runs both Linux and Windows on the same zone model. The nftables and Windows Firewall rulesets must match. This task consumes the same contract (segmentation_rules.json) and produces an equivalent Windows Firewall configuration via PowerShell, then exports the resulting rules as JSON so that downstream automation can diff the two platforms.

## Instructions: 

Write a PowerShell script 6-windows_firewall.ps1 that aligns Windows Firewall to the segmentation design. The script must:

    Read segmentation_rules.json from the project directory

    For each profile (Domain, Private, Public) set DefaultInboundAction = Block and DefaultOutboundAction = Allow via Set-NetFirewallProfile

    For each inbound flow in the rule file that terminates on this host, create a New-NetFirewallRule with:

        DisplayName of the form MedDefense-<src_zone>-<proto>-<dport>

        Direction Inbound

        Action Allow

        Protocol and LocalPort from the flow

        RemoteAddress from the cidr of the source zone

        Profile Any

    Remove any pre-existing rule whose DisplayName starts with MedDefense- before re-creating the ruleset so that the script is idempotent

    Enable dropped connection logging via Set-NetFirewallProfile -LogBlocked True -LogFileName "%systemroot%\system32\LogFiles\Firewall\meddefense.log"

**Expected Output:**

```bash
PS> .\6-windows_firewall.ps1
[*] Reading segmentation_rules.json...
[*] Setting profile defaults...
  Domain:  DefaultInboundAction=Block  LogBlocked=True   [SET]
  Private: DefaultInboundAction=Block  LogBlocked=True   [SET]
  Public:  DefaultInboundAction=Block  LogBlocked=True   [SET]
[*] Clearing previous MedDefense-* rules...              [6 removed]
[*] Creating rules from flow matrix...
  MedDefense-MGMT-TCP-22       Inbound Allow tcp 22    [CREATED]
  MedDefense-INTERNAL-TCP-443  Inbound Allow tcp 443   [CREATED]
  MedDefense-INTERNAL-TCP-3306 Inbound Allow tcp 3306  [CREATED]
  MedDefense-DMZ-TCP-3306      Inbound Allow tcp 3306  [CREATED]
  MedDefense-MEDDEV-TCP-4242   Inbound Allow tcp 4242  [CREATED]
  MedDefense-MEDDEV-TCP-443    Inbound Allow tcp 443   [CREATED]
```

---

# [7. The Firewall Log Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/7-firewall_log_analysis.sh)
### advanced

## Goal: 

Parse a captured firewall log and extract the patterns that matter for an analyst: top denied sources, denied port clusters, scan signatures and anomalous outbound connections.

## Context: 

The firewall is the first sensor that sees an attacker touching the perimeter. Its logs, read carelessly, look like a wall of identical lines. Read carefully, they contain the shape of the adversary. This task builds the parser that produces the shape.

## Instructions: 

Write a script 7-firewall_log_analysis.sh that consumes a provided firewall log sample and emits structured findings. The script must:

    Read /home/analyst/MedDefense_Lab/firewall_samples/ufw.log (or any file passed as argument) containing nftables/ufw-style LOG entries

    Parse each line into fields: timestamp, iface_in, iface_out, src_ip, dst_ip, proto, spt, dpt, action

    Compute the following aggregates:

        Top 10 denied source IPs by count

        Top 10 denied destination ports by count

        Hosts that touched 20 or more distinct destination ports within any 60-second window (scan signature)

        Hosts that generated denied outbound connections to public-IP destinations (potential beacon attempts from inside the zone)

        Time distribution histogram bucketed by hour

    For each scan candidate, record src_ip, window_start, window_end, ports_touched, dst_count

    Emit firewall_analysis.json with source_file, line_count, parsed_count, top_denied_sources, top_denied_ports, scan_candidates, outbound_anomalies and hourly_histogram

    Print a short summary to stdout (counts only) so that the analyst does not need to open the JSON to triage the run

Hint: the scan detection is a sliding window over sorted events. Do not rebuild a SQL engine; a small awk or Python helper is enough.

**Expected Output:**

```bash
$ ./7-firewall_log_analysis.sh /home/analyst/MedDefense_Lab/firewall_samples/ufw.log

$ cat firewall_analysis.json
{
  "src_ip": "10.10.5.14",
  "window_start": "2026-04-08T03:42:11Z",
  "window_end": "2026-04-08T03:42:49Z",
  "ports_touched": 87,
  "dst_count": 4
}
```

---

# [8. The Suricata Offline Setup](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/8-suricata_setup.sh)

## Goal: 

Install Suricata, configure it for offline PCAP replay and load the provided ruleset so that T9 through T11 have a working engine to analyze captures with.

## Context: 

Suricata is usually taught as a live IDS on an interface. In this project it is used exclusively in replay mode: the binary is pointed at a PCAP file with -r, the alerts land in eve.json on disk and the analyst reads them offline. That mode has three advantages: it does not depend on network hardware, it is deterministic (the same PCAP always produces the same alerts) and it mirrors the way a Tier 2 analyst actually uses the tool during an investigation.

## Instructions: 

Write a script 8-suricata_setup.sh that prepares Suricata for offline replay on the hardened endpoint. The script must:

    Install suricata and jq from the distribution repository if not already present (idempotent)

    Copy the provided ruleset from /home/analyst/MedDefense_Lab/suricata/rules/ into /var/lib/suricata/rules/ and verify the file count

    Render a minimal suricata.yaml in the project directory with the following overrides:

        default-rule-path: /var/lib/suricata/rules

        rule-files listing each provided file and a placeholder for meddefense.rules

        default-log-dir: /var/log/suricata

        outputs: enable eve-log with type json, filename eve.json and at least alert, http, dns, tls, fileinfo

        pcap-file: enabled (replay mode)

        HOME_NET: "[10.10.0.0/16]" and EXTERNAL_NET: "!$HOME_NET"

    Run suricata -T -c ./suricata.yaml -v and capture the test-config exit code

    Run one quick end-to-end check: suricata -c ./suricata.yaml -r /home/analyst/MedDefense_Lab/PCAPs/smoke.pcap -l /tmp/suricata-smoke/ and verify that eve.json contains at least one alert record

    Emit setup_verification.json with installed_version, rule_files_loaded, rule_count, config_test_exit, smoke_pcap, smoke_alerts

Hint: do not start the suricata.service systemd unit. This project does not run the daemon.

**Expected Output:**

```bash
$ sudo ./8-suricata_setup.sh


$ cat setup_verification.json
{
  "installed_version": "6.0.14",
  "rule_count": 34219,
  "config_test_exit": 0,
  "smoke_alerts": 4
}
```

---

# [9. The Suricata Replay Analysis](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/9-suricata_analysis.sh)

## Goal: 

Run Suricata against a provided PCAP containing mixed benign and malicious traffic, parse every alert from eve.json and classify the output by severity and kind.

## Context: 

The provided PCAP is /home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap. It contains a mix of normal MedDefense traffic, reconnaissance probes, a SMB lateral movement attempt and a DNS tunneling session. The engine will fire dozens of alerts. Your job is not to read them one by one. It is to build the parser that groups them, ranks them and surfaces the ones a Tier 1 analyst must escalate.

## Instructions: 

Write a script 9-suricata_analysis.sh that replays a PCAP through Suricata and classifies the resulting alerts. The script must:

    Accept a PCAP path as argument (default /home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap)

    Run suricata -c ./suricata.yaml -r <pcap> -l <tmpdir> and wait for completion

    Parse <tmpdir>/eve.json with jq or a streaming reader and retain only event_type=="alert" records

    For each alert, extract: timestamp, src_ip, src_port, dst_ip, dst_port, proto, alert.signature, alert.signature_id, alert.category, alert.severity

    Compute: total alerts, unique signatures, alert count per signature, alert count per source IP, alert count per destination IP and severity distribution

    Classify each signature into one of: reconnaissance, exploit, lateral_movement, exfiltration, malware_c2, policy_violation, other using a provided signature_categories.json map shipped with the project

    Emit suricata_alerts.json with pcap, started_at, finished_at, total_alerts, unique_signatures, severity_distribution, by_category, top_sources, top_destinations, alerts (full array)

Note: do not write custom detection logic. The ruleset is authoritative; this task is a reader.

**Expected Output:**

```bash
$ sudo ./9-suricata_analysis.sh

$ cat suricata_alerts.json
{"sig":"ET EXPLOIT PsExec Service Install","src":"10.10.1.99","dst":"10.10.1.10"}
{"sig":"ET TROJAN Cobalt Strike Beacon","src":"10.10.1.10","dst":"185.220.101.42"}
{"sig":"ET DNS Exfiltration Long TXT Query","src":"10.10.1.10","dst":"8.8.8.8"}
```

---

# [10. The Custom MedDefense Rules](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/10-rule_validation.sh)

## Goal: 

Write Suricata rules that detect MedDefense-specific threats not covered by the community ruleset and validate that each rule fires against its target capture.

## Context: 

Community rules detect common attack patterns on common infrastructure. They do not know that MedDefense has a medical device VLAN that must never talk to the Internet, that the PACS server on tcp/4242 is a legitimate DICOM endpoint and that a SMB session from a clinical workstation to the server VLAN is expected while the same session from the guest network is an incident. Those constraints belong in custom rules.

## Instructions: 

Write a rule file meddefense.rules containing at least six custom rules and a validation script 10-rule_validation.sh that proves each rule fires against a labeled PCAP. The rules must cover:

    Med device to Internet: any TCP or UDP traffic originating from 10.10.4.0/24 to an address outside $HOME_NET on any port other than udp/123 (NTP)

    Unauthorized SMB from guest: tcp/445 traffic where the source is 10.10.5.0/24 (guest) and the destination is $HOME_NET

    Large outbound from server: a threshold-based rule that fires when a host in 10.10.1.0/24 pushes more than 50 MB of TCP payload to a single external host inside a 300-second window

    DNS tunneling: a dns.query content rule that fires on any DNS query where the leftmost label exceeds 50 characters

    Clinical workstation to database: tcp/3306 traffic from 10.10.2.0/24 that is not destined to the authorized billing database host (use a negated address expression)

    Telnet cleartext to medical device: tcp/23 traffic to 10.10.4.0/24 from any source

Each rule must use a sid in the 9000000 range, a rev:1 and a classtype drawn from the Suricata classification config. The validation script must:

    For each labeled PCAP in /home/analyst/MedDefense_Lab/PCAPs/labels/, run Suricata with meddefense.rules loaded and confirm that the expected rule sid appears in eve.json

    Exit non-zero if any rule failed to fire against its target PCAP

Hint: test each rule against its own PCAP first. A rule that never fires is worse than no rule at all.

**Expected Output:**

```bash
$ sudo ./10-rule_validation.sh
[*] Loading meddefense.rules...          6 rules
[*] Running validation against labeled PCAPs...

sid 9000001 MEDDEV to Internet
  target: meddev_egress.pcap
  expected: fire
  observed: fire (4 hits)                PASS

sid 9000002 Guest to SMB
  target: guest_smb.pcap
  expected: fire
  observed: fire (2 hits)                PASS

sid 9000003 Large Outbound From Server
  target: large_outbound.pcap
  expected: fire
  observed: fire (1 hit)                 PASS

sid 9000004 DNS Tunneling Long Label
  target: dns_tunnel.pcap
  expected: fire
  observed: fire (17 hits)               PASS

sid 9000005 Clinical to Unauthorized DB
  target: clinical_wrong_db.pcap
  expected: fire
  observed: fire (3 hits)                PASS

sid 9000006 Telnet to MEDDEV
  target: telnet_meddev.pcap
  expected: fire
  observed: fire (2 hits)                PASS

Rules:  6
Passed: 6
Failed: 0
```

---

# [11. The PCAP Investigation](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/11-pcap_investigation.sh)

## Goal: 

Investigate a suspicious session in a provided PCAP and extract the conversation timeline, protocol breakdown, DNS queries and file transfer indicators as a single structured finding report.

## Context: 

One of the Suricata alerts in T9 pointed at a session between 10.10.1.10 and 185.220.101.42. Alerts are pointers. They do not replace investigation. In this task you do what a Tier 2 analyst does next: open the packet capture, extract the exact conversation, walk the protocol stack and characterize the activity. No alert, no signature, no ruleset. Just bytes.

## Instructions: 

Write a script 11-pcap_investigation.sh that takes a PCAP path and produces a structured investigation report. The script must:

    Accept a PCAP path as argument (default /home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap)

    Use tshark to extract, in order:

        Conversation statistics for tcp and udp via tshark -q -z conv,tcp and tshark -q -z conv,udp and parse the top 10 conversations

        DNS queries via tshark -Y dns.flags.response==0 -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type

        HTTP requests via tshark -Y http.request -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri

        TLS SNI via tshark -Y tls.handshake.type==1 -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name

        File transfers via tshark -Y "http.content_type or smb2.filename" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.file_data -e smb2.filename

        Protocol distribution via tshark -q -z io,phs

    Print a short stdout summary listing the top 5 conversations and any DNS query longer than 50 characters on the leftmost label

Note: keep the script resilient. If a given tshark query returns zero rows, the field must still appear in the JSON as an empty array.

**Expected Output:**

```bash
$ sudo ./11-pcap_investigation.sh
[*] PCAP: /home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap
[*] Duration: 482.14 s     Packets: 18,402
[*] Extracting TCP conversations...      (14)
[*] Extracting UDP conversations...      (7)
[*] Extracting DNS queries...            (214)
[*] Extracting HTTP requests...          (12)
[*] Extracting TLS SNI...                (8)
[*] Extracting file transfers...         (4)
[*] Protocol distribution...             (tcp 78%, udp 20%, icmp 1%, other 1%)
Top conversations:
  10.10.1.10 <-> 185.220.101.42  tcp  1,218 pkts  1.4 MB
  10.10.1.10 <-> 10.10.1.50      tcp    614 pkts  218 KB
  10.10.1.10 <-> 8.8.8.8         udp    214 pkts   42 KB
Long DNS labels (> 50 chars):
  ZG9jdW1lbnQuZXhlLm1kZC5jcmltc29uLXRpZGUtb3BzLnh5eg.c2.example.  (58 chars)
```

---

# [13. The DNS Filtering Layer](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/13-dns_filtering.sh)

## Goal: 

Configure local DNS filtering so that known malicious domains return a sinkhole answer while legitimate traffic is unaffected, and validate both paths.

## Context: 

DNS is the quietest attack surface on the network. It is almost never blocked and almost never inspected. The Suricata alerts in T9 showed a long DNS TXT query that pointed at a probable tunneling session. A local DNS filter cuts the channel off at the source. This task configures the filter and produces the evidence that it works.

## Instructions: 

Write a script 13-dns_filtering.sh that configures a local DNS filter and validates the configuration. The script must:

    Install dnsmasq from the distribution repository if not present (idempotent)

    Read a provided blocklist from /home/analyst/MedDefense_Lab/dns/blocklist.txt containing one domain per line

    Render a dnsmasq configuration that:

        Forwards every query to a configured upstream (defined in /etc/dnsmasq.d/meddefense-upstream.conf, shipped with the project)

        Returns 0.0.0.0 for every domain on the blocklist via a generated /etc/dnsmasq.d/meddefense-blocklist.conf

        Logs every query with log-queries to /var/log/dnsmasq.log

    Restart dnsmasq and verify via systemctl is-active that the service is running

    Run the following validation queries using dig @127.0.0.1:

        A known-allowed domain from a provided allowlist.txt, expect a non-sinkhole answer

        A known-blocked domain from blocklist.txt, expect 0.0.0.0

        A domain that does not appear in either list, expect normal resolution via the upstream

Note: do not rewrite /etc/resolv.conf. This task configures dnsmasq on the loopback and leaves the decision to route through it to the deployment step, which is outside the scope of this project.

**Expected Output:**

```bash
$ sudo ./13-dns_filtering.sh
[*] Ensuring dnsmasq is installed...     dnsmasq 2.86
[*] Rendering blocklist...               (814 domains)
[*] Restarting dnsmasq.service...        active
[*] Validation queries...
  dig @127.0.0.1 billing.meddefense.local
      -> 10.10.1.10            expected allow      PASS
  dig @127.0.0.1 c2.crimson-tide-ops.xyz
      -> 0.0.0.0               expected sinkhole   PASS
  dig @127.0.0.1 ubuntu.com
      -> 185.125.190.39        expected allow      PASS
```

---

