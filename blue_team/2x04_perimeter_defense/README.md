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

# [2. The Segmentation Design]https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/2x04_perimeter_defense/2-segmentation_rules.sh)

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

# 
