# Introduction

>"The network never lies. People lie. Logs can be tampered with. But the packets on the wire are physics, not policy." 
>
> — Richard Bejtlich, The Tao of Network Security Monitoring

Your phishing investigation uncovered a coordinated campaign targeting MedDefense. You identified the domains. You extracted the IOCs. You confirmed that a nurse clicked a link and likely submitted her credentials. You documented suspicious infrastructure and produced an evidence-based phishing investigation.

But the email investigation ended with an unanswered question:

What happened after the click?

The phishing email explained how the attacker obtained access. It did not explain how the attacker moved through the environment, how they communicated with their infrastructure, whether data was stolen or whether the credentials were actually used.

Now there is new evidence.

The MedDefense network team exported packet captures from multiple network segments during the 48-hour window surrounding the phishing incident. These captures contain every DNS request, every TLS handshake, every RDP connection and every suspicious outbound communication observed during the incident timeline. Unlike endpoint logs or SIEM dashboards, packet captures contain raw evidence. A SIEM may miss a rule. An endpoint may stop logging. But if the traffic crossed the wire, the packets exist.

This project teaches you to investigate incidents directly from PCAP evidence. You will establish a traffic baseline, analyze the exact phishing click, identify command-and-control beaconing, detect DNS tunneling, trace lateral movement and reconstruct the complete attack chain from packet evidence alone. This project is intentionally self-contained. You are not expected to deploy Wazuh, Suricata, Sysmon or any infrastructure from previous modules. You are not expected to reuse Module 2 firewall labs or Module 3 SIEM environments.

Everything required for the investigation is provided through PCAP files. Your task is to read the network like a forensic analyst.

## Why This Matters

Network forensics occupies a unique position in incident response.

    Endpoint logs can be deleted

    Applications can stop logging

    SIEM rules can miss novel techniques

    Alerts can be misconfigured

    EDR visibility can fail

But attackers cannot move across a network without generating traffic.

A phishing page requires DNS resolution and TLS negotiation. A beacon requires repeated outbound connections. A lateral movement attempt requires authentication traffic. A data exfiltration channel requires bytes leaving the environment.

Packet captures preserve these actions.

Modern SOC analysts must be able to:

    identify malicious behavior from traffic patterns

    distinguish automated beaconing from human browsing

    recognize DNS tunneling and encoded query structures

    analyze TLS traffic without decryption

    reconstruct timelines directly from packet evidence

    extract network indicators of compromise

    explain attacker behavior using timestamps and protocol evidence

## Context

Week eleven at MedDefense Health Systems. Thursday morning.

James Chen calls an emergency meeting with the incident response team.

The phishing investigation from 4x00 confirmed that a nurse workstation contacted a credential-harvesting domain shortly after receiving a suspicious email. The email campaign appeared targeted and coordinated, but the investigation could not prove whether the credentials were successfully used.

The network engineering team now provides additional evidence.

They installed temporary packet capture points on the clinical VLAN and exported historical captures from perimeter monitoring systems. They also recovered several packet segments associated with unusual outbound activity reported overnight.

James spreads six PCAP files across the shared investigation drive.

"The first capture contains the exact phishing click. The second is a normal baseline from earlier that day. The remaining captures cover traffic after the compromise window."

He pauses.

"Last night I found something disturbing. One workstation started making HTTPS connections every five minutes to the same external IP. Each connection lasted about two seconds and transferred almost no data. No signatures fired. No alerts triggered. Individually, every session looked legitimate."

Sarah Park studies the timestamps.

"That sounds like command-and-control beaconing."

James nods.

"Exactly. But signature-based detection missed it because nothing inside the packets matched known malware. The malicious behavior only becomes visible when you analyze timing and connection patterns over time."

He opens another capture.

"There is more. billing-srv-01 generated hundreds of unusual DNS TXT queries overnight. Long encoded-looking subdomains. Repeated intervals. A domain we have never seen before."

The room goes silent.

"I need a full reconstruction. Determine what happened after the phishing click. Identify how the attacker moved through the network. Confirm whether credentials were used. Determine whether data left the environment. Build the timeline entirely from packet evidence."
Investigation Scope

This project investigates a simulated phishing-driven compromise at MedDefense using packet captures only.

The provided PCAPs contain:

    normal clinical traffic

    phishing-click activity

    post-click beaconing

    DNS tunneling behavior

    cross-subnet lateral movement

    VPN access activity

    full attack timeline reconstruction evidence

The investigation focuses on:

    DNS analysis

    TLS metadata analysis

    connection timing analysis

    behavioral traffic analysis

    authentication-related traffic

    beacon detection

    DNS tunneling detection

    lateral movement reconstruction

    IOC extraction

    attack timeline reconstruction

All required evidence is already contained in the PCAP files.

## Provided Materials

Download the PCAP files before starting the investigation.

PCAP Files

1. Clinical Baseline Traffic

    File: [normal_baseline_clinical.pcap](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/normal_baseline_clinical.pcap)

    Purpose:

    Establish normal traffic behavior

    Identify standard DNS and TLS activity

    Build baseline connection patterns

    Compare later suspicious traffic against known-good traffic

2. Phishing Click Capture

    File: [phishing_click.pcap](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/phishing_click.pcap)

    Purpose:

    Analyze the exact phishing-click event

    Extract DNS queries and TLS metadata

    Investigate credential-submission evidence

    Correlate network evidence with 4x00 phishing findings

3. Beaconing Capture

    File: [c2_beaconing.pcap](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/c2_beaconing.pcap)

    Purpose:

    Detect command-and-control beaconing

    Analyze timing regularity

    Compare machine-generated traffic against human browsing behavior

4. DNS Exfiltration Capture

    File: [dns_exfil.pcap](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/dns_exfil.pcap)

    Purpose:

    Detect DNS tunneling behavior

    Analyze TXT query abuse

    Identify encoded DNS subdomains

    Estimate exfiltration volume

5. Lateral Movement Capture

    File: [lateral_movement.pcap](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/lateral_movement.pcap)

    Purpose:

    Trace cross-subnet movement

    Identify RDP and SMB activity

    Reconstruct attacker movement path

    Analyze failed and successful access attempts

6. Full Timeline Capture

    File: [full_timeline.pcap](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/full_timeline.pcap)

    Purpose:

    Correlate all phases together

    Identify external access behavior

    Connect phishing activity to later network actions

    Reconstruct the complete attack timeline

---

# [0. The Baseline](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/0-baseline_analysis.sh)

## Goal: 

Establish what normal MedDefense clinical network traffic looks like, creating the reference point against which all anomalies will be measured.

## Context: 

Before you can identify what is wrong, you must understand what is normal. The baseline PCAP contains 30 minutes of clinical VLAN traffic from the morning of April 14, before the phishing click occurred. Every application, every protocol, every traffic pattern in this capture is legitimate. Your job is to document it so thoroughly that anything deviating from this baseline in the other PCAPs immediately stands out.

This is how experienced network analysts work. They do not memorize every attack signature. They learn what normal looks like so deeply that anomalies become obvious.

## Instructions: 

Write a script 0-baseline_analysis.sh that processes normal_baseline_clinical.pcap and produces a comprehensive traffic profile:

    Protocol distribution: percentage of traffic by protocol (TCP, UDP, ICMP, other)

    Application layer breakdown: HTTP/HTTPS, DNS, Kerberos, LDAP, SMB, NTP, printing (port 9100), endpoint telemetry/agent traffic if present, and other observed services

    Top 10 talkers: source IPs ranked by total bytes

    Top 10 destinations: destination IPs ranked by total connections

    DNS query profile: top 20 queried domains, average queries per minute, query types (A, AAAA, TXT, MX)

    Connection duration distribution: short (<1s), medium (1-30s), long (>30s)

    TLS analysis: SNI values observed, TLS versions in use, certificate issuers where available

    Temporal pattern: traffic volume over time (per-minute bins) showing the natural rhythm of clinical operations

    Baseline signatures that can be used later for comparison:

    normal DNS rate
    normal TXT query rate
    normal external connection rhythm
    normal packet volume range
    known-good internal and external services

Your script must show the tshark commands or filters used so that the analysis is reproducible.

**Expected Output:**

```bash
$ ./0-baseline_analysis.sh normal_baseline_clinical.pcap

=== PROTOCOL DISTRIBUTION ===
TCP:  78.2%  (111,678 packets)
UDP:  19.4%  (27,710 packets)
ICMP:  1.1%  (1,571 packets)
Other: 1.3%  (1,878 packets)

=== APPLICATION BREAKDOWN ===
HTTPS (443):        41.2%
DNS (53):           18.8%
Kerberos (88):       8.4%
LDAP (389):          5.1%
Agent traffic:       4.2%
NTP (123):           2.1%
Printing (9100):     1.8%
SMB (445):           1.2%
Other:              17.2%

=== TOP 10 SOURCE IPS ===
  1. 10.10.2.15  (WS-NURSE-04)     4.2 MB
  2. 10.10.2.22  (WS-NURSE-07)     3.8 MB
  3. 10.10.2.31  (WS-BILLING-01)   3.1 MB
  [...]

=== TOP 10 DESTINATION IPS ===
  1. 52.96.10.45      321 connections
  2. 13.107.42.14     287 connections
  3. 10.10.1.20       221 connections
  [...]

=== DNS QUERY PROFILE ===
Total queries: 520 (17.3/min average)
Top domains:
  1. meddefense.com             112 queries
  2. login.microsoftonline.com   87 queries
  3. outlook.office365.com       64 queries
  4. windows.com                 31 queries
  [...]
Query types: A (82%), AAAA (14%), TXT (2%), MX (2%)
TXT queries: low volume and only to expected legitimate domains

=== CONNECTION DURATION DISTRIBUTION ===
Short (<1s):       64%
Medium (1-30s):    29%
Long (>30s):        7%

=== TLS ANALYSIS ===
Observed SNI values:
  login.microsoftonline.com
  outlook.office365.com
  windows.com
  api.github.com
Observed certificate issuers:
  Microsoft Azure TLS Issuing CA
  DigiCert
  Lets Encrypt

=== TEMPORAL PATTERN ===
06:00-06:05:  Low traffic
06:05-06:15:  Ramp-up
06:15-06:30:  Steady state

=== BASELINE SIGNATURES ===
Normal DNS rate: low-to-moderate and variable
Normal TXT query rate: very low
Normal connection to external IPs: varied intervals, human/application-driven
Normal packet volume: stable during business-hours baseline
No traffic to 91.234.99.107
No traffic to 154.118.42.89
No TXT queries to data-sync.meddefense-portal.com

BASELINE SAVED: baseline_clinical.json
```

---

# [1. The Click in the Wire](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/1-phishing_click.sh)

## Goal: 

Analyze the PCAP that captured the exact moment the nurse clicked the phishing link, correlating the network evidence with the email investigation findings from 4x00.

## Context: 

Your 4x00 investigation identified meddefense-portal[.]com and 91.234.99.107 as phishing infrastructure. Now you have the actual packets from the click window. The PCAP will tell you exactly what happened during the session: DNS resolution, TLS handshake, certificate details and encrypted data exchange metadata. You are not using SIEM alerts in this task. The PCAP is the evidence source. The 4x00 project may be used only as context for known IOCs.

## Instructions: 

Write a script 1-phishing_click.sh that analyzes phishing_click.pcap:

    Extract the DNS query for meddefense-portal[.]com: query timestamp, response IP, TTL

    Extract the TLS ClientHello: SNI value, supported cipher suites, TLS version offered

    Extract the server certificate details: subject, issuer, validity dates, serial number where available

    Calculate the data exchange: total bytes sent by the client, total bytes received, number of TCP segments in each direction

    Identify the exact timestamps: connection start, data transfer start, data transfer end, connection close

    Determine if the outbound data volume is consistent with credential submission. Do not claim password contents were visible unless packet contents actually prove it. Because HTTPS is encrypted, treat the conclusion as metadata-based.

    Check for any DNS query to the real meddefense.com portal immediately after the phishing session

    Explain how this PCAP confirms, updates or strengthens the 4x00 phishing investigation

Your script must show the tshark commands or filters used.

**Expected Output:**

```bash
$ ./1-phishing_click.sh phishing_click.pcap

=== DNS RESOLUTION ===
15:02:33.142  Query: meddefense-portal.com
15:02:33.287  Response: 91.234.99.107
TTL: 300
Source: 10.10.2.15 -> 10.10.1.1

=== TLS HANDSHAKE ===
15:02:33.412  SYN -> 91.234.99.107:443
15:02:33.587  SYN-ACK
15:02:33.589  ClientHello
  SNI: meddefense-portal.com
  TLS version offered: 1.3
  Cipher suites: TLS_AES_256_GCM_SHA384 (and others)

15:02:33.743  ServerHello + Certificate
  Subject: CN=meddefense-portal.com
  Issuer: Lets Encrypt
  Valid from: 2026-04-09
  Valid until: 2026-07-08
  Serial: 04:a3:f7:c9:12:8b:4e:...

=== DATA EXCHANGE ===
Duration: 47.2 seconds (15:02:33.412 to 15:03:20.614)
Client -> Server: 1,203 bytes across 8 TCP segments
Server -> Client: 12,847 bytes across 31 TCP segments
Largest client TLS record: 487 bytes at 15:02:58.721

[*] Analysis:
    The content is encrypted, so the exact form fields are not visible.
    However, a largest client record of ~487 bytes during the session is
    consistent with a small HTTPS form submission such as credentials plus
    token data.

=== POST-CLICK BEHAVIOR ===
15:03:22.108  DNS query: meddefense.com
15:03:22.256  DNS response: 10.10.1.20
15:03:22.389  HTTPS connection to 10.10.1.20:443

[*] Possible interpretation:
    The user queried the real portal shortly after the phishing session.
    This may indicate she noticed something wrong, or the phishing site
    redirected her to the legitimate portal after harvesting data.

=== 4x00 CORRELATION ===
IOC domain match: meddefense-portal.com
IOC IP match: 91.234.99.107
Conclusion: PCAP confirms the workstation contacted the phishing infrastructure.
```

---

# [2. The Beacon Hunter](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/2-beacon_hunter.sh)
### advanced

## Goal: 

Identify and characterize the command-and-control beaconing pattern hidden in the post-click network traffic, demonstrating why automated C2 communication is invisible to signature-based detection but visible through behavioral analysis.

## Context: 

Signature-based detection looks for known patterns: byte sequences, known-bad domains, known protocol abuse or fixed signatures. C2 beaconing may use none of these. Each individual HTTPS connection can look like a normal encrypted request.

The malicious pattern emerges when you analyze timing.

A human browses irregularly. Malware often phones home on a clock.

This is the core lesson of this task: some threats are invisible at the packet-content level and only visible at the session-pattern level.

## Instructions: 

Write a script 2-beacon_hunter.sh that analyzes c2_beaconing.pcap:

1. Extract all outbound connections from 10.10.2.15 (WS-NURSE-04) to external IPs during the capture window

2. For each unique destination IP:

    count the number of connections
    calculate the average interval between connections
    calculate the standard deviation of the interval
    calculate the average session duration
    calculate average bytes transferred

3. Identify connections with statistical regularity:

    interval standard deviation < 10% of the mean indicates automated behavior

4. For the identified beacon:

    extract beacon interval
    session duration
    payload size
    total number of beacons
    start time
    end time

5. Compare the beacon traffic against the Task 0 baseline:

    does this destination exist in the baseline?
    does this timing pattern exist in the baseline?
    does this occur during normal business activity?

6. Explain why this is behavioral evidence rather than signature evidence

Your script must show the tshark commands or filters used.

**Expected Output:**

```bash
$ ./2-beacon_hunter.sh c2_beaconing.pcap

=== OUTBOUND CONNECTIONS FROM 10.10.2.15 ===
Total unique destination IPs: 12
Total outbound connections: 67

Dest IP          | Count | Avg Interval | StdDev  | Regularity
-----------------|-------|--------------|---------|----------
91.234.99.107    | 24    | 300.2 sec    | 4.1 sec | 1.4% [!!!]
13.107.42.14     | 8     | 847.5 sec    | 412 sec | 48.6%
204.79.197.200   | 6     | 1102 sec     | 689 sec | 62.5%

=== C2 BEACON IDENTIFIED ===
Destination: 91.234.99.107
First beacon: 2026-04-15 02:00:12
Last beacon:  2026-04-15 03:55:14
Total beacons: 24
Interval: 300.2 seconds (5 minutes, +/- 4.1 seconds jitter)
Regularity: 1.4% coefficient of variation [HIGHLY AUTOMATED]

Per-beacon statistics:
  Session duration: 2.1 - 2.8 seconds (avg 2.4 sec)
  Client payload: 478 - 523 bytes (avg 501 bytes)
  Server payload: 187 - 214 bytes (avg 198 bytes)

=== BEHAVIORAL COMPARISON ===
                     | Baseline          | C2 Beacon
---------------------|-------------------|------------------
Interval regularity  | High variance     | 1.4% StdDev
Session duration     | 0.5-180 seconds   | 2.1-2.8 seconds
Payload size         | variable          | consistent
DNS pre-query        | common            | absent or cached
Time of activity     | business hours    | 02:00-04:00

=== TOTAL DATA EXCHANGED ===
Outbound (client -> C2): 12,024 bytes
Inbound (C2 -> client):  4,752 bytes
Total: 16,776 bytes (~16 KB)

=== CONCLUSION ===
The repeated HTTPS sessions to 91.234.99.107 show timing regularity
consistent with automated command-and-control beaconing.
```

---

# [3. The DNS Tunnel](https://github.com/sreilly1977/dlh-cyber_security/tree/main/threat_detection/4x01_wire_shark_territory/3-dns_tunnel.sh)

## Goal:

Detect, analyze and decode a DNS tunneling channel used for data exfiltration from billing-srv-01, understanding how attackers use the DNS protocol to bypass network security controls.

## Context: 

DNS is the invisible highway. Almost every network allows it. Many monitoring systems treat DNS queries as background noise. Attackers exploit this trust by encoding data into DNS query labels and receiving commands in DNS response records.

A query to a long encoded subdomain under data-sync.meddefense-portal.com can look like normal name resolution unless you notice the length, frequency, query type and encoding pattern.

You will confirm or deny DNS tunneling using packet-level evidence only.

## Instructions: 

Write a script 3-dns_tunnel.sh that analyzes dns_exfil.pcap:

1. Extract all DNS queries from billing-srv-01 (10.10.1.10)

2. Separate the queries into two categories:

    NORMAL: queries to expected domains such as meddefense.com, Microsoft, Ubuntu or other ordinary services
    ANOMALOUS: queries to unfamiliar domains or queries with unusual length, type, rate or encoded-looking labels

3. For anomalous queries:

    extract the full query name
    identify the base domain
    calculate the subdomain label length
    check if the subdomain appears encoded

4. Calculate anomalous query rate:

    queries per minute
    total count
    total time span

5. Decode a sample of 5 subdomain labels if possible.

    The PCAP may use base32 or base64-style encoding.
    Your script should document which decoding approach was attempted.
    If decoding fails, document the reason instead of inventing decoded data.

6. Analyze DNS responses:

    response type
    TXT response size
    possible command/control content if decodable

7. Calculate approximate exfiltration volume:

    number of queries x average encoded payload length
    estimate raw payload size after encoding overhead

8. Determine exfiltration rate in bytes per minute

9. Compare tunnel DNS behavior against Task 0 baseline DNS behavior

Your script must show the tshark commands or filters used.

**Expected Output:**

```bash
$ ./3-dns_tunnel.sh dns_exfil.pcap

=== DNS QUERY CLASSIFICATION ===
Total DNS queries: 487
Normal queries: 367
Anomalous queries: 120

=== ANOMALOUS QUERY ANALYSIS ===
Base domain: data-sync.meddefense-portal[.]com

Query pattern:
  Type: TXT
  Interval: 10-15 seconds between queries
  Subdomain label length: 44-60 characters (avg 52)
  Encoding: base32/base64-like high-entropy encoded labels

Sample decoded queries:
  Query 1: [encoded-label]
    -> Decoded or attempted decoding result documented
  Query 2: [encoded-label]
    -> Decoded or attempted decoding result documented
  Query 3: [encoded-label]
    -> Decoded or attempted decoding result documented
  Query 4: [encoded-label]
    -> Decoded or attempted decoding result documented
  Query 5: [encoded-label]
    -> Decoded or attempted decoding result documented

=== DNS RESPONSE ANALYSIS ===
Response type: TXT records
Average response size: 60-120 bytes
Content: encoded command or control-style responses

=== EXFILTRATION VOLUME ===
Queries: 120 in 30 minutes (4/min)
Average subdomain payload: 52 encoded bytes per query
Estimated raw data exfiltrated: approximately 4-5 KB

[*] This is low volume, but DNS tunneling often prioritizes
    stealth and structured records over bulk transfer.

=== DETECTION COMPARISON ===
                    | Normal DNS        | Tunnel DNS
--------------------|-------------------|--------------------
Query type          | A, AAAA           | TXT
Subdomain length    | short             | 44-60 chars
Subdomain encoding  | human-readable    | encoded/high entropy
Query rate          | variable          | regular
Destination domain  | known             | campaign-related
Time of activity    | business hours    | night activity

=== CONCLUSION ===
The DNS traffic from billing-srv-01 is consistent with DNS tunneling
and likely data exfiltration through TXT queries.
```

