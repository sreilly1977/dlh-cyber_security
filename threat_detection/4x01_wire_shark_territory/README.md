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
