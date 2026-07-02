# Open-Source Security Stack Blueprint

## Firewal/WAF — OPNsense

OPNsense is the standout recommendation here. It's a fork of pfSense, built on FreeBSD, and offers stateful packet inspection, VLANs, WireGuard/IPsec VPNs, traffic shaping, GeoIP filtering, and a built-in Suricata IDS/IPS plugin. It has a modern web UI, truly open-source licensing (unlike pfSense Plus which has some commercial elements), and releases on a quarterly cadence — currently at version 26.1. It's widely favored for home labs, SMBs, and even enterprise edge deployments.

---

## NIDS — Suricata (via Security Onion)

Suricata is the de facto open-source NIDS/IPS engine — high-performance, multi-threaded, with signature-based detection (Emerging Threats ruleset) and protocol analysis. Zeek (formerly Bro) pairs beautifully alongside it for network behavior analytics and metadata logging.

**Deployment approach:** Security Onion bundles both Suricata and Zeek with Elasticsearch, Kibana, and OSSEC/Wazuh integration out of the box. This gives us a turnkey NSM platform with dashboards, alerting, and hunt capabilities. Alternatively, we can deploy Suricata/Zeek standalone and forward logs to your SIEM of choice.

---

## HIDS — Wazuh (via Security Onion)

Wazuh is the clear leader here. As we discussed earlier, its agent-based approach covers Windows, Linux, and macOS with:

- File Integrity Monitoring (FIM)
- Security Configuration Assessment (SCA) against CIS benchmarks
- Vulnerability detection (CVE scanning)
- Rootkit/malware detection (Rootcheck)
- System inventory and asset visibility
- Active response automation (quarantine, script execution, IP blocking)
- MITRE ATT&CK mapping with threat intelligence enrichment

---

## SOAR — The Hive/Cortex (via Security Onion)

TheHive serves as the case management and incident response hub. Security Onion can automatically forward alerts to TheHive, where they're converted into cases with full context — observables, timelines, assigned analysts, task tracking, and custom fields.

Cortex runs alongside TheHive and handles automated enrichment and analysis of observables — IPs, domains, URLs, file hashes, filenames, etc. It does this through "analyzers" (for investigation) and "responders" (for taking action). There's a large library of analyzers covering threat intel feeds, sandboxes, reputation services, and more.

---

## SIEM — Wazuh (via Security Onion)

Wazuh already unifies SIEM + XDR capabilities. Its built-in Elastic Stack backend handles log aggregation, correlation, alerting, and dashboards. We could feed Suricata/Zeek logs from Security Onion into Wazuh's ingestion pipeline and use Wazuh as the central pane.

---

## GRC — Eramba

Eramba is the strongest open-source GRC option, offering policy management, risk assessment, audit management, and compliance modules with role-based access control and automated evidence collection. It supports multi-framework mapping and audit-ready reporting.

**Alternatives:**

- **SimpleRisk** — Lightweight, risk-focused with scoring and mitigation tracking; extensible with add-ons for ISO 27001 and GDPR
- **Baserow GRC** — Low-code, spreadsheet-style database for building custom risk registers and policy libraries
- **OpenGRC** — Community-driven framework mapping controls to NIST CSF, SOC 2, and ISO 27001

---

## How It All Fits Together

```mermaid
flowchart TB
    OPN["OPNsense<br>(Firewall / WAF)"]

    subgraph SO["Security Onion"]
        SUR["Suricata<br>(NIDS)"]
        ZEEK["Zeek<br>(Network Analytics)"]
        WAZ["Wazuh<br>(SIEM / HIDS)"]
        HIVE["TheHive<br>(Case Management)"]
        CORTEX["Cortex<br>(Enrichment / Response)"]
    end

    ERA["Eramba<br>(GRC)"]

    OPN -->|"Inspected Traffic"| SO

    SUR -.->|"Logs"| WAZ
    ZEEK -.->|"Metadata"| WAZ
    WAZ -->|"Alerts"| HIVE
    HIVE <-->|"Observables"| CORTEX

    WAZ -.->|"Evidence / Reporting"| ERA
```

## Key Considerations

**Infrastructure sizing** is going to be our biggest challenge. Running Elasticsearch on Security Onion is resource-intensive. Lots of CPU, memory and storage.

**Tuning burden** — Every detection engine (Suricata, Wazuh rules, Zeek) will generate noise initially. Budget time for baselining and tuning — this is where the "free software ≠ free operations" reality bites hardest.

**Integration gaps** — There's no single vendor stitching this together for us. Expect to write custom configuration for log forwarding, API integrations between SOAR/SIEM and GRC evidence collection pipelines.
