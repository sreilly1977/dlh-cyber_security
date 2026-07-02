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
graph TB
    %% ── External Network ──
    NET([Internet / External Traffic])

    %% ── Firewall / WAF Layer ──
    subgraph FW["🔥 Firewall / WAF"]
        OPN["<b>OPNsense v26.1</b><br/>━━━━━━━━━━━━━━<br/>• Stateful Packet Inspection<br/>• VLANs<br/>• WireGuard / IPsec VPNs<br/>• Traffic Shaping<br/>• GeoIP Filtering<br/>• Built-in Suricata IDS/IPS Plugin<br/><br/>Built on FreeBSD | Fork of pfSense<br/>Quarterly Releases | Truly Open Source"]
    end

    %% ── Security Onion Platform ──
    subgraph SO["🧅 Security Onion — Turnkey NSM Platform"]
        direction TB

        subgraph NIDS_LAYER["📡 NIDS"]
            SUR["<b>Suricata</b><br/>━━━━━━━━━━━━━━<br/>• Signature-based Detection<br/>• Emerging Threats Ruleset<br/>• Protocol Analysis<br/>• High-Performance / Multi-threaded"]
            ZEEK["<b>Zeek</b> (formerly Bro)<br/>━━━━━━━━━━━━━━<br/>• Network Behavior Analytics<br/>• Metadata Logging"]
        end

        subgraph HIDS_LAYER["🖥️ HIDS"]
            WAZ["<b>Wazuh</b><br/>━━━━━━━━━━━━━━<br/>• File Integrity Monitoring (FIM)<br/>• SCA — CIS Benchmarks<br/>• Vulnerability Detection (CVE)<br/>• Rootcheck — Rootkit / Malware<br/>• System Inventory & Asset Visibility<br/>• Active Response Automation<br/>• MITRE ATT&CK Mapping + Threat Intel"]
            AGENT["Wazuh Agents<br/>━━━━━━━━━━━━━━<br/>🪟 Windows&nbsp;&nbsp;🐧 Linux&nbsp;&nbsp;🍎 macOS"]
        end

        subgraph SIEM_LAYER["📊 SIEM / XDR"]
            ELASTIC["<b>Wazuh + Elastic Stack</b><br/>━━━━━━━━━━━━━━<br/>• Log Aggregation & Correlation<br/>• Alerting<br/>• Dashboards"]
            KB["<b>Kibana</b><br/>Visualization & Hunting"]
        end

        subgraph SOAR_LAYER["🔁 SOAR"]
            HIVE["<b>TheHive</b><br/>━━━━━━━━━━━━━━<br/>• Case Management<br/>• Observables & Timelines<br/>• Assigned Analysts<br/>• Task Tracking<br/>• Custom Fields"]
            CORTEX["<b>Cortex</b><br/>━━━━━━━━━━━━━━<br/>• Automated Enrichment<br/>• Analyzers — Investigation<br/>  (Threat Intel, Sandboxes, Reputation)<br/>• Responders — Take Action"]
        end
    end

    %% ── GRC Layer ──
    subgraph GRC_LAYER["📋 GRC — Governance, Risk & Compliance"]
        ERAMBA["<b>Eramba</b><br/>━━━━━━━━━━━━━━<br/>• Policy Management<br/>• Risk Assessment<br/>• Audit Management<br/>• RBAC<br/>• Automated Evidence Collection<br/>• Multi-framework Mapping<br/>• Audit-ready Reporting"]
    end

    %% ── Traffic Flow ──
    NET -->|"Ingress / Egress"| OPN
    OPN -->|"SPAN / Mirror Port"| SUR
    OPN -.->|"Inline IPS Block"| NET

    SUR <-->|"Telemetry"| ZEEK
    SUR -->|"Logs & Alerts"| ELASTIC
    ZEEK -->|"Metadata & Logs"| ELASTIC

    AGENT -->|"Agent Telemetry"| WAZ
    WAZ -->|"HIDS Alerts"| ELASTIC
    WAZ -.->|"Active Response<br/>Quarantine · Block IP · Script"| AGENT

    ELASTIC <-->|"Query / Visualize"| KB
    ELASTIC -->|"Forward Alerts"| HIVE

    HIVE <-->|"Observable Enrichment"| CORTEX
    CORTEX -.->|"Responder Actions"| OPN
    CORTEX -.->|"Responder Actions"| AGENT

    ERAMBA -.->|"Compliance Context"| ELASTIC
    ERAMBA -.->|"Audit Evidence"| HIVE

    %% ── Styling ──
    classDef fw fill:#FF6B35,color:#fff,stroke:#E55A2B,stroke-width:2px
    classDef nids fill:#2196F3,color:#fff,stroke:#1976D2,stroke-width:2px
    classDef hids fill:#4CAF50,color:#fff,stroke:#388E3C,stroke-width:2px
    classDef siem fill:#9C27B0,color:#fff,stroke:#7B1FA2,stroke-width:2px
    classDef soar fill:#FF9800,color:#fff,stroke:#F57C00,stroke-width:2px
    classDef grc fill:#607D8B,color:#fff,stroke:#546E7A,stroke-width:2px
    classDef agent fill:#81C784,color:#fff,stroke:#66BB6A,stroke-width:1px

    class OPN fw
    class SUR,ZEEK nids
    class WAZ hids
    class AGENT agent
    class ELASTIC,KB siem
    class HIVE,CORTEX soar
    class ERAMBA grc
```

## Key Considerations

**Infrastructure sizing** is going to be our biggest challenge. Running Elasticsearch at scale across Wazuh, Security Onion, and potentially UTMStack simultaneously is resource-intensive. We'll want to think about whether to consolidate ELK instances or keep them separate for blast-radius isolation.

**Log pipeline architecture** — Decide early whether we're using syslog, Filebeat/Winlogbeat, or a message broker (Kafka/Redis) as our transport layer. This affects everything downstream.

**Tuning burden** — Every detection engine (Suricata, Wazuh rules, UTMStack correlations) will generate noise initially. Budget time for baselining and tuning — this is where the "free software ≠ free operations" reality bites hardest.

**Integration gaps** — There's no single vendor stitching this together for us. Expect to write custom configuration for log forwarding, API integrations between SOAR and SIEM, and GRC evidence collection pipelines.
