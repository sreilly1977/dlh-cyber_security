```mermaid
flowchart TB
    subgraph Perimeter["Perimeter Defense"]
        OPN["OPNsense Firewall + Suricata IPS<br/>VPN + NetFlow"]
    end

    subgraph Detection["Detection & Monitoring"]
        SO["Security Onion SIEM / NIDS / Host Visibility<br/>Native Cases Module Elastic Stack"]
    end

    subgraph Orchestration["SOAR Layer"]
        SHF["Shuffle Workflow Automation<br/>Cross-Tool Orchestration"]
    end

    subgraph Governance["Secondary Governance Layer"]
        ERA["Eramba GRC Platform<br/>Compliance Risk Audit Tracking"]
    end

    subgraph Proxmox["Proxmox VE Instance"]
        subgraph MgmtNet["Management Network"]
            MGMT["Proxmox Host Management<br/>Cluster Admin + Hypervisor Console"]
        end

        subgraph BackupNet["Backup Network Segment"]
            FN1["FreeNAS Backup Storage<br/>Snapshots + Replication"]
        end

        subgraph AIMNet["AIM Network Segment"]
            DC1["Active Directory DC1<br/>Primary Domain Controller"]
            DC2["Active Directory DC2<br/>Secondary Domain Controller"]
        end

        subgraph FileShareNet["Fileshare Network Segment"]
            FN2["FreeNAS File Server<br/>SMB NFS Shares"]
        end
    end

    OPN -- "syslog / NetFlow" --> SO
    OPN <-. "API: block rules, rule enforcement" .-> SHF
    SHF -- "API: query logs, pull alerts, cases" --> SO
    SHF -- "HTTP: create incidents, push governance records" --> ERA
    ERA <-. "webhook: status triggers, risk updates" .-> SHF

    OPN -- "segmented routing / VLANs" --> MGMT
    MGMT -- "admin access" --> FN1
    MGMT -- "admin access" --> DC1
    MGMT -- "admin access" --> FN2
    DC1 <--> AD replication DC2
    FN1 -- "backup targets, AD GPO + SYSVOL" -.-> DC1
    FN1 -- "backup targets, SMB shares + datasets" -.-> FN2
    SO -- "HIDS agents / flow collection" -.-> MGMT
```
