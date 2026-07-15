``` mermaid
flowchart TB
    subgraph Perimeter["Perimeter Defense"]
        OPN["OPNsense<br/>Firewall + Suricata IPS<br/>VPN + NetFlow"]
    end

    subgraph Detection["Detection & Monitoring"]
        SO["Security Onion<br/>SIEM / NIDS / Host Visibility<br/>Native Cases Module<br/>Elastic Stack"]
    end

    subgraph Orchestration["SOAR Layer"]
        SHF["Shuffle<br/>Workflow Automation<br/>Cross-Tool Orchestration"]
    end

    subgraph Governance["Secondary Governance Layer"]
        ERA["Eramba<br/>GRC Platform<br/>Compliance, Risk, Audit Tracking"]
    end

    subgraph Proxmox["Proxmox VE Instance"]
        subgraph MgmtNet["Management Network"]
            MGMT["Proxmox Host Management<br/>Cluster Admin + Hypervisor Console"]
        end

        subgraph BackupNet["Backup Network Segment"]
            FN1["FreeNAS<br/>Backup Storage<br/>Snapshots + Replication"]
        end

        subgraph AIMNet["AIM Network Segment"]
            DC1["Active Directory DC1<br/>Primary Domain Controller"]
            DC2["Active Directory DC2<br/>Secondary Domain Controller"]
        end

        subgraph FileShareNet["Fileshare Network Segment"]
            FN2["FreeNAS<br/>File Server<br/>SMB / NFS Shares"]
        end
    end

    %% --- Existing Connections ---
    OPN -- "syslog / NetFlow" --> SO
    OPN <-. "API: block rules,<br/>rule enforcement" .-> SHF
    SHF -- "API: query logs,<br/>pull alerts, cases" --> SO
    SHF -- "HTTP: create incidents,<br/>push governance records" --> ERA
    ERA <-. "webhook: status triggers,<br/>risk updates" .-> SHF

    %% --- Proxmox Integration ---
    OPN -- "segmented routing / VLANs" --> MgmtNet
    MgmtNet -- "admin access" --> BackupNet
    MgmtNet -- "admin access" --> AIMNet
    MgmtNet -- "admin access" --> FileShareNet
    DC1 <-->|"AD replication"| DC2
    FN1 -- "backup targets<br/>AD GPO + SYSVOL"| AIMNet
    FN1 -- "backup targets<br/>SMB shares + datasets"| FileShareNet
    SO -- "HIDS agents / flow collection" --> MgmtNet
```
