# MedDefense Backup Architecture

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** Steve, IT Security  
**Date:** 2026-11-01  
**Approved by:** _________________________ Date: _________

## Strategy Overview

This document translates the recovery objectives established in `business_impact_analysis.md` version 1.0 into an implementable backup architecture for every Tier 1 and Tier 2 system. It addresses the five defects documented in the backup log review and resolves the three RPO conflicts where declared objectives were shorter than backup frequency could mathematically deliver.

### Governing Principle

Achievable RPO can never be better than backup frequency. A system declaring a 1-hour RPO must produce a verified recovery point no older than 60 minutes. This is an arithmetic constraint, not a tuning preference, and it is the test applied throughout the RPO Compliance Verification section.

### Architecture Layers

| Layer | Purpose | Scope |
|---|---|---|
| Operational backup | Frequent recovery points meeting RPO | All Tier 1 and Tier 2 systems |
| Local retention | Rapid restoration within RTO | Primary destination, on-site |
| Geographically separate copy | Site-loss survivability | Mandatory for all Tier 1 systems |
| Archive retention | Regulatory and legal hold | ePHI systems, up to 7 years |

### Defects Addressed from Backup Log Review

| Finding | Defect | Architectural Resolution |
|---|---|---|
| Finding 1 | LIS nightly-only backup conflicts with short RPO for critical values | Hourly transaction log backup added alongside nightly full dump |
| Finding 2 | Medical Device Gateway has no secondary destination | Encrypted off-site copy introduced, quarterly restore test mandated |
| Finding 3 | Active Directory 8-hour snapshot interval cannot support dependent Tier 1 RPO | Snapshot interval reduced to hourly |
| Finding 4 | Backup completion logged as verification | Hash validation, test restore, record-count check, tester identity and date required for every system |
| Finding 5 | Backup platform recovery under-documented and untimed | Catalog backup frequency increased, timed restore rehearsal mandated |

### Encryption Baseline

Every backup containing ePHI or system data that could disclose ePHI uses AES-256 encryption at rest and TLS 1.2 or later in transit. Keys are managed through a hardware-backed key management service with a distinct key per system, annual rotation, and documented escrow held separately from production credentials. The isolated backup account holding the catalog and configuration exports uses a key that is not accessible from production infrastructure, so that compromise of production does not yield the ability to decrypt or destroy backups.

## RPO Compliance Verification

Declared RPO values are inherited from `business_impact_analysis.md` version 1.0. Current frequency values are taken from `current_backup_schedule.csv`. Remediated frequency is the proposed architecture.

| System | Tier | Declared RPO | Current Frequency | Current Achievable RPO | Currently Compliant | Remediated Frequency | Remediated Achievable RPO | Margin |
|---|---:|---:|---|---:|---|---|---:|---:|
| Network Core | 1 | 1 hour | Device config every 6 hours | 6 hours | No | Device config every 1 hour | 1 hour | 0 minutes |
| Active Directory | 1 | 1 hour | Snapshot every 8 hours; system state daily | 8 hours | No | Snapshot every 1 hour; system state daily | 1 hour | 0 minutes |
| Epic EHR | 1 | 1 hour | Replication every 15 minutes; export nightly | 15 minutes | Yes | Replication every 15 minutes; hourly log ship; export nightly | 15 minutes | 45 minutes |
| Laboratory Information System | 1 | 1 hour | SQL dump nightly at 23:30 | 24 hours | No | Hourly transaction log backup; full dump nightly at 23:30 | 1 hour | 0 minutes |
| Pharmacy Dispensing System | 1 | 1 hour | Database hourly; config daily | 1 hour | Yes | Database hourly; config hourly; cabinet sync hourly | 1 hour | 0 minutes |
| Backup and DR Infrastructure | 1 | 2 hours | Catalog every 4 hours; config daily | 4 hours | No | Catalog every 1 hour; config daily | 1 hour | 60 minutes |
| PACS/RIS | 2 | 1 hour | Snapshot every 4 hours; metadata export nightly | 4 hours | No | Snapshot every 1 hour; RIS database hourly; metadata export nightly | 1 hour | 0 minutes |
| Medical Device Integration Gateway | 2 | 4 hours | Config export daily at 02:30 | 24 hours | No | Config export every 4 hours; full config daily at 02:30 | 4 hours | 0 minutes |
| Security Operations Platform | 2 | 4 hours | Index snapshot every 4 hours; config daily | 4 hours | Yes | Index snapshot every 4 hours; config daily | 4 hours | 0 minutes |

### Compliance Summary

Six of nine systems required remediation. Four systems were already compliant: Epic EHR, Pharmacy Dispensing System, and Security Operations Platform on frequency, plus Pharmacy on configuration cadence once cabinet synchronisation is added. No Tier 1 system retains a backup frequency longer than its declared RPO.

Four systems operate at zero margin, meaning backup frequency exactly equals declared RPO. This is arithmetically compliant but operationally fragile: a single missed or failed backup window breaches the objective immediately. Where budget permits, these four systems should move to sub-RPO frequencies, and each zero-margin system requires backup failure alerting with same-window retry.

## Per-System Backup Specifications

### Network Core

| Field | Specification |
|---|---|
| Backup type | Full device configuration backup plus incremental diff |
| Schedule | Incremental config backup every 1 hour; full configuration snapshot daily at 01:00 |
| Retention | Recent: 90 days hourly and daily. Monthly: 12 monthly full sets. Archive: 7 years configuration archive |
| Primary destination | Network management server, encrypted local volume, on-site |
| Secondary destination | Encrypted Git repository in geographically separate region |
| Encryption at rest | AES-256; dedicated key in hardware-backed KMS; annual rotation |
| Encryption in transit | TLS 1.2+ over HTTPS and SFTP transport |
| Integrity verification | SHA-256 hash per configuration file; diff check after every backup; quarterly restore to lab switch with routing and VLAN validation |
| Restoration sequence | 1. Retrieve most recent verified hourly configuration set. 2. Restore core switch and router configurations. 3. Validate routing, switching and VLAN segmentation. 4. Bring WAN interfaces up. 5. Confirm reachability for Active Directory, backup replication, PACS image movement and device gateway. |
| Responsible role | Executes: Network Engineering Lead. Verifies: Infrastructure Manager |

### Active Directory

| Field | Specification |
|---|---|
| Backup type | System state plus virtual machine snapshot, combination |
| Schedule | VM snapshot every 1 hour; system state backup daily at 01:00; continuous replication to secondary domain controller |
| Retention | Recent: 30 days hourly snapshots and daily system state. Monthly: 12 monthly full sets. Archive: 180 days |
| Primary destination | Backup NAS rack A, on-site |
| Secondary destination | Encrypted object storage account in geographically separate region |
| Encryption at rest | AES-256; dedicated key in hardware-backed KMS; VM disk encryption enabled |
| Encryption in transit | TLS 1.2+ and LDAPS for directory traffic |
| Integrity verification | SHA-256 manifest per backup; quarterly non-authoritative restore test into isolated forest; validation via dcdiag and repadmin replication status |
| Restoration sequence | 1. Confirm secondary domain controller health and replication state. 2. Perform non-authoritative restore of primary domain controller from most recent verified backup. 3. Monitor for USN rollback conditions. 4. Confirm inbound replication converges. 5. Run dcdiag validation suite. 6. Verify authentication for dependent systems before releasing them. |
| Responsible role | Executes: Systems Administrator. Verifies: Infrastructure Manager |

### Epic EHR

| Field | Specification |
|---|---|
| Backup type | Vendor replication plus nightly export plus hourly transaction log shipping, combination |
| Schedule | Replication every 15 minutes; transaction log ship every 1 hour; full export nightly at 23:00 |
| Retention | Recent: 35 days vendor retention. Monthly: 12 monthly full sets. Archive: 7 years |
| Primary destination | Vendor-hosted disaster recovery site |
| Secondary destination | Vendor cold archive in geographically separate region |
| Encryption at rest | AES-256; vendor-managed with MedDefense key escrow held separately |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Vendor monthly restore certificate plus MedDefense quarterly application-level validation with record count and allergy-verification checks |
| Restoration sequence | 1. Confirm Network Core and Active Directory available. 2. Initiate vendor failover to disaster recovery site. 3. Validate database integrity and record counts. 4. Reconnect LIS interface, pharmacy and PACS/RIS interfaces. 5. Validate order entry and allergy verification. 6. Release to clinical use. |
| Responsible role | Executes: Clinical Applications Manager. Verifies: IT Incident Commander |

### Laboratory Information System

| Field | Specification |
|---|---|
| Backup type | Full compressed SQL dump plus hourly transaction log backup, combination |
| Schedule | Full dump nightly at 23:30; transaction log backup every 1 hour |
| Retention | Recent: 30 days full and hourly logs. Monthly: 12 monthly full sets. Archive: 1 year |
| Primary destination | Backup NAS at `/backup/lis`, on-site |
| Secondary destination | CloudVault Medical backup bucket, geographically separate region |
| Encryption at rest | AES-256; gzip archive encrypted with asymmetric key, private key held in hardware-backed KMS |
| Encryption in transit | TLS 1.2+ over SFTP and HTTPS transport |
| Integrity verification | SHA-256 manifest per artifact; row count validation via `SELECT COUNT(*) FROM patient_orders;`; critical record verification for MRN-10043 and MRN-10045; tester identity and date recorded |
| Restoration sequence | 1. Confirm Network Core and Active Directory available. 2. Retrieve most recent verified full dump. 3. Apply hourly transaction logs in chronological sequence to reach target recovery point. 4. Decompress and load into recovery database. 5. Execute healthcheck query and confirm expected row count. 6. Verify critical records present with correct critical flags. 7. Reconnect Epic interface engine and lab instrument feeds. 8. Release to clinical use. |
| Responsible role | Executes: Laboratory Systems Lead. Verifies: Clinical Applications Lead |

### Pharmacy Dispensing System

| Field | Specification |
|---|---|
| Backup type | Database backup plus cabinet configuration export, combination |
| Schedule | Database backup every 1 hour; cabinet configuration export every 1 hour; full configuration snapshot daily at 01:00 |
| Retention | Recent: 30 days hourly. Monthly: 12 monthly full sets. Archive: 1 year |
| Primary destination | Pharmacy backup share, on-site |
| Secondary destination | Encrypted cloud copy in geographically separate region |
| Encryption at rest | AES-256; dedicated key in hardware-backed KMS |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Weekly hash verification; monthly restore test including controlled substance reconciliation against cabinet counts |
| Restoration sequence | 1. Confirm Network Core and Active Directory available. 2. Restore database from most recent verified hourly backup. 3. Restore cabinet configuration. 4. Reconcile controlled substance counts and document variances. 5. Reconnect Epic medication ordering interface. 6. Validate allergy and interaction checking before release. |
| Responsible role | Executes: Pharmacy IT Lead. Verifies: Clinical Applications Manager |

### Backup and DR Infrastructure

| Field | Specification |
|---|---|
| Backup type | Catalog backup plus configuration export, combination |
| Schedule | Catalog backup every 1 hour; configuration export daily at 01:00 |
| Retention | Recent: 30 days hourly catalog. Monthly: 12 monthly full sets. Archive: 1 year off-site |
| Primary destination | Disaster recovery platform storage, on-site |
| Secondary destination | Isolated backup account in geographically separate region, credentials not reachable from production |
| Encryption at rest | AES-256; dedicated key in hardware-backed KMS, isolated from production credential store |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Monthly catalog restore test; quarterly timed full restore rehearsal recording elapsed duration; tester identity and date recorded |
| Restoration sequence | 1. Restore backup catalog from isolated account. 2. Validate catalog integrity and index completeness. 3. Restore storage access credentials. 4. Confirm restore tooling operational. 5. Hand off to dependent system restorations. |
| Responsible role | Executes: Infrastructure Manager. Verifies: IT Incident Commander |

### PACS/RIS

| Field | Specification |
|---|---|
| Backup type | Storage snapshot plus metadata export plus RIS database backup, combination |
| Schedule | Image storage snapshot every 1 hour; RIS database backup every 1 hour; metadata export nightly at 23:00 |
| Retention | Recent: 30 days hot. Monthly: 12 monthly full sets. Archive: 7 years |
| Primary destination | PACS storage cluster, on-site |
| Secondary destination | Cloud object archive in geographically separate region |
| Encryption at rest | AES-256; dedicated key in hardware-backed KMS |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Quarterly restore test reinstated after documented miss; metadata-to-image reconciliation count; tester identity and date recorded |
| Restoration sequence | 1. Confirm Network Core and Active Directory available. 2. Restore RIS metadata database. 3. Mount image storage snapshot. 4. Reconcile study metadata against image objects. 5. Reconnect Epic order interface and modality devices. 6. Validate prior study retrieval before release. |
| Responsible role | Executes: Radiology Systems Lead. Verifies: Clinical Applications Manager |

### Medical Device Integration Gateway

| Field | Specification |
|---|---|
| Backup type | Full configuration export plus incremental configuration backup, combination |
| Schedule | Incremental configuration export every 4 hours; full configuration export daily at 02:30 |
| Retention | Recent: 14 days. Monthly: 12 monthly full sets. Archive: 90 days |
| Primary destination | Biomed file share, on-site |
| Secondary destination | Encrypted off-site copy in geographically separate region, newly introduced to close the documented geographic copy gap |
| Encryption at rest | AES-256; dedicated key in hardware-backed KMS |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | SHA-256 hash per configuration file replacing manual file existence check; quarterly restore test newly mandated |
| Restoration sequence | 1. Confirm Network Core available and VLAN segmentation restored. 2. Restore gateway configuration. 3. Validate VLAN segmentation and device connectivity. 4. Confirm telemetry flow into Epic. 5. Validate alarm routing to nursing units before release. |
| Responsible role | Executes: Biomedical IT Lead. Verifies: Clinical Applications Manager |

### Security Operations Platform

| Field | Specification |
|---|---|
| Backup type | Configuration backup plus index snapshot, combination |
| Schedule | Index snapshot every 4 hours; configuration backup daily at 01:00 |
| Retention | Recent: 30 days hot. Monthly: 12 monthly full sets. Archive: 180 days cold |
| Primary destination | SIEM storage, on-site |
| Secondary destination | Cloud archive in geographically separate region |
| Encryption at rest | AES-256; dedicated key in hardware-backed KMS |
| Encryption in transit | TLS 1.2+ |
| Integrity verification | Snapshot status check plus quarterly restore test with alerting validation, newly mandated to close the untested alerting continuity gap |
| Restoration sequence | 1. Confirm Network Core and Active Directory available. 2. Restore SIEM configuration. 3. Restore index snapshot. 4. Reconnect log sources. 5. Validate alerting and endpoint detection management. 6. Confirm reduced-mode monitoring plan was active during earlier restoration phases. |
| Responsible role | Executes: SOC Manager. Verifies: IT Incident Commander |

## Full Data Center Loss: Restoration Sequence

This sequence assumes total loss of the primary data center with no surviving production infrastructure. Order is determined by dependency, not alphabetically. Elapsed durations are planning estimates derived from the RTO values in the BIA and must be validated by test; they are not measured results.

### Phase 0: Declaration and Activation (0 to 30 minutes)

Administrator on Call authorises hospital-wide downtime declaration at extension 7000. Nursing Supervisor coordinates units at extension 7100. IT Incident Commander confirms outage scope at extension 7200. Clinical Applications Lead confirms clinical system status at extension 7300. Paper downtime procedures activate per the nursing station downtime binders and paper forms inventory.

### Phase 1: Network Core

Prerequisite: none. All subsequent phases are blocked until complete.

Restore device configurations from the most recent verified hourly backup. Validate routing, switching, WAN reachability and VLAN segmentation. Confirm the network path required for backup replication traffic is available. Target: within 2 hours of declaration.

### Phase 2: Active Directory

Prerequisite: Network Core reachable.

Confirm secondary domain controller health. Perform non-authoritative restore of the primary domain controller. Monitor for USN rollback. Confirm replication convergence and run validation suite. Identity must be functional before any authenticated clinical system is released. Target: within 2 hours of Phase 1 completion.

### Phase 3: Backup and DR Infrastructure

Prerequisite: Network Core and Active Directory.

Restore the backup catalog from the isolated account, validate catalog integrity, restore storage access credentials and confirm restore tooling operational. This phase is sequenced third despite not being patient-facing because every remaining restoration depends on the catalog being able to locate and serve backup artifacts. Skipping it converts remaining recovery attempts into manual media hunting. Target: within 3 hours of Phase 2 completion.

### Phase 4: Tier 1 Clinical Systems

Prerequisite: Phases 1 through 3 complete. Within this phase, order is driven by patient safety consequence and interface dependency.

1. Epic EHR: restore and validate, then reconnect interfaces. Order entry and allergy verification must function before dependent systems release.
2. Laboratory Information System: restore full dump, apply hourly transaction logs, validate row count and critical records, reconnect interface engine and analyser feeds.
3. Pharmacy Dispensing System: restore database and cabinet configuration, reconcile controlled substances, validate allergy and interaction checking.

Target: within 4 hours of Phase 3 completion for each system.

### Phase 5: Tier 2 Clinical Support Systems

Prerequisite: Phase 4 complete.

1. PACS/RIS: restore metadata database first, then mount image storage, then reconcile metadata to images, then reconnect order interface and modalities.
2. Medical Device Integration Gateway: restore configuration, validate VLAN segmentation, confirm telemetry flow into Epic and alarm routing to nursing units.

Target: within 6 hours of Phase 4 completion for each system.

### Phase 6: Security and Monitoring Visibility

Prerequisite: Phase 5 complete.

Security Operations Platform: restore configuration and index snapshot, reconnect log sources, validate alerting and endpoint detection management. Reduced-mode monitoring must have been maintained manually throughout Phases 0 through 5, since detection and response capability is degraded during the entire restoration window while attack risk rises. Target: within 6 hours of Phase 5 completion.

### Phase 7: Remaining Systems

Email and Secure Messaging and any business support systems restore last, per the recovery sequence in the dependency map seed.

## Dependency Restore Constraints

The following constraints are hard ordering rules. Violating any of them wastes restoration time and can force a restart of the dependent system's recovery.

1. **Network Core precedes everything.** No authenticated, replicated or remotely retrieved restoration is possible without routing, switching and WAN reachability.

2. **Active Directory precedes all authenticated clinical systems.** Epic EHR, LIS, PACS/RIS, Pharmacy and Security Operations all depend on domain authentication. Restoring a clinical application into a non-functional identity plane produces a system that boots but cannot be used.

3. **Backup and DR Infrastructure precedes all restores that consume backup artifacts.** The catalog must be available to locate and serve backups. This is the constraint most commonly overlooked, because the backup platform is not patient-facing and therefore rarely appears in clinical recovery sequencing.

4. **Epic EHR precedes or parallels Pharmacy and PACS/RIS interface reconnection.** Pharmacy medication ordering and PACS/RIS order interfaces terminate in Epic. Restoring those systems before Epic's interface layer is available leaves them functionally isolated.

5. **LIS interface engine depends on Epic interface availability.** Result posting to Epic requires the interface layer. LIS internal validation can proceed in parallel, but clinical release waits on the interface.

6. **PACS/RIS metadata must be restored before image store mounting is considered complete.** Images without a metadata layer cannot be associated to patients or studies, and radiologists cannot retrieve prior studies.

7. **Medical Device Integration Gateway requires VLAN segmentation before configuration restore is meaningful.** The gateway's function depends on network segmentation being in place. Configuration restored onto an unsegmented network will not route telemetry correctly.

8. **Active Directory restore requires an authoritative versus non-authoritative decision before execution.** With a healthy secondary domain controller, non-authoritative restore is the correct default. An authoritative restore forces the restored state onto the replica partner and is reserved for deliberate forest-wide rollback of deleted objects.

9. **USN rollback risk must be assessed before restoring a domain controller holding FSMO roles.** Improper restoration can silently halt replication, producing a domain controller that appears healthy while propagating nothing.

10. **Security Operations Platform restores late, but reduced-mode monitoring activates early.** Detection capability must be maintained manually from Phase 0 onward. Deferring security visibility until Phase 6 without a compensating control leaves the organisation blind during the period of greatest exposure.

11. **Zero-margin systems require backup failure alerting.** Network Core, Active Directory, LIS and PACS/RIS operate with backup frequency equal to declared RPO. A single missed window breaches the objective, so alerting and same-window retry are mandatory rather than optional.

12. **Every restoration requires recorded tester identity and date.** Per Finding 4, a log entry stating a job completed proves only that a job ended. Verification requires hash validation, a test restore, record count or application-level checks, and named accountability.

---
