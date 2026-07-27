# 13. The Encryption Levels

## Goal

Compare the six encryption levels defined and recommend the appropriate level for every MedDefense data store.

## Context

"Encrypt the database" sounds simple, but there are at least three ways to do it: encrypt the entire disk the database sits on (full-disk), encrypt the database files (file-level), or encrypt individual fields within the database (record-level). Each has radically different properties: scope of protection, performance impact, key management complexity and what happens when someone with legitimate database access queries the data.

Choosing the wrong level either leaves data exposed or creates operational problems that the clinical staff will not tolerate.

---

## Part 1 - Six Encryption Levels Comparison

### Encryption Level Definitions from CompTIA Security+ 1.4

| Level | Scope | Performance Impact | Key Management | Use Case | Best When... |
|---|---|---|---|---|---|
| **Full-disk** | Entire physical or virtual disk (includes OS, applications, all data) | **Low** (~5-15% overhead with AES-NI); transparent to all applications; single key | **Simple**; one key per disk; stored in TPM/HSM/initramfs; boot-time unlock required | Laptops, servers, NAS devices protecting all data at rest; compliance baseline | You need broad protection with minimal operational overhead; threat is physical theft or drive removal |
| **Partition** | One logical partition (subset of disk; other partitions remain unencrypted) | **Low-Medium**; same as full-disk but only affects partition I/O; requires partition planning | **Moderate**; separate key per partition; may require multiple unlock prompts | Isolating specific data sets on shared hardware (e.g., `/home` vs `/var/lib/mysql`) | You need selective encryption on systems with mixed sensitivity data; different teams manage different partitions |
| **Volume** | Logical volume (may span multiple physical disks via LVM, RAID, ZFS) | **Low-Medium**; block-level encryption before filesystem; ~10% overhead with hardware acceleration | **Moderate**; one key per volume; can use key slots for redundancy | SAN/NAS volumes, VM disk images, database storage pools, backup volumes | You need flexibility across multiple physical disks while maintaining encryption granularity at storage pool level |
| **File** | Individual files or directories (transparent encryption on write, decrypt on read) | **Medium-High**; per-file encryption adds CPU overhead; metadata (filenames) often unencrypted | **Complex**; one key per file or user namespace; requires file-level key management system | User home directories, shared document repositories, selective PHI files in mixed environments | You need fine-grained control over which specific files are encrypted; multiple users with different access rights |
| **Database** | Entire database or tablespace (TDE - Transparent Data Encryption) | **Medium**; database engine handles encryption/decryption; query performance unchanged for authorized sessions | **Complex**; keys stored in keystore integrated with DB; separate from OS encryption | SQL Server Always Encrypted, Oracle TDE, PostgreSQL pgcrypto, MySQL Enterprise Encryption | You need encryption that persists with the database regardless of underlying storage; protecting against DBA or storage-level access |
| **Record** | Individual fields or records within database tables (column-level encryption) | **High**; each query requires decrypting specific fields; application must handle keys; significant latency increase | **Very Complex**; keys tied to application logic or HSM; requires key distribution to authorized queries | PHI fields in EHR (diagnosis codes, medication lists), financial account numbers, SSN masking | You need to protect specific sensitive fields while keeping other data readable; regulatory requirements mandate field-level isolation |

### Detailed Analysis of Each Level

#### Full-disk Encryption

**When it's the best choice:** When the primary threat model is physical device theft (laptops, portable drives) or when you need a compliance baseline for all systems. Full-disk encryption is ideal for employee workstations and backup servers where protecting all data at rest with minimal operational friction is the priority.

**Limitations:** Once the system boots and the disk is unlocked, all data is accessible to any process with system privileges. This provides no protection against malware, insider threats, or compromised accounts that already have filesystem access.

**Example:** LUKS2 on NAS-01, BitLocker on employee laptops.

---

#### Partition Encryption

**When it's the best choice:** When you have mixed-sensitivity data on the same physical hardware and need to isolate encryption boundaries. Useful when different departments manage different partitions, or when regulatory requirements mandate that certain data types (PHI vs billing) be cryptographically separated.

**Limitations:** Still susceptible to attack from within the operating system once any partition is unlocked. Requires careful partition planning during initial system setup.

**Example:** Encrypting `/var/lib/mysql` separately from `/var/www` on web servers.

---

#### Volume Encryption

**When it's the best choice:** When managing storage pools that span multiple physical disks (SAN, NAS, LVM, ZFS pools). Ideal for virtualized environments where VM disk images are presented as logical volumes that need consistent encryption regardless of underlying hardware topology.

**Limitations:** More complex than full-disk encryption due to volume management layer. Key recovery must account for volume group dependencies.

**Example:** LUKS-encrypted LVM volumes on hypervisors, encrypted ZFS datasets on TrueNAS.

---

#### File-level Encryption

**When it's the best choice:** When you need granular control over individual files with different access policies. Suitable for collaborative environments where documents are shared across organizational boundaries, or when legacy applications cannot be modified for database-level encryption.

**Limitations:** Metadata leakage (filenames, directory structure, file timestamps). Significant key management overhead at scale. Vulnerable to memory-based attacks where decrypted files are cached.

**Example:** eCryptFS for `/home` directories, GPG-encrypted medical records stored in object storage.

---

#### Database Encryption (Transparent Data Encryption - TDE)

**When it's the best choice:** When protecting database storage at rest while maintaining transparent access for authorized queries. Ideal for HIPAA-compliant databases where the database administrator should not have access to decrypted PHI, but clinical applications need seamless query performance.

**Limitations:** Does not protect against authorized queries from compromised application accounts. Keys often stored on the same server unless integrated with external HSM. Backup files may still be encrypted but can be vulnerable if encryption keys are not properly separated.

**Example:** SQL Server TDE on billing-srv-01, PostgreSQL pgcrypto extensions on ehr-db-01.

---

#### Record-level Encryption

**When it's the best choice:** When regulatory requirements or security policies mandate that specific data elements be cryptographically isolated from general database access. Essential for protecting highly sensitive fields like social security numbers, mental health diagnosis codes, or HIV status where even authorized database queries should require explicit decryption.

**Limitations:** Highest performance cost and key management complexity. Application code must handle encryption/decryption logic. Breaking changes to database schema may be required. Makes SQL analytics and reporting significantly more difficult.

**Example:** AES-256 encrypted `ssn`, `mental_health_notes` columns in patient_records table with keys managed by HSM.

---

## Part 2 - MedDefense Encryption Level Map

### Data Store Recommendations

| Data Store | Recommended Level | Justification | Implementation Notes |
|---|---|---|---|
| **Patient records in PostgreSQL (ehr-db-01)** | **Database + Record** | Database encryption protects against storage compromise and rogue DBAs; record-level encryption on highest-risk fields (SSN, mental health notes) ensures even authorized DBAs cannot view those fields without explicit application authorization. Combined approach satisfies HIPAA §164.312(a)(2)(iv) while minimizing performance impact on routine clinical queries. | Enable PostgreSQL TDE (pgcrypto or enterprise edition); encrypt `ssn`, `psychiatric_diagnosis`, `genetic_testing` columns with HSM-managed keys; leave `patient_name`, `date_of_birth` at database encryption level for query performance |
| **Backup data on NAS-01** | **Volume** | NAS-01 stores all backups from ehr-db-01, billing-srv-01, pacs-srv-01, and email archives. Volume encryption (LUKS2) protects all data at rest with minimal performance overhead while maintaining compatibility with backup software. Key is stored NOT on the NAS itself (HSM-01). | LUKS2 AES-256-GCM on backup_data volume; key stored on HSM-01 (NOT on the NAS); header backup in bank safe; Shamir's Secret Sharing for admin recovery |
| **Financial records in MySQL (billing-srv-01)** | **Database** | Billing data requires protection against storage theft and unauthorized database access, but does not require field-level isolation since all billing fields have similar sensitivity. Database encryption satisfies PCI-DSS and HIPAA requirements for payment processing while maintaining query performance for accounting workflows. | MySQL Enterprise TDE enabled; keys stored in Vault integration; regular key rotation quarterly; audit logs for all decryption events |
| **Medical images on PACS (pacs-srv-01)** | **Volume** | DICOM images are large files where file-level encryption would introduce unacceptable latency for radiologist access. Volume encryption provides comprehensive protection at rest without impacting streaming performance for image retrieval. Images already contain embedded PHI metadata, making file-level isolation impractical. | LUKS2 volume spanning RAID array; hardware-accelerated AES-NI; key loaded from HSM at boot; volume-mounted before PACS service starts |
| **Email data in O365** | **Record** | Email contains variable sensitivity; most messages are business communication, but some contain PHI in attachments or body text. Record-level encryption through Office 365 Message Encryption ensures recipient-only decryption while maintaining Microsoft's cloud management responsibilities. | Enable O365 Message Encryption; configure sensitivity labels for PHI-containing emails; IRM (Information Rights Management) for attachment protection; audit access logs weekly |
| **Employee laptops** | **Full-disk** | Physical theft is the primary risk vector; full-disk encryption provides maximum protection with zero user overhead once unlocked at boot. Clinical staff should not be burdened with file-level or record-level decisions; BitLocker or LUKS2 protects all data if device is stolen from clinic, airport, or home. | BitLocker (Windows) or LUKS2 (macOS/Linux) with TPM integration; recovery key backed up to Azure AD; auto-lock after 15 minutes inactivity |
| **BD Alaris pump firmware/configuration** | **Full-disk** | IoT medical devices have limited computational resources and cannot support complex encryption schemes. Full-disk encryption protects device configuration and audit logs against tampering while maintaining FDA cybersecurity requirements. Keys stored in device TPM or secure element. | Device manufacturer encryption enabled; keys provisioned during manufacturing; audit logs encrypted at rest; firmware update process includes cryptographic signature verification |

---

## Part 3 - Implementation Priority Matrix

### Phase 1 (Immediate: 30 days)

| Priority | Data Store | Level | Owner | Status |
|---|---|---|---|---|
| **1** | Employee laptops | Full-disk | Steve | ✅ Complete |
| **2** | Backup data on NAS-01 | Volume | Steve | ✅ Complete (Task 12) |
| **3** | Patient records in PostgreSQL | Database | Steve | 🔄 In Progress |

### Phase 2 (60-90 days)

| Priority | Data Store | Level | Owner | Status |
|---|---|---|---|---|
| **4** | Medical images on PACS | Volume | SysAdmin | Pending |
| **5** | Financial records in MySQL | Database | Finance Team | Pending |
| **6** | Email data in O365 | Record | IT Admin | Pending |

### Phase 3 (Annual Review)

| Priority | Data Store | Level | Owner | Status |
|---|---|---|---|---|
| **7** | BD Alaris pump firmware/configuration | Full-disk | Biomed Team | Annual audit |

---

## Part 4 - Compliance Mapping

### Encryption Level Alignment with Regulations

| Regulation | Requirement | MedDefense Implementation |
|---|---|---|
| **HIPAA §164.312(a)(2)(iv)** | Addressable encryption of electronic PHI | ✅ Multi-layer approach (Database + Volume + Full-disk) |
| **HIPAA §164.312(e)(2)(ii)** | Addressable key management controls | ✅ HSM-01 with Shamir's Secret Sharing for critical keys |
| **PCI-DSS 3.4** | Render PAN unreadable anywhere stored | ✅ Database TDE on billing-srv-01 with key separation |
| **FDA Cybersecurity Guidance** | Medical device security requirements | ✅ Full-disk encryption on IoT devices; signature verification |
| **NIST SP 800-111** | Encryption standards for federal systems | ✅ AES-256-GCM across all implementations |
| **SOC 2 Type II** | Confidentiality controls | ✅ Audit trails for all decryption events; quarterly key rotation |

---

## Part 5 - Operational Considerations

### Performance Budget by Encryption Level

| Level | Max Acceptable Latency Increase | MedDefense Tolerance |
|---|---|---|
| Full-disk | < 15% | ✅ Accepted (Task 12 measurement: 13-17%) |
| Partition | < 15% | ✅ Same as full-disk |
| Volume | < 15% | ✅ Same as full-disk |
| File | < 25% | ⚠️ Requires testing (e.g., PACS file access) |
| Database | < 20% | ✅ Clinical staff tolerance threshold |
| Record | < 40% | ⚠️ High-risk; limit to critical fields only |

### Key Management Requirements

| Level | Minimum Key Count | Rotation Frequency | Backup Location |
|---|---|---|---|
| Full-disk | 3 (primary + 2 recovery) | Annually | Bank safe + HSM |
| Volume | 3 (primary + 2 recovery) | Annually | Bank safe + HSM |
| Partition | 5 (per partition) | Annually | HSM only |
| File | Variable (per file/user) | Per user lifecycle | HSM + key vault |
| Database | 5 (DB + recovery slots) | Quarterly | HSM only |
| Record | 10+ (per sensitive column) | Quarterly | HSM + application secrets manager |

---

## Part 6 - Decision Tree for Encryption Level Selection

```mermaid
flowchart TD
    Start([Start]) --> Q1{"What is the primary<br/>threat model?"}

    Q1 -- "Physical device theft" --> A1["Full-disk encryption<br/>(laptops, NAS, IoT devices)"]
    Q1 -- "Storage compromise /<br/>rogue DBA" --> A2["Database TDE"]
    Q1 -- "Specific regulated fields<br/>(SSN, genetic data)" --> A3["Record-level encryption"]
    Q1 -- "Mixed sensitivity on<br/>shared hardware" --> A4["Partition / Volume encryption"]

    A1 & A2 & A3 & A4 --> Q2{"What is the acceptable<br/>performance impact?"}

    Q2 -- "< 15%" --> B1["Full-disk, Partition, Volume"]
    Q2 -- "< 25%" --> B2["File, Database"]
    Q2 -- "< 40%" --> B3["Record<br/>(limited to critical fields)"]

    B1 & B2 & B3 --> Q3{"Can application logic<br/>handle key management?"}

    Q3 -- "YES" --> C1["Record-level feasible"]
    Q3 -- "NO" --> C2["Database or Volume level"]

    C1 & C2 --> Q4{"Are keys separable from<br/>encrypted data?"}

    Q4 -- "YES<br/>(HSM, offline USB)" --> D1["Proceed"]
    Q4 -- "NO<br/>(keys on same server)" --> D2["Escalate to<br/>Security Committee"]

    D1 --> Final(["Implement chosen level with<br/>documented justification"])
    D2 --> Final
```


---

## Summary

MedDefense's encryption strategy employs a **defense-in-depth** approach using multiple encryption levels matched to each data store's threat model and operational requirements:

1. ✅ **Full-disk encryption** protects employee laptops and IoT devices from physical theft
2. ✅ **Volume encryption** protects NAS-01 backups and PACS images with minimal performance impact
3. ✅ **Database encryption** protects PostgreSQL and MySQL data from storage compromise
4. ✅ **Record-level encryption** protects O365 email PHI and select database columns requiring highest isolation

This layered strategy satisfies HIPAA, PCI-DSS, FDA, and NIST requirements while maintaining clinical staff workflow efficiency. The key principle: **no single encryption level fits all use cases**—each data store requires deliberate selection based on its specific risk profile and operational constraints.
