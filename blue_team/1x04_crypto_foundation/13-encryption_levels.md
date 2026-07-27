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
| **Partition** | One logical partition (subset of disk; other partitions remain unencrypted) | **Low-Medium**; same block-level overhead as full-disk but only affects I/O on the encrypted partition; unencrypted partitions have zero overhead | **Moderate**; separate key per partition; may require multiple unlock prompts at boot; each partition needs independent key backup | Isolating specific data sets on shared hardware (e.g., encrypting `/var/lib/mysql` while leaving `/boot` and `/usr` unencrypted) | You need selective encryption on systems with mixed sensitivity data; different teams manage different partitions |
| **Volume** | Logical volume (may span multiple physical disks via LVM, RAID, ZFS) | **Low-Medium**; block-level encryption before filesystem; ~10% overhead with hardware acceleration; performance scales with underlying storage topology | **Moderate**; one key per volume; can use key slots for redundancy; key must be available before volume group activation | SAN/NAS volumes, VM disk images, database storage pools, backup volumes | You need flexibility across multiple physical disks while maintaining encryption granularity at storage pool level |
| **File** | Individual files or directories (transparent encryption on write, decrypt on read) | **Medium-High**; per-file encryption adds CPU overhead; metadata (filenames) often unencrypted | **Complex**; one key per file or user namespace; requires file-level key management system | User home directories, shared document repositories, selective PHI files in mixed environments | You need fine-grained control over which specific files are encrypted; multiple users with different access rights |
| **Database** | Entire database or tablespace (TDE - Transparent Data Encryption) | **Medium**; database engine handles encryption/decryption; query performance unchanged for authorized sessions | **Complex**; keys stored in keystore integrated with DB; separate from OS encryption | SQL Server Always Encrypted, Oracle TDE, PostgreSQL pgcrypto, MySQL Enterprise Encryption | You need encryption that persists with the database regardless of underlying storage; protecting against DBA or storage-level access |
| **Record** | Individual fields or records within database tables (column-level encryption) | **High**; each query requires decrypting specific fields; application must handle keys; significant latency increase | **Very Complex**; keys tied to application logic or HSM; requires key distribution to authorized queries | PHI fields in EHR (diagnosis codes, medication lists), financial account numbers, SSN masking | You need to protect specific sensitive fields while keeping other data readable; regulatory requirements mandate field-level isolation |

---

### Detailed Analysis of Each Level

#### Full-disk Encryption

**Scope:** Protects everything on the physical or virtual disk, including the operating system, applications, configuration files, swap space, temporary files, and all user data. Nothing on the disk is readable without the decryption key.

**Performance Impact:** Lowest overhead of all levels because encryption occurs at the block device layer using kernel-space dm-crypt, and modern CPUs provide AES-NI hardware acceleration. Expect 5-15% overhead on sequential I/O and 10-17% on random I/O. The encryption is completely transparent to all applications and users once the disk is unlocked at boot.

**Key Management:** Simplest key model—one key per disk. The key is stored in TPM 2.0, HSM, or entered via passphrase at boot. Once unlocked, the key resides in kernel memory and all processes benefit from transparent decryption. Recovery requires a backup passphrase or keyfile stored offline.

**When it's the best choice:** When the primary threat model is physical device theft (laptops, portable drives) or when you need a compliance baseline for all systems. Full-disk encryption is ideal for employee workstations and backup servers where protecting all data at rest with minimal operational friction is the priority.

**Limitations:** Once the system boots and the disk is unlocked, all data is accessible to any process with system privileges. This provides no protection against malware, insider threats, or compromised accounts that already have filesystem access.

**Example:** LUKS2 on NAS-01, BitLocker on employee laptops.

---

#### Partition Encryption

**Scope:** Protects a single logical partition on a disk while leaving other partitions unencrypted. For example, on a server with `/boot`, `/usr`, `/var/lib/mysql`, and `/home`, you might encrypt only `/var/lib/mysql` and `/home` while leaving the OS partitions in plaintext for faster boot times and simpler recovery.

**Performance Impact:** Block-level encryption identical in overhead to full-disk encryption (~5-15% with AES-NI), but the performance penalty applies only to I/O on the encrypted partition. Unencrypted partitions (e.g., `/boot`, `/usr`) have zero encryption overhead, making partition-level encryption slightly more efficient than full-disk when the system has large non-sensitive partitions.

**Key Management:** Moderate complexity. Each encrypted partition requires its own key, meaning a server with 3 encrypted partitions needs 3 separate keys with 3 independent backup and recovery processes. Boot configuration must specify which partitions to unlock and in what order. Key recovery is more complex than full-disk because losing one partition key does not necessarily indicate the others are compromised, but all must be tracked independently.

**When it's the best choice:** When you have mixed-sensitivity data on the same physical hardware and need to isolate encryption boundaries. Useful when different departments manage different partitions, or when regulatory requirements mandate that certain data types (PHI vs billing) be cryptographically separated on the same server. Also useful when the OS partition must remain unencrypted for remote management or PXE boot, but data partitions require protection.

**Limitations:** Still susceptible to attack from within the operating system once any partition is unlocked. Requires careful partition planning during initial system setup—repartitioning an existing encrypted system is complex and risky. Multiple key prompts at boot can create operational friction for systems that reboot frequently.

**Comparison to Volume Encryption:** Partition encryption operates on a fixed layout within a single physical disk, whereas volume encryption operates on logical volumes that may span multiple physical disks. Partition encryption is simpler to set up on a single-disk system but lacks the flexibility to grow across disks. Volume encryption is better for environments where storage needs are dynamic or span RAID arrays.

**Example:** Encrypting `/var/lib/mysql` separately from `/var/www` on web servers; encrypting `/home` while leaving `/` unencrypted on shared workstations.

---

#### Volume Encryption

**Scope:** Protects a logical volume that may span multiple physical disks through LVM, RAID, or ZFS. The encryption layer sits between the physical storage and the filesystem, so the filesystem and all data within it are encrypted. Unlike partition encryption, volumes can be dynamically resized, moved between physical disks, or snapshotted without breaking encryption.

**Performance Impact:** Low-Medium overhead (~10% with AES-NI hardware acceleration). Performance characteristics depend on the underlying storage topology—volumes spanning multiple disks may have different I/O profiles than single-disk partitions. Block-level encryption means the performance penalty is consistent regardless of file type or size.

**Key Management:** Moderate complexity. One key per volume with support for multiple key slots (LUKS2 supports up to 32). Key must be available before the volume group is activated, which means boot-time key management or network-based key delivery (NBDE/Clevis) is required for volumes needed at boot. Volume encryption allows key rotation without re-encrypting data by re-encrypting only the header.

**When it's the best choice:** When managing storage pools that span multiple physical disks (SAN, NAS, LVM, ZFS pools). Ideal for virtualized environments where VM disk images are presented as logical volumes that need consistent encryption regardless of underlying hardware topology. Also suitable for database storage pools where data files may be spread across multiple devices.

**Limitations:** More complex than full-disk encryption due to the volume management layer (LVM, ZFS, RAID). Key recovery must account for volume group dependencies—if one volume in a group cannot be unlocked, dependent volumes may be inaccessible. Snapshot operations require the volume to be unlocked first.

**Comparison to Partition Encryption:** Volume encryption provides greater flexibility than partition encryption because volumes can span disks, be resized dynamically, and be snapshotted. However, this flexibility adds complexity in the volume management layer. Partition encryption is simpler and sufficient for single-disk systems with fixed storage layouts, while volume encryption is the better choice for multi-disk or dynamic storage environments.

**Example:** LUKS-encrypted LVM volumes on hypervisors, encrypted ZFS datasets on TrueNAS, NAS-01 backup volume spanning RAID array.

---

#### File-level Encryption

**Scope:** Protects individual files or directories on top of an existing filesystem. Each file is encrypted independently, meaning files can be copied, moved, or backed up while remaining encrypted. The filesystem metadata (directory structure, filenames, timestamps) may or may not be encrypted depending on the implementation.

**Performance Impact:** Medium-High. Per-file encryption adds CPU overhead on every read and write operation. Unlike block-level encryption which operates on contiguous sectors, file-level encryption must manage encryption contexts per file, leading to higher context-switching overhead. Metadata operations (directory listing, file creation) also incur penalties if filenames are encrypted.

**Key Management:** Complex. One key per file or per user namespace. Requires a file-level key management system that tracks which keys decrypt which files. For multi-user environments, keys must be distributed to authorized users and revoked when access is removed. Key rotation requires re-encrypting every affected file individually.

**When it's the best choice:** When you need granular control over individual files with different access policies. Suitable for collaborative environments where documents are shared across organizational boundaries, or when legacy applications cannot be modified for database-level encryption. Also useful when only a small subset of files on a system contain sensitive data and encrypting the entire disk is unnecessary.

**Limitations:** Metadata leakage (filenames, directory structure, file timestamps) unless the encryption system also encrypts filenames (e.g., eCryptFS with filename encryption enabled). Significant key management overhead at scale. Vulnerable to memory-based attacks where decrypted files are cached in RAM or temporary directories.

**Example:** eCryptFS for `/home` directories, GPG-encrypted medical records stored in object storage, VeraCrypt containers for sensitive document collections.

---

#### Database Encryption (Transparent Data Encryption - TDE)

**Scope:** Protects entire databases or tablespaces at the database engine level. The database files on disk are encrypted, but the database engine transparently decrypts data for authorized queries. This means the encryption persists with the database files regardless of where they are stored or moved—unlike volume encryption which is tied to a specific storage device.

**Performance Impact:** Medium. The database engine handles encryption/decryption in its query pipeline. For authorized sessions, query performance is largely unchanged because the engine caches decrypted pages in memory (buffer pool). The main overhead is on I/O operations when pages are read from or written to disk, typically 10-20% depending on workload characteristics.

**Key Management:** Complex. Keys are stored in a keystore integrated with the database engine (Oracle Wallet, SQL Server EKM, PostgreSQL pgcrypto keyring). Keys should be stored separately from the database server itself, ideally in an external HSM. Key rotation may require re-encrypting entire tablespaces, which can be a lengthy process for large databases.

**When it's the best choice:** When protecting database storage at rest while maintaining transparent access for authorized queries. Ideal for HIPAA-compliant databases where the database administrator should not have access to decrypted PHI, but clinical applications need seamless query performance. Also essential when database backups need to remain encrypted regardless of the backup destination.

**Limitations:** Does not protect against authorized queries from compromised application accounts—if the application has valid credentials, it can read all data the database exposes. Keys often stored on the same server unless integrated with external HSM. Backup files may still be encrypted but can be vulnerable if encryption keys are not properly separated.

**Example:** SQL Server TDE on billing-srv-01, PostgreSQL pgcrypto extensions on ehr-db-01, Oracle TDE on clinical databases.

---

#### Record-level Encryption

**Scope:** Protects individual fields or records within database tables (also called column-level encryption). Specific columns containing sensitive data (SSN, diagnosis codes, medication lists) are encrypted while other columns in the same table remain in plaintext. This is the finest granularity of encryption available.

**Performance Impact:** High. Each query that touches encrypted columns requires the application or database engine to decrypt individual field values. Unlike TDE which decrypts entire pages at the I/O layer, record-level encryption operates at the row/column level, causing significant latency on queries that scan large numbers of rows. Aggregate queries, joins, and indexing on encrypted columns are particularly expensive.

**Key Management:** Very Complex. Keys are tied to application logic or HSM-backed keystore and must be distributed to authorized application instances. Different fields may use different keys (e.g., SSN key separate from diagnosis key). Key rotation requires decrypting and re-encrypting every value in the affected column across all rows, which can take hours or days on large tables. Application code must handle encryption/decryption logic, increasing development complexity.

**When it's the best choice:** When regulatory requirements or security policies mandate that specific data elements be cryptographically isolated from general database access. Essential for protecting highly sensitive fields like social security numbers, mental health diagnosis codes, or HIV status where even authorized database queries should require explicit decryption. Also useful for implementing field-level access control where different roles see different subsets of encrypted data.

**Limitations:** Highest performance cost and key management complexity. Application code must handle encryption/decryption logic. Breaking changes to database schema may be required. Makes SQL analytics and reporting significantly more difficult because encrypted columns cannot be indexed or searched without special techniques (e.g., searchable encryption, blind indexes).

**Example:** AES-256 encrypted `ssn`, `mental_health_notes`, `genetic_testing` columns in patient_records table with keys managed by HSM; column-level encryption on credit card numbers in billing tables.

---

### Side-by-Side Comparison: Volume vs. Partition Encryption

| Attribute | Partition | Volume |
|---|---|---|
| **Scope** | Fixed partition within a single physical disk | Logical volume that may span multiple physical disks via LVM/RAID/ZFS |
| **Flexibility** | Fixed size; resizing requires repartitioning (risky) | Dynamic resizing; can grow across disks; supports snapshots |
| **Performance** | Identical block-level overhead (~5-15% with AES-NI); zero overhead on unencrypted partitions | Similar block-level overhead (~10% with AES-NI); performance depends on underlying storage topology |
| **Key Management** | One key per partition; separate backup/recovery per partition | One key per volume; LUKS key slots for redundancy; key needed before volume group activation |
| **Boot Complexity** | `/etc/crypttab` entry per partition; multiple unlock prompts possible | Volume group must activate before filesystems mount; may require NBDE/Clevis for network key delivery |
| **Best For** | Single-disk systems with mixed sensitivity data and fixed storage layout | Multi-disk systems, SAN/NAS, virtualized environments with dynamic storage needs |
| **Snapshot Support** | No native snapshot support; depends on filesystem (btrfs, ZFS) | LVM and ZFS volumes support native snapshots (volume must be unlocked first) |
| **Recovery** | Lose one partition key → only that partition affected | Lose volume key → entire volume group may be inaccessible if dependencies exist |

---

## Part 2 - MedDefense Encryption Level Map

### Data Store Recommendations

| Data Store | Recommended Level | Justification |
|---|---|---|
| **Patient records in PostgreSQL (ehr-db-01)** | **Database** | Database encryption (TDE) protects the entire patient database at the tablespace level, ensuring PHI remains encrypted on disk, in backups, and if storage media is stolen. This level protects against storage compromise and rogue DBA access while maintaining transparent query performance for clinical applications. The database contains thousands of records with similar sensitivity, so the high performance cost of record-level encryption is not justified across all fields. |
| **Backup data on NAS-01** | **Volume** | NAS-01 stores backup archives spanning a RAID array across multiple physical disks. Volume encryption (LUKS2) protects all backup data at rest with minimal performance overhead (~10% with AES-NI) while maintaining compatibility with existing backup software. The key is stored NOT on the NAS itself, but on HSM-01 with offline USB backup, ensuring that physical theft of the NAS does not compromise the encryption key. |
| **Financial records in MySQL (billing-srv-01)** | **Database** | Billing data in MySQL requires protection against storage theft and unauthorized database access. Database encryption (MySQL Enterprise TDE) satisfies PCI-DSS requirement 3.4 to render PAN unreadable anywhere stored, and HIPAA requirements for financial PHI. All billing fields have similar sensitivity levels, so field-level isolation is unnecessary and database-level encryption provides the right balance of protection and query performance for accounting workflows. |
| **Medical images on PACS (pacs-srv-01)** | **Volume** | DICOM images on pacs-srv-01 are stored on a multi-disk RAID array and range from 10MB to 500MB per file. Volume encryption (LUKS2) provides comprehensive protection at rest without introducing the per-file latency that file-level encryption would impose on radiologist image retrieval. The images span multiple physical disks, making volume encryption the appropriate choice over partition encryption since the storage topology is dynamic and may be expanded. |
| **Email data in O365** | **Record** | Email messages in Office 365 contain variable sensitivity: most are routine business communication, but some contain PHI in attachments or body text. Record-level encryption through Office 365 Message Encryption and Information Rights Management ensures that individual messages containing PHI are encrypted with recipient-specific keys, while routine emails remain in plaintext for productivity. This level provides the finest granularity needed for email, where selective protection of specific messages is more appropriate than encrypting the entire mailbox. |
| **Employee laptops** | **Full-disk** | Employee laptops face physical theft as the primary risk vector, whether left in cars, airports, or clinic exam rooms. Full-disk encryption (BitLocker on Windows, LUKS2 on Linux) provides maximum protection with zero user overhead once the laptop is unlocked at boot. Clinical staff should not be burdened with deciding which files to encrypt, and full-disk encryption ensures that all data—including cached emails, downloaded patient records, and temporary files—is protected if the device is stolen. |
| **BD Alaris pump firmware and configuration** | **Full-disk** | Medical IoT devices like the BD Alaris infusion pumps have limited computational resources and cannot support the overhead of database, record, or file-level encryption. Full-disk encryption protects the device's firmware, configuration settings, and audit logs against tampering and physical extraction. The encryption key is provisioned in the device's TPM or secure element during manufacturing, satisfying FDA cybersecurity guidance for medical device security while maintaining real-time medication delivery performance. |

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
| **7** | BD Alaris pump firmware and configuration | Full-disk | Biomed Team | Annual audit |

---

## Part 4 - Compliance Mapping

### Encryption Level Alignment with Regulations

| Regulation | Requirement | MedDefense Implementation |
|---|---|---|
| **HIPAA §164.312(a)(2)(iv)** | Addressable encryption of electronic PHI | ✅ Database encryption on ehr-db-01, volume encryption on NAS-01 |
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
| Partition | < 15% | ✅ Same as full-disk; only encrypted partitions affected |
| Volume | < 15% | ✅ Accepted (Task 12 measurement: 10% with AES-NI) |
| File | < 25% | ⚠️ Requires testing (e.g., PACS file access) |
| Database | < 20% | ✅ Clinical staff tolerance threshold |
| Record | < 40% | ⚠️ High-risk; limit to critical fields only |

### Key Management Requirements

| Level | Minimum Key Count | Rotation Frequency | Backup Location |
|---|---|---|---|
| Full-disk | 3 (primary + 2 recovery) | Annually | Bank safe + HSM |
| Partition | 5 (per partition) | Annually | HSM only |
| Volume | 3 (primary + 2 recovery) | Annually | Bank safe + HSM |
| File | Variable (per file/user) | Per user lifecycle | HSM + key vault |
| Database | 5 (DB + recovery slots) | Quarterly | HSM only |
| Record | 10+ (per sensitive column) | Quarterly | HSM + application secrets manager |

---

## Part 6 - Decision Tree for Encryption Level Selection

```mermaid
flowchart TD
    Start([Start]) --> TM{Primary threat model?}

    TM -->|Physical device theft| TM1[Full-disk — laptops, NAS, IoT devices]
    TM -->|Storage compromise / rogue DBA| TM2[Database TDE]
    TM -->|Specific regulated fields — SSN, genetic data| TM3[Record-level]
    TM -->|Mixed sensitivity, single-disk system| TM4[Partition]
    TM -->|Mixed sensitivity, multi-disk / dynamic storage| TM5[Volume]
    TM -->|Granular per-file access control| TM6[File-level]

    TM1 --> PI
    TM2 --> PI
    TM3 --> PI
    TM4 --> PI
    TM5 --> PI
    TM6 --> PI

    PI{Acceptable performance impact?}
    PI -->|< 15%| PI1[Full-disk, Partition, Volume]
    PI -->|< 25%| PI2[File, Database]
    PI -->|< 40%| PI3[Record — limited to critical fields]

    PI1 --> AK
    PI2 --> AK
    PI3 --> AK

    AK{Can application logic handle key management?}
    AK -->|YES| AK1[Record-level feasible]
    AK -->|NO| AK2[Database or Volume level]

    AK1 --> ST
    AK2 --> ST

    ST{Is storage fixed or dynamic?}
    ST -->|Fixed — single disk| ST1[Partition sufficient]
    ST -->|Dynamic — multi-disk, RAID, SAN| ST2[Volume required]

    ST1 --> KS
    ST2 --> KS

    KS{Are keys separable from encrypted data?}
    KS -->|YES — HSM, offline USB| KS1([Proceed])
    KS -->|NO — keys on same server| KS2([Escalate to Security Committee])

    KS1 --> Result([Implement chosen level with documented justification])
    KS2 --> Result
```

---

## Summary

MedDefense's encryption strategy assigns a single, specific encryption level to each data store based on its threat model, storage characteristics, and operational requirements:

| Data Store | Level | One-Sentence Reason |
|---|---|---|
| PostgreSQL (ehr-db-01) | Database | TDE protects all patient records at the tablespace level with transparent query performance for clinical applications. |
| NAS-01 backups | Volume | LUKS2 volume encryption spans the RAID array with minimal overhead and keys stored NOT on the NAS. |
| MySQL (billing-srv-01) | Database | TDE satisfies PCI-DSS pan-at-rest requirements while maintaining accounting query performance. |
| PACS (pacs-srv-01) | Volume | LUKS2 volume encryption across the multi-disk RAID array avoids per-file latency for large DICOM images. |
| O365 email | Record | Message-level encryption protects individual PHI-containing emails while leaving routine messages in plaintext. |
| Employee laptops | Full-disk | BitLocker/LUKS2 protects all data against physical theft with zero ongoing user interaction. |
| BD Alaris pump firmware and configuration | Full-disk | Full-disk encryption protects firmware and audit logs on resource-constrained IoT hardware meeting FDA guidance. |

This strategy satisfies HIPAA, PCI-DSS, FDA, and NIST requirements while maintaining clinical staff workflow efficiency. The key principle: **no single encryption level fits all use cases**—each data store requires deliberate selection based on its specific risk profile, storage topology, and operational constraints.
