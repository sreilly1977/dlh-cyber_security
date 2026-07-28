# 15. The Crypto Posture Audit

## Goal

Produce a systematic, evidence-based assessment of MedDefense's entire cryptographic posture, connecting every finding to a specific risk and a specific recommendation.

## Context

You started this project with a Data Protection Map (T0) that showed where encryption was absent or weak. Since then, you have learned every primitive, inspected real certificates, built encryption scripts, analyzed TLS configurations and designed key management. Now apply everything you know to a formal audit.

---

## Part 1 - Reconstructed T0 Data Protection Map (Baseline State)

The T0 Data Protection Map identified every data store at MedDefense and its original cryptographic posture before remediation began. Cells marked **Weak** or **Absent** triggered the findings in this audit.

| Data Store | Data Category | At Rest | In Transit | In Use |
|---|---|---|---|---|
| PostgreSQL (ehr-db-01) | Patient EHR records | **Absent** (no TDE) | TLS 1.2 (adequate) | Unencrypted in buffer pool |
| NAS-01 (backup volume) | Backup archives | **Weak** (plaintext on RAID) | rsync over SSH (adequate) | N/A |
| MySQL (billing-srv-01) | Financial / billing records | **Absent** (no TDE) | TLS 1.2 (adequate) | Unencrypted in buffer pool |
| PACS (pacs-srv-01) | DICOM medical images | **Weak** (filesystem ACLs only) | DICOM TLS (weak: TLS 1.0) | Unencrypted during display |
| web-srv-01 (patient portal) | TLS session data | N/A | **Weak** (TLS 1.0/1.1 offered, SHA-1 cert chain) | Session tokens in plaintext |
| vpn-srv-01 (VPN concentrator) | VPN tunnel traffic | N/A | **Weak** (3DES/CBC, DH Group 2) | N/A |
| O365 (email) | Email messages + attachments | Microsoft-managed (opaque) | **Weak** ( Opportunistic TLS, no enforced encryption) | Plaintext in mailbox |
| Employee laptops | Cached PHI / credentials | **Absent** (no BitLocker/LUKS) | HTTPS (adequate for web apps) | Unencrypted on screen |
| BD Alaris pumps (IoT) | Firmware + audit logs | **Absent** (no encryption) | Proprietary (weak) | N/A |
| Clinical Research repository | Study protocols + consent forms | **Weak** (POSIX permissions only) | SCP/SFTP (adequate) | Unencrypted when opened |
| Internal CA (ca-srv-01) | CA private key | **Weak** (software keystore on CA server) | N/A | Key in software memory |
| HSM-01 (newly acquired) | HSM master key | N/A | mTLS to clients | Key in HSM hardware |

---

## Part 2 - Crypto Findings

Each finding corresponds to a cell in the T0 map marked **Weak** or **Absent**. Findings connect to vulnerabilities (1x02), risks (1x03), algorithm assessments (T6), encryption level recommendations (T13), and key management plans (T14).

---

### CRYPTO-001: Patient EHR Database — Encryption at Rest Absent

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-001 |
| **Data Category** | Patient EHR records (50,000 records) |
| **Data State** | At rest |
| **Current Protection** | None. PostgreSQL stores all tablespace data in plaintext on disk. No TDE, no filesystem encryption, no volume encryption beneath the database. |
| **Vulnerability Reference** | VULN-002 (from 1x02): Database files accessible to anyone with filesystem access to ehr-db-01 |
| **Risk Reference** | R-007: Database encryption key compromise / data exposure. ALE: $187,500 |
| **Algorithm Assessment** | N/A — no algorithm currently applied. T6 assessment specifies AES-256-GCM as the required symmetric cipher for PHI at rest per NIST SP 800-111. AES-256 is appropriate for long-term data retention exceeding 10 years. |
| **Recommended Protection** | PostgreSQL TDE using `pgcrypto` extension with AES-256-GCM. DEK generated on HSM, wrapped by KEK stored in HSM. Tablespaces encrypted transparently; clinical queries unaffected. |
| **Encryption Level** | Database (TDE) — per T13 recommendation |
| **Key Management** | TDE master key stored on HSM-01 (AWS CloudHSM) via PKCS#11. Quarterly key rotation. DBA never accesses plaintext key. HSM audit log records all cryptographic operations. Recovery via Shamir 3-of-5 shares. — per T14 |
| **Implementation Priority** | Immediate (Phase 1, in progress) |

---

### CRYPTO-002: Backup Storage — Volume Encryption Absent on NAS-01

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-002 |
| **Data Category** | Backup archives (full database dumps, PACS images, billing exports) |
| **Data State** | At rest |
| **Current Protection** | Weak. Backups stored on NAS-01 RAID array with POSIX filesystem permissions only. No block-level encryption. Anyone with shell access to NAS-01 can read all backup archives. Physical theft of disk array exposes all backups. |
| **Vulnerability Reference** | VULN-008 (from 1x02): Backup storage relies on filesystem ACLs with no cryptographic protection |
| **Risk Reference** | R-019: Backup encryption key lost or backups exposed. ALE: $75,000 |
| **Algorithm Assessment** | N/A — no encryption applied. T6 assessment specifies AES-256-XTS as the required mode for block device encryption. XTS mode is preferred over CBC for storage because it does not propagate errors and is designed specifically for sector-based encryption. |
| **Recommended Protection** | LUKS2 full volume encryption with AES-256-XTS. Key stored on HSM-01, delivered to NAS-01 at boot via NBDE/Clevis over mTLS. LUKS2 header backed up to offline USB in bank safe. Volume spans RAID array, protecting all physical disks uniformly. |
| **Encryption Level** | Volume — per T13 recommendation |
| **Key Management** | LUKS2 volume key stored on HSM-01 (primary). Offline USB backup with Shamir 3-of-5 shares stored in bank safe deposit box. Annual key rotation via `cryptsetup luksAddKey` / `luksKillSlot`. Key never stored on NAS-01 itself. — per T14 |
| **Implementation Priority** | Immediate (Phase 1, complete per Task 12) |

---

### CRYPTO-003: Financial Records — Database Encryption Absent on billing-srv-01

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-003 |
| **Data Category** | Financial / billing records (credit card numbers, insurance claims, payment histories) |
| **Data State** | At rest |
| **Current Protection** | None. MySQL stores all billing data in plaintext on disk. No TDE configured. Application-level encryption not implemented. PAN (Primary Account Numbers) stored in cleartext in the `payments` table. |
| **Vulnerability Reference** | VULN-005 (from 1x02): PCI-DSS violation — PAN stored in cleartext, no encryption at rest |
| **Risk Reference** | R-015: Compliance audit failure due to inadequate key management controls. ALE: $40,000. Additional exposure: PCI-DSS fines $5,000-$100,000/month until remediated. |
| **Algorithm Assessment** | N/A — no algorithm applied. T6 assessment specifies AES-256-GCM for financial data at rest per PCI-DSS 3.4 requirement to render PAN unreadable. GCM mode provides authenticated encryption, detecting tampering attempts on stored data. |
| **Recommended Protection** | MySQL Enterprise TDE with AES-256-GCM. Master key generated on HSM-01, stored in HSM keystore. All tablespaces including `payments`, `claims`, and `invoices` encrypted transparently. Query performance for accounting workflows maintained below 20% overhead threshold. |
| **Encryption Level** | Database (TDE) — per T13 recommendation |
| **Key Management** | MySQL TDE master key stored on HSM-01 (AWS CloudHSM) via PKCS#11. Quarterly key rotation. HSM enrollment approved by Finance Director + Security Engineer (dual control). — per T14 |
| **Implementation Priority** | Phase 2 (60-90 days) |

---

### CRYPTO-004: PACS Medical Images — Filesystem-Level Protection Only

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-004 |
| **Data Category** | DICOM medical images (radiology studies, 10MB-500MB per file) |
| **Data State** | At rest |
| **Current Protection** | Weak. PACS server uses filesystem ACLs (POSIX permissions) to restrict access to radiologist and technician Unix groups. No cryptographic protection. Files accessible to any process running on pacs-srv-01 with read permissions. Physical disk extraction exposes all images in cleartext. |
| **Vulnerability Reference** | VULN-010 (from 1x02): Medical images protected only by filesystem permissions; no encryption |
| **Risk Reference** | R-009: Unauthorized access to medical images via filesystem compromise. ALE: $112,500 |
| **Algorithm Assessment** | N/A — no encryption applied. T6 assessment specifies AES-256-GCM for file-level encryption of medical images. GCM mode preferred for streaming large files because it provides authenticated encryption without requiring a second pass over the data. AES-NI hardware acceleration on pacs-srv-01 reduces overhead to acceptable levels for radiologist workflows. |
| **Recommended Protection** | File-level encryption using AES-256-GCM for individual DICOM studies. Per-study keys generated and managed by HashiCorp Vault. PACS application retrieves file key from Vault via REST API at study access time. Selective encryption: studies containing PHI are encrypted; non-sensitive reference images may remain unencrypted for performance. Per-file audit trail logs which radiologist accessed which study and when. |
| **Encryption Level** | File — per T13 recommendation |
| **Key Management** | Per-study file keys stored in HashiCorp Vault (software KMS with HSM root of trust). PACS application authenticates to Vault via AppRole. Key lifecycle tied to study retention (7 years per HIPAA). No bulk rotation needed. — per T14 |
| **Implementation Priority** | Phase 2 (60-90 days) |

---

### CRYPTO-005: Patient Portal TLS Configuration — Weak Cipher Suites and Legacy Protocols

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-005 |
| **Data Category** | Patient portal session data (login credentials, appointment data, messaging) |
| **Data State** | In transit |
| **Current Protection** | Weak. web-srv-01 offers TLS 1.0, 1.1, and 1.2. TLS 1.0 and 1.1 are deprecated (RFC 8996). Server accepts weak cipher suites including `TLS_RSA_WITH_3DES_EDE_CBC_SHA` and `TLS_RSA_WITH_AES_128_CBC_SHA`. Certificate chain includes a SHA-1 intermediate certificate. Forward secrecy is not enforced because RSA key exchange is accepted. |
| **Vulnerability Reference** | VULN-001 (from 1x02): Web server offers deprecated TLS protocols and weak cipher suites |
| **Risk Reference** | R-003: Man-in-the-middle attack on patient portal via protocol downgrade. ALE: $94,500 |
| **Algorithm Assessment** | T6 assessment identifies RSA key exchange without forward secrecy as inadequate. SHA-1 in the certificate chain is cryptographically broken (SHAttered attack, 2017). 3DES is deprecated per NIST SP 800-131A (effective 2023). CBC mode is vulnerable to padding oracle attacks (Lucky 13, POODLE). TLS 1.0/1.1 are formally deprecated. |
| **Recommended Protection** | TLS 1.3 only (TLS 1.2 minimum as fallback with strict cipher list). Cipher suites: `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` for TLS 1.3. For TLS 1.2 fallback: `ECDHE-RSA-AES256-GCM-SHA384` with P-384 curve only. Disable RSA key exchange; enforce ECDHE for forward secrecy. Replace SHA-1 intermediate with SHA-256 certificate chain. HSTS header with `max-age=31536000; includeSubDomains; preload`. |
| **Encryption Level** | N/A (transport-layer encryption, not a data-at-rest level) |
| **Key Management** | TLS RSA-2048 private key stored on HSM-01. Key generated on HSM, CSR submitted to DigiCert. Annual rotation (398-day max per CA/B Forum). HSM retains key copy; web server stores key file with 600 permissions. — per T14 |
| **Implementation Priority** | Immediate (Phase 1, complete per Task 10) |

---

### CRYPTO-006: VPN Tunnel — Weak IKE/IPsec Parameters

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-006 |
| **Data Category** | VPN tunnel traffic (inter-site communication, remote clinician access to EHR) |
| **Data State** | In transit |
| **Current Protection** | Weak. vpn-srv-01 uses IPsec with IKEv1 Phase 1 parameters: 3DES encryption, SHA-1 integrity, Diffie-Hellman Group 2 (MODP 1024-bit). Phase 2 uses ESP with 3DES-CBC. 3DES provides only 112 bits of effective security (well below the 128-bit minimum per NIST SP 800-131A). DH Group 2 is vulnerable to precomputation attacks by nation-state actors. |
| **Vulnerability Reference** | VULN-003 (from 1x02): VPN concentrator uses deprecated 3DES cipher and weak DH group |
| **Risk Reference** | R-005: VPN tunnel decryption by attacker with precomputed DH tables. ALE: $67,500 |
| **Algorithm Assessment** | T6 assessment identifies 3DES as deprecated with effective key strength of 112 bits (below 128-bit minimum). SHA-1 is broken for collision resistance. DH Group 2 (1024-bit MODP) is below the 2048-bit minimum per NIST SP 800-57. CBC mode is vulnerable to padding oracle attacks. |
| **Recommended Protection** | Upgrade to IKEv2. Phase 1: AES-256-GCM, SHA-384, DH Group 19 (ECDH 256-bit) or Group 21 (ECDH 521-bit). Phase 2 ESP: AES-256-GCM with PFS using DH Group 19. Disable IKEv1 entirely. Perfect forward secrecy enforced on all tunnels. Pre-shared key replaced with certificate-based authentication using ECDSA P-256 certificates issued by internal CA. |
| **Encryption Level** | N/A (transport-layer encryption) |
| **Key Management** | VPN IPsec PSK stored in HashiCorp Vault (software KMS). Semi-annual rotation via Ansible playbook pushing new PSK to vpn-srv-01 and remote clients via MDM. Future migration to certificate-based auth using internal CA private key stored on HSM-01. — per T14 |
| **Implementation Priority** | Immediate (Phase 1, complete per Task 10) |

---

### CRYPTO-007: Email Messages — No Enforced Encryption for PHI-Containing Messages

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-007 |
| **Data Category** | Email messages and attachments (mixed: routine business + PHI-containing clinical correspondence) |
| **Data State** | In transit and at rest |
| **Current Protection** | Weak. Office 365 uses opportunistic TLS, meaning messages may fall back to plaintext if the receiving server does not support TLS. No mail flow rule enforces encryption for messages containing PHI. No Information Rights Management (IRM) applied. Emails containing PHI sent to external recipients may traverse the internet in cleartext. |
| **Vulnerability Reference** | VULN-012 (from 1x02): No email encryption policy; PHI sent externally without encryption |
| **Risk Reference** | R-011: PHI exposure via unencrypted email transmission. ALE: $56,250 |
| **Algorithm Assessment** | N/A — no encryption algorithm applied to messages. T6 assessment specifies AES-256-GCM for message-level encryption via Office 365 Message Encryption (OME), which uses Azure Information Protection (AIP) with AES-256-CBC for message body and attachments. |
| **Recommended Protection** | Office 365 Message Encryption (OME) with Azure Information Protection. Mail flow rules detect PHI indicators (ICD-10 codes, "patient," diagnosis terms, SSN patterns) and automatically apply encryption. Recipients access messages through OME portal with Azure AD authentication. IRM policies prevent forwarding, printing, and copying of encrypted messages. Routine business emails remain unencrypted for productivity. |
| **Encryption Level** | Record — per T13 recommendation |
| **Key Management** | Microsoft-managed keys within Azure Key Vault (FIPS 140-2 Level 1). For enhanced control: Customer Managed Keys (CMK) in Azure Key Vault backed by MedDefense's HSM-01 via BYOK. Key rotation managed by Microsoft (automatic) or by Steve (CMK). — per T14 |
| **Implementation Priority** | Phase 2 (60-90 days) |

---

### CRYPTO-008: Employee Laptops — No Full-Disk Encryption

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-008 |
| **Data Category** | Cached PHI, email attachments, credentials, VPN configs on employee laptops |
| **Data State** | At rest |
| **Current Protection** | Absent. Employee laptops (120 Windows devices, 15 macOS devices) have no full-disk encryption. BitLocker not enabled on Windows. FileVault not enabled on macOS. BIOS passwords not uniformly set. Disk contents readable by removing drive and attaching to another machine. |
| **Vulnerability Reference** | VULN-015 (from 1x02): Laptop disk encryption not enforced; devices contain cached PHI |
| **Risk Reference** | R-002: Physical theft of laptop with unencrypted PHI. ALE: $150,000 |
| **Algorithm Assessment** | N/A — no encryption applied. T6 assessment specifies AES-256-XTS for full-disk encryption per NIST SP 800-111. XTS mode is the NIST-approved mode for storage encryption. AES-128-XTS provides equivalent security to AES-256-XTS for disk encryption; AES-256 preferred for long-term retention sensitivity. |
| **Recommended Protection** | BitLocker (Windows) with AES-256-XTS, TPM 2.0 binding, and recovery key escrow in Active Directory. FileVault 2 (macOS) with AES-256-XTS and institutional recovery key. Enforce via Group Policy (Windows) and MDM (macOS). Recovery keys escrowed to both on-premise AD and HashiCorp Vault for redundancy. |
| **Encryption Level** | Full-disk — per T13 recommendation |
| **Key Management** | BitLocker VMK sealed by TPM 2.0 on each laptop. Recovery keys escrowed to Active Directory (primary) and HashiCorp Vault (secondary). TPM firmware updated to mitigate known vulnerabilities (CVE-2017-15361 for AMD fTPM). No manual key rotation needed—TPM binding provides per-boot key freshness. — per T14 |
| **Implementation Priority** | Immediate (Phase 1, complete) |

---

### CRYPTO-009: BD Alaris Pump Firmware — No Encryption on IoT Medical Devices

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-009 |
| **Data Category** | Infusion pump firmware, drug library configuration, audit logs |
| **Data State** | At rest |
| **Current Protection** | Absent. BD Alaris infusion pumps store firmware, drug library configurations, and infusion audit logs in unencrypted flash memory. Physical access to the device allows firmware extraction and audit log tampering. No secure boot mechanism verified. |
| **Vulnerability Reference** | VULN-018 (from 1x02): Medical IoT devices lack encryption; firmware and audit logs tamper-accessible |
| **Risk Reference** | R-014: Medical device tampering leading to patient safety incident. ALE: $225,000 |
| **Algorithm Assessment** | N/A — no encryption applied. T6 assessment specifies AES-256-XTS or AES-128-XTS for full-disk encryption on IoT devices, constrained by device computational resources. Given the limited CPU on the Alaris pumps, AES-128-XTS with hardware acceleration may be the practical maximum. NIST SP 800-131A permits AES-128 for devices where AES-256 is not computationally feasible. |
| **Recommended Protection** | Full-disk encryption of device flash storage using AES-128-XTS (resource-constrained). Firmware signed with RSA-4096 or ECDSA P-384 and verified at boot (secure boot). Audit logs written to encrypted append-only storage. Key provisioned in device TPM or secure element during manufacturing or clinical engineering provisioning. Meets FDA premarket cybersecurity guidance (Section 524B of FD&C Act). |
| **Encryption Level** | Full-disk — per T13 recommendation |
| **Key Management** | Device-specific key provisioned in TPM or secure element during clinical engineering provisioning. Key recovery via BD service console with manufacturer-held escrow key. Annual firmware signature key rotation by BD. Device key rotation during scheduled maintenance. — per T14 |
| **Implementation Priority** | Phase 3 (Annual review, coordinated with Biomed team and BD vendor) |

---

### CRYPTO-010: Clinical Research Repository — Filesystem Permissions Only

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-010 |
| **Data Category** | Study protocols, patient consent forms, trial data (shared across research teams with varying access rights) |
| **Data State** | At rest |
| **Current Protection** | Weak. Clinical Research document repository uses POSIX filesystem permissions (`chmod 750`) to control access. Researchers with shell access can read all documents regardless of team assignment. No per-document encryption. No audit trail for document access. Files copied to USB or emailed leave the access control boundary. |
| **Vulnerability Reference** | VULN-014 (from 1x02): Research repository uses filesystem ACLs; no per-document encryption or audit trail |
| **Risk Reference** | R-017: Research data exposure via shared filesystem access. ALE: $33,750 |
| **Algorithm Assessment** | N/A — no encryption applied. T6 assessment specifies AES-256-GCM for file-level encryption of research documents. GCM mode provides authenticated encryption ensuring document integrity. Per-document keys enable granular access control beyond what filesystem permissions provide. |
| **Recommended Protection** | File-level encryption using GPG or eCryptFS with AES-256-GCM. Per-document keys managed by HashiCorp Vault. Researcher access mediated by Vault policy tied to Active Directory group membership. Documents encrypted at rest and remain encrypted when transferred (GPG containers). Filename encryption enabled (eCryptFS) to prevent metadata leakage. Per-file audit trail in Vault logs. |
| **Encryption Level** | File — per T13 recommendation |
| **Key Management** | Per-document keys stored in HashiCorp Vault. Researcher access via Vault LDAP auth backend (tied to AD groups). Key lifecycle tied to study duration. Old keys retained 7 years post-study per IRB requirements. — per T14 |
| **Implementation Priority** | Phase 3 (Annual, coincides with IRB audit cycle) |

---

### CRYPTO-011: Internal CA Private Key — Software Keystore on CA Server

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-011 |
| **Data Category** | Internal Certificate Authority private key (root and intermediate CA keys) |
| **Data State** | At rest |
| **Current Protection** | Weak. CA private key stored in OpenSSL software keystore on ca-srv-01. Key is protected by a passphrase, but the key file is on the same server that issues certificates. Anyone with root access to ca-srv-01 can extract the CA private key from memory or from the keystore. No hardware protection. No tamper detection. |
| **Vulnerability Reference** | VULN-007 (from 1x02): CA private key stored in software; root compromise of CA server exposes all certificates |
| **Risk Reference** | R-020: CA private key compromise enabling rogue certificate issuance. ALE: $135,000 |
| **Algorithm Assessment** | Current CA key is RSA-2048. T6 assessment notes RSA-2048 remains acceptable through 2030 per NIST SP 800-57, but ECDSA P-384 is preferred for new CAs due to smaller key sizes and faster operations. The issue here is not the algorithm but the storage mechanism—software keystore vs. hardware HSM. |
| **Recommended Protection** | Generate new CA key pair on HSM-01 (ECDSA P-384). Key never leaves HSM in plaintext. All certificate signing operations performed on HSM via PKCS#11. Decommission software keystore. Existing RSA-2048 certificates continue to validate until natural expiry, then reissued from new ECDSA CA. Root CA key offline except during signing ceremonies. |
| **Encryption Level** | N/A (CA key management, not data encryption level) |
| **Key Management** | CA private key generated and stored exclusively on HSM-01. Root CA key marked as non-exportable. Intermediate CA key accessible via PKCS#11 for automated certificate issuance. Signing ceremonies require dual control (Steve + IT Director). — per T14 |
| **Implementation Priority** | Phase 2 (60-90 days, after HSM-01 is operational) |

---

### CRYPTO-012: PACS DICOM TLS — Weak Transport Encryption

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-012 |
| **Data Category** | DICOM image transfers between modalities (CT, MRI), PACS server, and radiologist workstations |
| **Data State** | In transit |
| **Current Protection** | Weak. DICOM TLS configured with TLS 1.0 and `SSL_RSA_WITH_3DES_EDE_CBC_SHA`. No forward secrecy. Some modalities transmit DICOM without TLS entirely (cleartext over hospital network). No mutual TLS between modalities and PACS server—server identity not verified by modalities. |
| **Vulnerability Reference** | VULN-016 (from 1x02): DICOM transport uses TLS 1.0 with 3DES; some modalities unencrypted |
| **Risk Reference** | R-009: Network sniffing of medical images on hospital LAN. ALE: $45,000 |
| **Algorithm Assessment** | T6 assessment identifies TLS 1.0 as deprecated (RFC 8996). 3DES is deprecated per NIST SP 800-131A (effective 2023). RSA key exchange provides no forward secrecy. CBC mode vulnerable to padding oracle attacks. |
| **Recommended Protection** | DICOM TLS upgraded to TLS 1.2 minimum with `ECDHE-RSA-AES256-GCM-SHA384`. Mutual TLS enforced: both modalities and PACS server present certificates. Modalities issued client certificates from internal CA (CRYPTO-011 remediation). No cleartext DICOM permitted—enforce via network policy on hospital switches. TLS 1.3 if supported by modality firmware. |
| **Encryption Level** | N/A (transport-layer encryption) |
| **Key Management** | Modality client certificates issued by internal CA (key on HSM-01 per CRYPTO-011). PACS server TLS certificate uses RSA-2048 key on HSM-01. Certificate rotation annual. — per T14 |
| **Implementation Priority** | Phase 2 (60-90 days, coordinated with modality firmware updates) |

---

### CRYPTO-013: Patient Portal Session Data — No Encryption of Session Tokens at Rest

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-013 |
| **Data Category** | Session tokens, JWT refresh tokens, cached authentication state on web-srv-01 |
| **Data State** | At rest (on web server disk and in session store) |
| **Current Protection** | Weak. Session tokens stored in plaintext in Redis session store and in log files. JWT refresh tokens stored in application configuration files with 644 permissions. Log files containing Authorization headers are not redacted. Server compromise exposes all active session tokens. |
| **Vulnerability Reference** | VULN-004 (from 1x02): Session tokens stored in plaintext; logs contain authorization headers |
| **Risk Reference** | R-006: Session hijacking via token extraction from compromised web server. ALE: $51,000 |
| **Algorithm Assessment** | N/A — no encryption of session data at rest. T6 assessment specifies AES-256-GCM for encrypting session token stores. JWT signing should use RS256 (RSA-SHA256) or ES256 (ECDSA-SHA256), not HS256 (HMAC-SHA256), to separate signing authority from verification. |
| **Recommended Protection** | Encrypt Redis session store with AES-256-GCM using key from HashiCorp Vault. Redact Authorization headers from all log files via log formatter. JWT refresh tokens signed with ES256 (ECDSA P-256), key on HSM-01. Session token encryption at application layer using Vault Transit engine (Vault performs encryption/decryption; application never sees key). |
| **Encryption Level** | Record (application-level field encryption of session data) |
| **Key Management** | Session encryption key in HashiCorp Vault Transit engine. JWT signing key (ECDSA P-256) on HSM-01. Quarterly rotation for session key; annual for JWT signing key. Application authenticates to Vault via AppRole. — per T14 |
| **Implementation Priority** | Phase 2 (60-90 days) |

---

## Part 3 - Finding Summary Matrix

| Finding ID | Data Category | State | Severity | Priority | Status |
|---|---|---|---|---|---|
| CRYPTO-001 | Patient EHR records | At rest | Critical | Immediate | 🔄 In progress |
| CRYPTO-002 | Backup archives | At rest | Critical | Immediate | ✅ Complete |
| CRYPTO-003 | Financial / billing records | At rest | Critical | Phase 2 | ⏳ Pending |
| CRYPTO-004 | DICOM medical images | At rest | High | Phase 2 | ⏳ Pending |
| CRYPTO-005 | Portal TLS sessions | In transit | High | Immediate | ✅ Complete |
| CRYPTO-006 | VPN tunnel traffic | In transit | High | Immediate | ✅ Complete |
| CRYPTO-007 | Email messages | At rest / transit | High | Phase 2 | ⏳ Pending |
| CRYPTO-008 | Employee laptop data | At rest | Critical | Immediate | ✅ Complete |
| CRYPTO-009 | BD Alaris pump firmware | At rest | Critical | Phase 3 | ⏳ Pending |
| CRYPTO-010 | Clinical Research documents | At rest | Medium | Phase 3 | ⏳ Pending |
| CRYPTO-011 | Internal CA private key | At rest | Critical | Phase 2 | ⏳ Pending |
| CRYPTO-012 | DICOM image transfers | In transit | High | Phase 2 | ⏳ Pending |
| CRYPTO-013 | Portal session tokens | At rest | Medium | Phase 2 | ⏳ Pending |

---

## Part 4 - Posture Score

### Remediation Coverage Assessment

| Category | Total Findings | Findings with Clear Remediation Path | Coverage |
|---|---|---|---|
| Data at rest | 8 | 8 | 100% |
| Data in transit | 4 | 4 | 100% |
| Data in use | 1 (session tokens) | 1 | 100% |
| **Overall** | **13** | **13** | **100%** |

### Implementation Status

| Status | Count | Percentage |
|---|---|---|
| ✅ Complete | 4 | 31% |
| 🔄 In progress | 1 | 8% |
| ⏳ Pending (Phase 2) | 6 | 46% |
| ⏳ Pending (Phase 3) | 2 | 15% |
| No remediation path | 0 | 0% |

### Key Performance Indicators

| Metric | Value | Change | Status |
|---|---|---|---|
| Remediation Coverage | 100% | All 13 findings have clear path | ✅ Up |
| Findings Remediated | 4 / 13 | 31% complete | ✅ Up |
| Critical Findings Open | 3 | CRYPTO-001, 003, 009, 011 | ➡️ Flat |
| Total ALE Addressed | $1.49M | Across all 13 findings | ✅ Up |

## Posture Score

100% of MedDefense's data flows now have a clear remediation path. Every finding identified in the T0 Data Protection Map has been connected to a specific vulnerability reference, risk reference, algorithm assessment, recommended protection, encryption level, key management plan, and implementation priority. Four findings are fully remediated, one is in progress, and eight are scheduled across Phases 2 and 3.

The remaining gap is execution, not strategy. No data flow lacks a defined remediation path.

## Part 5 — Top 3 Crypto Risks

Ranked by combined impact (ALE × severity × breadth of data affected):

### Finding: CRYPTO-001 — Patient EHR Database Encryption Gap

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-001 |
| **Title** | Patient EHR — No At-Rest Encryption |
| **Severity** | 🔴 Critical |
| **Description** | 50,000 patient records stored in plaintext PostgreSQL with no TDE. Any filesystem-level compromise exposes the entire patient population. |
| **ALE (Annualized Loss Expectancy)** | $187,500 |
| **Remediation** | PostgreSQL TDE with AES-256-GCM, HSM-backed key management |
| **Status** | 🔄 In progress (Phase 1) |```

# Part 5 - Top 3 Crypto Risks

Ranked by combined impact (ALE × severity × breadth of data affected):

---

## Rank 1: CRYPTO-001 — Patient EHR Database Without Encryption at Rest

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-001 |
| **Severity** | Critical |
| **Description** | 50,000 patient records stored in plaintext PostgreSQL with no TDE. Any filesystem-level compromise exposes the entire patient population. |
| **ALE** | $187,500 |
| **Remediation** | PostgreSQL TDE with AES-256-GCM, HSM-backed key management |
| **Status** | In progress (Phase 1) |

### Why This Ranks #1

This finding has the highest ALE ($187,500), affects the largest single dataset (50,000 patient records), and represents the core HIPAA compliance requirement. Every other system in MedDefense ultimately traces back to the EHR database—backups contain copies of this data, the portal displays this data, and clinicians access it via VPN. If the EHR is unencrypted, the entire data protection strategy has a hole at its center. The remediation is straightforward (database TDE) but must be executed carefully to avoid clinical downtime.

---

## Rank 2: CRYPTO-009 — BD Alaris Pump Firmware Without Encryption

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-009 |
| **Severity** | Critical |
| **Description** | Infusion pump firmware, drug libraries, and audit logs stored in unencrypted flash memory. Physical tampering enables firmware modification and audit log deletion. Patient safety risk. |
| **ALE** | $225,000 |
| **Remediation** | Full-disk encryption, signed firmware, secure boot |
| **Status** | Phase 3, pending vendor coordination |

### Why This Ranks #2

While the ALE is technically higher than CRYPTO-001 ($225,000 vs. $187,500), it ranks second because the remediation is constrained by vendor capability (BD must support encrypted firmware on the pumps) and the implementation timeline is longer (Phase 3, annual review cycle). However, this finding is uniquely dangerous because it involves patient safety, not just data confidentiality. Tampered firmware could deliver incorrect medication doses, making this a life-safety issue in addition to a data protection issue. FDA cybersecurity guidance under Section 524B of the FD&C Act makes this a regulatory imperative as well.

---

## Rank 3: CRYPTO-011 — Internal CA Private Key in Software Keystore

| Field | Value |
|---|---|
| **Finding ID** | CRYPTO-011 |
| **Severity** | Critical |
| **Description** | Root and intermediate CA private keys stored in OpenSSL software keystore on ca-srv-01. Root compromise of the CA server enables rogue certificate issuance for any MedDefense system. |
| **ALE** | $135,000 |
| **Remediation** | Generate CA keys on HSM-01, migrate to PKCS#11 signing |
| **Status** | Phase 2 |

### Why This Ranks #3

The ALE is $135,000, but the blast radius is enormous. If the CA private key is compromised, an attacker can issue valid certificates for any MedDefense system, enabling persistent man-in-the-middle attacks that would bypass TLS protections on the patient portal (CRYPTO-005), the PACS DICOM transport (CRYPTO-012), and the VPN (CRYPTO-006). This makes CRYPTO-011 a force multiplier: its compromise cascades into multiple other findings. The remediation (move CA key to HSM) is technically simple but operationally complex because it requires reissuing all internal certificates. Prioritizing this in Phase 2 strengthens the foundation for all transport-layer encryption across MedDefense.

---

## ALE by Implementation Phase

Phase 1 (complete/in-progress) covers $532.5K ALE; remaining $955.5K in Phases 2-3

| Finding | ALE ($) | Phase | Status |
|---|---|---|---|
| CRYPTO-009 Alaris IoT | 225,000 | Phase 3 | Pending |
| CRYPTO-001 EHR DB | 187,500 | Phase 1 | In Progress |
| CRYPTO-008 Laptops FDE | 150,000 | Phase 1 | Complete ✅ |
| CRYPTO-011 CA Key | 135,000 | Phase 2 | Pending |
| CRYPTO-004 PACS Images | 112,500 | Phase 2 | Pending |
| CRYPTO-005 Portal TLS | 94,500 | Phase 1 | Complete ✅ |
| CRYPTO-002 NAS Backups | 75,000 | Phase 1 | Complete ✅ |
| CRYPTO-006 VPN Tunnels | 67,500 | Phase 1 | Complete ✅ |
| CRYPTO-007 Email O365 | 56,250 | Phase 2 | Pending |
| CRYPTO-013 Session Tokens | 51,000 | Phase 2 | Pending |
| CRYPTO-012 DICOM TLS | 45,000 | Phase 2 | Pending |
| CRYPTO-003 Billing DB | 40,000 | Phase 2 | Pending |
| CRYPTO-010 Research Repo | 33,750 | Phase 3 | Pending |

**Summary:**
- **Phase 1 Total:** $532,500 (4 complete, 1 in progress)
- **Phase 2 Total:** $384,750 (6 pending)
- **Phase 3 Total:** $258,750 (2 pending)
- **Grand Total:** $1,176,000 across all phases

# Crypto Posture Audit Summary

13 findings identified across at-rest, in-transit, and in-use data states. 100% of findings have a defined remediation path connecting vulnerability, risk, algorithm assessment, encryption level, key management, and implementation priority.

- **4 findings complete** (31%)
- **1 in progress** (8%)
- **8 pending across Phases 2-3** (62%)
- **Total ALE addressed across all findings**: $1,488,000

**Top 3 risks:**
1. CRYPTO-001 (EHR database, $187.5K ALE)
2. CRYPTO-009 (BD Alaris firmware, $225K ALE)
3. CRYPTO-011 (CA private key, $135K ALE)

The posture gap is now execution, not strategy.

---

## Appendix - Cross-Reference Index

| Finding ID | Vulnerability Ref (1x02) | Risk Ref (1x03) | Algorithm Ref (T6) | Encryption Level (T13) | Key Mgmt (T14) |
|---|---|---|---|---|---|
| CRYPTO-001 | VULN-002 | R-007 ($187.5K) | AES-256-GCM | Database (TDE) | HSM-01 PKCS#11 |
| CRYPTO-002 | VULN-008 | R-019 ($75K) | AES-256-XTS | Volume (LUKS2) | HSM-01 + offline USB |
| CRYPTO-003 | VULN-005 | R-015 ($40K) | AES-256-GCM | Database (TDE) | HSM-01 PKCS#11 |
| CRYPTO-004 | VULN-010 | R-009 ($112.5K) | AES-256-GCM | File | Vault KMS |
| CRYPTO-005 | VULN-001 | R-003 ($94.5K) | TLS 1.3, ECDHE | N/A (transport) | HSM-01 TLS key |
| CRYPTO-006 | VULN-003 | R-005 ($67.5K) | AES-256-GCM, IKEv2 | N/A (transport) | Vault KMS (PSK) |
| CRYPTO-007 | VULN-012 | R-011 ($56.25K) | AES-256-CBC (OME) | Record | Azure Key Vault / CMK |
| CRYPTO-008 | VULN-015 | R-002 ($150K) | AES-256-XTS | Full-disk | TPM 2.0 + AD escrow |
| CRYPTO-009 | VULN-018 | R-014 ($225K) | AES-128-XTS (constrained) | Full-disk | Device TPM / BD escrow |
| CRYPTO-010 | VULN-014 | R-017 ($33.75K) | AES-256-GCM | File | Vault KMS (LDAP auth) |
| CRYPTO-011 | VULN-007 | R-020 ($135K) | ECDSA P-384 | N/A (CA key) | HSM-01 (non-exportable) |
| CRYPTO-012 | VULN-016 | R-009 ($45K) | TLS 1.2+, ECDHE-AES256-GCM | N/A (transport) | HSM-01 (CA + TLS) |
| CRYPTO-013 | VULN-004 | R-006 ($51K) | AES-256-GCM, ES256 | Record (app-layer) | Vault Transit engine |

---

**Total ALE across all findings: $1,488,000**

---
