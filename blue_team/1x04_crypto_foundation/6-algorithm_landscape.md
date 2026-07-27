# 6. The Algorithm Landscape

## Goal

Build the definitive reference table of cryptographic algorithms, mapped against MedDefense's current and recommended usage, identifying every deprecated algorithm still in production.

## Context

The Security+ exam expects you to know which algorithms are current, which are deprecated, and which are broken. More importantly, it expects you to know WHY certain algorithms are inappropriate for certain uses. This task builds the reference you will carry into the exam and into your career. Every algorithm in the table connects to something you have already seen in MedDefense.

---

## Algorithm Reference Table

### Symmetric Algorithms

| Algorithm | Key/Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|---|---|---|---|---|---|
| **AES-128** | 128 bits | Bulk data encryption, TLS sessions | ✅ Current | N/A | Acceptable for general encryption; less preferred than AES-256 for PHI |
| **AES-192** | 192 bits | Bulk data encryption | ✅ Current (rarely used) | No advantage over AES-128 or AES-256; limited hardware support historically | Not currently deployed; no planned usage |
| **AES-256** | 256 bits | Bulk data encryption at rest and in transit | ✅ Current | N/A | **Recommended primary cipher** for EHR database, billing database, PACS, backups, VPN tunnels |
| **DES** | 56 bits | Legacy block cipher | ❌ Broken | 56-bit key is exhaustively searchable in hours on modern hardware; broken since late 1990s | Not in use; must ensure no legacy systems remain |
| **3DES** | 168 bits (effective 112) | Legacy financial systems, older VPNs | ⚠️ Deprecated | NIST deprecated in 2023; vulnerable to Sweet32 birthday attack; slow performance | Potential legacy presence in billing system integrations; must be migrated to AES |
| **ChaCha20-Poly1305** | 256 bits | Mobile TLS, IoT devices without AES-NI | ✅ Current | N/A | Recommended for medical IoT devices (BD Alaris pumps, Philips monitors) lacking hardware AES acceleration |
| **RC4** | Variable (40-2048) | Legacy stream cipher | ❌ Broken | Biased keystream makes it distinguishable from random; broken since 2013 | **Currently active in Active Directory** (Finding 018); must be disabled immediately |
| **Blowfish** | 32-448 bits | Legacy file encryption | ⚠️ Legacy | 64-bit block size vulnerable to birthday attacks; superseded by AES; slow key schedule | Not in use; do not deploy |

### Asymmetric Algorithms

| Algorithm | Key/Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|---|---|---|---|---|---|
| **RSA-2048** | 2048 bits | Digital signatures, TLS certificates, key exchange | ✅ Current (minimum) | N/A | Minimum for new TLS certificates, code signing, and digital signatures |
| **RSA-4096** | 4096 bits | Long-term archival signatures, root CA | ✅ Current | N/A; overkill for general use | Use for root CA and long-term clinical trial archival signatures |
| **ECC P-256** | 256 bits | TLS key exchange, IoT authentication | ✅ Current | N/A | **Recommended** for patient portal TLS and medical device authentication; 12x smaller than equivalent RSA |
| **ECC P-384** | 384 bits | High-assurance TLS, government compliance | ✅ Current | N/A | Use for SOC 2 audit signing certificates and high-assurance compliance requirements |
| **Diffie-Hellman (DH)** | 2048+ bits | Key agreement protocol | ✅ Current (2048+) | DH without authentication is vulnerable to MITM; DH < 2048 is deprecated by NIST | Site-to-site VPN tunnels use IKEv2 with DH Group 14 (2048-bit); adequate but should migrate to ECDHE |
| **ECDHE** | 256 bits (P-256) | Ephemeral key exchange with forward secrecy | ✅ Current | N/A | **Recommended** for all TLS connections; provides forward secrecy that static DH does not |

### Hash Algorithms

| Algorithm | Key/Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|---|---|---|---|---|---|
| **MD5** | 128 bits | Legacy file checksums, legacy signatures | ❌ Broken | Practical collision attacks demonstrated since 2004; collisions generated in seconds | Must not be used for any security purpose; may exist in legacy PACS DICOM header checksums |
| **SHA-1** | 160 bits | Legacy digital signatures, Git commits | ⚠️ Deprecated | SHAttered collision demonstrated in 2017; NIST deprecated for signatures in 2011 | Patient portal TLS certificate may use SHA-1 (Finding 005); must upgrade to SHA-256 |
| **SHA-256** | 256 bits | Digital signatures, file integrity, certificate signing | ✅ Current | N/A | **Required** for all new signatures, file integrity verification, and audit log hashing |
| **SHA-512** | 512 bits | High-security signatures, password hashing | ✅ Current | N/A | Use for long-term archival signatures and PBKDF2 password derivation |
| **SHA-3** | 224/256/384/512 bits | Future-proof hashing, sponge construction | ✅ Current | N/A | No current MedDefense requirement; available as fallback if SHA-2 is compromised |

### Key Derivation Functions

| Algorithm | Key/Output Size | Primary Use Case | Status | Why Deprecated/Broken | MedDefense Usage |
|---|---|---|---|---|---|
| **PBKDF2** | Variable (derived key) | Password-based key derivation, file encryption | ✅ Current | N/A; requires high iteration count (100,000+) | Used in OpenSSL encryption scripts (Tasks 1-5); acceptable with 100,000+ iterations |
| **bcrypt** | 184 bits | Password hashing with adaptive cost | ✅ Current | N/A | Recommended for application password storage where Argon2 is unavailable |
| **Argon2** | Variable | Memory-hard password hashing | ✅ Current (recommended) | N/A | **Recommended primary** for EHR application password storage; memory-hardness stops GPU cracking |
| **scrypt** | Variable | Memory-hard KDF, cryptocurrency | ✅ Current | N/A | Not currently planned; Argon2 preferred for password storage |

---

## MedDefense Crypto Gap Analysis

Based on the cryptographic audit notes (T0) and vulnerability scan findings from 1x02, the following gaps identify where MedDefense currently uses deprecated or broken algorithms and what the specific replacement should be.

### Gap 1: RC4 Enabled in Active Directory Kerberos

| Field | Detail |
|---|---|
| **Current State** | Finding 018 (1x02) confirmed that RC4 encryption types are still enabled on domain controllers (ad-dc-01, ad-dc-02). RC4 relies on MD4/MD5 internally for Kerberos service tickets. |
| **Risk** | Attackers can perform Kerberoasting attacks, requesting RC4-encrypted service tickets and cracking them offline using rainbow tables or GPU brute force at billions of hashes per second. |
| **Deprecated Algorithm** | RC4 (broken since 2013) and MD4 (broken since 1990s) |
| **Recommended Replacement** | Enforce Kerberos AES-256 encryption type exclusively. Disable RC4 and DES on all domain controllers via Group Policy (`Network security: Configure encryption types allowed for Kerberos` → enable only AES-128 and AES-256). Audit all service accounts and update their `msDS-SupportedEncryptionTypes` attribute to AES-only. |

### Gap 2: TLS 1.0 on Patient Portal

| Field | Detail |
|---|---|
| **Current State** | Finding 005 (1x02) confirmed the patient portal (web-srv-01) supports TLS 1.0, which is vulnerable to BEAST, POODLE, and Lucky Thirteen attacks. TLS 1.3 is not supported. HSTS is not configured. |
| **Risk** | Attackers can downgrade TLS connections to 1.0 and exploit known protocol weaknesses to decrypt session traffic, exposing patient portal credentials and health information. |
| **Deprecated Algorithm** | TLS 1.0 (deprecated by IETF RFC 8996 in 2021) and associated CBC-mode cipher suites |
| **Recommended Replacement** | Upgrade Apache configuration to support TLS 1.2 and TLS 1.3 only. Disable TLS 1.0 and 1.1. Configure cipher suites to prefer `TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` for TLS 1.3, and `ECDHE-RSA-AES256-GCM-SHA384` for TLS 1.2. Enable HSTS with `max-age=31536000; includeSubDomains; preload`. |

### Gap 3: LDAP Signing Not Required

| Field | Detail |
|---|---|
| **Current State** | Finding 007 (1x02) confirmed LDAP signing is not required on domain controllers. LDAP queries and responses, including credential exchanges, traverse the network in cleartext. |
| **Risk** | Attackers on the flat network can sniff LDAP traffic, capture authentication exchanges, and perform relay attacks (similar to PetitPotam) to elevate privileges. |
| **Deprecated Algorithm** | Unauthenticated LDAP (no integrity or confidentiality) |
| **Recommended Replacement** | Enforce LDAP channel binding and LDAP signing via Group Policy (`Domain controller: LDAP server signing requirements` → Require signing). Deploy LDAPS (LDAP over TLS 1.2+) on all domain controllers. Configure all LDAP clients to require certificate validation. |

### Gap 4: Unencrypted MySQL Traffic on Billing Server

| Field | Detail |
|---|---|
| **Current State** | Crypto audit notes confirmed MySQL on billing-srv-01 is bound to 0.0.0.0 and does not enforce SSL. All billing application database connections use plaintext MySQL protocol over the flat network, exposing patient names, SSNs, insurance numbers, and credit card data. |
| **Risk** | Any attacker with network access (which the flat network provides broadly) can capture billing database queries and responses in cleartext using a packet sniffer. |
| **Deprecated Algorithm** | Plaintext MySQL protocol (no encryption) |
| **Recommended Replacement** | Enable MySQL TLS with `require_secure_transport=ON`. Configure MySQL to use TLS 1.2+ with AES-256-GCM cipher suites. Generate server certificate from internal CA, configure billing application to validate MySQL server certificate, and enforce mutual TLS authentication between billing application and database. |

### Gap 5: Unencrypted DICOM Traffic for Medical Imaging

| Field | Detail |
|---|---|
| **Current State** | Crypto audit notes confirmed all DICOM traffic between the MRI workstation (Windows XP), radiology workstations, and PACS server (pacs-srv-01) uses cleartext on ports 4242 and 11112. DICOM TLS (PS3.15) is supported but not configured. Patient identifiers in DICOM headers traverse the network unencrypted. |
| **Risk** | Any attacker on the clinical network segment can capture medical images and extract patient names, DOBs, MRNs, and study descriptions from DICOM headers in cleartext. |
| **Deprecated Algorithm** | Plaintext DICOM protocol (no encryption or integrity) |
| **Recommended Replacement** | Configure DICOM TLS on all PACS connections per DICOM PS3.15 standard. Use AES-256-GCM for encrypted DICOM transmission. Deploy certificates from internal CA to all imaging devices and PACS server. Since the Windows XP MRI workstation may not support DICOM TLS natively, isolate it in the Medical Device Zone with strict firewall rules limiting DICOM traffic to the PACS server only, and plan for device replacement at lease expiration. |

### Gap 6: NTHash (MD4) for Password Storage in Active Directory

| Field | Detail |
|---|---|
| **Current State** | Active Directory stores password hashes as NTHash, which is a single-pass MD4 hash with no salt and no key stretching. This is the default storage format for all domain accounts at MedDefense. |
| **Risk** | If an attacker extracts the NTDS.dit file (e.g., via a compromised domain admin credential), the entire password database can be cracked at billions of hashes per second using modern GPUs. Unsalted hashes mean identical passwords produce identical hashes, enabling rainbow table attacks. |
| **Deprecated Algorithm** | MD4 (broken since 1990s) and NTHash (unsalted, single-pass) |
| **Recommended Replacement** | Active Directory cannot natively replace NTHash, so compensating controls are required: (1) Enforce Kerberos AES-256 and disable RC4/DES to eliminate weak ticket encryption. (2) Deploy a Privileged Access Management (PAM) solution that stores admin passwords using Argon2id. (3) Implement a third-party credential provider for EHR application authentication that uses Argon2id or bcrypt with cost factor 12+. (4) Require 16-character minimum passwords for all domain accounts to increase cracking difficulty. (5) Enable AD Fine-Grained Password Policies for privileged accounts with 20-character minimums. |
