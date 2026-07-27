# 0. The Crypto Inventory

## Goal

Map every data flow at MedDefense against its current cryptographic protection state, exposing every gap in one document.

## Context

Before you can fix MedDefense's cryptographic posture, you need to see the full picture in one place. The vulnerability findings from 1x02 identified individual crypto weaknesses (TLS 1.0 on the portal, unencrypted backups, cleartext DICOM). The risk register in 1x03 tracked some of these as risks. But nobody has produced a systematic inventory that maps every category of data, in every state, to its current level of protection. This is the document that makes the invisible visible. When you finish, every cell where it says "None" is a gap that the rest of this project will address.

---

## Data Protection Map

| Data Category | At Rest | In Transit | In Use |
|---|---|---|---|
| **Patient medical records** (EHR / PostgreSQL on ehr-db-01) | **Protection:** None. PostgreSQL data directory on unencrypted ext4 filesystem. If root access or physical drive removal occurs, all patient records are readable in plaintext. **Evidence:** Crypto audit notes, PATIENT DATA section. No 1x02 finding referenced (gap not previously scanned for). **Status:** Absent | **Protection:** Partial. PostgreSQL ssl=on configured, but pg_hba.conf contains "hostnossl" entries allowing non-SSL connections from 10.10.0.0/16. No mechanism to confirm which connections use encryption. **Evidence:** Crypto audit notes, PATIENT DATA section, Encryption in transit. **Status:** Weak | **Protection:** None. Records are decrypted in memory on ehr-srv-01 and transmitted to browser. Nurse station workstations have screensaver timeout set to "Never" in Group Policy, leaving patient data visible on screen indefinitely. **Evidence:** Crypto audit notes, PATIENT DATA section, Encryption in use. **Status:** Absent |
| **Financial / billing data** (MySQL on billing-srv-01) | **Protection:** None. MySQL data directory on unencrypted ext4 filesystem. Database contains patient names, DOBs, SSNs, insurance policy numbers, credit card last-4 digits, and 3 years of billing records. Crypto-miner incident responder confirmed all database files were readable from filesystem without MySQL credentials. **Evidence:** Crypto audit notes, FINANCIAL DATA section. References 1x00 crypto-miner forensic review. **Status:** Absent | **Protection:** None. MySQL bound to 0.0.0.0 and does not enforce SSL. Billing application connects via plaintext MySQL protocol over the flat network. All billing data transmits in cleartext. **Evidence:** Crypto audit notes, FINANCIAL DATA section, Encryption in transit. **Status:** Absent | **Protection:** None. No mention of application-level encryption for billing data in use. Billing clerks access financial data through a web application with no documented session encryption or screen-lock enforcement. **Evidence:** Crypto audit notes (no In Use section documented for billing, indicating absence). **Status:** Absent |
| **Medical images** (DICOM on PACS / pacs-srv-01) | **Protection:** None. PACS stores images on local disk without encryption. DICOM files contain embedded patient identifiers (name, DOB, MRN, study description) readable with any DICOM viewer or text editor (header is partially plaintext). **Evidence:** Crypto audit notes, MEDICAL IMAGES section, Storage. **Status:** Absent | **Protection:** None. DICOM protocol on ports 4242 and 11112 transmits between MRI workstation (Windows XP), radiology workstations, and PACS server in cleartext. DICOM TLS (PS3.15) is supported but not configured on any MedDefense system. All imaging data including patient identifiers in DICOM headers traverse the network unencrypted. **Evidence:** Crypto audit notes, MEDICAL IMAGES section, DICOM traffic. **Status:** Absent | **Protection:** None. DICOM images are viewed on radiology workstations with no documented in-use protection. Patient identifiers embedded in image headers are displayed and accessible during active viewing sessions. **Evidence:** Crypto audit notes (no In Use section documented for PACS, indicating absence). **Status:** Absent |
| **Credentials** (Active Directory on ad-dc-01 / ad-dc-02) | **Protection:** Mixed. Active Directory stores passwords as NTHash (MD4) by default for NTLM compatibility. Kerberos supports AES-256, AES-128, RC4, and DES encryption types. DES and RC4 remain enabled, enabling Kerberoasting attacks against RC4 service tickets (crackable offline). DES is trivially breakable. No documentation exists for which systems require legacy algorithms. **Evidence:** 1x02 Finding 018. Crypto audit notes, CREDENTIALS section. **Status:** Weak | **Protection:** Weak. LDAP is not encrypted by default and LDAP signing is not required on domain controllers. Kerberos authentication supports weak encryption types (DES, RC4) alongside strong ones (AES-256). Attackers on the flat network can intercept LDAP queries and responses in cleartext. **Evidence:** 1x02 Finding 007. Crypto audit notes, CREDENTIALS section, LDAP. **Status:** Weak | **Protection:** None. No documented protection for credentials in active use. Authentication tokens and session tickets processed in memory without additional safeguards. Screens do not lock, leaving authenticated sessions exposed. **Evidence:** Crypto audit notes (no In Use section documented for credentials, indicating absence). Screensaver timeout set to "Never" per Group Policy. **Status:** Absent |
| **Backup data** (Synology NAS-01) | **Protection:** None. NAS stores all backup data on RAID-5 array with no encryption layer. NAS management interface (DSM) accessible over the flat network. Database dumps from PostgreSQL and MySQL stored in plaintext. Synology shared folder encryption (AES-256-CBC) is available but not enabled. Sarah Park notes the design flaw: if key is stored on the NAS and ransomware encrypts the NAS, both backups and key are lost. **Evidence:** 1x02 Finding 015 (DSM accessible). Crypto audit notes, BACKUP DATA section. **Status:** Absent | **Protection:** None. Backup data transfers from database servers to NAS-01 occur over the flat network without encryption. Database dumps traverse the network in cleartext during backup operations. **Evidence:** Crypto audit notes, BACKUP DATA section (NAS accessible on flat network per Finding 015). No encryption documented for backup transfer. **Status:** Absent | **Protection:** N/A. Backup data is not actively processed in a user-facing manner. Restoration processes load data from NAS to target systems, inheriting the target system's encryption posture (currently none). **Evidence:** Not applicable based on audit notes. **Status:** N/A |
| **Email** (Microsoft 365 / Exchange Online) | **Protection:** BitLocker on Microsoft datacenter disks plus per-mailbox encryption using Microsoft-managed keys. Encryption is handled entirely by Microsoft's infrastructure. **Evidence:** Crypto audit notes, EMAIL section, At rest. **Status:** Adequate | **Protection:** TLS 1.2 enforced for all Exchange Online connections (Microsoft enforced in 2023). **Evidence:** Crypto audit notes, EMAIL section, In transit. **Status:** Adequate | **Protection:** None. S/MIME and Office Message Encryption (OME) are not configured. Sensitive patient information is sometimes emailed between physicians in plaintext. No end-to-end encryption exists for individual messages. Sarah Park notes: "I've told them not to email PHI. They do it anyway." **Evidence:** Crypto audit notes, EMAIL section, S/MIME or OME. **Status:** Absent |
| **VPN traffic** (site-to-site IPSec tunnels) | **Protection:** N/A. VPN tunnel configuration and IPSec keys are stored on FortiGate appliances (presumably secure) and the Westside Netgear Nighthawk consumer router (firmware update history unknown). Key storage security on the consumer router is undocumented. **Evidence:** Crypto audit notes, VPN TRAFFIC section. **Status:** N/A | **Protection:** IPSec with AES-256 encryption, SHA-256 for integrity, IKEv2 key exchange with DH Group 14. Configuration appears adequate on the FortiGate side. However, the Westside tunnel terminates on a Netgear Nighthawk consumer router with unknown firmware update history, introducing endpoint vulnerability risk regardless of algorithm strength. **Evidence:** Crypto audit notes, VPN TRAFFIC section, Central to Westside. **Status:** Weak | **Protection:** N/A. VPN traffic is not actively processed in a user-facing manner. Decrypted traffic enters the internal network and inherits the destination system's encryption posture. **Evidence:** Not applicable based on audit notes. **Status:** N/A |

---

## Gap Summary

### Cell-by-Cell Status Count

| Status | Count | Cells |
|--------|-------|-------|
| **Adequate** | 2 | Email At Rest, Email In Transit |
| **Weak** | 5 | Patient Records In Transit, Credentials At Rest, Credentials In Transit, Email In Use, VPN In Transit |
| **Absent** | 11 | Patient Records At Rest, Patient Records In Use, Financial Data At Rest, Financial Data In Transit, Financial Data In Use, Medical Images At Rest, Medical Images In Transit, Medical Images In Use, Backup Data At Rest, Backup Data In Transit, Credentials In Use |
| **N/A** | 3 | Backup Data In Use, VPN At Rest, VPN In Use |
| **Total** | 21 | |

### Overall Crypto Coverage

**Applicable cells:** 18 (21 total minus 3 N/A)

**Adequate protection:** 2 of 18 applicable cells = **11.1% crypto coverage**

**Inadequate protection (Weak + Absent):** 16 of 18 applicable cells = **88.9% of MedDefense's data is inadequately protected**

### Critical Observations

1. **Only Microsoft 365 provides adequate cryptographic protection**, and only because MedDefense has outsourced that responsibility entirely. Every system MedDefense directly manages has either absent or weak encryption.

2. **At-rest encryption is universally absent** across all MedDefense-managed systems (PostgreSQL, MySQL, PACS, NAS-01). Zero out of 5 applicable data categories encrypt data at rest.

3. **In-transit encryption is absent or weak** for 5 of 6 applicable data categories. Only email (handled by Microsoft) is adequate. Patient records, financial data, medical images, backups, and credentials all transmit in cleartext or with unenforced encryption.

4. **In-use encryption is universally absent** for all 5 applicable data categories. No system implements application-level encryption, session protection, or automatic screen locking for data being actively processed.

5. **The crypto-miner incident on billing-srv-01** confirmed that unencrypted at-rest data was accessible to an attacker who gained filesystem access, demonstrating that these are not theoretical gaps but realized vulnerabilities.

6. **Credentials face compound risk:** weak storage (NTHash/MD4), legacy protocols enabled (DES, RC4 per Finding 018), unencrypted LDAP (Finding 007), and no session protection. This means credential interception is possible at every state of the authentication lifecycle.
