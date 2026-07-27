# [0. The Crypto Inventory](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/0-crypto_inventory.md)

## Goal
Map every data flow at MedDefense against its current cryptographic protection state, exposing every gap in one document.

## Context
Before you can fix MedDefense's cryptographic posture, you need to see the full picture in one place. The vulnerability findings from 1x02 identified individual crypto weaknesses (TLS 1.0 on the portal, unencrypted backups, cleartext DICOM). The risk register in 1x03 tracked some of these as risks. But nobody has produced a systematic inventory that maps every category of data, in every state, to its current level of protection.

This is the document that makes the invisible visible. When you finish, every cell where it says "None" is a gap that the rest of this project will address.

### Provided Files
`meddefense-crypto-audit-notes.txt`

## Instructions
Produce a **Data Protection Map** for MedDefense. The map is a matrix that crosses data categories (rows) with data states (columns).

### Columns (Data States):

1. **At Rest** (stored on disk, database, NAS, backup)
2. **In Transit** (moving between systems over the network)
3. **In Use** (actively being processed or displayed)

### Rows (Data Categories): Use at minimum these 7:

1. Patient medical records (EHR data in PostgreSQL)
2. Financial/billing data (MySQL on billing-srv-01)
3. Medical images (DICOM on PACS)
4. Credentials (Active Directory, application passwords)
5. Backup data (NAS-01)
6. Email (O365)
7. VPN traffic (site-to-site tunnels)

For each cell, document:

```
Protection: [Algorithm/Protocol used, or "None"]
Evidence: [Reference to 1x02 finding, 1x00 observation, or audit notes]
Status: [Adequate / Weak / Absent]
```

After the matrix, produce a **Gap Summary:** How many of the 21 cells (7 × 3) have adequate protection? How many are weak? How many are absent? What is the overall crypto coverage percentage?

---

# [1. The Symmetric Engine](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/1-symmetric_encrypt.sh)

## Goal
Master symmetric encryption through hands-on OpenSSL operations, comparing modes, measuring performance and building an automation script.

## Context
Symmetric encryption is the workhorse of modern cryptography. Every file encrypted at rest, every database field protected, every VPN tunnel carrying data between MedDefense sites uses symmetric encryption at its core. AES is the standard. But "use AES" is not a complete answer. AES-128 or AES-256? CBC or GCM mode? What are the performance implications?

You are going to find out by doing it.

## Instructions

### Part 1 - AES Encryption and Decryption

Create a test file containing the text:


```
Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation

```

Encrypt this file using OpenSSL with three different configurations and document the exact command for each:

1. AES-256-CBC (the traditional mode)
2. AES-256-GCM (the authenticated encryption mode)
3. AES-128-CBC (reduced key length)

### Part 2 - The Performance Measurement

Create a 100MB test file:

```bash
dd if=/dev/urandom of=testfile bs=1M count=100
```


### Part 3 - The Script

Write a script `1-symmetric_encrypt.sh` that takes three arguments: an input file, an output file and a mode (cbc or gcm). The script should encrypt the input file with AES-256 in the specified mode and output the result.

---
