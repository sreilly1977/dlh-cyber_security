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

# 2. The Asymmetric Engine

## Goal
Generate RSA and ECC key pairs, discover the size limitation of asymmetric encryption through experimentation, and understand why the hybrid model exists.

## Context
If symmetric encryption is the workhorse, asymmetric encryption is the handshake. It solves the key distribution problem that symmetric encryption alone cannot: how do two parties who have never met agree on a shared secret? The answer involves key pairs, where one key encrypts and the other decrypts. But this elegance comes at a cost that you are about to measure.

## Instructions

### Part 1 - RSA Key Generation and Encryption

Generate an RSA-2048 key pair:

```bash
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

Encrypt a small file (the same patient record from T1) with the public key. Decrypt with the private key. Document the commands.

Now try to encrypt the 100MB test file from T1 with RSA. What happens? Document the error message. Explain in 2-3 sentences why RSA cannot encrypt large files directly and what this limitation means for real-world usage.

### Part 2 - ECC Key Generation

Generate an ECC key pair using the P-256 curve:

```bash
openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
```

Compare the file sizes of `rsa_private.pem` and `ecc_private.pem`. What is the ratio? Explain in 2-3 sentences why ECC achieves equivalent security with much smaller keys and why this matters for constrained environments (think: MedDefense's BD Alaris pumps and Philips monitors with limited processing power).

### Part 3 - The Hybrid Model

In practice, TLS and most encrypted communication use a hybrid approach: asymmetric encryption to exchange a symmetric key, then symmetric encryption for the actual data. Describe this hybrid model in 4-5 sentences. Why is this combination superior to using either approach alone? Connect this to MedDefense's patient portal: when a patient connects via HTTPS, which part of the protocol handles the key exchange and which part handles the bulk data encryption?

### Part 4 - The Key Length Table

Produce a comparison table covering the algorithms Sec+ 1.4 expects:

| Algorithm | Type | Key Lengths | Equivalent Security | Status | MedDefense Usage |
|-----------|------|-------------|----------------------|--------|-----------------|

Cover: AES (128/192/256), RSA (2048/4096), ECC (P-256/P-384), DES, 3DES, ChaCha20-Poly1305, RC4. For each, state whether it is approved for use in a healthcare environment handling regulated data.

---
