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

# [2. The Asymmetric Engine](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/2-asymmetric_analysis.md)

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

# 3. [The Hash Laboratory](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/3-hash_analysis.md)

## Goal
Explore hashing through experimentation: observe the avalanche effect, crack weak hashes, understand salting and key stretching, and build an integrity verification tool.

## Context
Hashing is not encryption. Encryption is reversible (with the key). Hashing is one-way. This distinction matters enormously because MedDefense stores password hashes in Active Directory, and the difference between a well-hashed password and a poorly hashed one is the difference between "attacker has hashes but cannot use them" and "attacker has every user's password in 30 minutes."

## Instructions

### Part 1 - The Avalanche Effect

Hash the string "MedDefense" with SHA-256:

```bash
bash echo -n "MedDefense" | sha256sum
```

Now hash "MedDefense1" (one character added). Compare the two hashes. How many characters of the hex output differ? This is the avalanche effect: a single bit of input change should change approximately 50% of the output. Repeat with MD5. Document all four hashes.

### Part 2 - Hash Collisions and the Birthday Problem

MD5 produces a 128-bit hash. SHA-256 produces a 256-bit hash. Calculate: how many possible unique outputs does each produce? (Express as a power of 2.)

Explain in 3-4 sentences why a shorter hash is more susceptible to collision attacks and what a birthday attack exploits. Reference Finding 018 from 1x02 (Kerberos weak encryption): if MedDefense's AD uses RC4 for Kerberos tickets, which relies on MD5 internally, what is the practical implication for password security?

### Part 3 - Rainbow Table Demonstration

Hash the password "password123" with MD5:

```bash
echo -n "password123" | md5sum
```

Go to crackstation.net and look up the resulting hash. Document what you find.

Now hash "password123" with a salt:

```bash
echo -n "s4lt9xQ2:password123" | md5sum
```

Look up this salted hash on crackstation.net. Document the result. Explain in 3-4 sentences why salting defeats rainbow tables and why every user needs a unique salt.

### Part 4 - Key Stretching

Research bcrypt, PBKDF2 and Argon2. For each, explain in 2-3 sentences: what it does differently from a simple hash, why it is more resistant to brute-force and what the "cost factor" or "iteration count" parameter controls.

Which would you recommend for MedDefense's application password storage, and why? Which is used by Active Directory by default (research this) and is it adequate?

### Part 5 - The Integrity Verification Script

Write a script [`3-hash_verify.sh`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/3-hash_verify.sh) that:

1. Takes two arguments: a file path and an expected SHA-256 hash
2. Computes the SHA-256 hash of the file
3. Compares it to the expected hash
4. Outputs "INTEGRITY OK" if they match, "INTEGRITY FAILED - expected [hash] got [hash]" if they do not
5. Returns exit code 0 on success, 1 on failure

---

# [4. The Key Exchange](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/4-key_exchange.md)

## Goal
Simulate a Diffie-Hellman key exchange with OpenSSL to understand how two parties agree on a shared secret over an insecure channel, then analyze the man-in-the-middle vulnerability that certificates exist to solve.

## Context
The fundamental problem of symmetric encryption is key distribution: Alice and Bob need the same key, but they cannot send it over the network because Eve is listening. In 1976, Whitfield Diffie and Martin Hellman solved this problem with mathematics. You are about to reproduce their solution with OpenSSL.

But their solution has a weakness. If Eve is not just listening but actively intercepting and modifying traffic, Diffie-Hellman alone cannot detect her. This is why certificates exist. The connection between key exchange and PKI is the thread that runs through the rest of this project.

## Instructions

### Part 1 - The DH Simulation

Simulate a Diffie-Hellman key exchange between Alice and Bob using OpenSSL. Document every command and its output:

1. Generate shared DH parameters: `openssl dhparam -out dhparams.pem 2048`
2. Generate Alice's private key from the parameters
3. Extract Alice's public key
4. Repeat for Bob
5. Derive the shared secret from Alice's side using Bob's public key
6. Derive the shared secret from Bob's side using Alice's public key
7. Compare the two secrets: `diff alice_secret.bin bob_secret.bin`

### Part 2 - The Explanation

In 5-6 sentences, explain what just happened in terms a non-cryptographer (for example, Robert Kim, the CFO) could understand. Alice and Bob never exchanged a secret key, yet they both derived the same one. How? What would Eve (listening on the network) have seen, and why could she not derive the same secret?

### Part 3 - The MITM Attack

Describe in 4-5 sentences how a man-in-the-middle attack defeats plain Diffie-Hellman. Eve intercepts Alice's public key, performs her own DH exchange with both Alice and Bob separately, and now has two different shared secrets. Map this to MedDefense: if the VPN tunnel between Central and Westside uses DH without certificate-based authentication, what could an attacker on the network path do? How do certificates prevent this?

---

# [5. Digital Signatures in Practice](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/5-sign_verify.sh)

## Goal
Sign and verify files with OpenSSL, then connect the cryptographic properties of digital signatures to real-world healthcare requirements where non-repudiation is legally mandated.

## Context
A digital signature simultaneously provides three properties: integrity (the content has not been modified), authentication (the signer is who they claim to be) and non-repudiation (the signer cannot deny having signed). In healthcare, these properties are not optional. Electronic prescriptions, clinical trial consent forms and audit logs all require digital signatures to be legally valid under HIPAA and the ESIGN Act.

## Instructions

### Part 1 - Sign and Verify

Using your RSA key pair from T2:

1. Create a file `prescription.txt` with content: `Patient: John Smith | MRN: MED-10042 | Rx: Metoprolol 50mg | Prescriber: Dr. Patel`
2. Sign the file with SHA-256 and your RSA private key. Document the command.
3. Verify the signature with the public key. Document the command and output.
4. Modify one character in `prescription.txt`. Verify again. Document the failure output.

### Part 2 - The Signing Script

Write a script [`5-sign_verify.sh`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/5-sign_verify.sh) that:

1. Accepts a mode argument: sign or verify
2. In sign mode: takes a file path and a private key path, produces a `.sig` signature file
3. In verify mode: takes a file path, a signature file path and a public key path, outputs the verification result

---

# [6. The Algorithm Landscape](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/6-algorithm_landscape.md)

## Goal
Build the definitive reference table of cryptographic algorithms, mapped against MedDefense's current and recommended usage, identifying every deprecated algorithm still in production.

## Context
The Security+ exam expects you to know which algorithms are current, which are deprecated and which are broken. More importantly, it expects you to know WHY certain algorithms are inappropriate for certain uses. This task builds the reference you will carry into the exam and into your career.

Every algorithm in the table connects to something you have already seen in MedDefense.

## Instructions
Produce an **Algorithm Reference Table** organized by type:

- **Symmetric:** AES-128, AES-192, AES-256, DES, 3DES, ChaCha20-Poly1305, RC4, Blowfish
- **Asymmetric:** RSA-2048, RSA-4096, ECC P-256, ECC P-384, Diffie-Hellman, ECDHE
- **Hash:** MD5, SHA-1, SHA-256, SHA-512, SHA-3
- **Key Derivation:** PBKDF2, bcrypt, Argon2, scrypt

For each algorithm:

| Field | What to document |
|-------|-----------------|
| Type | Symmetric / Asymmetric / Hash / KDF |
| Key/Output Size | In bits |
| Primary Use Case | What it is designed for |
| Status | Current / Deprecated / Broken |
| Why Deprecated/Broken | If applicable, one sentence |
| MedDefense Usage | Where this algorithm is or should be used at MedDefense |

After the table, produce a **MedDefense Crypto Gap Analysis:** compare what MedDefense currently uses (from T0 and 1x02 findings) against what it should use. Identify at least 4 cases where MedDefense uses a deprecated or broken algorithm and recommend the specific replacement.

---

# [7. The Obfuscation Toolkit](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/7-obfuscation_toolkit.md)

## Goal
Distinguish between encryption, hashing and obfuscation techniques, design a tokenization scheme for MedDefense, and evaluate steganography as both a protection tool and a threat vector.

## Context
Not every data protection mechanism is encryption. Sec+ 1.4 distinguishes several obfuscation techniques: tokenization (replacing sensitive data with non-sensitive tokens), data masking (hiding parts of data while preserving format) and steganography (hiding data within other data). Each has a specific use case, and confusing them is a common exam mistake and a real-world design error.

## Instructions

### Part 1 - Technique Comparison

Produce a comparison of 5 data protection techniques: Encryption, Hashing, Tokenization, Data Masking and Steganography. For each:

1. What it does to the data
2. Whether the original data can be recovered (and by whom)
3. A concrete healthcare use case

### Part 2 - MedDefense Tokenization Design

MedDefense's billing department needs to process payments but should not store full credit card numbers. Design a tokenization scheme:

1. What data is tokenized (and what format the token takes)
2. Where the token-to-real-data vault is stored (and how that vault is protected, including encryption and access controls)
3. What happens if the token vault is compromised
4. How this compares to simply encrypting the credit card numbers (advantages and disadvantages of tokenization vs encryption for this use case)

### Part 3 - Data Masking Examples

Produce 3 masked MedDefense data examples showing what different roles should see:

| Data Field | Full Value | Nurse (clinical) | Billing Clerk | Reception |
|------------|------------|-------------------|---------------|-----------|
| SSN | 987-65-4321 | ? | ? | ? |
| Patient Name | Maria Gonzalez | ? | ? | ? |
| Diagnosis | Type 2 Diabetes | ? | ? | ? |

For each cell, determine the appropriate masking level and justify it in one sentence based on the role's need-to-know.

### Part 4 - Steganography as Threat Vector

In 4-5 sentences, explain why steganography is a serious concern for MedDefense's data loss prevention program. Consider: DICOM medical images are large binary files routinely transferred between facilities. How could a malicious insider embed exfiltrated patient data within legitimate imaging files? What makes this harder to detect than traditional data exfiltration? What control from your 1x03 strategy would help detect this?

---

# [8. The Certificate Anatomy](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/8-certificate_anatomy.md)

## Goal
Inspect real X.509 certificates from live websites using OpenSSL, identify every field that matters for security, and diagnose intentionally broken certificates.

## Context
Every time a patient opens the MedDefense portal, their browser performs a certificate check in milliseconds: Is this really MedDefense? Is the certificate still valid? Was it issued by a trusted authority? You need to understand exactly what the browser is checking, because in 18 days, MedDefense's certificate expires and you are the person who will replace it.

## Instructions

### Part 1 - Inspect Three Real Certificates

Use `openssl s_client` to download and inspect the certificate from 3 different websites:

1. A site with a Let's Encrypt certificate (example: letsencrypt.org)
2. A site with a commercial CA certificate (example: github.com)
3. A site with a broken certificate from badssl.com (choose one: expired.badssl.com, wrong.host.badssl.com, or self-signed.badssl.com)

For each certificate, use `openssl x509 -text` to extract and document:

- Subject (CN, O, L, ST, C)
- Issuer (who signed it)
- Validity period (Not Before, Not After)
- Serial Number
- Signature Algorithm
- Public Key Algorithm and Key Size
- Subject Alternative Names (SAN extension)
- Key Usage and Extended Key Usage
- Authority Information Access (OCSP URL, CA Issuer URL)

### Part 2 - The Broken Certificate

For your badssl.com certificate, explain precisely what is wrong. What error would a browser display? What risk does this misconfiguration create? Would you advise a patient to proceed to a portal that displays this type of error?

### Part 3 - MedDefense Certificate Profile

Based on what you have learned, describe the ideal certificate for MedDefense's patient portal:

- What type (DV, OV, EV) and why
- What CA should issue it and why
- What SAN entries should it include
- What key algorithm and size
- What validity period
- Whether a wildcard or single-domain certificate is more appropriate

---

# [9. The Chain of Trust](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/9-chain_of_trust.md)

## Goal
Capture and verify a complete certificate chain, understand how trust propagates from root to leaf, and analyze what happens when the chain breaks.

## Context
A certificate is only as trustworthy as the chain behind it. The patient's browser trusts the portal's certificate because it trusts the intermediate CA that signed it, which it trusts because it trusts the root CA in its trust store. If any link in this chain is invalid, expired, revoked or untrusted, the entire connection fails.

## Instructions

### Part 1 - Capture the Full Chain

Use `openssl s_client -showcerts` to capture the complete certificate chain from a website with at least 2 certificates in the chain (most commercial sites qualify). Save each certificate to a separate file. Document:

- How many certificates are in the chain
- The role of each (leaf, intermediate, root)
- The Subject and Issuer of each (show how the Issuer of one matches the Subject of the next)

### Part 2 - Manual Chain Verification

Use `openssl verify` to manually verify the chain. Document the command and the output. Then remove the intermediate certificate and try to verify again. Document the error. Explain in 2-3 sentences what this demonstrates about why servers must send the full chain (not just the leaf certificate).

### Part 3 - Revocation Mechanisms

Research and explain:

- **CRL (Certificate Revocation List):** What it is, how a client uses it, and its main limitation (hint: size and update frequency).
- **OCSP (Online Certificate Status Protocol):** What it is, how it improves on CRLs, and what OCSP Stapling adds.

For MedDefense: If the portal's private key were compromised tomorrow (as in MCQ T25 of 1x03, where a key was exposed in a Git repository), describe the exact sequence of actions needed to revoke and replace the certificate.

### Part 4 - Trust Store Exploration

On your Linux machine, find where the system's trusted root certificates are stored (typically `/etc/ssl/certs/` or similar). How many root CAs does your system trust? Pick one root CA certificate and inspect it with `openssl x509 -text`. What is its validity period? Does this surprise you?

---

# [10. The CSR Workshop](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/10-csr_workshop.md)

## Goal
Generate a Certificate Signing Request for the MedDefense patient portal, making every field decision deliberately and documenting the reasoning.

## Context
The patient portal certificate expires in 18 days. James Chen has approved the renewal. You are generating the CSR that will be submitted to the Certificate Authority. Every field in the CSR becomes a field in the certificate, and every field matters. A wrong Common Name locks out patients. A missing SAN entry breaks mobile access. A weak key algorithm undermines the entire purpose.

## Instructions

### Part 1 - Key Generation Decision

Before generating the CSR, decide: RSA-2048, RSA-4096 or ECC P-256 for the private key?

Write a **3-4 sentence justification** for your choice. Consider: security level, performance impact on the web server handling 800 patient connections per day, compatibility with older browsers/devices and the recommendations from your Algorithm Reference Table (T6).

Generate the key with your chosen algorithm. Document the command.

### Part 2 - CSR Generation

Generate the CSR with appropriate fields for MedDefense's patient portal:

```
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
```

You will need to create an `openssl.cnf` file (or use command-line options) to include:

- **Common Name:** `portal.meddefense.local`
- **Organization:** `MedDefense Health Systems`
- **Organizational Unit:** `Information Technology`
- **Locality, State, Country:** appropriate for MedDefense
- **Subject Alternative Names:** include both `portal.meddefense.local` and any other hostnames patients might use

Document the complete CSR generation process.

### Part 3 - CSR Inspection

Inspect your CSR:

```
openssl req -text -noout -in portal.csr
```

Verify that every field is correct. Document the output. Confirm the SAN entries are present.

### Part 4 - The Full Lifecycle

Write a step-by-step description (not a script, but a procedure document) of the complete certificate lifecycle from this point:

1. CSR generated (done)
2. Submission to CA (which CA? Let's Encrypt via ACME or a commercial CA?)
3. Validation process (what the CA verifies)
4. Certificate issuance
5. Installation on the web server
6. Verification that the new certificate is serving correctly
7. Decommission of the old certificate
8. Monitoring for the next renewal

Write a script [`10-generate_csr.sh`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/10-generate_csr.sh) that automates steps 1-3 of the key generation and CSR creation process.

---
