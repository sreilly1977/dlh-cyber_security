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

# 5. Digital Signatures in Practice

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

Write a script `5-sign_verify.sh` that:

1. Accepts a mode argument: sign or verify
2. In sign mode: takes a file path and a private key path, produces a `.sig` signature file
3. In verify mode: takes a file path, a signature file path and a public key path, outputs the verification result
