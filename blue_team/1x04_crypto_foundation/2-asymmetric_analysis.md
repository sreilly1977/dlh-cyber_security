# 2. The Asymmetric Engine

## Goal

Generate RSA and ECC key pairs, discover the size limitation of asymmetric encryption through experimentation, and understand why the hybrid model exists.

## Context

If symmetric encryption is the workhorse, asymmetric encryption is the handshake. It solves the key distribution problem that symmetric encryption alone cannot: how do two parties who have never met agree on a shared secret? The answer involves key pairs, where one key encrypts and the other decrypts. But this elegance comes at a cost that you are about to measure.

## Part 1 - RSA Key Generation and Encryption

### Generate RSA-2048 Key Pair

```bash
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

Verify key creation:

```bash
ls -lh rsa_*.pem
openssl rsa -in rsa_private.pem -text -noout | head -20
```

Output:

```bash
.rw-------  1.7k steve 27 Jul 12:02   rsa_private.pem
.rw-r--r--   451 steve 27 Jul 12:02   rsa_public.pem
Private-Key: (2048 bit, 2 primes)
modulus:
    00:b5:2b:b9:96:cd:b9:47:3c:b4:0e:66:5d:12:a3:
    fe:5e:e5:e9:e3:2a:03:aa:a0:4f:30:f7:13:47:09:
    20:5f:ac:bf:d2:6a:fa:20:75:41:0d:89:b7:e1:30:
    8e:76:20:c7:88:df:25:dd:7c:a1:40:e9:dd:a3:a8:
    ac:1b:e3:57:90:1a:8a:a7:fb:39:af:5c:66:1a:8e:
    53:29:ca:2d:c9:59:31:66:22:74:fa:9d:3c:3d:90:
    25:79:7b:36:40:d1:b4:d8:64:38:87:80:8e:f0:ae:
    57:75:7c:2c:bf:3e:12:f1:b5:f6:20:45:18:53:31:
    c6:03:94:ff:70:e1:4c:5c:1b:c3:9c:8e:a0:8b:06:
    83:63:2b:2c:6a:88:9a:a2:96:3a:ea:18:be:96:21:
    68:9c:b4:69:9b:09:bd:41:a3:3d:65:d9:33:eb:aa:
    29:d3:62:2c:a3:ec:5c:af:50:db:dc:90:c1:97:77:
    2d:3d:b9:ff:09:00:8c:26:93:4c:a5:85:f2:de:d6:
    6e:06:e6:c9:59:0b:4f:ad:f8:be:7a:8f:38:c5:cf:
    a5:ec:07:a3:cf:1c:03:ed:00:b5:49:6b:d1:96:8b:
    68:85:2f:06:c8:8c:f7:b4:36:b6:9d:26:2e:7b:c8:
    75:c7:61:40:5b:82:3d:6f:03:65:e8:16:b6:fc:7a:
    c4:bf
```

### Encrypt and Decrypt with RSA

```bash
# Use the patient record from Task 1
echo -n "Patient: Jane Doe | DOB: 1985-03-14 | MRN: MED-50421 | Diagnosis: Atrial Fibrillation" > patient_record.txt
```

# Encrypt with public key

```bash
openssl rsautl -encrypt -pubin -inkey rsa_public.pem -in patient_record.txt -out patient_record_rsa.enc
```

# Decrypt with private key

```bash
openssl rsautl -decrypt -inkey rsa_private.pem -in patient_record_rsa.enc -out patient_record_rsa.dec
```

# Verify the decryption

```bash
diff patient_record.txt patient_record_rsa.dec && echo "RSA: Files match"
```

### Attempt to Encrypt 100MB File with RSA

```bash
openssl rsautl -encrypt -pubin -inkey rsa_public.pem -in testfile -out testfile_rsa.enc 2>&1
RSA operation error
40C78A6B257F0000:error:0200006E:rsa routines:ossl_rsa_padding_add_PKCS1_type_2_ex:data too large for key size:crypto/rsa/rsa_pk1.c:132:
```

## Why RSA Cannot Encrypt Large Files

RSA has a hard mathematical limit: the plaintext must be smaller than the modulus minus padding overhead. For RSA-2048 with PKCS#1 v1.5 padding, that means a maximum of approximately 245 bytes per encryption operation. Encrypting a 100MB file would require splitting it into over 400,000 separate RSA operations, which is computationally infeasible and would take hours. This is why RSA is never used for bulk data encryption in practice—it is used only to encrypt a short symmetric key, and that symmetric key then encrypts the actual data.

## Part 2 - ECC Key Generation

### Generate ECC Key Pair (P-256 Curve)

```bash
openssl ecparam -genkey -name prime256v1 -out ecc_private.pem
openssl ec -in ecc_private.pem -pubout -out ecc_public.pem
```

Verify key creation:

```bash
ls -lh ecc_*.pem
openssl ec -in ecc_private.pem -text -noout | head -15
```

Output:

```bash
.rw-------   302 steve 27 Jul 12:12   ecc_private.pem
.rw-r--r--   178 steve 27 Jul 12:13   ecc_public.pem
Private-Key: (256 bit)
priv:
    99:59:76:ae:b4:70:af:1a:bf:ab:49:13:6b:63:29:
    33:18:0c:b9:81:48:3b:69:03:67:05:8e:8b:69:64:
    e9:25
pub:
    04:ca:5f:83:db:27:67:ab:cd:63:08:00:d4:68:03:
    6f:0c:6c:9b:da:1f:a8:60:79:ee:b0:31:3a:c9:aa:
    16:e1:36:70:bd:24:1b:14:ac:0a:13:cb:f9:93:f2:
    11:d7:70:f8:cf:8e:a9:79:3a:4a:9f:e6:f9:8d:b9:
    75:66:90:fc:5a
ASN1 OID: prime256v1
NIST CURVE: P-256
```

# Compare RSA vs ECC Key Sizes

| Algorithm | Key Size | Private Key File Size | Public Key File Size | Security Equivalent |
|---|---|---|---|---|
| RSA-2048 | 2048 bits | ~1,700 bytes | ~450 bytes | 112-bit symmetric |
| ECC-P256 | 256 bits | ~227 bytes | ~178 bytes | 128-bit symmetric |

Size ratio: RSA-2048 private key is approximately 7.5x larger than ECC-P256 private key.

## Why ECC Achieves Equivalent Security with Smaller Keys

ECC's security is based on the elliptic curve discrete logarithm problem, which has no known sub-exponential time algorithm, unlike the integer factorization problem that RSA relies on. This mathematical property means a 256-bit ECC key provides comparable security to a 3,072-bit RSA key while being roughly 12x smaller in storage. For MedDefense's BD Alaris infusion pumps and Philips patient monitors, which use embedded microcontrollers with limited CPU power and memory, ECC keys reduce TLS handshake time from hundreds of milliseconds to tens of milliseconds, enabling secure encrypted communication without degrading clinical performance or draining battery-powered devices.

## Part 3 - The Hybrid Model

In practice, TLS and most encrypted communication use a hybrid approach: asymmetric encryption to exchange a symmetric key, then symmetric encryption for the actual data. The client and server first perform an asymmetric key exchange—using RSA, ECDHE, or X25519—to establish a shared secret that only those two parties can compute. This shared secret becomes the symmetric session key. Once the symmetric key is established, all subsequent data transfers are encrypted using fast symmetric algorithms like AES-256-GCM or ChaCha20-Poly1305. This combination is superior to using either approach alone because asymmetric encryption solves the key distribution problem securely but cannot handle large data volumes, while symmetric encryption handles bulk data at high speed but requires a pre-shared secret that is impractical to distribute at scale without asymmetric cryptography.

For MedDefense's patient portal, when a patient connects via HTTPS to portal.meddefense.org, the TLS handshake (specifically the Client Hello and Server Hello messages) uses ECDHE with ECC P-256 for the key exchange portion, establishing a shared secret that only the patient's browser and the web server know. The actual page content, patient lab results, and messaging data flowing between browser and server is then encrypted using AES-256-GCM symmetric encryption with the session key negotiated during the handshake. The asymmetric operation happens once per connection, while the symmetric operation handles all subsequent bulk data transfer.

## Part 4 - The Key Length Table

| Algorithm | Type | Key Lengths | Equivalent Security | Status | MedDefense Usage |
|---|---|---|---|---|---|
| AES-128 | Symmetric block cipher | 128 bits | 128-bit | ✅ Approved | Acceptable for general data encryption; less preferred than AES-256 for PHI |
| AES-192 | Symmetric block cipher | 192 bits | 192-bit | ✅ Approved | Rarely used; no advantage over AES-128 or AES-256 in practice |
| AES-256 | Symmetric block cipher | 256 bits | 256-bit | ✅ Approved | Primary recommendation for EHR database, billing database, PACS images, backups, VPN tunnels |
| RSA-2048 | Asymmetric public key | 2048 bits | 112-bit | ✅ Approved (minimum) | TLS certificates, digital signatures, code signing; minimum acceptable for new deployments |
| RSA-4096 | Asymmetric public key | 4096 bits | 150-bit | ✅ Approved | Long-term archival signing, root CA certificates; overkill for general use |
| ECC P-256 | Asymmetric public key | 256 bits | 128-bit | ✅ Approved | TLS key exchange for patient portal and VPN; preferred for medical IoT devices |
| ECC P-384 | Asymmetric public key | 384 bits | 192-bit | ✅ Approved | High-assurance TLS certificates, government compliance requirements |
| DES | Symmetric block cipher | 56 bits | ~56-bit | ❌ Deprecated | Never use. Broken since 1990s. No acceptable use case in healthcare |
| 3DES | Symmetric block cipher | 168 bits (effective 112) | 112-bit | ⚠️ Deprecated | NIST deprecated 2023. Migrate existing systems to AES immediately |
| ChaCha20-Poly1305 | Symmetric stream cipher (AEAD) | 256 bits | 128-bit | ✅ Approved | Mobile TLS connections, medical IoT devices without AES-NI hardware acceleration |
| RC4 | Symmetric stream cipher | Variable (40-2048) | Broken | ❌ Prohibited | Never use. Cryptographically broken since 2013. Currently detected in Active Directory (Finding 018) — disable immediately |

## Approved vs. Prohibited Summary

| Category | Algorithms | Action |
|---|---|---|
| ✅ Approved for PHI | AES-256 (GCM preferred), ChaCha20-Poly1305, RSA-2048+, ECC P-256+ | Use for all new deployments; audit existing systems for compliance |
| ⚠️ Deprecated | 3DES, AES-192 (unnecessary), RSA-1024 | Identify affected systems; create migration timeline; no new implementations |
| ❌ Prohibited | DES, RC4, MD4 (NTLM) | Disable immediately; RC4 in Active Directory must be remediated within 30 days |
