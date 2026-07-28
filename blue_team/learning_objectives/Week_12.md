# The Cryptographic Foundation

### Cryptographic Primitives

**Symmetric vs Asymmetric Encryption**
- Symmetric uses one shared key for both encrypt/decrypt (fast, scalable for bulk data), asymmetric uses a public/private key pair (slower, solves key exchange and enables signatures); both are needed because symmetric handles bulk encryption while asymmetric solves key distribution and authentication.

**AES, RSA, ECC, ChaCha20**
- AES is a symmetric block cipher (128/192/256-bit keys, 256 is standard today), RSA is asymmetric (2048-bit minimum, 4096 recommended), ECC achieves equivalent security with much smaller keys (256-bit ECC ≈ 3072-bit RSA), and ChaCha20 is a fast stream cipher (256-bit key) optimized for software without hardware AES acceleration.

**Cryptographic Hashing**
- Hashing maps arbitrary input to a fixed-size digest with one-way, collision-resistant, and avalanche properties; SHA-2/SHA-3 are secure, MD5 and SHA-1 are broken due to practical collisions, salting prevents rainbow table attacks, and key stretching slows brute force via repeated iterations (e.g., PBKDF2, bcrypt, Argon2).

**Diffie-Hellman Key Exchange**
- DH allows two parties to derive a shared secret over an insecure channel without prior shared keys, but without authentication it's vulnerable to man-in-the-middle attacks since neither party can verify the other's identity.

**Digital Signatures**
- Digital signatures provide integrity (any tampering invalidates the signature), authentication (only the private key holder could have signed), and non-repudiation (signer cannot later deny signing) by encrypting a hash of the message with the sender's private key.

**Encryption vs Hashing vs Obfuscation vs Tokenization vs Masking vs Steganography**
- Encryption is reversible with a key, hashing is irreversible one-way, obfuscation makes code/data hard to understand but isn't cryptographically secure, tokenization replaces sensitive data with non-sensitive tokens mapped back via a vault, masking hides portions of data for display, and steganography hides data *within* other media so its very existence is concealed.

---

### PKI and Certificates

**X.509 Certificate Fields**
- Key fields include subject/issuer distinguished names, public key, validity period, serial number, signature algorithm, extensions (SAN, Key Usage, EKU, Basic Constraints), and the CA's signature binding identity to the public key.

**Chain of Trust**
- Root CAs are self-signed and pre-installed as trust anchors, intermediate CAs are signed by roots to allow CA operability and reduce root exposure risk, and leaf (end-entity) certificates are issued to servers/users by intermediates, forming a verifiable chain from leaf to root.

**Certificate Lifecycle**
- CSR is generated on the requesting system containing the public key and identity info, the CA verifies identity and issues the certificate, renewal occurs before expiry, and revocation invalidates compromised or expiring certs via CRL (published list) or OCSP (real-time protocol check).

**Self-Signed vs Third-Party vs Wildcard vs SAN Certificates**
- Self-signed certs are issued to oneself (no third-party trust, good for internal/test), third-party certs are issued by a trusted CA (publicly trusted), wildcard certs cover a domain and all first-level subdomains (`*.example.com`), and SAN certs list multiple hostnames/IPs in one certificate.

**TLS and Certificate Evaluation**
- TLS uses certificates to authenticate the server and negotiate a symmetric session key via handshake, and you evaluate configurations using SSL Labs to check supported protocols (TLS 1.2+), cipher suite strength, certificate validity/trust chain, forward secrecy, and HSTS.

---

### Data Protection

**Three States of Data**
- Data at rest is stored on disk/media (protected by encryption like LUKS/FDE), data in transit moves across networks (protected by TLS/IPsec), and data in use is being processed in memory (protected by secure enclaves, homomorphic encryption, or access controls).

**Encryption Levels**
- Full-disk encrypts the entire physical drive, partition encrypts a single partition, file-level encrypts individual files, volume encryption applies to logical volumes, database encryption can be at the DB layer (TDE), and record-level encrypts specific fields or rows.

**Data Classification**
- Classification categories (regulated, PII, financial, intellectual property) determine protection requirements: regulated data has legal/compliance mandates, PII requires privacy safeguards, financial data needs strong encryption and access controls, and IP demands confidentiality and access restriction — higher sensitivity drives stronger encryption, stricter access control, and more audit logging.

**Hardware Security**
- TPM is a chip on the motherboard for device attestation and sealed storage, HSM is a dedicated tamper-resistant appliance for high-value cryptographic operations and key storage, key management systems centralize key lifecycle operations (generation, rotation, distribution, destruction), and secure enclaves (like Intel SGX, Apple SEP) isolate sensitive computation within the CPU.

---

### Operational Skills

**OpenSSL Usage**
- OpenSSL CLI covers symmetric encryption (`openssl enc`), asymmetric ops (`openssl rsautl`/`pkeyutl`), hashing (`openssl dgst`), key generation (`openssl genrsa`/`genpkey`), CSR creation (`openssl req`), and certificate inspection (`openssl x509 -text -noout`).

**LUKS Disk Encryption**
- Set up LUKS on Linux by initializing a partition with `cryptsetup luksFormat`, opening it with `cryptsetup luksOpen`, formatting the mapped device with a filesystem, and adding an entry to `/etc/crypttab` and `/etc/fstab` for persistent mounting.

**SSL Labs Evaluation**
- Submit your domain to SSL Labs (ssllabs.com/ssltest), review the grade (A+ is ideal), verify TLS version support, cipher suite ordering, certificate chain completeness, and check for vulnerabilities like Heartbleed, ROBOT, and weak key exchanges.

**Bash Scripts for Crypto Operations**
- Write bash scripts wrapping OpenSSL commands to automate key generation, certificate signing, hash verification, batch file encryption/decryption, and periodic certificate expiry checks using `openssl x509 -enddate` and cron scheduling.

---

# The Board Briefing

## Integration and Synthesis

**Q1: What is integration and synthesis?**

A1: Integration and synthesis means connecting asset management, threat intelligence, vulnerability analysis, risk quantification, control strategy, and cryptographic protection into a single coherent assessment.

**Q2: How do you apply existing analysis to a new, specific, emerging threat?**

A2: You map known threat patterns and controls onto the new scenario to identify gaps quickly.

**Q3: How do you make prioritized recommendations under time pressure with incomplete information?**

A3: Focus on highest-risk assets and most exploitable vulnerabilities while documenting assumptions for later review.

## Emergency Response

**Q4: How do you translate a CISA advisory into an organization-specific impact assessment?**

A4: Match the advisory's affected systems and exploit details against your asset inventory to determine exposure and required actions.

**Q5: How do you design a 72-hour emergency response plan that addresses the most critical gaps first?**

A5: Prioritize containment, isolation, and communication steps for systems with active compromise or maximum business impact.

**Q6: How do you communicate urgency to non-technical stakeholders without causing panic?**

A6: Use clear business language focused on potential impact, timeline, and what's being done to protect organizational interests.

## Professional Mastery

**Q7: How do you produce a comprehensive Board-ready security package?**

A7: Combine executive summary, key metrics, risk posture, incident status, and strategic recommendations in business-focused language.

**Q8: How do you present complex technical concepts to diverse audiences (CEO, CFO, legal counsel, Board members)?**

A8: Tailor messaging to each audience's priorities—business outcomes for executives, financial implications for CFO, liability concerns for legal.

**Q9: How do you defend technical decisions against financial and legal scrutiny?**

A9: Document the risk reduction achieved, cost-benefit analysis, industry best practices, and regulatory alignment for each decision.
