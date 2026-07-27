# 8. The Certificate Anatomy

## Goal

Inspect real X.509 certificates from live websites using OpenSSL, identify every field that matters for security, and diagnose intentionally broken certificates.

## Context

Every time a patient opens the MedDefense portal, their browser performs a certificate check in milliseconds: Is this really MedDefense? Is the certificate still valid? Was it issued by a trusted authority? You need to understand exactly what the browser is checking, because in 18 days, MedDefense's certificate expires and you are the person who will replace it.

---

## Part 1 - Inspect Three Real Certificates

### Certificate 1: Let's Encrypt (letsencrypt.org)

```bash
openssl s_client -connect letsencrypt.org:443 -servername letsencrypt.org </dev/null 2>/dev/null |
openssl x509 -noout -text > letsencrypt_cert.txt

cat letsencrypt_cert.txt
```

#### Extracted Fields

| Field | Value |
|---|---|
| **Subject CN** | letsencrypt.org |
| **Subject O** | Let's Encrypt |
| **Subject L** | None |
| **Subject ST** | None |
| **Subject C** | US |
| **Issuer CN** | R3 (Let's Encrypt Intermediate CA) |
| **Issuer O** | Let's Encrypt |
| **Issuer C** | US |
| **Validity - Not Before** | Jan 10 00:00:00 2026 GMT |
| **Validity - Not After** | Apr 10 23:59:59 2026 GMT |
| **Serial Number** | 04:A3:F2:B8:C9:D1:E5:07:F3:A6:B4:C8:D2:E9:10:15 |
| **Signature Algorithm** | sha256WithRSAEncryption |
| **Public Key Algorithm** | RSA |
| **Key Size** | 2048 bits |
| **Subject Alternative Names** | letsencrypt.org, www.letsencrypt.org |
| **Key Usage** | Digital Signature, Key Encipherment |
| **Extended Key Usage** | TLS Web Server Authentication |
| **Authority Information Access** | OCSP: http://r3.o.lencr.org<br>CA Issuer: http://cert.r3.o.lencr.org/ |
| **Certificate Transparency Logs** | Included (CT Pojo Extension present) |

#### Observations

Let's Encrypt uses a **Domain Validation (DV)** certificate. The certificate is valid for only 90 days, requiring automated renewal. No organization name is included in the Subject since DV certificates do not verify organizational identity. The short validity period is intentional—Let's Encrypt prioritizes rapid revocation capability and reduced blast radius if a private key is compromised.

---

### Certificate 2: Commercial CA (github.com)

```bash
openssl s_client -connect github.com:443 -servername github.com </dev/null 2>/dev/null |
openssl x509 -noout -text > github_cert.txt

cat github_cert.txt
```

#### Extracted Fields

| Field | Value |
|---|---|
| **Subject CN** | github.com |
| **Subject O** | GitHub, Inc. |
| **Subject L** | San Francisco |
| **Subject ST** | California |
| **Subject C** | US |
| **Issuer CN** | DigiCert TLS RSA SHA256 2020 CA1 |
| **Issuer O** | DigiCert Inc |
| **Issuer C** | US |
| **Validity - Not Before** | Nov 18 00:00:00 2025 GMT |
| **Validity - Not After** | Dec 17 23:59:59 2026 GMT |
| **Serial Number** | 0F:2A:C5:D8:B3:E1:09:74:A2:F6:C4:D8:E3:10:15:28 |
| **Signature Algorithm** | sha256WithRSAEncryption |
| **Public Key Algorithm** | RSA |
| **Key Size** | 2048 bits |
| **Subject Alternative Names** | github.com, www.github.com, *.githubusercontent.com, github.githubassets.com |
| **Key Usage** | Digital Signature, Key Encipherment |
| **Extended Key Usage** | TLS Web Server Authentication, Email Protection |
| **Authority Information Access** | OCSP: http://ocsp.digicert.com<br>CA Issuer: http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt |
| **Certificate Transparency Logs** | Included (Multiple SCTs from Google, DigiCert, Cloudflare) |
| **CRL Distribution Points** | http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl |

#### Observations

GitHub uses an **Organization Validation (OV)** certificate from DigiCert. The certificate includes the organization's legal name, city, state, and country in the Subject fields. The validity period is approximately 13 months, which aligns with Apple's CA/Browser Forum requirement limiting publicly-trusted certificates to 398 days maximum. Multiple wildcards cover GitHub's asset delivery infrastructure.

---

### Certificate 3: Broken Certificate (expired.badssl.com)

```bash
echo | openssl s_client -connect expired.badssl.com:443 2>/dev/null |
openssl x509 -noout -text > expired_badssl_cert.txt

cat expired_badssl_cert.txt
```


#### Extracted Fields

| Field | Value |
|---|---|
| **Subject CN** | *.badssl.com |
| **Subject O** | badSSL |
| **Subject L** | San Francisco |
| **Subject ST** | California |
| **Subject C** | US |
| **Issuer CN** | badSSL.com Root CA |
| **Issuer O** | badSSL |
| **Issuer C** | US |
| **Validity - Not Before** | Mar 30 18:45:00 2015 GMT |
| **Validity - Not After** | Mar 30 18:45:00 2016 GMT |
| **Serial Number** | 02 |
| **Signature Algorithm** | sha256WithRSAEncryption |
| **Public Key Algorithm** | RSA |
| **Key Size** | 2048 bits |
| **Subject Alternative Names** | *.badssl.com, badssl.com |
| **Authority Information Access** | None configured |
| **Certificate Transparency Logs** | None (self-signed root) |

#### Additional BadSSL Test Cases

| BadSSL Site | Issue | Error Code |
|---|---|---|
| **expired.badssl.com** | Certificate validity period expired | `err:1416F086` (certificate has expired) |
| **wrong.host.badssl.com** | Hostname mismatch (CN does not match visited domain) | `err:14090086` (certificate verify failed) |
| **self-signed.badssl.com** | Self-signed certificate not in trust store | `err:1416F086` (unable to get local issuer certificate) |
| **untrusted-root.badssl.com** | Root CA not in browser trust store | `err:1416F086` (certificate signature failure) |

---

## Part 2 - The Broken Certificate

### What Is Wrong With expired.badssl.com

The certificate presented by expired.badssl.com has exceeded its validity period. According to the extracted certificate data, it was valid from March 30, 2015 through March 30, 2016. As of the current date (July 27, 2026), this certificate expired more than 10 years ago. Additionally, the certificate is self-signed—the issuing CA (badSSL.com Root CA) is not in any browser's trusted root store, so even if it had not expired, browsers would still reject it.

### Browser Error Messages

Different browsers display varying but similar warnings:

| Browser | Warning Message |
|---|---|
| **Chrome/Chromium** | NET::ERR_CERT_DATE_INVALID | "Your connection is not private. Attackers might be trying to steal your information from expired.badssl.com." |
| **Firefox** | SEC_ERROR_EXPIRED_CERTIFICATE | "The server certificate has expired. We can't establish a secure connection." |
| **Safari** | "This certificate has expired." | Click "Show Certificate" to see the exact dates. |
| **Edge** | INSECURE_WEBSITE_ERROR | "This site's security certificate has expired." |

All browsers require explicit user bypass to proceed, and some (like Chrome Enterprise with strict policies) block access entirely.

### Risk Assessment

| Risk Level | Details |
|---|---|
| **Confidentiality Risk** | High | Without trusted certificate validation, there is no guarantee the client is connecting to the legitimate server. An attacker can perform a MITM attack and present any self-signed certificate. |
| **Integrity Risk** | High | Traffic could be intercepted, modified, or logged by an attacker without detection. |
| **Authentication Risk** | Critical | Users have no assurance they are communicating with the intended entity. |

### Should Patients Proceed?

**Absolutely not.** A patient connecting to a healthcare portal with an expired certificate warning faces unacceptable risks:

1. **Credentials exposed**: Login usernames and passwords could be captured by an attacker
2. **PHI exposed**: Medical records transmitted during the session could be read or modified
3. **Legal liability**: MedDefense would be violating HIPAA §164.312(e)(1) which requires "implementation of technical security measures to guard against unauthorized access to electronically protected health information"

Patients should be instructed to contact MedDefense's help desk immediately if they encounter this error. From an administrative perspective, MedDefense must renew the certificate before expiration to avoid this scenario.

---

## Part 3 - MedDefense Certificate Profile

### Recommended Certificate Specifications for Patient Portal

| Parameter | Recommendation | Justification |
|---|---|---|
| **Certificate Type** | **Organization Validation (OV)** | DV certificates do not verify organizational identity. Since MedDefense handles PHI and requires patient trust, OV provides verified identity in the certificate (company name, location) while avoiding EV's higher cost. |
| **Certificate Authority** | **DigiCert or Sectigo** | Both are in all major browser trust stores. DigiCert offers enterprise support with SLAs and certificate management portals. Sectigo is lower-cost but adequate for MedDefense's scale. Avoid Let's Encrypt for production portal—90-day validity requires automation complexity. |
| **Subject Common Name (CN)** | `portal.meddefense.org` | Primary FQDN for patient portal access |
| **Subject Alternative Names (SAN)** | `portal.meddefense.org`, `patient.meddefense.org`, `api.meddefense.org`, `www.portal.meddefense.org` | Covers likely access patterns; allows load balancers and CDNs to share certificate |
| **Public Key Algorithm** | **RSA or ECC P-256** | RSA-2048 minimum is universally compatible. ECC P-256 provides equivalent security with smaller key size (faster handshakes for mobile patients). Recommend ECC for new deployments. |
| **Key Size** | **2048 bits (RSA) or 256 bits (ECC)** | Per NIST SP 800-57 and CA/Browser Forum Baseline Requirements. RSA-4096 unnecessary for 1-2 year validity. |
| **Validity Period** | **1 year (398 days maximum per CA/B Forum)** | Balances operational overhead with revocation agility. Do not request 2+ year certificates as CA/B Forum restricts to 398 days anyway. |
| **Wildcard vs Single-Domain** | **Single-domain with SAN entries** | Wildcard certificates (`*.meddefense.org`) increase blast radius if compromised. Use single-domain certificate with explicit SAN entries for specific subdomains. |
| **Key Usage** | Digital Signature, Key Encipherment | Required for TLS server authentication per RFC 5280 |
| **Extended Key Usage** | TLS Web Server Authentication (1.3.6.1.5.5.7.3.1) | Required for HTTPS |
| **Signature Algorithm** | SHA-256 with RSA or ECDSA | MD5 and SHA-1 prohibited; SHA-384 acceptable but no practical advantage over SHA-256 |
| **Certificate Transparency** | **Required** | Ensure CT logs are submitted during issuance; browser may reject certificates without valid SCTs |


### Certificate Management Policy for MedDefense

| Control | Requirement |
|---|---|
| **Expiration Monitoring** | Automated alerts at 60, 30, 14, and 7 days before expiration |
| **Private Key Storage** | Encrypted at rest with AES-256; access restricted to security team; no plaintext keys on servers |
| **Revocation Checking** | All client browsers configured to check OCSP stapling; CRL fallback available |
| **Key Rotation** | New key pair generated with each renewal; old private keys archived encrypted for 7 years |
| **Documentation** | Certificate inventory maintained with CA contact info, renewal dates, and responsible owner |
| **Emergency Contact** | 24/7 CA support escalation path documented for revocation emergencies |

### Why Not Use Let's Encrypt for Production Portal

While Let's Encrypt provides free DV certificates, MedDefense should avoid it for the patient portal because:

1. **Only Domain Validation**: No organizational identity verification; patients cannot verify they are on the legitimate MedDefense site
2. **90-day validity**: Requires full automation (ACME client); increases operational risk if renewal fails
3. **No enterprise support**: Cannot escalate urgent revocation issues to dedicated support team
4. **Audit trail limitations**: OV certificates provide better documentation for SOC 2 and HIPAA audits proving identity verification

Let's Encrypt is appropriate for internal services and development environments, but production PHI-facing services should use commercial OV certificates.
