# 11. The TLS Audit

## Goal

Evaluate real-world TLS configurations using SSL Labs, produce a remediation plan for MedDefense's patient portal, and write a hardened TLS configuration.

## Context

Finding 005 from your vulnerability assessment (1x02) identified that the patient portal still supports TLS 1.0 alongside TLS 1.2. That finding has been sitting on the remediation list for 3 weeks. Now you have the knowledge to fix it. But before you write the configuration, you need to understand what a good TLS configuration looks like and what a bad one looks like, using real data from real websites.

---

## Part 1 - SSL Labs Analysis

### Website 1: Cloudflare (A+ Rating)

**URL Tested:** cloudflare.com

#### Overall Grade

| Metric | Value |
|---|---|
| **Overall Rating** | A+ |
| **SSL/TLS Protocols** | TLS 1.2, TLS 1.3 |
| **Cipher Strength** | A |
| **Forward Secrecy** | Yes |
| **Certificate** | A |

#### Protocol Support

| Protocol | Version | Status |
|---|---|---|
| **TLS 1.0** | N/A | Disabled ✅ |
| **TLS 1.1** | N/A | Disabled ✅ |
| **TLS 1.2** | Supported | Enabled ✅ |
| **TLS 1.3** | Supported | Enabled ✅ |

#### Key Exchange Strength

| Parameter | Value | Security Level |
|---|---|---|
| **Key Exchange Algorithm** | ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) | Strong |
| **Curve Used** | X25519, secp256r1 (P-256), secp384r1 (P-384) | Strong |
| **Certificate Key Size** | RSA 2048 bits | Strong |
| **Forward Secrecy** | Yes | Perfect Forward Secrecy (PFS) achieved |

#### Cipher Suite Selection

Cloudflare supports 12 cipher suites, ordered by preference (strongest first):

```
TLS_AES_128_GCM_SHA256 
TLS_AES_256_GCM_SHA384 
TLS_CHACHA20_POLY1305_SHA256 
ECDHE-RSA-AES256-GCM-SHA384 
ECDHE-RSA-AES128-GCM-SHA256
```

**Analysis:** All ciphers use AES-GCM or ChaCha20-Poly1305 AEAD modes with strong key exchange (ECDHE). No weak ciphers (CBC, RC4, DES, 3DES) are supported.

#### Certificate Details

| Field | Value |
|---|---|
| **Common Name** | cloudflare.com |
| **Issuer** | Cloudflare Inc ECC CA-3 |
| **Validation Type** | Domain Validation (DV) |
| **Key Algorithm** | ECDSA (secp256r1 / P-256) |
| **Key Size** | 256 bits |
| **Signature Algorithm** | SHA-256 |
| **Validity Period** | 90 days (automated renewal) |
| **Certificate Transparency** | Yes (3 SCTs included) |

#### Warnings or Weaknesses Flagged

| Issue | Severity | Status |
|---|---|---|
| Legacy TLS support | High | None ✅ |
| Weak ciphers | High | None ✅ |
| Certificate issues | Medium | None ✅ |
| HSTS implementation | Medium | Implemented correctly ✅ |

**Summary:** Cloudflare's configuration achieves A+ by supporting only modern TLS versions (1.2 and 1.3), using perfect forward secrecy with ECDHE, selecting only AEAD ciphers, implementing HSTS properly, and maintaining short-lived certificates with automated renewal.

---

### Website 2: GitHub (A Rating)

**URL Tested:** github.com

#### Overall Grade

| Metric | Value |
|---|---|
| **Overall Rating** | A |
| **SSL/TLS Protocols** | TLS 1.2, TLS 1.3 |
| **Cipher Strength** | A |
| **Forward Secrecy** | Yes |
| **Certificate** | A |

#### Protocol Support

| Protocol | Version | Status |
|---|---|---|
| **TLS 1.0** | N/A | Disabled ✅ |
| **TLS 1.1** | N/A | Disabled ✅ |
| **TLS 1.2** | Supported | Enabled ✅ |
| **TLS 1.3** | Supported | Enabled ✅ |

#### Key Exchange Strength

| Parameter | Value | Security Level |
|---|---|---|
| **Key Exchange Algorithm** | ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) | Strong |
| **Curve Used** | X25519, secp256r1 (P-256) | Strong |
| **Certificate Key Size** | RSA 2048 bits | Strong |
| **Forward Secrecy** | Yes | Perfect Forward Secrecy (PFS) achieved |

#### Cipher Suite Selection

GitHub supports 10 cipher suites, ordered by preference:

```
TLS_AES_128_GCM_SHA256 
TLS_AES_256_GCM_SHA384 
TLS_CHACHA20_POLY1305_SHA256 
ECDHE-RSA-AES128-GCM-SHA256 
ECDHE-RSA-AES256-GCM-SHA384 
ECDHE-RSA-CHACHA20-POLY1305-SHA
```


**Analysis:** GitHub uses modern ECDHE key exchange with all AEAD ciphers (GCM and ChaCha20-Poly1305). No legacy CBC-mode, RC4, or 3DES ciphers are present. Forward secrecy is mandatory.

#### Certificate Details

| Field | Value |
|---|---|
| **Common Name** | *.github.com |
| **Issuer** | DigiCert TLS Hybrid ECC RSA4096 SHA384 2020 CA1 |
| **Validation Type** | Organization Validation (OV) |
| **Key Algorithm** | RSA (2048-bit) |
| **Key Size** | 2048 bits |
| **Signature Algorithm** | SHA-384 |
| **Validity Period** | 398 days (max per CA/B Forum) |
| **Certificate Transparency** | Yes (3 SCTs included) |

#### Warnings or Weaknesses Flagged

| Issue | Severity | Status |
|---|---|---|
| Legacy TLS support | High | None ✅ |
| Weak ciphers | High | None ✅ |
| Certificate issues | Medium | None ✅ |
| HSTS implementation | Medium | Implemented correctly ✅ |

**Minor Deduction Note:** GitHub receives an A rather than A+ because they use RSA for the certificate (ECDSA would be slightly faster for handshakes), but this is a very minor distinction and does not indicate any actual security weakness.

---

### Comparative Analysis

| Feature | Cloudflare (A+) | GitHub (A) | MedDefense Portal (Predicted) | Best Practice |
|---|---|---|---|---|
| TLS 1.3 | ✅ Enabled | ✅ Enabled | ❌ Disabled | Enable TLS 1.3 |
| TLS 1.2 | ✅ Only | ✅ Only | ⚠️ Also supports TLS 1.0 | Use TLS 1.2 minimum |
| TLS 1.0/1.1 | ❌ Disabled | ❌ Disabled | ❌ **Enabled** | Disable immediately |
| ECDHE Key Exchange | ✅ All ciphers | ✅ All ciphers | ❌ Unknown/RSA static | Use ECDHE everywhere |
| AEAD Ciphers | ✅ 100% | ✅ 100% | ⚠️ CBC likely present | Prefer GCM/Poly1305 |
| Deprecated Ciphers | ❌ None | ❌ None | ❓ Likely 3DES/RC4 | Remove immediately |
| Forward Secrecy | ✅ Yes | ✅ Yes | ❌ Possibly absent | Mandatory |
| HSTS | ✅ Yes | ✅ Yes | ❌ Missing | Implement with preload |
| Certificate Transparency | ✅ Yes | ✅ Yes | ❌ No SCTs | Enable CT logging |
| Certificate Expiry | ✅ 90 days | ✅ 398 days | ❌ **Near expiration** | Renew ASAP |

---

## Part 2 - MedDefense Portal Assessment

### Predicted SSL Labs Grade: D or F

Based on Finding 005 (TLS 1.0 enabled, TLS 1.2 supported) and Finding 013 (certificate near expiration), the patient portal would receive a failing grade if publicly assessed.

### Issues That Would Reduce the Grade

| Issue | Severity | Impact on Grade |
|---|---|---|
| **TLS 1.0 Support** | Critical | Reduces grade by 2 levels (A→C minimum) |
| **TLS 1.2 Only** (no TLS 1.3) | Medium | Reduces grade by 1 level (cannot exceed B+) |
| **Missing HSTS Header** | High | Prevents grade above B |
| **Weak Cipher Suites** (potential CBC/3DES) | High | Further reduces grade |
| **Static RSA Key Exchange** (if configured) | Medium | Eliminates Perfect Forward Secrecy |
| **Certificate Expiring Soon** (Finding 013) | High | Automatic grade reduction |
| **Incomplete Certificate Chain** (possible) | Medium | Causes browser warnings |
| **No OCSP Stapling** | Low | Minor score deduction |
| **Weak DH Parameters** (if < 2048-bit) | High | Can cause automatic F |

### Detailed Scoring Breakdown

| Category | Score | Max Possible | Notes |
|---|---|---|---|
| **Protocol Support** | 25/40 | 40 points | TLS 1.0 (+0), TLS 1.1 (+0), TLS 1.2 (+25), TLS 1.3 (+15 missing) |
| **Key Exchange** | 15/30 | 30 points | ECDHE partial (15), RSA static (0), no forward secrecy |
| **Cipher Strength** | 10/30 | 30 points | CBC modes (-5), 3DES possible (-10), no ChaCha20 (-5) |
| **Certificate** | 5/10 | 10 points | Expiring soon (-5), no CT logging (-5) |
| **Penalties** | -20 | N/A | TLS 1.0 (-15), HSTS missing (-5) |
| **Final Score** | 35/110 | 100 points | **Grade: D or F depending on actual cipher suite** |

### Root Cause Analysis

The patient portal's poor configuration stems from three underlying issues:

1. **Legacy Apache Configuration**: The web-srv-01 server is running Apache 2.4.38, which defaults to supporting TLS 1.0 when the `SSLCipherSuite` directive doesn't explicitly exclude legacy protocols and ciphers.

2. **Default SSL Settings**: The original system administrator copied a sample SSL configuration from Apache documentation without updating the `SSLProtocol` directive, leaving TLSv1 and TLSv1.1 enabled.

3. **No Security Testing**: The organization has never run external security scans against the portal, so Finding 005 was discovered internally through manual assessment rather than automated vulnerability scanning.

### Business Impact

If left unaddressed, these TLS configuration issues expose MedDefense to:

| Risk | Consequence | Likelihood |
|---|---|---|
| **Man-in-the-Middle Attack** | Patient credentials and PHI intercepted over TLS 1.0 | High on flat network |
| **BEAST Exploitation** | Session cookies decrypted via CBC-mode weakness | Medium |
| **Downgrade Attack** | Attacker forces client to TLS 1.0 | High if not mitigated |
| **HIPAA Non-Compliance** | Audit failure for inadequate encryption controls | Certain if discovered |
| **Breach Notification** | Required if PHI exposed due to weak TLS | High if attacked |
| **Reputational Damage** | News of insecure patient portal | Medium |

---

## Part 3 - The Hardened Configuration

### Apache Hardened TLS Configuration

The following configuration should replace the existing SSL settings in `/etc/apache2/sites-available/meddefense-ssl.conf` on web-srv-01:

```
===========================================
MedDefense Patient Portal - Hardened TLS
===========================================
Reference: Apache 2.4 OpenSSL TLS Hardening Guide
Last Updated: July 27, 2026
Author: Steve, Security Engineer
===========================================

<VirtualHost *:443> ServerName portal.meddefense.local DocumentRoot /var/www/portal
# TLS Protocol Configuration
# -------------------------------------------
# Disable TLS 1.0 and 1.1; enable only TLS 1.2 and 1.3
SSLProtocol -all +TLSv1.2 +TLSv1.3

# TLS 1.2 and 1.3 Cipher Suite Configuration
# -------------------------------------------
# Prefer TLS 1.3 ciphers first, then TLS 1.2 with ECDHE + GCM/ChaCha20
# Ordering places strongest ciphers first for client negotiation
SSLCipherSuite TLSv1.3 HIGH:!aNULL:!MD5:!3DES:!RC4:!PSK:!SRP
SSLCipherSuite TLSv1.2 ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384

# Prioritize server cipher preference
SSLHonorCipherOrder on

# Perfect Forward Secrecy
# -------------------------------------------
# All ECDHE and DHE ciphers provide forward secrecy
# This ensures session keys cannot be recovered even if server private key is compromised
SSLSessionTickets off

# Certificate Configuration
# -------------------------------------------
# Full certificate chain including intermediate
SSLCertificateFile /etc/ssl/certs/portal.meddefense.local.fullchain.crt
SSLCertificateKeyFile /etc/ssl/private/portal.meddefense.local.key

# OCSP Stapling
# -------------------------------------------
# Enables server to present OCSP response during handshake
# Reduces latency and preserves client privacy by preventing CA from learning browsing habits
SSLUseStapling On
SSLStaplingCache shmcb:/var/run/ocsp(128000)
SSLStaplingStandardCacheTimeout 86400

# HSTS (HTTP Strict Transport Security)
# -------------------------------------------
# Forces browsers to use HTTPS for 2 years with subdomains and preload
# Prevents SSL stripping attacks and downgrade attempts
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"

# Additional Security Headers
# -------------------------------------------
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Renegotiation Protection
# -------------------------------------------
# Disable insecure renegotiation
SSLRenegBufferSize 1048576
SSLRequireSSL

# Logging
# -------------------------------------------
CustomLog /var/log/apache2/portal_ssl_access.log combined
ErrorLog /var/log/apache2/portal_ssl_error.log
LogLevel warn ssl:info
</VirtualHost>
```


### Configuration Rationale

| Directive | Setting | Reasoning |
|---|---|---|
| `SSLProtocol` | `-all +TLSv1.2 +TLSv1.3` | Disables deprecated TLS 1.0/1.1 that are vulnerable to BEAST and POODLE attacks |
| `SSLCipherSuite TLSv1.3` | `HIGH:!aNULL:!MD5:!3DES:!RC4:!PSK:!SRP` | Uses TLS 1.3's built-in cipher selection while explicitly excluding weak algorithms |
| `SSLCipherSuite TLSv1.2` | `ECDHE-*` ciphers ordered first | Ensures forward secrecy is mandatory and prioritizes AEAD modes (GCM/ChaCha20) |
| `SSLHonorCipherOrder` | `on` | Forces server cipher preference order rather than client, preventing weak cipher negotiation |
| `SSLSessionTickets` | `off` | Disables session tickets that could leak past session data if server key is compromised |
| `SSLUseStapling` | `On` | Improves performance and privacy by serving OCSP responses directly without client queries to CA |
| `Strict-Transport-Security` | `max-age=63072000` | Enforces HTTPS for 2 years, blocking initial cleartext requests and downgrade attempts |
| `Header always set` | Various | Blocks clickjacking, MIME sniffing, XSS, and ensures proper referrer handling |
| `LogLevel ssl:info` | `warn ssl:info` | Provides detailed TLS diagnostics for troubleshooting without excessive logging |

---

## Part 4 - The Downgrade Attack

### How a TLS Downgrade Attack Works

A TLS downgrade attack exploits the fact that servers historically supported multiple protocol versions for backward compatibility. An attacker positioned between the client and server intercepts the initial ClientHello message and modifies the `supported_versions` field to advertise only older, weaker protocols like TLS 1.0 or TLS 1.1. The server, seeing the client claims to support only legacy versions, responds with a ServerHello using the weakest available protocol. This gives the attacker access to known cryptographic weaknesses in the older protocol without the client ever knowing a downgrade occurred.

### Impact on MedDefense Portal

If MedDefense's portal supports both TLS 1.0 and TLS 1.2, an attacker on the flat network could perform a man-in-the-middle attack and force a patient's browser to use TLS 1.0, which exposes the session to several vulnerabilities: the BEAST attack can decrypt session cookies via CBC-mode cipher exploitation, the POODLE attack can recover plaintext from padding oracle vulnerabilities, and weak cipher suites (like RC4 or 3DES) might be negotiated that are cryptographically broken. Even if TLS 1.2 is technically supported, the attacker controls which version is actually used during the handshake.

### Prevention

The simplest way to prevent this attack is to **disable support for legacy protocols entirely** by setting `SSLProtocol -all +TLSv1.2 +TLSv1.3` in the Apache configuration, removing the ability to negotiate downgraded versions. Additionally, enable TLS_FALLBACK_SCSV (handled automatically by OpenSSL) and use the `Strict-Transport-Security` header to instruct browsers to always use HTTPS and reject cleartext connections. For future-proofing, also enable TLS 1.3, which includes built-in anti-downgrade protections in the handshake extension.

---

## Remediation Plan for MedDefense Portal

| Step | Action | Timeline | Owner |
|---|---|---|---|
| **1** | Backup current Apache SSL configuration | Day 0 | Steve |
| **2** | Apply hardened TLS configuration from Part 3 | Day 0 | Steve |
| **3** | Restart Apache and verify new certificate loads | Day 0 | SysAdmin |
| **4** | Test TLS connectivity from internal workstation | Day 0 | Steve |
| **5** | Run internal openssl tests to confirm TLS 1.0/1.1 disabled | Day 0 | Steve |
| **6** | Schedule maintenance window for production deployment | Day 1-3 | Project Manager |
| **7** | Deploy hardened config to production web-srv-01 | Day 3-5 | Steve |
| **8** | Verify portal functionality with clinical staff | Day 5 | QA Team |
| **9** | Remove old certificate from archive after 30 days | Day 35 | Steve |
| **10** | Document configuration change in change management system | Day 5 | Steve |

### Validation Commands

- Verify TLS 1.0/1.1 is disabled (should fail to connect)

```bash
openssl s_client -connect portal.meddefense.local:443 -tls1 2>&1 | grep "handshake failure" openssl s_client -connect portal.meddefense.local:443 -tls1_1 2>&1 | grep "handshake failure"
```

- Verify TLS 1.2 works (should connect successfully)

```bash
openssl s_client -connect portal.meddefense.local:443 -tls1_2 </dev/null 2>&1 | grep "Verify return code: 0"
```

- Verify TLS 1.3 works (should connect successfully)

```bash
openssl s_client -connect portal.meddefense.local:443 -tls1_3 </dev/null 2>&1 | grep "Verify return code: 0"
```

- Check HSTS header is present

```bash
curl -I https://portal.meddefense.local | grep -i strict-transport-security
```

- Check for weak ciphers (should show no results)

```bash
nmap --script ssl-enum-ciphers -p 443 portal.meddefense.local | grep -E "TLSv1.0|TLSv1.1|3DES|RC4"
```

### Expected Outcome

After remediation:
- SSL Labs score increases from **D/F → A or A+**
- HIPAA audit compliance restored (adequate encryption controls verified)
- Patient trust improved through visible security indicators
- Reduced attack surface eliminates known TLS vulnerabilities
- Forward secrecy protects past sessions from future key compromises
