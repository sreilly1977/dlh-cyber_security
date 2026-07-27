# 9. The Chain of Trust

## Goal

Capture and verify a complete certificate chain, understand how trust propagates from root to leaf, and analyze what happens when the chain breaks.

## Context

A certificate is only as trustworthy as the chain behind it. The patient's browser trusts the portal's certificate because it trusts the intermediate CA that signed it, which it trusts because it trusts the root CA in its trust store. If any link in this chain is invalid, expired, revoked, or untrusted, the entire connection fails.

---

## Part 1 - Capture the Full Chain

### Capture the Certificate Chain from github.com

```bash
~/projects/cert
❯ openssl s_client -connect github.com:443 -servername github.com -showcerts </dev/null 2>/dev/null > github_chain.pem

~/projects/cert
❯ cat github_chain.pem
CONNECTED(00000003)
---
Certificate chain
 0 s:CN=github.com
   i:C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA256
   v:NotBefore: Jul  3 00:00:00 2026 GMT; NotAfter: Sep 30 23:59:59 2026 GMT
-----BEGIN CERTIFICATE-----
MIID7jCCA5SgAwIBAgIQcgEOA/SgZ/5OeWJmQwcY9jAKBggqhkjOPQQDAjBgMQsw
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5T
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgRTM2MB4X
DTI2MDcwMzAwMDAwMFoXDTI2MDkzMDIzNTk1OVowFTETMBEGA1UEAxMKZ2l0aHVi
LmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIWWMDSOi/1sMgquP4I/obBM
735wpzcIZi4fLeiBsToXVVSwjj4OPH+W6azHzxETM0gUP7raehddpJ8uwjqYsTij
ggJ5MIICdTAfBgNVHSMEGDAWgBQXmagEwW/kLXCoChA9A9PpGrgmYzAdBgNVHQ4E
FgQUEKU6Ytbv1gZWnty4gvzCe2hdPWkwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB
/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwSQYDVR0gBEIwQDA0BgsrBgEEAbIx
AQICBzAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZn
gQwBAgEwgYQGCCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZDaHR0cDovL2NydC5z
ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljU2VydmVyQXV0aGVudGljYXRpb25DQURW
RTM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wggEF
BgorBgEEAdZ5AgQCBIH2BIHzAPEAdgDXbX0Q0af1d8LH6V/XAL/5gskzWmXh0LMB
cxfAyMVpdwAAAZ8lTHVtAAAEAwBHMEUCIQCkpa0ZYNwsPiMRLHz+kk1QS/W9bg/8
4yNBVGkT289dNQIgMWLgxYp6vGJXJxyD3c1NI1aZsPA7GqyLSXaZLZHgKh0AdwDI
o8R/x7OtuTVrAT9qehJt4zpOQ6XGRvmXrTl1mR3PmgAAAZ8lTHVhAAAEAwBIMEYC
IQDsO+TR8EVfCiObBPoDLRKzKLQ/uorsebJ2aZDIejA9RgIhAJ6dp7FqCD93tQXX
AF24pDIms1fX4dZ+VPzXGuD8u8t1MCUGA1UdEQQeMByCCmdpdGh1Yi5jb22CDnd3
dy5naXRodWIuY29tMAoGCCqGSM49BAMCA0gAMEUCIB0PC2GRSurxu8gCkSNsYxmw
kAtCNfCvpXRiif8PhGkmAiEAzBH4AVYAtv1FsMrJabD9FYcAql0EteKafckH2exj
Uag=
-----END CERTIFICATE-----
 1 s:C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
   i:C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46
   a:PKEY: EC, (prime256v1); sigalg: ecdsa-with-SHA384
   v:NotBefore: Mar 22 00:00:00 2021 GMT; NotAfter: Mar 21 23:59:59 2036 GMT
-----BEGIN CERTIFICATE-----
MIIDXzCCAuagAwIBAgIQNuBZ7YiN1Xrt1XC2cn+b2jAKBggqhkjOPQQDAzBfMQsw
CQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1T
ZWN0aWdvIFB1YmxpYyBTZXJ2ZXIgQXV0aGVudGljYXRpb24gUm9vdCBFNDYwHhcN
MjEwMzIyMDAwMDAwWhcNMzYwMzIxMjM1OTU5WjBgMQswCQYDVQQGEwJHQjEYMBYG
A1UEChMPU2VjdGlnbyBMaW1pdGVkMTcwNQYDVQQDEy5TZWN0aWdvIFB1YmxpYyBT
ZXJ2ZXIgQXV0aGVudGljYXRpb24gQ0EgRFYgRTM2MFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEaKGnbAUnBYljHDmn/yUhxe3TLxKYuyzc9VXoSaCEV5F73Fhfa/Si
/RMsmwTFW3R9s7J6JpYZFmu4do3vk/Vgl6OCAYEwggF9MB8GA1UdIwQYMBaAFNEi
2kxZ8UtfJjiqndbu6w3D+6lhMB0GA1UdDgQWBBQXmagEwW/kLXCoChA9A9PpGrgm
YzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEC
ATBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
Z29QdWJsaWNTZXJ2ZXJBdXRoZW50aWNhdGlvblJvb3RFNDYuY3JsMIGEBggrBgEF
BQcBAQR4MHYwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2Vj
dGlnb1B1YmxpY1NlcnZlckF1dGhlbnRpY2F0aW9uUm9vdEU0Ni5wN2MwIwYIKwYB
BQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMAoGCCqGSM49BAMDA2cAMGQC
MFsKnBQDh64l+v+aUYWjDCJKQMxHUUGmcwAYDIjJ9pbRYItMCIx5xu0oUb6sIfTX
qQIwPddcsDE4KdeLu1hJdpHgdLvsHAK3vygyLGujMU9xBJCDackRT93VHEE0gppg
NqdV
-----END CERTIFICATE-----
 2 s:C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46
   i:C=US, ST=New Jersey, L=Jersey City, O=The USERTRUST Network, CN=USERTrust ECC Certification Authority
   a:PKEY: EC, (secp384r1); sigalg: ecdsa-with-SHA384
   v:NotBefore: Mar 22 00:00:00 2021 GMT; NotAfter: Jan 18 23:59:59 2038 GMT
-----BEGIN CERTIFICATE-----
MIIDRjCCAsugAwIBAgIQGp6v7G3o4ZtcGTFBto2Q3TAKBggqhkjOPQQDAzCBiDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl
eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT
JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIy
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBfMQswCQYDVQQGEwJHQjEYMBYGA1UEChMP
U2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIg
QXV0aGVudGljYXRpb24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR2
+pmpbiDt+dd34wc7qNs9Xzjoq1WmVk/WSOrsfy2qw7LFeeyZYX8QeccCWvkEN/U0
NSt3zn8gj1KjAIns1aeibVvjS5KToID1AZTc8GgHHs3u/iVStSBDHBv+6xnOQ6Oj
ggEgMIIBHDAfBgNVHSMEGDAWgBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAdBgNVHQ4E
FgQU0SLaTFnxS18mOKqd1u7rDcP7qWEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBEGA1UdIAQK
MAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVz
dC5jb20vVVNFUlRydXN0RUNDQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwNQYI
KwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3Qu
Y29tMAoGCCqGSM49BAMDA2kAMGYCMQCMCyBit99vX2ba6xEkDe+YO7vC0twjbkv9
PKpqGGuZ61JZryjFsp+DFpEclCVy4noCMQCwvZDXD/m2Ko1HA5Bkmz7YQOFAiNDD
49IWa2wdT7R3DtODaSXH/BiXv8fwB9su4tU=
-----END CERTIFICATE-----
---
Server certificate
subject=CN=github.com
issuer=C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
---
No client certificate CA names sent
Peer signing digest: SHA256
Peer signature type: ecdsa_secp256r1_sha256
Peer Temp Key: X25519, 253 bits
---
SSL handshake has read 3089 bytes and written 1616 bytes
Verification: OK
---
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Protocol: TLSv1.3
Server public key is 256 bit
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---

~/projects/cert
❯ wc -l github_chain.pem

103 github_chain.pem
```

### Split the chain into individual certificate files

```bash
~/projects/cert
# Extract leaf certificate only (first certificate block)
awk '/-----BEGIN CERTIFICATE-----/{n++} n==1' github_chain.pem > leaf_cert.pem

# Extract intermediate (second certificate block)
awk '/-----BEGIN CERTIFICATE-----/{n++} n==2' github_chain.pem > intermediate_ca.pem

# Extract root (third certificate block, if present)
awk '/-----BEGIN CERTIFICATE-----/{n++} n==3' github_chain.pem > root_ca.pem

~/projects/cert
❯ ll
.rw-r--r-- 5.3k steve 27 Jul 16:16  github_chain.pem
.rw-r--r-- 1.5k steve 27 Jul 17:18  intermediate_ca.pem
.rw-r--r-- 1.7k steve 27 Jul 17:16  leaf_cert.pem
.rw-r--r-- 1.8k steve 27 Jul 17:18  root_ca.pem

```

#### Display chain summary — Subject, Issuer, and dates for each cert

```bash
~/projects/cert
❯ openssl x509 -in intermediate_cert.pem -noout -subject -issuer -dates
subject=CN=github.com
issuer=C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
notBefore=Jul  3 00:00:00 2026 GMT
notAfter=Sep 30 23:59:59 2026 GMT
```

#### Show how Issuer of leaf matches Subject of intermediate

```bash
~/projects/cert
❯ echo "Leaf Issuer:      $(openssl x509 -in leaf_cert.pem -noout -issuer | sed 's/issuer=//')"
Leaf Issuer:      C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36

~/projects/cert
❯ echo "Intermediate Subj: $(openssl x509 -in intermediate_ca.pem -noout -subject | sed 's/subject=//')"
Intermediate Subj: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36

~/projects/cert
❯ echo "Intermediate Iss: $(openssl x509 -in intermediate_ca.pem -noout -issuer | sed 's/issuer=//')"
Intermediate Iss: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication Root E46
```

#### Full text dump of each certificate for documentation

```bash
~/projects/cert
❯ openssl x509 -in leaf_cert.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            72:01:0e:03:f4:a0:67:fe:4e:79:62:66:43:07:18:f6
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36
        Validity
            Not Before: Jul  3 00:00:00 2026 GMT
            Not After : Sep 30 23:59:59 2026 GMT
        Subject: CN=github.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:85:96:30:34:8e:8b:fd:6c:32:0a:ae:3f:82:3f:
                    a1:b0:4c:ef:7e:70:a7:37:08:66:2e:1f:2d:e8:81:
                    b1:3a:17:55:54:b0:8e:3e:0e:3c:7f:96:e9:ac:c7:
                    cf:11:13:33:48:14:3f:ba:da:7a:17:5d:a4:9f:2e:
                    c2:3a:98:b1:38
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                17:99:A8:04:C1:6F:E4:2D:70:A8:0A:10:3D:03:D3:E9:1A:B8:26:63
            X509v3 Subject Key Identifier: 
                10:A5:3A:62:D6:EF:D6:06:56:9E:DC:B8:82:FC:C2:7B:68:5D:3D:69
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Certificate Policies: 
                Policy: 1.3.6.1.4.1.6449.1.2.2.7
                  CPS: https://sectigo.com/CPS
                Policy: 2.23.140.1.2.1
            Authority Information Access: 
                CA Issuers - URI:http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt
                OCSP - URI:http://ocsp.sectigo.com
            CT Precertificate SCTs: 
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : D7:6D:7D:10:D1:A7:F5:77:C2:C7:E9:5F:D7:00:BF:F9:
                                82:C9:33:5A:65:E1:D0:B3:01:73:17:C0:C8:C5:69:77
                    Timestamp : Jul  3 00:06:35.629 2026 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:45:02:21:00:A4:A5:AD:19:60:DC:2C:3E:23:11:2C:
                                7C:FE:92:4D:50:4B:F5:BD:6E:0F:FC:E3:23:41:54:69:
                                13:DB:CF:5D:35:02:20:31:62:E0:C5:8A:7A:BC:62:57:
                                27:1C:83:DD:CD:4D:23:56:99:B0:F0:3B:1A:AC:8B:49:
                                76:99:2D:91:E0:2A:1D
                Signed Certificate Timestamp:
                    Version   : v1 (0x0)
                    Log ID    : C8:A3:C4:7F:C7:B3:AD:B9:35:6B:01:3F:6A:7A:12:6D:
                                E3:3A:4E:43:A5:C6:46:F9:97:AD:39:75:99:1D:CF:9A
                    Timestamp : Jul  3 00:06:35.617 2026 GMT
                    Extensions: none
                    Signature : ecdsa-with-SHA256
                                30:46:02:21:00:EC:3B:E4:D1:F0:45:5F:0A:23:9B:04:
                                FA:03:2D:12:B3:28:B4:3F:BA:8A:EC:79:B2:76:69:90:
                                C8:7A:30:3D:46:02:21:00:9E:9D:A7:B1:6A:08:3F:77:
                                B5:05:D7:00:5D:B8:A4:32:26:B3:57:D7:E1:D6:7E:54:
                                FC:D7:1A:E0:FC:BB:CB:75
            X509v3 Subject Alternative Name: 
                DNS:github.com, DNS:www.github.com
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:1d:0f:0b:61:91:4a:ea:f1:bb:c8:02:91:23:6c:
        63:19:b0:90:0b:42:35:f0:af:a5:74:62:89:ff:0f:84:69:26:
        02:21:00:cc:11:f8:01:56:00:b6:fd:45:b0:ca:c9:69:b0:fd:
        15:87:00:aa:5d:04:b5:e2:9a:7d:c9:07:d9:ec:63:51:a8
```

## Part 2 - Manual Chain Verification

#### Verify the leaf using the intermediate as untrusted CA

```bash
~/projects/cert
❯ openssl verify -CAfile root_ca.pem -untrusted intermediate_ca.pem leaf_cert.pem
leaf_cert.pem: OK

```

#### Verify using system trust store directly (no intermediate)

```bash
~/projects/cert
❯ openssl verify -CAfile root_ca.pem leaf_cert.pem
CN=github.com
error 20 at 0 depth lookup: unable to get local issuer certificate
error leaf_cert.pem: verification failed

```

#### Verify the intermediate against the system trust store

```bash
~/projects/cert
❯ openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt intermediate_ca.pem 2>&1
  echo "Exit code: $status"
intermediate_ca.pem: OK
Exit code: 0
```

#### Chain order verification — confirm leaf is first, intermediate second

```bash
~/projects/cert
❯ grep -c "BEGIN CERTIFICATE" github_chain.pem
  echo "Certificates in chain file: $(grep -c 'BEGIN CERTIFICATE' github_chain.pem)"
3
Certificates in chain file: 3
```

## Part 3 - Revocation Mechanisms

### CRL (Certificate Revocation List)

A Certificate Revocation List is a signed, timestamped list of serial numbers of certificates that a CA has revoked before their scheduled expiration date. The CA publishes the CRL at a URL specified in the certificate's CRL Distribution Points extension, and clients download and cache the list, checking whether the certificate's serial number appears in it before trusting the certificate. The main limitations of CRLs are size and freshness: a large CA's CRL can grow to megabytes as revoked certificates accumulate, and the list is only updated at intervals (often every 24 hours), meaning a certificate revoked minutes ago may not appear in the cached CRL the client uses. Additionally, downloading a multi-megabyte CRL on every TLS connection introduces unacceptable latency for users, especially on mobile networks.

### OCSP (Online Certificate Status Protocol)

OCSP is a real-time protocol that allows clients to query the CA directly about the revocation status of a specific certificate by its serial number, receiving a signed response of "good," "revoked," or "unknown." This improves on CRLs by eliminating the need to download large lists and providing near-real-time revocation status. However, standard OCSP introduces privacy and performance concerns: the client must make a separate HTTP request to the CA's OCSP responder for every TLS connection, leaking the user's browsing habits to the CA and adding latency.

### OCSP Stapling

OCSP Stapling addresses the privacy and latency problems of standard OCSP by having the server fetch its own OCSP response from the CA and "staple" it to the TLS handshake. The client receives the signed OCSP response directly from the server during the normal handshake, eliminating the need for a separate request to the CA. This means the CA never learns which sites the client is visiting, and the handshake completes faster since no additional round trip is needed. The stapled response is time-limited and signed by the CA, so the client can verify its authenticity. OCSP Stapling is also called the TLS Certificate Status Request extension (RFC 6066).

| Feature | CRL | OCSP | OCSP Stapling |
|---|---|---|---|
| **Mechanism** | Download full revocation list | Query CA per certificate | Server fetches and presents OCSP response |
| **Update Frequency** | Every 24 hours (typical) | Near real-time | Near real-time (cached by server) |
| **Client Privacy** | No leakage (cached locally) | CA sees client queries | No leakage (server queries CA) |
| **Performance Impact** | High (large downloads) | Medium (extra round trip) | Low (embedded in handshake) |
| **Failure Mode** | Uses stale list | Connection may fail open or closed | Falls back to CRL or OCSP |
| **Bandwidth** | High (megabytes) | Low (small response) | Low (stapled in handshake) |

### MedDefense Key Compromise Scenario

#### Scenario

From MCQ T25 of 1x03: MedDefense's portal private key was accidentally committed to a public Git repository. An attacker has downloaded the key and can impersonate `portal.meddefense.org`.

#### Immediate Response Sequence

| Step | Action | Timeframe | Owner |
|---|---|---|---|
| **1** | Confirm the key exposure by verifying the Git commit contains a valid private key and checking the key fingerprint against the production certificate | Within 1 hour | Security Engineer (Steve) |
| **2** | Contact the Certificate Authority (DigiCert/Sectigo) emergency support line to request immediate certificate revocation | Within 1 hour | Security Engineer |
| **3** | Provide the CA with the certificate serial number, reason code (key compromise), and evidence of exposure | Within 2 hours | Security Engineer |
| **4** | CA revokes the certificate, adds it to the CRL, and updates the OCSP responder to return "revoked" status | Within 4 hours of CA confirmation | Certificate Authority |
| **5** | Generate a new RSA-2048 or ECC P-256 private key on a clean, air-gapped system (NOT on the compromised server) | Within 4 hours | Security Engineer |
| **6** | Generate a new CSR with the new key and submit to the CA for a replacement certificate | Within 6 hours | Security Engineer |
| **7** | Deploy the new certificate and private key to the portal web server | Within 8 hours | Systems Administrator |
| **8** | Force all active TLS sessions to renegotiate by restarting the web server (nginx/Apache reload) | Within 8 hours | Systems Administrator |
| **9** | Scrub the Git repository history to remove the private key using git filter-branch or BFG Repo Cleaner | Within 24 hours | DevOps Engineer |
| **10** | Rotate any credentials that may have been stored alongside the private key in the repository | Within 24 hours | Security Engineer |
| **11** | Notify MedDefense's compliance officer and document the incident per HIPAA Breach Notification Rule | Within 24 hours | CISO |
| **12** | If the compromised key was used for more than 72 hours before detection, notify patients per HIPAA Breach Notification requirements (60-day rule) | Within 60 days | CISO + Legal Counsel |
| **13** | Enable OCSP Stapling on the web server to ensure clients check revocation status without performance penalty | Within 48 hours | Systems Administrator |
| **14** | Implement automated certificate monitoring with expiration and revocation alerts | Within 1 week | Security Engineer |
| **15** | Conduct post-incident review to identify root cause and prevent recurrence | Within 2 weeks | CISO |

---

## Part 4 - Trust Store Exploration

### Locate the System Trust Store

```bash
~/projects/cert
❯ ls /etc/ssl/certs/*.pem | wc -l
121
```

#### Pick one root CA certificate and inspect it

```bash
~/projects/cert
❯ openssl x509 -in /etc/ssl/certs/Amazon_Root_CA_1.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            06:6c:9f:cf:99:bf:8c:0a:39:e2:f0:78:8a:43:e6:96:36:5b:ca
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Amazon, CN=Amazon Root CA 1
        Validity
            Not Before: May 26 00:00:00 2015 GMT
            Not After : Jan 17 00:00:00 2038 GMT
        Subject: C=US, O=Amazon, CN=Amazon Root CA 1
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:b2:78:80:71:ca:78:d5:e3:71:af:47:80:50:74:
                    7d:6e:d8:d7:88:76:f4:99:68:f7:58:21:60:f9:74:
                    84:01:2f:ac:02:2d:86:d3:a0:43:7a:4e:b2:a4:d0:
                    36:ba:01:be:8d:db:48:c8:07:17:36:4c:f4:ee:88:
                    23:c7:3e:eb:37:f5:b5:19:f8:49:68:b0:de:d7:b9:
                    76:38:1d:61:9e:a4:fe:82:36:a5:e5:4a:56:e4:45:
                    e1:f9:fd:b4:16:fa:74:da:9c:9b:35:39:2f:fa:b0:
                    20:50:06:6c:7a:d0:80:b2:a6:f9:af:ec:47:19:8f:
                    50:38:07:dc:a2:87:39:58:f8:ba:d5:a9:f9:48:67:
                    30:96:ee:94:78:5e:6f:89:a3:51:c0:30:86:66:a1:
                    45:66:ba:54:eb:a3:c3:91:f9:48:dc:ff:d1:e8:30:
                    2d:7d:2d:74:70:35:d7:88:24:f7:9e:c4:59:6e:bb:
                    73:87:17:f2:32:46:28:b8:43:fa:b7:1d:aa:ca:b4:
                    f2:9f:24:0e:2d:4b:f7:71:5c:5e:69:ff:ea:95:02:
                    cb:38:8a:ae:50:38:6f:db:fb:2d:62:1b:c5:c7:1e:
                    54:e1:77:e0:67:c8:0f:9c:87:23:d6:3f:40:20:7f:
                    20:80:c4:80:4c:3e:3b:24:26:8e:04:ae:6c:9a:c8:
                    aa:0d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                84:18:CC:85:34:EC:BC:0C:94:94:2E:08:59:9C:C7:B2:10:4E:0A:08
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        98:f2:37:5a:41:90:a1:1a:c5:76:51:28:20:36:23:0e:ae:e6:
        28:bb:aa:f8:94:ae:48:a4:30:7f:1b:fc:24:8d:4b:b4:c8:a1:
        97:f6:b6:f1:7a:70:c8:53:93:cc:08:28:e3:98:25:cf:23:a4:
        f9:de:21:d3:7c:85:09:ad:4e:9a:75:3a:c2:0b:6a:89:78:76:
        44:47:18:65:6c:8d:41:8e:3b:7f:9a:cb:f4:b5:a7:50:d7:05:
        2c:37:e8:03:4b:ad:e9:61:a0:02:6e:f5:f2:f0:c5:b2:ed:5b:
        b7:dc:fa:94:5c:77:9e:13:a5:7f:52:ad:95:f2:f8:93:3b:de:
        8b:5c:5b:ca:5a:52:5b:60:af:14:f7:4b:ef:a3:fb:9f:40:95:
        6d:31:54:fc:42:d3:c7:46:1f:23:ad:d9:0f:48:70:9a:d9:75:
        78:71:d1:72:43:34:75:6e:57:59:c2:02:5c:26:60:29:cf:23:
        19:16:8e:88:43:a5:d4:e4:cb:08:fb:23:11:43:e8:43:29:72:
        62:a1:a9:5d:5e:08:d4:90:ae:b8:d8:ce:14:c2:d0:55:f2:86:
        f6:c4:93:43:77:66:61:c0:b9:e8:41:d7:97:78:60:03:6e:4a:
        72:ae:a5:d1:7d:ba:10:9e:86:6c:1b:8a:b9:59:33:f8:eb:c4:
        90:be:f1:b9
```

### Analysis of Amazon Root CA 1 Certificate

#### Validity Period

| Field | Value |
|---|---|
| **Not Before** | May 26, 2015 GMT |
| **Not After** | January 17, 2038 GMT |
| **Total Validity** | Approximately **22.5 years** (8,261 days) |

#### Does This Surprise Me?

Yes and no—this depends on what comparison we're making:

| Perspective | Is This Surprising? |
|---|---|
| **Compared to end-entity certificates** (e.g., web server certs) | **Yes, extremely.** End-entity certificates are capped at 398 days maximum per the CA/Browser Forum Baseline Requirements. A 22.5-year validity is nearly 20 times longer. |
| **Compared to other root CAs** (e.g., DigiCert Global Root CA) | **No, this is typical.** Root CAs consistently have 20-25 year validity periods because rotating a root CA is operationally massive. |

#### Why This Length Makes Sense (and Why It Doesn't)

**Why such long validity periods make sense:**

1. **Trust store inertia**: Every browser, operating system, and application in the world that trusts Amazon Root CA 1 must be updated to trust its successor before this root expires. If this root expires on January 17, 2038, every client connecting to AWS services after that date will see certificate errors unless the transition is completed well in advance.

2. **Backward compatibility**: Old systems (like Windows XP, Windows 7, or embedded medical devices) may not receive OS updates after their end-of-life. These systems must continue to trust this root CA indefinitely to access AWS-hosted services.

3. **Chain of trust stability**: All certificates issued by Amazon Root CA 1 and its intermediates depend on this root remaining valid. If the root expires, every subordinate certificate in the entire Amazon PKI tree becomes untrustworthy simultaneously.

**Why this length is concerning:**

1. **Algorithm obsolescence**: The RSA-2048 key and SHA-256 signature algorithm used by this root may be considered weak by 2038 standards. NIST projects RSA-2048 security until ~2030, meaning this root's cryptographic strength is borderline at expiry.

2. **Key compromise risk window**: If Amazon's root private key were compromised, the impact would be catastrophic. Because the root is trusted so broadly, an attacker could impersonate any AWS service anywhere in the world.

3. **No natural expiration pressure**: Unlike 90-day Let's Encrypt certificates that force operational discipline through frequent renewal, a 22.5-year validity creates complacency risk—engineers may forget about this root entirely until it's too late.

#### Comparison to DigiCert Global Root CA

| Attribute | Amazon Root CA 1 | DigiCert Global Root CA |
|---|---|---|
| **Valid From** | May 26, 2015 | November 10, 2006 |
| **Valid Until** | January 17, 2038 | November 10, 2031 |
| **Total Duration** | 22.5 years | 25 years |
| **Signature Algorithm** | SHA-256 | SHA-1 |
| **Key Size** | RSA-2048 | RSA-2048 |
| **Self-Signed** | Yes | Yes |

Both roots follow the same pattern: decades-long validity, same key size, self-signed, with Amazon using the more secure SHA-256 algorithm (while DigiCert's root still uses deprecated SHA-1).

#### Conclusion

The 22.5-year validity period does **not** surprise me in the context of root CA certificates, as we established in Part 4 of Task 9 that root CAs operate under fundamentally different constraints than end-entity certificates.
