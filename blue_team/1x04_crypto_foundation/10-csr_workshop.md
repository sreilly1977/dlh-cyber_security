# 10. The CSR Workshop

## Goal

Generate a Certificate Signing Request for the MedDefense patient portal, making every field decision deliberately and documenting the reasoning.

## Context

The patient portal certificate expires in 18 days. James Chen has approved the renewal. You are generating the CSR that will be submitted to the Certificate Authority. Every field in the CSR becomes a field in the certificate, and every field matters. A wrong Common Name locks out patients. A missing SAN entry breaks mobile access. A weak key algorithm undermines the entire purpose.

---

## Part 1 - Key Generation Decision

### Algorithm Selection: RSA-2048

**Chosen algorithm: RSA-2048**

RSA-2048 is selected over RSA-4096 and ECC P-256 for the patient portal based on four factors. First, RSA-2048 provides 112-bit security, which meets NIST SP 800-57 minimum requirements for use through 2030 and aligns with the MedDefense Algorithm Reference Table (Task 6) approval criteria. Second, the web server (web-srv-01) handles approximately 800 patient connections per day, a moderate load where RSA-2048's TLS handshake overhead of 15-25ms is negligible compared to RSA-4096's 60-100ms per handshake, which would add measurable latency for elderly patients accessing the portal on older mobile devices. Third, RSA-2048 guarantees compatibility with all browsers and devices including older Android phones and legacy clinical workstations that may not support ECC cipher suites. Fourth, the CA/Browser Forum Baseline Requirements mandate a maximum 398-day certificate validity, meaning the key will be rotated annually, so RSA-2048's security margin is adequate for the certificate lifetime.

While ECC P-256 would offer faster handshakes and smaller key sizes, the compatibility risk with older patient devices outweighs the performance benefit at 800 connections per day. RSA-4096 would provide a longer security margin but doubles handshake computation time with no practical security advantage for a 1-year certificate.

### Key Generation Command

- Generate RSA-2048 private key and verify

```bash
openssl genrsa -out portal_key.pem 2048
openssl rsa -in portal_key.pem -text -noout | head -5
Private-Key: (2048 bit, 2 primes)
modulus:
    00:8f:22:96:63:1f:b8:c7:ec:02:d3:2b:44:f7:de:
    a8:b6:93:08:8c:b1:a2:4b:71:9d:e6:73:58:fa:a5:
    b5:85:66:65:27:30:c5:06:98:cf:ee:ca:e3:64:bd:
```

- Protect the private key and verify permissions

```bash
chmod 600 portal_key.pem
ls -l portal_key.pem
.rw------- 1.7k steve 27 Jul 20:22  portal_key.pem
```

---

## Part 2 - CSR Generation

### Create OpenSSL Configuration File

Rather than passing all parameters on the command line, an `openssl.cnf` file provides explicit control over every field and ensures SAN entries are included (a common omission when using command-line `-subj` alone, which does not reliably populate SANs in all OpenSSL versions).

```bash
cat > openssl.cnf << '\''EOF'\''
  [req]
  default_bits = 2048
  default_md = sha256
  distinguished_name = req_distinguished_name
  req_extensions = req_ext
  prompt = no

  [req_distinguished_name]
  C = US
  ST = California
  L = San Francisco
  O = MedDefense Health Systems
  OU = Information Technology
  CN = portal.meddefense.local

  [req_ext]
  subjectAltName = @alt_names
  basicConstraints = CA:FALSE
  keyUsage = digitalSignature, keyEncipherment
  extendedKeyUsage = serverAuth

  [alt_names]
  DNS.1 = portal.meddefense.local
  DNS.2 = patient.meddefense.local
  DNS.3 = www.portal.meddefense.local
  DNS.4 = api.meddefense.local
  EOF
```

### Field Justifications

| Field | Value | Reasoning |
|---|---|---|
| **C (Country)** | US | MedDefense is headquartered in San Francisco, California, USA |
| **ST (State)** | California | Primary facility location |
| **L (Locality)** | San Francisco | Corporate office location |
| **O (Organization)** | MedDefense Health Systems | Legal entity name as registered with the CA; must match business registration records for OV validation |
| **OU (Organizational Unit)** | Information Technology | Department responsible for the portal; provides internal organizational context |
| **CN (Common Name)** | portal.meddefense.local | Primary FQDN patients use to access the portal; the URL printed on patient materials and appointment reminders |
| **SAN DNS.1** | portal.meddefense.local | Primary domain (mirrors CN) |
| **SAN DNS.2** | patient.meddefense.local | Alternate URL some patients use based on marketing campaigns referencing "patient portal" |
| **SAN DNS.3** | www.portal.meddefense.local | Handles patients who prepend www. out of habit |
| **SAN DNS.4** | api.meddefense.local | Backend API endpoint used by the mobile responsive portal for AJAX calls; must be covered by the same certificate to avoid mixed-content warnings |
| **basicConstraints** | CA:FALSE | This is an end-entity certificate, not a CA certificate |
| **keyUsage** | digitalSignature, keyEncipherment | Required for TLS server authentication per RFC 5280 |
| **extendedKeyUsage** | serverAuth | Restricts certificate to TLS server authentication only |

### Generate the CSR and verify

```bash
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
ll
.rw-r--r--  566 steve 27 Jul 20:27  openssl.cnf
.rw-r--r-- 1.3k steve 27 Jul 20:28  portal.csr
.rw------- 1.7k steve 27 Jul 20:22  portal_key.pem
```

---

## Part 3 - CSR Inspection

### Inspect the Complete CSR

```bash
openssl req -text -noout -in portal.csr
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=US, ST=California, L=San Francisco, O=MedDefense Health Systems, OU=Information Technology, CN=portal.meddefense.local
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:8f:22:96:63:1f:b8:c7:ec:02:d3:2b:44:f7:de:
                    a8:b6:93:08:8c:b1:a2:4b:71:9d:e6:73:58:fa:a5:
                    b5:85:66:65:27:30:c5:06:98:cf:ee:ca:e3:64:bd:
                    76:1f:a9:11:ba:da:7d:a3:33:6e:19:15:d9:09:24:
                    7e:29:21:40:e2:7d:51:fa:9d:3e:97:43:2b:90:0a:
                    3a:46:b3:aa:50:93:41:97:79:d8:b8:48:b4:02:ea:
                    78:d1:e7:bc:a2:84:33:9b:ca:3a:de:8e:1d:74:29:
                    9a:69:69:4b:9f:07:ea:0d:68:c6:6e:3f:1b:cc:ba:
                    fc:bc:46:d9:f7:a4:9a:9a:11:78:14:44:c1:af:a1:
                    1d:a1:ca:02:1d:15:01:2c:04:89:e4:aa:da:e6:b8:
                    52:c8:ba:1d:bb:20:bc:91:8d:47:5f:f6:1c:56:de:
                    70:c8:10:9d:32:ff:9d:50:4b:30:69:dc:fb:1f:cb:
                    b8:3f:43:05:63:10:e2:00:d4:d3:5e:13:6c:67:fa:
                    91:38:eb:bb:96:3e:a5:4c:58:57:ed:7e:e6:78:af:
                    8c:7c:38:1d:39:09:b4:90:2a:0b:f9:91:5a:25:de:
                    03:aa:56:2c:6e:ce:4d:c1:fd:cf:9f:85:61:e3:30:
                    9a:cc:5a:09:0b:01:b1:0d:23:68:03:21:af:58:86:
                    03:d7
                Exponent: 65537 (0x10001)
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    DNS:portal.meddefense.local, DNS:patient.meddefense.local, DNS:www.portal.meddefense.local, DNS:api.meddefense.local
                X509v3 Basic Constraints: 
                    CA:FALSE
                X509v3 Key Usage: 
                    Digital Signature, Key Encipherment
                X509v3 Extended Key Usage: 
                    TLS Web Server Authentication
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        51:94:0b:77:50:cb:d3:90:b1:1a:db:ec:eb:06:38:4e:78:03:
        f1:61:cf:68:85:10:b7:46:ff:76:5b:77:f7:cc:17:61:5d:77:
        6e:b8:bf:66:d7:6e:1e:45:0f:fb:f0:54:d4:67:e4:5f:4f:76:
        cb:4d:d6:6c:3c:11:4b:e6:48:36:62:e1:f7:f1:59:2b:8e:0f:
        a4:2c:da:ac:66:3a:53:3c:6f:8a:33:00:1a:d8:20:ca:9b:a8:
        be:df:91:fb:48:1b:cc:8b:fd:fa:8b:dc:d7:55:9a:cf:e1:7a:
        c3:24:05:df:05:e8:6e:69:20:eb:32:01:84:c3:cd:00:6e:a2:
        72:3c:ac:46:9f:fe:92:8f:1d:8c:69:a1:cf:73:84:b0:49:cc:
        b9:c1:6f:e4:41:31:54:6d:07:bd:de:e2:5a:78:c5:b7:0b:7e:
        7b:89:70:94:74:ff:51:26:f3:3c:89:0e:22:a4:de:02:ed:ff:
        f5:26:c9:21:6b:68:46:c3:4c:71:f4:4b:c2:b3:8e:22:8d:ae:
        ef:55:5c:41:23:c9:c3:b8:75:5e:d4:e1:60:4f:2f:48:20:98:
        62:bd:e1:48:03:77:a2:5b:63:e7:13:91:ee:c8:b1:a6:c2:1d:
        53:8e:15:84:38:47:e8:30:d5:c0:43:be:76:fc:5b:49:76:f2:
        ef:34:0f:a5
```

### Verification Checklist

| Field | Expected Value | Verified |
|---|---|---|
| Subject C | US | ✅ |
| Subject ST | California | ✅ |
| Subject L | San Francisco | ✅ |
| Subject O | MedDefense Health Systems | ✅ |
| Subject OU | Information Technology | ✅ |
| Subject CN | portal.meddefense.local | ✅ |
| Public Key Algorithm | RSA | ✅ |
| Key Size | 2048 bits | ✅ |
| SAN DNS.1 | portal.meddefense.local | ✅ |
| SAN DNS.2 | patient.meddefense.local | ✅ |
| SAN DNS.3 | www.portal.meddefense.local | ✅ |
| SAN DNS.4 | api.meddefense.local | ✅ |
| Basic Constraints | CA:FALSE | ✅ |
| Key Usage | Digital Signature, Key Encipherment | ✅ |
| Extended Key Usage | TLS Web Server Authentication | ✅ |
| Signature Algorithm | sha256WithRSAEncryption | ✅ |

### Confirm SAN Entries Are Present

```bash
openssl req -text -noout -in portal.csr | grep -A1 "Subject Alternative Name"
                X509v3 Subject Alternative Name: 
                    DNS:portal.meddefense.local, DNS:patient.meddefense.local, DNS:www.portal.meddefense.local, DNS:api.meddefense.local
```

All four SAN entries are present. This confirms that patients using any of the four portal URLs will be served a valid certificate without browser warnings.

### Verify the Key and CSR Match

```bash
openssl rsa -in portal_key.pem -modulus -noout | openssl md5
MD5(stdin)= 8f4507baca8ec4788baee06fc36c3cbd

openssl req -in portal.csr -modulus -noout | openssl md5
MD5(stdin)= 8f4507baca8ec4788baee06fc36c3cbd
```

Matching MD5 hashes confirm the CSR was generated from the correct private key.

---

## Part 4 - The Full Lifecycle

### Certificate Lifecycle Procedure for MedDefense Patient Portal

#### Phase 1: Preparation (Completed)

**Step 1: Key Generation (Done)**
- RSA-2048 private key generated on an air-gapped workstation
- Key file (`portal_key.pem`) stored with 600 permissions
- Key backed up to encrypted USB drive stored in the data center safe

**Step 2: CSR Generation (Done)**
- CSR created with all required fields
- SAN entries verified
- Key-to-CSR modulus match confirmed

#### Phase 2: CA Selection and Submission

**Step 3: Select Certificate Authority**

MedDefense will use **DigiCert** as the Certificate Authority for the patient portal. This decision is based on:

| Factor | DigiCert (Selected) | Let's Encrypt (Not Selected) |
|---|---|---|
| **Certificate Type** | Organization Validation (OV) — verifies MedDefense's legal identity | Domain Validation (DV) only — no identity verification |
| **Validity Period** | Up to 398 days | 90 days (requires ACME automation) |
| **Support** | 24/7 enterprise support with phone escalation | Community support only |
| **Revocation** | Emergency revocation within hours via phone | Must use ACME API; no emergency phone support |
| **Audit Trail** | OV validation documentation available for HIPAA/SOC 2 audits | No identity verification records |
| **Cost** | ~$399/year per certificate | Free |

For a healthcare portal handling PHI, the OV certificate from DigiCert is justified because patients need visual confirmation that the certificate belongs to a verified organization, and the compliance audit trail supports HIPAA and SOC 2 requirements.

**Step 4: Submission to CA**
- Log in to DigiCert CertCentral portal
- Upload `portal.csr` file
- Select certificate product: GeoTrust or DigiCert OV TLS Certificate
- Select validity period: 1 year (398 days)
- Submit organization validation documents if not already on file (Articles of Incorporation, business license, phone verification via callback to published business number)

#### Phase 3: Validation process

**Step 5: CA Validation (DigiCert performs)**

DigiCert will verify the following before issuing the certificate:

| Validation Step | What the CA Verifies | How |
|---|---|---|
| **Domain Control Validation (DCV)** | MedDefense controls portal.meddefense.local | DNS TXT record, email to admin@meddefense.local, or HTTP file upload to /.well-known/pki-validation/ |
| **Organization Validation (OV)** | MedDefense Health Systems is a legitimate registered business | Dun & Bradstreet lookup, Secretary of State business registry, or Articles of Incorporation |
| **Address Validation** | 1234 Healthcare Blvd, San Francisco, CA is a real business address | Utility bill, lease agreement, or government registration |
| **Telephone Validation** | MedDefense's phone number is a valid business line | Callback to the phone number listed in the business registry |
| **Order Verification** | The person submitting the CSR is authorized to act for MedDefense | Phone call to a verified MedDefense contact, employment verification |

This validation process typically takes 1-3 business days for a new account, or 1-2 hours for an existing DigiCert account with validated organization information on file.

#### Phase 4: Certificate issuance

**Step 6: Receive Certificate from CA**

Upon successful completion of the validation process, DigiCert issues the certificate. The certificate issuance process works as follows:

1. DigiCert's CA system generates the certificate by signing the CSR's public key with the intermediate CA's private key using SHA-256 with RSA
2. The certificate includes all fields from the CSR (Subject, SANs, Key Usage, Extended Key Usage) plus the CA's additions (serial number, validity dates, issuer information, CA signature)
3. DigiCert sends an email notification to Steve and the registered contacts when the certificate is issued
4. The certificate is available for download from the DigiCert CertCentral portal in multiple formats (PEM, DER, PKCS#7)
5. The intermediate certificate bundle is also available for download to complete the trust chain

Download the following files from CertCentral:
- `portal.crt` — the issued end-entity certificate in PEM format
- `intermediate.crt` — the DigiCert intermediate CA certificate bundle in PEM format

The certificate issuance is typically completed within 1-2 hours after validation is confirmed for existing DigiCert accounts.

#### Phase 5: Installation on the web server

**Step 7: Install Certificate on Web Server**

- Transfer certificate files to the web server

```bash
scp portal.crt admin@web-srv-01:/tmp/ 
scp intermediate.crt admin@web-srv-01:/tmp/ 
scp portal_key.pem admin@web-srv-01:/tmp/
```

- SSH to the web server

```bash
ssh admin@web-srv-01
```

- Move files to correct locations

```bash
sudo mv portal.crt /etc/ssl/certs/portal.meddefense.local.crt 
sudo mv intermediate.crt /etc/ssl/certs/portal.meddefense.local.intermediate.crt 
sudo mv portal_key.pem /etc/ssl/private/portal.meddefense.local.key 
sudo chmod 600 /etc/ssl/private/portal.meddefense.local.key 
sudo chown root:root /etc/ssl/private/portal.meddefense.local.key
```

- Combine leaf and intermediate for full chain file

```bash
sudo cat /etc/ssl/certs/portal.meddefense.local.crt /etc/ssl/certs/portal.meddefense.local.intermediate.crt > /etc/ssl/certs/portal.meddefense.local.fullchain.crt
```

- Back up the current Apache configuration

```bash
sudo cp /etc/apache2/sites-available/meddefense-ssl.conf /etc/apache2/sites-available/meddefense-ssl.conf.bak.$(date +%Y%m%d)
```

- Update Apache configuration by editing /etc/apache2/sites-available/meddefense-ssl.conf:

```
SSLCertificateFile /etc/ssl/certs/portal.meddefense.local.fullchain.crt
SSLCertificateKeyFile /etc/ssl/private/portal.meddefense.local.key
SSLUseStapling On
SSLStaplingCache shmcb:/var/run/ocsp(128000)
```

- Test Apache configuration syntax

```bash
sudo apachectl configtest
```

- Reload Apache to apply the new certificate

```bash
sudo systemctl reload apache2
```

#### Phase 6: Verification that the new certificate is serving correctly

**Step 8: Verify the New Certificate Is Serving Correctly**

- Test from an external machine

```bash
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -serial
```

- Verify the full chain

```bash
openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -showcerts </dev/null 2>/dev/null | grep -E "depth|verify"
```

- Check OCSP Stapling

```bash
echo | openssl s_client -connect portal.meddefense.local:443 -servername portal.meddefense.local -status 2>/dev/null | grep "OCSP Response Status"
```

- Test with curl (should show no certificate errors)

```bash
curl -vI https://portal.meddefense.local 2>&1 | grep -E "subject|issuer|SSL"
```

- Test each SAN entry

```bash
for domain in portal.meddefense.local patient.meddefense.local www.portal.meddefense.local api.meddefense.local; do
    echo "Testing: $domain"
    openssl s_client -connect "${domain}:443" -servername "${domain}" </dev/null 2>/dev/null |
    openssl x509 -noout -subject
done
```

#### Phase 7: Decommission of the old certificate

**Step 9: Decommission the Old Certificate**

- Archive the old certificate and key

```bash
sudo mkdir -p /etc/ssl/archive/portal.old.$(date +%Y%m%d) 
sudo mv /etc/ssl/certs/portal.meddefense.local.crt.old /etc/ssl/archive/portal.old.$(date +%Y%m%d)/ 
sudo mv /etc/ssl/private/portal.meddefense.local.key.old /etc/ssl/archive/portal.old.$(date +%Y%m%d)/
```

- Retain the old certificate for signature verification of historical documents (Records signed with the old certificate may need verification during audit)

```bash
sudo chmod 700 /etc/ssl/archive/portal.old.$(date +%Y%m%d)/
```

-Revoke the old certificate at the CA if the private key is being decommissioned early (Not necessary if the old certificate has already expired naturally)

- Contact DigiCert support with the old certificate serial number if early revocation is required

- Delete the temporary backup files from /tmp

```bash
rm -f /tmp/portal.crt /tmp/intermediate.crt /tmp/portal_key.pem
```

#### Phase 8: Monitoring for the next renewal

**Step 10: Set Up Monitoring for the Next Renewal**

- Create a monitoring script

```bash
sudo tee /usr/local/bin/check_cert_expiry.sh > /dev/null << 'SCRIPT'
#!/bin/bash
DOMAIN="portal.meddefense.local"
WARN_DAYS=60
CRIT_DAYS=14
ADMIN_EMAIL="steve@meddefense.local"

# Extract expiry date from certificate
EXPIRY_DATE=$(echo | openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" 2>/dev/null |
              openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')

if [[ -z "${EXPIRY_DATE}" ]]; then
    echo "[CRITICAL] Could not retrieve certificate for ${DOMAIN}" |
    mail -s "CERT ALERT: ${DOMAIN}" "${ADMIN_EMAIL}"
    exit 2
fi

EXPIRY_EPOCH=$(date -d "${EXPIRY_DATE}" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

if [[ ${DAYS_LEFT} -le ${CRIT_DAYS} ]]; then
    echo "[CRITICAL] Certificate for ${DOMAIN} expires in ${DAYS_LEFT} days (${EXPIRY_DATE})" |
    mail -s "CERT CRITICAL: ${DOMAIN} expires in ${DAYS_LEFT} days" "${ADMIN_EMAIL}"
    exit 2
elif [[ ${DAYS_LEFT} -le ${WARN_DAYS} ]]; then
    echo "[WARNING] Certificate for ${DOMAIN} expires in ${DAYS_LEFT} days (${EXPIRY_DATE})" |
    mail -s "CERT WARNING: ${DOMAIN} expires in ${DAYS_LEFT} days" "${ADMIN_EMAIL}"
    exit 1
else
    echo "[OK] Certificate for ${DOMAIN} expires in ${DAYS_LEFT} days (${EXPIRY_DATE})"
    exit 0
fi
SCRIPT
```

- Make the script executable and add daily cron job

```bash
sudo chmod +x /usr/local/bin/check_cert_expiry.sh
echo "0 8 * * * /usr/local/bin/check_cert_expiry.sh" | sudo tee /etc/cron.d/check_cert_expiry
```

- Also add to the IT team calendar manually:

```
Renewal deadline: June 28, 2027 (30 days before expiry)
CSR generation: June 14, 2027
CA submission: June 21, 2027
```

### Lifecycle Summary

| Phase | Step | Status | Owner | Deadline |
|---|---|---|---|---|
| **Preparation** | Key generation | ✅ Complete | Steve | Done |
| **Preparation** | CSR generation | ✅ Complete | Steve | Done |
| **CA Selection** | Choose CA (DigiCert OV) | ✅ Complete | Steve | Done |
| **Submission to CA** | Submit CSR to DigiCert | Pending | Steve | Day 1 |
| **Validation** | DCV + OV validation | Pending | DigiCert | Days 1-3 |
| **Certificate issuance** | Download issued certificate | Pending | Steve | Day 3 |
| **Installation** | Deploy certificate to web-srv-01 | Pending | Steve + SysAdmin | Day 4 |
| **Verification** | Confirm new cert is live and correct | Pending | Steve | Day 4 |
| **Decommission** | Archive old certificate | Pending | Steve | Day 4 |
| **Monitoring** | Set up expiry alerts | Pending | Steve | Day 5 |
| **Next Cycle** | Begin renewal process | Scheduled | Steve | June 2027 |

### Certificate Renewal Timeline

```mermaid flowchart TD Start([July 27, 2026]) --> Phase1[CSR Generated]
Phase1 --> Milestone1["Submit CSR to DigiCert<br/>Day 1"]

Milestone1 --> Validation["DigiCert validates<br/>organization & domain<br/>Days 1-3"]

Validation --> Issue["Certificate issuance<br/>by DigiCert<br/>Day 3"]

Issue --> Deploy["Install certificate,<br/>verify, decommission old<br/>Day 4"]

Deploy --> Monitor["Monitoring active<br/>Day 5"]

Monitor --> Validity["─── 358 days of<br/>certificate validity ───"]

Validity --> Warning[June 28, 2027]
Warning --> Alert60["⚠️ Alert triggered<br/>(60 days before expiry)"]

Alert60 --> Escalation[July 14, 2027]
Escalation --> Alert14["🔴 Alert escalated<br/>(14 days before expiry)"]

Alert14 --> Expiry[July 28, 2027]
Expiry --> End(["🛑 Certificate expires<br/>if not renewed"])
```

---

A script [`10-generate_csr.sh`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/10-generate_csr.sh) that automates steps 1-3 of the key generation and CSR creation process.

---
