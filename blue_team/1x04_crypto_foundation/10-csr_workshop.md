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

```bash
openssl genrsa -out portal_key.pem 2048
```

### Verify the key was created and check its properties

```bash
openssl rsa -in portal_key.pem -text -noout | head -5
Private-Key: (2048 bit, 2 primes)
modulus:
    00:9b:78:65:8d:44:ac:7b:1c:11:49:c2:c3:6f:c5:
    9a:0b:f8:6f:73:6a:99:ad:2b:67:0d:5a:fd:1c:18:
    0a:4a:7d:64:b4:76:90:1e:c8:11:f3:ab:96:4b:f3:
```

### Protect the private key

```bash
chmod 600 portal_key.pem
```

### Verify file permissions

```bash
ls -l portal_key.pem
.rw------- 1.7k steve 27 Jul 19:41  portal_key.pem
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

### Generate the CSR

```bash
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
```

### Verify the CSR was created

```bash
ls -l portal.csr
.rw-r--r-- 1.3k steve 27 Jul 19:47  portal.csr
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
                    00:9b:78:65:8d:44:ac:7b:1c:11:49:c2:c3:6f:c5:
                    9a:0b:f8:6f:73:6a:99:ad:2b:67:0d:5a:fd:1c:18:
                    0a:4a:7d:64:b4:76:90:1e:c8:11:f3:ab:96:4b:f3:
                    cb:1b:59:bd:9d:36:c1:76:64:ec:46:9e:20:cc:b6:
                    8a:0e:4b:74:92:e2:38:0a:c8:43:2b:87:1c:f6:11:
                    34:00:47:65:0b:6e:f5:f4:0c:b4:08:8b:1c:81:45:
                    c0:52:30:1c:67:52:a5:73:15:c9:d3:4f:7c:f6:20:
                    47:92:1c:5c:89:99:0d:72:f4:60:cc:27:81:16:ea:
                    90:0f:60:03:ad:7e:f4:b1:12:d5:15:0b:70:e3:61:
                    2f:ba:9b:4d:bc:05:06:88:20:68:80:d9:8e:ac:ad:
                    62:f1:2f:59:40:9b:e3:11:6f:b6:d1:76:21:ab:26:
                    7f:e2:0a:72:da:04:a8:9d:83:b5:ac:51:7f:18:9e:
                    45:5b:88:f1:75:89:1d:f7:32:f1:b1:d9:31:2a:dc:
                    e0:4d:7d:df:4c:e5:71:47:33:31:17:92:5c:2e:d3:
                    c2:16:23:9b:fb:48:ed:a7:2e:4e:2f:59:75:e2:5b:
                    9f:37:c5:ee:9a:a1:85:fc:3b:d6:98:bf:b2:c0:02:
                    3a:0c:e0:aa:90:81:3f:e3:01:5e:15:db:8b:ac:ac:
                    54:87
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
        16:20:be:10:fa:b4:23:12:b8:b5:51:88:0c:ca:b7:f9:37:b1:
        b7:ff:55:60:77:e8:0a:0f:ab:43:2b:74:92:75:b1:1d:69:0b:
        78:ca:58:52:7e:3c:92:68:80:d9:47:1a:21:74:fd:53:f9:29:
        e9:be:93:6f:af:e7:14:6c:b1:89:09:78:f0:ff:e0:6f:07:eb:
        40:84:77:2a:cf:f3:5e:b8:38:d2:18:b7:83:72:bf:08:3c:22:
        8c:a1:3e:0b:b1:42:9e:e9:43:38:55:79:9c:36:24:e5:0f:18:
        94:de:32:aa:b5:44:a3:64:13:ec:88:2c:90:4a:56:bf:5c:ce:
        5f:99:f1:0e:aa:7b:15:2a:8d:2e:87:5c:d3:71:6e:98:61:b8:
        38:2c:ef:f7:13:cf:65:04:85:cc:74:1d:3a:5b:60:1e:48:d8:
        d1:33:b0:bf:7a:c3:4b:91:8d:66:22:66:9e:6f:37:51:8e:bc:
        a2:2e:21:bd:01:d6:98:24:ce:ff:83:63:df:fc:71:58:3a:88:
        21:90:9a:d4:75:dc:c2:67:d6:5e:29:e7:c6:27:7a:b4:54:50:
        6a:06:39:a4:2a:9e:67:2b:9a:54:7c:ce:2a:9f:39:be:52:d4:
        eb:16:a7:b8:90:ca:fb:78:83:e7:67:22:0c:04:37:bb:46:b9:
        df:fc:43:09
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
MD5(stdin)= b9ad568bd8802f4cec7b215fdc35079f

openssl req -in portal.csr -modulus -noout | openssl md5
MD5(stdin)= b9ad568bd8802f4cec7b215fdc35079f
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

#### Phase 4: Certificate Issuance and Installation

**Step 6: Receive Certificate from CA**
- DigiCert sends an email notification when the certificate is issued
- Download the certificate from CertCentral in PEM format
- Download the intermediate certificate bundle
- Save files as: `portal.crt`, `intermediate.crt`

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

### Phase 5: Verification

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

- Test each SAN entry

```bash
for domain in portal.meddefense.local patient.meddefense.local www.portal.meddefense.local api.meddefense.local; do echo "Testing: $domain"; openssl s_client -connect "${domain}:443" -servername "${domain}" </dev/null 2>/dev/null | openssl x509 -noout -subject; done
```

#### Phase 6: Decommission

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

- Revoke the old certificate at the CA if the private key is being decommissioned early (Not necessary if the old certificate has already expired naturally)

- Contact DigiCert support with the old certificate serial number if early revocation is required

- Delete the temporary backup files from /tmp

```bash
rm -f /tmp/portal.crt /tmp/intermediate.crt /tmp/portal_key.pem
```

#### Phase 7: Monitoring

**Step 10: Set Up Monitoring for the Next Renewal**

- Create a monitoring script

```bash
sudo tee /usr/local/bin/check_cert_expiry.sh > /dev/null << 'EOF'
#!/bin/bash
DOMAIN="portal.meddefense.local"
WARN_DAYS=60
CRIT_DAYS=14
ADMIN_EMAIL="steve@meddefense.local"

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
EOF
```

- Make script executable 

```bash
chmod +x /usr/local/bin/check_cert_expiry.sh
```

- Add daily cron job

```bash
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
| **Issuance** | Download certificate from CertCentral | Pending | Steve | Day 3 |
| **Installation** | Deploy certificate to web-srv-01 | Pending | Steve + SysAdmin | Day 4 |
| **Verification** | Confirm new cert is live and correct | Pending | Steve | Day 4 |
| **Decommission** | Archive old certificate | Pending | Steve | Day 4 |
| **Monitoring** | Set up expiry alerts | Pending | Steve | Day 5 |
| **Next Cycle** | Begin renewal process | Scheduled | Steve | June 2027 |

### Certificate Renewal Timeline

```mermaid flowchart TD Start([July 27, 2026]) --> Phase1[CSR Generated]
Phase1 --> Milestone1["Submit CSR to DigiCert<br/>Day 1"]

Milestone1 --> Validation["DigiCert validates<br/>organization & domain<br/>Days 1-3"]

Validation --> Issue["Certificate issued<br/>by DigiCert<br/>Day 3"]

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
