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

#### Generate RSA-2048 private key

```bash
openssl genrsa -out portal_key.pem 2048
```

#### Verify the key was created and check its properties

```bash
❯ openssl rsa -in portal_key.pem -text -noout | head -5
Private-Key: (2048 bit, 2 primes)
modulus:
    00:8d:59:64:c6:ed:ed:21:09:86:d2:ac:75:27:06:
    78:d7:a6:e6:83:c1:f1:f9:d4:1d:67:c2:06:ad:67:
    93:1f:c3:57:71:45:08:61:30:84:75:06:59:d8:1a:
```    

#### Protect the private key

```bash
~/projects/cert/meddef
❯ chmod 600 portal_key.pem


~/projects/cert/meddef
❯ ll
.rw------- 1.7k steve 27 Jul 19:18  portal_key.pem
```

---

## Part 2 - CSR Generation

### Create OpenSSL Configuration File

Rather than passing all parameters on the command line, an `openssl.cnf` file provides explicit control over every field and ensures SAN entries are included (a common omission when using command-line `-subj` alone, which does not reliably populate SANs in all OpenSSL versions).

```bash
~/projects/cert/meddef
❯cat > openssl.cnf << '\''EOF'\''
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
EOF'
```

---

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
---

```bash
openssl req -new -key portal_key.pem -out portal.csr -config openssl.cnf
```

### Verify the CSR was created

```bash
~/projects/cert/meddef
❯ ll
.rw-r--r--  566 steve 27 Jul 19:24  openssl.cnf
.rw-r--r-- 1.3k steve 27 Jul 19:27  portal.csr
.rw------- 1.7k steve 27 Jul 19:18  portal_key.pem
```

---

## Part 3 - CSR Inspection

### Inspect the Complete CSR

```bash
~/projects/cert/meddef
❯ openssl req -text -noout -in portal.csr
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C=US, ST=California, L=San Francisco, O=MedDefense Health Systems, OU=Information Technology, CN=portal.meddefense.local
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:8d:59:64:c6:ed:ed:21:09:86:d2:ac:75:27:06:
                    78:d7:a6:e6:83:c1:f1:f9:d4:1d:67:c2:06:ad:67:
                    93:1f:c3:57:71:45:08:61:30:84:75:06:59:d8:1a:
                    ea:d9:09:75:2d:e4:30:f6:ab:07:8c:86:36:99:79:
                    81:67:22:40:17:ed:f0:5f:e9:91:d4:73:c9:a3:92:
                    c6:22:0e:6a:56:43:c9:ad:8c:57:88:6b:2a:dd:87:
                    34:a8:61:0d:02:61:a2:20:06:be:9b:4d:3c:35:82:
                    6e:b0:80:37:d7:b5:f2:a8:1f:3b:7c:0e:af:9f:cf:
                    23:07:14:8d:10:d6:87:d7:cb:49:99:63:39:a0:bf:
                    44:51:73:c7:f7:d4:c2:4b:c6:7d:56:8f:b4:ba:6f:
                    14:68:84:fb:be:06:91:bf:2d:e7:bf:39:88:31:4b:
                    43:c4:a8:f2:50:e9:5e:d3:60:cf:fd:6d:57:20:af:
                    8d:1c:c1:38:0e:f3:5e:06:d5:88:2e:2b:f8:d4:e7:
                    f0:b6:63:96:ff:66:32:e1:cc:9c:ed:e6:76:a1:9c:
                    9f:9d:80:8b:7f:80:ec:98:ad:ac:87:6e:42:1b:7e:
                    0a:0a:fd:e0:fc:90:9e:5d:64:63:66:2e:55:4e:ae:
                    e6:bd:dc:53:c1:21:5b:5e:b0:6b:52:70:ca:af:54:
                    5d:a7
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
        8a:6e:00:37:18:41:c2:dc:c3:9e:33:2e:35:f4:f6:98:82:a1:
        d9:fa:33:36:6d:b2:ea:3e:6b:a5:3b:26:af:51:ee:79:fc:29:
        3f:42:cc:f8:c9:45:72:ca:49:d2:49:a1:68:c4:84:3d:5f:08:
        6f:03:0a:0f:19:bc:bf:db:ed:e5:d6:71:59:2c:9b:6a:bd:1b:
        af:da:cf:9d:f0:a6:5a:68:f6:2d:5e:70:0e:a0:8a:16:1c:ce:
        c3:64:40:e2:9a:39:f1:4b:24:5f:a5:20:7c:b3:3f:6a:05:9b:
        01:22:cc:2d:dd:d9:24:7e:70:b5:02:48:30:e2:9b:4a:9e:dc:
        a9:d8:8e:7b:dc:de:90:ea:68:90:8c:22:ad:10:6d:b3:05:d5:
        b5:8b:10:a2:16:a8:d3:22:88:b3:17:dd:15:42:b3:27:9c:b4:
        67:82:0c:8b:fe:f1:9d:e0:a8:1e:cd:e1:ba:47:ba:5f:0c:73:
        69:c0:dd:eb:e0:98:aa:3d:be:d9:5b:a0:43:dd:aa:35:9f:4b:
        d2:f8:73:b9:09:52:f3:64:4f:f2:27:4d:a4:a0:e3:0f:30:7c:
        db:bd:c8:42:4b:83:ee:a8:39:58:91:f7:f6:e8:07:23:99:ae:
        f0:50:e6:47:9a:d5:4e:c0:e1:ec:2d:fe:1c:2f:8f:78:50:d5:
        98:93:ae:94
```

---

#### Verification Checklist

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

---

### Confirm SAN Entries Are Present

```bash
~/projects/cert/meddef
❯ openssl req -text -noout -in portal.csr | grep -A1 "Subject Alternative Name"
                X509v3 Subject Alternative Name: 
                    DNS:portal.meddefense.local, DNS:patient.meddefense.local, DNS:www.portal.meddefense.local, DNS:api.meddefense.local
```

All four SAN entries are present. This confirms that patients using any of the four portal URLs will be served a valid certificate without browser warnings.


### Compare the modulus of the private key and the CSR

```bash
~/projects/cert/meddef
❯ openssl rsa -in portal_key.pem -modulus -noout | openssl md5
MD5(stdin)= 5786579cfab9c7d3275e760a37f3f390

~/projects/cert/meddef
❯ openssl req -in portal.csr -modulus -noout | openssl md5
MD5(stdin)= 5786579cfab9c7d3275e760a37f3f390
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

#### Phase 3: Validation Process

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
scp portal.crt admin@web-srv-01:/tmp/ scp intermediate.crt admin@web-srv-01:/tmp/ scp portal_key.pem admin@web-srv-01:/tmp/
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

- Update Apache configuration

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

---

#### Phase 5: Verification

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

- Test with curl

```bash
curl -vI https://portal.meddefense.local 2>&1 | grep -E "subject|issuer|SSL"
```

- Test each SAN entry

```bash
for domain in portal.meddefense.local patient.meddefense.local www.portal.meddefense.local api.meddefense.local; do echo "Testing: $domain" openssl s_client -connect "domain:443"−servername"{domain}" </dev/null 2>/dev/null | openssl x509 -noout -subject done
```

---

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

--- 

#### Phase 7: Monitoring

**Step 10: Set Up Monitoring for the Next Renewal**

- Create a monitoring script

```bash
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
``` 

```bash
sudo chmod +x /usr/local/bin/check_cert_expiry.sh
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

---

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

```mermaid
flowchart TD
    Start([July 27, 2026]) --> Phase1[CSR Generated]
    
    Phase1 --> Sub1[Day 1]
    Sub1[Day 1] --> Milestone1["Submit CSR to DigiCert"]
    
    Milestone1 --> Phase2["Days 1-3"]
    Phase2["Days 1-3"] --> Validation["DigiCert validates<br/>organization & domain"]
    
    Validation --> Milestone3[Day 3]
    Milestone3 --> Issue["Certificate issued<br/>by DigiCert"]
    
    Issue --> Milestone4[Day 4]
    Milestone4 --> Deploy["Install certificate,<br/>verify, decommission old"]
    
    Deploy --> Milestone5[Day 5]
    Milestone5 --> Monitor["Monitoring active"]
    
    Monitor --> Validity["─── 358 days of<br/>certificate validity ───"]
    
    Validity --> Warning[June 28, 2027]
    Warning --> Alert60["⚠️ Alert triggered<br/>(60 days before expiry)"]
    
    Alert60 --> Escalation[July 14, 2027]
    Escalation --> Alert14["🔴 Alert escalated<br/>(14 days before expiry)"]
    
    Alert14 --> Expiry[July 28, 2027]
    Expiry --> End(["🛑 Certificate expires<br/>if not renewed"])
    
    %% Styling
    classDef milestone fill:#6d4aff,color:white,stroke-width:2px
    classDef alert fill:#ff9800,color:black,stroke-width:2px
    classDef critical fill:#f44336,color:white,stroke-width:2px
    classDef phase fill:#e0e0e0,color:black
    
    class Start,Milestone1,Milestone3,Milestone4,Milestone5 milestone
    class Warning,Escalation alert
    class Expiry,End critical
    class Phase1,Phase2,Validity,Deploy,Monitor,Alert60,Alert14 phase
```

---

Script [`10-generate_csr.sh`](https://github.com/sreilly1977/dlh-cyber_security/blob/main/blue_team/1x04_crypto_foundation/10-generate_csr.sh) automates steps 1-3 of the key generation and CSR creation process.

---
