# 17. Certificate Lifecycle Management

## Goal

Design the certificate management program that prevents MedDefense from ever facing another "certificate expires in 18 days" emergency.

## Context

The patient portal certificate is a symptom, not the disease. The disease is that MedDefense has no certificate inventory, no expiration monitoring, no renewal process and no policy on certificate types. This task creates the program.

---

## Part 1 - Certificate Inventory

### Complete Certificate Register

| Certificate Name | Purpose | Issuer | Algorithm | Valid From | Expiration | Owner | Notes |
|---|---|---|---|---|---|---|---|
| **Patient Portal (web-srv-01)** | TLS for patientportal.meddefense.com | DigiCert Global G2 TLS RSA SHA256 2020 CA1 | RSA-2048 | Jan 15, 2026 | Jan 15, 2027 | Steve (Security Engineer) | **Priority 1** — public-facing, 800 daily patients |
| **Internal CA Root (ca-srv-01)** | Root certificate authority for internal services | MedDefense Internal CA (Self-signed) | ECDSA P-384 | Jun 30, 2025 | Jun 29, 2035 (10-year) | Steve + IT Director (dual control) | Signed on HSM-01; offline storage; annual audit |
| **Internal CA Intermediate (ca-srv-01)** | Intermediate CA for employee/service certs | MedDefense Internal CA Root | ECDSA P-384 | Jul 1, 2025 | Jul 1, 2030 (5-year) | Steve | Issues certificates to internal services |
| **VPN Concentrator (vpn-srv-01)** | IPsec/IKEv2 client/server auth | MedDefense Internal CA Intermediate | ECDSA P-256 | Aug 1, 2025 | Aug 1, 2026 | NetAdmin | Required for remote clinician access |
| **PACS Server (pacs-srv-01)** | Mutual TLS for DICOM communications | MedDefense Internal CA Intermediate | ECDSA P-256 | Sep 1, 2025 | Sep 1, 2026 | Radiology Admin | Critical for medical image transfers |
| **Modality Workstations (CT/MRI)** | Client cert for DICOM to PACS | MedDefense Internal CA Intermediate | RSA-2048 | Oct 1, 2025 | Oct 1, 2026 | Radiology Admin | ~12 modalities; batch renew annually |
| **EHR Database (ehr-db-01)** | TLS for application-to-database connections | MedDefense Internal CA Intermediate | ECDSA P-256 | Nov 1, 2025 | Nov 1, 2026 | DBA | PostgreSQL sslmode=require |
| **Billing Database (billing-srv-01)** | TLS for application-to-database connections | MedDefense Internal CA Intermediate | ECDSA P-256 | Nov 1, 2025 | Nov 1, 2026 | Finance DBA | MySQL require_secure_transport=ON |
| **O365 Email Signing (internal)** | S/MIME for clinical email | Microsoft Office 365 CA | RSA-2048 | Dec 1, 2025 | Dec 1, 2027 | Compliance Officer | Patient communication authentication |
| **HSM-01 (AWS CloudHSM)** | HSM management interface mTLS | AWS ACM PCA | RSA-2048 | Jan 1, 2026 | Jan 1, 2027 | Steve | HSM admin access only |
| **Vault KMS (vault.meddefense.local)** | HashiCorp Vault API TLS | MedDefense Internal CA Intermediate | ECDSA P-256 | Feb 1, 2026 | Feb 1, 2027 | Steve | Key management system access |
| **BD Alaris Pump Firmware** | Signed firmware updates | BD Medical CA | RSA-4096 | Mar 1, 2025 | Mar 1, 2027 | Biomed Team | Vendor-managed; annual signature verification |
| **Code Signing (CI/CD Pipeline)** | Software build signing (meddefense-apps) | DigiCert Trusted Code Signing CA | RSA-4096 | Apr 1, 2026 | Apr 1, 2029 | DevOps Lead | Internal application deployment |

### Certificate Summary Statistics

| Metric | Count |
|---|---|
| Public-facing certificates (external CA) | 2 (Patient Portal, Code Signing) |
| Internal certificates (MedDefense CA) | 8 (VPN, PACS, Modalities, Databases, Vault) |
| Vendor-managed certificates | 1 (BD Alaris) |
| Microsoft-managed certificates | 1 (O365 Email) |
| **Total Certificates Tracked** | **12** |
| Expiring within 6 months | 4 (VPN, PACS, Modalities, Databases) |
| Expiring within 1 year | 6 (includes Patient Portal, HSM, Vault) |
| Long-term (3+ years) | 2 (Root CA, Code Signing) |

---

## Part 2 - Auto-Renewal Strategy

### Recommendation: Hybrid Approach

**MedDefense should use BOTH ACME/Let's Encrypt AND Commercial CAs, depending on the certificate purpose:**

| Certificate Type | Recommended CA | Reasoning |
|---|---|---|
| **Public-facing (Patient Portal)** | **Commercial CA (DigiCert)** | Trust anchor matters for patients. Browser trust chain must be unambiguous. 800 daily patients cannot tolerate any confusion about certificate legitimacy. Let's Encrypt certificates are valid but may trigger "less secure" perceptions among clinical staff and patients unfamiliar with automation. |
| **Internal Services (Databases, VPN, PACS)** | **MedDefense Internal CA** | Zero cost, full control, 1-year renewal cycles align with internal audit. No public trust required—clients validate against internal CA bundle. |
| **Development/Staging** | **ACME/Let's Encrypt** | Free, automated, 90-day rotation forces automation discipline. Mimics production certificate lifecycle without cost. |
| **Code Signing** | **Commercial CA (DigiCert EV Code Signing)** | Extended Validation required for Windows SmartScreen reputation. Internal CA code signing triggers "unknown publisher" warnings. |
| **Email Signing (S/MIME)** | **Microsoft Office 365 or Commercial CA** | S/MIME requires email-address-validated certificates. O365 manages this internally at no additional cost. |

### Patient Portal Justification (Commercial CA, Not Let's Encrypt)

**Why DigiCert over Let's Encrypt for the patient portal:**

| Factor | DigiCert (Commercial) | Let's Encrypt (ACME) | Winner for Patient Portal |
|---|---|---|---|
| **Certificate validity period** | 1 year (standard) | 90 days (mandatory) | DigiCert (fewer rotations reduce failure risk) |
| **Automated renewal** | Possible via ACME | Required via ACME | Tie (both support automation) |
| **Trust perception** | Explicit OV/EV validation visible | DV only, no validation visible | DigiCert (patients see organization name) |
| **Cost** | ~$600/year | Free | Let's Encrypt |
| **Support SLA** | 24×7 phone/email with response guarantees | Community forums only | DigiCert (clinical operations cannot tolerate weekend certificate failures) |
| **Revocation handling** | Dedicated OCSP responders, CRL distribution points | Shared infrastructure | DigiCert (faster revocation if compromised) |
| **Cross-certification** | Automatic trust across all major browsers | Trust issues in some legacy Windows environments | DigiCert (broader compatibility with older hospital clients) |

**Decision:** For the patient portal serving 800 daily patients, **commercial CA (DigiCert)** is justified because:
1. **Clinical impact of expiration:** A certificate failure blocks patient access to appointments, lab results, and secure messaging—directly impacting care delivery during business hours
2. **Trust signaling:** Organization-validated certificates show "MedDefense Health System" in certificate details, reinforcing legitimacy to patients
3. **SLA support:** DigiCert provides guaranteed response times during business hours; if an automation failure occurs, humans can intervene immediately rather than waiting for community forums
4. **Fewer rotation windows:** 1-year certificates mean 1 renewal event per year vs. 4 for 90-day certificates—reducing operational failure surface by 75%

**Automation Requirement:** Even with DigiCert, MedDefense **must** use ACME protocol for renewal automation. Manual certificate management caused the "expires in 18 days" crisis in Task 10. DigiCert supports ACME via its Partner API. Automate the renewal even with paid certificates.

---

## Part 3 - Monitoring and Alerting

### Certificate Monitoring System Architecture

MedDefense should implement **HashiCorp Consul** integrated with **Prometheus** and **Alertmanager** for certificate expiration monitoring. Alternative: **Uptime Kuma** or **Datadog SSL monitoring** for simpler setups.

#### Monitoring Components

| Component | Function | Deployment |
|---|---|---|
| **cert_exporter** (Prometheus exporter) | Scrapes each certificate endpoint via TLS handshake; extracts expiration date | Deployed on each monitored server |
| **Prometheus** | Time-series database storing certificate age data | Central server (prometheus.meddefense.internal) |
| **Alertmanager** | Routes alerts based on thresholds and recipient groups | Same server as Prometheus |
| **Grafana Dashboard** | Visual certificate inventory and expiration timeline | Grafana instance showing all certificates |

#### Alternative: Centralized Solution

If Prometheus/Alertmanager is too complex for current team capacity, use **SSL Shopper API** with custom script:

```bash
#!/bin/bash
# cert-monitor.sh — Run daily via cron

for cert in $(cat /etc/ssl/certs/inventory.txt); do
    # Get expiration timestamp
    exp_ts=$(echo | openssl s_client -connect "${cert}" 2>/dev/null | \
             openssl x509 -enddate -noout | \
             awk -F= '{print $2}' | \
             xargs -I{} date -d {} +%s)
    
    # Calculate days remaining
    now=$(date +%s)
    days_left=$(( (exp_ts - now) / 86400 ))
    
    # Send alerts at thresholds
    if [ $days_left -lt 7 ]; then
        send_slack_alert "#security-critical" "CRITICAL: ${cert} expires in ${days_left} days!"
    elif [ $days_left -lt 30 ]; then
        send_email "steve@meddefense.com" "WARNING: ${cert} expires in ${days_left} days"
    elif [ $days_left -lt 60 ]; then
        send_email "it-admin@meddefense.com" "NOTICE: ${cert} expires in ${days_left} days"
    fi
done
```

## Alert Thresholds and Notification Matrix

| Days Until Expiration | Severity | Notification Channel | Recipient(s) | Action Required |
|---|---|---|---|---|
| 90 days | Notice | Email (weekly digest) | IT Admin (netadmin@meddefense.com), Steve (steve@meddefense.com) | Add to monthly maintenance calendar |
| 60 days | Warning | Email (immediate) + Slack | Steve, IT Director | Begin renewal procurement if commercial CA |
| 30 days | High | Slack + PagerDuty | Steve, DBA (for database certs), NetAdmin (for network certs) | Execute renewal; test in staging environment |
| 7 days | Critical | PagerDuty + SMS + Phone Call | Steve, CISO, IT Director | Emergency change request; manual intervention required |
| 1 day | Emergency | Phone Call + War Room | All stakeholders | Rollback plan ready; outage imminent |

## Certificate Dashboard (Grafana)

The Grafana dashboard should display:

- **Table view:** Certificate name, issuer, expiration date, days remaining, owner, status color (green/yellow/red)
- **Timeline view:** X-axis = time, Y-axis = certificate count by status, stacked bars showing expiring soon vs. healthy
- **Histogram:** Distribution of certificate ages across the fleet
- **Alert history:** Log of all expiration alerts fired in the past 30 days

### Query Example (PromQL)

(cert_expiry_seconds - time()) < 2592000
(cert_expiry_seconds - time()) < 604800
avg(cert_expiry_seconds - time()) / 86400

## Escalation Procedure

When a certificate reaches the 7-day critical threshold, execute this procedure:

| Step | Action | Owner | Timeline |
|---|---|---|---|
| 1 | Acknowledge alert via PagerDuty | Steve | 15 minutes |
| 2 | Initiate emergency change request in Jira (ECR-2026-XXX) | Steve | 30 minutes |
| 3 | Generate new CSR and submit to CA (DigiCert/Internal CA) | Steve | 1 hour |
| 4 | Receive new certificate from CA | Steve/IT Director | 2-24 hours (depends on CA) |
| 5 | Install new certificate in staging environment | Steve | 2 hours |
| 6 | Test all affected services in staging (functional + load tests) | QA Team | 4 hours |
| 7 | Schedule maintenance window (if zero-downtime not possible) | IT Director | 1 hour |
| 8 | Deploy new certificate to production | Steve | During maintenance window |
| 9 | Verify all services operational; monitor error rates | NetAdmin | Continuous |
| 10 | Close emergency change request; conduct post-mortem | Steve | Within 48 hours |

## Part 4 - Certificate Policy

### MedDefense Certificate Management Policy v1.0

**Approved by:** Security Engineer (Steve), IT Director, CISO  
**Effective Date:** August 1, 2026  
**Review Cycle:** Annual (or upon major cryptographic incident)

#### Policy Rule 1: Authorized Certificate Authorities

"All TLS/SSL certificates deployed in production environments must be issued by either (a) the MedDefense Internal CA (for internal services only) or (b) a CA included in the Mozilla CA Certificate Store (for public-facing services). Self-signed certificates are prohibited in production environments except for development/staging workloads explicitly tagged as non-production. Certificate exceptions require written approval from the CISO."

**Rationale:** Ensures all certificates chain to a trusted root, preventing man-in-the-middle attacks from unknown issuers. The Mozilla CA Store defines industry-standard trust anchors.

**Enforcement:** Automated scanning via sslscan or testssl.sh on all deployments; failed scans block CI/CD pipeline.

#### Policy Rule 2: Minimum Key Strength and Algorithm Requirements

"All new certificates must use RSA keys of at least 2048 bits or elliptic curve keys of at least P-256 strength. Signature algorithms must be SHA-256 or stronger. SHA-1, MD5, RSA-1024, and DSA keys are prohibited. Code signing certificates must use RSA-4096 or ECDSA P-384 minimum. Certificates violating these requirements must be rotated within 90 days of discovery."

**Rationale:** Aligns with NIST SP 800-131A and CA/Browser Forum Baseline Requirements. Ensures cryptographic longevity matching data classification requirements.

**Enforcement:** Certificate issuance workflow validates key algorithm before signing; existing certificates scanned quarterly.

#### Policy Rule 3: Maximum Certificate Lifetime

"Public-facing certificates must not exceed 398 days (13 months) validity, per CA/B Forum guidelines. Internal certificates may be issued for up to 1 year. Code signing certificates may be issued for up to 3 years with Strong Time-Stamping Authority (TSA). Root CA certificates may be issued for up to 10 years. No certificate may be re-issued with the same serial number after revocation."

**Rationale:** Industry practice limits certificate lifetime to reduce damage window from compromised private keys. Root CA certificates require longer lifetimes due to operational complexity of rotation.

**Enforcement:** CA signing workflow rejects requests exceeding maximum lifetime; certificate scanner flags violations.

#### Policy Rule 4: Automated Renewal and Monitoring

"All certificates must be enrolled in the MedDefense certificate monitoring system (Prometheus/Alertmanager or approved equivalent). Certificates must renew automatically via ACME protocol where supported. For certificates requiring manual renewal, the renewal process must be documented in a runbook and rehearsed semi-annually. No certificate may expire without triggering an alert at least 7 days prior to expiration."

**Rationale:** Prevents certificate expiration emergencies like the Task 10 patient portal incident. Automation reduces human error. Early alerts provide time for troubleshooting.

**Enforcement:** Certificate inventory must include monitoring registration; audit checks confirm Prometheus scrape connectivity weekly.

#### Policy Rule 5: Certificate Revocation and Reissuance

"If a private key is suspected compromised, the associated certificate must be revoked within 24 hours via OCSP stapling or CRL publication. Revoked certificates must be reissued with new key material—never reuse the old key pair. Compromised keys must be documented in the Incident Response Playbook with root cause analysis completed within 7 days. All certificates associated with the compromised CA must be evaluated for revocation."

**Rationale:** Minimizes blast radius from key compromise. Timely revocation prevents continued malicious use. Documentation enables lessons learned.

**Enforcement:** Revocation workflow integrated into incident response; CISO must approve delayed revocations beyond 24 hours.

#### Policy Rule 6: Private Key Protection

"All private keys for production certificates must be stored in HSM (for public-facing high-value certificates) or in encrypted filesystem storage with 600/400 file permissions (for internal certificates). Keys must never be stored in plaintext in source control, configuration management databases, or backup archives without encryption. HSM-backed keys must be rotated quarterly; software-stored keys must be rotated annually or upon personnel turnover for key custodians."

**Rationale:** Protects keys from theft even if storage systems are compromised. Aligns with T14 key management design.

**Enforcement:** Configuration audits detect plaintext key files; access logs track who accessed key storage.

#### Policy Rule 7: Internal CA Chain Validation

"All client applications connecting to internal services must be configured with the MedDefense Internal CA certificate bundle. Hardcoded CA certificates in application code are prohibited. The Internal CA root certificate must be distributed via Group Policy for Windows devices and MDM profiles for iOS/Android devices. Clients rejecting invalid or expired intermediate certificates must fail closed—graceful degradation to untrusted certificates is prohibited."

**Rationale:** Ensures all internal traffic validates against the correct CA chain. Hardcoded CA bundles become stale when intermediates rotate. Graceful degradation defeats the purpose of certificate validation.

**Enforcement:** Application security review checklist requires CA bundle distribution method; pentests verify fail-closed behavior.

#### Policy Rule 8: Certificate Transparency Logging

"All publicly-trusted certificates must be submitted to at least two Certificate Transparency (CT) logs at issuance. MedDefense must monitor CT logs for unauthorized certificates using CT Observer or similar tool. Any unexpected certificate for a MedDefense domain must be investigated within 24 hours and reported to the CISO if unauthorized issuance is confirmed."

**Rationale:** Detects fraudulent certificate issuance by compromised CAs or insider threats. Google Chrome requires CT logging for all certificates.

**Enforcement:** CA submission validated during certificate issuance; CT monitoring dashboard reviewed weekly.

### Policy Exceptions Process

Exceptions to this certificate policy require:

1. Written justification explaining why the policy cannot be followed
2. Risk assessment quantifying the security impact of the exception
3. Mitigating controls describing compensating security measures
4. CISO approval signed digitally with valid certificate
5. Expiration date for the exception (maximum 6 months)
6. Quarterly review while exception remains active

Exception form: security-exception-request.md stored in /policy/exceptions/cert-policy/

## Part 5 - Implementation Checklist

### Week 1 (Immediate)

| Task | Owner | Due Date |
|---|---|---|
| Create certificate inventory spreadsheet with all 12 certificates | Steve | Day 1 |
| Install cert_exporter on web-srv-01, vpn-srv-01, pacs-srv-01, ehr-db-01, billing-srv-01 | Steve | Day 2 |
| Configure Prometheus to scrape cert_exporter endpoints | Steve | Day 3 |
| Set up Alertmanager with email/Slack/PagerDuty routing | Steve | Day 4 |
| Create Grafana dashboard for certificate visibility | Steve | Day 5 |
| Send initial alert notifications to owners | Steve | Day 5 |

### Month 1 (Short-term)

| Task | Owner | Due Date |
|---|---|---|
| Document renewal runbooks for all 12 certificates | Steve + Owners | Week 3 |
| Configure ACME automation for internal CA certificates | Steve | Week 4 |
| Submit patient portal certificate to CT logs; set up monitoring | Steve | Week 4 |
| Conduct first certificate renewal drill (simulated) | Steve + IT Director | Week 4 |

### Quarter 1 (Long-term)

| Task | Owner | Due Date |
|---|---|---|
| Deploy PKI-aware secrets manager (HashiCorp Vault PKI engine) | Steve | Month 2 |
| Migrate all internal service certificates to Vault PKI for automation | Steve | Month 3 |
| Conduct first quarterly certificate audit (verify all 12 certificates match inventory) | Compliance Officer | Month 3 |
| Review and update Certificate Management Policy | Steve + CISO | Month 3 |

## Appendix - Quick Reference

### Certificate Contact Directory

| Certificate Category | Primary Owner | Backup Owner | Contact |
|---|---|---|---|
| Public-facing (Patient Portal) | Steve | CISO | steve@meddefense.com |
| Internal CA (Root + Intermediate) | Steve + IT Director | CISO | steve@meddefense.com, itdirector@meddefense.com |
| Network Services (VPN) | NetAdmin | Steve | netadmin@meddefense.com |
| Application Services (Databases, PACS) | DBA / Radiology Admin | Steve | dba@meddefense.com, radiology@meddefense.com |
| Email (O365) | Compliance Officer | Steve | compliance@meddefense.com |
| Vendor Certificates (BD Alaris) | Biomed Team | Steve | biomed@meddefense.com |
| Code Signing | DevOps Lead | Steve | devops@meddefense.com |

### Emergency Contacts

| Situation | Contact | Availability |
|---|---|---|
| Certificate expiration alert (7 days) | Steve (PagerDuty) | 24x7 |
| Certificate expiration alert (1 day) | Steve + CISO (Phone) | Immediate |
| CA vendor escalation | DigiCert Support | Business hours (commercial CA) |
| Internal CA emergency | Steve + IT Director (Dual control) | On-call rotation |
| Security incident involving certificates | CISO + Incident Response Team | 24x7 |

## Summary

MedDefense's Certificate Lifecycle Management Program establishes:

- Complete inventory of 12 certificates with owners, issuers, and expiration dates
- Hybrid CA strategy using commercial CA (DigiCert) for public-facing services and Internal CA for internal services, with ACME automation throughout
- Four-tier alerting system (90/60/30/7 days) escalating from email to PagerDuty/SMS
- Eight enforceable policy rules covering authorized CAs, key strength, certificate lifetime, automation, revocation, key protection, chain validation, and transparency logging
- Implementation roadmap progressing from immediate monitoring setup to quarterly automation migration

The patient portal certificate emergency that triggered Task 10 will never repeat. The certificate inventory is explicit, the renewal automation is mandatory, the alerting thresholds are aggressive, and the policy provides clear accountability. If a certificate expires under this program, the failure is operational—not procedural.
