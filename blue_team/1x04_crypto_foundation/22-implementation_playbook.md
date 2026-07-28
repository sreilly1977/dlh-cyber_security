# 20. The Implementation Playbook

## Purpose

This document provides step-by-step operational instructions for deploying the five highest-priority cryptographic changes at MedDefense. Sarah Park distributes this to the IT team for execution starting Monday morning. Each action includes prerequisites, detailed steps, validation criteria, rollback procedures, maintenance windows, and communication requirements.

**Distribution:** Sarah Park (IT Director), Steve (Security Engineer), DBA Team, NetAdmin Team, Radiology Admin
**Last Updated:** July 28, 2026
**Review Cadence:** After each action completion to verify procedure accuracy

---

## Action #1: Enable PostgreSQL Transparent Data Encryption (TDE)

**Priority:** Immediate (Phase 1)
**System Affected:** ehr-db-01 (PostgreSQL production server)
**Objective:** Encrypt patient EHR data at rest to satisfy HIPAA §164.312(a)(2)(iv) and close CRYPTO-001 finding

### Prerequisites

- [ ] HSM-01 (AWS CloudHSM) is operational and reachable from ehr-db-01
- [ ] PostgreSQL pgcrypto extension installed and tested in staging environment
- [ ] DBA team has completed pgcrypto training session
- [ ] Maintenance window approved (Saturday 22:00-02:00 EST)
- [ ] Full database backup completed 24 hours before change
- [ ] Monitoring alerting configured for database availability
- [ ] Stakeholders notified: Clinical Operations Director, Compliance Officer

### Steps

1. **Verify HSM connectivity from ehr-db-01**
   - SSH to ehr-db-01 as admin
   - Run HSM ping utility and confirm PONG response within 10ms

2. **Generate TDE master key on HSM-01**
   - Use AWS CLI to create AES-256-GCM key with tag "MedDefense-TDE"
   - Record Key ID and ARN for reference

3. **Install pgcrypto extension on PostgreSQL**
   - Connect as postgres superuser
   - Run: CREATE EXTENSION IF NOT EXISTS pgcrypto;

4. **Configure TDE tablespace encryption**
   - Set encryption_key_location to HSM ARN
   - Set encryption_algorithm to AES-256-GCM
   - Reload configuration via pg_reload_conf()
   - Encrypt existing patient_records table: ALTER TABLE patient_records SET ENCRYPTION ON USING AES_256_GCM;

5. **Restart PostgreSQL service**
   - sudo systemctl restart postgresql
   - Wait 60 seconds for warmup

6. **Verify encryption status**
   - Query pg_tablespace for patient_records table
   - Confirm is_encrypted = true

### Validation

- pg_stat_activity shows all active connections resumed within 5 minutes
- Run sample EHR lookup for test patient record, returns successfully
- Filesystem: encrypted file sizes match pre-change expectations
- Clinical portal shows "Connection Successful" within 10 minutes of restart
- No error logs in /var/log/postgresql/ for 30 minutes post-restart

### Rollback

- **Procedure:** Disable TDE on specific tables (does not require full restore)
  - Run: ALTER TABLE patient_records SET ENCRYPTION OFF;
  - Reload config and restart PostgreSQL
- **Maximum Downtime:** 15 minutes before triggering rollback decision
- **Data Recovery:** If rollback fails, restore from backup taken 24 hours prior (restoration time: 2-3 hours)

### Maintenance Window

- **Schedule:** Saturday 22:00 - 02:00 EST (overnight, outside business hours)
- **Duration:** 4-hour window allocated (2 hours actual change, 2 hours buffer)
- **Business Hours OK:** No, clinical workflows cannot be interrupted

### Communication

| Timing | Audience | Channel | Message |
|---|---|---|---|
| T-48 hours | Clinical Ops, Nursing Directors | Email + Slack #clinical-ops | Scheduled PostgreSQL TDE encryption: Saturday 22:00-02:00. Brief connection interruptions expected. Contact IT for questions. |
| T-1 hour | All staff | Email blast | System maintenance starting in 1 hour. Patient portal may be temporarily unavailable. |
| Start | On-call IT | Slack #it-operations | TDE encryption starting now. ETA 30 minutes. |
| Completion | Clinical Ops, Compliance Officer | Email + Slack #compliance | PostgreSQL TDE complete. No issues observed. Tables encrypted successfully. |
| +24 hours | CISO, IT Director | Email summary | Post-TDE monitoring: Zero errors, zero performance degradation. CRYPTO-001 remediation 50% complete. |

---

## Action #2: Enable MySQL Transparent Data Encryption (Billing Database)

**Priority:** Immediate (Phase 1)
**System Affected:** billing-srv-01 (MySQL production server)
**Objective:** Encrypt financial PHI data to satisfy PCI-DSS 3.4 and HIPAA §164.312(a)(2)(iv)

### Prerequisites

- [ ] HSM-01 operational and reachable from billing-srv-01
- [ ] MySQL Enterprise Edition license confirmed (TDE requires enterprise features)
- [ ] Finance DBA trained on MySQL Enterprise TDE
- [ ] Maintenance window approved (Sunday 00:00-04:00 EST)
- [ ] Full backup of billing database completed
- [ ] Accounting system tested with encrypted database in staging
- [ ] CFO notified 72 hours in advance

### Steps

1. **Verify HSM connectivity**
   - SSH to billing-srv-01 as admin
   - Curl HSM health endpoint, confirm status healthy and latency under 15ms

2. **Generate MySQL TDE master key on HSM**
   - Use AWS CLI to create AES-256-GCM key with tag "MedDefense-MySQL-TDE"
   - Record Key ID and ARN

3. **Configure MySQL to use HSM as keystore**
   - Edit /etc/mysql/my.cnf
   - Add plugin_load_add for file_key_storage
   - Set file_key_management_filename and filekey paths
   - Set encryption_algorithm to AES_256

4. **Enable TDE on billing database**
   - Connect as root
   - Install keyring HSM plugin: INSTALL PLUGIN keyring_hsm SONAME 'keyring_hsm.so';
   - Enable encryption: ALTER DATABASE billing_db ENCRYPTION='Y';
   - Verify: SHOW ENCRYPTION PLUGINS;

5. **Rotate existing billing data to encrypted storage**
   - ALTER TABLE payments ENGINE=InnoDB ALGORITHM=COPY;
   - ALTER TABLE insurance_claims ENGINE=InnoDB ALGORITHM=COPY;
   - ALTER TABLE invoices ENGINE=InnoDB ALGORITHM=COPY;

6. **Restart MySQL to apply keystore changes**
   - sudo systemctl restart mysqld
   - sudo systemctl status mysqld

7. **Verify payment processing continues**
   - Run billing system health check
   - Confirm status OK and encryption active

### Validation

- SHOW TABLE STATUS FROM billing_db for payments table shows "Encryption = Yes"
- Billing system dashboard shows all services green
- Test charge processing for dummy account ($0.01 test transaction)
- /var/lib/mysql/billing_db/*.ibd files show encrypted sizes
- No slow query log entries exceeding 500ms for first 30 minutes

### Rollback

- **Procedure:** Disable TDE on database
  - Run: ALTER DATABASE billing_db ENCRYPTION='N';
  - Restart mysqld
- **Maximum Downtime:** 15 minutes before triggering rollback
- **Data Recovery:** Restore from backup if encryption causes data corruption (3-4 hours)

### Maintenance Window

- **Schedule:** Sunday 00:00 - 04:00 EST (overnight, minimal accounting activity)
- **Duration:** 4-hour window allocated
- **Business Hours OK:** No, financial system cannot be interrupted during working hours

### Communication

| Timing | Audience | Channel | Message |
|---|---|---|---|
| T-72 hours | CFO, Accounting Director | Email | MySQL TDE for billing database: Sunday 00:00-04:00. Invoice processing will pause briefly during maintenance. |
| T-2 hours | Accounts Receivable team | Email | System maintenance in 2 hours. Complete all pending invoice runs by 23:00. |
| Start | Finance DBA, IT Operations | Slack #finance-it | MySQL TDE starting. ETA 45 minutes. |
| Completion | CFO, Compliance Officer | Email + Slack #compliance | MySQL TDE complete. Payment processing verified. PCI-DSS requirement 3.4 now satisfied. |
| +24 hours | CISO | Email | Post-TDE monitoring: Zero issues. CRYPTO-003 remediation complete. |

---

## Action #3: Force Database TLS Connections (PostgreSQL + MySQL)

**Priority:** Immediate (Phase 1)
**Systems Affected:** ehr-db-01, billing-srv-01, web-srv-01, application servers
**Objective:** Prevent cleartext ePHI transmission over database connections

### Prerequisites

- [ ] TLS certificates generated for both database servers (stored on HSM-01)
- [ ] Application servers have CA certificate bundle installed
- [ ] Testing completed in staging environment (db-staging-01)
- [ ] All application connection strings documented
- [ ] Maintenance window approved (Monday 02:00-06:00 EST)
- [ ] Rollback scripts prepared and tested

### Steps

1. **Configure PostgreSQL to require TLS**
   - On ehr-db-01: Modify postgresql.conf
   - Set ssl = on
   - Set ssl_ca_file, ssl_cert_file, ssl_key_file paths
   - Set ssl_min_protocol_version = 'TLSv1.2'
   - Reload configuration via pg_reload_conf()

2. **Set sslmode to 'require' on PostgreSQL clients**
   - On web-srv-01 and all app servers: Modify connection pool configuration files
   - Update connection strings to include: sslmode=require sslrootcert=/etc/ssl/certs/ca-bundle.crt

3. **Configure MySQL to require secure transport**
   - On billing-srv-01: Edit /etc/mysql/my.cnf
   - Set require_secure_transport = ON
   - Set ssl_ca, ssl_cert, ssl_key paths
   - Restart mysqld

4. **Update MySQL client connection strings**
   - Add ssl_ca and ssl_verify_cert=True to all application database configs

5. **Test TLS enforcement**
   - Attempt cleartext connection to PostgreSQL with sslmode=disable (should fail with error)
   - Test TLS connection with sslmode=require (should connect successfully)
   - Repeat for MySQL: attempt connection without SSL (should be rejected)

### Validation

- Cleartext connections rejected on port 5432 (PostgreSQL) and 3306 (MySQL)
- All clinical portals successfully connect to databases with TLS
- No "connection refused" errors in application logs
- Average query latency increased less than 10% (acceptable threshold)
- OpenSSL s_client connection test shows TLS 1.2+ handshake successful

### Rollback

- **Procedure:** Disable TLS requirement on database servers
  - PostgreSQL: Set ssl = off, clear ssl_min_protocol_version, reload config
  - MySQL: Set require_secure_transport = OFF, restart mysqld
- **Maximum Downtime:** 10 minutes before triggering rollback
- **Fallback:** Update connection strings back to non-TLS if server-side changes fail

### Maintenance Window

- **Schedule:** Monday 02:00 - 06:00 EST (lowest traffic period)
- **Duration:** 4-hour window allocated
- **Business Hours OK:** No, database access required for clinical operations during day

### Communication

| Timing | Audience | Channel | Message |
|---|---|---|---|
| T-72 hours | All IT staff, App Development leads | Email + Slack | Database TLS enforcement: Monday 02:00-06:00. All application connection strings must support TLS. |
| T-24 hours | Clinical applications team | Email | Final reminder: Verify your app's database connection supports sslmode=require by Monday 00:00. |
| Start | IT Operations, DBAs | Slack #it-ops | Database TLS enforcement starting. Monitor for connection failures. |
| +1 hour | All stakeholders | Slack update | 50% complete. No major issues detected. 2 apps required config fixes. |
| Completion | CISO, Compliance Officer | Email | Database TLS enforcement complete. All DB connections now encrypted in transit. |

---

## Action #4: Deploy Multi-Factor Authentication for Clinical Applications

**Priority:** Immediate (Phase 1)
**Systems Affected:** All clinical applications (EHR portal, PACS viewer, lab system)
**Objective:** Satisfy HIPAA §164.312(d) authentication requirements and reduce insider threat risk

### Prerequisites

- [ ] MFA vendor selected (Azure AD MFA or Duo Security licensed and configured)
- [ ] Administrative accounts enrolled in MFA (IT team only initially)
- [ ] Test group of 10 clinical users identified for pilot
- [ ] Backup authentication method documented (SMS fallback, hardware token)
- [ ] Helpdesk trained on MFA troubleshooting
- [ ] Communication templates ready for rollout announcement

### Steps

1. **Configure MFA provider**
   - In Azure AD or Duo admin console, create MFA enrollment group
   - Enable security defaults or conditional access policy
   - Configure MFA methods: authenticator app (primary), SMS (fallback), hardware token (for users without smartphones)

2. **Enroll administrative accounts**
   - Add IT admins to MFA enrollment group
   - Force MFA registration at next login
   - Verify each admin completes enrollment within 24 hours
   - Test break-glass account access

3. **Deploy MFA conditional access policy for clinical applications**
   - Create policy targeting EHR Portal, PACS Viewer, Lab System application IDs
   - Include all users except service accounts and break-glass accounts
   - Set grant controls to require MFA
   - Set state to "Report-Only" initially for monitoring

4. **Pilot with 10 clinical users**
   - Select users from different departments (Radiology, Nursing, Pharmacy)
   - Provide hardware tokens for users without smartphones
   - Train on MFA enrollment process (15-minute video plus live demo)
   - Monitor for 48 hours for login issues
   - Collect feedback on workflow impact

5. **Switch policy from Report-Only to Enabled**
   - After pilot completes with no critical issues
   - Enable MFA enforcement for all clinical application access
   - Notify helpdesk to expect increased support tickets for 2 weeks

6. **Disable password-only authentication**
   - After 30-day grace period, enforce MFA for all clinical access
   - Remove legacy password-only conditional access policies
   - Document break-glass procedure for MFA outage scenarios

### Validation

- Login to EHR portal prompts for second factor (push notification or token code)
- Login without MFA factor is blocked with "additional verification required" message
- Break-glass account can bypass MFA (logged and alerted)
- PACS viewer requires MFA for remote access
- Helpdesk ticket volume returns to baseline within 2 weeks of rollout
- Zero account lockouts caused by MFA misconfiguration

### Rollback

- **Procedure:** Set conditional access policy state to "Disabled"
  - Users revert to password-only authentication immediately
  - No data changes required
- **Maximum Downtime:** 5 minutes (policy change propagation)
- **Trigger:** More than 10% of clinical users unable to authenticate within first 4 hours

### Maintenance Window

- **Schedule:** Pilot starts Tuesday 08:00 EST; full rollout Monday following week
- **Duration:** 48-hour pilot, then permanent enforcement
- **Business Hours OK:** Yes, MFA enrollment must happen during business hours for clinical staff

### Communication

| Timing | Audience | Channel | Message |
|---|---|---|---|
| T-2 weeks | All clinical staff | Email + posted notices | MFA coming to clinical systems. Watch for enrollment email. Training sessions available. |
| T-1 week | Department heads | Email | MFA pilot starts next week. Identify super-users in your department to assist colleagues. |
| T-48 hours | Pilot users | Email + phone call | You have been selected for MFA pilot. Enrollment instructions attached. Support: x4357. |
| Go-live | All clinical staff | Email + Slack + posted notices | MFA is now required for EHR, PACS, and Lab systems. Have your phone or token ready at login. |
| +1 week | CISO, IT Director | Email summary | MFA rollout status: X% enrolled, Y issues resolved, Z users requiring hardware tokens. |

---

## Action #5: Disable Legacy TLS Protocols and Weak Cipher Suites on Patient Portal

**Priority:** Immediate (Phase 1)
**System Affected:** web-srv-01 (patient portal)
**Objective:** Eliminate TLS downgrade attack surface and enforce strong transport encryption

### Prerequisites

- [ ] Current TLS configuration audited and documented (Task 10 complete)
- [ ] New nginx configuration tested in staging environment
- [ ] HSTS header tested with browser dev tools
- [ ] TLS 1.3 compatibility verified for all major browsers used by patients
- [ ] Rollback configuration file saved
- [ ] Maintenance window approved (Sunday 02:00-04:00 EST)

### Steps

1. **Backup current nginx configuration**
   - Copy /etc/nginx/sites-available/patientportal to /etc/nginx/backup/patientportal.pre-tls-hardening
   - Verify backup file is readable

2. **Update nginx TLS configuration**
   - Edit /etc/nginx/sites-available/patientportal
   - Set ssl_protocols to: TLSv1.2 TLSv1.3 (remove TLSv1 and TLSv1.1)
   - Set ssl_ciphers to: ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
   - Set ssl_prefer_server_ciphers to: on
   - Set ssl_session_cache to: shared:SSL:10m
   - Set ssl_session_timeout to: 10m

3. **Add HSTS header**
   - Add to server block: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

4. **Enable OCSP stapling**
   - Set ssl_stapling to: on
   - Set ssl_stapling_verify to: on
   - Set ssl_trusted_certificate path to CA bundle

5. **Test nginx configuration syntax**
   - Run: nginx -t
   - Expected: "syntax is ok" and "test is successful"

6. **Reload nginx**
   - Run: sudo systemctl reload nginx
   - Verify service status is active

7. **Verify TLS configuration from external client**
   - Run: openssl s_client -connect patientportal.meddefense.com:443 -tls1_2
   - Confirm cipher suite is ECDHE-RSA-AES256-GCM-SHA384 or similar AEAD cipher
   - Run: openssl s_client -connect patientportal.meddefense.com:443 -tls1
   - Expected: handshake failure (TLS 1.0 disabled)

### Validation

- Browser test: Access https://patientportal.meddefense.com from Chrome, Firefox, Safari
- Browser shows green padlock with valid certificate
- HSTS header present in response (verify via browser dev tools or curl -I)
- TLS 1.0 and 1.1 connection attempts fail with protocol error
- Only AEAD cipher suites (GCM or CHACHA20) accepted
- External scanner: Run Qualys SSL Labs test, target grade A or A+
- No patient complaints about portal access within 48 hours
- Error log shows no TLS handshake failures from modern browsers

### Rollback

- **Procedure:** Restore previous nginx configuration
  - Copy backup file: cp /etc/nginx/backup/patientportal.pre-tls-hardening /etc/nginx/sites-available/patientportal
  - Test: nginx -t
  - Reload: sudo systemctl reload nginx
- **Maximum Downtime:** 2 minutes (nginx reload is near-instantaneous)
- **Trigger:** Any patient unable to access portal from a modern browser (Chrome 90+, Firefox 88+, Safari 14+)

### Maintenance Window

- **Schedule:** Sunday 02:00 - 04:00 EST (lowest patient traffic)
- **Duration:** 2-hour window (15 minutes actual change, 1 hour 45 minutes buffer)
- **Business Hours OK:** No, patient portal must be available during clinic hours

### Communication

| Timing | Audience | Channel | Message |
|---|---|---|---|
| T-72 hours | CISO, IT Director | Email | TLS hardening scheduled for web-srv-01 Sunday 02:00-04:00. No patient impact expected. |
| T-24 hours | Helpdesk | Email | Tomorrow night: TLS hardening on patient portal. If patients report access issues after 04:00, escalate to Steve immediately. |
| Start | IT Operations | Slack #it-ops | TLS hardening starting on web-srv-01. |
| +15 min | IT Operations | Slack #it-ops | Configuration deployed. Running SSL Labs scan to verify. |
| Completion | CISO | Email | TLS hardening complete. SSL Labs grade: A. TLS 1.0/1.1 disabled. HSTS enabled. CRYPTO-005 remediation complete. |
| +48 hours | Compliance Officer | Email summary | Post-hardening monitoring: Zero patient access complaints. No TLS errors in logs. Downgrade attack surface eliminated. |

---

## Appendix - Pre-Execution Checklist

Before beginning ANY of the 5 actions above, verify the following:

- [ ] All stakeholders identified and contact information confirmed
- [ ] Maintenance windows approved by IT Director (Sarah Park)
- [ ] Backups completed and verified for all affected systems
- [ ] Rollback scripts tested in staging environment
- [ ] Monitoring dashboards operational (Prometheus, Grafana)
- [ ] PagerDuty escalation rules configured for on-call engineers
- [ ] Helpdesk briefed on potential user impact for each change
- [ ] Change management tickets created in Jira for each action
- [ ] CISO informed of timeline and risk acceptance
- [ ] Compliance Officer informed of HIPAA remediation milestones

## Execution Order

| Sequence | Action | Est. Duration | Dependency |
|---|---|---|---|
| 1 | Action #5: TLS hardening on web-srv-01 | 15 minutes | None |
| 2 | Action #1: PostgreSQL TDE on ehr-db-01 | 2-4 hours | HSM-01 operational |
| 3 | Action #3: Force database TLS connections | 2-4 hours | Actions #1 and #2 complete |
| 4 | Action #2: MySQL TDE on billing-srv-01 | 2-4 hours | HSM-01 operational |
| 5 | Action #4: Deploy MFA for clinical apps | 2-4 weeks | User training completed |

Actions #5 and #1 can be executed in parallel since they affect different systems. Action #3 depends on #1 and #2 being complete because TLS must be configured before enforcing it on clients. Action #4 (MFA) runs in parallel with all others since it does not touch the same systems.
