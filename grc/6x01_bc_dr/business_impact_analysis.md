# MedDefense Business Impact Analysis

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** Steve, IT Security  
**Date:** 2026-11-01  
**CISO approval:** _________________________ Date: _________

## Executive Summary

MedDefense operates 10 critical systems supporting a 230-bed acute care hospital with 24×7 emergency department, ICU, inpatient surgery, radiology, laboratory and pharmacy operations. This Business Impact Analysis classifies each system by patient safety consequence at 1-hour, 4-hour and 24-hour downtime thresholds, documents regulatory obligations under HIPAA Security Rule 164.308(a)(7), estimates revenue exposure, and establishes defensible RTO, RPO and MTD values.

Three key findings drive the recovery priority sequence:

1. **Tier 1 clinical systems** (Epic EHR, LIS, Pharmacy) directly affect medication administration, diagnostic testing and care coordination with patient safety consequences escalating within 4 hours of downtime.
2. **Dependency infrastructure** (Network Core, Active Directory, Backup and DR Infrastructure) must recover before clinical systems regardless of their individual patient safety profile, as all clinical applications depend on these foundations.
3. **Current backup schedules for three systems**—Laboratory Information System, Medical Device Integration Gateway and Active Directory—declare RPOs that are shorter than backup frequency can mathematically deliver, creating structural gaps between documented recovery objectives and operational reality.

## Methodology

This assessment applies the framework defined in HIPAA Security Rule 164.308(a)(7), specifically:

- 164.308(a)(7)(ii)(E): Applications and Data Criticality Analysis
- 164.308(a)(7)(ii)(A): Data Backup Plan
- 164.308(a)(7)(ii)(B): Disaster Recovery Plan
- 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan
- 164.308(a)(7)(ii)(D): Testing and Revision Procedures

Impact thresholds derive from MedDefense's documented downtime guidance:

- **1 hour:** Most departments continue with downtime procedures; risk is missed context (allergies, recent medications, pending orders, recent labs, imaging availability, patient movement).
- **4 hours:** Manual workarounds become strained; duplicate documentation, specimen tracking errors, medication verification delays and delayed diagnostic decisions become more likely.
- **24 hours:** Downtime becomes a patient safety and regulatory event; paper records become hard to reconcile, delayed critical results affect treatment, leadership may need emergency operations and reporting processes.

Maximum Tolerable Downtime (MTD) represents the total elapsed time a process can be unavailable before consequences become unacceptable. Recovery Time Objective (RTO) sits below MTD with margin for validation. Recovery Point Objective (RPO) measures backward data loss tolerance from failure, constrained by backup frequency per the principle established in Robert Kim's backup log review: achievable RPO can never be better than backup frequency.

## System Impact Assessment

### Active Directory

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | New logins to Epic, LIS, PACS/RIS, pharmacy fail; cached sessions survive briefly; service account authentication for dependent systems begins to degrade | 164.312(d): Personnel Authentication; 164.308(a)(4): Access Management | Estimated $15,000/hour: all workforce authentication blocked |
| 4 hours | Epic, LIS, PACS/RIS, pharmacy, email and security tools unable to authorize new users or service accounts; clinical workflow transitions fully to paper procedures | 164.308(a)(7)(i): Contingency Plan; Joint Commission EM.02.02.03 (staff role clarity during emergencies) | Estimated $15,000/hour compounded; dependent system downtime cannot proceed without identity foundation |
| 24 hours | Complete identity outage becomes a patient safety and regulatory event; credential reset backlog creates weeks of recovery friction; security visibility degraded | 164.312(d): Personnel Authentication; potential breach notification if authentication logs unavailable for incident investigation | Estimated $15,000/hour compounded; potential regulatory enforcement if identity controls cannot be demonstrated |

**Dependencies:** None (identity foundation)

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 2 hours

**Recovery Point Objective (RPO):** 8 hours (snapshot interval from `current_backup_schedule.csv`)

**Priority Tier:** Tier 1

---

### Epic EHR

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Order entry, medication documentation, clinical notes, allergy verification, patient history unavailable; missed context risk elevated for deteriorating patients | 164.308(a)(7)(i): Contingency Plan; 164.312(c)(1): Integrity (incomplete documentation during downtime) | Estimated $50,000/hour: order entry and clinical documentation halted across all units |
| 4 hours | Duplicate documentation strain increases; medication verification delays; delayed diagnostic decisions; reconciliation burden at restoration grows substantially | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission EM.03.01.01 (downtime procedures must be tested) | Estimated $50,000/hour; potential claim denial if documentation incomplete post-restoration |
| 24 hours | Paper records become hard to reconcile; delayed critical results affect treatment decisions; leadership requires emergency operations reporting; potential patient safety events from documentation gaps | 164.308(a)(7)(i): Contingency Plan; potential Joint Commission citations if downtime reconciliation incomplete; HIPAA integrity violations possible | Estimated $50,000/hour; significant claim denial exposure and regulatory enforcement risk |

**Dependencies:** Network Core, Active Directory, Pharmacy Dispensing System, LIS interface, PACS/RIS, Email and Secure Messaging

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 4 hours (per `current_backup_schedule.csv`, though `downtime_impact_notes.md` notes "local downtime procedure outdated"—validation required)

**Recovery Point Objective (RPO):** 15 minutes (vendor replication frequency per `current_backup_schedule.csv`)

**Priority Tier:** Tier 1

---

### Laboratory Information System

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Lab order intake, specimen tracking, analyzer result association, critical value notification delayed; STAT workflows continue by phone and paper but mislabeling risk elevated | 164.308(a)(7)(i): Contingency Plan; 164.308(a)(7)(ii)(E): Applications and Data Criticality Analysis | Estimated $25,000/hour: laboratory operations delayed; STAT critical value notification failures |
| 4 hours | Mislabeling and delayed critical value notification become primary risks; paper requisitions accumulate; chemistry bench critical value call log cannot be reconciled to digital record until restoration | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; CLIA requirements for critical result notification timelines may be exceeded | Estimated $25,000/hour; potential liability if critical results delayed beyond clinical standards |
| 24 hours | Specimen tracking becomes hard to reconcile; delayed critical results affect treatment decisions; patient safety event from missed critical values possible; regulatory reporting delayed | 164.308(a)(7)(i): Contingency Plan; CLIA critical result notification requirements; potential Joint Commission findings for untested recovery procedures | Estimated $25,000/hour; significant patient safety liability if critical values not communicated |

**Dependencies:** Network Core, Active Directory, Epic interface engine, lab instrument feeds

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 4 hours (declared; current test evidence shows nightly backup only, no prior restore executed—actual RTO must be validated in recovery test)

**Recovery Point Objective (RPO):** 24 hours (nightly SQL dump at 23:30 per `current_backup_schedule.csv`; per `backup_log_review_findings.md`, implied operational RPO of 1 hour for critical values conflicts with actual achievable RPO)

**Priority Tier:** Tier 1

---

### PACS/RIS

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Imaging acquisition may continue locally, but prior studies, reports and distribution to clinicians delayed; ED, stroke, trauma and surgery workflows most exposed | 164.308(a)(7)(i): Contingency Plan; 164.312(c)(1): Integrity (imaging metadata and reports) | Estimated $20,000/hour: radiology interpretation delayed; imaging-dependent decisions postponed |
| 4 hours | Prior study comparison unavailable for urgent imaging decisions; report distribution delayed; ED and trauma clinical decisions based on limited information | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; potential delay in diagnosis affecting standard of care | Estimated $20,000/hour; potential liability if diagnostic decisions made without prior imaging context |
| 24 hours | Diagnostic decisions made without imaging history; delayed diagnoses affect treatment; paper imaging requests cannot be tracked accurately until restoration | 164.308(a)(7)(i): Contingency Plan; potential Joint Commission findings for untested restore sequence (per `current_backup_schedule.csv` known gap) | Estimated $20,000/hour; significant diagnostic delay liability |

**Dependencies:** Network Core, Active Directory, modality devices, Epic order interface

**Maximum Tolerable Downtime (MTD):** 6 hours

**Recovery Time Objective (RTO):** 2 hours (per declared RTO in scenario)

**Recovery Point Objective (RPO):** 4 hours (storage snapshot frequency per `current_backup_schedule.csv`)

**Priority Tier:** Tier 2

---

### Pharmacy Dispensing System

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Medication verification and dispensing continue manually; allergy and interaction checks delayed; barcode administration degrades; controlled substance tracking shifts to paper | 164.308(a)(7)(i): Contingency Plan; DEA controlled substance documentation requirements | Estimated $35,000/hour: medication dispensing slowed; verification delays increase error risk |
| 4 hours | Medication verification delays compound; allergy checks deferred to manual processes; interaction screening absent during dispensing; controlled substance reconciliation burden increases | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; DEA controlled substance accountability may be compromised | Estimated $35,000/hour; potential medication error liability; controlled substance audit findings possible |
| 24 hours | Medication errors from missing allergy or interaction checks become probable; controlled substance paper tracking difficult to reconcile; regulatory compliance at risk | 164.308(a)(7)(i): Contingency Plan; DEA controlled substance documentation requirements; potential medication error investigation | Estimated $35,000/hour; significant medication error liability; DEA audit findings possible |

**Dependencies:** Active Directory, Epic EHR, Network Core, medication cabinets

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 3 hours

**Recovery Point Objective (RPO):** 1 hour (database backup frequency per `current_backup_schedule.csv`)

**Priority Tier:** Tier 1

---

### Medical Device Integration Gateway

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Bedside monitoring continues locally, but automatic charting and alarm routing degrade; ICU and telemetry units most affected; vital signs documentation shifts to manual | 164.308(a)(7)(i): Contingency Plan; Joint Commission national patient safety goals for alarm management | Estimated $15,000/hour: nursing documentation burden increases; alarm fatigue risk elevated |
| 4 hours | Alarm routing delays affect clinical response; automatic vital signs charting fails; nursing units must manually capture device readings; alarm fatigue increases | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission National Patient Safety Goal for alarm safety may be compromised | Estimated $15,000/hour; potential alarm-related adverse event liability |
| 24 hours | Manual vital signs documentation accumulates unmanageably; alarm routing failures may delay critical responses; device data integration gap widens | 164.308(a)(7)(i): Contingency Plan; Joint Commission alarm safety findings possible; device data integrity gaps | Estimated $15,000/hour; potential alarm-related adverse events; regulatory findings for untested vendor backup |

**Dependencies:** Network Core, VLAN segmentation, downstream integration into Epic

**Maximum Tolerable Downtime (MTD):** 8 hours

**Recovery Time Objective (RTO):** 6 hours

**Recovery Point Objective (RPO):** 24 hours (daily configuration export at 02:30 per `current_backup_schedule.csv`; no secondary destination or restore test documented)

**Priority Tier:** Tier 2

---

### Network Core

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Routing, switching, WAN access, VLAN segmentation and site connectivity disrupted; simultaneous failure across all clinical and business systems begins | 164.308(a)(7)(i): Contingency Plan; 164.312(e)(1): Transmission Security | Estimated $75,000/hour: all systems affected simultaneously; hospital-wide downtime declared |
| 4 hours | Clinical systems, monitoring, authentication, communication and security visibility fail simultaneously; paper downtime procedures activated across all units | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission EM.02.02.03 (staff role clarity during emergencies); 164.312(e)(1): Transmission Security violations during outage | Estimated $75,000/hour; hospital-wide operational paralysis |
| 24 hours | Extended network outage creates cascading failures across all clinical operations; security visibility lost; patient safety event probability rises sharply | 164.308(a)(7)(i): Contingency Plan; Joint Commission emergency management citations likely; 164.312(e)(1): Transmission Security violations during prolonged outage | Estimated $75,000/hour; significant patient safety and regulatory exposure |

**Dependencies:** None (network foundation)

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 2 hours

**Recovery Point Objective (RPO):** 6 hours (device config backup frequency per `current_backup_schedule.csv`)

**Priority Tier:** Tier 1

---

### Email and Secure Messaging

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Clinical communication, alert notification and regulatory correspondence shifts to phone; mobile device access affected; coordination delays begin | 164.308(a)(7)(i): Contingency Plan; 164.312(e)(1): Transmission Security for secure messaging component | Estimated $10,000/hour: administrative and coordination overhead increases |
| 4 hours | Clinical communication bridge not tested per `current_backup_schedule.csv`; alert notification delays affect escalation chains; coordination strain increases | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission communication requirements during emergencies | Estimated $10,000/hour; escalation delays may extend to clinical systems |
| 24 hours | Extended communication outage affects regulatory correspondence, shift handoffs and non-emergency clinical coordination; paper communication burden unmanageable | 164.308(a)(7)(i): Contingency Plan; potential Joint Commission findings for untested continuity procedures | Estimated $10,000/hour; regulatory correspondence delays possible |

**Dependencies:** Identity provider, network egress, mobile device access

**Maximum Tolerable Downtime (MTD):** 12 hours

**Recovery Time Objective (RTO):** 8 hours

**Recovery Point Objective (RPO):** Provider continuous retention; export daily per `current_backup_schedule.csv`

**Priority Tier:** Tier 3

---

### Backup and DR Infrastructure

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Backup catalog and restore capability unavailable; recovery risk created even when production systems still run; restoration cannot be initiated | 164.308(a)(7)(ii)(A): Data Backup Plan; 164.308(a)(7)(ii)(B): Disaster Recovery Plan | Estimated $20,000/hour: recovery capability unavailable; outage can become permanent data loss |
| 4 hours | Any system failure during this window cannot be recovered; backup platform itself is a dependency per Finding 5 in `backup_log_review_findings.md` | 164.308(a)(7)(ii)(A): Data Backup Plan; 164.308(a)(7)(ii)(D): Testing and Revision Procedures (catalog restore timing untested) | Estimated $20,000/hour; permanent data loss risk for any concurrent production failure |
| 24 hours | Recovery platform failure for extended period creates existential data loss risk; 7-year archive access potentially affected; regulatory evidence chain broken | 164.308(a)(7)(ii)(A): Data Backup Plan; 164.308(a)(7)(ii)(D): Testing and Revision Procedures | Estimated $20,000/hour; potential breach notification if data loss occurs during platform outage |

**Dependencies:** DR platform storage, isolated backup account

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 3 hours

**Recovery Point Objective (RPO):** 4 hours (catalog backup frequency per `current_backup_schedule.csv`)

**Priority Tier:** Tier 1

---

### Security Operations Platform

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | SIEM event collection continues but alert triage and EDR management unavailable; detection and response reduced during period when opportunistic attack risk can rise | 164.308(a)(7)(i): Contingency Plan; 164.312(b): Audit Controls | Estimated $12,000/hour: security visibility reduced; incident response delayed |
| 4 hours | Security operations blind spot extends; threat detection reduced precisely when clinical systems in downtime are more vulnerable to exploitation | 164.308(a)(7)(i): Contingency Plan; 164.312(b): Audit Controls; potential NIST Cybersecurity Framework alignment gap | Estimated $12,000/hour; increased breach probability during clinical downtime |
| 24 hours | Extended security visibility loss compounds breach risk; cold restore documented but alerting continuity not tested per `current_backup_schedule.csv`; forensic evidence incomplete | 164.308(a)(7)(i): Contingency Plan; 164.312(b): Audit Controls; potential HIPAA breach notification if incident not detected | Estimated $12,000/hour; significant breach liability if incident undetected |

**Dependencies:** Network Core, log sources, EDR management, identity

**Maximum Tolerable Downtime (MTD):** 8 hours

**Recovery Time Objective (RTO):** 6 hours

**Recovery Point Objective (RPO):** 4 hours (index snapshot frequency per `current_backup_schedule.csv`)

**Priority Tier:** Tier 2

---

## Dependency Map

```text
Network Core
├── Active Directory
│   ├── Epic EHR
│   │   ├── LIS interface
│   │   ├── Pharmacy Dispensing System
│   │   └── PACS/RIS ordering and results
│   ├── Email and Secure Messaging
│   ├── Security Operations Platform
│   └── Backup and DR Infrastructure access control
├── Medical Device Integration Gateway
├── PACS/RIS image movement
└── Backup replication traffic
```
