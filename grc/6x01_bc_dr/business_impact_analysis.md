# MedDefense Business Impact Analysis

**Version:** 1.0  
**Classification:** Confidential  
**Prepared by:** Steve, IT Security  
**Date:** 2026-11-01  
**CISO approval:** _________________________ Date: _________

## Executive Summary

MedDefense operates 10 critical systems supporting a 230-bed acute care hospital with 24×7 emergency department, ICU, inpatient surgery, radiology, laboratory and pharmacy operations. This Business Impact Analysis classifies each system by patient safety consequence at 1-hour, 4-hour and 24-hour downtime thresholds, documents regulatory obligations under HIPAA Security Rule 164.308(a)(7), estimates revenue exposure, and establishes defensible RTO, RPO and MTD values.

Three key findings drive the recovery priority sequence:

1. **Tier 1 clinical systems** (Epic EHR, LIS, Pharmacy) directly affect medication administration, diagnostic testing and care coordination, with patient safety consequences escalating within 4 hours of downtime.
2. **Dependency infrastructure** (Network Core, Active Directory, Backup and DR Infrastructure) must recover before clinical systems regardless of their individual patient safety profile, as all clinical applications depend on these foundations.
3. **Downtime duration, not system category, drives severity:** the downtime impact notes show the same system producing missed-context risk at 1 hour, strained manual workarounds at 4 hours, and a patient safety and regulatory event at 24 hours. RTO, RPO and MTD values in this document are anchored to those three thresholds.

## Methodology

This assessment applies the framework defined in HIPAA Security Rule 164.308(a)(7):

- 164.308(a)(7)(ii)(E): Applications and Data Criticality Analysis
- 164.308(a)(7)(ii)(A): Data Backup Plan
- 164.308(a)(7)(ii)(B): Disaster Recovery Plan
- 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan
- 164.308(a)(7)(ii)(D): Testing and Revision Procedures

Impact thresholds derive from MedDefense's documented downtime guidance:

- **1 hour:** Most departments continue with downtime procedures; risk is missed context (allergies, recent medications, pending orders, recent labs, imaging availability, patient movement).
- **4 hours:** Manual workarounds become strained; duplicate documentation, specimen tracking errors, medication verification delays and delayed diagnostic decisions become more likely.
- **24 hours:** Downtime becomes a patient safety and regulatory event; paper records become hard to reconcile, delayed critical results affect treatment, leadership may need emergency operations and reporting processes.

Maximum Tolerable Downtime (MTD) represents the total elapsed time a process can be unavailable before consequences become unacceptable. Recovery Time Objective (RTO) is the time within which service must be restored, and sits strictly below MTD with margin for validation, because restoring a system is not the same as confirming it is fit for clinical use. Recovery Point Objective (RPO) measures data loss tolerance backwards from the moment of failure and is stated in time for every system.

**Consistency rule applied throughout:** every system satisfies RPO < RTO < MTD, stated in uniform units of hours, so that objectives can be validated mechanically and no system promises data preservation beyond its own tolerable outage window.

## System Impact Assessment

### Active Directory

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | New logins to Epic, LIS, PACS/RIS, pharmacy and email fail; cached sessions survive briefly; service-account authentication for dependent systems begins to degrade | 164.308(a)(4): Access Management; 164.308(a)(7)(i): Contingency Plan | Estimated $15,000/hour: workforce authentication blocked across clinical and administrative systems |
| 4 hours | Epic, LIS, PACS/RIS, pharmacy, email and security tools cannot authorize new users or service accounts; clinical workflow transitions fully to paper procedures | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission emergency management expectations for staff role clarity | Estimated $15,000/hour compounded; dependent system recovery cannot proceed without identity foundation |
| 24 hours | Identity outage becomes a patient safety and regulatory event; credential recovery backlog extends harm beyond restoration; security visibility remains degraded | 164.308(a)(7)(i): Contingency Plan; Joint Commission emergency management expectations | Estimated $15,000/hour compounded; regulatory enforcement risk if access controls cannot be demonstrated |

**Operational Dependencies:** None; identity foundation for all clinical systems

**Downstream Failure Sequence:** Active Directory loss blocks authentication for Epic EHR, LIS, PACS/RIS, Pharmacy Dispensing System, Email and Secure Messaging, Security Operations Platform, and Backup and DR Infrastructure access control

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 2 hours

**Recovery Point Objective (RPO):** 1 hour

**Priority Tier:** Tier 1

---

### Epic EHR

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Order entry, medication documentation, clinical notes, allergy verification, patient history and care coordination unavailable; missed-context risk elevated for deteriorating patients | 164.308(a)(7)(i): Contingency Plan; 164.312(c)(1): Integrity (documentation gaps during downtime) | Estimated $50,000/hour: order entry and clinical documentation halted across all units |
| 4 hours | Manual workarounds strained; duplicate documentation, medication verification delays and delayed diagnostic decisions become likely; reconciliation burden at restoration grows substantially | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission emergency management expectations for continuity of patient care | Estimated $50,000/hour; claim denial exposure if documentation incomplete post-restoration |
| 24 hours | Paper records hard to reconcile; delayed critical results affect treatment; leadership requires emergency operations and reporting; patient safety events from documentation gaps | 164.308(a)(7)(i): Contingency Plan; Joint Commission emergency management expectations | Estimated $50,000/hour; significant claim denial exposure and regulatory enforcement risk |

**Operational Dependencies:** Network Core, Active Directory, Pharmacy Dispensing System, LIS interface, PACS/RIS ordering and results, Email and Secure Messaging

**Downstream Failure Sequence:** Epic outage halts order entry feeding LIS and pharmacy, blocks allergy verification for medication administration, and stops results distribution to clinicians

**Maximum Tolerable Downtime (MTD):** 8 hours

**Recovery Time Objective (RTO):** 4 hours

**Recovery Point Objective (RPO):** 1 hour

**Priority Tier:** Tier 1

---

### Laboratory Information System

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Lab order intake, specimen tracking, analyzer result association, critical value notification and result posting to Epic delayed; STAT workflows continue by phone and paper with elevated mislabeling risk | 164.308(a)(7)(i): Contingency Plan; 164.308(a)(7)(ii)(E): Applications and Data Criticality Analysis | Estimated $25,000/hour: laboratory throughput delayed; STAT processing slowed |
| 4 hours | Mislabeling and delayed critical value notification become primary risks; specimen tracking errors become likely; paper requisitions accumulate without reconciliation path | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission expectations for critical result communication | Estimated $25,000/hour; liability exposure if critical results delayed beyond clinical standards |
| 24 hours | Delayed critical results affect treatment decisions; specimen records hard to reconcile; patient safety event from missed critical values possible | 164.308(a)(7)(i): Contingency Plan; Joint Commission emergency management expectations | Estimated $25,000/hour; significant patient safety liability |

**Operational Dependencies:** Network Core, Active Directory, Epic interface engine, lab instrument feeds

**Downstream Failure Sequence:** LIS outage stops analyzer result association and result posting to Epic; critical value notification degrades to phone with read-back documentation required per escalation contacts

**Maximum Tolerable Downtime (MTD):** 8 hours

**Recovery Time Objective (RTO):** 4 hours

**Recovery Point Objective (RPO):** 1 hour

**Priority Tier:** Tier 1

---

### PACS/RIS

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Prior studies, reports and distribution to clinicians delayed; ED, stroke, trauma and surgery workflows most exposed; urgent image acquisition continues | 164.308(a)(7)(i): Contingency Plan; 164.312(c)(1): Integrity (imaging metadata and reports) | Estimated $20,000/hour: radiology interpretation and report distribution delayed |
| 4 hours | Prior study comparison unavailable for urgent imaging decisions; delayed diagnostic decisions based on limited information in ED, stroke, trauma and surgery | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission expectations for continuity of patient care | Estimated $20,000/hour; diagnostic delay liability exposure |
| 24 hours | Diagnostic decisions made without imaging history; delayed diagnoses affect treatment; imaging distribution backlog unmanageable | 164.308(a)(7)(i): Contingency Plan; Joint Commission emergency management expectations | Estimated $20,000/hour; significant diagnostic delay liability |

**Operational Dependencies:** Network Core, Active Directory, modality devices, Epic order interface

**Downstream Failure Sequence:** PACS/RIS outage delays report availability to Epic; image movement across the network halts; ED, stroke, trauma and surgery decisions proceed without prior studies

**Maximum Tolerable Downtime (MTD):** 6 hours

**Recovery Time Objective (RTO):** 2 hours

**Recovery Point Objective (RPO):** 1 hour

**Priority Tier:** Tier 2

---

### Pharmacy Dispensing System

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Medication verification and dispensing continue manually; allergy and interaction checks may be delayed; controlled substance tracking and barcode administration degrade | 164.308(a)(7)(i): Contingency Plan; DEA controlled substance documentation requirements | Estimated $35,000/hour: dispensing slowed; verification delays raise error risk |
| 4 hours | Medication verification delays compound; allergy and interaction checks absent during dispensing; duplicate documentation strain increases error probability | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; DEA controlled substance accountability requirements | Estimated $35,000/hour; medication error liability; controlled substance audit exposure |
| 24 hours | Medication errors from missing allergy and interaction checks become probable; controlled substance paper tracking difficult to reconcile; regulatory compliance at risk | 164.308(a)(7)(i): Contingency Plan; DEA documentation requirements; potential medication error investigation | Estimated $35,000/hour; significant medication error liability |

**Operational Dependencies:** Active Directory, Epic EHR, Network Core, medication cabinets

**Downstream Failure Sequence:** Pharmacy outage severs medication verification and barcode administration flow from Epic ordering; manual dispensing proceeds with paper MAR documentation

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 3 hours

**Recovery Point Objective (RPO):** 1 hour

**Priority Tier:** Tier 1

---

### Medical Device Integration Gateway

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Bedside monitoring continues locally; automatic charting and alarm routing degrade; ICU and telemetry most affected; vital signs documentation shifts to manual | 164.308(a)(7)(i): Contingency Plan; Joint Commission expectations for alarm management | Estimated $15,000/hour: nursing documentation burden rises; alarm fatigue risk elevated |
| 4 hours | Alarm routing delays affect clinical response; manual vital signs capture strains nursing units; alarm fatigue increases missed-alert probability | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission alarm safety expectations | Estimated $15,000/hour; alarm-related adverse event liability exposure |
| 24 hours | Manual vital signs documentation unmanageable; alarm routing failures may delay critical responses in ICU and telemetry | 164.308(a)(7)(i): Contingency Plan; Joint Commission emergency management expectations | Estimated $15,000/hour; alarm-related adverse events and regulatory findings |

**Operational Dependencies:** Network Core, VLAN segmentation; downstream integration into Epic

**Downstream Failure Sequence:** Gateway outage stops device telemetry charting into Epic and degrades alarm routing to nursing stations; ICU and telemetry units most affected

**Maximum Tolerable Downtime (MTD):** 8 hours

**Recovery Time Objective (RTO):** 6 hours

**Recovery Point Objective (RPO):** 4 hours

**Priority Tier:** Tier 2

---

### Network Core

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Routing, switching, WAN access and VLAN segmentation disrupted; simultaneous failure across applications, monitoring, authentication, communication and security visibility begins | 164.308(a)(7)(i): Contingency Plan; 164.312(e)(1): Transmission Security | Estimated $75,000/hour: all systems affected simultaneously |
| 4 hours | Clinical systems, monitoring, authentication, communication and security visibility fail simultaneously; downtime procedures activated hospital-wide | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; 164.312(e)(1): Transmission Security; Joint Commission emergency management expectations | Estimated $75,000/hour; hospital-wide operational paralysis |
| 24 hours | Cascading failures across all clinical operations; security visibility lost; patient safety event probability rises sharply | 164.308(a)(7)(i): Contingency Plan; 164.312(e)(1): Transmission Security | Estimated $75,000/hour; significant patient safety and regulatory exposure |

**Operational Dependencies:** None; network foundation for all systems

**Downstream Failure Sequence:** Network Core loss produces simultaneous failure of Active Directory authentication, all clinical applications, backup replication traffic, PACS image movement, and the Medical Device Integration Gateway

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 2 hours

**Recovery Point Objective (RPO):** 1 hour

**Priority Tier:** Tier 1

---

### Email and Secure Messaging

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Clinical communication and alert notification shift to phone; regulatory correspondence delayed; coordination delays begin | 164.308(a)(7)(i): Contingency Plan; 164.312(e)(1): Transmission Security for secure messaging | Estimated $10,000/hour: coordination overhead increases |
| 4 hours | Alert notification delays affect escalation chains; clinical communication bridging strains; downtime coordination degrades | 164.308(a)(7)(ii)(C): Emergency Mode Operation Plan; Joint Commission expectations for downtime communication | Estimated $10,000/hour; escalation delays extend to clinical processes |
| 24 hours | Extended communication outage affects shift handoffs, regulatory correspondence and clinical coordination | 164.308(a)(7)(i): Contingency Plan; Joint Commission emergency management expectations | Estimated $10,000/hour; regulatory correspondence delays possible |

**Operational Dependencies:** Identity provider, network egress, mobile device access

**Downstream Failure Sequence:** Messaging outage forces clinical and administrative escalation onto phone channels defined in the escalation contact procedures; regulatory correspondence queues

**Maximum Tolerable Downtime (MTD):** 12 hours

**Recovery Time Objective (RTO):** 8 hours

**Recovery Point Objective (RPO):** 4 hours

**Priority Tier:** Tier 3

---

### Backup and DR Infrastructure

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | Backup catalog and restore capability unavailable; recovery cannot be initiated for any failed system even while production systems still run | 164.308(a)(7)(ii)(A): Data Backup Plan; 164.308(a)(7)(ii)(B): Disaster Recovery Plan | Estimated $20,000/hour: restore capability unavailable during outage |
| 4 hours | Any concurrent system failure during this window cannot be recovered; outage can become permanent data loss | 164.308(a)(7)(ii)(A): Data Backup Plan; 164.308(a)(7)(ii)(B): Disaster Recovery Plan | Estimated $20,000/hour; permanent data loss risk for concurrent failures |
| 24 hours | Extended recovery platform failure creates existential data loss risk; regulatory evidence chain for ePHI protection broken | 164.308(a)(7)(ii)(A): Data Backup Plan; 164.308(a)(7)(ii)(D): Testing and Revision Procedures | Estimated $20,000/hour; potential breach notification if data loss occurs |

**Operational Dependencies:** DR platform storage, isolated backup account, Active Directory access control

**Downstream Failure Sequence:** Backup infrastructure loss blocks restoration of every other system; all recoverable systems depend on backup catalog, storage access and restore tooling

**Maximum Tolerable Downtime (MTD):** 4 hours

**Recovery Time Objective (RTO):** 3 hours

**Recovery Point Objective (RPO):** 2 hours

**Priority Tier:** Tier 1

---

### Security Operations Platform

| Impact Level | Patient Safety Consequence | Regulatory Impact | Revenue Exposure |
|---|---|---|---|
| 1 hour | SIEM event collection and EDR management degrade; detection and response reduced during a period when opportunistic attack risk can rise | 164.308(a)(7)(i): Contingency Plan; 164.312(b): Audit Controls | Estimated $12,000/hour: security visibility reduced; incident response delayed |
| 4 hours | Security operations blind spot extends precisely when clinical systems in downtime are more vulnerable | 164.308(a)(7)(i): Contingency Plan; 164.312(b): Audit Controls | Estimated $12,000/hour; increased breach probability during downtime |
| 24 hours | Extended visibility loss compounds breach risk; forensic evidence incomplete; incident detection may fail entirely | 164.308(a)(7)(i): Contingency Plan; 164.312(b): Audit Controls; potential breach notification obligations | Estimated $12,000/hour; breach liability if incidents undetected |

**Operational Dependencies:** Network Core, log sources, EDR management, identity

**Downstream Failure Sequence:** Security platform loss removes detection and response capability while clinical downtime procedures expand the attack surface and opportunistic attack risk rises

**Maximum Tolerable Downtime (MTD):** 8 hours

**Recovery Time Objective (RTO):** 6 hours

**Recovery Point Objective (RPO):** 4 hours

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
