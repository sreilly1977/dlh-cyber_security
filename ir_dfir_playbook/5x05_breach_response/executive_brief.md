# Executive Brief — Cybersecurity Incident at MedDefense

**Prepared for:** Dr. Morales, Chief Executive — for presentation to the Board
**Prepared by:** Incident Response, on behalf of the incident commander
**Date:** Monday, 2026-04-20, 07:00
**Status as of:** Sunday night, 23:00

## What happened

On Thursday evening, April 17, a fraudulent email convinced a member of our
staff to open an infected document. Criminals used that opening to install
unauthorized software on her computer and to steal her sign-in credentials.
Using those stolen credentials, the criminals entered our systems Thursday
night and remained until Sunday evening, when we discovered them and shut
them out. *(Findings MEM-001, MEM-002, FS-002)*

## What the criminals took

On Saturday, April 19, between 2:14 and 2:41 a.m., the criminals opened
1,847 patient files on our clinical documentation file server. These were
lab results and clinical notes. They read only; they did not alter or delete
any patient record. Twenty-one seconds after opening the first file, the
criminals transferred 2.4 megabytes of data off that server to their own
systems. We must therefore assume those patient files have been copied and
are in criminal hands. *(Findings FS-001, FS-002, PRX-003)*

## What we stopped

The criminals had placed software on four computers intended to lock up our
systems for ransom. It had not yet been activated. As of Sunday night, all
affected computers and servers are disconnected from the network, the
criminals' ability to reach our systems or use the stolen password is
confirmed severed, and complete forensic copies of every affected machine
have been preserved for evidence and for law enforcement. No patient care
was interrupted; the emergency department operated on standard downtime
procedures during containment, and staffed operations continue normally.
*(Findings SYS-003, containment record STEPs 01–09)*

## Regulatory position

Our legal counsel is being briefed tonight; the evidence indicates this
meets the federal definition of a reportable health-information breach, and
we are proceeding on the basis that notification obligations apply, with
the formal determination to be confirmed by counsel this morning.

## What happens next

Eradication and rebuilding of the affected machines begins today. We will
identify the specific patients whose files were taken, so that notification
letters can be prepared within the legally required window. Criminal referral
and, if appropriate, engagement with federal authorities will be assessed
with counsel this week. A full after-action review with permanent fixes —
including email, credential, and monitoring improvements this incident
exposed — will follow recovery.

**Next update:** daily at 08:00 to the executive team, immediate escalation
for any material change, and a full status report to the Board within 72
hours.

---
*One page bound. Every statement above is supported by the forensic record
(IR-2026-0420-01 findings MEM-001, MEM-002, MEM-005, FS-001, FS-002, FS-003,
PRX-002, PRX-003, SYS-001, SYS-003; containment_execution.md STEPs 01–09).*
