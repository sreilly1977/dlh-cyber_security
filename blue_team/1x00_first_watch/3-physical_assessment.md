# Physical Security Walk-Through: MedDefense Central
## Structured Risk Decomposition

---

### Observation 1: Server Room Access

**Vulnerability:** Server room access is controlled by the same generic badge issued to all employees (~2,000 people, including non-clinical and custodial staff). There is no camera surveillance on the door and no visitor log. The room is on the ground floor accessible from a public cafeteria corridor, meaning anyone with a badge, or anyone tailgating through the door, can enter the server room unobserved.

**Threat:** A disgruntled employee, contractor, or social engineering adversary gains physical access to the server room undetected. They attach a rogue device (USB rubber ducky, network tap, Kali live USB) to a server, clone a hard drive, or directly interact with console ports on the domain controllers, backup server, or database server. With no camera and no log, the access is unattributable after the fact.

**Impact:**
- **Integrity:** Attacker can modify server configurations, plant malware, alter backups, or tamper with domain controller settings to create persistent backdoor accounts
- **Confidentiality:** Physical access enables disk cloning, memory extraction, or direct database queries, exposing PHI, credentials, and encryption keys stored on disk or in memory
- **Availability:** Attacker can physically damage equipment, pull drives, disconnect network cables, or power off servers, causing immediate clinical service disruption

**Severity: Critical**: All CIA pillars are compromised through a single access point that is protected by a credential shared with approximately 2,000 people and has zero audit trail. This is the organization's most concentrated asset in its least-protected physical location.

---

### Observation 2: Network Closet

**Vulnerability:** The second-floor network closet containing switches and patch panels has no lock, the door is physically ajar, and administrative credentials for switch management are taped to the wall in plain text. Anyone walking the second-floor corridor can enter the closet, and anyone who enters has immediate access to privileged network infrastructure credentials without any effort.

**Threat:** An opportunistic or targeted adversary, potentially a visitor, vendor, or employee with no IT role, enters the unlocked closet, photographs or notes the credentials, and later accesses the switch management interface remotely. Alternatively, they connect a personal device directly to a switch port or patch panel, gaining direct network access at the infrastructure layer. The laminated credential sheet also means anyone who has ever entered this closet, cleaning staff, maintenance workers, delivery personnel, may already have these credentials.

**Impact:**
- **Integrity:** With switch admin access, an attacker can reconfigure VLANs (if any existed), redirect traffic, disable port security, mirror traffic to a capture port, or alter network topology to facilitate man-in-the-middle attacks
- **Confidentiality:** Switch-level access enables traffic mirroring/spanning to capture all network traffic on affected segments, including PHI transmitted between workstations, servers, and medical devices on the flat 10.10.0.0/16 network
- **Availability:** Attacker can disable switch ports, reconfigure spanning tree, or shut down the switch entirely, causing network outages to entire floors of the hospital

**Severity: Critical**: The combination of physical access (unlocked, ajar) and credential exposure (plaintext, prominently displayed) means the network infrastructure is effectively uncontrolled. The flat network topology documented by Marcus amplifies the blast radius of any switch-level compromise to the entire organization.

---

### Observation 3: Nurse Station

**Vulnerability:** A workstation is logged into the EHR system with a patient's record visible on screen, unattended for at least 15 minutes. The posted signage instructing staff not to log out between shifts creates an organizational culture that normalizes this behavior. No automatic screen lock policy appears to be enforced (session remained active after 15+ minutes of idle time).

**Threat:** A visitor, patient, contractor, or unauthorized staff member approaches the unattended workstation during the idle window and views, photographs, or modifies the patient's record. They could also navigate to other patient records, export data to a USB device, print records, or send data via email from the authenticated session. Because the workstation is logged in under a legitimate clinical credential, all actions are attributed to that clinician, not the actual perpetrator.

**Threat Actor Variant:** A targeted adversary (insider or outsider) could use this recurring pattern to systematically harvest patient data over multiple visits, each time using a different clinician's session to obscure the pattern.

**Impact:**
- **Confidentiality:** Direct unauthorized access to patient PHI, the specific record on screen plus any additional records accessible through the authenticated session. This constitutes a reportable HIPAA breach.
- **Integrity:** An attacker could modify medication orders, allergy information, or clinical notes in the patient's record, creating a patient safety risk with potentially lethal consequences. Modifications would appear to originate from the legitimate clinician.

**Severity: High**: While the physical access window is limited compared to the server room, the combination of unattended PHI, normalized culture of non-logout, apparent absence of screen lock policy, and attribution ambiguity makes this a routine, repeating exposure with direct patient safety implications.

---

### Observation 4: Medical IoT

**Vulnerability:** A connected vital signs monitor (Philips IntelliVue, firmware v2.1.3, last updated 2019) displays its IP address (10.10.3.47) and firmware version on the diagnostic screen — accessible to anyone in the patient room. The device sits on the same IP range (10.10.0.0/16) as clinical workstations, servers, and all other networked systems. Firmware has not been updated in approximately 5 years, meaning known vulnerabilities patched in subsequent firmware releases remain exploitable.

**Threat:** An adversary with any network access on the flat 10.10.0.0/16 segment — whether through the compromised billing server, the unlocked network closet, an infected USB, or a rogue wireless device — can directly reach this medical device at 10.10.3.47. They can exploit known firmware vulnerabilities to intercept patient vitals data, alter displayed readings, or potentially disrupt device functionality. The exposed firmware version on-screen serves as reconnaissance, an attacker in the room can determine exactly which exploits apply without scanning.

**Threat Actor Variant:** A patient or visitor with a smartphone on the guest WiFi (if isolation is not properly configured) could potentially reach the medical device network and enumerate these devices.

**Impact:**
- **Confidentiality:** Patient vitals and diagnostic data can be intercepted or exfiltrated, constituting PHI exposure
- **Integrity:** Falsified vital signs readings could lead to inappropriate clinical interventions, administering medication based on fabricated hypertension, or failing to respond to a cardiac event because the monitor was altered to show normal readings
- **Availability:** Device can be crashed or rendered non-functional, losing real-time patient monitoring capability

**Severity: Critical**: The convergence of unpatched medical firmware, flat network topology, and publicly displayed device information creates a direct path from any network compromise to patient safety impact. This is not theoretical, the parameters displayed on screen are an attacker's targeting information.

---

### Observation 5: Emergency Exit

**Vulnerability:** A fire exit door separating the public waiting area from the restricted administrative wing is propped open with a wooden wedge, defeating the physical access control boundary. A handwritten sign institutionalizes this bypass ("Please do not close, staff passage"). The open door provides direct line-of-sight and physical pathway to the IT department and the Deputy CISO's office. The wedge defeats any badge reader, alarm, or door logging that may exist on this door.

**Threat:** Any person in the public waiting area, visitors, patients, delivery drivers, or a targeted adversary posing as any of these, walks through the propped-open door into the administrative wing with no authentication, no badge, and no log entry. From there, they have physical access to the IT department, potentially including workstations, IT staff devices, documentation, and the path to James Chen's office. If IT workstations are similarly unprotected (given the organizational culture observed in Observation 3), an attacker could pivot from physical access to digital access within minutes.

**Threat Actor Variant:** A social engineer exploits the cultural norm, walking confidently through the open door carrying a clipboard or wearing a lanyard. Staff who see the person assume they belong, because the door is "supposed to be open."

**Impact:**
- **Integrity:** Physical access to IT department enables tampering with IT workstations, stealing documentation (network diagrams, credentials, asset lists), or planting devices
- **Confidentiality:** Access to IT staff workspace may expose printed credentials, network documentation,+

**Severity: High**: The door creates a direct unauthenticated path from a public area to IT infrastructure and security leadership offices. The organizational normalization ("staff passage" sign) means this vulnerability is persistent and unlikely to self-correct. While slightly lower than the server room or network closet (less concentrated critical assets behind this specific door), the pathway it enables makes every downstream vulnerability easier to exploit.

---

## Walk-Through Summary Matrix

| # | Observation | Vulnerability Type | CIA Impact | Severity |
|---|-------------|-------------------|------------|----------|
| 1 | Server Room Access | Physical access control failure | C, I, A | **Critical** |
| 2 | Network Closet | Physical + credential exposure | C, I, A | **Critical** |
| 3 | Nurse Station | Logical access control failure + policy | C, I | **High** |
| 4 | Medical IoT | Network segmentation + unpatched firmware | C, I, A | **Critical** |
| 5 | Emergency Exit | Physical access control bypass | C, I, A | **High** |

**Pattern Observation:** Four of five findings involve physical access control failures (either broken or absent). Three of five involve organizational culture or policy that normalizes insecure behavior. This is not a technology problem — it is a governance and accountability problem. Marcus escalated these issues to Sarah Park, who deprioritized them. The systemic root cause is the authority gap between security (James) and IT operations (Sarah) documented in the org chart.
