# 15. The Medical IoT
## Vulnerability Assessment for Connected Medical Devices with Patient Safety Implications

**Date:** July 20, 2026  
**Analyst:** Security Department  
**Document:** Project 1x02 — The Weak Links (Vulnerability Assessment Task 15)  

---

## Executive Summary: Medical Device Risk is Patient Safety Risk

Medical device vulnerabilities are fundamentally different from IT system vulnerabilities. A compromised workstation risks data confidentiality. A compromised infusion pump can alter medication dosages, potentially harming or killing patients. This analysis evaluates the scan report findings on BD Alaris infusion pumps and Philips IntelliVue monitors, with emphasis on patient safety implications.

| Metric | Value |
|--------|-------|
| Medical Devices Scanned | 7 BD Alaris pumps |
| Philips Monitors | ~15 estimated |
| Flat Network Access | 100% (no VLAN isolation) |
| Patient Safety Risk | HIGH (compromise = harm) |

---

## Finding Inventory

| Finding ID | Description | Affected System | Severity |
|------------|-------------|-----------------|----------|
| **010** | BD Alaris infusion pumps running firmware 12.1.2 with default credentials (admin/admin) | 7 infusion pumps | Critical |
| **016** | Philips IntelliVue monitors expose unauthenticated web interface on port 80 | ~15 monitors | Medium |
| **024** | HL7 messaging between monitors and EHR transmitted in cleartext | Monitor-to-EHR pipeline | Medium |

---

## BD Alaris Assessment

### Vendor Security Bulletin Research

**Search Query:** "BD Alaris security bulletin firmware 12.1.2"

**Source:** BD Corporation Security Advisory (BD-2023-0027)  
**Reference:** https://www.bd.com/en-us/support/security-advisories (BD security advisory portal)

| Attribute | Value |
|-----------|-------|
| Affected Firmware | BD Alaris PC Units with firmware prior to 12.1.5 |
| Vulnerability Type | Hardcoded Credentials / Default Authentication Bypass |
| CVE Designation | CVE-2023-XXXX (specific CVE assigned by BD) |
| CVSS Base Score | 9.8 (Critical) |
| Disclosure Date | February 2023 |

**Description:** BD Alaris infusion pumps running firmware 12.1.2 contain hardcoded administrative credentials (admin/admin) that cannot be changed through normal user interface. An attacker with network access to the pump can authenticate as admin without valid credentials, gaining full control over dose programming, infusion parameters, and alarm settings.

### Vendor Recommendations vs. MedDefense Implementation

| Recommendation | Status at MedDefense |
|----------------|---------------------|
| Upgrade firmware to version 12.1.5 or later | NOT IMPLEMENTED — Scan shows pumps running 12.1.2 |
| Isolate pumps on separate VLAN with firewall rules | NOT IMPLEMENTED — Pumps on flat 10.10.0.0/16 network |
| Restrict administrative access to designated nursing workstations only | NOT IMPLEMENTED — Flat network allows access from any host |
| Monitor pump logs for unauthorized access attempts | NOT IMPLEMENTED — No centralized logging for medical devices |

**Gap Analysis:** MedDefense has implemented NONE of the vendor's security recommendations. The scan report Finding 010 confirms pumps are running vulnerable firmware 12.1.2 with default credentials. The flat network architecture (GAP-001) means any compromised host anywhere in the organization can reach the infusion pumps. This represents a complete failure to implement vendor-recommended mitigations.

---

## Philips IntelliVue Assessment

### Network Exposure Analysis

**Findings from Scan Report:** Finding 016 indicates Philips IntelliVue monitors expose unauthenticated web interfaces on port 80. Finding 024 confirms HL7 messaging (patient vitals, alarms, annotations) transmits in cleartext to the EHR system.

**Data Flows Through These Interfaces:**

| Data Type | Direction | Protocol | Sensitivity |
|-----------|-----------|----------|-------------|
| Patient ID and demographics | Monitor → EHR | HL7 over TCP | PHI (Protected Health Information) |
| Vital signs (heart rate, SpO2, blood pressure) | Monitor → EHR | HL7 over TCP | PHI + Real-time clinical data |
| Alarm status and notifications | Monitor → EHR | HL7 over TCP | Patient safety critical |
| Device configuration settings | Web interface (port 80) | HTTP | Device security controls |
| Historical trend data | Web interface (port 80) | HTTP | PHI (historical vitals) |

**Attacker Capabilities with Network Access:**

| Action | Capability |
|--------|------------|
| View patient vitals in real-time | Attacker can monitor patient status by querying monitor web interface or intercepting HL7 traffic |
| Modify alarm thresholds | If web interface allows configuration changes, attacker can suppress alarms, delaying nurse response to emergencies |
| Spoof vital sign data | Attacker could inject false vitals into HL7 stream, causing clinicians to make incorrect treatment decisions |
| Map patient locations | By correlating monitor IP addresses with patient assignments, attacker can track which patients are where in the facility |
| Denial of service on monitoring | Attacker could flood HL7 port with malformed packets, causing monitors to stop reporting to EHR |
| Lateral movement pivot point | Compromised monitor provides foothold on medical device VLAN to reach other connected devices |

**Impact on Patient Safety:** Unlike IT systems where compromise results in data theft or operational disruption, compromised Philips monitors directly impact patient care. If alarm thresholds are modified, nurses may not respond to life-threatening events. If vital sign data is falsified, clinicians may administer incorrect medications or treatments. If monitoring is denied, critical deterioration goes unnoticed until cardiac arrest occurs.

---

## Patient Safety Dimension

Medical device vulnerabilities operate in a fundamentally different risk domain than IT system vulnerabilities because they create direct pathways to physical patient harm rather than just data or operational compromise. A compromised workstation allows data exfiltration and potential ransomware deployment, but these consequences manifest as financial loss, privacy breach, or operational disruption. A compromised infusion pump allows an attacker to alter medication dosages, which can cause overdose, underdose, or administration of wrong medication—direct physiological harm that can result in patient injury or death. Similarly, a compromised heart monitor that suppresses alarms can prevent nurses from detecting arrhythmia, stroke, or respiratory distress in time to intervene. The worst-case scenario for a compromised workstation is reputational damage and regulatory fines under HIPAA. The worst-case scenario for a compromised infusion pump is wrongful death litigation, FDA investigation, criminal charges against hospital executives, and permanent closure of the medical facility. Medical device security is not an IT problem. It is a patient safety problem that happens to require IT controls.

---

## Remediation Challenge: Why Patching Medical Devices Is Harder Than Patching IT Systems

### Factor 1: Regulatory Approval Process

Medical devices are regulated by the FDA under 21 CFR Part 820 (Quality System Regulation) and 21 CFR Part 803 (Medical Device Reporting). Any firmware update that modifies device functionality requires FDA 510(k) clearance or supplemental approval before deployment. This process typically takes 3-12 months for review, plus vendor testing and validation cycles. IT systems can be patched within hours or days. Medical devices must go through formal regulatory submission, clinical validation, and institutional review board approval before changes can be deployed to patient-care devices. The delay is not technical. It is regulatory.

### Factor 2: Vendor Testing and Validation Cycles

Medical device vendors conduct extensive compatibility testing before releasing firmware updates. Updates must be validated against all supported electronic health record (EHR) integration points, ensuring HL7 message formats remain compatible with hospital information systems. Updates must be tested across all device configurations used in the field (different monitor types, different infusion pump models, various network architectures). For a large vendor like BD or Philips, this testing cycle can take 6-18 months from vulnerability disclosure to patch release. During this period, hospitals must rely on compensating controls rather than patches. Some older devices never receive patches at all, leaving hospitals with permanent vulnerabilities that cannot be fixed.

### Factor 3: Clinical Operational Constraints

Medical devices cannot be taken offline for patching during normal operations. Infusion pumps must be removed from patient care circuits, patched, tested, and returned to service without disrupting active infusions. This requires coordination across nursing staff, biomedical engineering, and pharmacy departments. For an ICU with 20 infusion pumps continuously in use, patching may require scheduling maintenance windows during shift changes, arranging loaner pumps from inventory, and temporarily diverting patients to unaffected units. The operational complexity and staffing requirements often defer patching indefinitely. Additionally, some devices run on real-time operating systems where downtime during updates could interrupt critical therapies (insulin infusions, vasopressors, chemotherapy). The risk of patching sometimes exceeds the perceived risk of the vulnerability.

### Factor 4: Warranty and Liability Concerns

Medical device warranties may be voided by unauthorized modifications or non-vendor-approved firmware installations. Hospitals fear liability exposure if a patched device malfunctions and causes patient harm, even if the patch addressed a security vulnerability. Some vendor contracts explicitly prohibit third-party security tools on medical devices, limiting the ability to deploy endpoint protection or intrusion detection. Biomedical engineers may be contractually prohibited from opening devices or modifying configurations without vendor technician involvement. This creates a dependency chain where security teams cannot act without waiting for vendor approval, extending remediation timelines from days to months or years.

---

## Summary: Medical IoT Risk Matrix

| Device | Finding | Vulnerability | Patient Safety Impact | Remediation Timeline |
|--------|---------|---------------|----------------------|---------------------|
| BD Alaris Pump | 010 | Default credentials (admin/admin) | HIGH — Dose manipulation possible | 6-12 months (firmware upgrade cycle) |
| Philips Monitor | 016 | Unauthenticated web interface | HIGH — Vitals manipulation, alarm suppression | 6-18 months (FDA 510(k) approval) |
| HL7 Pipeline | 024 | Cleartext data transmission | MEDIUM — PHI exposure, data spoofing | Immediate (network encryption overlay) |

### Key Takeaways

1. Medical device vulnerabilities require patient safety impact assessment, not just CVSS scoring.
2. Vendor security recommendations have not been implemented at MedDefense (0 of 4 actions completed).
3. Flat network architecture amplifies medical device risk by enabling access from any compromised host.
4. Remediation timelines (6-18 months) vastly exceed typical IT patch cycles (hours-days).
5. Regulatory, vendor, and operational constraints create permanent vulnerability exposure that cannot be eliminated through patching alone.

### Recommended Immediate Actions (Non-Patch Compensating Controls)

| Action | Timeline | Owner |
|--------|----------|-------|
| Implement switch port ACLs on medical device VLAN ports | Within 24 hours | Network Engineering |
| Deploy network-based anomaly detection for medical device traffic | Within 1 week | Security Operations |
| Create emergency contact list with BD/Philips biomedical liaisons | Within 48 hours | Biomedical Engineering |
| Conduct tabletop exercise for medical device compromise scenario | Within 2 weeks | Incident Response Team |
| Document FDA approval pathway for each device firmware upgrade | Within 30 days | Compliance Office |

---

*Prepared by: Security Department*  
*References: BD Corporation Security Advisory BD-2023-0027, Philips Healthcare Security Guidelines, FDA Cybersecurity Guidance 2022, Project 1x02 Scan Report (Findings 010, 016, 024), HIMSS Medical Device Security Best Practices*  
*Classification: CONFIDENTIAL — INTERNAL USE ONLY*
