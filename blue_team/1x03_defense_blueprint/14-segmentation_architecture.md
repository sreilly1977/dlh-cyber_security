# 14. The Segmentation Architecture

## Goal

Design a network segmentation plan that transforms MedDefense's flat network into a defensible architecture.

## Context

The flat network appeared in every kill chain built in 1x01. It amplified every vulnerability in 1x02. It is the single architectural weakness whose resolution has the greatest cascading effect on MedDefense's risk posture. Now you design the fix.

---

## PART 1 - ZONE DEFINITIONS

### Zone 1: Server Zone (CORE-SERVER-VLAN)

| Attribute | Specification |
|-----------|---------------|
| **Purpose** | Hosts all critical backend infrastructure supporting EHR, billing, and enterprise services |
| **IP Range** | 10.10.1.0/24 |
| **Systems Included** | EHR application servers, billing-srv-01, Active Directory domain controllers, file servers, SQL database servers, backup repositories, print servers |
| **Allowed Outbound Connections** | Internet (HTTPS 443 only for updates and cloud services), Management Zone (all ports), Monitoring/SIEM systems (syslog 514 UDP, SNMP 161 UDP) |
| **Allowed Inbound Connections** | Clinical Workstation Zone (EHR app port 8443, SQL port 1433 only), Billing Workstations (port 443), Management Zone (all administrative ports), Server-to-server within zone (all ports) |
| **Security Notes** | No direct internet access except whitelisted update endpoints. No inbound from Guest/IoT Zone. No RDP permitted from any zone except Management Zone via jump box. |

---

### Zone 2: Clinical Workstation Zone (CLINICAL-WS-VLAN)

| Attribute | Specification |
|-----------|---------------|
| **Purpose** | Houses nurse station workstations, physician desktops, and mobile carts used for patient care |
| **IP Range** | 10.10.2.0/24 |
| **Systems Included** | Nurse station computers at all floors, physician workstations in exam rooms, medication administration carts, bedside charting terminals, order entry workstations |
| **Allowed Outbound Connections** | Server Zone (EHR port 8443, SQL port 1433 only), Medical Device Zone (PACS retrieval port 104 DICOM), Internet (HTTPS 443 for clinical references), Email Gateway (SMTP 587) |
| **Allowed Inbound Connections** | Server Zone (initiated connections only for session keepalives), Management Zone (for updates and security scanning), Medical Device Zone (DICOM push responses only) |
| **Security Notes** | No RDP or SMB inbound from any external zone. No internet HTTP (80) allowed. USB ports disabled per AUP Section 4.1. Cannot initiate connections to Billing Zone directly—must route through Server Zone. |

---

### Zone 3: Medical Device Zone (MED-DEVICE-VLAN)

| Attribute | Specification |
|-----------|---------------|
| **Purpose** | Isolates vulnerable medical devices with legacy OS and limited patching capability |
| **IP Range** | 10.10.3.0/24 |
| **Systems Included** | MRI machines, infusion pumps, patient monitors, ventilators, PACS imaging servers, lab analyzers, anesthesia workstations, radiology workstations |
| **Allowed Outbound Connections** | Server Zone (to PACS archive only on DICOM 104), SIEM/Syslog collectors (port 514 UDP), Management Zone (for vendor remote support sessions via pre-approved timeslot) |
| **Allowed Inbound Connections** | Medical Device Zone (device-to-device for modality-to-PACS transfer), Clinical Workstation Zone (DICOM query/retrieve responses), Server Zone (PACS archive writes only) |
| **Security Notes** | Devices may not initiate connections to any zone outside this zone and Server Zone PACS archive. All outbound traffic logged for anomaly detection. Vendor remote access requires CISO approval, time-limited session through Management Zone jump box, not direct device access. |

---

### Zone 4: Management Zone (ADMIN-MGMT-VLAN)

| Attribute | Specification |
|-----------|---------------|
| **Purpose** | Houses IT administrative workstations, security tools, and privileged access infrastructure |
| **IP Range** | 10.10.4.0/24 |
| **Systems Included** | IT administrator laptops/desktops, jump box servers, SIEM platform, EDR management console, vulnerability scanner, patch management server, PAM vault, MFA servers, domain controller administrators' workstations |
| **Allowed Outbound Connections** | ALL other zones (all required administrative ports for management), Internet (HTTPS 443 for updates, vendor support portals), Cloud management APIs |
| **Allowed Inbound Connections** | Server Zone (status beacons and log forwarding only), Monitoring systems (SNMP traps), Jump box connection initiations from remote users via VPN |
| **Security Notes** | This zone is the most restricted by inbound access. No user workstations allowed to initiate connections to this zone except through the designated VPN + jump box architecture. All sessions recorded via PAM. Requires MFA authentication to access any system in this zone. Administrators must use dedicated admin accounts—not personal user accounts—for any Management Zone access. |

---

### Zone 5: Guest / IoT Zone (GUEST-IOT-VLAN)

| Attribute | Specification |
|-----------|---------------|
| **Purpose** | Contains all non-clinical, unmanaged, or third-party connected devices |
| **IP Range** | 10.10.5.0/24 |
| **Systems Included** | Visitor Wi-Fi access points, lobby kiosks, building HVAC controllers, elevator systems, cafeteria point-of-sale, visitor badge printers, conference room AV systems, contractor laptops during approved access periods, vendor remote support gateways |
| **Allowed Outbound Connections** | Internet (HTTP/HTTPS only, no other protocols), DNS (UDP 53), Time/NTP servers |
| **Allowed Inbound Connections** | NONE from any other zone. This is a sink-only zone with no inbound initiation permitted from Corporate zones. |
| **Security Notes** | Strictest isolation in the architecture. No device in this zone may ever communicate with Server, Clinical, Medical Device, or Management zones. Contractor laptops connecting through approved vendor portal are isolated here even when performing authorized work—they may access the Management Zone jump box only, which then controls their access to target systems. This zone has the highest monitoring for command-and-control traffic since it contains the most unpredictable device types. |

---

## PART 2 - FIREWALL RULES (PSEUDOCODE FORMAT)

```
Rule 1: CLINICAL-WS → SERVER : 1433/TCP : ALLOW Description: Permit clinical workstations to query EHR SQL database. Blocks all other database ports to prevent unauthorized data access.

Rule 2: CLINICAL-WS → SERVER : 8443/TCP : ALLOW Description: Permit clinical workstations to connect to EHR application server over HTTPS. Uses application-layer gateway to validate EHR protocol.

Rule 3: SERVER → MANAGEMENT : ALL/TCP : ALLOW Description: Permit management tools to poll servers for status, deploy patches, and collect logs. All inbound traffic to Management Zone still blocked.

Rule 4: MED-DEVICE → SERVER(PACS): 104/UDP : ALLOW Description: Permit medical devices to push images to PACS archive only. Blocks all other outbound traffic from medical device zone.

Rule 5: MANAGEMENT → MED-DEVICE : PREDEFINED-PORTS : ALLOW Description: Permit authorized IT maintenance access to medical devices during approved windows. Requires time-based ACL and CISO ticket approval.

Rule 6: ANY → GUEST-IOT : ALL : DENY Description: CRITICAL DENY - No traffic from any corporate zone may initiate connection to Guest/IoT zone. Prevents lateral movement from compromised guest devices to clinical systems.

Rule 7: GUEST-IOT → SERVER : ALL : DENY Description: CRITICAL DENY - Guest/IoT devices cannot reach any server resources. Even if an attacker compromises a kiosk or contractor laptop, they cannot pivot to EHR or billing.

Rule 8: CLINICAL-WS → GUEST-IOT : ALL : DENY Description: Block clinical workstations from reaching guest network. Prevents data exfiltration pathways where a workstation might be compromised and used to stage data to a guest device.

Rule 9: SERVER → INTERNET : EXCEPT(80,21,25,3389) : DENY Description: Servers may only reach internet on whitelisted ports (primarily HTTPS for updates). Blocks SMTP to prevent spam relay, blocks FTP and RDP to prevent command-and-control.

Rule 10: ADMIN-JUMPBOX → ANY-ZONE : ADMIN-PORTS : ALLOW WITH SESSION-LOGGING Description: Jump box is the only authorized entry point to corporate zones from external networks. All sessions are recorded and logged in PAM for forensic review.
```


### Explanation of Critical Deny Rules

**Rule 6 (ANY → GUEST-IOT : DENY):** This rule creates an asymmetrical boundary that protects against supply chain attacks and compromised vendor equipment. In 1x01 Kill Chain #2, a vendor with legitimate network access pivoted to clinical systems because there was no segmentation between vendor access and core infrastructure. This rule ensures that even if the Guest/IoT zone is fully compromised (contractor laptop infected, kiosk malware, malicious visitor device), the attacker cannot send any traffic inward to reach clinical or administrative systems.

**Rule 7 (GUEST-IOT → SERVER : DENY):** This rule prevents data exfiltration from clinical systems through the guest network. In 1x01 Kill Chain #4 (Insider Threat), a disgruntled employee attempted to exfiltrate PHI via a personal hotspot device connected to the office. While this scenario involved a cellular device, the same attack path would work if the employee compromised the guest network and used it as a staging area. This deny rule closes that pathway entirely.

---

## PART 3 - KILL CHAIN IMPACT ANALYSIS

### Primary Kill Chain Disrupted: 1x01 Kill Chain #2 (Ransomware via RDP)

| Kill Chain Step | Original Attack Path | Segmentation Disruption Point | Status After Segmentation |
|-----------------|---------------------|-------------------------------|--------------------------|
| **Step 1: Initial Access** | Attacker scans internet, finds RDP open on billing-srv-01 | RDP removed from public internet per Quick Win #1; firewall Rule 9 blocks outbound server internet access | BLOCKED — No initial foothold achievable |
| **Step 2: Establish Foothold** | Brute-force credential guessing succeeds on billing-srv-01 | Account lockout policy (Quick Win #2) + Management Zone access restrictions | MITIGATED — Even if credentials compromised, no lateral movement possible |
| **Step 3: Lateral Movement** | Attacker uses flat network to reach EHR database and file servers | Firewall Rule 1 & 2 restrict Server Zone access to clinical workstations only. Billing workstation cannot initiate SQL connections. Management Zone is unreachable without MFA + jump box. | BLOCKED — Flat network eliminated; attacker stuck in billing-srv-01 subnet |
| **Step 4: Objective Execution** | Deploy ransomware across EHR, encrypt databases, hold for ransom | EHR servers are in isolated Server Zone. Ransomware cannot propagate without lateral movement capability. Backups in Server Zone remain unreachable from billing-srv-01 | MITIGATED — Blast radius contained to billing subsystem only |
| **Step 5: Impact** | Complete EHR outage for 72 hours, clinical operations suspended, patient diversion initiated | Only billing subsystem affected. Clinical staff can continue EHR access. Ransomware does not reach backup systems or EHR application servers | REDUCED IMPACT — Estimated 80% reduction in business impact |

### Top 5 Kill Chains and Segmentation Disruption Rate

| Kill Chain | Primary Weakness Exploited | Segmentation Breaks At | Disruption Percentage |
|------------|---------------------------|------------------------|----------------------|
| **#1: Ransomware via Phishing** | Flat network enables lateral spread from infected workstation | After initial infection; attacker cannot reach EHR/SQL servers from Clinical WS | 70% (blocks Steps 3-5) |
| **#2: Ransomware via RDP (Primary)** | Public RDP exposure + flat network | At Step 1 (RDP blocked) and Step 3 (lateral movement blocked) | 90% (blocks Steps 1-3) |
| **#3: Social Engineering USB Attack** | USB malware + flat network for propagation | After initial infection; attacker cannot reach Server Zone from Clinical WS | 65% (blocks Steps 3-5) |
| **#4: Insider Threat Exfiltration** | No network egress monitoring + flat network | At data transfer point; outbound to Guest/IoT blocked by Rule 8 | 50% (detects but does not prevent initial access) |
| **#5: Supply Chain Vendor Compromise** | Vendor access to production systems | At vendor access point; vendor traffic confined to Guest/IoT Zone, jumps through Mgmt Zone only | 85% (blocks Step 2 onward) |

### Overall Segmentation Effectiveness

**Percentage of Top 5 Kill Chains Disrupted:** Approximately **72% of all attack steps in the top 5 kill chains would fail due to segmentation alone.**

This calculation considers that segmentation does not block initial access vectors (phishing emails, USB drops, social engineering) but it fundamentally breaks the lateral movement and data exfiltration phases that transform an initial compromise into a full-blown incident. Without segmentation, MedDefense operates as a single trust boundary—once breached anywhere, the entire network is accessible. With segmentation, each zone represents a separate trust boundary requiring its own breach path.

### Cascading Risk Reduction Benefits

1. **RISK-001 (Ransomware):** Risk score reduced from 20 (Critical) to 10 (Medium) because lateral movement and backup access are blocked.

2. **RISK-002 (Vendor Breach):** Risk score reduced from 15 (High) to 6 (Low) because vendor access is confined to Guest/IoT Zone and jump box architecture.

3. **RISK-005 (HIPAA Violation):** Risk score reduced from 16 (Critical) to 9 (Medium) because data exfiltration pathways are monitored and constrained.

4. **RISK-006 (Medical Device Compromise):** Risk score reduced from 10 (Medium) to 4 (Low) because devices cannot communicate outside their zone except to PACS archive.

5. **RISK-009 (RDP Ransomware):** Risk score reduced from 16 (Critical) to 6 (Low) because public RDP exposure is eliminated and Management Zone is isolated.

---

## Implementation Timeline

| Week | Milestone | Owner | Success Criteria |
|------|-----------|-------|------------------|
| **Week 1-2** | Deploy perimeter firewall hardware, define initial VLANs on core switch | CTO | New firewall online; 5 VLANs configured; existing connectivity maintained |
| **Week 3-4** | Move billing-srv-01 to Server Zone; implement Quick Win #1 (disable public RDP) | CTO | RDP port 3389 closed externally; billing staff validated on VPN |
| **Week 5-6** | Relocate all clinical workstations to Clinical WS Zone; deploy firewall Rules 1-3 | CISO + CTO | Clinical staff can access EHR; no unauthorized inter-zone traffic observed |
| **Week 7-8** | Isolate medical devices to MED-DEVICE zone; implement PACS-only routing | CTO + CMIO | Medical devices operational; PACS retrieval working; no other outbound traffic |
| **Week 9-10** | Configure Management Zone with jump box architecture; migrate admin workstations | CISO | All admin access through PAM; session logging functional; MFA enforced |
| **Week 11-12** | Activate Guest/IoT Zone; move all contractor/vendor access; implement Rules 6-10 | CTO | Guest network operational; no inbound/outbound violations detected in logs |
| **Week 13+** | Validation testing, documentation, ongoing review | CISO | Segmentation audit passed; false positive tuning complete; quarterly review scheduled |

### Contingency Plan

If segmentation causes unexpected service interruption:
- Revert firewall rules for affected zone within 1 hour (document rollback)
- Contact affected application owner to identify legitimate traffic pattern
- Add exception rule with logging enabled for monitoring
- Return to segmentation plan with adjusted rule after root cause analysis

All changes documented in change management system with emergency contact escalation path to CISO and CTO for immediate rollback authorization.
