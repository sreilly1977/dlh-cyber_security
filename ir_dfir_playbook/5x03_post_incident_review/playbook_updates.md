<!-- Name: playbook_updates.md -->
<!-- Purpose: Close procedural gaps exposed during IR-2026-0414-01, linking each -->
<!--          change to a Gap ID from Task 2 and a specific forensic finding. -->
<!-- Author: Steve - Cybersecurity Engineer -->
<!-- Date: 19 October 2026 -->

# Playbook Updates: IR-2026-0414-01

All changes below target the `playbook_credential_exposure.yaml` playbook.
Each entry documents the section modified, the original and replacement text,
the Gap ID closed, and the forensic finding that drove the update. Changes are
sequenced to prevent recurrence of the exact failure modes observed in this
incident.

---

## Change PB-UPD-001

**Playbook:** `playbook_credential_exposure.yaml`
**Section:** `triggers`
**Gap closed:** GAP-002, GAP-003
**Finding reference:** control_effectiveness.yaml Phase 2; forensic_findings_summary.md open item 2

**Before:**

```yaml
triggers:
  - Alert: credential submitted to external domain (phishing confirmation)
  - Alert: brute-force authentication attempts on account
  - Alert: password reset request from unusual location
```

**After:**

```yaml
triggers:
  - Alert: credential submitted to external domain (phishing confirmation)
  - Alert: brute-force authentication attempts on account
  - Alert: password reset request from unusual location
  - Alert: VPN authentication from country not seen for this account in the prior 30 days
  - Alert: impossible-travel detected on account (two logins from geographically inconsistent IPs within 2 hours)
  - Alert: sign-in risk medium-or-higher from Azure AD Identity Protection (do not wait for manual triage)
```

**Reason:** The incident entry point was a foreign-IP VPN login from 45.63.9.88 (RU)
at 2026-04-13T18:14:41Z that matched no existing trigger. Azure AD had generated
risk signals at that moment, but the playbook did not instruct the analyst to
monitor for platform-computed risk independently, and the conditional access
compliant-device rule suppressed the signals before the analyst ever saw them.
Adding geographic anomalies as autonomous triggers ensures the playbook activates
even when the signal suppression layer fails.

---

## Change PB-UPD-002

**Playbook:** `playbook_credential_exposure.yaml`
**Section:** `response.scope_expansion_checklist`
**Gap closed:** GAP-011
**Finding reference:** forensic_findings_summary.md AD-LOG-01, ART-003-M01; control_effectiveness.yaml Phase 6

**Before:**

```yaml
scope_expansion_checklist:
  - Review affected workstation's session history for the last 24 hours
  - Notify the endpoint owner and collect additional logs if warranted
  - Escalate to the SOC manager for additional guidance
```

**After:**

```yaml
scope_expansion_checklist:
  - Review affected workstation's session history for the last 24 hours
  - Query Active Directory for Kerberos ticket grants issued by the compromised account
    in the same window and enumerate all destination hosts
  - Check all hosts where the compromised account logged on in the prior 30 days,
    regardless of whether a successful login is still active
  - Identify all file servers or data repositories the account accessed during
    the session window and enumerate accessible shares
  - Expand containment to newly identified hosts before concluding initial scope
  - Confirm whether clinical or PHI-handling systems appear in the expanded scope
    (see HIPAA four-factor assessment node below)
  - Notify the endpoint owner and collect additional logs if warranted
  - Escalate to the SOC manager for additional guidance
```

**Reason:** Lateral movement via Kerberos pass-the-ticket allowed the adversary to
reach LIS-WSIDE-01 and read 14 PHI report PDFs from share LIS_REPORTS$ (AD-LOG-01).
The original playbook had no structured step for expanding containment when
ticket reuse surfaces, so the blast radius remained confined to the initial
workstation (WST-WS-031) while the attack progressed to a second host (WST-WS-017)
and then to the clinical file server. The new checklist forces enumeration of
all hosts touched via Kerberos before containment is declared complete.

---

## Change PB-UPD-003

**Playbook:** `playbook_credential_exposure.yaml`
**Section:** `response.credential_remediation_steps`
**Gap closed:** GAP-009, GAP-010
**Finding reference:** forensic_findings_summary.md ART-002-M04 (NTLM hash in lsass); control_effectiveness.yaml Phase 5

**Before:**

```yaml
credential_remediation_steps:
  - Reset password for the compromised account immediately
  - Invalidate active sessions for the compromised account
  - Review MFA registration and revoke tokens if necessary
  - Monitor the account for suspicious activity over the next 30 days
```

**After:**

```yaml
credential_remediation_steps:
  - Reset password for the compromised account immediately
  - Invalidate active sessions for the compromised account
  - If LSASS memory extraction or Kerberos ticket theft is confirmed,
    perform krbtgt double-reset within 24 hours:
      - First krbtgt password reset
      - Wait 24 hours to allow all tickets issued under the first secret
        to expire naturally
      - Second krbtgt password reset
      - Force GPO replication across all domain controllers
  - Review MFA registration and revoke tokens if necessary
  - Monitor the account for suspicious activity over the next 30 days
  - Enable Credential Guard and RunAsPPL on all hosts in the affected VLAN
    to prevent repeat LSASS extraction (link to HRD-004 hardening task)
```

**Reason:** NTLM hash material for `dmarsh` was extracted from lsass at memory
capture (ART-002-M04), enabling the subsequent lateral movement to WST-WS-017.
The original playbook only instructed a user-account password reset, which does
nothing to invalidate forged Kerberos tickets or tickets granted under the
compromised hash. The krbtgt double-reset sequence is required to rotate the
domain authentication secret and force all previously-issued tickets to become
invalid. Without this step, an attacker holding a forged TGT retains access
indefinitely.

---

## Change PB-UPD-004

**Playbook:** `playbook_credential_exposure.yaml`
**Section:** `decision_nodes.phi_assessment_node` (new node inserted after scope expansion)
**Gap closed:** GAP-012
**Finding reference:** forensic_findings_summary.md open item 3; HIPAA Breach Notification Rule 45 CFR 164.402–164.414

**Before:**

```yaml
# No PHI-specific decision node existed
```

**After:**

```yaml
phi_assessment_node:
  applicable_when: clinical_system_or_phi_data_in_blast_radius
  four_factor_assessment:
    # Per HIPAA Breach Notification Rule presumption
    1. Type_and_extent_of_data: What PHI identifiers are involved?
       - Names, dates, medical record numbers, diagnosis codes
    2. Unauthorized_person_who_received_PHI: Did the data leave the organisation?
       - Egress volume analysis required; check DLP logs for staged files
    3. Whether_PHI_was_actually_viewed_acquired: Can you prove access or exfil?
       - File access auditing on the share; review DLP egress inspection results
    4. Extent_to_which_risk_is_mitigated: Has the attacker been fully contained?
       - Confirm no additional hosts remain compromised; validate C2 channels blocked

  decision_tree:
    - If factors 2 OR 3 indicate possible acquisition without proven mitigation:
        - Trigger breach notification pathway
        - Notify HIPAA Privacy Officer immediately
        - Begin documentation for 60-day HHS OCR notice deadline
        - Prepare individual notification letters (minimum 500 individuals requires state AG and media notices)
    - If all four factors support low probability of compromise:
        - Document the determination with evidence trail
        - Still notify HIPAA Privacy Officer for secondary review
        - Retain documentation for six years minimum

  mandatory_outputs:
    - Written PHI exposure assessment signed by HIPAA Privacy Officer
    - List of all affected individuals with contact information (if notification required)
    - Timeline of discovery, containment, and assessment completion
```

**Reason:** The incident accessed PHI report PDFs for 14 patients (AD-LOG-01),
but the forensic summary recorded data access as confirmed and data transfer as
unconfirmed pending DLP log review (open investigative item 3). The original
playbook had no branch for clinical-system involvement, so the HIPAA breach
notification obligation was not automatically raised as a decision point. This
change inserts the mandatory four-factor assessment prescribed by 45 CFR
164.402–164.414 and forces the documentation trail before any closure decision
is made. Without this node, the organisation risks late notification penalties
if the DLP review later confirms exfiltration.

---

## Validation Checklist for Updated Playbook

| Item | Test | Expected result |
|---|---|---|
| PB-UPD-001 triggers | Simulate VPN login from a non-trusted country for a test account | Playbook activation fires within 15 minutes, no Azure AD risk suppression |
| PB-UPD-002 scope expansion | Execute simulated lateral movement via Kerberos in lab environment | Checklist enumerates all touched hosts before containment is declared |
| PB-UPD-003 krbtgt reset | Document krbtgt double-reset procedure with domain controller owners | Procedure executed and verified within 24-hour SLA after credential exposure confirmed |
| PB-UPD-004 PHI assessment | Conduct tabletop with clinical system access scenario | HIPAA Privacy Officer notified; four-factor assessment documented |

---

---

## Sign-Off

| Role | Name | Title | Date |
|------|------|-------|------|
| Playbook Owner / IR Commander | James Chen | SOC Lead | Pending |
| HIPAA breach-reportability authority | Helena Reyes | General Counsel, Legal Liaison | Pending |
| Executive Sponsor | Dr. Patricia Morales | CISO | Pending |

**Effective date:** Upon sign-off by all roles above. Previous version archived
with commit hash reference for audit trail.

**Training requirement:** All Tier 1 and Tier 2 analysts must complete updated
playbook training within two weeks of effective date; competency verified via
quarterly tabletop exercises using the validation scenarios listed above.
