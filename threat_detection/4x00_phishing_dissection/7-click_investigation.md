# 7-click_investigation.md

**Name:** Click Investigation

**Purpose:** Assess Diane Marsh's reported click on the Email 2 phishing link and
          define the evidence needed to determine whether compromise occurred

**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — CLICK INVESTIGATION REPORT

Subject: Diane Marsh (dmarsh@meddefense.com) / Workstation WS-NURSE-04

Evidence source: Email evidence batch (collected 2026-04-17 by Mike Torres)

Status: CONFIRMED CLICK — Compromise status UNKNOWN

No endpoint or SIEM logs were analyzed for this report. All log-based checks
below are RECOMMENDED FOLLOW-UP ACTIONS only, clearly labeled as such.

================================================================================

## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts

The following facts are established solely by the email evidence batch and the recorded click note in the footer. No additional telemetry was queried.

- **User:** Diane Marsh (dmarsh@meddefense.com), clinical staff, nursing role
- **Workstation:** WS-NURSE-04, internal IP 10.10.2.15
- **Triggering email:** E2 — "MedDefense IT Security" <noreply@meddefense-portal[.]com>, Subject: "ACTION REQUIRED: Portal re-verification needed within 24 hours" (SPF fail, DKIM none, DMARC fail)
- **Clicked URL:** hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1
- **Click timestamp:** 2026-04-14 15:02:33 CDT (per workstation NTP)
- **Email receipt time:** 2026-04-14 14:47:52 CDT — click occurred approximately 15 minutes after delivery
- **Investigation start:** 2026-04-17 ~09:15 CDT — approximately 36 hours elapsed between click and investigation
- **Related infrastructure:** Sending/harvesting IP 91.234.99.107 (mail.meddefense-portal.com); the same domain serves the mail infrastructure and the credential harvesting page

The URL structure carries the victim's username (id=dmarsh) and a per-victim session token (token=a8f3e2d1), meaning the attacker can attribute the visit to Diane individually regardless of any subsequent credential entry. The lure impersonated MedDefense IT with a fabricated 24-hour re-verification deadline and lockout threats, and the legitimate internal announcement E4 (received the following day) confirms the real password-change portal is only accessible internally — the E2 link could never have led anywhere genuine.

---

### Risk Assessment

A reported click on a credential-harvesting portal must be treated seriously even without confirmed credential entry, for the following reasons:

1. **Harvester attribution succeeded.** The URL parameters prove the attacker mapped the click to Diane Marsh specifically. The page load alone confirms to the attacker that a real, reachable nurse interacts with MedDefense-branded lures. Her address is now a validated target for re-phishing, follow-up pretexts (such as a fake helpdesk callback referencing the "verification"), and resale in targeted lists.
2. **Click does not equal submission, but exposure is binary.** There is no middle ground in the attacker's log: either credentials were submitted on the harvesting form or they were not. Since we currently cannot see the POST request (requires proxy logs), the entire window from 15:02:33 CDT onward is an unbounded exposure window. At 36 hours elapsed, any harvested credentials may already have been used against the VPN, the patient portal, or the EHR.
3. **Potential for follow-on activity.** The HC3 advisory in E8 describes possible Stage 2 deployment once credentials are validated. Even though the Email 2 raw content shows only a harvesting link (no attachments, no scripts), the landing page content itself is invisible to us from the batch — we cannot rule out drive-by techniques or a scripted redirect chain served only to the clicked session.
4. **Account sensitivity.** Diane is clinical staff. Compromised access to the EHR gateway implies potential access to Protected Health Information, which carries regulatory consequence under HIPAA and reputational consequence for MedDefense.
5. **Timing compounds impact.** The legitimate password-change window opened April 20 (per E4). Had credentials been harvested, any legitimate password change by Diane on April 20 would have cut off attacker access — but nothing forces her to have waited, and in any case, at the moment of investigation the harvested-credential window may still be open.

Therefore, this incident warrants P1 treatment: act as if compromise occurred until evidence proves otherwise.

---

### Key Unknowns

- Whether Diane Marsh entered credentials on the harvesting form (no proxy log available to check for a POST after the click GET)
- Whether the landing page delivered any client-side payload to WS-NURSE-04's browser
- Whether any subsequent successful authentication occurred with her credentials from an unexpected source
- Whether other staff clicked E2 or related campaign URLs without reporting (Sarah Park's concern — the batch contains only reported/unquarantined emails)
- Whether additional phishing domains beyond the four observed were used against other staff during the campaign window

---

### Endpoint Checks To Perform

*(Recommended follow-up only — no endpoint logs, Sysmon, Wazuh or Suricata data were available or searched for this report.)*

- **Browser history and cache for WS-NURSE-04**, user profile dmarsh, window 2026-04-14 14:45–16:30 CDT: confirm the visited URL sequence, whether the harvesting form page loaded, any redirects that followed, and whether form-fill history or saved-password entries reference meddefense-portal[.]com
- **Downloaded files check**: examine the browser Downloads folder and common drop locations (Desktop, %TEMP%, AppData\Local\Temp) for any files created in the 72 hours post-click, which would indicate a follow-on payload
- **Process execution review**: identify browser process start/stop times around 15:02:33 CDT and any child processes spawned by the browser in the following hours (unexpected cmd.exe, powershell.exe, mshta.exe, rundll32.exe children of browser processes are classic Stage 2 indicators)
- **PowerShell / command-line activity**: check for any powershell.exe or cmd.exe executions on WS-NURSE-04 in the post-click window, particularly with encoded-command (-enc), download cradles (IEX, Invoke-WebRequest, certutil) or network-outbound parameters
- **File creation and persistence review**: look for newly created executables, scripts, or DLLs under user-writable paths, plus new scheduled tasks, startup registry keys, or services established after the click timestamp
- **DNS/client-side resolution check** (if internal DNS query logs are retained): search for A-record queries from 10.10.2.15 for meddefense-portal[.]com around 2026-04-14 15:02:30–15:02:33 CDT to independently corroborate the click timestamp, plus any subsequent queries to domains not in the batch's IOC list
- **AV/EDR detections** on WS-NURSE-04 covering the post-click window as a completeness sweep

---

### Account Checks To Perform

*(Recommended follow-up only — no authentication logs were available or searched for this report.)*

- **Failed logon attempts** for dmarsh from 2026-04-14 15:02:33 CDT onward: attacker-side credential testing often produces failed authentications before successful ones
- **Successful logons from unusual sources**: review all successful authentications for dmarsh, flagging any source IP other than 10.10.2.15 or expected clinical subnet ranges, any VPN-gateway logins from external IPs, and any off-shift authentications (a nurse's EHR login at 03:00 would warrant immediate escalation)
- **MFA prompt records**: check for MFA push prompts issued to Diane's registered devices in the post-click window — prompt fatigue/push-bombing is the standard attacker response to harvested passwords paired with MFA
- **Password change events**: verify whether dmarsh's password was changed after the click and by whom; note that the legitimate quarterly change window opens April 20 (per E4), so a change before that date outside self-service would itself be anomalous
- **Inbox rule creation**: review dmarsh's mailbox for any rules created after the click (auto-delete, auto-forward to external addresses, or redirect rules) — these are standard attacker persistence and mail-interception moves
- **Group membership and privilege changes**: confirm no additions of dmarsh's account to privileged groups, and no OAuth app consents granted, in the post-click window
- **EHR audit trail**: pull patient record access logs for dmarsh's account from 2026-04-14 15:02 CDT forward, watching for abnormal access patterns, bulk record viewing, or export/print activity inconsistent with her normal clinical workflow

---

### Decision Matrix

| Outcome | Definition | Evidence that would support it | Response actions |
|---------|-----------|-------------------------------|------------------|
| **No compromise found** | Diane clicked but did not interact further; no malicious activity followed | Browser history shows single page load with immediate close-back; no POST recorded at proxy for her session; no new files, processes or persistence artifacts; no anomalous authentications for dmarsh; no MFA anomalies; interview confirms she recognized the ruse | Close incident as "click without submission"; reinforce positive user behavior; retain the click record as an indicator that this user and the nursing department are actively targeted; block the domains/IPs regardless |
| **Possible credential exposure** | Cannot rule out form submission; evidence is inconclusive but no confirmed malicious use | Proxy/DNS/endpoint logs unavailable or inconclusive; Diane's interview is uncertain ("I don't remember if I entered anything"); no anomalous logons but log coverage gaps exist | Treat as presumed compromise: force password reset immediately, revoke active sessions and MFA tokens, conduct the full account checks above for at least 30 days of retrospective log review, and re-interview with the helpdesk |
| **Confirmed compromise** | Credentials were submitted, and/or attacker activity on the account is evidenced | Proxy log shows POST from 10.10.2.15 to the harvesting endpoint; successful authentication for dmarsh from unexpected source IP, unusual geography, or off-shift hours; new inbox rule, MFA-device registration, or EHR access anomaly; endpoint artifacts indicating Stage 2 execution | Immediate credential reset and session revocation; isolate WS-NURSE-04 for forensic imaging; expand the investigation to what the account touched (EHR records accessed, mail items read, lateral movement); notify compliance/privacy officer for HIPAA assessment; escalate to incident commander; prepare IOC submission to HC3 per E8; consider notifying affected patients if PHI access is confirmed |

---

### Recommended Containment

These steps are safe, realistic, and do not require waiting for log confirmation. All are recommended on a precautionary basis given the 36-hour exposure window:

1. **Force an immediate password reset for dmarsh@meddefense.com** from a verified, in-person or helpdesk-mediated channel — do not send reset instructions by email, since the attacker may hold mailbox access
2. **Revoke all active sessions and refresh tokens** for the account (mail, VPN, SSO, EHR portal) so any harvested session ceases to be valid regardless of the password used to create it
3. **Reset/re-register MFA** for the account to defeat any attacker-initiated MFA device enrollment; review registered authenticators for anything Diane does not recognize
4. **Interview Diane Marsh promptly and non-punitively**, asking specifically: did she enter her username and password on the page, did she receive any MFA prompts afterward, did she notice any downloads or unusual computer behavior, and has she received any follow-up contact referencing the "verification"
5. **Block the campaign infrastructure** at the mail gateway, DNS and proxy layers: the four domains (meddefense-portal[.]com, outlook-protection[.]com, medequip-supplies[.]net, meddefense-benefits[.]org) and the associated sending IPs, including 91.234.99.107 for the clicked domain
6. **Maintain enhanced monitoring on the dmarsh account for 30 days**: alert on any authentication from an unmanaged device or external IP, any MFA prompt surge, any inbox rule creation, and unusual EHR query patterns
7. **Preserve evidence**: retain the raw email batch, the workstation click record, and any subsequently gathered proxy/DNS/auth logs under chain of custody for the incident record and potential regulatory response
8. **Verify and patch user awareness**: communicate the campaign to clinical staff using the lookalike-domain pattern (without exposing the victim's identity), emphasizing that IT will never email links to internal portals, as E4 itself states

---

### Conclusion

The evidence batch confirms that Diane Marsh clicked a per-victim credential harvesting URL at 2026-04-14 15:02:33 CDT, from workstation WS-NURSE-04 (10.10.2.15), roughly 15 minutes after the phishing email E2 was delivered, and approximately 36 hours before the investigation began. The specific harms of the click — whether credentials were submitted, whether any payload executed, and whether the account has since been accessed by the attacker — cannot be determined from the email evidence alone and require the endpoint and authentication log reviews documented above.

The absence of confirmed compromise is not the absence of risk. The URL's per-victim token proves the attacker attributed the click to Diane; the harvest page's content is invisible from the batch; and the HC3 advisory warns of Stage 2 activity after credential validation. The investigation therefore defaults to treating the account as potentially compromised, applying immediate containment (password reset, session and MFA revocation, infrastructure blocking, user interview) while the decision matrix evidence is gathered. Should log review move the incident to "confirmed compromise," the response expands to host isolation, HIPAA assessment, and external reporting per the E8 advisory — with MedDefense potentially among the first organizations to report IOCs for this campaign.

================================================================================
