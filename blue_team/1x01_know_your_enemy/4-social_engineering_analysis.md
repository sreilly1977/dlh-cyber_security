# Social Engineering Threat Analysis
## MedDefense Health Systems

---

## Scenario 1: Fake FortiGate Firmware Alert

**Vector Type:** Phishing (brand impersonation)

**Target:** Sarah Park, IT Director. Sarah is vulnerable because she owns the FortiGate firewall and would naturally be the recipient of legitimate vendor security alerts. The billing-srv-01 compromise creates heightened anxiety about infrastructure vulnerabilities, making a "critical firmware vulnerability" email feel timely and credible. IT staff are conditioned to respond quickly to vendor advisories.

**Psychological Lever:** Urgency. The 24-hour deadline and threat of service termination create artificial time pressure designed to bypass critical evaluation.

**Red Flags:**
1. Sender domain is fortinet-support.net rather than the legitimate fortinet.com domain used for official communications
2. Legitimate vendor security advisories link to the vendor's official support portal, not a direct download link in an email
3. No CVE identifier, advisory number, or PSIRT reference is provided to verify the vulnerability independently

**Technical Control:** Implement email authentication (SPF, DKIM, DMARC) on the MedDefense mail domain and configure FortiGate email filtering to quarantine emails from domains impersonating known vendors. Additionally, deploy anti-phishing toolbar extensions that flag newly registered domains and look-alike domains.

**Administrative Control:** Establish a vendor communication verification policy requiring all staff to independently verify vendor security alerts by navigating directly to the vendor's official website (fortinet.com) rather than clicking email links. Document the official support URLs for all critical vendors in the IT operations runbook.

---

## Scenario 2: Fake CEO Wire Transfer Request

**Vector Type:** Business Email Compromise (BEC)

**Target:** Robert Kim, CFO. Robert is vulnerable because the request appears to come from the CEO, creating an authority gradient that discourages verification. The "confidential acquisition" and "do not discuss with anyone" instruction isolates him from colleagues who might identify the fraud. Executives are accustomed to processing urgent, high-value transactions as part of normal operations.

**Psychological Lever:** Authority. The email impersonates the highest-ranking executive in the organization, triggering deference and obedience rather than verification.

**Red Flags:**
1. Sender email address has a subtle difference from the real CEO email address (lookalike domain or character substitution)
2. "Do not discuss with anyone" instruction is designed to prevent verification through normal channels
3. Urgent wire transfer request with no prior discussion, purchase order, or procurement documentation

**Technical Control:** Implement Microsoft Defender for Office 365 BEC protection (included in E3 license), which uses mailbox intelligence to detect impersonation attempts and flags suspicious sender domains with warning banners. Configure mail flow rules to flag external emails displaying CEO display names.

**Administrative Control:** Implement a dual-authorization wire transfer policy requiring verbal verification (phone call to a known number, not one provided in email) for any wire transfer exceeding $10,000. Document the procedure in the finance department's SOP and train all executives on BEC red flags.

---

## Scenario 3: Phone-Based EHR Credential Theft

**Vector Type:** Vishing

**Target:** Staff Nurse at MedDefense Central. The nurse is vulnerable because clinical staff are trained to be helpful and cooperative with IT requests. The mention of the billing server incident lends credibility because it references a real event the nurse likely heard about. Nurses are busy and focused on patient care, making them susceptible to bypassing security procedures when pressured by perceived IT authority.

**Psychological Lever:** Helpfulness. The caller exploits the nurse's instinct to assist IT with a security investigation, framed as helping protect the organization after a known incident.

**Red Flags:**
1. IT will never ask for a password over the phone; legitimate IT support verifies identity through other means and resets passwords through AD, not by asking the user to read them aloud
2. The caller initiates contact and requests credentials rather than the user initiating a support request through the helpdesk ticketing system
3. "Emergency security audit" creates false urgency to bypass normal verification procedures

**Technical Control:** Deploy MFA on all EHR and Active Directory accounts. Even if the nurse provides her password, the attacker cannot authenticate without the second factor. This converts a total credential compromise into a partial compromise that fails at the authentication gate.

**Administrative Control:** Implement and communicate a clear policy that IT will never request passwords by phone, email, or in person under any circumstances. Train all staff annually with a specific module on vishing that includes this policy. Require helpdesk staff to verify caller identity using employee ID number and manager name before performing any account actions.

---

## Scenario 4: Fake Parking Permit Renewal SMS

**Vector Type:** Smishing

**Target:** All MedDefense employees. Employees are vulnerable because parking permits are a mundane administrative concern that triggers low suspicion. The threat of towing creates immediate financial anxiety. The fake HR portal looks familiar, encouraging credential entry without close examination. SMS messages feel more personal and trustworthy than email.

**Psychological Lever:** Urgency (expiring tomorrow) combined with Fear (towing and associated costs).

**Red Flags:**
1. MedDefense would not send parking permit renewals via SMS; administrative notifications come through email or the intranet portal
2. The link leads to a portal asking for Active Directory credentials, which is unrelated to parking permit management
3. SMS sender is an unknown short code or phone number, not an official MedDefense communication channel

**Technical Control:** Deploy mobile device management (MDM) on all company-owned and BYOD phones that enforces URL filtering and blocks known phishing domains. Configure Microsoft Defender for Endpoint mobile protection on enrolled devices to block malicious links in SMS messages.

**Administrative Control:** Establish an official communication channels policy documenting that administrative notifications will only be sent via email or the intranet portal, never via SMS. Communicate this policy to all staff and include it in new hire orientation. Create a simple internal reporting mechanism (forward suspicious messages to abuse@meddefense.org) and publicize it.

---

## Scenario 5: Compromised CME Website

**Vector Type:** Watering Hole Attack

**Target:** MedDefense physicians who visit the Regional Healthcare Association website monthly for continuing medical education credits. Physicians are vulnerable because they trust the industry association website and have no reason to suspect it has been compromised. CME requirements create a regular visiting pattern that attackers can predict and exploit.

**Psychological Lever:** Familiarity. Physicians trust the website as a known, reputable source and let down their guard, failing to notice the silent redirect to a malicious domain.

**Red Flags:**
1. Browser security warnings or certificate errors when browsing the CME site (the malicious redirect target may have an invalid certificate)
2. Unexpected browser behavior such as pop-ups, redirects to unknown domains, or downloads initiating without user action
3. Endpoint protection alerts on the physician's workstation (if endpoint protection is installed and current)

**Technical Control:** Deploy DNS-based threat protection (e.g., Cisco Umbrella or a DNS filtering service) on all MedDefense networks and VPN connections. This blocks connections to known malicious domains at the DNS resolution layer, preventing the silent redirect from reaching the attacker's exploit kit even if the CME site is compromised.

**Technical Control (Alternative):** Ensure all physician workstations are running current Sophos endpoint protection with web control and exploit prevention enabled. The Sophos agent should block exploit attempts at the browser level.

**Administrative Control:** Include third-party website dependencies in the MedDefense third-party risk management policy. Require periodic security assessment of websites that physicians access regularly for professional purposes. Communicate watering hole risks in annual security awareness training with specific guidance to report unexpected browser behavior to IT.

---

## Scenario 6: Typosquatted Patient Portal

**Vector Type:** Typosquatting (with brand impersonation)

**Target:** Patients attempting to access the MedDefense patient portal. Patients are vulnerable because they may not know the exact URL of the legitimate portal and rely on search engine results to find it. The typo (defence vs defense) is subtle enough to escape notice, especially for users typing quickly or relying on autocorrect.

**Phychological Lever:** Familiarity. The pixel-perfect portal copy looks exactly like the real site, creating trust that suppresses suspicion. Users expect to enter credentials on this page, so the attack does not require any abnormal user behavior.

**Red Flags:**
1. Domain name contains "defence" (British spelling) instead of "defense" (American spelling), which is a subtle deviation from the legitimate MedDefense branding
2. Google Ads placement above organic search results suggests commercial intent, whereas the legitimate portal would likely appear as the top organic result without paid advertising
3. Browser does not autofill saved credentials (because the domain differs from the legitimate one), which should alert attentive users to a domain mismatch

**Technical Control:** Register defensive domain variations (meddefence-portal.com, meddefense-portal.net, etc.) to prevent typosquatting. Additionally, implement Extended Validation (EV) or Organization Validation (OV) certificates on the legitimate patient portal, which display the organization name in the browser address bar, helping patients verify they are on the authentic site.

**Administrative Control:** Include the exact patient portal URL on all patient communications (appointment reminders, discharge papers, billing statements, business cards). Educate patients through waiting room posters and portal login screens: "Always verify the URL starts with [exact address]. MedDefense will never ask for your password via email or text."

---

## Scenario 7: Tailgating Through Badge Door

**Vector Type:** Impersonation (physical tailgating)

**Target:** Any MedDefense staff member entering through the badge-controlled door to the IT department corridor. The staff member is vulnerable because social norms discourage challenging someone who appears to belong. The scrubs, stethoscope, and hospital-branded coffee cup create a visual disguise that signals "legitimate employee." The "my badge is in my locker" excuse is relatable and non-confrontational.

**Psychological Lever:** Helpfulness (holding the door for a colleague) combined with Familiarity (scrubs and stethoscope signal belonging).

**Red Flags:**
1. Visitor badge is expired (two days past expiration), which should disqualify entry under any circumstances
2. The person has no MedDefense employee badge visible; visitor badges are not valid for unescorted access to restricted areas
3. "My badge is in my locker" is a classic tailgating excuse; legitimate staff without badges should be directed to security for temporary access, not waved through

**Technical Control:** Install anti-tailgating physical controls at restricted access points: mantrap vestibules (two-door sequential entry requiring individual badge authentication), or optical turnstiles that permit only one person per badge swipe. These eliminate the social engineering element by making piggybacking physically impossible.

**Administrative Control:** Implement a "challenge badge" policy requiring all staff to politely verify badge access for anyone entering restricted areas. Train staff with a simple script: "I'm happy to hold the door, but I need to see your badge first for compliance." Make this a cultural expectation, not just a policy document, by having leadership model the behavior.

---

## Summary Table

| Scenario | Vector Type | Target Role | Psychological Lever | Primary Gap Enabled |
|----------|-------------|-------------|----------------------|----------------------|
| 1 | Phishing (Brand Impersonation) | IT Director (Sarah Park) | Urgency | GAP-003 (No detection of malicious email activity) |
| 2 | Business Email Compromise | CFO (Robert Kim) | Authority | GAP-004 (No MFA to verify executive identity) |
| 3 | Vishing | Staff Nurse | Helpfulness | GAP-004 (No MFA on EHR access) |
| 4 | Smishing | All Employees | Urgency + Fear | GAP-012 (No MDM on mobile devices) |
| 5 | Watering Hole | Physicians | Familiarity | GAP-012 (Endpoint protection gaps on workstations) |
| 6 | Typosquatting | Patients | Familiarity | GAP-013 (TLS/brand verification gaps) |
| 7 | Impersonation (Physical) | Staff at Badge Door | Helpfulness + Familiarity | GAP-011 (Physical security failures) |
