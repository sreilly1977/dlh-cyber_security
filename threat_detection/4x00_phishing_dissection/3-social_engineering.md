# 3-social_engineering.md

**Name:** Social Engineering Analysis

**Purpose:** Analyze content of suspicious emails E2, E3, E5, E7 and identify
          psychological manipulation techniques and targeting precision
          
**Author:** Steve - Cybersecurity Engineer

**Date:** 18 September 2026

================================================================================

MEDDEFENSE HEALTH SYSTEMS — SOCIAL ENGINEERING ANALYSIS

Analysis targets: E2, E3, E5, E7 (identified as SUSPICIOUS during initial triage)

Evidence source: Email evidence batch (collected 2026-04-17 by Mike Torres)

================================================================================

## Email 2 — meddefense-portal.com

- **Psychological lever:** Authority + Urgency + Fear of Loss
- **Pretext:** MedDefense IT Security rolled out a weekend security policy update requiring mandatory portal re-verification
- **Requested action:** Click verification link (https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1)
- **Targeting level:** TARGETED
- **Content red flags:**
  - 24-hour deadline creates artificial time pressure
  - Threatens lockout from three critical systems (scheduling, EHR gateway, shift swaps)
  - Uses employee's full name (Diane Marsh) in greeting
  - Includes fabricated ticket number (INC-2026-04-14-7741) to simulate internal process
  - Display name "MedDefense IT Security" paired with unauthenticated domain
  - No TLS on relay hop inconsistent with legitimate IT communications
- **Attacker knowledge required:**
  - Employee name (Diane Marsh)
  - Employee email address (dmarsh@meddefense.com)
  - Workstation identifier or role hint (WS-NURSE-04 implied by nursing-specific systems)
  - MedDefense internal system names (scheduling, EHR gateway, shift swap requests)
  - Organization name for domain lookalike construction
- **Conclusion:** This is a highly targeted credential phishing attack. The attacker knew enough to reference specific MedDefense internal systems that nurses would use daily, making the pretest believable to clinical staff. The 24-hour deadline combined with lockout threats exploits fear of disrupting workflow. The use of the employee's actual name and the fabrication of a ticket number indicate reconnaissance or leaked employee data.

================================================================================

## Email 3 — outlook-protection.com

- **Psychological lever:** Fear + Urgency + External Threat
- **Pretext:** Microsoft detected unusual sign-in activity from Lagos, Nigeria; account may be compromised
- **Requested action:** Click verification link (https://outlook-protection.com/verify)
- **Targeting level:** SEMI-TARGETED
- **Content red flags:**
  - Claims geographic location (Lagos, Nigeria) known to trigger alarm about unauthorized access
  - Displays recipient's actual email address (rmendez@meddefense.com) to establish credibility
  - Provides fake IP address (41.203.72.188) and device details to simulate forensic evidence
  - 48-hour account lockout threat creates time pressure
  - Brand impersonation (claims Microsoft but originates from unrelated domain)
  - Timestamp shows "April 15, 2026 at 10:47 AM UTC" while email arrived 9:13 AM CDT, creating timeline confusion
  - Copyright footer with Microsoft address attempts to add legitimacy
- **Attacker knowledge required:**
  - Recipient email address (rmendez@meddefense.com)
  - Target organization name (MedDefense) to embed in the sign-in context
  - Generic Microsoft 365 branding assets (logo hotlinked from attacker site)
  - No specific internal workflow knowledge needed
- **Conclusion:** This is semi-targeted brand impersonation leveraging fear of credential compromise. Unlike E2, this does not reference MedDefense-specific internal systems. The attacker needed only the email address to personalize the lure. The geographic baiting (Nigeria) is a common technique designed to make recipients believe they have concrete evidence of unauthorized access, increasing likelihood of immediate action.

================================================================================

## Email 5 — medequip-supplies.net

- **Psychological lever:** Financial Pressure + Urgency + Authority
- **Pretext:** Invoice INV-2026-04891 for $24,716.38 delivered on April 9; payment required within 7 days
- **Requested action:** Click invoice portal link AND/OR open PDF attachment containing embedded link
- **Targeting level:** TARGETED
- **Content red flags:**
  - Large-dollar amount ($24,716.38) creates significant financial pressure on AP department
  - 7-day deadline with explicit late fee threat (2%)
  - Consequence escalation (suspension of future deliveries)
  - Invoice numbered with date-based format (INV-2026-04891) appearing professional
  - PDF attachment contains embedded URI action pointing to payment portal
  - 1-800 number provided adds false credibility
  - Supplier name "MedEquip Supplies" mimics legitimate medical equipment vendors
  - No prior purchase order or delivery confirmation referenced
- **Attacker knowledge required:**
  - Recipient name and role (Angela Rivera, Accounts Payable)
  - Recipient email address (arivera@meddefense.com)
  - Organization name (MedDefense Health Systems)
  - Department-specific workflow (AP processing invoices)
  - Invoice numbering conventions and dollar amount ranges plausible for medical supplies
- **Conclusion:** This is a targeted business email compromise (BEC) variant. The attacker understood that Accounts Payable personnel handle high-value invoices and respond to payment deadlines. The combination of email body and PDF attachment with embedded link is designed to evade initial link scanning while directing victims to credential harvesting or fraudulent payment portals. The specific invoice number format and amount suggest the attacker may have sampled legitimate invoice structures from prior reconnaissance.

================================================================================

## Email 7 — meddefense-benefits.org

- **Psychological lever:** Urgency + Scarcity + Fear of Loss
- **Pretext:** Open Enrollment for 2026 benefits closes at midnight tomorrow; recipient has not yet enrolled
- **Requested action:** Click enrollment portal link (https://meddefense-benefits.org/enroll)
- **Targeting level:** TARGETED
- **Content red flags:**
  - "TOMORROW" and "closes at midnight" language creates maximum urgency
  - States recipient has "not yet completed" enrollment when Linda Patterson confirmed never signed up
  - Threatens coverage lapse and default to basic plan until November 2026
  - Asks recipient to verify even if they think they already enrolled (double-compromise trap)
  - Hyphenated domain (meddefense-benefits.org) mimics internal HR/benefits communications
  - Red accent color (#b40000) used for warning styling
  - Recipient name personalized (Linda)
- **Attacker knowledge required:**
  - Recipient name (Linda Patterson)
  - Recipient email address (lpatterson@meddefense.com)
  - Organization name (MedDefense Health Systems)
  - Benefits terminology (open enrollment, coverage lapse, election)
  - Calendar timing (April open enrollment period)
  - Role-appropriate department targeting (Billing/Human Resources)
- **Conclusion:** This is a targeted HR benefits impersonation attack exploiting enrollment periods. The attacker knew enough to use MedDefense's exact enrollmen

================================================================================
