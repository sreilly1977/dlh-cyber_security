# Security Quick Reference: IT Staff

**[MedDefense branding placeholder]**
**Version:** 1.0 — 2026-11-10
**Reading time:** 90 seconds

---

## Your biggest threats

- **Vendor-support pretexting.** "We need temporary domain admin for the emergency patch — the helpdesk can approve it after." It targets us because we're the ones who can actually grant it, and the 6x02 audit caught exactly this live: vendor and contractor requests produced Domain Admin access with no ticket and no expiry (`iam_audit_summary_6x02.md`, `insider_threat_case_notes.md` Case C). **Watch for:** a privilege request without a ticket, a change reference, or an expiration date.

- **Dormant and over-privileged service accounts coming alive.** The audit found `svc_epic_int` and `svc_helpdesk` sitting on Domain Admin, `admin.legacy` with no MFA, and a contractor account still enabled after contract end (`privileged_account_findings.md`, IAM-001 through IAM-007). Nobody watches these accounts — which is what an attacker counts on. **Watch for:** a `svc_*` account logging in interactively, or any account active outside its documented function or hours.

- **Admin action from personal contexts.** Approving or executing privileged changes from personal email, personal devices, or untracked sessions. **Watch for:** "can you just do it quickly" pressure to skip the tracked console for a one-off.

## What to do right now

- Inventory your service accounts this week: owner, documented function, expected activity. No owner, no function, or no recent expected activity = raise a review ticket — that's the audit's practical rule.
- Route every privilege request through ticket + change reference + expiry. No exceptions for vendor urgency.
- Confirm MFA on every admin account you touch, including migration-era leftovers, and kill interactive rights on service accounts where they're not needed.

## When something looks wrong

Report observable facts — account name, time, what happened — to **ext. 4-SECURITY** or security@meddefense.org. No accusation needed: "this account is active outside its documented purpose" is a complete, useful report.

## What not to do

- Don't run admin actions from personal email, personal devices, or untracked sessions — if it isn't in a console log, it didn't officially happen, and that works in the attacker's favor.
- Don't accept "the vendor needs it broad" as a justification — scope the credential, then expire it.
- Don't assume a disabled account is a closed account: disabled users still holding privileged group memberships was a real audit finding (IAM-007).

---

**Questions anytime:** ext. 4-SECURITY · security@meddefense.org · **Outlook:** select the message, click **Report Phishing**
