# SOC Automation Brief

**For: James Chen | From: Steve Reilly, Cybersecurity Engineer | 08 November 2026**

## What Was Built

- **An enrichment engine** that answers "is this IP, domain or web address
  known-bad?" in under 2 seconds using our internal threat intelligence feed,
  replacing the three-tab manual lookup that cost 45 minutes during the
  Cobalt Strike incident.
- **A case manager** that automatically opens a tracked case for every alert
  the playbooks touch, with the full evidence attached, so nothing lives only
  in Slack anymore.
- **A phishing triage playbook** that checks every link and sender in an
  email alert, and escalates known-malicious messages to the on-call analyst
  immediately, queues unknown senders for review, and closes clearly benign
  internal mail with a recorded reason.
- **A credential exposure playbook** that checks whether stolen-credential
  alerts involve admin accounts or known attacker infrastructure, and flags
  affected machines for isolation — as a recommendation an analyst must
  approve. It never takes a machine offline by itself.

## Integration Test Results

Five alert scenarios were run end-to-end against the built system; all five
produced the expected outcome (5 of 5 PASS):

- A phishing email from a known attacker IP and lookalike domain was
  escalated as Critical within 2 seconds, with no analyst involvement.
- A phishing email from an unknown external sender was correctly held for
  analyst review rather than escalated or closed.
- An internal maintenance email was correctly assessed as benign and closed
  with a documented reason.
- An LSASS credential dump from a known attacker IP using a Domain Admin
  service account was escalated as Critical and the workstation was flagged
  for analyst-authorized isolation.
- A pass-the-hash alert from an internal IP by a standard user was
  correctly routed for manual review with no isolation flagged.

## Efficiency Estimate

At the planning baseline of 150 alerts per day at 8 minutes of analyst effort
each, the team spends about 20 hours per day on triage, and the March review
found 67 percent of that is lookup work. Automating the phishing playbook's
enrichment portion recovers roughly 13 hours per day, or about 400
analyst-hours per month — comparable to adding more than two full shifts of
analyst capacity at zero headcount. The estimate assumes the current alert
mix and the 8-minute and 67-percent figures hold; if phishing volume falls
or the intel feed ages, the saving shrinks. We committed in the strategy to
re-measure after 90 days of real data.

## What the Playbooks Cannot Do Yet

- **The threat feed is a static local file.** Every verdict depends on the
  snapshot we load; as attacker infrastructure rotates, unknown addresses
  score "review" instead of "malicious" until the feed is updated.
- **No cross-alert deduplication.** The same sender attacking twice creates
  two separate cases; analysts still need to link related activity by hand.
- **No connections to production systems.** Notifications are written to a
  queue, not sent to paging; isolation flags are written to a file, not
  pushed to the EDR console. Every action still requires a human to act on
  the case.

## What Needs Authorization

1. Deploy the playbooks in shadow mode against a staging SIEM feed,
   processing all live alerts in parallel with manual triage.
2. Two weeks of analyst time to validate playbook verdicts against their own
   conclusions during the shadow period, before any case data is trusted for
   the auto-close decision.
3. A 30-day false-positive measurement period on the auto-close logic before
   it is allowed to close anything in production, with a documented rollback
   procedure.
4. Read-only API access to the EDR console (to surface isolation flags
   directly to analysts) and to the email gateway (to pull full message
   context), both queued for Phase 2-3 review, not for automated action.

## Recommendation

Approve the four-week shadow-mode deployment above this week so measurement
data starts accumulating now; any production action, including auto-close,
waits until the false-positive measurement confirms the strategy's
thresholds.
