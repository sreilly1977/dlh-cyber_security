#!/bin/bash
# Name: 10-fp_tuning.sh
# Purpose: Process Batch 8 false positive aggregation. Reads every
#          tickets/batchN_*.json file (batches 1-7), collects every ticket
#          with classification == false_positive, and groups by (rule_id,
#          fp_reason), joining rule_id / rule_title through
#          enriched_queue.json on alert_id. For each group with two or more
#          tickets, emits a tuning recommendation:
#            - rule_id, rule_title, fp_count, fp_reason
#            - sample_alert_ids: up to five example ticket references
#            - proposed_change: a concrete Sigma filter YAML fragment keyed
#              to the fp_reason vocabulary established in batches 2 and 5
#              (service_account_activity, management_subnet, baseline_match,
#              clean_ioc_no_deviation, suspicious_but_baseline_known_
#              elsewhere, unknown_ip_low_asset, baseline_edge_burst), with
#              a generic suppression-exclusion fallback for unanticipated
#              reasons
#            - expected_fp_reduction: integer count (all members of the
#              group the proposed change addresses)
#            - tp_risk_note: one-sentence false-negative risk assessment
#              citing a concrete scenario per reason
#          Writes the full output (metadata + recommendations) to
#          tuning_recommendations.json and prints a compact summary
#          ordered by fp_count descending. On this shift's queue the FP
#          population is zero (documented queue-composition finding:
#          score-0 process noise routed to monitor, not FP), so the output
#          is a valid empty recommendations array; groups of one are
#          excluded per the two-or-more threshold and counted separately.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
TICKETS_DIR="$TRIAGE_PKG/tickets"
OUT_JSON="$TRIAGE_PKG/tuning_recommendations.json"

if [[ ! -r "$ENRICHED_JSON" ]]; then
    echo "ERROR: $ENRICHED_JSON not found (run 2-context_assembly.sh first)" >&2
    exit 1
fi
if [[ ! -d "$TICKETS_DIR" ]]; then
    echo "ERROR: $TICKETS_DIR not found (run triage batches first)" >&2
    exit 1
fi

ENRICHED_PATH="$ENRICHED_JSON" \
TICKETS_DIR="$TICKETS_DIR" \
OUT_PATH="$OUT_JSON" \
python3 - <<'PY'
import glob
import json
import os

enriched_path = os.environ["ENRICHED_PATH"]
tickets_dir = os.environ["TICKETS_DIR"]
out_path = os.environ["OUT_PATH"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
entries = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}

# ---------------------------------------------------------------------------
# Collect false-positive tickets from every batch file.
# Individual ticket files carry alert_id; incident tickets carry
# contributing_alerts but never classification false_positive on this
# pipeline, so plain filtering over all batchN_*.json files is sufficient.
# ---------------------------------------------------------------------------
fp_tickets = []
for path in sorted(glob.glob(os.path.join(tickets_dir, "batch*_*.json"))):
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, list):
        for ticket in payload:
            if isinstance(ticket, dict) \
                    and ticket.get("classification") == "false_positive":
                fp_tickets.append(ticket)

# Group by (rule_id, fp_reason).
groups = {}
for ticket in fp_tickets:
    entry = entries.get(ticket.get("alert_id")) or {}
    rule_id = entry.get("rule_id") or "unknown_rule"
    rule_title = entry.get("rule_title") or "Unknown Rule"
    reason = ticket.get("fp_reason") or "unspecified"
    groups.setdefault((rule_id, reason), {
        "rule_id": rule_id,
        "rule_title": rule_title,
        "fp_reason": reason,
        "tickets": [],
    })["tickets"].append(ticket)

# ---------------------------------------------------------------------------
# Per-reason Sigma YAML fragments and false-negative risk assessments.
# Reason vocabulary verified against batch 2 and batch 5 code paths.
# ---------------------------------------------------------------------------
PROPOSED_CHANGE = {
    "service_account_activity": (
        "filter:\n"
        "  TargetUserName|startswith: 'svc_'\n"
        "# exclude documented service accounts: apply jointly with their\n"
        "# approved activity windows from asset_inventory service_accounts"
    ),
    "management_subnet": (
        "filter:\n"
        "  IpAddress|cidr:\n"
        "    - '10.1.12.0/24'   # ADMIN zone (management)\n"
        "    # add further management CIDRs as documented substitutions"
    ),
    "baseline_match": (
        "filter:\n"
        "  # processes observed in this host's baseline process.per_host\n"
        "  # profile during the 3x01 baseline window\n"
        "  Image|endswith:\n"
        "    - '\\\\explorer.exe'   # example: parent matched baseline"
    ),
    "clean_ioc_no_deviation": (
        "filter:\n"
        "  # destination not on threat feed and present in the host's\n"
        "  # network.per_host_destinations baseline (join at evaluate time\n"
        "  # or enrich the rule to consume ioc reputation)"
    ),
    "suspicious_but_baseline_known_elsewhere": (
        "filter:\n"
        "  # process/destination appears in another host's baseline;\n"
        "  # scope the rule to assets whose own baseline lacks the value\n"
        "  # rather than suppressing organization-wide"
    ),
    "unknown_ip_low_asset": (
        "filter:\n"
        "  # cross-reference user history (historical source set built\n"
        "  # from the event store) before alerting on unfamiliar source"
    ),
    "baseline_edge_burst": (
        "filter:\n"
        "  # failure count within [max_failures_1h_window,\n"
        "  # 2*max_failures_1h_window) is baseline-edge, not anomalous;"
    ),
    "unspecified": (
        "filter:\n"
        "  # generic suppression predicate: retire once root cause is\n"
        "  # promoted to a named reason by the detection engineer"
    ),
}

TP_RISK = {
    "service_account_activity":
        "Credential theft frequently replays valid service-account names, "
        "so this filter would suppress a real compromise that executes as "
        "svc_backup outside its 01:00-04:00 window.",
    "management_subnet":
        "An attacker operating from inside the ADMIN zone would be "
        "invisible to this rule, so pair the CIDR exclusion with an "
        "alert-rate check rather than silent filtering.",
    "baseline_match":
        "Malware frequently masquerades as explorer.exe, so excluding "
        "baseline-matched images could hide post-exploitation child "
        "processes.",
    "clean_ioc_no_deviation":
        "Feed latency means a newly-turned-malicious destination can "
        "momentarily read clean, so a stale baseline whitelist would "
        "mask beaconing on rotation.",
    "suspicious_but_baseline_known_elsewhere":
        "Lateral movement reuses processes legitimate on other hosts, so "
        "suppressing cross-host baseline matches could hide an adversary "
        "standardizing a foothold across the estate.",
    "unknown_ip_low_asset":
        "A stolen credential used from a foreign source on a low-value "
        "asset is exactly the pivot event this suppression would hide.",
    "baseline_edge_burst":
        "A patient brute force that stays just under twice the failure "
        "threshold would be permanently ignored by this filter.",
    "unspecified":
        "Suppressing under an unnamed root cause risks conflating "
        "distinct behaviors; do not deploy until the reason is named.",
}

recommendations = []
singleton_groups = 0
for (rule_id, reason), group in groups.items():
    tickets = group["tickets"]
    if len(tickets) < 2:
        singleton_groups += 1
        continue
    recommendations.append({
        "rule_id": rule_id,
        "rule_title": group["rule_title"],
        "fp_count": len(tickets),
        "fp_reason": reason,
        "sample_alert_ids": sorted(t["alert_id"] for t in tickets)[:5],
        "proposed_change": PROPOSED_CHANGE.get(reason,
                                               PROPOSED_CHANGE["unspecified"]),
        "expected_fp_reduction": len(tickets),
        "tp_risk_note": TP_RISK.get(reason, TP_RISK["unspecified"]),
    })

recommendations.sort(key=lambda r: (-r["fp_count"], r["rule_id"]))

output = {
    "shift_date": "2026-03-27",
    "source_batches": sorted(
        os.path.basename(p) for p in
        glob.glob(os.path.join(tickets_dir, "batch*_*.json"))),
    "total_fp_tickets": len(fp_tickets),
    "groups_meeting_threshold": len(recommendations),
    "singleton_groups_excluded": singleton_groups,
    "recommendations": recommendations,
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(output, fh, indent=2)
    fh.write("\n")

print("tuning recommendations")
if not recommendations:
    print("  (none: no false positive group met the two-or-more threshold)")
for rec in recommendations:
    print("  %-3s %-32s fp=%-3d reason=%s"
          % (rec["rule_id"], rec["rule_title"][:32], rec["fp_count"],
             rec["fp_reason"]))
print("recommendations written : %d" % len(recommendations))
print("total fp tickets        : %d" % len(fp_tickets))
print("tuning_recommendations.json")
PY
