#!/bin/bash
# Name: 9-triage_priority_conflicts.sh
# Purpose: Process Batch 7 priority conflicts. Reads enriched_queue.json and
#          the tickets produced in batches 1-6, identifies alerts where the
#          rule-driven priority band conflicts with asset-driven or
#          context-driven urgency, and emits override tickets to
#          tickets/batch7_overrides.json. Conflict patterns (first match
#          wins; matching is case-insensitive against verified data shapes:
#          criticality and data_classification are uppercase in the joined
#          asset, zone_id vocabulary is uppercase):
#            1. priority_band in (low, medium) AND asset.criticality ==
#               CRITICAL AND asset.data_classification in (phi, pci,
#               confidential) -> true_positive / escalate_tier2 /
#               override_reason critical_data_asset
#            2. priority_band == critical AND asset.criticality == LOW AND
#               asset.role == test -> false_positive / monitor /
#               override_reason test_asset_not_production
#               (dead pattern on this queue: no critical band, no test role;
#               branch retained for tree fidelity)
#            3. all ioc_hits reputation == unknown AND asset in a regulated
#               zone (zone_id or zone data_types indicate phi or
#               medical_devices) -> force monitor /
#               override_reason regulated_zone_unknown_reputation
#               (dead pattern on this queue: every IOC hit carries
#               reputation malicious; branch retained for tree fidelity)
#          Override tickets are emitted for matching alerts regardless of
#          prior batch classification; batch 7 is authoritative for the
#          overridden verdict. No back-propagation into batches 1-6 (their
#          hashes are stable and the override record is the audit trail).
#          Alerts still unclassified after batches 1-6 (none on this queue)
#          are carried forward as true_positive / monitor with a
#          fell-through-every-batch justification requiring human review.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"

if [[ ! -r "$ENRICHED_JSON" ]]; then
    echo "ERROR: $ENRICHED_JSON not found (run 2-context_assembly.sh first)" >&2
    exit 1
fi

mkdir -p "$TRIAGE_PKG/tickets"

ENRICHED_PATH="$ENRICHED_JSON" \
TICKETS_DIR="$TRIAGE_PKG/tickets" \
python3 - <<'PY'
import json
import os
import uuid

enriched_path = os.environ["ENRICHED_PATH"]
tickets_dir = os.environ["TICKETS_DIR"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
entries = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}

# ---------------------------------------------------------------------------
# Regulated zone vocabulary: zone_id / data_types from network_zones.json,
# surfaced per-asset via the joined network_zone and data_classification
# fields. Pattern 3 checks both the asset's zone identity and its data
# classification for PHI / medical-device regulation.
# ---------------------------------------------------------------------------
REGULATED_ZONE_HINTS = ("phi", "medical_devices", "medical_device", "radiology")

def zone_is_regulated(asset):
    candidates = [
        str(asset.get("network_zone") or ""),
        str(asset.get("zone") or ""),
    ]
    if isinstance(asset.get("data_classification"), str):
        candidates.append(asset["data_classification"])
    for cand in candidates:
        lowered = cand.lower()
        if any(h in lowered for h in REGULATED_ZONE_HINTS):
            return True
    return False

# ---------------------------------------------------------------------------
# Prior-batch verdicts (context for the override justification)
# ---------------------------------------------------------------------------
BATCH_FILES = ["batch1_clearcut_tp.json", "batch2_clearcut_fp.json",
               "batch3_benign.json", "batch4_auth.json",
               "batch5_proc_net.json", "batch6_incidents.json"]
prior = {}
for name in BATCH_FILES:
    path = os.path.join(tickets_dir, name)
    if not os.path.isfile(path):
        continue
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, list):
        for ticket in payload:
            if isinstance(ticket, dict):
                if ticket.get("alert_id"):
                    prior[ticket["alert_id"]] = (name, ticket.get("classification"),
                                                 ticket.get("recommended_action"))
                for aid in (ticket.get("contributing_alerts") or []):
                    prior[aid] = (name, ticket.get("classification"),
                                  ticket.get("recommended_action"))

EST_SECONDS = {"escalate": 600, "monitor": 300, "tune": 180}

def base_ticket(entry):
    return {
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                    "meddefense.tickets."
                                    + entry["alert_id"])),
        "alert_id": entry["alert_id"],
        "evidence_refs": [entry["event_ref"]],
        "ioc_hits": entry.get("ioc_hits", []),
        "attack_techniques": entry.get("attack_techniques", []),
        "created_at": entry.get("generated_at"),
    }

def prior_note(entry):
    rec = prior.get(entry["alert_id"])
    if rec is None:
        return "no prior-batch ticket"
    return ("prior batch %s: %s / %s"
            % (rec[0].replace(".json", ""), rec[1], rec[2]))

tickets = []
stats = {"pattern1": 0, "pattern2": 0, "pattern3": 0, "carried_forward": 0}

for entry in enriched:
    if not isinstance(entry, dict):
        continue
    band = entry.get("priority_band")
    asset = entry.get("asset") or {}
    crit = (asset.get("criticality") or "unknown").upper()
    dc = (str(asset.get("data_classification") or "")).lower()
    role = (str(asset.get("role") or "")).lower()
    hits = entry.get("ioc_hits") or []

    # Pattern 1: low/medium band on critical data-bearing asset
    if band in ("low", "medium") and crit == "CRITICAL" \
            and dc in ("phi", "pci", "confidential"):
        ticket = base_ticket(entry)
        ticket.update({
            "classification": "true_positive",
            "recommended_action": "escalate_tier2",
            "override_reason": "critical_data_asset",
            "justification":
                "priority conflict override (critical_data_asset): rule "
                "assigned priority_band=%s but asset %s is CRITICAL with "
                "data_classification=%s (field and value forcing override: "
                "asset.criticality=%s, asset.data_classification=%s); %s; "
                "machine ranking overridden upward to tier 2 escalation"
                % (band, asset.get("hostname"), asset.get("data_classification"),
                   crit, asset.get("data_classification"),
                   prior_note(entry)),
            "analyst_time_seconds": EST_SECONDS["escalate"],
        })
        tickets.append(ticket)
        stats["pattern1"] += 1
        continue

    # Pattern 2: critical band firing on a test box
    if band == "critical" and crit == "LOW" and role == "test":
        ticket = base_ticket(entry)
        ticket.update({
            "classification": "false_positive",
            "recommended_action": "monitor",
            "override_reason": "test_asset_not_production",
            "justification":
                "priority conflict override (test_asset_not_production): "
                "rule assigned priority_band=critical but asset %s is "
                "criticality=LOW with role=test (fields forcing override: "
                "asset.criticality=%s, asset.role=%s); %s; machine ranking "
                "overridden downward, finding does not affect production"
                % (asset.get("hostname"), crit, asset.get("role"),
                   prior_note(entry)),
            "analyst_time_seconds": EST_SECONDS["monitor"],
        })
        tickets.append(ticket)
        stats["pattern2"] += 1
        continue

    # Pattern 3: all-unknown IOC reputation in a regulated zone
    if hits and all(h.get("reputation") == "unknown" for h in hits) \
            and zone_is_regulated(asset):
        ticket = base_ticket(entry)
        ticket.update({
            "classification": entry.get("priority_band") in ("high", "critical")
                              and "true_positive" or "true_positive",
            "recommended_action": "monitor",
            "override_reason": "regulated_zone_unknown_reputation",
            "justification":
                "priority conflict override "
                "(regulated_zone_unknown_reputation): all %d IOC hits carry "
                "reputation=unknown on asset %s in regulated zone %s "
                "(data_classification=%s); forced to monitor pending "
                "reputation confirmation rather than automatic closure or "
                "escalation; %s"
                % (len(hits), asset.get("hostname"),
                   asset.get("network_zone") or asset.get("zone"),
                   asset.get("data_classification"), prior_note(entry)),
            "analyst_time_seconds": EST_SECONDS["monitor"],
        })
        tickets.append(ticket)
        stats["pattern3"] += 1
        continue

    # Carry-forward: unclassified after batches 1-6
    if entry["alert_id"] not in prior:
        ticket = base_ticket(entry)
        ticket.update({
            "classification": "true_positive",
            "recommended_action": "monitor",
            "justification":
                "carried forward: alert fell through every previous batch "
                "(1-6) without a recorded conflict pattern or verdict; "
                "requires human review; priority_band=%s, asset %s "
                "(criticality %s, data_classification %s)"
                % (band, asset.get("hostname"), crit,
                   asset.get("data_classification")),
            "analyst_time_seconds": EST_SECONDS["monitor"],
        })
        tickets.append(ticket)
        stats["carried_forward"] += 1

tickets.sort(key=lambda t: t["alert_id"])
out_path = os.path.join(tickets_dir, "batch7_overrides.json")
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(tickets, fh, indent=2)
    fh.write("\n")

print("batch 7 priority conflicts")
for ticket in tickets:
    src = entries.get(ticket["alert_id"]) or {}
    print("  %-14s %-8s -> %-15s %s"
          % (ticket["alert_id"][:14],
             src.get("priority_band") or "-",
             ticket["classification"],
             ticket.get("override_reason", "carried_forward")))
print("overrides applied         : %d" % (len(tickets) - stats["carried_forward"]))
print("  critical_data_asset       : %d" % stats["pattern1"])
print("  test_asset_not_production : %d" % stats["pattern2"])
print("  regulated_zone_unknown    : %d" % stats["pattern3"])
print("unclassified carried forward : %d" % stats["carried_forward"])
print("tickets written            : %d" % len(tickets))
print("tickets/batch7_overrides.json")
PY
