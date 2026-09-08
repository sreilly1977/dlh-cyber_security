#!/bin/bash
# Name: 8-triage_correlation.sh
# Purpose: Process Batch 6 multi-alert correlation. Groups alerts from
#          enriched_queue.json into incidents keyed by hostname: any two
#          alerts on the same hostname whose event_summary timestamps are
#          within 600 seconds of each other belong to the same incident
#          (transitive chain clustering: consecutive-gap linkage, so a chain
#          of alerts each within 600s of its predecessor forms one incident
#          even when first-to-last exceeds the window). Clusters of 3+
#          alerts are high_confidence; clusters of 2 are medium_confidence.
#          Single-alert clusters are NOT incidents: their individual
#          batch 1-5 tickets stand unchanged. The 10 null-hostname alerts
#          (the unattributed C2 beacons) cannot participate in
#          hostname-keyed grouping and keep their individual tickets.
#          Each incident produces one ticket:
#            - ticket_id: incident_<hostname>_<start_iso>
#            - classification: true_positive when any contributing alert was
#              classified true_positive in batches 1-5 (inheritance; on this
#              queue every alert is true_positive so inheritance always
#              fires); otherwise evaluated fresh from the group's highest
#              priority_score (score >= 5 true_positive, else
#              false_positive) - dead code retained for tree fidelity
#            - recommended_action: escalate_tier2 for high_confidence groups
#              on CRITICAL/HIGH assets, else monitor
#          Contributing alerts are marked grouped: true (plus
#          incident_ticket_id) in their individual batch ticket files so
#          downstream tasks can deduplicate alert-level counts. Batch file
#          rewrites are idempotent (flag set is stable across reruns);
#          expect one-time hash changes in batch 1-5 outputs.
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
import collections
import json
import os
from datetime import datetime, timedelta

enriched_path = os.environ["ENRICHED_PATH"]
tickets_dir = os.environ["TICKETS_DIR"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
entries = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}

WINDOW = timedelta(seconds=600)

def parse_ts(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def iso_z(dt):
    return dt.astimezone(tz=None).utctimetuple() and dt.strftime(
        "%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------------------
# Chain clustering per hostname (consecutive-gap linkage)
# ---------------------------------------------------------------------------
by_host = collections.defaultdict(list)
skipped_null_host = 0
for entry in enriched:
    if not isinstance(entry, dict):
        continue
    summary = entry.get("event_summary") or {}
    hostname = summary.get("hostname")
    stamp = parse_ts(summary.get("timestamp"))
    if hostname is None:
        skipped_null_host += 1
        continue
    if stamp is None:
        # No usable timestamp: cannot be window-correlated, keeps its
        # individual ticket unmarked. (Preview showed 0 such alerts.)
        continue
    by_host[hostname].append((stamp, entry["alert_id"]))

clusters = []
for hostname, items in by_host.items():
    items.sort(key=lambda pair: (pair[0], pair[1]))
    current = [items[0]]
    for prev, cur in zip(items, items[1:]):
        if cur[0] - prev[0] <= WINDOW:
            current.append(cur)
        else:
            clusters.append((hostname, current))
            current = [cur]
    clusters.append((hostname, current))

incidents = [(host, cluster) for host, cluster in clusters if len(cluster) > 1]

# ---------------------------------------------------------------------------
# Prior-batch classifications (inheritance source) and file rewrite map
# ---------------------------------------------------------------------------
BATCH_FILES = ["batch1_clearcut_tp.json", "batch2_clearcut_fp.json",
               "batch3_benign.json", "batch4_auth.json",
               "batch5_proc_net.json"]
prior = {}          # alert_id -> (classification, source_file)
batch_payloads = {}  # source_file -> loaded ticket list
for name in BATCH_FILES:
    path = os.path.join(tickets_dir, name)
    if not os.path.isfile(path):
        continue
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if isinstance(payload, list):
        batch_payloads[name] = payload
        for ticket in payload:
            if isinstance(ticket, dict) and ticket.get("alert_id"):
                prior[ticket["alert_id"]] = (
                    ticket.get("classification"), name)

grouped_alerts = {aid for _, cluster in incidents for _, aid in cluster}

# ---------------------------------------------------------------------------
# Incident assembly
# ---------------------------------------------------------------------------
CRIT_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, None: -1}

incident_tickets = []
for hostname, cluster in incidents:
    cluster_sorted = sorted(cluster, key=lambda pair: (pair[0], pair[1]))
    start_dt = cluster_sorted[0][0]
    end_dt = cluster_sorted[-1][0]
    alert_ids = [aid for _, aid in cluster_sorted]
    conf = "high_confidence" if len(alert_ids) >= 3 else "medium_confidence"

    # Highest asset criticality across the group.
    crit = None
    for aid in alert_ids:
        entry = entries.get(aid) or {}
        asset = entry.get("asset") or {}
        entry_crit = (asset.get("criticality") or "unknown").upper()
        if CRIT_RANK.get(entry_crit, -1) > CRIT_RANK.get(crit, -1):
            crit = entry_crit

    # Classification: inheritance from prior batches, else fresh eval.
    tp_inherited = [aid for aid in alert_ids
                    if prior.get(aid, (None,))[0] == "true_positive"]
    if tp_inherited:
        classification = "true_positive"
        class_basis = ("inherited: %d of %d contributing alerts classified "
                       "true_positive in batches 1-5" %
                       (len(tp_inherited), len(alert_ids)))
    else:
        scores = [entries.get(aid, {}).get("priority_score") or 0
                  for aid in alert_ids]
        classification = "true_positive" if max(scores) >= 5 \
            else "false_positive"
        class_basis = ("fresh evaluation from highest group "
                       "priority_score %s" % max(scores))

    if conf == "high_confidence" and crit in ("CRITICAL", "HIGH"):
        action = "escalate_tier2"
        analyst_seconds = 600
    else:
        action = "monitor"
        analyst_seconds = 300

    evidence_refs = sorted({entries[aid]["event_ref"] for aid in alert_ids
                            if entries.get(aid, {}).get("event_ref")})
    techniques = sorted({t for aid in alert_ids
                         for t in (entries.get(aid, {})
                                   .get("attack_techniques") or [])})
    ioc_merged = {}
    for aid in alert_ids:
        for hit in (entries.get(aid, {}).get("ioc_hits") or []):
            key = (hit.get("indicator"), hit.get("reputation"))
            ioc_merged.setdefault(key, hit)
    ioc_hits = list(ioc_merged.values())

    start_iso = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    ticket_id = "incident_%s_%s" % (hostname, start_iso)

    incident_tickets.append({
        "ticket_id": ticket_id,
        "alert_id": None,  # incident-level record, not an individual alert
        "classification": classification,
        "justification":
            "correlated incident on %s: %d alerts within %s..%s "
            "(chain-linked gaps <=600s); %s; confidence %s; asset "
            "criticality %s; techniques %s; %d distinct IOC indicators hit"
            % (hostname, len(alert_ids), start_iso,
               end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"), class_basis, conf,
               crit, ", ".join(techniques) or "none", len(ioc_hits)),
        "evidence_refs": evidence_refs,
        "ioc_hits": ioc_hits,
        "attack_techniques": techniques,
        "recommended_action": action,
        "analyst_time_seconds": analyst_seconds,
        "created_at": entries[alert_ids[0]].get("generated_at"),
        "contributing_alerts": alert_ids,
        "incident_window": {"start": start_iso,
                            "end": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")},
        "confidence": conf,
    })

incident_tickets.sort(key=lambda t: (t["incident_window"]["start"], t["ticket_id"]))

out_path = os.path.join(tickets_dir, "batch6_incidents.json")
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(incident_tickets, fh, indent=2)
    fh.write("\n")

# ---------------------------------------------------------------------------
# Back-propagate grouped flags into batch 1-5 ticket files (idempotent)
# ---------------------------------------------------------------------------
incident_of = {}
for ticket in incident_tickets:
    for aid in ticket["contributing_alerts"]:
        incident_of[aid] = ticket["ticket_id"]

regrouped_files = set()
for name, payload in batch_payloads.items():
    changed = False
    for ticket in payload:
        if not isinstance(ticket, dict):
            continue
        aid = ticket.get("alert_id")
        if aid in incident_of:
            if ticket.get("grouped") is not True \
                    or ticket.get("incident_ticket_id") != incident_of[aid]:
                changed = True
            ticket["grouped"] = True
            ticket["incident_ticket_id"] = incident_of[aid]
            regrouped_files.add(name)
    if changed:
        with open(os.path.join(tickets_dir, name), "w",
                  encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
ACTION_SHORT = {"escalate_tier2": "escalate", "monitor": "monitor"}
print("batch 6 correlated incidents")
for ticket in incident_tickets:
    print("  %-52s alerts=%-4d %-16s %s"
          % (ticket["ticket_id"][:52], len(ticket["contributing_alerts"]),
             ticket["confidence"], ACTION_SHORT[ticket["recommended_action"]]))
print("incidents assembled      : %d" % len(incident_tickets))
print("alerts regrouped         : %d" % len(grouped_alerts))
print("null-hostname excluded   : %d (individual tickets retained)"
      % skipped_null_host)
print("batch files updated      : %s" % ", ".join(sorted(regrouped_files))
      if regrouped_files else "batch files updated      : none")
print("tickets/batch6_incidents.json")
PY
