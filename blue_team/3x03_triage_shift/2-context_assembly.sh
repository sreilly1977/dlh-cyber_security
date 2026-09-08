#!/bin/bash
# Name: 2-context_assembly.sh
# Purpose: Merge the 3x02 alert queue with the 3x00 asset inventory and event
#          store, 3x01 host baseline profiles, and 3x03 IOC context into a
#          single enriched_queue.json. Downstream triage scripts read only
#          the enriched queue. Also ensures the tickets/ output directory
#          exists.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"

QUEUE_JSON="$CATALOG_DIR/alerts/alert_queue.json"
INVENTORY_JSON="$HANDOFF_DIR/context/asset_inventory.json"
EVENTS_JSON="$HANDOFF_DIR/data/enriched_events.json"
BASELINE_JSON="$BASELINE_PKG/baselines/baseline_summary.json"
IOC_JSON="$ASSETS_DIR/ioc_context.json"

for f in "$QUEUE_JSON" "$INVENTORY_JSON" "$EVENTS_JSON" "$BASELINE_JSON" "$IOC_JSON"; do
    if [[ ! -r "$f" ]]; then
        echo "ERROR: required input not readable: $f" >&2
        exit 1
    fi
done

mkdir -p "$TRIAGE_PKG/tickets"

QUEUE_JSON="$QUEUE_JSON" INVENTORY_JSON="$INVENTORY_JSON" EVENTS_JSON="$EVENTS_JSON" \
BASELINE_JSON="$BASELINE_JSON" IOC_JSON="$IOC_JSON" \
OUT_PATH="$TRIAGE_PKG/enriched_queue.json" \
python3 - <<'PY'
import json
import os
import sys

queue_path = os.environ["QUEUE_JSON"]
inventory_path = os.environ["INVENTORY_JSON"]
events_path = os.environ["EVENTS_JSON"]
baseline_path = os.environ["BASELINE_JSON"]
ioc_path = os.environ["IOC_JSON"]
out_path = os.environ["OUT_PATH"]


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def norm(name):
    """Normalize hostname spelling variants: db-patient-01 == db_patient_01 == dbpatient01."""
    if not isinstance(name, str):
        return None
    return name.replace("-", "").replace("_", "").lower()


class Lookup:
    """Exact-match first, then normalized-spelling fallback."""

    def __init__(self, mapping):
        self.exact = mapping
        self.norm = {norm(k): v for k, v in mapping.items()}

    def get(self, key):
        if key in self.exact:
            return self.exact[key]
        return self.norm.get(norm(key))


with open(queue_path, encoding="utf-8") as fh:
    queue = load_json(queue_path)
inventory = load_json(inventory_path)
baseline = load_json(baseline_path)
ioc_doc = load_json(ioc_path)

assets_by_host = {a["hostname"]: a for a in inventory.get("assets", []) if isinstance(a, dict)}
assets_by_ip = {a.get("ip"): a for a in inventory.get("assets", []) if a.get("ip")}
asset_lookup = Lookup(assets_by_host)

# Stream the NDJSON event store once, keeping only referenced records.
wanted_refs = {a.get("event_ref") for a in queue if isinstance(a, dict)}
events_by_ref = {}
with open(events_path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = rec.get("record_id")
        if rid in wanted_refs:
            events_by_ref[rid] = rec

# Host-keyed baseline slices.
auth_lookup = Lookup(baseline.get("auth", {}).get("per_host", {}))
proc_pairs_lookup = Lookup(baseline.get("process", {}).get("parent_child_pairs", {}))
proc_perhost = baseline.get("process", {}).get("per_host", {})
proc_perhost_lookup = Lookup(proc_perhost) if isinstance(proc_perhost, dict) else None
net_dest_lookup = Lookup(baseline.get("network", {}).get("per_host_destinations", {}))
net_ports_lookup = Lookup(baseline.get("network", {}).get("per_host_ports", {}))

indicators = ioc_doc.get("indicators", {})


def priority_band(score):
    if isinstance(score, (int, float)) and score >= 20:
        return "critical"
    if isinstance(score, (int, float)) and score >= 10:
        return "high"
    if isinstance(score, (int, float)) and score >= 5:
        return "medium"
    return "low"


def collect_iocs(record):
    """Match IOC indicators against any IP/domain field in the alert + event."""
    candidates = set()
    summary = record.get("event_summary") or {}
    event = record.get("event_record") or {}
    for value in (summary.get("src_ip"), summary.get("dst_ip"),
                  event.get("src_ip"), event.get("dst_ip")):
        if isinstance(value, str):
            candidates.add(value)
    hits = []
    for indicator in sorted(candidates):
        entry = indicators.get(indicator)
        if entry is None:
            continue
        merged = dict(entry)
        merged["indicator"] = indicator
        merged["ioc_flag"] = entry.get("reputation") != "clean"
        hits.append(merged)
    return hits


stats = {"alerts": 0, "assets": 0, "missing_asset": 0, "baseline": 0, "ioc": 0}
rep_counts = {}
enriched = []

for alert in queue:
    if not isinstance(alert, dict):
        continue
    stats["alerts"] += 1
    entry = dict(alert)
    event = events_by_ref.get(alert.get("event_ref"), {})

    # Asset resolution: summary hostname -> event hostname -> event IPs -> summary src_ip
    asset = asset_lookup.get((alert.get("event_summary") or {}).get("hostname"))
    asset_source = "asset_inventory.hostname"
    if asset is None and event:
        asset = asset_lookup.get(event.get("hostname"))
        asset_source = "event_record.hostname"
    if asset is None and event:
        for ip in (event.get("dst_ip"), event.get("src_ip")):
            if ip in assets_by_ip:
                asset = assets_by_ip[ip]
                asset_source = "asset_inventory.ip"
                break
    if asset is None and (alert.get("event_summary") or {}).get("src_ip") in assets_by_ip:
        asset = assets_by_ip[alert["event_summary"]["src_ip"]]
        asset_source = "asset_inventory.ip"
    if asset is None:
        stats["missing_asset"] += 1
    else:
        stats["assets"] += 1
        asset = dict(asset)
        asset["network_zone"] = asset.get("zone")
        asset["asset_join_source"] = asset_source
    entry["asset"] = asset

    # Baseline profile for the host, sliced by event category.
    host = None
    for candidate in ((alert.get("event_summary") or {}).get("hostname"),
                      event.get("hostname"), (asset or {}).get("hostname")):
        if isinstance(candidate, str) and candidate:
            host = candidate
            break
    profile = {}
    category = (alert.get("event_summary") or {}).get("event_category") \
        or event.get("event_category")
    if host:
        if category == "authentication":
            profile["auth_per_host"] = auth_lookup.get(host)
        elif category == "process":
            profile["process_parent_child_pairs"] = proc_pairs_lookup.get(host)
            if proc_perhost_lookup is not None:
                profile["process_per_host"] = proc_perhost_lookup.get(host)
        elif category in ("network", "firewall"):
            profile["network_per_host_destinations"] = net_dest_lookup.get(host)
            profile["network_per_host_ports"] = net_ports_lookup.get(host)
        if not any(v is not None for v in profile.values()):
            profile = {"auth_per_host": auth_lookup.get(host),
                       "process_parent_child_pairs": proc_pairs_lookup.get(host),
                       "network_per_host_destinations": net_dest_lookup.get(host)}
    entry["baseline_host_profile"] = profile if profile else None
    if any(v is not None for v in (entry["baseline_host_profile"] or {}).values()):
        stats["baseline"] += 1

    entry["event_record"] = event or None

    ioc_hits = collect_iocs({"event_summary": alert.get("event_summary"),
                             "event_record": event})
    entry["ioc_hits"] = ioc_hits
    if ioc_hits:
        stats["ioc"] += 1
    for hit in ioc_hits:
        rep_counts[hit["reputation"]] = rep_counts.get(hit["reputation"], 0) + 1

    entry["priority_band"] = priority_band(alert.get("priority_score"))
    enriched.append(entry)

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(enriched, fh, indent=2)
    fh.write("\n")

size_kb = os.path.getsize(out_path) // 1024
print("alerts processed          : %d" % stats["alerts"])
print("assets joined             : %d" % stats["assets"])
print("missing asset records     : %d" % stats["missing_asset"])
print("alerts with IOC hits      : %d" % stats["ioc"])
for rep in ("malicious", "suspicious", "unknown", "clean"):
    if rep in rep_counts:
        print("  %-23s: %d" % (rep, rep_counts[rep]))
print("baseline profiles joined  : %d" % stats["baseline"])
print("enriched_queue.json written (%d KB)" % size_kb)
PY
