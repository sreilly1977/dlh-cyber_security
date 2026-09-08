#!/bin/bash
# Name: 4-triage_clearcut_fp.sh
# Purpose: Process Batch 2 clear-cut false positives from enriched_queue.json.
#          Applies four FP signatures in order (first match wins):
#            1. service_account_activity - alert user matches a registered
#               service account (full name or bare stem) on an auth/process rule
#            2. management_subnet - src_ip falls in the management range and the
#               rule is a network rule (ADMIN zone CIDRs from network_zones.json
#               stand in for the absent inventory management_subnets field)
#            3. baseline_match - referenced process_name is in the host's
#               baseline process set (process.per_host, fallback to
#               parent_child_pairs)
#            4. clean_ioc_no_deviation - at least one IOC hit, all clean,
#               and no category-relevant baseline deviation
#          Writes locked-schema false_positive tickets tagged with fp_reason
#          to tickets/batch2_clearcut_fp.json, excluding alerts already
#          classified in batch 1. One fp_reason per ticket for T10 aggregation.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
INVENTORY_JSON="$HANDOFF_DIR/context/asset_inventory.json"
ZONES_JSON="$HANDOFF_DIR/context/network_zones.json"
TP_BATCH="$TRIAGE_PKG/tickets/batch1_clearcut_tp.json"
OUT_PATH="$TRIAGE_PKG/tickets/batch2_clearcut_fp.json"

if [[ ! -r "$ENRICHED_JSON" ]]; then
    echo "ERROR: $ENRICHED_JSON not found (run 2-context_assembly.sh first)" >&2
    exit 1
fi
if [[ ! -r "$INVENTORY_JSON" ]]; then
    echo "ERROR: $INVENTORY_JSON not found" >&2
    exit 1
fi
if [[ ! -r "$ZONES_JSON" ]]; then
    echo "ERROR: $ZONES_JSON not found" >&2
    exit 1
fi

mkdir -p "$TRIAGE_PKG/tickets"

ENRICHED_PATH="$ENRICHED_JSON" \
INVENTORY_PATH="$INVENTORY_JSON" \
ZONES_PATH="$ZONES_JSON" \
TP_PATH="$TP_BATCH" \
OUT_PATH="$OUT_PATH" \
python3 - <<'PY'
import ipaddress
import json
import os
import uuid

enriched_path = os.environ["ENRICHED_PATH"]
inventory_path = os.environ["INVENTORY_PATH"]
zones_path = os.environ["ZONES_PATH"]
tp_path = os.environ["TP_PATH"]
out_path = os.environ["OUT_PATH"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
with open(inventory_path, encoding="utf-8") as fh:
    inventory = json.load(fh)
with open(zones_path, encoding="utf-8") as fh:
    zones_doc = json.load(fh)

# Alerts already classified true_positive in batch 1 are excluded.
already_classified = set()
if os.path.isfile(tp_path):
    with open(tp_path, encoding="utf-8") as fh:
        already_classified = {t.get("alert_id") for t in json.load(fh)}

# --- Signature 1 data: registered service accounts, full name + bare stem --
SERVICE_PREFIX = "svc_"
service_meta = {}
for account in inventory.get("service_accounts", []):
    if not (isinstance(account, dict) and isinstance(account.get("account"), str)):
        continue
    name = account["account"]
    key = name.lower()
    service_meta[key] = account
    if key.startswith(SERVICE_PREFIX):
        service_meta[key[len(SERVICE_PREFIX):]] = account

# --- Signature 2 data: management range (ADMIN zone CIDRs) -------------------
mgmt_networks = []
for zone in zones_doc.get("zones", []):
    zone_text = ("%s %s" % ((zone.get("zone_id") or ""),
                            (zone.get("name") or ""))).lower()
    if "admin" in zone_text or "mgmt" in zone_text or "manage" in zone_text:
        for cidr in zone.get("cidrs", []):
            try:
                mgmt_networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                continue

# --- Category resolution ------------------------------------------------------
CATEGORY_MAP = {
    "login_failure": "authentication",
    "login_success": "authentication",
    "account_lockout": "authentication",
    "privilege_escalation": "authentication",
    "logout": "authentication",
    "process_start": "process",
    "process_stop": "process",
    "child_process_spawn": "process",
    "network_connection_outbound": "network",
    "network_connection_inbound": "network",
    "network_blocked": "network",
    "network_alert": "network",
}

def alert_category(alert):
    summary = alert.get("event_summary") or {}
    event = alert.get("event_record") or {}
    for value in (summary.get("event_category"), event.get("event_category")):
        if value in ("authentication", "process", "network", "firewall"):
            return value
    label = summary.get("canonical_label") or event.get("canonical_label")
    return CATEGORY_MAP.get(label)

def event_host(alert):
    summary = alert.get("event_summary") or {}
    event = alert.get("event_record") or {}
    host = summary.get("hostname") or event.get("hostname")
    return host if isinstance(host, str) and host else "(unattributed)"

# --- Signature 3 helper: expected process set for the host -------------------
def expected_processes(alert):
    profile = alert.get("baseline_host_profile") or {}
    per_host = profile.get("process_per_host")
    if isinstance(per_host, dict) and per_host:
        return {str(k).lower() for k in per_host.keys()}
    procs = set()
    pairs = profile.get("process_parent_child_pairs")
    if isinstance(pairs, list):
        for pair in pairs:
            if isinstance(pair, dict):
                for key in ("parent", "child"):
                    value = pair.get(key)
                    if isinstance(value, str):
                        procs.add(value.lower())
    return procs

# --- Baseline deviation check (used by signature 4) ---------------------------
def baseline_deviation_present(alert):
    profile = alert.get("baseline_host_profile") or {}
    if not any(v is not None for v in profile.values()):
        return False
    summary = alert.get("event_summary") or {}
    event = alert.get("event_record") or {}
    category = alert_category(alert)
    if category in ("network", "firewall"):
        destinations = profile.get("network_per_host_destinations")
        dst = summary.get("dst_ip") or event.get("dst_ip")
        if isinstance(destinations, dict) and dst and dst not in destinations:
            return True
    if category == "process":
        process = event.get("process_name") or summary.get("process_name")
        if isinstance(process, str) and process:
            if process.lower() not in expected_processes(alert):
                return True
    return False

# --- Signature evaluation, first match wins -----------------------------------
def match_signature(alert):
    summary = alert.get("event_summary") or {}
    event = alert.get("event_record") or {}
    category = alert_category(alert)
    user = summary.get("user") or event.get("user")
    hostname = event_host(alert)

    # Signature 1: service account on auth/process rule
    if isinstance(user, str) and user.lower() in service_meta:
        if category in ("authentication", "process"):
            meta = service_meta[user.lower()]
            permitted = ", ".join(meta.get("permitted_hosts") or ["unspecified"])
            schedule = meta.get("schedule") or "unspecified"
            return ("service_account_activity",
                    "user '%s' matches registered service account '%s' "
                    "(permitted hosts: %s; schedule: %s) and the rule covers "
                    "%s activity" % (user, meta.get("account", user),
                                     permitted, schedule, category))

    # Signature 2: management-subnet source on a network rule
    if category in ("network", "firewall"):
        src = summary.get("src_ip") or event.get("src_ip")
        if isinstance(src, str):
            try:
                addr = ipaddress.ip_address(src)
            except ValueError:
                addr = None
            if addr is not None:
                for net in mgmt_networks:
                    if addr in net:
                        return ("management_subnet",
                                "src_ip %s falls within management subnet %s "
                                "and the rule covers %s activity"
                                % (src, net, category))

    # Signature 3: process_name in the host's baseline set
    process = event.get("process_name") or summary.get("process_name")
    if isinstance(process, str) and process and hostname != "(unattributed)":
        procs = expected_processes(alert)
        if procs and process.lower() in procs:
            return ("baseline_match",
                    "process_name '%s' appears in the baseline process set for "
                    "host %s (process.per_host)" % (process, hostname))

    # Signature 4: clean IOCs only, no baseline deviation
    ioc_hits = alert.get("ioc_hits") or []
    if ioc_hits and all(h.get("reputation") == "clean" for h in ioc_hits):
        if not baseline_deviation_present(alert):
            indicators = ", ".join(h.get("indicator", "?") for h in ioc_hits)
            return ("clean_ioc_no_deviation",
                    "all IOC hits (%s) carry reputation=clean and no "
                    "category-relevant baseline deviation is present"
                    % indicators)

    return None

EST_SECONDS = {"critical": 120, "high": 180, "medium": 240, "low": 300}

tickets = []
for entry in enriched:
    if entry.get("alert_id") in already_classified:
        continue
    matched = match_signature(entry)
    if matched is None:
        continue
    fp_reason, justification = matched
    tickets.append({
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                    "meddefense.tickets." + entry["alert_id"])),
        "alert_id": entry["alert_id"],
        "classification": "false_positive",
        "justification": justification,
        "evidence_refs": [entry["event_ref"]],
        "ioc_hits": entry.get("ioc_hits", []),
        "attack_techniques": entry.get("attack_techniques", []),
        "recommended_action": "tune_rule",
        "fp_reason": fp_reason,
        "analyst_time_seconds": EST_SECONDS.get(entry.get("priority_band"), 300),
        "created_at": entry.get("generated_at"),
    })

tickets.sort(key=lambda t: t["alert_id"])
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(tickets, fh, indent=2)
    fh.write("\n")

reason_order = ["service_account_activity", "management_subnet",
                "baseline_match", "clean_ioc_no_deviation"]
reason_counts = {r: 0 for r in reason_order}
for t in tickets:
    reason_counts[t["fp_reason"]] += 1

by_id = {e["alert_id"]: e for e in enriched}
print("batch 2 clear-cut false positives")
for t in tickets:
    src_alert = by_id[t["alert_id"]]
    rule = src_alert.get("rule_title") or ""
    print("  %-14s %-28s %-15s CLOSE  %s"
          % (t["alert_id"][:14], rule[:28],
             str(event_host(src_alert))[:15], t["fp_reason"]))
print("batch size               : %d" % len(tickets))
for reason in reason_order:
    print("  %-25s: %d" % (reason, reason_counts[reason]))
print("tickets written          : %d" % len(tickets))
print("tickets/batch2_clearcut_fp.json")
PY
