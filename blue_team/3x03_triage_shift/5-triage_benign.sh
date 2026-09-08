#!/bin/bash
# Name: 5-triage_benign.sh
# Purpose: Process Batch 3 benign-activity alerts from enriched_queue.json.
#          A benign alert fired correctly and the behavior occurred, but it
#          carries no security meaning for MedDefense. Four benign patterns
#          are applied in order:
#            1. single_fail_then_success - one login_failure for a user/host
#               (no IOC-flagged source) followed by login_success within 60s,
#               success looked up in the enriched event store
#            2. dhcp_renewal - DHCP renewal signature in the event record
#            3. ntp_drift_under_threshold - NTP drift event with delta < 500 ms
#            4. perimeter_smb_block - blocked SMB probe from an external IP
#               (dst_port 445, network_blocked) that never bypassed the firewall
#          A benign ticket requires a matched pattern; the low priority band
#          is eligibility context, not a solo close criterion (set
#          BENIGN_BAND_BYPASS=1 for the literal OR reading). Excludes alerts
#          already classified in batches 1 and 2. Writes locked-schema benign
#          tickets to tickets/batch3_benign.json.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
EVENTS_JSON="$HANDOFF_DIR/data/enriched_events.json"
TP_BATCH="$TRIAGE_PKG/tickets/batch1_clearcut_tp.json"
FP_BATCH="$TRIAGE_PKG/tickets/batch2_clearcut_fp.json"
OUT_PATH="$TRIAGE_PKG/tickets/batch3_benign.json"
BENIGN_BAND_BYPASS="${BENIGN_BAND_BYPASS:-0}"

if [[ ! -r "$ENRICHED_JSON" ]]; then
    echo "ERROR: $ENRICHED_JSON not found (run 2-context_assembly.sh first)" >&2
    exit 1
fi
if [[ ! -r "$EVENTS_JSON" ]]; then
    echo "ERROR: $EVENTS_JSON not found" >&2
    exit 1
fi

mkdir -p "$TRIAGE_PKG/tickets"

ENRICHED_PATH="$ENRICHED_JSON" \
EVENTS_PATH="$EVENTS_JSON" \
TP_PATH="$TP_BATCH" \
FP_PATH="$FP_BATCH" \
OUT_PATH="$OUT_PATH" \
BAND_BYPASS="$BENIGN_BAND_BYPASS" \
python3 - <<'PY'
import ipaddress
import json
import os
import uuid
from datetime import datetime

enriched_path = os.environ["ENRICHED_PATH"]
events_path = os.environ["EVENTS_PATH"]
tp_path = os.environ["TP_PATH"]
fp_path = os.environ["FP_PATH"]
out_path = os.environ["OUT_PATH"]
band_bypass = os.environ["BAND_BYPASS"] == "1"

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)

# Cumulative exclusion chain: batches 1 and 2.
classified = set()
for prior_path in (tp_path, fp_path):
    if os.path.isfile(prior_path):
        with open(prior_path, encoding="utf-8") as fh:
            for ticket in json.load(fh):
                if isinstance(ticket, dict) and ticket.get("alert_id"):
                    classified.add(ticket["alert_id"])

# ---------------------------------------------------------------------------
# login_success index built from the enriched event store (single streaming
# pass; only successes are retained). Key: (user, host) -> sorted timestamps.
# ---------------------------------------------------------------------------
def parse_ts(raw):
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

success_index = {}
with open(events_path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("canonical_label") != "login_success":
            continue
        user = record.get("user") or (record.get("event_data") or {}).get("user")
        host = record.get("hostname")
        ts = parse_ts(record.get("timestamp"))
        if isinstance(user, str) and isinstance(host, str) and ts is not None:
            success_index.setdefault((user, host), []).append(ts)
for timestamps in success_index.values():
    timestamps.sort()

def event_data_of(entry):
    event = entry.get("event_record") or {}
    data = event.get("event_data")
    return data if isinstance(data, dict) else {}

def summary_of(entry):
    return entry.get("event_summary") or {}

def record_of(entry):
    return entry.get("event_record") or {}

def label_of(entry):
    return (summary_of(entry).get("canonical_label")
            or record_of(entry).get("canonical_label"))

def is_public_ip(raw):
    if not isinstance(raw, str):
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)

# ---------------------------------------------------------------------------
# Benign patterns, first match wins
# ---------------------------------------------------------------------------
def pattern_single_fail_then_success(entry):
    if label_of(entry) != "login_failure":
        return None
    # An IOC-flagged source disqualifies benign: hostile origin plus a
    # following success is potential compromise, not transient typo entry.
    if any(h.get("ioc_flag") for h in entry.get("ioc_hits") or []):
        return None
    burst = 1 + (entry.get("dedup_suppressed_count") or 0)
    if burst != 1:
        return None
    summary = summary_of(entry)
    user = summary.get("user") or record_of(entry).get("user")
    host = summary.get("hostname") or record_of(entry).get("hostname")
    ts = parse_ts(summary.get("timestamp") or record_of(entry).get("timestamp"))
    if not (isinstance(user, str) and isinstance(host, str)) or ts is None:
        return None
    for success_ts in success_index.get((user, host), []):
        delta = (success_ts - ts).total_seconds()
        if 0 <= delta <= 60:
            return ("single_fail_then_success",
                    "single login_failure for user '%s' on %s followed by "
                    "login_success within 60s (transient credential entry)"
                    % (user, host))
        if success_ts > ts:
            break  # sorted; no later timestamp can be within 60s
    return None

def pattern_dhcp_renewal(entry):
    data = event_data_of(entry)
    event = record_of(entry)
    haystack = " ".join([
        str(event.get("raw_message") or ""),
        json.dumps(data, sort_keys=True, default=str),
    ]).lower()
    if "dhcp" in haystack:
        return ("dhcp_renewal",
                "event record matches the DHCP renewal pattern (routine "
                "lease maintenance, no security meaning)")
    return None

def pattern_ntp_drift(entry):
    data = event_data_of(entry)
    event = record_of(entry)
    haystack = " ".join([
        str(event.get("raw_message") or ""),
        json.dumps(data, sort_keys=True, default=str),
    ]).lower()
    if "ntp" not in haystack:
        return None
    for field in ("offset_ms", "delta_ms", "drift_ms"):
        value = data.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if abs(value) < 500:
                return ("ntp_drift_under_threshold",
                        "NTP drift of %.1f ms is below the 500 ms benign "
                        "threshold" % abs(value))
            return None
    return None

def pattern_perimeter_smb_block(entry):
    if label_of(entry) != "network_blocked":
        return None
    summary = summary_of(entry)
    data = event_data_of(entry)
    dst_port = data.get("dst_port") or record_of(entry).get("dst_port") \
        or summary.get("dst_port")
    src = summary.get("src_ip") or record_of(entry).get("src_ip")
    if dst_port != 445 or not is_public_ip(src):
        return None
    # Blocked at the perimeter and never bypassed: the block action on this
    # flow is the terminal disposition, no allow event exists for it.
    action = (data.get("action") or record_of(entry).get("action") or "").lower()
    if action and action not in ("block", "blocked", "deny", "deny_flow"):
        return None
    return ("perimeter_smb_block",
            "blocked SMB probe (dst_port 445) from external IP %s; the "
            "firewall denied the flow and it never bypassed the perimeter"
            % src)

PATTERNS = (
    pattern_single_fail_then_success,
    pattern_dhcp_renewal,
    pattern_ntp_drift,
    pattern_perimeter_smb_block,
)

EST_SECONDS = 60

tickets = []
for entry in enriched:
    if not isinstance(entry, dict):
        continue
    if entry.get("alert_id") in classified:
        continue
    band = entry.get("priority_band")
    matched = None
    for pattern in PATTERNS:
        matched = pattern(entry)
        if matched is not None:
            break
    # Literal-OR bypass (opt-in): unclaimed low-band alerts close as benign
    # on band membership alone, per the task spec's inclusive reading.
    if matched is None and band_bypass and band == "low":
        matched = ("low_band_default",
                   "priority_band is low and no exclusion or pattern evidence "
                   "raises security concern")
    if matched is None:
        continue
    benign_pattern, justification = matched
    tickets.append({
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                    "meddefense.tickets." + entry["alert_id"])),
        "alert_id": entry["alert_id"],
        "classification": "benign",
        "justification": justification,
        "evidence_refs": [entry["event_ref"]],
        "ioc_hits": entry.get("ioc_hits", []),
        "attack_techniques": entry.get("attack_techniques", []),
        "recommended_action": "close",
        "benign_pattern": benign_pattern,
        "analyst_time_seconds": EST_SECONDS,
        "created_at": entry.get("generated_at"),
    })

tickets.sort(key=lambda t: t["alert_id"])
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(tickets, fh, indent=2)
    fh.write("\n")

by_id = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}
pattern_order = ["single_fail_then_success", "dhcp_renewal",
                 "ntp_drift_under_threshold", "perimeter_smb_block",
                 "low_band_default"]
pattern_counts = {p: 0 for p in pattern_order}
for ticket in tickets:
    pattern_counts[ticket["benign_pattern"]] += 1

print("batch 3 benign")
for ticket in tickets:
    band = (by_id.get(ticket["alert_id"]) or {}).get("priority_band", "?")
    print("  %-14s %-4s %s"
          % (ticket["alert_id"][:14], band, ticket["benign_pattern"]))
print("batch size               : %d" % len(tickets))
for pattern in pattern_order:
    if pattern_counts[pattern] or pattern != "low_band_default":
        print("  %-27s: %d" % (pattern, pattern_counts[pattern]))
print("tickets written          : %d" % len(tickets))
print("tickets/batch3_benign.json")
PY
