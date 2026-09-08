#!/bin/bash
# Name: 6-triage_ambiguous_auth.sh
# Purpose: Process Batch 4 ambiguous authentication alerts from
#          enriched_queue.json: every authentication alert not classified in
#          batches 1-3. Builds each user's historical login pattern (host set,
#          source IP set, last twenty authentication events) from the enriched
#          event store in one streaming pass. Note: the 3x00 event store keys
#          records by event_category (not canonical_label, which is an alert-
#          queue projection), so history is built from event_category ==
#          "authentication" records with multi-field outcome detection. The
#          baseline's auth.per_user carries counts only, so the event store is
#          the documented source of the historical pattern.
#          Reads max_failures_1h_window from baseline_summary.json, then
#          applies the four-branch decision tree:
#            1. unknown source IP + critical/high asset + host never used by
#               the user            -> true_positive, escalate_tier2
#            2. unknown source IP + medium/low asset + no IOC hit
#                                 -> false_positive, tune_rule,
#                                    fp_reason unknown_ip_low_asset
#            3. known source IP + failure burst between max_failures_1h_window
#               and 2x max_failures_1h_window
#                                 -> false_positive, tune_rule,
#                                    fp_reason baseline_edge_burst
#            4. any other ambiguous state -> true_positive, monitor,
#               uncertainty documented and fields cited
#          Hostname comparison uses normalized names (case, - and _ stripped)
#          to bridge the inventory's spelling variants. Alerts with no
#          recorded src_ip cannot be assessed for IP novelty and fall to
#          branch 4 with the gap documented.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
EVENTS_JSON="$HANDOFF_DIR/data/enriched_events.json"
BASELINE_JSON="$BASELINE_PKG/baselines/baseline_summary.json"
OUT_PATH="$TRIAGE_PKG/tickets/batch4_auth.json"

for f in "$ENRICHED_JSON" "$EVENTS_JSON" "$BASELINE_JSON"; do
    if [[ ! -r "$f" ]]; then
        echo "ERROR: required input not readable: $f" >&2
        exit 1
    fi
done

mkdir -p "$TRIAGE_PKG/tickets"

ENRICHED_PATH="$ENRICHED_JSON" \
EVENTS_PATH="$EVENTS_JSON" \
BASELINE_PATH="$BASELINE_JSON" \
OUT_PATH="$OUT_PATH" \
python3 - <<'PY'
import json
import os
import uuid
from datetime import datetime

enriched_path = os.environ["ENRICHED_PATH"]
events_path = os.environ["EVENTS_PATH"]
baseline_path = os.environ["BASELINE_PATH"]
out_path = os.environ["OUT_PATH"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
with open(baseline_path, encoding="utf-8") as fh:
    baseline = json.load(fh)

MAX_FAILURES = baseline.get("auth", {}).get("max_failures_1h_window")
if not isinstance(MAX_FAILURES, (int, float)) or isinstance(MAX_FAILURES, bool):
    MAX_FAILURES = 9

# Cumulative exclusion chain: batches 1-3.
classified = set()
tickets_dir = os.path.dirname(out_path)
for name in ("batch1_clearcut_tp.json", "batch2_clearcut_fp.json",
             "batch3_benign.json"):
    prior = os.path.join(tickets_dir, name)
    if os.path.isfile(prior):
        with open(prior, encoding="utf-8") as fh:
            for ticket in json.load(fh):
                if isinstance(ticket, dict) and ticket.get("alert_id"):
                    classified.add(ticket["alert_id"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_ts(raw):
    if not isinstance(raw, str):
        return None
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None

def norm_user(raw):
    """Normalize user identity: DOMAIN\\user and user@domain both reduce to
    the bare lowercased username."""
    if not isinstance(raw, str) or not raw:
        return None
    name = raw
    if "\\" in name:
        name = name.split("\\")[-1]
    if "@" in name:
        name = name.split("@")[0]
    name = name.strip().lower()
    return name or None

def norm_host(raw):
    """Normalize hostname spelling variants: db-patient-01 == db_patient_01 ==
    dbpatient01."""
    if not isinstance(raw, str) or not raw:
        return None
    return raw.replace("-", "").replace("_", "").lower() or None

def is_auth_record(record):
    """An authentication record in the 3x00 event store. The store keys
    records by event_category; canonical_label is a 3x02 alert projection,
    but is accepted if present at any nesting for robustness."""
    if record.get("event_category") == "authentication":
        return True
    data = record.get("event_data")
    if isinstance(data, dict) and data.get("event_category") == "authentication":
        return True
    return False

def record_outcome(record):
    """Classify an auth record as a success or failure. Indicator priority:
    canonical_label, then Windows event_id (4624=success, 4625=failure),
    then outcome/result/status strings, then boolean flags."""
    data = record.get("event_data")
    if not isinstance(data, dict):
        data = {}
    label = record.get("canonical_label") or data.get("canonical_label")
    if isinstance(label, str):
        if label == "login_success":
            return "success"
        if label == "login_failure":
            return "failure"
    event_id = record.get("event_id") or data.get("EventID") \
        or (data.get("EventID") if isinstance(data.get("EventID"), int) else None)
    try:
        eid = int(event_id := record.get("event_id") or data.get("EventID") or 0)
    except (TypeError, ValueError):
        eid = 0
    if eid == 4624:
        return "success"
    if eid == 4625:
        return "failure"
    for field in ("outcome", "result", "status"):
        value = data.get(field)
        if isinstance(value, str):
            lowered = value.lower()
            if lowered in ("success", "successful", "ok"):
                return "success"
            if value.lower() in ("failure", "failed", "error"):
                return "failure"
    return None

def record_field(record, *names):
    """Fetch the first non-null field from the record body or event_data."""
    sources = [record, record.get("event_data") or {}]
    for name in names:
        for source in sources:
            if isinstance(source, dict):
                value = source.get(name)
                if value not in (None, ""):
                    return value
    return None

# ---------------------------------------------------------------------------
# Per-user historical login pattern from the event store (single pass).
# user -> {"hosts": set(norm hosts), "src_ips": set, "events": [...]}
# events = [(ts, outcome, host, src_ip)]; last twenty per user after sorting.
# ---------------------------------------------------------------------------
user_history = {}
with open(events_path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not is_auth_record(record):
            continue
        user = norm_user(record_field(record, "user", "TargetUserName",
                                      "SubjectUserName"))
        if user is None:
            continue
        host_norm = norm_host(record_field(record, "hostname",
                                          "TargetHostname", "WorkstationName"))
        src_ip = record_field(record, "src_ip", "IpAddress",
                              "SourceIp", "SourceAddress")
        ts = parse_ts(record_field(record, "timestamp", "TimeCreated"))
        outcome = record_outcome(record)
        profile = user_history.setdefault(user,
                                          {"hosts": set(), "src_ips": set(),
                                           "events": []})
        if host_norm is not None:
            profile["hosts"].add(host_norm)
        if isinstance(src_ip, str) and src_ip:
            profile["src_ips"].add(src_ip)
        profile["events"].append((ts, outcome, host_norm, src_ip))
for profile in user_history.values():
    profile["events"].sort(key=lambda ev: (ev[0] is None, ev[0]))
    profile["events"] = profile["events"][-20:]

# ---------------------------------------------------------------------------
# Alert accessors (alert summaries DO carry canonical_label)
# ---------------------------------------------------------------------------
def summary_of(entry):
    return entry.get("event_summary") or {}

def record_of(entry):
    return entry.get("event_record") or {}

def label_of(entry):
    return (summary_of(entry).get("canonical_label")
            or record_of(entry).get("canonical_label"))

def alert_category(entry):
    for value in (summary_of(entry).get("event_category"),
                  record_of(entry).get("event_category")):
        if value in ("authentication", "process", "network", "firewall"):
            return value
    return {"login_failure": "authentication",
            "login_success": "authentication",
            "account_lockout": "authentication",
            "privilege_escalation": "authentication",
            "logout": "authentication"}.get(label_of(entry))

EST_SECONDS = {"escalate": 600, "monitor": 300, "tune": 180}

def decide(entry):
    """Apply the four-branch decision tree. Returns a ticket dict."""
    summary = summary_of(entry)
    user_raw = record_field(summary_of(entry) or {}, "user") \
        or record_field(record_of(entry) or {}, "user")
    user = norm_user(user_raw) or str(user_raw)
    src_ip = summary.get("src_ip") or record_of(entry).get("src_ip")
    hostname = summary.get("hostname") or record_of(entry).get("hostname")
    asset = entry.get("asset") or {}
    criticality = (asset.get("criticality") or "unknown")
    ioc_hits = entry.get("ioc_hits") or []
    profile = user_history.get(user,
                               {"hosts": set(), "src_ips": set(),
                                "events": []})

    host_norm = norm_host(hostname)
    known_host = host_norm is not None and host_norm in profile["hosts"]
    ip_present = isinstance(src_ip, str) and src_ip.strip() != ""
    known_ip = ip_present and src_ip in profile["src_ips"]
    high_value = criticality.upper() in ("CRITICAL", "HIGH")
    burst = 1 + (entry.get("dedup_suppressed_count") or 0)

    base = {
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                    "meddefense.tickets."
                                    + entry["alert_id"])),
        "alert_id": entry["alert_id"],
        "evidence_refs": [entry["event_ref"]],
        "ioc_hits": ioc_hits,
        "attack_techniques": entry.get("attack_techniques", []),
        "created_at": entry.get("generated_at"),
    }

    # Branch 1: unknown source IP, critical/high asset, host never used before
    if ip_present and (not known_ip) and high_value and not known_host:
        base.update({
            "classification": "true_positive",
            "recommended_action": "escalate_tier2",
            "decision_branch": 1,
            "justification":
                "ambiguous-auth branch 1: src_ip %s is absent from user "
                "'%s' historical source set (%d distinct IPs across %d "
                "authentication events in the store), asset %s has "
                "criticality %s, and '%s' has no prior authentication to "
                "this host (normalized match; %d hosts in history)"
                % (src_ip, user, len(profile["src_ips"]),
                   len(profile["events"]), hostname, criticality, user,
                   len(profile["hosts"])),
            "analyst_time_seconds": EST_SECONDS["escalate"],
        })
        return base

    # Branch 2: unknown source IP, medium/low asset, no IOC hit
    if ip_present and (not known_ip) and not high_value \
            and criticality.upper() in ("MEDIUM", "LOW") and not ioc_hits:
        base.update({
            "classification": "false_positive",
            "recommended_action": "tune_rule",
            "fp_reason": "unknown_ip_low_asset",
            "decision_branch": 2,
            "justification":
                "ambiguous-auth branch 2: src_ip %s is absent from user "
                "'%s' historical source set (%d distinct IPs across %d "
                "authentication events in the store), but asset %s "
                "criticality is %s and no IOC hit is present; tuning "
                "candidate" % (src_ip, user, len(profile["src_ips"]),
                               len(profile["events"]), hostname,
                               criticality),
            "analyst_time_seconds": EST_SECONDS["tune"],
        })
        return base

    # Branch 3: known source IP + baseline-edge failure burst
    if known_ip and label_of(entry) == "login_failure":
        if MAX_FAILURES <= burst <= MAX_FAILURES * 2:
            base.update({
                "classification": "false_positive",
                "recommended_action": "tune_rule",
                "fp_reason": "baseline_edge_burst",
                "decision_branch": 3,
                "justification":
                    "ambiguous-auth branch 3: burst of %d failures from "
                    "known source %s (present in user '%s' historical set) "
                    "sits between max_failures_1h_window (%d) and 2x (%d); "
                    "baseline-edge noise"
                    % (burst, src_ip, user, int(MAX_FAILURES),
                       int(MAX_FAILURES) * 2),
                "analyst_time_seconds": EST_SECONDS["tune"],
            })
            return base

    # Branch 4: any other ambiguous state -> true_positive, monitor
    recent = profile["events"]
    successes = sum(1 for _, outcome, _, _ in recent
                    if outcome == "success")
    if not ip_present:
        gap_note = ("src_ip is not recorded for this event, so source "
                    "novelty cannot be assessed")
    else:
        gap_note = ("src_ip %s %s user '%s' historical source set"
                    % (src_ip,
                       "is in" if known_ip else "is absent from", user))
    base.update({
        "classification": "true_positive",
        "recommended_action": "monitor",
        "decision_branch": 4,
        "justification":
            "ambiguous-auth branch 4 (uncertainty documented): %s; host %s "
            "%s that user's host set (normalized match); asset criticality "
            "%s; %d IOC hits; %d of last %d authentication events for this "
            "user are successes; insufficient signal for a definitive "
            "close, monitoring continues"
            % (gap_note, hostname,
               "is in" if known_host else "is absent from",
               criticality, len(ioc_hits), successes, len(recent)),
        "analyst_time_seconds": EST_SECONDS["monitor"],
    })
    return base

tickets = []
for entry in enriched:
    if not isinstance(entry, dict):
        continue
    if entry.get("alert_id") in classified:
        continue
    if alert_category(entry) != "authentication":
        continue
    tickets.append(decide(entry))

tickets.sort(key=lambda t: t["alert_id"])
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(tickets, fh, indent=2)
    fh.write("\n")

ACTION_SHORT = {"escalate_tier2": "escalate", "tune_rule": "tune_rule",
                "monitor": "monitor"}
by_id = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}
branch_counts = {1: 0, 2: 0, 3: 0, 4: 0}
print("batch 4 ambiguous authentication")
for ticket in tickets:
    src_alert = by_id.get(ticket["alert_id"]) or {}
    rule = src_alert.get("rule_title") or ""
    branch_counts[ticket["decision_branch"]] += 1
    print("  %-14s %-28s %-15s %s"
          % (ticket["alert_id"][:14], rule[:28],
             ticket["classification"], ACTION_SHORT[ticket["recommended_action"]]))
print("batch size               : %d" % len(tickets))
for branch in (1, 2, 3, 4):
    print("  branch %d                 : %d" % (branch, branch_counts[branch]))
print("tickets written          : %d" % len(tickets))
print("tickets/batch4_auth.json")
PY
