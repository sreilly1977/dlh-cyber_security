#!/bin/bash
# Name: 7-triage_ambiguous_proc_net.sh
# Purpose: Process Batch 5 ambiguous process and network alerts from
#          enriched_queue.json: every process or network alert not classified
#          in batches 1-4. Extraction from the enriched event record:
#            process alerts: process_name (record body), parent_process and
#              command_line from Sysmon-style event_data (ParentImage,
#              ParentCommandLine, CommandLine) with Linux auditd fallbacks
#              (comm, exe, message); scheduled-task 4698 records carry no
#              process detail and extract as null.
#            network alerts: dst_ip, dst_host, dst_port from the record body
#              and event_data (DestinationIp/DestinationHostname/dest_port
#              variants), with IOC reputation already joined by task 2.
#          Decision tree, first match wins:
#            1. any IOC hit reputation == malicious
#                                 -> true_positive, escalate_tier2
#            2. IOC suspicious AND asset criticality critical/high
#                                 -> true_positive, monitor
#            3. IOC suspicious AND asset medium/low AND the process or
#               destination appears in the baseline of a DIFFERENT host
#                                 -> false_positive, tune_rule,
#                                    fp_reason suspicious_but_baseline_known_elsewhere
#            4. IOC clean AND no baseline deviation
#                                 -> false_positive, tune_rule,
#                                    fp_reason clean_ioc_no_deviation
#            5. any other state -> true_positive, monitor, justification
#               documents what was checked
#          Writes locked-schema tickets to tickets/batch5_proc_net.json.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
BASELINE_JSON="$BASELINE_PKG/baselines/baseline_summary.json"
OUT_PATH="$TRIAGE_PKG/tickets/batch5_proc_net.json"

if [[ ! -r "$ENRICHED_JSON" ]]; then
    echo "ERROR: $ENRICHED_JSON not found (run 2-context_assembly.sh first)" >&2
    exit 1
fi
if [[ ! -r "$BASELINE_JSON" ]]; then
    echo "ERROR: $BASELINE_JSON not found" >&2
    exit 1
fi

mkdir -p "$TRIAGE_PKG/tickets"

ENRICHED_PATH="$ENRICHED_JSON" \
BASELINE_PATH="$BASELINE_JSON" \
OUT_PATH="$OUT_PATH" \
python3 - <<'PY'
import json
import os
import uuid

enriched_path = os.environ["ENRICHED_PATH"]
baseline_path = os.environ["BASELINE_PATH"]
out_path = os.environ["OUT_PATH"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
with open(baseline_path, encoding="utf-8") as fh:
    baseline = json.load(fh)

# Cumulative exclusion chain: batches 1-4.
classified = set()
tickets_dir = os.path.dirname(out_path)
for name in ("batch1_clearcut_tp.json", "batch2_clearcut_fp.json",
             "batch3_benign.json", "batch4_auth.json"):
    prior = os.path.join(tickets_dir, name)
    if os.path.isfile(prior):
        with open(prior, encoding="utf-8") as fh:
            for ticket in json.load(fh):
                if isinstance(ticket, dict) and ticket.get("alert_id"):
                    classified.add(ticket["alert_id"])

# ---------------------------------------------------------------------------
# Hostname normalization (same discipline as tasks 2 and 6)
# ---------------------------------------------------------------------------
def norm_host(raw):
    if not isinstance(raw, str) or not raw:
        return None
    return raw.replace("-", "").replace("_", "").lower() or None

# ---------------------------------------------------------------------------
# Global baseline indexes (verified shapes):
#   network.per_host_destinations: hostname -> {dst_ip: count}
#   process.per_host:             hostname -> {process_name: {...}}
# Used for the "present in a DIFFERENT host's baseline" test (branch 3) and
# the same-host deviation test (branch 4).
# ---------------------------------------------------------------------------
net_dests_by_host = {}
raw_dests = baseline.get("network", {}).get("per_host_destinations") or {}
for host, dests in raw_dests.items():
    if isinstance(dests, dict):
        norm = norm_host(host)
        if norm:
            net_dests_by_host[norm] = {ip for ip in dests if isinstance(ip, str)}

proc_by_host = {}
raw_procs = baseline.get("process", {}).get("per_host") or {}
for host, procs in raw_procs.items():
    if isinstance(procs, dict):
        norm = norm_host(host)
        if norm:
            proc_by_host[norm] = {p.lower() for p in procs if isinstance(p, str)}

def baseline_known_elsewhere(kind, value, alert_host_norm):
    """True when value appears in the baseline of a host other than alert's."""
    if value is None:
        return False
    if kind == "destination":
        for host, dests in net_dests_by_host.items():
            if host != alert_host_norm and value in dests:
                return True
    elif kind == "process":
        for host, procs in proc_by_host.items():
            if host != alert_host_norm and value in procs:
                return True
    return False

# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------
def summary_of(entry):
    return entry.get("event_summary") or {}

def record_of(entry):
    return entry.get("event_record") or {}

def event_data_of(entry):
    data = record_of(entry).get("event_data")
    return data if isinstance(data, dict) else {}

def record_field(entry, *names):
    record = record_of(entry)
    data = event_data_of(entry)
    for name in names:
        for source in (record, data, summary_of(entry)):
            if isinstance(source, dict):
                value = source.get(name)
                if value not in (None, ""):
                    return value
    return None

def basename(path):
    if not isinstance(path, str) or not path:
        return None
    return path.replace("\\", "/").rstrip("/").split("/")[-1] or None

def extract_process(entry):
    """(process_name, parent_process, command_line) or Nones."""
    process = record_field(entry, "process_name") \
        or basename(record_field(entry, "Image")) \
        or record_field(entry, "comm")
    parent = basename(record_field(entry, "ParentImage")) \
        or basename(record_field(entry, "ParentCommandLine")) \
        or record_field(entry, "ppid")
    cmdline = record_field(entry, "CommandLine") \
        or record_field(entry, "message") \
        or record_field(entry, "msg")
    return process, parent, cmdline

def extract_network(entry):
    """(dst_ip, dst_host, dst_port) or Nones."""
    dst_ip = record_field(entry, "dst_ip", "DestinationIp", "dest_ip")
    dst_host = record_field(entry, "dst_host", "DestinationHostname",
                            "dns_query", "hostname")
    dst_port = record_field(entry, "dst_port", "DestinationPort",
                            "dest_port")
    return dst_ip, dst_host, dst_port

def alert_category(entry):
    for value in (summary_of(entry).get("event_category"),
                  record_of(entry).get("event_category")):
        if value in ("authentication", "process", "network", "firewall"):
            return value
    return None

def top_ioc(entry):
    """Highest-severity IOC hit: malicious > suspicious > clean."""
    hits = entry.get("ioc_hits") or []
    for rep in ("malicious", "suspicious", "clean"):
        for hit in hits:
            if hit.get("reputation") == rep:
                return hit
    return None

EST_SECONDS = {"escalate": 600, "monitor": 300, "tune": 180}

def decide(entry):
    summary = summary_of(entry)
    category = alert_category(entry)
    hostname = summary.get("hostname") or record_of(entry).get("hostname")
    host_norm = norm_host(hostname)
    asset = entry.get("asset") or {}
    criticality = (asset.get("criticality") or "unknown").upper()
    ioc = top_ioc(entry)
    is_process = category == "process"
    is_network = category in ("network", "firewall")

    if is_process:
        process, parent, cmdline = extract_process(entry)
        dst_ip = dst_host = dst_port = None
    else:
        process = parent = cmdline = None
        dst_ip, dst_host, dst_port = extract_network(entry)

    # Per-host baseline deviation (branch 4 test).
    deviation = False
    if host_norm:
        if is_network and dst_ip:
            deviation = dst_ip not in net_dests_by_host.get(host_norm, set())
        if is_process and process:
            deviation = process.lower() not in proc_by_host.get(host_norm, set())

    base = {
        "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                    "meddefense.tickets."
                                    + entry["alert_id"])),
        "alert_id": entry["alert_id"],
        "evidence_refs": [entry["event_ref"]],
        "ioc_hits": entry.get("ioc_hits", []),
        "attack_techniques": entry.get("attack_techniques", []),
        "created_at": entry.get("generated_at"),
    }

    extracted = "process_name=%s parent_process=%s command_line=%s" % (
        process, parent, cmdline) if is_process else (
        "dst_ip=%s dst_host=%s dst_port=%s" % (dst_ip, dst_host, dst_port))

    # Branch 1: malicious IOC
    if ioc is not None and ioc.get("reputation") == "malicious":
        base.update({
            "classification": "true_positive",
            "recommended_action": "escalate_tier2",
            "decision_branch": 1,
            "justification":
                "proc/net branch 1: IOC %s carries reputation=malicious "
                "(categories: %s; last_seen %s); %s on asset %s "
                "(criticality %s); source %s"
                % (ioc.get("indicator"),
                   ", ".join(ioc.get("categories", [])),
                   ioc.get("last_seen", "unknown"), extracted, hostname,
                   criticality, summary.get("src_ip")),
            "analyst_time_seconds": EST_SECONDS["escalate"],
        })
        return base

    # Branch 2: suspicious IOC, critical/high asset
    if ioc is not None and ioc.get("reputation") == "suspicious" \
            and criticality in ("CRITICAL", "HIGH"):
        base.update({
            "classification": "true_positive",
            "recommended_action": "monitor",
            "decision_branch": 2,
            "justification":
                "proc/net branch 2: IOC %s reputation=suspicious on "
                "critical/high asset %s (%s); %s; elevated watch, not "
                "sufficient for escalation"
                % (ioc.get("indicator"), hostname, criticality, extracted),
            "analyst_time_seconds": EST_SECONDS["monitor"],
        })
        return base

    # Branch 3: suspicious IOC, medium/low asset, baseline-known elsewhere
    if ioc is not None and ioc.get("reputation") == "suspicious" \
            and criticality in ("MEDIUM", "LOW"):
        kind = "process" if is_process else "destination"
        value = (process.lower() if (is_process and process) else None) \
            if is_process else dst_ip
        if baseline_known_elsewhere(kind, value, host_norm):
            base.update({
                "classification": "false_positive",
                "recommended_action": "tune_rule",
                "fp_reason": "suspicious_but_baseline_known_elsewhere",
                "decision_branch": 3,
                "justification":
                    "proc/net branch 3: IOC %s is suspicious but asset %s is "
                    "%s and %s '%s' appears in the baseline of a different "
                    "host; cross-host routine, tuning candidate"
                    % (ioc.get("indicator"), hostname, criticality, kind,
                       value),
                "analyst_time_seconds": EST_SECONDS["tune"],
            })
            return base

    # Branch 4: clean IOC, no baseline deviation
    if ioc is not None and ioc.get("reputation") == "clean" and not deviation:
        base.update({
            "classification": "false_positive",
            "recommended_action": "tune_rule",
            "fp_reason": "clean_ioc_no_deviation",
            "decision_branch": 4,
            "justification":
                "proc/net branch 4: IOC %s is clean and no baseline "
                "deviation for host %s (%s); %s; tuning candidate"
                % (ioc.get("indicator"), hostname, criticality, extracted),
            "analyst_time_seconds": EST_SECONDS["tune"],
        })
        return base

    # Branch 5: any other state
    checked = [
        "IOC hits: %d" % len(entry.get("ioc_hits") or []),
        "top IOC reputation: %s" % (ioc.get("reputation") if ioc else "none"),
        "asset criticality: %s" % criticality,
        "baseline deviation: %s" % ("present" if deviation else "absent"),
        extracted,
    ]
    if is_process:
        checked.append("scheduled-task record: %s" %
                       ("no process detail in event_data (event_id 4698 "
                         "carries EventID only)" if process is None
                        else "process detail present"))
    base.update({
        "classification": "true_positive",
        "recommended_action": "monitor",
        "decision_branch": 5,
        "justification":
            "proc/net branch 5 (checks documented): %s; insufficient "
            "signal for a definitive close, monitoring continues"
            % "; ".join(checked),
        "analyst_time_seconds": EST_SECONDS["monitor"],
    })
    return base

tickets = []
for entry in enriched:
    if not isinstance(entry, dict):
        continue
    if entry.get("alert_id") in classified:
        continue
    category = alert_category(entry)
    if category not in ("process", "network", "firewall"):
        continue
    tickets.append(decide(entry))

tickets.sort(key=lambda t: t["alert_id"])
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(tickets, fh, indent=2)
    fh.write("\n")

ACTION_SHORT = {"escalate_tier2": "escalate", "tune_rule": "tune_rule",
                "monitor": "monitor"}
by_id = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}
branch_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
print("batch 5 ambiguous process and network")
for ticket in tickets:
    src_alert = by_id.get(ticket["alert_id"]) or {}
    rule = src_alert.get("rule_title") or ""
    branch_counts[ticket["decision_branch"]] += 1
    print("  %-14s %-28s %-15s %s"
          % (ticket["alert_id"][:14], rule[:28],
             ticket["classification"],
             ACTION_SHORT[ticket["recommended_action"]]))
print("batch size               : %d" % len(tickets))
for branch in (1, 2, 3, 4, 5):
    print("  branch %d                 : %d" % (branch, branch_counts[branch]))
print("tickets written          : %d" % len(tickets))
print("tickets/batch5_proc_net.json")
PY
