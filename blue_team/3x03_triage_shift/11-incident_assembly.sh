#!/bin/bash
# Name: 11-incident_assembly.sh
# Purpose: Process Batch 9 incident assembly. Reads every ticket produced
#          in batches 1-7 plus enriched_queue.json, selects true_positive
#          tickets with recommended_action escalate_tier2 or monitor, and
#          assembles one structured incident record per disposition for
#          Tier 2 handoff.
#          Representation policy (documented):
#            - the 279 grouped alerts are represented solely by their 93
#              batch-6 incident records (contributing_alerts supply the
#              timelines); grouped is a property of the ALERT, determined
#              by batch-6 contributing_alerts membership, not by the
#              grouped flag on any individual ticket (batch-7 override
#              tickets on incident members therefore add no records)
#            - the 364 singleton alerts plus 10 null-hostname C2 beacon
#              alerts (IP-joined to asset med-mri-02) produce individual
#              records from their authoritative ticket: batch 7 override
#              > batch 1 > batch 5 > batch 4 (batches 2 and 3 hold zero
#              tickets on this shift)
#          Timeline events come from the event_record embedded in each
#          enriched_queue entry (no event-store re-read). Each record
#          carries a deterministic incident_id (INC-<YYYYMMDD>-<NNNN>,
#          sequentially assigned after sorting by first timeline
#          timestamp then source ticket id; date = latest event timestamp
#          in the shift), a one-sentence summary, an ordered timeline,
#          deduplicated affected assets (hostname, criticality,
#          data_classification, network_zone), deduplicated IOC lists
#          (ips/domains/user accounts/process names from the event
#          records), deduplicated attack techniques, recommended_
#          containment from a fixed table (c2/beacon/https_tunnel IOC
#          categories or egress/outbound rule -> block_ip_at_egress;
#          bruteforce/ssh_scan IOC categories or brute-force rule text ->
#          block_source_ip; interpreter abuse -> isolate_host; monitor-
#          action records without those signals -> enhanced_monitoring;
#          scheduled task escalation -> isolate_host; privileged-logon
#          escalation -> disable_account; default -> isolate_host), and
#          related_incidents (other records sharing a threat-feed IOC
#          indicator or an affected hostname). Writes incidents.json;
#          prints one line per incident.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
TICKETS_DIR="$TRIAGE_PKG/tickets"
OUT_JSON="$TRIAGE_PKG/incidents.json"

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
import collections
import json
import os

enriched_path = os.environ["ENRICHED_PATH"]
tickets_dir = os.environ["TICKETS_DIR"]
out_path = os.environ["OUT_PATH"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
entries = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def timeline_of(ent_list):
    events = []
    for ent in ent_list:
        record = ent.get("event_record") or {}
        if not record.get("record_id"):
            continue
        raw = " ".join(str(record.get("raw_message") or "").split())
        events.append({
            "timestamp": record.get("timestamp"),
            "hostname": record.get("hostname")
                        or (ent.get("asset") or {}).get("hostname"),
            "event_category": record.get("event_category"),
            "description": (raw or "(no raw_message)")[:120],
        })
    events.sort(key=lambda ev: (ev["timestamp"] or "",
                                 ev["hostname"] or ""))
    return events

def assets_of(ent_list):
    seen = {}
    for ent in ent_list:
        asset = ent.get("asset") or {}
        host = asset.get("hostname")
        if host and host not in seen:
            seen[host] = {
                "hostname": host,
                "criticality": asset.get("criticality"),
                "data_classification": asset.get("data_classification"),
                "network_zone": asset.get("network_zone"),
            }
    return list(seen.values())

def iocs_of(ent_list):
    ips, domains, users, procs = set(), set(), set(), set()
    for ent in ent_list:
        record = ent.get("event_record") or {}
        for field in ("src_ip", "dst_ip"):
            value = record.get(field)
            if isinstance(value, str) and value:
                ips.add(value)
        user = record.get("user")
        if isinstance(user, str) and user:
            users.add(user.split("\\")[-1].split("@")[0].lower())
        proc = record.get("process_name")
        if isinstance(proc, str) and proc:
            procs.add(proc)
        data = record.get("event_data")
        if isinstance(data, dict):
            for key in ("dns_query", "QueryName", "DestinationHostname"):
                value = data.get(key)
                if isinstance(value, str) and value:
                    domains.add(value.lower())
    return {"ips": sorted(ips), "domains": sorted(domains),
            "user_accounts": sorted(users), "process_names": sorted(procs)}

def indicators_of(ent_list):
    out = set()
    for ent in ent_list:
        for hit in (ent.get("ioc_hits") or []):
            if hit.get("indicator"):
                out.add(hit["indicator"])
    return out

def categories_of(ent_list):
    out = set()
    for ent in ent_list:
        for hit in (ent.get("ioc_hits") or []):
            out.update(hit.get("categories") or [])
    return out

def techniques_of(ent_list):
    out = set()
    for ent in ent_list:
        out.update(ent.get("attack_techniques") or [])
    return sorted(out)

def containment_of(ent_list, action, categories):
    rule_text = " ".join(
        str(e.get("rule_title") or "") for e in ent_list).lower()
    if categories & {"c2", "beacon", "https_tunnel"} \
            or "egress" in rule_text or "outbound" in rule_text:
        return "block_ip_at_egress"
    if categories & {"bruteforce", "ssh_scan"} \
            or "brute" in rule_text \
            or "repeated authentication" in rule_text:
        return "block_source_ip"
    if "interpreter" in rule_text:
        return "isolate_host"
    if action == "monitor":
        return "enhanced_monitoring"
    if "scheduled task" in rule_text:
        return "isolate_host"
    if "privileged" in rule_text or "logon" in rule_text:
        return "disable_account"
    return "isolate_host"

def host_label(ent_list):
    for ent in ent_list:
        host = (ent.get("asset") or {}).get("hostname")
        if host:
            return host
    return "unattributed host"

def build_record(source, ticket_id, aid, action, ent_list):
    timeline = timeline_of(ent_list)
    titles = collections.Counter(
        e.get("rule_title") or "Unclassified alert" for e in ent_list)
    rule_label = titles.most_common(1)[0][0]
    host = host_label(ent_list)
    if timeline:
        window = "%s..%s" % (timeline[0]["timestamp"],
                              timeline[-1]["timestamp"])
    else:
        window = "unknown"
    summary = ("%s on %s: %d event(s) (%s), true_positive with action %s"
               % (rule_label, host, len(timeline), window, action))
    return {
        "source": source,
        "source_ticket_id": ticket_id,
        "alert_id": aid,
        "classification": "true_positive",
        "recommended_action": action,
        "summary": summary,
        "timeline": timeline,
        "affected_assets": assets_of(ent_list),
        "iocs": iocs_of(ent_list),
        "indicators": sorted(indicators_of(ent_list)),
        "attack_techniques": techniques_of(ent_list),
        "recommended_containment":
            containment_of(ent_list, action, categories_of(ent_list)),
        "rule_label": rule_label,
        "host": host,
    }

# ---------------------------------------------------------------------------
# Grouped membership is a property of the alert: any alert appearing in a
# batch-6 contributing_alerts list is represented solely by its incident
# record, regardless of which batch file its individual ticket lives in.
# ---------------------------------------------------------------------------
grouped_membership = set()
_inc_path = os.path.join(tickets_dir, "batch6_incidents.json")
if os.path.isfile(_inc_path):
    with open(_inc_path, encoding="utf-8") as fh:
        for _ticket in json.load(fh):
            if isinstance(_ticket, dict):
                grouped_membership.update(
                    _ticket.get("contributing_alerts") or [])

# ---------------------------------------------------------------------------
# Authoritative individual tickets: batch 7 > 1 > 5 > 4 (2 and 3 empty).
# ---------------------------------------------------------------------------
INDIVIDUAL_BATCHES = ["batch7_overrides.json", "batch1_clearcut_tp.json",
                      "batch5_proc_net.json", "batch4_auth.json",
                      "batch2_clearcut_fp.json", "batch3_benign.json"]

records = []
authoritative = {}
for name in INDIVIDUAL_BATCHES:
    path = os.path.join(tickets_dir, name)
    if not os.path.isfile(path):
        continue
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, list):
        continue
    for ticket in payload:
        if not isinstance(ticket, dict):
            continue
        aid = ticket.get("alert_id")
        if not aid or aid in authoritative or aid in grouped_membership:
            continue
        if ticket.get("classification") != "true_positive":
            continue
        if ticket.get("recommended_action") not in ("escalate_tier2",
                                                     "monitor"):
            continue
        authoritative[aid] = ticket

for aid, ticket in sorted(authoritative.items()):
    ent = entries.get(aid)
    if ent is None:
        continue
    records.append(build_record("individual", ticket["ticket_id"], aid,
                                 ticket["recommended_action"], [ent]))

# ---------------------------------------------------------------------------
# Batch-6 correlated incidents
# ---------------------------------------------------------------------------
if os.path.isfile(_inc_path):
    with open(_inc_path, encoding="utf-8") as fh:
        incident_tickets = json.load(fh)
    for ticket in incident_tickets:
        if not isinstance(ticket, dict):
            continue
        if ticket.get("classification") != "true_positive":
            continue
        if ticket.get("recommended_action") not in ("escalate_tier2",
                                                     "monitor"):
            continue
        aids = [a for a in (ticket.get("contributing_alerts") or [])
                if a in entries]
        ent_list = [entries[a] for a in aids]
        record = build_record("correlated_incident",
                              ticket["ticket_id"], None,
                              ticket["recommended_action"], ent_list)
        record["summary"] = ("Correlated incident of %d alert(s): %s"
                             % (len(aids), record["summary"]))
        records.append(record)

# ---------------------------------------------------------------------------
# Deterministic incident IDs
# ---------------------------------------------------------------------------
all_ts = [ev["timestamp"] for r in records for ev in r["timeline"]
          if ev["timestamp"]]
id_date = max(all_ts)[:10].replace("-", "") if all_ts else "19700101"

records.sort(key=lambda r: (r["timeline"][0]["timestamp"]
                            if r["timeline"] else "9999",
                            r["source_ticket_id"]))
for seq, record in enumerate(records, start=1):
    record["incident_id"] = "INC-%s-%04d" % (id_date, seq)

# ---------------------------------------------------------------------------
# Related incidents: shared threat-feed indicator or affected hostname
# ---------------------------------------------------------------------------
by_indicator, by_host = collections.defaultdict(set), collections.defaultdict(set)
for idx, record in enumerate(records):
    for ind in record["indicators"]:
        by_indicator[ind].add(idx)
    for asset in record["affected_assets"]:
        by_host[asset["hostname"]].add(idx)

for idx, record in enumerate(records):
    related = set()
    for ind in record["indicators"]:
        related |= by_indicator[ind]
    for asset in record["affected_assets"]:
        related |= by_host[asset["hostname"]]
    related.discard(idx)
    record["related_incidents"] = sorted(
        records[j]["incident_id"] for j in related)

# ---------------------------------------------------------------------------
# Final shape and write (working keys dropped, order fixed)
# ---------------------------------------------------------------------------
KEY_ORDER = ["incident_id", "source", "source_ticket_id", "alert_id",
             "classification", "recommended_action", "summary",
             "timeline", "affected_assets", "iocs",
             "attack_techniques", "recommended_containment",
             "related_incidents"]
final = []
for record in records:
    final.append({key: record[key] for key in KEY_ORDER})

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(final, fh, indent=2)
    fh.write("\n")

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
print("incidents assembled")
for record in records:
    print("  %-20s %-16s %-28s %s"
          % (record["incident_id"], record["host"][:16],
             record["rule_label"][:28],
             record["recommended_containment"]))
print("total incidents         : %d" % len(final))
print("incidents.json written")
PY
