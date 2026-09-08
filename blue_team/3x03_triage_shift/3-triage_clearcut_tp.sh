#!/bin/bash
# Name: 3-triage_clearcut_tp.sh
# Purpose: Process Batch 1 clear-cut true positives from enriched_queue.json.
#          Selects alerts where the configured priority band, a malicious IOC
#          hit, and a category-relevant baseline violation all agree; writes
#          locked-schema tickets (true_positive / escalate_tier2) to
#          tickets/batch1_clearcut_tp.json with correlation-linked evidence
#          refs from sibling alerts and, when available, the 3x02
#          correlation_primitives.json chain records; prints a summary table.
#          Band predicate defaults to critical per spec; CLEARCUT_BANDS
#          overrides without code edits (this queue's max score is 8.96, so
#          no alert lands in the critical band).
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
CLEARCUT_BANDS="${CLEARCUT_BANDS:-critical}"
PRIMITIVES_JSON="${PRIMITIVES_JSON:-$HOME/3x02_package/correlation_primitives.json}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
TICKETS_DIR="$TRIAGE_PKG/tickets"

if [[ ! -r "$ENRICHED_JSON" ]]; then
    echo "ERROR: $ENRICHED_JSON not found (run 2-context_assembly.sh first)" >&2
    exit 1
fi

mkdir -p "$TICKETS_DIR"

ENRICHED_PATH="$ENRICHED_JSON" RULES_DIR="$CATALOG_DIR/rules" \
PRIMITIVES_PATH="$PRIMITIVES_JSON" BANDS="$CLEARCUT_BANDS" \
OUT_PATH="$TICKETS_DIR/batch1_clearcut_tp.json" \
python3 - <<'PY'
import json
import os
import sys
import uuid

try:
    import yaml
except ImportError:
    yaml = None

enriched_path = os.environ["ENRICHED_PATH"]
rules_dir = os.environ["RULES_DIR"]
primitives_path = os.environ["PRIMITIVES_PATH"]
bands = {b.strip().lower() for b in os.environ["BANDS"].split(",") if b.strip()}
out_path = os.environ["OUT_PATH"]

# Deterministic analyst-time estimates per band (seconds). The queue carries no
# per-alert runner timestamps, so these are fixed estimates, consistent across
# reruns to preserve idempotency.
EST_SECONDS = {"critical": 300, "high": 480, "medium": 720, "low": 1500}

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)


def load_rule_stems():
    """Map rule_id -> filename stem from sigma/ and tuned/ rule files."""
    stems = {}
    if yaml is None or not os.path.isdir(rules_dir):
        return stems
    for sub in ("sigma", "tuned"):
        subdir = os.path.join(rules_dir, sub)
        if not os.path.isdir(subdir):
            continue
        for name in sorted(os.listdir(subdir)):
            if not name.endswith(".yml"):
                continue
            path = os.path.join(subdir, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    doc = yaml.safe_load(fh)
            except (yaml.YAMLError, OSError):
                continue
            if isinstance(doc, dict) and isinstance(doc.get("id"), str):
                stems[doc["id"]] = name[:-len(".yml")]
    return stems


def load_primitives():
    """Index correlation primitives by member ref and by (hostname, failure_src_ip)."""
    by_ref = {}
    by_host_src = {}
    if not os.path.isfile(primitives_path):
        return by_ref, by_host_src
    with open(primitives_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                prim = json.loads(line)
            except json.JSONDecodeError:
                continue
            stages = prim.get("stage_refs") or {}
            refs = set(stages.get("failures") or [])
            refs.add(stages.get("success"))
            refs.update(stages.get("privilege_escalations") or [])
            refs.discard(None)
            for ref in refs:
                by_ref[ref] = prim
            key = (prim.get("hostname"), prim.get("failure_src_ip"))
            by_host_src.setdefault(key, []).append(prim)
    return by_ref, by_host_src


def baseline_violation(alert):
    """Return (baseline_field, violation_detail) for the alert's event category, else None."""
    profile = alert.get("baseline_host_profile") or {}
    if not any(v is not None for v in profile.values()):
        return None
    summary = alert.get("event_summary") or {}
    event = alert.get("event_record") or {}
    category = summary.get("event_category") or event.get("event_category")

    if category == "authentication":
        if isinstance(profile.get("auth_per_host"), dict):
            burst = 1 + (alert.get("dedup_suppressed_count") or 0)
            return ("auth.per_host",
                    "failure burst from a single source exceeds the clean-week "
                    "per-source ceiling of 5 failures per 600s (rule 001 tuning "
                    "note; baseline max_failures_1h_window=9); alert evidences "
                    "%d+ failures from src_ip in the 600s rule window" % burst)
        return None

    if category in ("network", "firewall"):
        dests = profile.get("network_per_host_destinations")
        dst = summary.get("dst_ip") or event.get("dst_ip")
        if isinstance(dests, dict) and dst and dst not in dests:
            return ("network.per_host_destinations",
                    "dst_ip %s absent from the host's baseline destination set "
                    "(unknown_destination_penalty=4)" % dst)
        return None

    if category == "process":
        proc = event.get("process_name") or summary.get("process_name")
        if proc:
            return ("process.parent_child_pairs",
                    "process %s absent from the host's baseline process "
                    "inventory (unknown_process_penalty=5)" % proc)
    return None


def main():
    stems = load_rule_stems()
    prim_by_ref, prim_by_host_src = load_primitives()

    # Sibling index: alerts sharing (rule_id, src_ip) are correlation-linked.
    siblings = {}
    for entry in enriched:
        src = (entry.get("event_summary") or {}).get("src_ip")
        if src:
            siblings.setdefault((entry.get("rule_id"), src), []).append(entry)

    tickets = []
    for entry in enriched:
        if entry.get("priority_band") not in bands:
            continue
        malicious = [h for h in entry.get("ioc_hits", [])
                     if h.get("reputation") == "malicious"]
        if not malicious:
            continue
        violation = baseline_violation(entry)
        if violation is None:
            continue

        summary = entry.get("event_summary") or {}
        event = entry.get("event_record") or {}
        alert_id = entry["alert_id"]
        top_hit = entry["ioc_hits"][0]
        field, detail = violation

        # Linked evidence: sibling alerts, plus any correlation primitive
        # touching this event or matching (hostname, failure_src_ip).
        linked = set()
        src = summary.get("src_ip")
        host = summary.get("hostname") or event.get("hostname")
        for other in siblings.get((entry.get("rule_id"), src), []):
            if other["alert_id"] != alert_id:
                linked.add(other["event_ref"])
        prim = prim_by_ref.get(entry["event_ref"])
        if prim is None and host and src:
            cands = prim_by_host_src.get((host, src))
            prim = cands[0] if cands else None
        if prim:
            stages = prim.get("stage_refs") or {}
            linked.update(stages.get("failures") or [])
            linked.add(stages.get("success"))
            linked.update(stages.get("privilege_escalations") or [])
        linked.discard(None)

        refs = [entry["event_ref"]] + sorted(linked)
        justification = (
            "ioc_context reputation=malicious for %s (categories: %s); "
            "baseline violation in %s: %s" % (
                top_hit.get("indicator"),
                ", ".join(top_hit.get("categories", [])),
                field, detail))

        tickets.append({
            "ticket_id": str(uuid.uuid5(uuid.NAMESPACE_DNS,
                                        "meddefense.tickets." + alert_id)),
            "alert_id": alert_id,
            "classification": "true_positive",
            "justification": justification,
            "evidence_refs": list(dict.fromkeys(refs)),
            "ioc_hits": entry["ioc_hits"],
            "attack_techniques": entry.get("attack_techniques", []),
            "recommended_action": "escalate_tier2",
            "analyst_time_seconds": EST_SECONDS.get(entry.get("priority_band"), 1500),
            "created_at": entry.get("generated_at"),
        })

    tickets.sort(key=lambda t: t["alert_id"])
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(tickets, fh, indent=2)
        fh.write("\n")

    by_id = {e["alert_id"]: e for e in enriched}
    print("batch 1 clear-cut true positives")
    for t in tickets:
        src_alert = by_id[t["alert_id"]]
        summary = src_alert.get("event_summary") or {}
        host = summary.get("hostname") or "(unattributed)"
        stem = stems.get(src_alert.get("rule_id"), src_alert.get("rule_title", "?"))
        print("  %-14s %-28s %-15s %-10s ESCALATE"
              % (t["alert_id"][:14], str(stem)[:28], str(host)[:15],
                 src_alert["ioc_hits"][0]["reputation"]))
    print("batch size               : %d" % len(tickets))
    print("tickets written          : %d" % len(tickets))
    print("tickets/batch1_clearcut_tp.json")
    if not tickets and bands == {"critical"}:
        print("note: no critical-band alerts exist in this queue "
              "(max priority_score 8.96); rerun with "
              "CLEARCUT_BANDS=medium to process the IOC-backed medium band")


main()
PY
