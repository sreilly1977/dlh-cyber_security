#!/bin/bash
# Name: 12-shift_metrics.sh
# Purpose: Process Batch 10 shift metrics. Reads all batch ticket files
#          (1-7), enriched_queue.json, queue_assessment.json (T0), and
#          spec/triage_methodology.md, and produces shift_metrics.json:
#            - shift_start / shift_end: from queue_assessment.time_span when
#              parseable, else min/max event timestamps in the queue
#            - queue_size: alerts in the queue (653)
#            - tickets_total: ticket INSTANCES across batch files 1-7
#              (845 on this shift; counting basis declared in the output)
#            - tickets_by_classification, fp_rate (FP/tickets_total),
#              escalation_ratio (escalate_tier2 instances/tickets_total)
#              over ticket instances, matching the tickets_total basis
#            - mttd_seconds: median, over all 653 alerts counted ONCE
#              each (per-alert dedup; incident tickets inherit their member
#              latencies and add no observations), of
#              event_record.timestamp -> alert generated_at
#            - mttr_seconds: median of generated_at -> ticket created_at;
#              0 by construction (determinism contract sets created_at =
#              generated_at; the dataset contains no analyst wall-clock
#              times) - reported with an explicit data_quality_note
#            - sla_compliance: percentage of the 653 alerts (authoritative
#              ticket each) whose analyst_time_seconds is within the SLA
#              for the alert's priority_band, parsed at runtime from
#              triage_methodology.md ("N minutes" -> N*60; "same business
#              day" / "reviewed before shift end" -> 28800s documented
#              interpretation; band none maps to the score-0 batch SLA)
#            - per_rule_metrics: TP / FP / fp_rate per rule_id over the
#              per-alert authoritative view (batch 7 > 1 > 5 > 4;
#              incident tickets excluded - their member alerts are already
#              counted individually)
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"

ENRICHED_JSON="$TRIAGE_PKG/enriched_queue.json"
ASSESSMENT_JSON="$TRIAGE_PKG/queue_assessment.json"
METHODOLOGY_MD="$TRIAGE_PKG/spec/triage_methodology.md"
TICKETS_DIR="$TRIAGE_PKG/tickets"
OUT_JSON="$TRIAGE_PKG/shift_metrics.json"

for required in "$ENRICHED_JSON" "$ASSESSMENT_JSON" "$METHODOLOGY_MD"; do
    if [[ ! -r "$required" ]]; then
        echo "ERROR: $required not found" >&2
        exit 1
    fi
done
if [[ ! -d "$TICKETS_DIR" ]]; then
    echo "ERROR: $TICKETS_DIR not found" >&2
    exit 1
fi

ENRICHED_PATH="$ENRICHED_JSON" \
ASSESSMENT_PATH="$ASSESSMENT_JSON" \
METHODOLOGY_PATH="$METHODOLOGY_MD" \
TICKETS_DIR="$TICKETS_DIR" \
OUT_PATH="$OUT_JSON" \
python3 - <<'PY'
import json
import os
import re
import statistics
from datetime import datetime

enriched_path = os.environ["ENRICHED_PATH"]
assessment_path = os.environ["ASSESSMENT_PATH"]
methodology_path = os.environ["METHODOLOGY_PATH"]
tickets_dir = os.environ["TICKETS_DIR"]
out_path = os.environ["OUT_PATH"]

with open(enriched_path, encoding="utf-8") as fh:
    enriched = json.load(fh)
entries = {e["alert_id"]: e for e in enriched if isinstance(e, dict)}
with open(assessment_path, encoding="utf-8") as fh:
    assessment = json.load(fh)

# ---------------------------------------------------------------------------
# SLA table parsed from the methodology (runtime source of truth)
# ---------------------------------------------------------------------------
def sla_seconds(text):
    text = text.strip().lower()
    match = re.match(r"(\d+)\s*minute", text)
    if match:
        return int(match.group(1)) * 60
    match = re.match(r"(\d+)\s*hour", text)
    if match:
        return int(match.group(1)) * 3600
    if "business day" in text or "shift end" in text:
        return 8 * 3600  # documented interpretation
    raise ValueError("unparseable SLA value: %r" % text)

sla_by_band = {}
with open(methodology_path, encoding="utf-8") as fh:
    in_sla = False
    for line in fh:
        stripped = line.strip()
        if stripped.lower().startswith("## sla"):
            in_sla = True
            continue
        if in_sla and stripped.startswith("## "):
            break
        if in_sla and stripped.startswith("- "):
            parts = stripped[2:].split(":", 1)
            if len(parts) == 2:
                sla_by_band[parts[0].strip().lower()] = \
                    sla_seconds(parts[1])
if not sla_by_band:
    raise SystemExit("ERROR: no SLA entries parsed from methodology")
DEFAULT_SLA = sla_by_band.get("low", 8 * 3600)
BAND_SLA = dict(sla_by_band)
BAND_SLA.setdefault("none", DEFAULT_SLA)  # score-0 batch clause

# ---------------------------------------------------------------------------
# Ticket instances across all batch files (counting basis: instances)
# ---------------------------------------------------------------------------
BATCH_FILES = ["batch1_clearcut_tp.json", "batch2_clearcut_fp.json",
               "batch3_benign.json", "batch4_auth.json",
               "batch5_proc_net.json", "batch6_incidents.json",
               "batch7_overrides.json"]

tickets_total = 0
class_counts = {}
escalate_count = 0
payloads = {}
for name in BATCH_FILES:
    path = os.path.join(tickets_dir, name)
    if not os.path.isfile(path):
        continue
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)
    payloads[name] = payload
    for ticket in payload:
        if not isinstance(ticket, dict):
            continue
        tickets_total += 1
        cls = ticket.get("classification")
        class_counts[cls] = class_counts.get(cls, 0) + 1
        if ticket.get("recommended_action") == "escalate_tier2":
            escalate_count += 1

# ---------------------------------------------------------------------------
# Per-alert authoritative view: batch 7 > 1 > 5 > 4 (2 and 3 empty).
# First writer wins because of the priority-ordered iteration.
# ---------------------------------------------------------------------------
INDIVIDUAL_FILES = ["batch7_overrides.json", "batch1_clearcut_tp.json",
                    "batch5_proc_net.json", "batch4_auth.json",
                    "batch2_clearcut_fp.json", "batch3_benign.json"]

auth = {}   # alert_id -> ticket
for name in INDIVIDUAL_FILES:
    for ticket in payloads.get(name, []):
        if not isinstance(ticket, dict):
            continue
        aid = ticket.get("alert_id")
        if not aid or aid in auth:
            continue
        auth[aid] = ticket

# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
def parse_dt(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

# Shift window: time_span first, defensive about shape; fallback to
# min/max event timestamps in the queue.
shift_start = shift_end = None
span = assessment.get("time_span")
if isinstance(span, dict):
    shift_start = span.get("start") or span.get("first") or span.get("min")
    shift_end = span.get("end") or span.get("last") or span.get("max")
elif isinstance(span, list) and len(span) == 2:
    shift_start, shift_end = span
event_ts = [parse_dt((e.get("event_record") or {}).get("timestamp"))
            for e in enriched if isinstance(e, dict)]
event_ts = [t for t in event_ts if t is not None]
if event_ts:
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    if not shift_start:
        shift_start = min(event_ts).strftime(fmt)
    if not shift_end:
        shift_end = max(event_ts).strftime(fmt)

# ---------------------------------------------------------------------------
# MTTD: per alert, event timestamp -> generated_at (constant for the shift)
# ---------------------------------------------------------------------------
mttd_obs = []
for entry in enriched:
    if not isinstance(entry, dict):
        continue
    generated = parse_dt(entry.get("generated_at"))
    event_dt = parse_dt((entry.get("event_record") or {}).get("timestamp"))
    if generated is not None and event_dt is not None:
        mttd_obs.append((generated - event_dt).total_seconds())

# ---------------------------------------------------------------------------
# MTTR: generated_at -> ticket created_at (0 by construction)
# ---------------------------------------------------------------------------
mttr_obs = []
for aid, ticket in auth.items():
    entry = entries.get(aid)
    if entry is None:
        continue
    created = parse_dt(ticket.get("created_at"))
    generated = parse_dt(entry.get("generated_at"))
    if created is not None and generated is not None:
        mttr_obs.append((created - generated).total_seconds())

# ---------------------------------------------------------------------------
# SLA compliance over the per-alert authoritative view
# ---------------------------------------------------------------------------
sla_total = sla_ok = 0
for aid, ticket in auth.items():
    entry = entries.get(aid)
    if entry is None:
        continue
    band = (entry.get("priority_band") or "none").lower()
    limit = BAND_SLA.get(band, DEFAULT_SLA)
    seconds = ticket.get("analyst_time_seconds")
    if isinstance(seconds, (int, float)):
        sla_total += 1
        if seconds <= limit:
            sla_ok += 1

# ---------------------------------------------------------------------------
# Per-rule metrics over the per-alert authoritative view
# ---------------------------------------------------------------------------
per_rule = {}
for aid, ticket in auth.items():
    entry = entries.get(aid)
    if entry is None:
        continue
    rule_id = entry.get("rule_id") or "unknown"
    rec = per_rule.setdefault(rule_id, {"tp": 0, "fp": 0})
    if ticket.get("classification") == "false_positive":
        rec["fp"] += 1
    else:
        rec["tp"] += 1
per_rule_out = {}
for rule_id, rec in sorted(per_rule.items()):
    total = rec["tp"] + rec["fp"]
    per_rule_out[rule_id] = {
        "tp": rec["tp"],
        "fp": rec["fp"],
        "fp_rate": round(rec["fp"] / total, 4) if total else 0.0,
    }

fp_rate = class_counts.get("false_positive", 0) / tickets_total \
    if tickets_total else 0.0
escalation_ratio = escalate_count / tickets_total if tickets_total else 0.0
sla_pct = round(100.0 * sla_ok / sla_total, 1) if sla_total else None
mttd = int(statistics.median(mttd_obs)) if mttd_obs else None
mttr = int(statistics.median(mttr_obs)) if mttr_obs else None

output = {
    "shift_start": shift_start,
    "shift_end": shift_end,
    "queue_size": assessment.get("queue_size", len(enriched)),
    "tickets_total": tickets_total,
    "counting_basis": {
        "tickets_total": "ticket instances across batch files 1-7",
        "mttd": "one observation per alert (653); incident tickets add none",
        "sla_and_per_rule": "per-alert authoritative ticket "
                            "(batch 7 > 1 > 5 > 4)",
    },
    "tickets_by_classification": {str(k): v
                                  for k, v in sorted(class_counts.items())},
    "fp_rate": round(fp_rate, 4),
    "escalation_ratio": round(escalation_ratio, 4),
    "mttd_seconds": mttd,
    "mttr_seconds": mttr,
    "mttr_data_quality_note": ("mttr is 0 by construction: the determinism "
                               "contract sets created_at = generated_at "
                               "for every ticket; the dataset contains no "
                               "analyst wall-clock timestamps"),
    "sla_compliance_pct": sla_pct,
    "sla_seconds_by_band": {k: v for k, v in sorted(BAND_SLA.items())},
    "per_rule_metrics": per_rule_out,
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(output, fh, indent=2)
    fh.write("\n")

# ---------------------------------------------------------------------------
# Compact summary
# ---------------------------------------------------------------------------
def hms(seconds):
    if seconds is None:
        return "n/a"
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return "%02d:%02d:%02d" % (h, m, s)

date_label = (shift_end or "unknown")[:10]
print("=== SHIFT METRICS %s ===" % date_label)
print("queue size            : %d" % output["queue_size"])
print("tickets total         : %d  (instances, batches 1-7)"
      % tickets_total)
for cls, count in sorted(class_counts.items()):
    print("  %-20s : %3d" % (cls, count))
print("escalated (tier 2)    : %d" % escalate_count)
print("fp_rate               : %.3f" % fp_rate)
print("escalation_ratio      : %.3f" % escalation_ratio)
print("mttd                  : %s  (median, n=%d)" % (hms(mttd),
                                                       len(mttd_obs)))
print("mttr                  : %s  (by construction; see data_quality_note)"
      % hms(mttr))
print("sla compliance        : %s %%" % sla_pct)
print("per-rule fp rates     : "
      + ", ".join("%s=%.3f" % (rid, rec["fp_rate"])
                  for rid, rec in per_rule_out.items()))
print("shift_metrics.json written")
PY
