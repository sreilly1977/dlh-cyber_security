#!/bin/bash
# Name: 0-queue_assessment.sh
# Purpose: Load the 3x02 alert queue, validate every alert against the queue
#          schema contract, and emit queue_assessment.json (queue size,
#          validation errors, priority bands, rule/host/tactic distributions,
#          time span, top targets) into $TRIAGE_PKG, plus a human-readable
#          shift briefing on stdout. Tactics are derived from attack.<tactic>
#          tags in the rule YAML files, mapped to alerts via rule id.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"
TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"

QUEUE_JSON="$CATALOG_DIR/alerts/alert_queue.json"
SCHEMA_JSON="$CATALOG_DIR/alerts/alert_queue_schema.json"
RULES_DIR="$CATALOG_DIR/rules"

for f in "$QUEUE_JSON" "$SCHEMA_JSON"; do
    if [[ ! -r "$f" ]]; then
        echo "ERROR: required input not readable: $f" >&2
        exit 1
    fi
done
if [[ ! -d "$RULES_DIR" ]]; then
    echo "ERROR: rules directory not found: $RULES_DIR" >&2
    exit 1
fi

mkdir -p "$TRIAGE_PKG"

QUEUE_JSON="$QUEUE_JSON" SCHEMA_JSON="$SCHEMA_JSON" RULES_DIR="$RULES_DIR" \
OUT_PATH="$TRIAGE_PKG/queue_assessment.json" \
python3 - <<'PY'
import collections
import datetime
import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required (apt install python3-yaml)", file=sys.stderr)
    sys.exit(1)

with open(os.environ["QUEUE_JSON"], encoding="utf-8") as fh:
    queue = json.load(fh)
with open(os.environ["SCHEMA_JSON"], encoding="utf-8") as fh:
    schema = json.load(fh)

rules_dir = os.environ["RULES_DIR"]
out_path = os.environ["OUT_PATH"]

LEVELS = set(schema["fields"]["rule_level"]["enum"])
SUMMARY_FIELDS = set(schema["fields"]["event_summary"]["fields"])
STATUS_CONST = schema["fields"]["status"]["const"]


def is_num(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def is_sha256_hex(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def is_iso_utc(value):
    if not isinstance(value, str):
        return False
    try:
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def is_nonneg_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_alert(alert, idx):
    """Validate one alert against the queue schema contract."""
    if not isinstance(alert, dict):
        return ["alert[%d]: not an object" % idx]
    aid = alert.get("alert_id", "<missing@%d>" % idx)
    errs = []

    required = ("alert_id", "generated_at", "rule_id", "rule_title",
                "rule_level", "priority_score", "event_ref", "event_summary",
                "asset_context", "attack_techniques", "status",
                "evidence_hash", "dedup_suppressed_count")
    for key in required:
        if key not in alert:
            errs.append("%s: missing required field '%s'" % (aid, key))

    if not isinstance(alert.get("alert_id"), str):
        errs.append("%s: alert_id is not a string" % aid)
    if not is_iso_utc(alert.get("generated_at")):
        errs.append("%s: generated_at is not ISO 8601 UTC" % aid)
    if not isinstance(alert.get("rule_id"), str):
        errs.append("%s: rule_id is not a string" % aid)
    if not isinstance(alert.get("rule_title"), str):
        errs.append("%s: rule_title is not a string" % aid)
    if alert.get("rule_level") not in LEVELS:
        errs.append("%s: rule_level '%s' not in enum" % (aid, alert.get("rule_level")))
    if not is_num(alert.get("priority_score")):
        errs.append("%s: priority_score is not a number" % aid)
    if not isinstance(alert.get("event_ref"), str):
        errs.append("%s: event_ref is not a string" % aid)

    summary = alert.get("event_summary")
    if not isinstance(summary, dict):
        errs.append("%s: event_summary is not an object" % aid)
    else:
        for key in SUMMARY_FIELDS:
            if key not in summary:
                errs.append("%s: event_summary missing '%s'" % (aid, key))
        if not is_iso_utc(summary.get("timestamp")):
            errs.append("%s: event_summary.timestamp is not ISO 8601 UTC" % aid)

    ctx = alert.get("asset_context")
    if ctx is not None and not isinstance(ctx, dict):
        errs.append("%s: asset_context is neither object nor null" % aid)

    techs = alert.get("attack_techniques")
    if not isinstance(techs, list) or not all(isinstance(t, str) for t in techs):
        errs.append("%s: attack_techniques is not an array of strings" % aid)

    if alert.get("status") != STATUS_CONST:
        errs.append("%s: status is not '%s'" % (aid, STATUS_CONST))
    if not is_sha256_hex(alert.get("evidence_hash")):
        errs.append("%s: evidence_hash is not a sha256 hex string" % aid)
    if not is_nonneg_int(alert.get("dedup_suppressed_count")):
        errs.append("%s: dedup_suppressed_count is not a non-negative integer" % aid)

    return errs


def load_rule_metadata():
    """Map rule_id -> {'stem', 'tactics'} from sigma and tuned rule files."""
    meta = {}
    tactic_tags = re.compile(r"^attack\.([a-z_]+)$")
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
            if not isinstance(doc, dict) or not isinstance(doc.get("id"), str):
                continue
            stem = name[:-len(".yml")]
            tactics = sorted({
                m.group(1)
                for tag in (doc.get("tags") or [])
                if isinstance(tag, str) and (m := tactic_tags.match(tag))
            })
            # tuned/ wins over sigma/ when both define the same rule id
            meta[doc["id"]] = {"stem": stem, "tactics": tactics}
    return meta


def priority_band(score):
    if not is_num(score):
        return "none"
    if score >= 20:
        return "critical"
    if score >= 10:
        return "high"
    if score >= 5:
        return "medium"
    if score >= 1:
        return "low"
    return "none"


def main():
    validation_errors = []
    for idx, alert in enumerate(queue):
        validation_errors.extend(validate_alert(alert, idx))

    rule_meta = load_rule_metadata()

    band_counts = collections.Counter()
    rule_counts = collections.Counter()
    host_counts = collections.Counter()
    tactic_counts = collections.Counter()
    host_scores = collections.Counter()
    timestamps = []

    for alert in queue:
        if not isinstance(alert, dict):
            continue
        score = alert.get("priority_score")
        band_counts[priority_band(score)] += 1

        rid = alert.get("rule_id")
        stem = rule_meta.get(rid, {}).get("stem")
        label = stem if stem else alert.get("rule_title", "unknown_rule")
        rule_counts[label] += 1

        for tactic in rule_meta.get(rid, {}).get("tactics", []):
            tactic_counts[tactic] += 1

        hostname = (alert.get("event_summary") or {}).get("hostname")
        host_key = hostname if isinstance(hostname, str) and hostname else "(unattributed)"
        host_counts[host_key] += 1
        if is_num(score):
            host_scores[host_key] += score

        ts = (alert.get("event_summary") or {}).get("timestamp")
        if is_iso_utc(ts):
            timestamps.append(ts)

    sorted_band = lambda c: {k: v for k, v in sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))}

    assessment = {
        "queue_size": len(queue),
        "validation_errors": sorted(validation_errors),
        "by_priority_band": {b: band_counts.get(b, 0)
                             for b in ("critical", "high", "medium", "low", "none")},
        "by_rule": sorted_band(rule_counts),
        "by_hostname": sorted_band(host_counts),
        "by_attack_tactic": sorted_band(tactic_counts),
        "time_span": {
            "first": min(timestamps) if timestamps else None,
            "last": max(timestamps) if timestamps else None,
        },
        "top_targets": [
            {"hostname": h, "cumulative_priority_score": s}
            for h, s in sorted(host_scores.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        ],
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(assessment, fh, indent=2, sort_keys=False)
        fh.write("\n")

    briefing_date = queue[0].get("generated_at", "")[:10] if queue else "unknown"
    print("=== SHIFT BRIEFING %s ===" % briefing_date)
    print("queue size           : %d alerts" % assessment["queue_size"])
    print("validation errors    : %d" % len(validation_errors))
    print("time span            : %s -> %s" % (
        assessment["time_span"]["first"], assessment["time_span"]["last"]))
    print("priority bands")
    for band in ("critical", "high", "medium", "low", "none"):
        print("  %-9s: %4d" % (band, assessment["by_priority_band"][band]))
    print("top rules (%d)" % min(5, len(rule_counts)))
    for label, count in sorted(rule_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:5]:
        print("  %-45s %4d" % (label, count))
    print("top hosts (3 by cumulative score)")
    for target in assessment["top_targets"]:
        print("  %-25s score %.2f" % (target["hostname"],
                                      target["cumulative_priority_score"]))
    print("attack tactics covered : %d" % len(tactic_counts))
    print("queue_assessment.json written")


main()
PY
