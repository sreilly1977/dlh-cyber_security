#!/bin/bash
#
# Name: 0-detection_matrix.sh
# Purpose: Map canonical detection types (signature/anomaly/behavioral/correlation) onto each
#          source_type in the 3x00 enriched evidence stream, driven by field stability,
#          cardinality, baseline coverage, and join-key availability. Emits detection_matrix.json.
# Author: Steve - Cybersecurity Engineer
# Date: 04 September 2026

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
OUT_FILE="${MATRIX_OUT:-detection_matrix.json}"

ENRICHED="$HANDOFF_DIR/data/enriched_events.json"
SCHEMA="$HANDOFF_DIR/schema/event_schema.json"
BASELINE_SUMMARY="$BASELINE_PKG/baselines/baseline_summary.json"
TAXONOMY="$ASSETS_DIR/attack_taxonomy.json"

for f in "$ENRICHED" "$SCHEMA" "$BASELINE_SUMMARY"; do
    if [ ! -r "$f" ]; then
        echo "ERROR: required input not readable: $f" >&2
        exit 1
    fi
done

python3 - "$ENRICHED" "$SCHEMA" "$BASELINE_SUMMARY" "$TAXONOMY" "$OUT_FILE" <<'PY'
import hashlib
import json
import os
import sys
from datetime import datetime

enriched_path, schema_path, baseline_path, taxonomy_path, out_path = sys.argv[1:6]

def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        die(f"cannot read/parse {path}: {exc}")

def parse_iso(value):
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))

def is_present(value):
    """A field counts as present when the key exists with a non-null, non-empty value."""
    if value is None:
        return False
    if isinstance(value, str) and not value.strip():
        return False
    return True

def digest(value):
    """Deterministic, compact value fingerprint for cardinality counting."""
    if isinstance(value, (dict, list)):
        raw = json.dumps(value, sort_keys=True, default=str)
    else:
        raw = str(value)
    return hashlib.blake2b(raw.encode("utf-8", "replace"), digest_size=16).hexdigest()

# Fields with small, enumerable vocabularies: track RAW values (used by the
# category->domain and category->tactics mappings and multi-value gates).
ENUM_FIELDS = {"event_category", "event_id", "action", "severity", "protocol"}

# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
schema_doc = load_json(schema_path)
track_fields = [f["name"] for f in schema_doc.get("fields", [])]
track_fields += ["asset", "src_zone", "dst_zone"]  # enrichment overlay

summary = load_json(baseline_path)

# Baseline window length (runtime-derived, never hardcoded)
baseline_days = 0.0
bw = summary.get("baseline_window") or {}
if isinstance(bw, dict) and bw.get("start") and bw.get("end"):
    try:
        baseline_days = (parse_iso(bw["end"]) - parse_iso(bw["start"])).total_seconds() / 86400.0
    except (ValueError, TypeError):
        pass
BEHAVIORAL_MIN_BASELINE_DAYS = 7.0

baseline_domains = {d for d in ("auth", "file", "network", "process", "temporal")
                    if d in summary}

# Optional ATT&CK taxonomy validation
valid_tactics = None
if taxonomy_path and os.path.isfile(taxonomy_path):
    tax = load_json(taxonomy_path)
    valid_tactics = {t["tactic_id"] for t in tax.get("tactics", [])}

# Event category -> baseline domain (does a learned profile exist for this behavior?)
CATEGORY_DOMAIN = {
    "authentication": "auth",
    "process": "process",
    "powershell": "process",
    "service": "process",
    "file": "file",
    "network": "network",
    "network_alert": "network",
    "network_flow": "network",
}

# Event category -> ATT&CK tactics it can reasonably surface
CATEGORY_TACTICS = {
    "authentication": ["TA0001", "TA0006", "TA0008"],
    "process": ["TA0002", "TA0004", "TA0005"],
    "powershell": ["TA0002", "TA0005"],
    "service": ["TA0003", "TA0005"],
    "file": ["TA0003", "TA0005"],
    "network": ["TA0010", "TA0011"],
    "network_alert": ["TA0007", "TA0010", "TA0011"],
    "network_flow": ["TA0007", "TA0010", "TA0011"],
}

# ---------------------------------------------------------------------------
# Single streaming pass over enriched_events.json
# ---------------------------------------------------------------------------
sources = {}

def blank_stats():
    return {
        "count": 0,
        "present": {},        # field -> count of present values
        "distinct": {},       # field -> set of value digests (cardinality proxy)
        "distinct_raw": {},   # field -> set of raw values, ENUM_FIELDS only
        "session_events": 0,  # records whose event_data carries flow/session lifecycle keys
    }

with open(enriched_path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue  # malformed lines were quarantined upstream in 3x00; skip defensively
        st = sources.setdefault(rec.get("source_type") or "unknown", blank_stats())
        st["count"] += 1

        ev = rec.get("event_data")
        if isinstance(ev, dict) and any(
            k in ev for k in ("duration_seconds", "session_id", "packets")
        ):
            st["session_events"] += 1

        for field in track_fields:
            if field in rec and is_present(rec[field]):
                st["present"][field] = st["present"].get(field, 0) + 1
                st["distinct"].setdefault(field, set()).add(digest(rec[field]))
                if field in ENUM_FIELDS:
                    st["distinct_raw"].setdefault(field, set()).add(rec[field])

# ---------------------------------------------------------------------------
# Per-source classification
# ---------------------------------------------------------------------------
CANONICAL_ORDER = ["windows_json", "linux_text", "suricata", "suricata_alert",
                   "audit", "firewall", "pcap_flow"]
TYPE_ORDER = ["signature", "anomaly", "behavioral", "correlation"]

entries = []
order = [s for s in CANONICAL_ORDER if s in sources]
order += sorted(s for s in sources if s not in CANONICAL_ORDER)

for name in order:
    st = sources[name]
    count = st["count"]
    if count == 0:
        continue

    present_ratio = {f: st["present"][f] / count for f in st["present"]}
    stable_fields = sorted(f for f, r in present_ratio.items() if r >= 0.95)
    stable_set = set(stable_fields)
    high_card = sorted(f for f in st["distinct"] if len(st["distinct"][f]) > 0.5 * count)

    categories = sorted(st["distinct_raw"].get("event_category", set()))

    domains_needed = {CATEGORY_DOMAIN[c] for c in categories if c in CATEGORY_DOMAIN}
    has_baseline_coverage = bool(domains_needed) and domains_needed.issubset(baseline_domains)
    is_alert_stream = categories == ["network_alert"]

    has_identity_join = "user" in stable_set or "hostname" in stable_set
    has_flow_join = ("action" in stable_set and "src_ip" in stable_set
                     and "dst_ip" in stable_set)
    has_session_shape = st["session_events"] / count >= 0.95

    detected_types = []

    # signature: stable exact-match discriminators to key rule logic on
    signature_reasons = []
    if "event_id" in stable_set and len(st["distinct_raw"].get("event_id", ())) >= 2:
        signature_reasons.append("stable event_id with multiple distinct values")
    if "signature" in stable_set:
        signature_reasons.append("stable signature field")
    if "event_category" in stable_set and len(categories) >= 2:
        signature_reasons.append("stable event_category with multiple variants")
    signature_ok = bool(signature_reasons)

    # anomaly: baseline volume/behavior profiles exist for this source's categories,
    # and the source is raw telemetry rather than a pre-curated alert feed
    anomaly_ok = has_baseline_coverage and not is_alert_stream

    # behavioral: a stable principal or session shape, plus >= 7 days of baseline
    behavioral_reasons = []
    if has_identity_join:
        behavioral_reasons.append("stable principal field (user/hostname)")
    if has_session_shape:
        behavioral_reasons.append("session lifecycle fields in event_data")
    if baseline_days >= BEHAVIORAL_MIN_BASELINE_DAYS:
        behavioral_reasons.append(
            f"{baseline_days:.1f} days of baseline ({BEHAVIORAL_MIN_BASELINE_DAYS:.0f} required)"
        )
    behavioral_ok = (has_identity_join or has_session_shape) \
        and baseline_days >= BEHAVIORAL_MIN_BASELINE_DAYS and has_baseline_coverage

    # correlation: join keys that survive into other sources (identity, alert
    # signature, or firewall action + endpoint pair)
    correlation_ok = has_identity_join or "signature" in stable_set or has_flow_join

    rationale = {}
    if signature_ok:
        rationale["signature"] = "; ".join(signature_reasons)
    if anomaly_ok:
        covered = sorted(domains_needed)
        rationale["anomaly"] = (
            f"baseline domains {covered} available; "
            + ("raw telemetry suitable for volume deviation analysis"
               if not is_alert_stream else "alert feed exempt from anomaly gating")
        )
    if behavioral_ok:
        rationale["behavioral"] = "; ".join(behavioral_reasons)
    if correlation_ok:
        if has_identity_join:
            rationale["correlation"] = "stable user/hostname join keys"
        elif "signature" in stable_set:
            rationale["correlation"] = "stable signature join key"
        else:
            rationale["correlation"] = "stable action + src/dst endpoint pairs"

    for t in TYPE_ORDER:
        if t == "signature" and signature_ok:
            detected_types.append(t)
        elif t == "anomaly" and anomaly_ok:
            detected_types.append(t)
        elif t == "behavioral" and behavioral_ok:
            detected_types.append(t)
        elif t == "correlation" and correlation_ok:
            detected_types.append(t)

    tactics = []
    for c in categories:
        for t in CATEGORY_TACTICS.get(c, []):
            if t not in tactics:
                tactics.append(t)
    tactics.sort()
    if valid_tactics is not None:
        tactics = [t for t in tactics if t in valid_tactics]

    entries.append({
        "source_type": name,
        "record_count": count,
        "stable_fields": stable_fields,
        "high_cardinality_fields": high_card,
        "supported_detection_types": detected_types,
        "rationale": rationale,
        "recommended_attack_tactics": tactics,
    })

result = {
    "version": "1.1",
    "project": "3x02 Alert Factory - Detection Type Decision Matrix",
    "inputs": {
        "enriched_events": enriched_path,
        "event_schema": schema_path,
        "baseline_summary": baseline_path,
    },
    "derived_baseline_days": round(baseline_days, 3),
    "behavioral_min_baseline_days": BEHAVIORAL_MIN_BASELINE_DAYS,
    "sources": entries,
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, indent=2)
    fh.write("\n")

# stdout report (fixed-width, deterministic ordering)
name_width = max((len(e["source_type"]) for e in entries), default=0)
for e in entries:
    types = e["supported_detection_types"]
    print(f"{e['source_type']:<{name_width}}  {len(types)} types  [{', '.join(types)}]")
print(f"{len(entries)} source types analyzed")
print(f"detection_matrix.json written")
PY
