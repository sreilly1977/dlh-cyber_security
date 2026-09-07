#!/bin/bash
#
# Name: 13-rule_quality.sh
# Purpose: Compute precision, recall, and F1 for every rule in the catalog
#          (base and tuned) against a two-tier ground truth: tier 1 is the
#          literal event_refs from ranked_anomalies.json; tier 2 is the
#          measured March 25 attack narrative expressed as reproducible
#          predicates over the labeled dataset. fp_count composes eval-window
#          non-GT matches with baseline-window matches (fp_baseline.json for
#          base rules, measured directly for tuned variants).
# Author: Steve - Cybersecurity Engineer
# Date: 2026/09/07
#
# Environment:
#   BASELINE_PKG       3x01 baseline package (default: ~/3x01_package/baseline_package)
#   RULES_DIR          Sigma rules dir with tuned/ subdir (default: ~/3x02_scripts/rules/sigma)
#   RUNNER             sigma runner path (default: ~/3x02_scripts/3-sigma_runner.sh)
#   FP_BASELINE        T10 fp ledger (default: ~/3x02_package/fp_baseline.json)
#   RULE_QUALITY_OUT   output JSON (default: ~/3x02_package/rule_quality.json)
#   EVAL_END           evaluation window end override (default: 2026-03-27T00:00:00Z,
#                      documented deviation: official evaluation_window ends before the attack)
#   EMPTY_METRICS      convention for 0/0 precision or recall: "null" (default) or "one"
#   GT2_*              tier-2 ground truth predicate overrides (see defaults below)

set -euo pipefail

BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
RULES_DIR="${RULES_DIR:-$HOME/3x02_scripts/rules/sigma}"
RUNNER="${RUNNER:-$HOME/3x02_scripts/3-sigma_runner.sh}"
FP_BASELINE="${FP_BASELINE:-$HOME/3x02_package/fp_baseline.json}"
OUTPUT_PATH="${RULE_QUALITY_OUT:-$HOME/3x02_package/rule_quality.json}"
EVAL_END="${EVAL_END:-2026-03-27T00:00:00Z}"
EMPTY_METRICS="${EMPTY_METRICS:-null}"

for f in "$BASELINE_PKG/anomalies/ranked_anomalies.json" \
         "$BASELINE_PKG/taxonomy/labeled_events.json" \
         "$BASELINE_PKG/baseline_summary.json" \
         "$FP_BASELINE" "$RUNNER"; do
    if [ ! -f "$f" ]; then
        echo "ERROR: required file not found: $f" >&2
        exit 1
    fi
done
if [ ! -d "$RULES_DIR" ]; then
    echo "ERROR: rules directory not found: $RULES_DIR" >&2
    exit 1
fi
OUT_DIR="$(dirname "$OUTPUT_PATH")"
if [ ! -d "$OUT_DIR" ]; then
    echo "ERROR: output directory not found: $OUT_DIR" >&2
    exit 1
fi

BASELINE_PKG="$BASELINE_PKG" RULES_DIR="$RULES_DIR" RUNNER="$RUNNER" \
FP_BASELINE="$FP_BASELINE" OUTPUT_PATH="$OUTPUT_PATH" EVAL_END="$EVAL_END" \
EMPTY_METRICS="$EMPTY_METRICS" \
python3 -W error - <<'PYEOF'
import glob
import json
import os
import subprocess
import sys

baseline_pkg = os.environ["BASELINE_PKG"]
rules_dir = os.environ["RULES_DIR"]
runner_path = os.environ["RUNNER"]
output_path = os.environ["OUTPUT_PATH"]
eval_end = os.environ["EVAL_END"]
empty_convention = os.environ["EMPTY_METRICS"]

# ---------------------------------------------------------------- ground truth

with open(os.path.join(baseline_pkg, "anomalies", "ranked_anomalies.json"),
          encoding="utf-8") as fh:
    ranked = json.load(fh)
tier1_refs = set()
tier1_no_refs = []
for anom in ranked.get("ranked_anomalies", []):
    refs = anom.get("event_refs") or []
    if refs:
        tier1_refs.update(refs)
    else:
        tier1_no_refs.append({"anomaly_type": anom.get("anomaly_type"),
                               "host": anom.get("host"),
                               "timestamp": anom.get("timestamp")})

# Tier-2: measured attack narrative (3x01 analysis), env-overridable.
BRUTE_IPS = set(os.environ.get(
    "GT2_BRUTE_IPS",
    "203.0.113.41,203.0.113.42,203.0.113.43,203.0.113.44").split(","))
BRUTE_LO, BRUTE_HI = os.environ.get(
    "GT2_BRUTE_WINDOW", "2026-03-25T01:16:00Z,2026-03-25T01:50:00Z").split(",")
LAT_HOSTS = set(os.environ.get(
    "GT2_LATERAL_HOSTS", "clin-ws-07,clin-ws-12").split(","))
LAT_USER = os.environ.get("GT2_LATERAL_USER", "p.morales")
LAT_WINS = [tuple(w.split(",")) for w in os.environ.get(
    "GT2_LATERAL_WINDOWS",
    "2026-03-25T02:15:00Z,2026-03-25T02:35:00Z;"
    "2026-03-25T14:20:00Z,2026-03-25T14:35:00Z").split(";")]
EG_SRC, EG_DST = os.environ.get(
    "GT2_EGRESS_PAIR", "10.2.3.2,198.51.100.73").split(",")
EG_LO, EG_HI = os.environ.get(
    "GT2_EGRESS_WINDOW", "2026-03-25T11:40:00Z,2026-03-25T12:35:00Z").split(",")

tier1 = {}   # ref -> {"label": canonical_label}
tier2 = {}   # ref -> {"label": ..., "component": ...}

labeled_path = os.path.join(baseline_pkg, "taxonomy", "labeled_events.json")
with open(labeled_path, encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = rec.get("record_id")
        if not rid:
            continue
        if rid in tier1_refs:
            tier1[rid] = {"label": rec.get("canonical_label")}
        ts = rec.get("timestamp") or ""
        src = rec.get("src_ip")
        dst = rec.get("dst_ip")
        if src in BRUTE_IPS and BRUTE_LO <= ts < BRUTE_HI:
            tier2[rid] = {"label": rec.get("canonical_label"),
                          "component": "brute_force"}
        elif (rec.get("hostname") in LAT_HOSTS and rec.get("user") == LAT_USER
                and any(lo <= ts < hi for lo, hi in LAT_WINS)):
            tier2[rid] = {"label": rec.get("canonical_label"),
                          "component": "lateral_movement"}
        elif src == EG_SRC and dst == EG_DST and EG_LO <= ts < EG_HI:
            tier2[rid] = {"label": rec.get("canonical_label"),
                          "component": "egress_burst"}

gt_all = set(tier1) | set(tier2)
print("tier-1 refs (ranked_anomalies): %d" % len(tier1), file=sys.stderr)
print("tier-2 refs (attack narrative): %d  "
      "(brute=%d lateral=%d egress=%d)"
      % (len(tier2),
         sum(1 for v in tier2.values() if v["component"] == "brute_force"),
         sum(1 for v in tier2.values() if v["component"] == "lateral_movement"),
         sum(1 for v in tier2.values() if v["component"] == "egress_burst")),
      file=sys.stderr)

# ---------------------------------------------------------------- windows

with open(os.path.join(baseline_pkg, "baseline_summary.json"),
          encoding="utf-8") as fh:
    summary = json.load(fh)
eval_start = summary["evaluation_window"]["start"]
base_lo = summary["baseline_window"]["start"]
base_hi = summary["baseline_window"]["end"]

# ---------------------------------------------------------------- fp ledger

with open(os.environ["FP_BASELINE"], encoding="utf-8") as fh:
    fp_ledger = {e["rule_id"]: e for e in json.load(fh)}

# ------------------------------------------------- per-rule FN scope by label

SCOPE = {
    "001": ["login_failure", "account_lockout"],
    "002": ["login_success", "privilege_escalation"],
    "003": ["process_start", "child_process_spawn"],
    "004": ["process_start", "child_process_spawn"],
    "005": ["process_start"],
    "006": ["file_permission_change"],
    "007": ["network_connection_outbound"],
    "008": ["network_connection_outbound"],
    "009": ["login_success"],
    "010": ["login_failure", "login_success"],
    "011": ["file_read_sensitive"],
    "012": ["network_connection_outbound"],
    "013": ["privilege_escalation"],
}
CORRELATION_PREFIXES = {"010"}  # need --preprocess (T10 precedent)


def run_rule(path, lo, hi, needs_pre):
    cmd = [runner_path, path, labeled_path, "--window", "%s,%s" % (lo, hi)]
    if needs_pre:
        cmd.append("--preprocess")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        return None
    return json.loads(proc.stdout)


def fmt(value):
    return "n/a" if value is None else "%.2f" % value


base_files = sorted(glob.glob(os.path.join(rules_dir, "*.yml")))
tuned_files = sorted(glob.glob(os.path.join(rules_dir, "tuned", "*.yml")))
tasks = [(p, False) for p in base_files] + [(p, True) for p in tuned_files]

print("evaluating %d rules against labeled ground truth" % len(tasks),
      file=sys.stderr)

entries = []
for path, is_tuned in tasks:
    stem = os.path.splitext(os.path.basename(path))[0]
    prefix = stem.split("_", 0)[0][:3]
    prefix = stem[:3]
    scope_labels = SCOPE.get(prefix, [])
    needs_pre = prefix in CORRELATION_PREFIXES

    print("  running %s (%s) eval window..." % (stem, "tuned" if is_tuned else "base"),
          file=sys.stderr)
    result = run_rule(path, eval_start, eval_end, needs_pre)
    if result is None:
        entries.append({"rule": stem, "variant": "tuned" if is_tuned else "base",
                        "path": path, "evaluation_error": True})
        continue

    match_refs = [m.get("event_ref") for m in result.get("matches", [])
                  if m.get("event_ref")]
    match_set = set(match_refs)
    truncated = bool(result.get("matches_truncated"))

    # fp: eval-window non-GT matches + baseline-window matches
    fp_eval = len(match_set - gt_all)
    if is_tuned:
        # tuned variants are not in the T10 ledger; measure baseline window
        print("  running %s (tuned) baseline window..." % stem, file=sys.stderr)
        bres = run_rule(path, base_lo, base_hi, needs_pre)
        if bres is None:
            entries.append({"rule": stem, "variant": "tuned", "path": path,
                            "evaluation_error": True})
            continue
        fp_base = bres.get("match_count", 0)
        fp_source = "measured-baseline-window"
    else:
        entry_ledger = fp_ledger.get(result.get("rule_id", ""))
        if entry_ledger is not None:
            fp_base = entry_ledger["fp_count"]
            fp_source = "fp_baseline.json"
        else:
            print("  running %s (base, no ledger entry) baseline window..." % stem,
                  file=sys.stderr)
            bres = run_rule(path, base_lo, base_hi, needs_pre)
            if bres is None:
                entries.append({"rule": stem, "variant": "base", "path": path,
                                "evaluation_error": True})
                continue
            fp_base = bres.get("match_count", 0)
            fp_source = "measured-baseline-window"

    tp = len(match_set & gt_all)
    tier1_tp = len(match_set & set(tier1))
    tier2_tp = len(match_set & set(tier2))
    fp_count = fp_eval + fp_base

    scoped_gt = {r for r, v in list(tier1.items()) + list(tier2.items())
                 if v.get("label") in scope_labels}
    fn = len(scoped_gt - match_set)

    prec_denom = tp + fp_count
    rec_denom = tp + fn
    degenerate_p = prec_denom == 0
    degenerate_r = rec_denom == 0

    if degenerate_p:
        precision = 1.0 if empty_convention == "one" else None
    else:
        precision = tp / prec_denom
    if degenerate_r:
        recall = 1.0 if empty_convention == "one" else None
    else:
        recall = tp / rec_denom

    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)

    entries.append({
        "rule": stem,
        "display": stem.replace("_", " ", 1) + (" (tuned)" if is_tuned else ""),
        "variant": "tuned" if is_tuned else "base",
        "path": path,
        "rule_id": result.get("rule_id"),
        "rule_title": result.get("rule_title"),
        "level": result.get("level"),
        "tp_count": tp,
        "tp_tier1_ranked_anomalies": tier1_tp,
        "tp_tier2_attack_narrative": tier2_tp,
        "fp_count": fp_count,
        "fp_eval_window_non_gt": fp_eval,
        "fp_baseline_window": fp_base,
        "fp_baseline_source": fp_source,
        "fn_count": fn,
        "gt_scope_labels": scope_labels,
        "gt_scope_size": len(scoped_gt),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "degenerate_precision": degenerate_p,
        "degenerate_recall": degenerate_r,
        "matches_truncated": truncated,
    })

report = {
    "generator": "13-rule_quality.sh",
    "evaluation_window": {"start": eval_start, "end": eval_end},
    "baseline_window": {"start": base_lo, "end": base_hi},
    "ground_truth": {
        "tier1_ranked_anomalies_refs": len(tier1),
        "tier2_attack_narrative_refs": len(tier2),
        "tier2_components": {
            "brute_force_window": [BRUTE_LO, BRUTE_HI],
            "lateral_movement_windows": [list(w) for w in LAT_WINS],
            "egress_burst_window": [EG_LO, EG_HI],
        },
        "tier1_anomalies_without_refs": tier1_no_refs,
        "tier1_unresolved_refs": sorted(tier1_refs - set(tier1)),
        "total_gt_refs": len(gt_all),
    },
    "empty_metric_convention": empty_convention,
    "notes": [
        "Deviations and conventions: (1) ranked_anomalies.json contains only "
        "March 24 anomalies and no attack-chain coverage, so ground truth is "
        "two-tier: its literal event_refs plus the measured March 25 attack "
        "narrative (3x01 analysis) expressed as attribute predicates, "
        "env-overridable via GT2_* variables. (2) Evaluation window extends "
        "the official evaluation_window end to EVAL_END to cover the attack, "
        "consistent with the 3x01 documented deviation. (3) fn_count is scoped "
        "to each rule's canonical-label responsibility map (gt_scope_labels), "
        "a documented per-rule table. (4) 0/0 precision or recall reported as "
        "null with degenerate_* flags (EMPTY_METRICS=one switches to 1.00, "
        "the sample-output convention).",
        "tp is computed against the full two-tier GT; fn only against the "
        "rule's scoped subset, so a rule can show tp > scoped matches when it "
        "cross-catches another rule's GT events.",
    ],
    "rules": sorted(entries, key=lambda e: e.get("rule", "")),
}

with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")

ranked_ok = [e for e in entries if not e.get("evaluation_error")]
ranked_ok.sort(key=lambda e: (e["f1"] is None, -(e["f1"] or 0.0)))
print("evaluating %d rules against labeled ground truth" % len(tasks))
print("strongest")
for e in ranked_ok[:5]:
    mark = "[STRONG]" if (e["f1"] or 0.0) >= 0.7 else (
        "[WEAK]" if (e["f1"] or 0.0) < 0.3 else "")
    print("  %-34s f1=%s  p=%s r=%s  %s" % (
        e["display"], fmt(e["f1"]), fmt(e["precision"]),
        fmt(e["recall"]), mark))
print("weakest")
for e in ranked_ok[-5:]:
    mark = "[STRONG]" if (e["f1"] or 0.0) >= 0.7 else (
        "[WEAK]" if (e["f1"] or 0.0) < 0.3 else "")
    print("  %-34s f1=%s  p=%s r=%s  %s" % (
        e["display"], fmt(e["f1"]), fmt(e["precision"]),
        fmt(e["recall"]), mark))
print("%s written" % output_path)
PYEOF
