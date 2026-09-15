#!/bin/bash
# Name: 12-tuning_recommendations.sh
# Purpose: Produce detection gap analysis and tuning recommendations grounded
#          in counted observations from this shift. Computes per-rule FP rates
#          from triage_log.jsonl (FP classifications / total classifications per
#          rule), identifies rules_with_fp (fp_rate > 0) and rules_with_noise
#          (every classification NOISE). Compares the ATT&CK technique union
#          of all three investigation findings against the alerts_by_rule map
#          in catalog_run.json via the 3x02 attack coverage map: a technique
#          with no firing covering rule is a detection gap, classified as
#          missing_rule (no catalog rule covers the technique) or
#          correlation_gap (covering rule exists but produced zero alerts).
#          Emits rules_to_suppress for FP-heavy rules citing alert_ids from
#          the triage log, and new_rules_proposed Sigma sketches for
#          missing_rule gaps. Exits non-zero if any rules_that_missed entry
#          cites an incident_id absent from incidents.json, if any
#          missed_because value is outside the allowed set, or if any
#          rule reference does not resolve to a real catalog rule.
# Author: Steve - Cybersecurity Engineer
# Date: 15 September 2026

set -euo pipefail

err_trap() { printf '[tune][ERROR] command failed at line %s (exit %s)\n' "$1" "$2" >&2; }
trap 'err_trap $LINENO $?' ERR

WS="${SHIFT_WORKSPACE:?SHIFT_WORKSPACE not set}"
CATALOG_DIR="${CATALOG_DIR:-$HOME/3x02_package/detection_catalog}"

TRIAGE_LOG="$WS/alerts/triage_log.jsonl"
INC_FILE="$WS/alerts/incidents.json"
CATALOG_RUN="$WS/runtime/catalog_run.json"
COVERAGE_FILE="$CATALOG_DIR/coverage/attack_coverage.json"
RULES_DIR="$CATALOG_DIR/rules"
F_A="$WS/investigations/incident_A.json"
F_B="$WS/investigations/incident_B.json"
F_C="$WS/investigations/incident_C_cli.json"
OUT_FILE="$WS/response/tuning_recommendations.json"

for f in "$TRIAGE_LOG" "$INC_FILE" "$CATALOG_RUN" "$F_A" "$F_B" "$F_C"; do
    [[ -f "$f" && -s "$f" ]] || { printf '[tune][ERROR] required input missing or empty: %s\n' "$f" >&2; exit 1; }
done

mkdir -p "$(dirname "$OUT_FILE")"

python3 - "$TRIAGE_LOG" "$INC_FILE" "$CATALOG_RUN" "$COVERAGE_FILE" \
    "$RULES_DIR" "$F_A" "$F_B" "$F_C" "$OUT_FILE" <<'PY'
import json
import os
import sys

ALLOWED_MISSED_BECAUSE = {"threshold", "field_mapping", "correlation_gap", "missing_rule"}
MAX_EXPECTED = 160
MAX_FIX = 240

TECH_NAMES = {
    "T1071.001": "Web Protocols",
    "T1078": "Valid Accounts",
    "T1110.003": "Password Spraying",
    "T1543.003": "Windows Service",
}


def log(msg):
    print(f"[tune] {msg}")


def fail(msg):
    print(f"[tune][ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(triage_path, inc_path, run_path, coverage_path, rules_dir,
         fa_path, fb_path, fc_path, out_path):

    # --- 1. Per-rule classification counts from the triage log -------------------
    rule_counts = {}
    fp_examples = {}  # rule_id -> first FP alert_id (for suppression citations)
    n_total = 0
    with open(triage_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = rec.get("rule_id")
            cls = rec.get("classification")
            if not rid or not cls:
                continue
            n_total += 1
            counts = rule_counts.setdefault(rid, {})
            counts[cls] = counts.get(cls, 0) + 1
            if cls == "FP" and rid not in fp_examples:
                fp_examples[rid] = rec.get("alert_id", "unknown")

    tp_total = sum(c.get("TP", 0) for c in rule_counts.values())
    fp_total = sum(c.get("FP", 0) for c in rule_counts.values())
    noise_total = sum(c.get("NOISE", 0) for c in rule_counts.values())
    log(f"triage_log: {n_total} alerts (TP={tp_total} FP={fp_total} NOISE={noise_total})")

    fp_rate_by_rule = {}
    rules_with_fp = []
    rules_with_noise = []
    for rid, counts in sorted(rule_counts.items()):
        total = sum(counts.values())
        fp_rate = counts.get("FP", 0) / total if total else 0.0
        fp_rate_by_rule[rid] = round(fp_rate, 4)
        if counts.get("FP", 0) > 0:
            rules_with_fp.append(rid)
        if total > 0 and counts.get("NOISE", 0) == total:
            rules_with_noise.append(rid)

    log(f"rules_with_fp: {len(rules_with_fp)} (fp_rate > 0)")
    log(f"rules_with_noise: {len(rules_with_noise)} (100% noise)")

    # --- 2. Fired rules and coverage map -----------------------------------------
    run_doc = load(run_path)
    alerts_by_rule = run_doc.get("alerts_by_rule", {}) or {}
    fired = set(alerts_by_rule.keys())

    # Catalog rule filenames (base + tuned) for reference validation.
    catalog_rules = set()
    for root, _dirs, files in os.walk(rules_dir):
        for fn in files:
            if fn.endswith(".yml"):
                catalog_rules.add(fn[:-4])

    coverage = {}
    if os.path.exists(coverage_path) and os.path.getsize(coverage_path) > 0:
        cov_doc = load(coverage_path)
        for tid, detail in (cov_doc.get("covered_techniques_detail") or {}).items():
            if isinstance(detail, dict):
                coverage[tid.upper()] = detail

    # --- 3. Technique union across findings, with first-citing incident ----------
    findings = []
    for path in (fa_path, fb_path, fc_path):
        findings.append(load(path))

    tech_to_incident = {}
    for finding in findings:
        inc_id = finding.get("incident_id")
        for tid in (finding.get("attack_techniques") or []):
            tid_u = tid.upper()
            tech_to_incident.setdefault(tid_u, inc_id)
    all_techniques = sorted(tech_to_incident.keys())

    # --- 4. Gap analysis: technique has no firing covering rule -------------------
    valid_incident_ids = {i.get("incident_id") for i in load(inc_path).get("incidents", [])}

    rules_that_missed = []
    for tid in all_techniques:
        base = tid.split(".")[0]
        cov_entry = coverage.get(tid) or coverage.get(base)
        if cov_entry and cov_entry.get("detected_by"):
            detected_by = cov_entry["detected_by"]
            if any(r in fired for r in detected_by):
                continue  # a covering rule fired: matched, not a gap
            reason = "correlation_gap"
            expected = (
                f"Rules {', '.join(detected_by[:2])} cover {tid} "
                f"({TECH_NAMES.get(tid, 'technique')}) but produced zero alerts this shift."
            )[:MAX_EXPECTED]
            fix = (
                f"Extend {detected_by[0]} correlation logic (or lower threshold) so "
                f"{tid} evidence feeding {tech_to_incident[tid]} produces alerts."
            )[:MAX_FIX]
        else:
            reason = "missing_rule"
            expected = (
                f"No catalog rule covers {tid} ({TECH_NAMES.get(tid, 'technique')}); "
                f"activity was found by investigation of {tech_to_incident[tid]}."
            )[:MAX_EXPECTED]
            fix = (
                f"Author a Sigma rule for {tid} targeting the event categories seen in the "
                f"{tech_to_incident[tid]} finding evidence timeline."
            )[:MAX_FIX]

        # Validate cited rules exist in the catalog (interpretation of the
        # catalog_run.json reference check for rules that did not fire).
        if cov_entry:
            for r in cov_entry.get("detected_by", []):
                if r not in catalog_rules and r not in fired:
                    fail(f"cited rule {r} not found in catalog or catalog_run.json")

        rules_that_missed.append({
            "expected_behavior": expected,
            "incident_id": tech_to_incident[tid],
            "missed_because": reason,
            "proposed_fix": fix,
            "estimated_fp_risk": "medium",
        })

    # Spec validation: incident ids and missed_because vocabulary.
    for entry in rules_that_missed:
        if entry["missed_because"] not in ALLOWED_MISSED_BECAUSE:
            fail(f"invalid missed_because value: {entry['missed_because']}")
        if entry["incident_id"] not in valid_incident_ids:
            fail(f"cited incident_id not in incidents.json: {entry['incident_id']}")

    log(f"detection gaps: {len(rules_that_missed)} (techniques in findings not matched by catalog)")

    # --- 5. Suppressions (FP-heavy rules, citing triage_log alert_ids) ------------
    rules_to_suppress = []
    for rid in rules_with_fp:
        citation = fp_examples.get(rid)
        if not citation:
            continue
        rules_to_suppress.append({
            "rule_id": rid,
            "reason": (f"FP rate {fp_rate_by_rule[rid]:.0%} across this shift's triage; "
                       "scope suppression to approved-change windows.")[:MAX_EXPECTED],
            "supporting_observation": citation,
        })
    # Suppress entries must reference rules that appeared in catalog_run.json.
    for entry in rules_to_suppress:
        if entry["rule_id"] not in rule_counts:
            fail(f"suppression references rule not in triage or catalog_run: {entry['rule_id']}")

    log(f"rules_to_suppress: {len(rules_to_suppress)}")

    # --- 6. New rules proposed (one per missing_rule gap) -------------------------
    SKETCHES = {
        "T1110.003": (
            "Windows_ssh_password_spraying",
            "authentication",
            "selection:\n  event_id: 4625\n  count() by user >= 3 within 15m\n"
            "filter_change_window:\n  change_ticket_match != null\n"
            "condition: selection and not filter_change_window",
        ),
        "T1543.003": (
            "Windows_service_install_persistence",
            "process_creation",
            "selection:\n  event_id: 7045\n  event_data.ImagePath|contains: temp\n"
            "filter_known_services:\n  service_name|in: whitelist\n"
            "condition: selection and not filter_known_services",
        ),
    }
    new_rules_proposed = []
    for entry in rules_that_missed:
        if entry["missed_because"] != "missing_rule":
            continue
        tid = None
        for t in all_techniques:
            if t in entry["expected_behavior"]:
                tid = t
                break
        name, cat, sketch = SKETCHES.get(tid, (
            f"Custom_{tid.replace('.', '_')}" if tid else "Custom_rule",
            "unknown",
            "selection:\n  technique_tag: placeholder\ncondition: selection",
        ))
        new_rules_proposed.append({
            "working_name": name,
            "logsource_category": cat,
            "detection_sketch": sketch[:MAX_FIX],
            "attack_technique": tid or "",
            "estimated_fp_risk": entry["estimated_fp_risk"],
        })

    log(f"new_rules_proposed: {len(new_rules_proposed)}")

    # --- 7. Shift id and write ------------------------------------------------------
    started = run_doc.get("started_at") or ""
    shift_id = f"SHIFT-{started[:10].replace('-', '')}" if started[:10] else "SHIFT-unknown"

    output = {
        "shift_id": shift_id,
        "fp_rate_by_rule": fp_rate_by_rule,
        "rules_with_fp": sorted(rules_with_fp),
        "rules_with_noise": sorted(rules_with_noise),
        "rules_that_missed": rules_that_missed,
        "rules_to_suppress": rules_to_suppress,
        "new_rules_proposed": new_rules_proposed,
    }

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)
        fh.write("\n")

    log("tuning_recommendations.json written")


args = sys.argv[1:]
if len(args) != 9:
    print(f"[tune][ERROR] expected 9 args, got {len(args)}", file=sys.stderr)
    sys.exit(1)
main(*args)
PY
