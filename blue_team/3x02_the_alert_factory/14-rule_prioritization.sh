#!/bin/bash
#
# Name: 14-rule_prioritization.sh
# Purpose: Rank detection rules by organizational risk: intersect each rule's
#          MITRE ATT&CK tags with risk register scenarios, weight by rule F1,
#          emit rule_prioritization.json plus a console top-10 ranking.
# Author: Steve - Cybersecurity Engineer
# Date: 2026/09/07
#
# Inputs:
#   $ASSETS_DIR/risk_register.json  - threat scenarios (likelihood/impact/mitre_techniques)
#   $RULE_QUALITY                   - rule_quality.json from 13-rule_quality.sh
#   $ATTACK_COVERAGE                - attack_coverage.json from 12-attack_coverage.sh
# Output:
#   $OUT_JSON                       - rule_prioritization.json
#
# Deviations (documented):
#   1. Register stores likelihood/impact as words; numeric scales default to
#      likelihood {low:1,medium:2,high:3}, impact {low:1,medium:2,high:3,critical:4}.
#      Overridable via LIKELIHOOD_SCALE / IMPACT_SCALE env vars (JSON objects).
#   2. Technique intersection is hierarchical (case-insensitive): a base technique
#      (t1078) matches its sub-techniques (T1078.002) and vice versa. Precedent:
#      attack_coverage.json classifies such pairs as "granularity", not mismatch.
#   3. Rules with f1=null (undefined F1) are scored as f1=0; the task's
#      risk_score*0.1 floor for f1=0 rules then applies.
#   4. Tuned variants get their own entries (18 total from rule_quality.json).
#   5. Display labels reuse rule_quality.json's "display" field (already carries
#      "(tuned)" for variants; no suffix appended here).

set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RULE_QUALITY="${RULE_QUALITY:-$HOME/3x02_package/rule_quality.json}"
ATTACK_COVERAGE="${ATTACK_COVERAGE:-$HOME/3x02_package/attack_coverage.json}"
OUT_JSON="${OUT_JSON:-$HOME/3x02_package/rule_prioritization.json}"
LIKELIHOOD_SCALE="${LIKELIHOOD_SCALE:-{\"low\":1,\"medium\":2,\"high\":3}}"
IMPACT_SCALE="${IMPACT_SCALE:-{\"low\":1,\"medium\":2,\"high\":3,\"critical\":4}}"
export ASSETS_DIR RULE_QUALITY ATTACK_COVERAGE OUT_JSON LIKELIHOOD_SCALE IMPACT_SCALE

for f in "$ASSETS_DIR/risk_register.json" "$RULE_QUALITY" "$ATTACK_COVERAGE"; do
    if [[ ! -f "$f" ]]; then
        echo "error: required input not found: $f" >&2
        exit 1
    fi
done

python3 - <<'PYEOF'
import json
import os
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("error: python3 yaml module (PyYAML) required\n")
    sys.exit(1)

assets_dir = os.environ["ASSETS_DIR"]
rule_quality_path = os.environ["RULE_QUALITY"]
attack_coverage_path = os.environ["ATTACK_COVERAGE"]
out_path = os.environ["OUT_JSON"]
like_scale = json.loads(os.environ["LIKELIHOOD_SCALE"])
impact_scale = json.loads(os.environ["IMPACT_SCALE"])

def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

def norm(tech):
    return tech.strip().upper()

def tech_match(a, b):
    """Exact match, or one side is the base of the other's sub-technique."""
    return a == b or a.startswith(b + ".") or b.startswith(a + ".")

def rule_techniques(path):
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    techs = set()
    for tag in (doc.get("tags") or []):
        if isinstance(tag, str) and tag.lower().startswith("attack.t"):
            techs.add(norm(tag.split(".", 1)[1]))
    return techs

register = load(os.path.join(assets_dir, "risk_register.json"))
quality = load(rule_quality_path)
coverage = load(attack_coverage_path)

scenarios = []
for sc in register.get("scenarios", []):
    like = like_scale.get(str(sc.get("likelihood", "")).lower())
    imp = impact_scale.get(str(sc.get("impact", "")).lower())
    if like is None or imp is None:
        sys.stderr.write(
            "error: scenario %s has unmapped likelihood=%r impact=%r\n"
            % (sc.get("scenario_id"), sc.get("likelihood"), sc.get("impact"))
        )
        sys.exit(1)
    scenarios.append({
        "scenario_id": sc.get("scenario_id"),
        "weight": like * imp,
        "techniques": {norm(t) for t in (sc.get("mitre_techniques") or [])},
    })

entries = []
for rq in quality.get("rules", []):
    techs = rule_techniques(rq["path"])
    covering = []
    risk_score = 0
    for sc in scenarios:
        if any(tech_match(rt, st) for rt in techs for st in sc["techniques"]):
            covering.append(sc["scenario_id"])
            risk_score += sc["weight"]
    f1 = rq.get("f1")
    eff_f1 = f1 if isinstance(f1, (int, float)) else 0.0
    priority = risk_score * eff_f1
    if eff_f1 == 0 and risk_score > 0:
        priority = risk_score * 0.1
    entries.append({
        "rule_id": rq.get("rule_id"),
        "rule": rq.get("rule"),
        "rule_title": rq.get("rule_title"),
        "variant": rq.get("variant"),
        "display": rq.get("display", rq.get("rule", "")),
        "level": rq.get("level"),
        "techniques": sorted(techs),
        "covering_scenarios": covering,
        "risk_score": risk_score,
        "f1": f1,
        "priority_score": round(priority, 4),
    })

entries.sort(key=lambda e: (-e["priority_score"], e["display"] or ""))

result = {
    "generator": "14-rule_prioritization.sh",
    "inputs": {
        "risk_register": os.path.join(assets_dir, "risk_register.json"),
        "rule_quality": rule_quality_path,
        "attack_coverage": attack_coverage_path,
    },
    "likelihood_scale": like_scale,
    "impact_scale": impact_scale,
    "matching_semantics": (
        "hierarchical case-insensitive ATT&CK technique intersection (base "
        "technique matches its sub-techniques); risk_score = sum(likelihood*"
        "impact) over covering scenarios; priority_score = risk_score * f1 "
        "with risk_score*0.1 floor when f1 is 0 or null"
    ),
    "coverage_summary": coverage.get("coverage_summary"),
    "rules": entries,
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, indent=2)
    fh.write("\n")

print("evaluating %d rules against risk register" % len(entries))
print("top 10 rules by priority_score")
for i, e in enumerate(entries[:10], start=1):
    print("%2d %6.1f  %s" % (i, e["priority_score"], e["display"]))
orphans = [e for e in entries if e["priority_score"] == 0]
print("orphan rules (no risk scenario covers) : %d" % len(orphans))
for e in orphans:
    print("  %s" % e["display"])
print("%s written" % out_path)
PYEOF
