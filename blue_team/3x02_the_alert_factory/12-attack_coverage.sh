#!/bin/bash
#
# Name: 12-attack_coverage.sh
# Purpose: Aggregate every Sigma rule's ATT&CK technique tags into a tactic
#          coverage map (attack_coverage.json) and print a tactic-by-tactic
#          coverage table. Rule-declared attack.tXXXX[.YYY] tags are joined
#          against the bundled attack taxonomy; base technique tags with no
#          direct taxonomy entry inherit their sub-technique entries, and
#          tags absent from the taxonomy are reported, never silently dropped.
# Author: Steve - Cybersecurity Engineer
# Date: 2026/09/07
#
# Environment:
#   ASSETS_DIR           directory containing attack_taxonomy.json
#                        (default: ~/3x02_assets)
#   RULES_DIR            Sigma rules directory, scanned together with its
#                        tuned/ subdirectory (default: ~/3x02_scripts/rules/sigma)
#   ATTACK_COVERAGE_OUT  output JSON path (default: ./attack_coverage.json)

set -euo pipefail

ASSETS_DIR="${ASSETS_DIR:-$HOME/3x02_assets}"
RULES_DIR="${RULES_DIR:-$HOME/3x02_scripts/rules/sigma}"
OUTPUT_PATH="${ATTACK_COVERAGE_OUT=$HOME/3x02_package/attack_coverage.json}"

TAXONOMY_FILE="$ASSETS_DIR/attack_taxonomy.json"

if [ ! -f "$TAXONOMY_FILE" ]; then
    echo "ERROR: taxonomy not found: $TAXONOMY_FILE" >&2
    exit 1
fi
if [ ! -d "$RULES_DIR" ]; then
    echo "ERROR: rules directory not found: $RULES_DIR" >&2
    exit 1
fi
if [ ! -d "$RULES_DIR/tuned" ]; then
    echo "WARNING: no tuned/ directory under $RULES_DIR; scanning base rules only" >&2
fi
OUT_DIR="$(dirname "$OUTPUT_PATH")"
if [ ! -d "$OUT_DIR" ]; then
    echo "ERROR: output directory not found: $OUT_DIR" >&2
    exit 1
fi

RULES_DIR="$RULES_DIR" \
TAXONOMY_FILE="$TAXONOMY_FILE" \
OUTPUT_PATH="$OUTPUT_PATH" \
python3 <<'PYEOF'
import glob
import json
import os
import re

import yaml

TAG_RE = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)\Z")

rules_dir = os.environ["RULES_DIR"]
taxonomy_file = os.environ["TAXONOMY_FILE"]
output_path = os.environ["OUTPUT_PATH"]

with open(taxonomy_file, encoding="utf-8") as fh:
    taxonomy = json.load(fh)

tactics = taxonomy["tactics"]
techniques = taxonomy["techniques"]
tech_by_id = {t["technique_id"]: t for t in techniques}

# Normalize rule_to_technique_map for both possible shapes:
# object {"rule": ["TXXXX"]} or list of {"key": ..., "value": [...]}.
_rt = taxonomy.get("rule_to_technique_map", [])
if isinstance(_rt, dict):
    map_by_rule = {str(k): list(v) for k, v in _rt.items()}
elif isinstance(_rt, list):
    map_by_rule = {e["key"]: e["value"] for e in _rt}
else:
    map_by_rule = {}

rule_files = sorted(
    glob.glob(os.path.join(rules_dir, "*.yml"))
    + glob.glob(os.path.join(rules_dir, "tuned", "*.yml"))
)
if not rule_files:
    raise SystemExit("ERROR: no .yml rules found under " + rules_dir)

# Pass 1: collect declared technique tags per rule stem (tuned variants
# share stems with originals, so unions collapse naturally).
declared_by_rule = {}
for path in rule_files:
    stem = os.path.splitext(os.path.basename(path))[0]
    with open(path, encoding="utf-8") as fh:
        rule = yaml.safe_load(fh)
    tags = rule.get("tags") or []
    declared = set()
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = TAG_RE.match(tag.strip())
        if match:
            declared.add(match.group(1))
    declared_by_rule.setdefault(stem, set()).update(declared)

# Pass 2: resolve tags to taxonomy technique IDs.
# Direct hit -> direct. Base tag (no dot) with no direct entry but
# sub-technique children in the taxonomy -> inherit all children.
# Otherwise -> unmapped, reported.
tech_detail = {}
unmapped_tags = {}
for stem, tags in sorted(declared_by_rule.items()):
    for tag in sorted(tags):
        tid = "T" + tag[1:].upper()
        if tid in tech_by_id:
            entry = tech_detail.setdefault(
                tid, {"detected_by": set(), "resolution": "direct", "declared_as": set()}
            )
            entry["detected_by"].add(stem)
            entry["declared_as"].add(tag)
            continue
        if "." not in tid:
            children = sorted(k for k in tech_by_id if k.startswith(tid + "."))
            if children:
                for child in children:
                    entry = tech_detail.setdefault(
                        child,
                        {
                            "detected_by": set(),
                            "resolution": "inherited-from-base:" + tid,
                            "declared_as": set(),
                        },
                    )
                    entry["detected_by"].add(stem)
                    entry["declared_as"].add(tag)
                continue
        unmapped_tags.setdefault(tid, set()).add(stem)

# Matrix: tactic -> sorted list of covered technique IDs, in taxonomy order.
coverage_matrix = {}
for tac in tactics:
    tactic_id = tac["tactic_id"]
    coverage_matrix[tactic_id] = sorted(
        t for t in tech_detail
        if t in tech_by_id and tech_by_id[t]["tactic"] == tactic_id
    )

uncovered_tactics = [
    tac["tactic_id"] for tac in tactics if not coverage_matrix[tac["tactic_id"]]
]
uncovered_tactics_detail = [
    {"tactic_id": t["tactic_id"], "name": t["name"], "shortname": t["shortname"]}
    for t in tactics if not coverage_matrix[t["tactic_id"]]
]

# Cross-check: rule-declared tags vs taxonomy rule_to_technique_map.
discrepancies = []
for stem in sorted(set(declared_by_rule) & set(map_by_rule)):
    declared_norm = sorted("T" + t[1:].upper() for t in declared_by_rule[stem])
    mapped = sorted(map_by_rule[stem])
    if declared_norm == mapped:
        kind = "match"
    elif all(any(m == d or m.startswith(d + ".") for m in mapped) for d in declared_norm):
        kind = "granularity: rule declares base technique, taxonomy map lists sub-technique"
    else:
        kind = "mismatch: rule tags and taxonomy map disagree beyond granularity"
    if kind != "match":
        discrepancies.append(
            {
                "rule": stem,
                "rule_declared": declared_norm,
                "taxonomy_map": mapped,
                "classification": kind,
            }
        )

map_refs_missing = sorted(
    {t for vals in map_by_rule.values() for t in vals if t not in tech_by_id}
)

covered_ids = sorted(t for t in tech_detail if t in tech_by_id)
result = {
    "generator": "12-attack_coverage.sh",
    "taxonomy_source": taxonomy.get("source", ""),
    "taxonomy_version": taxonomy.get("version", ""),
    "rules_scanned": [os.path.relpath(p, rules_dir) for p in rule_files],
    "coverage_matrix": coverage_matrix,
    "tactics_reference": [
        {"tactic_id": t["tactic_id"], "name": t["name"], "shortname": t["shortname"]}
        for t in tactics
    ],
    "covered_techniques_detail": {
        tid: {
            "name": tech_by_id[tid]["name"],
            "tactic": tech_by_id[tid]["tactic"],
            "resolution": tech_detail[tid]["resolution"],
            "declared_as": sorted(tech_detail[tid]["declared_as"]),
            "detected_by": sorted(tech_detail[tid]["detected_by"]),
        }
        for tid in covered_ids
    },
    "uncovered_tactics": uncovered_tactics,
    "uncovered_tactics_detail": uncovered_tactics_detail,
    "unmapped_tags": {
        tag: {"contributing_rules": sorted(rules)}
        for tag, rules in sorted(unmapped_tags.items())
    },
    "rule_to_technique_map_discrepancies": discrepancies,
    "rule_to_technique_map_refs_absent_from_taxonomy": map_refs_missing,
    "coverage_summary": {
        "tactics_total": len(tactics),
        "tactics_covered": len(tactics) - len(uncovered_tactics),
        "tactics_with_zero_coverage": len(uncovered_tactics),
        "techniques_in_taxonomy": len(techniques),
        "techniques_covered": len(covered_ids),
        "distinct_unmapped_tags": len(unmapped_tags),
    },
    "notes": [
        "Technique-to-tactic mapping is single-valued in the bundled taxonomy: "
        "techniques ATT&CK assigns to multiple tactics appear in one column only "
        "(T1078 is mapped to initial access here, so rules 002/010/013 contribute "
        "no privilege-escalation coverage).",
        "Base technique tags with no direct taxonomy entry inherit their "
        "sub-technique entries (t1071 -> T1071.001, t1110 -> T1110.001); "
        "inherited entries deduplicate against direct declarations.",
        "Coverage derives from rule-declared tags per task instructions; "
        "rule_to_technique_map is cross-checked and differences reported, "
        "not merged into the matrix.",
        "Impact (TA0040) is absent from the bundled taxonomy, so no impact "
        "row is emitted.",
    ],
}

with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh, indent=2)
    fh.write("\n")

labels = [tac["shortname"].replace("-", "_") for tac in tactics]
width = max(len(label) for label in labels)
for tac, label in zip(tactics, labels):
    count = len(coverage_matrix[tac["tactic_id"]])
    unit = "technique" if count == 1 else "techniques"
    gap = "  [GAP]" if count == 0 else ""
    print("%-*s  %d %s%s" % (width, label, count, unit, gap))
PYEOF

echo "${OUTPUT_PATH} written"
