#!/bin/bash
#
# Name: 11-tune_rules.sh
# Purpose: Tuning pass on every rule flagged [TUNE] in fp_baseline.json.
#          Runs the original and tuned variant (rules/sigma/tuned/) against
#          the clean baseline window (fp) and the attack-bearing window
#          (tp), enforces acceptance (fp_after < fp_before/2 AND
#          tp_after >= tp_before), and writes tuning_report.json.
# Author: Steve - Cybersecurity Engineer
# Date: 07 September 2026
#
# Window notes:
#   - fp window: baseline_window from $BASELINE_PKG/baseline_summary.json
#     (official, midnight-aligned Mar 17 -> Mar 24).
#   - tp window: baseline end -> EVAL_END. The summary's own evaluation_window
#     (Mar 24 -> Mar 25) ends before the March 25 intrusion activity, so the
#     recall leg uses EVAL_END (default 2026-03-27T00:00:00Z, dataset ends
#     03-26T01:57) — documented deviation, without which tp_before is
#     structurally 0 and the recall test is vacuous.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="${RULES_DIR:-$SCRIPT_DIR/rules/sigma}"
TUNED_DIR="$RULES_DIR/tuned"
RUNNER="${RUNNER:-$SCRIPT_DIR/3-sigma_runner.sh}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SUMMARY="${SUMMARY:-$BASELINE_PKG/baseline_summary.json}"
FP_BASELINE="${FP_BASELINE:-$HOME/3x02_package/fp_baseline.json}"
OUTPUT="${TUNING_REPORT_OUT:-$HOME/3x02_package/tuning_report.json}"
EVAL_END="${EVAL_END:-2026-03-27T00:00:00Z}"
TUNE_THRESHOLD=10

if [ ! -r "$RUNNER" ] || [ ! -r "$SUMMARY" ] || [ ! -r "$FP_BASELINE" ]; then
    echo "ERROR: runner, baseline_summary.json, and fp_baseline.json are all required" >&2
    exit 1
fi

START="$(jq -r '.baseline_window.start // empty' "$SUMMARY")"
END="$(jq -r '.baseline_window.end // empty' "$SUMMARY")"
if [ -z "$START" ] || [ -z "$END" ]; then
    echo "ERROR: baseline window not found in $SUMMARY" >&2
    exit 1
fi
BWIN="${START},${END}"
EWIN="${END},${EVAL_END}"

LOGDIR="$(mktemp -d)"
trap 'rm -rf "$LOGDIR"' EXIT

ROWS="$(mktemp)"

noise_rules=0
accepted=0
rejected=0

for rule in "$RULES_DIR"/*.yml; do
    name="$(basename "$rule" .yml)"
    rid="$(awk '/^id:/ {print $2; exit}' "$rule")"
    fp_before="$(jq -r --arg id "$rid" '
        ([.[] | select(.rule_id == $id) | .fp_count] | first) // 0' "$FP_BASELINE")"

    # task scope: only rules above the noise threshold
    if [ "$fp_before" -le "$TUNE_THRESHOLD" ]; then
        continue
    fi
    noise_rules=$((noise_rules + 1))

    tuned="$TUNED_DIR/${name}.yml"
    if [ ! -r "$tuned" ]; then
        echo "tuning $name"
        echo "  ERROR: no tuned variant at rules/sigma/tuned/${name}.yml" >&2
        exit 1
    fi
    tid="$(awk '/^id:/ {print $2; exit}' "$tuned")"

    echo "tuning $name" >&2
    tp_before="$("$RUNNER" "$rule"  --window "$EWIN" --count-only 2>>"$LOGDIR/runner.log")"
    fp_after="$("$RUNNER" "$tuned" --window "$BWIN" --count-only 2>>"$LOGDIR/runner.log")"
    tp_after="$("$RUNNER" "$tuned" --window "$EWIN" --count-only 2>>"$LOGDIR/runner.log")"

    # exclusions added: delta of filter_* selection keys between variants
    excl_before="$(grep -cE '^[[:space:]]+filter_[a-z_]+:' "$rule" || true)"
    excl_after="$(grep -cE '^[[:space:]]+filter_[a-z_]+:' "$tuned" || true)"
    exclusions=$((excl_after > excl_before ? excl_after - excl_before : 0))

    justification="$(awk '/^justification:/ {sub(/^justification:[ ]*/, ""); print; exit}' "$tuned")"
    [ -n "$justification" ] || justification="(none documented)"

    verdict="ACCEPTED"
    if [ "$((2 * fp_after))" -ge "$fp_before" ] || [ "$tp_after" -lt "$tp_before" ]; then
        verdict="REJECTED"
        rejected=$((rejected + 1))
    else
        accepted=$((accepted + 1))
    fi

    echo "tuning $name"
    echo "  exclusions added : $exclusions"
    echo "  fp $fp_before -> $fp_after    tp $tp_before -> $tp_after    $verdict"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$rid" "$tid" "$fp_before" "$fp_after" "$tp_before" "$tp_after" \
        "$exclusions" "$verdict" "$justification" >>"$ROWS"
done

python3 - "$ROWS" "$OUTPUT" <<'PY'
import json
import sys

rows_path, out_path = sys.argv[1:3]
entries = []
with open(rows_path, encoding="utf-8") as fh:
    for line in fh:
        p = line.rstrip("\n").split("\t")
        if len(p) < 9:
            continue
        entries.append({
            "original_rule_id": p[0],
            "tuned_rule_id": p[1],
            "fp_before": int(p[2]),
            "fp_after": int(p[3]),
            "tp_before": int(p[4]),
            "tp_after": int(p[5]),
            "exclusions_added": int(p[6]),
            "verdict": p[7],
            "tuning_justification": p[8],
        })
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump({
        "tuned": len(entries),
        "accepted": sum(1 for e in entries if e["verdict"] == "ACCEPTED"),
        "rejected": sum(1 for e in entries if e["verdict"] == "REJECTED"),
        "entries": entries,
    }, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
PY

echo "${noise_rules} rules tuned  ${accepted} accepted  ${rejected} rejected"
echo "tuning_report.json written"
