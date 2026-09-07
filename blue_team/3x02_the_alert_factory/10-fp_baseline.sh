#!/bin/bash
#
# Name: 10-fp_baseline.sh
# Purpose: Evaluate every Sigma rule in rules/sigma/ against the 3x01 clean
#          baseline window (read from baseline_summary.json) and record the
#          per-rule false-positive count, producing fp_baseline.json and a
#          console summary sorted by fp_count descending. Rules exceeding
#          10 baseline false positives are marked [TUNE] as T11 targets.
# Author: Steve - Cybersecurity Engineer
# Date: 07 September 2026
#
# Behavior:
#   - Window source: $BASELINE_PKG/baseline_summary.json, key baseline_window
#     (start, end, duration_days - observed shape, 3x01 midnight-aligned).
#   - Correlation rules (selectors referencing correlation_primitive) are
#     invoked with --preprocess against the primitive stream.
#   - Output JSON entries: rule_id, rule_title, level, fp_count,
#     baseline_window_start, baseline_window_end, fp_rate_per_day.
#   - The official 3x01 baseline window is midnight-aligned (Mar 17 -> Mar 24)
#     and supersedes the 18:02:45-aligned conversational window split used
#     during rule measurement; counts here are canonical for the fp ledger.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="${RULES_DIR:-$SCRIPT_DIR/rules/sigma}"
RUNNER="${RUNNER:-$SCRIPT_DIR/3-sigma_runner.sh}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
SUMMARY="${SUMMARY:-$BASELINE_PKG/baseline_summary.json}"
OUTPUT="${FP_BASELINE_OUT:-$HOME/3x02_package/fp_baseline.json}"
TUNE_THRESHOLD=10

if [ ! -r "$RUNNER" ]; then
    echo "ERROR: runner not found or readable: $RUNNER" >&2
    exit 1
fi
if [ ! -r "$SUMMARY" ]; then
    echo "ERROR: baseline summary not found or readable: $SUMMARY" >&2
    exit 1
fi

# --- Extract the baseline window (direct reads, observed shape) ---
START="$(jq -r '.baseline_window.start // empty' "$SUMMARY")"
END="$(jq -r '.baseline_window.end // empty' "$SUMMARY")"
DAYS_INT="$(jq -r '.baseline_window.duration_days // 7' "$SUMMARY")"

if [ -z "$START" ] || [ -z "$END" ]; then
    echo "ERROR: could not locate baseline window start/end in $SUMMARY" >&2
    jq -r '.baseline_window // keys[]' "$SUMMARY" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
TMP_ROWS="$(mktemp)"
trap 'rm -f "$TMP_ROWS"' EXIT

RULE_COUNT="$(ls "$RULES_DIR"/*.yml | wc -l)"
echo "evaluating ${RULE_COUNT} rules against baseline window $(cut -dT -f1 <<<"$START") -> $(cut -dT -f1 <<<"$END")"

for rule in "$RULES_DIR"/*.yml; do
    name="$(basename "$rule" .yml)"
    extra=()
    if grep -q "correlation_primitive" "$rule"; then
        extra+=(--preprocess)
    fi
    if ! result="$("$RUNNER" "$rule" --window "${START},${END}" "${extra[@]}" 2>/dev/null)"; then
        echo "ERROR: runner failed on $name" >&2
        exit 1
    fi
    jq -Rrs --arg name "$name" '
        fromjson as $r |
        [($r.rule_id // "unknown"),
         ($r.rule_title // $name),
         ($r.level // "unknown"),
         ($r.match_count // 0)] | @tsv
    ' <<<"$result" >>"$TMP_ROWS"
done

# --- Print summary sorted by fp_count descending ---
printf "%-52s %-12s %6s\n" "rule" "level" "fp"
while IFS=$'\t' read -r rid rtitle rlevel fp; do
    marker=""
    if [ "$fp" -gt "$TUNE_THRESHOLD" ]; then
        marker="   [TUNE]"
    fi
    printf "%-52s %-12s %6d%s\n" "$rtitle" "$rlevel" "$fp" "$marker"
done < <(sort -t$'\t' -k4,4rn "$TMP_ROWS")

# --- Write fp_baseline.json ---
python3 - "$TMP_ROWS" "$START" "$END" "$DAYS_INT" "$OUTPUT" <<'PY'
import json
import sys

rows_path, start, end, days, out_path = sys.argv[1:6]
entries = []
with open(rows_path, encoding="utf-8") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 4:
            continue
        fp = int(parts[3])
        entries.append({
            "rule_id": parts[0],
            "rule_title": parts[1],
            "level": parts[2],
            "fp_count": fp,
            "baseline_window_start": start,
            "baseline_window_end": end,
            "fp_rate_per_day": round(fp / int(days), 2),
        })
entries.sort(key=lambda e: -e["fp_count"])
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(entries, fh, indent=2, ensure_ascii=False)
    fh.write("\n")
PY

echo "fp_baseline.json written"
