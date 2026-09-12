#!/bin/bash
# Name: 15-tool_evaluation_package.sh
# Purpose: Assemble the final tool_evaluation/ package with the locked
#          layout: findings (8), wazuh rules (4), comparison questions
#          (4) and comparison outputs (4), the tool-agnostic playbook,
#          the vendor brief, the workspace init record, and all runtime
#          task scripts 0-13 (14 files). Verifies every required file
#          exists and is non-empty BEFORE copying and fails loudly on
#          any miss (brief and playbook abort the run outright).
#          Generates MANIFEST.json recording path, size, and sha256 for
#          each of the 37 entries, then re-verifies every hash against
#          the copied files as a sanity check.
# Author: Steve - Cybersecurity Engineer
# Date: 12 September 2026

set -u -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PKG_ROOT="${PKG_ROOT:-$SCRIPT_DIR/tool_evaluation}"
FINDINGS_SRC="$SCRIPT_DIR/findings"
RULES_SRC="$SCRIPT_DIR/rules/wazuh"
COMPARE_SRC="$SCRIPT_DIR/comparison"
PLAYBOOK_SRC="${PLAYBOOK_SRC:-$SCRIPT_DIR/playbook/tool_agnostic_playbook.md}"
BRIEF_SRC="${BRIEF_SRC:-$SCRIPT_DIR/brief/vendor_brief.md}"
WORKSPACE_SRC="$SCRIPT_DIR/workspace/workspace_init.json"

EXPECTED_ENTRIES=37

failures=0
fail() {
    printf '%-20s : FAIL (%s)\n' "$1" "$2"
    failures=$((failures + 1))
}

# ---------------------------------------------------------------------------
# Required file lists (locked layout).
# ---------------------------------------------------------------------------
FINDING_FILES=(
    anchor_cli.json anchor_export.json
    scenario_a_cli.json scenario_a_export.json
    scenario_b_cli.json scenario_b_export.json
    scenario_c_cli.json scenario_c_export.json
)
RULE_FILES=(
    001_ssh_brute_force.xml
    003_interpreter_abuse.xml
    010_credential_theft_chain.xml
    translation_report.json
)
QUESTION_FILES=(q1.yml q2.yml q3.yml q4.yml)
COMPARISON_FILES=(
    query_comparison.json
    tradeoff_table.json
    tradeoff_table.md
    workflow_comparison.json
)
RUNTIME_FILES=(
    0-tool_check.sh
    1-wazuh_workspace.sh
    2-cli_anchor.sh
    3-export_anchor.sh
    4-cli_scenario_a.sh
    5-cli_scenario_b.sh
    6-cli_scenario_c.sh
    7-export_scenario_a.sh
    8-export_scenario_b.sh
    9-export_scenario_c.sh
    10-rule_translation.sh
    11-query_comparison.sh
    12-tradeoff_analysis.sh
    13-workflow_comparison.sh
)

# ---------------------------------------------------------------------------
# Pre-flight: every required file exists and is non-empty. Brief and
# playbook are abort conditions on their own. Sigma question blocks live
# under comparison/questions/ (written there by 11-query_comparison.sh).
# ---------------------------------------------------------------------------
preflight=0
for f in "${FINDING_FILES[@]}"; do
    [[ -s "$FINDINGS_SRC/$f" ]] || { fail "findings" "missing: $FINDINGS_SRC/$f"; preflight=1; }
done
for f in "${RULE_FILES[@]}"; do
    [[ -s "$RULES_SRC/$f" ]] || { fail "rules" "missing: $RULES_SRC/$f"; preflight=1; }
done
for f in "${QUESTION_FILES[@]}"; do
    [[ -s "$COMPARE_SRC/questions/$f" ]] || { fail "comparison" "missing: $COMPARE_SRC/questions/$f"; preflight=1; }
done
for f in "${COMPARISON_FILES[@]}"; do
    [[ -s "$COMPARE_SRC/$f" ]] || { fail "comparison" "missing: $COMPARE_SRC/$f"; preflight=1; }
done
for f in "${RUNTIME_FILES[@]}"; do
    [[ -s "$SCRIPT_DIR/$f" ]] || { fail "runtime" "missing: $SCRIPT_DIR/$f"; preflight=1; }
done
[[ -s "$WORKSPACE_SRC" ]] || { fail "workspace" "missing: $WORKSPACE_SRC"; preflight=1; }

if [[ ! -s "$BRIEF_SRC" ]]; then
    fail "brief" "vendor brief missing or empty: $BRIEF_SRC - aborting"
    exit 1
fi
if [[ ! -s "$PLAYBOOK_SRC" ]]; then
    fail "playbook" "playbook missing or empty: $PLAYBOOK_SRC - aborting"
    exit 1
fi
if (( preflight > 0 )); then
    exit 1
fi

# ---------------------------------------------------------------------------
# Copy groups into the locked layout.
# ---------------------------------------------------------------------------
copy_group() {
    # copy_group <dest_subdir> <src_dir> <files...>; counts and copies.
    local dest="$PKG_ROOT/$1" src_dir="$2"
    shift 2
    mkdir -p "$dest"
    local n=0 f
    for f in "$@"; do
        cp -p "$src_dir/$f" "$dest/$f"
        n=$(( n + 1 ))
    done
    echo "$n"
}

n_findings=$(copy_group "findings" "$FINDINGS_SRC" "${FINDING_FILES[@]}")
n_rules=$(copy_group "rules/wazuh" "$RULES_SRC" "${RULE_FILES[@]}")
mkdir -p "$PKG_ROOT/comparison/questions"
n_questions=$(copy_group "comparison/questions" "$COMPARE_SRC/questions" "${QUESTION_FILES[@]}")
n_comparison=$(copy_group "comparison" "$COMPARE_SRC" "${COMPARISON_FILES[@]}")

mkdir -p "$PKG_ROOT/playbook" "$PKG_ROOT/brief"
cp -p "$PLAYBOOK_SRC" "$PKG_ROOT/playbook/tool_agnostic_playbook.md"
cp -p "$BRIEF_SRC" "$PKG_ROOT/brief/vendor_brief.md"

mkdir -p "$PKG_ROOT/workspace"
cp -p "$WORKSPACE_SRC" "$PKG_ROOT/workspace/workspace_init.json"

n_runtime=$(copy_group "runtime" "$SCRIPT_DIR" "${RUNTIME_FILES[@]}")

printf 'copying findings   : %s files\n' "$n_findings"
printf 'copying rules      : %s files\n' "$n_rules"
printf 'copying comparison : %s files\n' "$(( n_questions + n_comparison ))"
printf 'copying playbook   : 1 file\n'
printf 'copying brief      : 1 file\n'
printf 'copying workspace  : 1 file\n'
printf 'copying runtime    : %s files\n' "$n_runtime"

# ---------------------------------------------------------------------------
# MANIFEST.json: path, size, sha256 for every file under the package.
# ---------------------------------------------------------------------------
manifest_tmp="$(mktemp)"
trap 'rm -f "$manifest_tmp"' EXIT
printf '%s' "[" > "$manifest_tmp"
first="true"

while IFS= read -r -d '' f; do
    rel="${f#"$PKG_ROOT"/}"
    size=$(stat -c '%s' "$f")
    hash=$(sha256sum "$f" | awk '{print $1}')
    entry=$(jq -nc --arg p "$rel" --argjson s "$size" --arg h "$hash" \
        '{path: $p, size: $s, sha256: $h}')
    [[ "$first" == "false" ]] && printf '%s' "," >> "$manifest_tmp"
    first="false"
    printf '%s' "$entry" >> "$manifest_tmp"
done < <(find "$PKG_ROOT" -type f -not -name MANIFEST.json -print0 | sort -z)

printf '%s' "]" >> "$manifest_tmp"

jq --arg g "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{generated_at: $g, package: "tool_evaluation", files: .}' \
    "$manifest_tmp" > "$PKG_ROOT/MANIFEST.json"

n_entries=$(jq '.files | length' "$PKG_ROOT/MANIFEST.json")
printf 'MANIFEST.json      : %s entries\n' "$n_entries"

# ---------------------------------------------------------------------------
# Sanity check: hash-verify every manifest entry against the copied file,
# and confirm the entry count matches the locked layout.
# ---------------------------------------------------------------------------
ok=1
[[ "$n_entries" -eq "$EXPECTED_ENTRIES" ]] || { fail "manifest" "expected $EXPECTED_ENTRIES entries, got $n_entries"; ok=0; }

while IFS=$'\t' read -r p h; do
    actual=$(sha256sum "$PKG_ROOT/$p" 2>/dev/null | awk '{print $1}') || actual=""
    if [[ "$actual" != "$h" ]]; then
        fail "verify" "hash mismatch: $p"
        ok=0
    fi
done < <(jq -r '.files[] | [.path, .sha256] | @tsv' "$PKG_ROOT/MANIFEST.json")

if [[ "$ok" -eq 1 ]]; then
    printf 'sanity check       : ok\n'
    printf '%s\n' "tool_evaluation/ ready"
    exit 0
fi
exit 1
