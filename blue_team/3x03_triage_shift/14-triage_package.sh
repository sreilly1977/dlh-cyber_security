#!/bin/bash
# Name: 14-triage_package.sh
# Purpose: Process Batch 12 triage package assembly. Verifies every
#          required source file exists and is non-empty (failing loudly
#          with a complete list of missing/empty files otherwise, with
#          the shift report and methodology treated as mandatory),
#          assembles the locked package layout under $TRIAGE_PKG
#          (tickets/, incidents/, tuning/, metrics/, reports/, spec/,
#          runtime/), copies every listed file (same-file copies are
#          skipped via inode identity rather than erroring), generates
#          MANIFEST.json with path, size, and sha256 for all 25 entries
#          (sorted by path; no wall-clock fields, so reruns are
#          byte-stable), and runs a post-copy sanity check re-hashing
#          every entry against the manifest.
#          Data-artifact sources (incidents.json,
#          tuning_recommendations.json, queue_assessment.json,
#          shift_metrics.json) are resolved canonical-subdirectory-first
#          via SRC_OF, falling back to the legacy flat package-root
#          path, so the packager is idempotent whether or not the root
#          stragglers have been cleaned up.
# Author: Steve - Cybersecurity Engineer
# Date: 08 September 2026

set -euo pipefail

TRIAGE_PKG="${TRIAGE_PKG:-$HOME/3x03_package/triage_package}"
ASSETS_DIR="${ASSETS_DIR:-$HOME/3x03_assets}"
RUNTIME_DIR="${RUNTIME_DIR:-$ASSETS_DIR/scripts}"
if [[ ! -d "$RUNTIME_DIR" ]]; then
    RUNTIME_DIR="$ASSETS_DIR"
fi

TICKETS=(batch1_clearcut_tp.json batch2_clearcut_fp.json
         batch3_benign.json batch4_auth.json batch5_proc_net.json
         batch6_incidents.json batch7_overrides.json)
METRICS=(queue_assessment.json shift_metrics.json)
RUNTIME=(0-queue_assessment.sh 2-context_assembly.sh
         3-triage_clearcut_tp.sh 4-triage_clearcut_fp.sh
         5-triage_benign.sh 6-triage_ambiguous_auth.sh
         7-triage_ambiguous_proc_net.sh 8-triage_correlation.sh
         9-triage_priority_conflicts.sh 10-fp_tuning.sh
         11-incident_assembly.sh 12-shift_metrics.sh)
EXPECTED_ENTRIES=25

# rel-path -> absolute source / destination
declare -A SRCS DESTS
add_pair() {
    local rel="$1" src="$2"
    SRCS["$rel"]="$src"
    DESTS["$rel"]="$TRIAGE_PKG/$rel"
}

# Canonical-subdirectory-first source resolution with legacy flat-path
# fallback. Prints the usable path; caller supplies both candidates.
SRC_OF() {
    local canon="$1" legacy="$2"
    if [[ -s "$canon" ]]; then
        printf '%s' "$canon"
    else
        printf '%s' "$legacy"
    fi
}

SECTION_TICKETS=()
for f in "${TICKETS[@]}"; do
    add_pair "tickets/$f" "$TRIAGE_PKG/tickets/$f"
    SECTION_TICKETS+=("tickets/$f")
done
add_pair "incidents/incidents.json" \
         "$(SRC_OF "$TRIAGE_PKG/incidents/incidents.json" \
                   "$TRIAGE_PKG/incidents.json")"
SECTION_INCIDENTS=("incidents/incidents.json")
add_pair "tuning/tuning_recommendations.json" \
         "$(SRC_OF "$TRIAGE_PKG/tuning/tuning_recommendations.json" \
                   "$TRIAGE_PKG/tuning_recommendations.json")"
SECTION_TUNING=("tuning/tuning_recommendations.json")
SECTION_METRICS=()
for f in "${METRICS[@]}"; do
    add_pair "metrics/$f" \
             "$(SRC_OF "$TRIAGE_PKG/metrics/$f" "$TRIAGE_PKG/$f")"
    SECTION_METRICS+=("metrics/$f")
done
add_pair "reports/shift_report.md" "$TRIAGE_PKG/reports/shift_report.md"
SECTION_REPORTS=("reports/shift_report.md")
add_pair "spec/triage_methodology.md" \
         "$TRIAGE_PKG/spec/triage_methodology.md"
SECTION_SPEC=("spec/triage_methodology.md")
SECTION_RUNTIME=()
for f in "${RUNTIME[@]}"; do
    add_pair "runtime/$f" "$RUNTIME_DIR/$f"
    SECTION_RUNTIME+=("runtime/$f")
done

# ---------------------------------------------------------------------------
# Pre-flight: every source must exist and be non-empty. Fail loudly with
# the complete list; the shift report and methodology are mandatory.
# ---------------------------------------------------------------------------
missing=0
for rel in "${!SRCS[@]}"; do
    src="${SRCS[$rel]}"
    if [[ ! -e "$src" ]]; then
        echo "MISSING: $src (required at $rel)" >&2
        missing=1
    elif [[ ! -s "$src" ]]; then
        echo "EMPTY   : $src (required at $rel)" >&2
        missing=1
    fi
done
if (( missing )); then
    echo "ERROR: package assembly aborted; fix the files above" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Copy one section; same-inode destinations (files already in place) are
# skipped rather than cp-ed onto themselves.
# ---------------------------------------------------------------------------
copy_section() {
    local label="$1"
    shift
    local rels=("$@")
    local rel dst
    for rel in "${rels[@]}"; do
        dst="${DESTS[$rel]}"
        mkdir -p "$(dirname "$dst")"
        if [[ -e "$dst" && "${SRCS[$rel]}" -ef "$dst" ]]; then
            continue
        fi
        cp "${SRCS[$rel]}" "$dst"
    done
    local n=${#rels[@]}
    local noun="files"
    if (( n == 1 )); then
        noun="file"
    fi
    printf 'copying %-11s ... %d %s\n' "$label" "$n" "$noun"
}

copy_section "tickets" "${SECTION_TICKETS[@]}"
copy_section "incidents" "${SECTION_INCIDENTS[@]}"
copy_section "tuning" "${SECTION_TUNING[@]}"
copy_section "metrics" "${SECTION_METRICS[@]}"
copy_section "reports" "${SECTION_REPORTS[@]}"
copy_section "spec" "${SECTION_SPEC[@]}"
copy_section "runtime" "${SECTION_RUNTIME[@]}"

# ---------------------------------------------------------------------------
# MANIFEST.json: path, size, sha256 per entry, sorted by path
# ---------------------------------------------------------------------------
mapfile -t RELS < <(printf '%s\n' "${!DESTS[@]}" | LC_ALL=C sort)

if (( ${#RELS[@]} != EXPECTED_ENTRIES )); then
    echo "ERROR: expected $EXPECTED_ENTRIES entries, found ${#RELS[@]}" >&2
    exit 1
fi

json_parts=()
hashes=()
sizes=()
for rel in "${RELS[@]}"; do
    full="${DESTS[$rel]}"
    size=$(stat -c '%s' "$full")
    hash=$(sha256sum "$full" | awk '{print $1}')
    sizes+=("$size")
    hashes+=("$hash")
    json_parts+=('    { "path": "'"$rel"'", "size": '"$size"', "sha256": "'"$hash"'" }')
done

{
    echo '{'
    echo '  "package": "triage_package",'
    echo '  "module": "3x03_triage_shift",'
    echo '  "entry_count": '"${#RELS[@]}"','
    echo '  "entries": ['
    printf '%s\n' "${json_parts[@]}" | paste -sd ',' -
    echo '  ]'
    echo '}'
} > "$TRIAGE_PKG/MANIFEST.json"

# ---------------------------------------------------------------------------
# Sanity check: re-verify every entry is present, non-empty, and its
# sha256 matches the manifest.
# ---------------------------------------------------------------------------
failed=0
for i in "${!RELS[@]}"; do
    rel="${RELS[$i]}"
    full="${DESTS[$rel]}"
    if [[ ! -s "$full" ]]; then
        echo "SANITY FAIL: $rel missing or empty after copy" >&2
        failed=1
    elif [[ "$(sha256sum "$full" | awk '{print $1}')" != "${hashes[$i]}" ]]; then
        echo "SANITY FAIL: $rel hash mismatch after copy" >&2
        failed=1
    fi
done
if (( failed )); then
    echo "ERROR: sanity check FAILED" >&2
    exit 1
fi

printf 'MANIFEST.json       : %d entries\n' "${#RELS[@]}"
echo  "sanity check        : ok"
echo  "triage_package/ ready"
