#!/bin/bash
# Name: 10-compliance_report.sh
# Purpose: Emit machine-readable compliance report joining target_state.json, validation.json, and framework_map.json
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
# Exit Codes: 0=Success (overall_verdict == ready), 1=Not ready or failure, 2=Environment error
# This script produces the compliance report with framework mapping and evidence paths

set -euo pipefail

# --- Configuration ---
TARGET_STATE="${1:-capstone/target_state.json}"
VALIDATION_REPORT="${2:-capstone/validation.json}"
FRAMEWORK_MAP="/home/analyst/MedDefense_Lab/capstone/framework_map.json"
COMPLIANCE_REPORT="capstone/compliance.json"
SCHEMA_VERSION="capstone-compliance-v1"
SITE="hawthorne"

# --- Helper Functions ---

log() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

fail_exit() {
    log "FAILURE: $1"
    exit 1
}

env_error() {
    log "ENVIRONMENT ERROR: $1"
    exit 2
}

# --- Pre-flight Checks ---

log "Checking environment dependencies..."

if [[ $EUID -ne 0 ]]; then
    env_error "This script must be run as root."
fi

if ! command -v jq &>/dev/null; then
    env_error "jq is required but not installed"
fi

if [[ ! -f "$TARGET_STATE" ]]; then
    env_error "target_state.json not found at $TARGET_STATE"
fi

if [[ ! -f "$VALIDATION_REPORT" ]]; then
    env_error "validation.json not found at $VALIDATION_REPORT"
fi

if [[ ! -f "$FRAMEWORK_MAP" ]]; then
    log "Warning: framework_map.json not found at $FRAMEWORK_MAP"
    log "Proceeding with empty framework mappings — all controls will be unmapped."
    FRAMEWORK_MAP=""
fi

mkdir -p "$(dirname "$COMPLIANCE_REPORT")"

# --- Step 1: Join target_state.json and validation.json by control ID ---

log "Joining target_state.json and validation.json by control ID..."

CONTROL_COUNT=$(jq '.controls | length' "$TARGET_STATE")
log "Found $CONTROL_COUNT controls in target_state.json"

VALIDATION_CONTROL_COUNT=$(jq '.controls | length' "$VALIDATION_REPORT")
log "Found $VALIDATION_CONTROL_COUNT controls in validation.json"

# --- Step 2: Build the compliance controls array ---

log "Building compliance report with framework mapping and evidence paths..."

CONTROLS_JSON="[]"
UNMAPPED_CONTROLS="[]"

for i in $(seq 0 $((CONTROL_COUNT - 1))); do
    ctrl_id=$(jq -r ".controls[$i].id" "$TARGET_STATE")
    ctrl_description=$(jq -r ".controls[$i].description" "$TARGET_STATE")
    ctrl_family=$(jq -r ".controls[$i].family" "$TARGET_STATE")
    ctrl_severity=$(jq -r ".controls[$i].severity" "$TARGET_STATE")
    ctrl_source_project=$(jq -r ".controls[$i].source_project" "$TARGET_STATE")
    ctrl_check_target=$(jq -r ".controls[$i].check_target" "$TARGET_STATE")

    # Look up verdict and evidence from validation.json
    validation_entry=$(jq -e --arg id "$ctrl_id" '.controls[] | select(.id == $id)' "$VALIDATION_REPORT" 2>/dev/null || echo "")

    if [[ -n "$validation_entry" ]]; then
        ctrl_verdict=$(echo "$validation_entry" | jq -r '.verdict')
        ctrl_evidence=$(echo "$validation_entry" | jq -r '.evidence')
    else
        ctrl_verdict="not_evaluated"
        ctrl_evidence="No validation entry found for control $ctrl_id"
    fi

    # evidence_path: the evidence field from validation, or the check_target path
    evidence_path="$ctrl_evidence"
    if [[ -z "$evidence_path" || "$evidence_path" == "null" ]]; then
        evidence_path="$ctrl_check_target"
    fi

    # Look up framework mapping from framework_map.json
    framework_mapping="[]"
    if [[ -n "$FRAMEWORK_MAP" ]]; then
        mapping_raw=$(jq -c --arg id "$ctrl_id" '.[$id] // []' "$FRAMEWORK_MAP" 2>/dev/null || echo "[]")
        if [[ "$mapping_raw" != "[]" ]]; then
            framework_mapping="$mapping_raw"
        else
            # No mapping found — record as unmapped
            UNMAPPED_CONTROLS=$(echo "$UNMAPPED_CONTROLS" | jq --arg id "$ctrl_id" '. + [$id]')
        fi
    else
        # No framework map file — all controls are unmapped
        UNMAPPED_CONTROLS=$(echo "$UNMAPPED_CONTROLS" | jq --arg id "$ctrl_id" '. + [$id]')
    fi

    # Build the compliance control entry
    CONTROLS_JSON=$(echo "$CONTROLS_JSON" | jq \
        --arg id "$ctrl_id" \
        --arg description "$ctrl_description" \
        --arg family "$ctrl_family" \
        --arg severity "$ctrl_severity" \
        --arg source_project "$ctrl_source_project" \
        --arg verdict "$ctrl_verdict" \
        --arg evidence_path "$evidence_path" \
        --argjson framework_mapping "$framework_mapping" \
        '. + [{
            id: $id,
            description: $description,
            family: $family,
            severity: $severity,
            source_project: $source_project,
            verdict: $verdict,
            evidence_path: $evidence_path,
            framework_mapping: $framework_mapping
        }]')
done

log "Compliance controls array built with ${#CONTROLS_JSON[@]} entries"

# --- Step 3: Compute overall verdict ---

log "Computing overall verdict from validation summary..."

validation_fail_count=$(jq -r '.fail_count // 0' "$VALIDATION_REPORT")
validation_error_count=$(jq -r '.error_count // 0' "$VALIDATION_REPORT")

if [[ "$validation_fail_count" -eq 0 && "$validation_error_count" -eq 0 ]]; then
    overall_verdict="ready"
else
    overall_verdict="not_ready"
fi

log "Overall verdict: $overall_verdict (fail=$validation_fail_count, error=$validation_error_count)"

# --- Step 4: Build summary block with totals by family and severity ---

log "Building summary block with totals by family and severity..."

# Collect unique families and severities
FAMILIES=$(jq -r '.controls[].family' "$TARGET_STATE" | sort -u)
SEVERITIES=$(jq -r '.controls[].severity' "$TARGET_STATE" | sort -u)

FAMILY_SUMMARY="[]"
for family in $FAMILIES; do
    family_total=$(jq --arg f "$family" '[.controls[] | select(.family == $f)] | length' "$TARGET_STATE")
    family_pass=$(echo "$CONTROLS_JSON" | jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "pass")] | length')
    family_fail=$(echo "$CONTROLS_JSON" | jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "fail")] | length')
    family_error=$(echo "$CONTROLS_JSON" | jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "error")] | length')
    family_skip=$(echo "$CONTROLS_JSON" | jq --arg f "$family" '[.[] | select(.family == $f and .verdict == "skip")] | length')

    if [[ "$family_total" -gt 0 ]]; then
        family_pct=$(awk -v p="$family_pass" -v t="$family_total" 'BEGIN { printf "%.1f", (p / t) * 100 }')
    else
        family_pct="0.0"
    fi

    FAMILY_SUMMARY=$(echo "$FAMILY_SUMMARY" | jq \
        --arg family "$family" \
        --argjson total "$family_total" \
        --argjson pass "$family_pass" \
        --argjson fail "$family_fail" \
        --argjson error "$family_error" \
        --argjson skip "$family_skip" \
        --arg pct "$family_pct" \
        '. + [{
            family: $family,
            total: $total,
            pass: $pass,
            fail: $fail,
            error: $error,
            skip: $skip,
            pass_rate_pct: ($pct | tonumber)
        }]')
done

SEVERITY_SUMMARY="[]"
for sev in $SEVERITIES; do
    sev_total=$(jq --arg s "$sev" '[.controls[] | select(.severity == $s)] | length' "$TARGET_STATE")
    sev_pass=$(echo "$CONTROLS_JSON" | jq --arg s "$sev" '[.[] | select(.severity == $s and .verdict == "pass")] | length')
    sev_fail=$(echo "$CONTROLS_JSON" | jq --arg s "$sev" '[.[] | select(.severity == $s and (.verdict == "fail" or .verdict == "error"))] | length')

    SEVERITY_SUMMARY=$(echo "$SEVERITY_SUMMARY" | jq \
        --arg severity "$sev" \
        --argjson total "$sev_total" \
        --argjson pass "$sev_pass" \
        --argjson fail "$sev_fail" \
        '. + [{
            severity: $severity,
            total: $total,
            pass: $pass,
            fail: $fail
        }]')
done

# --- Step 5: Count framework hits across all controls ---

log "Counting framework hits across all mapped controls..."

FRAMEWORK_HITS="[]"

if [[ -n "$FRAMEWORK_MAP" ]]; then
    # Extract all framework entries and count occurrences
    FRAMEWORK_NAMES=$(jq -r '.[] | .[].framework' "$FRAMEWORK_MAP" 2>/dev/null | sort -u || echo "")

    for fw in $FRAMEWORK_NAMES; do
        hit_count=$(echo "$CONTROLS_JSON" | jq --arg fw "$fw" \
            '[.[] | .framework_mapping[]? | select(.framework == $fw)] | length')

        if [[ "$hit_count" -gt 0 ]]; then
            FRAMEWORK_HITS=$(echo "$FRAMEWORK_HITS" | jq \
                --arg framework "$fw" \
                --argjson count "$hit_count" \
                '. + [{framework: $framework, control_count: $count}]')
        fi
    done
fi

# Sort framework hits by count descending and take top 5
FRAMEWORK_TOP5=$(echo "$FRAMEWORK_HITS" | jq 'sort_by(-.control_count) | .[0:5]')

# --- Step 6: Emit capstone/compliance.json ---

log "Emitting compliance report to $COMPLIANCE_REPORT..."

jq -n \
    --arg schema_version "$SCHEMA_VERSION" \
    --arg generated_at "$(date -Iseconds)" \
    --arg hostname "$(hostname)" \
    --arg site "$SITE" \
    --arg overall_verdict "$overall_verdict" \
    --argjson controls "$CONTROLS_JSON" \
    --argjson family_summary "$FAMILY_SUMMARY" \
    --argjson severity_summary "$SEVERITY_SUMMARY" \
    --argjson unmapped_controls "$UNMAPPED_CONTROLS" \
    --argjson framework_hits "$FRAMEWORK_TOP5" \
    '{
        schema_version: $schema_version,
        generated_at: $generated_at,
        hostname: $hostname,
        site: $site,
        overall_verdict: $overall_verdict,
        controls: $controls,
        summary: {
            by_family: $family_summary,
            by_severity: $severity_summary
        },
        unmapped_controls: $unmapped_controls,
        framework_hits: $framework_hits
    }' > "$COMPLIANCE_REPORT"

log "Compliance report saved to $COMPLIANCE_REPORT"

# --- Step 7: Print stdout summary ---

echo ""
echo "============================================================"
echo "  Compliance Report Summary"
echo "  Site: $SITE"
echo "  Host: $(hostname)"
echo "  Schema: $SCHEMA_VERSION"
echo "  Generated: $(date -Iseconds)"
echo "  Overall Verdict: $overall_verdict"
echo "============================================================"
echo ""

echo "--- Per-Family Pass Rate ---"
printf "%-14s %-8s %-8s %-8s %-8s %-8s %-12s\n" "FAMILY" "TOTAL" "PASS" "FAIL" "ERR" "SKIP" "PASS%"
printf "%-14s %-8s %-8s %-8s %-8s %-8s %-12s\n" "------" "-----" "----" "----" "---" "----" "-----"

for family in $FAMILIES; do
    ft=$(echo "$FAMILY_SUMMARY" | jq -r --arg f "$family" '.[] | select(.family == $f) | .total')
    fp=$(echo "$FAMILY_SUMMARY" | jq -r --arg f "$family" '.[] | select(.family == $f) | .pass')
    ff=$(echo "$FAMILY_SUMMARY" | jq -r --arg f "$family" '.[] | select(.family == $f) | .fail')
    fe=$(echo "$FAMILY_SUMMARY" | jq -r --arg f "$family" '.[] | select(.family == $f) | .error')
    fs=$(echo "$FAMILY_SUMMARY" | jq -r --arg f "$family" '.[] | select(.family == $f) | .skip')
    fpct=$(echo "$FAMILY_SUMMARY" | jq -r --arg f "$family" '.[] | select(.family == $f) | .pass_rate_pct')
    printf "%-14s %-8s %-8s %-8s %-8s %-8s %-12s\n" "$family" "$ft" "$fp" "$ff" "$fe" "$fs" "${fpct}%"
done

echo ""
echo "--- Top 5 Framework Hits ---"
printf "%-30s %-12s\n" "FRAMEWORK" "CONTROLS"
printf "%-30s %-12s\n" "---------" "---------"

FRAMEWORK_TOP5_COUNT=$(echo "$FRAMEWORK_TOP5" | jq 'length')
for j in $(seq 0 $((FRAMEWORK_TOP5_COUNT - 1))); do
    fw_name=$(echo "$FRAMEWORK_TOP5" | jq -r ".[$j].framework")
    fw_count=$(echo "$FRAMEWORK_TOP5" | jq -r ".[$j].control_count")
    printf "%-30s %-12s\n" "$fw_name" "$fw_count"
done

if [[ "$FRAMEWORK_TOP5_COUNT" -eq 0 ]]; then
    echo "  (no framework mappings found)"
fi

echo ""

UNMAPPED_COUNT=$(echo "$UNMAPPED_CONTROLS" | jq 'length')
echo "Unmapped controls: $UNMAPPED_COUNT"
if [[ "$UNMAPPED_COUNT" -gt 0 ]]; then
    echo "$UNMAPPED_CONTROLS" | jq -r '.[] | "  - \(.)"'
fi

echo ""

# --- Step 8: Exit based on overall verdict ---

if [[ "$overall_verdict" == "ready" ]]; then
    log "SUCCESS: Compliance report emitted. Overall verdict: ready."
    exit 0
else
    log "FAILURE: Compliance report emitted. Overall verdict: not_ready."
    log "Fix failing controls and re-run validation before compliance report."
    exit 1
fi
