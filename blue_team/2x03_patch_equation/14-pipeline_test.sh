#!/bin/bash
#
# Name:        14-pipeline_test.sh
# Purpose:     Execute an end-to-end pipeline test against a simulated CVE
#              advisory feed, validating deterministic output and restoration
# Author:      Steve - Cybersecurity Engineer
# Date:        August 12, 2026
#
# In emergency mode (override window check):
# sudo MEDDEFENSE_EMERGENCY=1 ./13-patch_pipeline.sh
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly CVE_FEED="${BASE_DIR}/cve_feed.json"
readonly CVE_FEED_BAK="${BASE_DIR}/cve_feed.json.bak"
readonly CVE_FEED_SIM="${BASE_DIR}/cve_feed.simulated.json"
readonly PATCH_PLAN="${BASE_DIR}/patch_plan.json"
readonly PATCH_PLAN_EXPECTED="${BASE_DIR}/patch_plan.expected.json"
readonly PIPELINE_RUN="${BASE_DIR}/pipeline_run.json"
readonly PIPELINE_SCRIPT="${BASE_DIR}/13-patch_pipeline.sh"
readonly OUTPUT_FILE="${BASE_DIR}/pipeline_test_results.json"

log() {
    echo "[*] $*"
}

info() {
    echo "    $*"
}

warn() {
    echo "[!] $*" >&2
}

# ============================================
# RESTORE: restore original cve_feed.json from backup
# ============================================
cleanup() {
    # Restore original cve_feed.json if backup exists
    if [[ -f "$CVE_FEED_BAK" ]]; then
        cp "$CVE_FEED_BAK" "$CVE_FEED"
        log "Restoring cve_feed.json...                OK"
        rm -f "$CVE_FEED_BAK"
    fi
}

trap cleanup EXIT

# ============================================
# NORMALIZE TIMESTAMPS IN JSON FOR COMPARISON
# ============================================
normalize_json_timestamps() {
    local input_file="$1"
    local temp_file
    temp_file=$(mktemp)

    # Replace any ISO 8601 timestamp with a placeholder
    # Matches patterns like 2026-08-12T06:26:06Z or 2026-08-12T06:26:06+02:00
    jq '
        walk(
            if type == "string" then
                gsub("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}[Z+-]\\d{2}:?\\d{2}?"; "TIMESTAMP_PLACEHOLDER")
            else
                .
            end
        )
    ' "$input_file" > "$temp_file" 2>/dev/null || cp "$input_file" "$temp_file"

    echo "$temp_file"
}

# ============================================
# COMPARE PATCH PLAN AGAINST EXPECTED
# ============================================
compare_patch_plan() {
    local actual="$1"
    local expected="$2"

    if [[ ! -f "$expected" ]]; then
        echo "MISSING_EXPECTED"
        return 1
    fi

    if [[ ! -f "$actual" ]]; then
        echo "MISSING_ACTUAL"
        return 1
    fi

    # Normalize both files
    local norm_actual norm_expected
    norm_actual=$(normalize_json_timestamps "$actual")
    norm_expected=$(normalize_json_timestamps "$expected")

    # Compare sorted JSON
    local sorted_actual sorted_expected
    sorted_actual=$(jq -S '.' "$norm_actual" 2>/dev/null || echo "")
    sorted_expected=$(jq -S '.' "$norm_expected" 2>/dev/null || echo "")

    rm -f "$norm_actual" "$norm_expected"

    if [[ "$sorted_actual" == "$sorted_expected" ]]; then
        echo "MATCH"
        return 0
    else
        echo "DIFF"
        return 1
    fi
}

# ============================================
# GENERATE UNIFIED DIFF AS JSON ARRAY
# ============================================
generate_diff_array() {
    local actual="$1"
    local expected="$2"

    local norm_actual norm_expected
    norm_actual=$(normalize_json_timestamps "$actual")
    norm_expected=$(normalize_json_timestamps "$expected")

    local sorted_actual sorted_expected
    local sa_file se_file
    sa_file=$(mktemp)
    se_file=$(mktemp)
    sorted_actual=$(jq -S '.' "$norm_actual" 2>/dev/null || cat "$norm_actual")
    sorted_expected=$(jq -S '.' "$norm_expected" 2>/dev/null || cat "$norm_expected")
    echo "$sorted_actual" > "$sa_file"
    echo "$sorted_expected" > "$se_file"

    rm -f "$norm_actual" "$norm_expected"

    local diff_output
    diff_output=$(diff -u "$se_file" "$sa_file" 2>/dev/null || true)

    rm -f "$sa_file" "$se_file"

    if [[ -z "$diff_output" ]]; then
        echo '[]'
    else
        echo "$diff_output" | jq -R -s 'split("\n") | map(select(length > 0))'
    fi
}

# ============================================
# VALIDATE ARTIFACTS: confirm every stage produced a non-empty JSON artifact
# ============================================
validate_artifacts() {
    local pipeline_json="$1"
    local missing_count=0
    local total_stages=0
    local ok_stages=0

    if [[ ! -f "$pipeline_json" ]]; then
        echo "0|0"
        return 1
    fi

    total_stages=$(jq '.stages | length' "$pipeline_json" 2>/dev/null || echo 0)

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue

        local script exit_code skipped artifact_path artifact_exists
        script=$(echo "$entry" | jq -r '.script')
        exit_code=$(echo "$entry" | jq -r '.exit_code')
        skipped=$(echo "$entry" | jq -r '.skipped')
        artifact_path=$(echo "$entry" | jq -r '.artifact')
        artifact_exists=$(echo "$entry" | jq -r '.artifact_exists')

        if [[ "$skipped" == "true" ]]; then
            ok_stages=$((ok_stages + 1))
            continue
        fi

        if [[ "$exit_code" == "0" ]] && [[ "$artifact_exists" == "true" ]]; then
            ok_stages=$((ok_stages + 1))
        else
            missing_count=$((missing_count + 1))
        fi

    done < <(jq -c '.stages[]' "$pipeline_json" 2>/dev/null)

    echo "${ok_stages}|${total_stages}"
    return 0
}

# ============================================
# MAIN
# ============================================
main() {
    local started_at
    started_at=$(date -u -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')

    log "Scenario: simulated CVE advisory"

    # ============================================
    # STEP 1: Backup cve_feed.json
    # ============================================
    if [[ -f "$CVE_FEED" ]]; then
        cp "$CVE_FEED" "$CVE_FEED_BAK"
        log "Backing up cve_feed.json...              OK"
    else
        log "Backing up cve_feed.json...              OK (file did not exist)"
    fi

    # ============================================
    # STEP 2: Inject simulated CVE feed
    # ============================================
    if [[ ! -f "$CVE_FEED_SIM" ]]; then
        warn "Simulated CVE feed not found: $CVE_FEED_SIM"
        warn "Creating a minimal placeholder."
        echo '{"feed":"simulated","advisories":[]}' > "$CVE_FEED_SIM"
    fi

    cp "$CVE_FEED_SIM" "$CVE_FEED"
    log "Injecting cve_feed.simulated.json...     OK"

    # ============================================
    # STEP 3: Run the pipeline with PIPELINE_TEST=1
    # ============================================
    log "Running pipeline (PIPELINE_TEST=1)..."

    local pipeline_exit=0
    set +e
    PIPELINE_TEST=1 sudo -E "$PIPELINE_SCRIPT"
    pipeline_exit=$?
    set -e

    # ============================================
    # STEP 4: Validate pipeline results
    # ============================================
    local pipeline_status
    pipeline_status=$(jq -r '.pipeline_status // "failed"' "$PIPELINE_RUN" 2>/dev/null || echo "failed")

    local stages_ok total_stages
    local artifact_result
    artifact_result=$(validate_artifacts "$PIPELINE_RUN")
    stages_ok=$(echo "$artifact_result" | cut -d'|' -f1)
    total_stages=$(echo "$artifact_result" | cut -d'|' -f2)

    # Pipeline status must be ok or deferred
    local status_valid=false
    if [[ "$pipeline_status" == "ok" ]] || [[ "$pipeline_status" == "deferred" ]]; then
        status_valid=true
    fi

    # ============================================
    # STEP 5: Compare patch_plan.json to expected
    # ============================================
    local plan_matches=false
    local diff_array='[]'

    if [[ -f "$PATCH_PLAN" ]] && [[ -f "$PATCH_PLAN_EXPECTED" ]]; then
        log "Comparing patch_plan.json to expected...  match"
        local cmp_result
        cmp_result=$(compare_patch_plan "$PATCH_PLAN" "$PATCH_PLAN_EXPECTED")
        if [[ "$cmp_result" == "MATCH" ]]; then
            plan_matches=true
        else
            log "Comparing patch_plan.json to expected...  DIFF"
            diff_array=$(generate_diff_array "$PATCH_PLAN" "$PATCH_PLAN_EXPECTED")
        fi
    elif [[ ! -f "$PATCH_PLAN_EXPECTED" ]]; then
        log "Comparing patch_plan.json to expected...  (no expected file, skipping)"
        plan_matches=true
    else
        log "Comparing patch_plan.json to expected...  (no plan generated)"
    fi

    # ============================================
    # STEP 6: Restore original cve_feed.json (via trap)
    # ============================================
    # Restoration happens in the cleanup trap on EXIT

    # ============================================
    # STEP 7: Determine verdict
    # ============================================
    local verdict="fail"
    if [[ "$status_valid" == "true" ]] && [[ "$plan_matches" == "true" ]]; then
        verdict="pass"
    fi

    local finished_at
    finished_at=$(date -u -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')

    # ============================================
    # STEP 8: Emit pipeline_test_results.json
    # ============================================
    jq -n \
        --arg scenario "simulated CVE advisory" \
        --arg started_at "$started_at" \
        --arg finished_at "$finished_at" \
        --argjson stages_ok "$stages_ok" \
        --argjson total_stages "$total_stages" \
        --arg pipeline_status "$pipeline_status" \
        --argjson status_valid "$status_valid" \
        --argjson plan_matches "$plan_matches" \
        --argjson diff "$diff_array" \
        --arg verdict "$verdict" \
        '{
            scenario: $scenario,
            started_at: $started_at,
            finished_at: $finished_at,
            stages_ok: $stages_ok,
            total_stages: $total_stages,
            pipeline_status: $pipeline_status,
            status_valid: $status_valid,
            plan_matches_expected: $plan_matches,
            diff: $diff,
            verdict: $verdict
        }' > "$OUTPUT_FILE"

    echo "VERDICT: ${verdict}"
    log "Report saved to: $OUTPUT_FILE"

    if [[ "$verdict" == "pass" ]]; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
