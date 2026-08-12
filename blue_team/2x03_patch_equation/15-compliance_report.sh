#!/bin/bash
#
# Name:        15-compliance_report.sh
# Purpose:     Generate a machine-readable patch compliance artifact that proves
#              the current CVE posture of the host for auditors and regulators
# Author:      Steve - Cybersecurity Engineer
# Date:        August 12, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly VULN_INVENTORY="${BASE_DIR}/vulnerability_inventory.json"
readonly CHANGE_LOG="${BASE_DIR}/patch_change_log.json"
readonly HOLD_MGMT="${BASE_DIR}/hold_management.json"
readonly PIPELINE_RUN="${BASE_DIR}/pipeline_run.json"
readonly CVE_FEED="${BASE_DIR}/cve_feed.json"
readonly HISTORY_DIR="${BASE_DIR}/history"
readonly OUTPUT_FILE="${BASE_DIR}/patch_compliance.json"

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

# ============================================
# NORMALIZE SEVERITY STRINGS
# ============================================
normalize_severity() {
    local s="$1"
    if [[ -z "$s" ]] || [[ "$s" == "null" ]]; then
        echo "unknown"
        return
    fi
    s=$(echo "$s" | tr '[:upper:]' '[:lower:]')
    case "$s" in
        crit|critical) echo "critical" ;;
        high) echo "high" ;;
        med|medium|moderate) echo "medium" ;;
        low) echo "low" ;;
        *)
            if [[ "$s" =~ ^[0-9]+\.?[0-9]*$ ]]; then
                awk -v v="$s" 'BEGIN {
                    if (v >= 9.0) print "critical"
                    else if (v >= 7.0) print "high"
                    else if (v >= 4.0) print "medium"
                    else print "low"
                }'
            else
                echo "unknown"
            fi
            ;;
    esac
}

# ============================================
# COLLECT ALL VULNERABILITY INVENTORY FILES
# (current run + history directory copies)
# ============================================
collect_inventory_files() {
    if [[ -f "$VULN_INVENTORY" ]]; then
        echo "$VULN_INVENTORY"
    fi

    # Also check ./history for rotated vulnerability inventory copies
    if [[ -d "$HISTORY_DIR" ]]; then
        find "$HISTORY_DIR" -name 'vulnerability_inventory*.json' -type f 2>/dev/null | sort
    fi
}

# ============================================
# INITIALIZE ASSOCIATIVE ARRAYS (safe under set -u)
# ============================================
declare -A severity_map=()
declare -A resolved_map=()
declare -A resolved_at_map=()
declare -A held_map=()

# ============================================
# BUILD CVE → SEVERITY MAP FROM CVE FEED
# ============================================
build_severity_map() {
    local feed_file="$CVE_FEED"

    if [[ ! -f "$feed_file" ]]; then
        log "No CVE feed found at $feed_file, severity will default to unknown"
        return
    fi

    log "Parsing CVE feed: $feed_file"

    # CVE feed structure: { "cves": { "CVE-2024-1086": { "cvss": 7.8, ... }, ... } }
    local entries
    entries=$(jq -r '
        .cves | to_entries[] |
        "\(.key)|\(.value.cvss // .value.cvss_score // .value.severity // "")"
    ' "$feed_file" 2>/dev/null || echo "")

    local map_count=0
    while IFS='|' read -r cve sev; do
        [[ -z "$cve" ]] && continue
        local normalized
        normalized=$(normalize_severity "$sev")
        severity_map["$cve"]="$normalized"
        map_count=$((map_count + 1))
    done <<< "$entries"

    log "Loaded ${map_count} CVE→severity mappings from CVE feed"
}

# ============================================
# EXTRACT ALL UNIQUE CVEs FROM INVENTORY HISTORY
# Returns temp file path containing: CVE_ID|package|first_seen
# ============================================
extract_all_cves() {
    local temp_file
    temp_file=$(mktemp)

    # Source 1: vulnerability_inventory.json + history copies
    local inv_files
    inv_files=$(collect_inventory_files)

    while IFS= read -r inv_file; do
        [[ -z "$inv_file" ]] && continue
        [[ ! -f "$inv_file" ]] && continue

        local generated_at
        generated_at=$(jq -r '.generated_at // empty' "$inv_file" 2>/dev/null || echo "")

        while IFS= read -r entry; do
            [[ -z "$entry" ]] && continue

            local pkg
            pkg=$(echo "$entry" | jq -r '.package // empty')

            while IFS= read -r cve_id; do
                [[ -z "$cve_id" ]] && continue
                [[ "$cve_id" == "null" ]] && continue
                echo "${cve_id}|${pkg}|${generated_at}" >> "$temp_file"
            done < <(echo "$entry" | jq -r '.cves[]? // empty')

        done < <(jq -c '.packages[]?' "$inv_file" 2>/dev/null || echo "")

    done <<< "$inv_files"

    # Source 2: cve_feed.json (object keyed by CVE ID with affected_packages)
    if [[ -f "$CVE_FEED" ]]; then
        local feed_generated
        feed_generated=$(jq -r '.generated_at // empty' "$CVE_FEED" 2>/dev/null || echo "")

        while IFS=$'\t' read -r cve_id pkg; do
            [[ -z "$cve_id" ]] && continue
            [[ "$cve_id" == "null" ]] && continue
            [[ -z "$pkg" ]] && continue
            echo "${cve_id}|${pkg}|${feed_generated}" >> "$temp_file"
        done < <(jq -r '
            .cves | to_entries[] |
            .key as $cve |
            (.value.affected_packages[]?) |
            [$cve, .] | @tsv
        ' "$CVE_FEED" 2>/dev/null || echo "")
    fi

    # Deduplicate keeping the earliest first_seen
    if [[ -s "$temp_file" ]]; then
        sort -t'|' -k1,1 -k3,3 "$temp_file" | awk -F'|' '!seen[$1]++ { print }' > "${temp_file}.dedup"
        mv "${temp_file}.dedup" "$temp_file"
    fi

    echo "$temp_file"
}

# ============================================
# BUILD RESOLVED CVE SET AND TIMESTAMPS
# ============================================
build_resolved_maps() {
    if [[ ! -f "$CHANGE_LOG" ]]; then
        log "No change log found at $CHANGE_LOG"
        return
    fi

    log "Parsing change log: $CHANGE_LOG"

    # Debug: show structure of first event
    local first_event
    first_event=$(jq -c '.events[0] // empty' "$CHANGE_LOG" 2>/dev/null || echo "")
    log "First event in change log: ${first_event}" >&2

    local event_count
    event_count=$(jq -r '.events | length' "$CHANGE_LOG" 2>/dev/null || echo "0")
    log "  Change log has ${event_count} events"

    # Debug: show how many CVEs each event has
    jq -r '.events[]? | "\(.started) → cves_resolved count: \(.cves_resolved // [] | length)"' "$CHANGE_LOG" 2>/dev/null >&2 || true

    # Build resolved CVE set
    local resolved_count_raw=0
    while IFS= read -r cve; do
        [[ -z "$cve" ]] && continue
        [[ "$cve" == "null" ]] && continue
        resolved_map["$cve"]=1
        resolved_count_raw=$((resolved_count_raw + 1))
    done < <(jq -r '.events[]?.cves_resolved[]? // empty' "$CHANGE_LOG" 2>/dev/null || echo "")

    log "  Raw resolved CVE lines: ${resolved_count_raw}" >&2
    log "  Unique resolved CVEs: ${#resolved_map[@]}"

    # Build resolved_at map
    while IFS=$'\t' read -r cve ts; do
        [[ -z "$cve" ]] && continue
        if [[ -z "${resolved_at_map[$cve]:-}" ]]; then
            resolved_at_map["$cve"]="$ts"
        fi
    done < <(jq -r '
        .events[]? | .started as $ts | .cves_resolved[]? | [., $ts] | @tsv
    ' "$CHANGE_LOG" 2>/dev/null | sort -t$'\t' -k2,2 | awk -F'\t' '!seen[$1]++ { print }' || echo "")
}

# ============================================
# BUILD HELD PACKAGE SET
# ============================================
build_held_map() {
    if [[ ! -f "$HOLD_MGMT" ]]; then
        log "No hold management file found at $HOLD_MGMT"
        return
    fi

    log "Parsing hold management: $HOLD_MGMT"

    # Try various possible JSON structures for held packages
    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue
        [[ "$pkg" == "null" ]] && continue
        held_map["$pkg"]=1
    done < <(jq -r '
        [
            (.applied[]?.package // empty),
            (.holds[]?.package // empty),
            (.held_packages[]? // empty),
            (.currently_held[]? // empty),
            (.packages[]? | select(type == "string")),
            (.packages[]?.package // empty)
        ] | .[] | select(. != null and . != "")
    ' "$HOLD_MGMT" 2>/dev/null || echo "")

    log "  Found ${#held_map[@]} held packages"
}

# ============================================
# CHECK IF PIPELINE IS DEFERRED
# ============================================
is_pipeline_deferred() {
    if [[ ! -f "$PIPELINE_RUN" ]]; then
        echo "false"
        return
    fi

    local status
    status=$(jq -r '.pipeline_status // "failed"' "$PIPELINE_RUN" 2>/dev/null)
    if [[ "$status" == "deferred" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# ============================================
# CHECK IF A CVE IS OVERDUE
# (open critical/high > 7 days from first_seen)
# ============================================
is_overdue() {
    local first_seen="$1"
    local severity="$2"

    if [[ "$severity" != "critical" ]] && [[ "$severity" != "high" ]]; then
        echo "false"
        return
    fi

    if [[ -z "$first_seen" ]]; then
        echo "false"
        return
    fi

    local now_epoch first_epoch
    now_epoch=$(date '+%s')
    first_epoch=$(date -d "$first_seen" '+%s' 2>/dev/null || echo 0)

    if [[ "$first_epoch" -eq 0 ]]; then
        echo "false"
        return
    fi

    local age_days=$(( (now_epoch - first_epoch) / 86400 ))

    if [[ $age_days -gt 7 ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# ============================================
# MAIN
# ============================================
main() {
    log "Generating patch compliance artifact..."

    local started_at
    started_at=$(date -u -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    local kernel_val
    kernel_val=$(uname -r 2>/dev/null || echo "unknown")

    # ============================================
    # STEP 1: Build severity map from CVE feed
    # ============================================
    log "Loading severity data from CVE feed..."
    build_severity_map

    # ============================================
    # STEP 2: Extract all unique CVEs from inventory history
    # ============================================
    log "Collecting CVEs from vulnerability inventory and history..."
    local cve_data_file
    cve_data_file=$(extract_all_cves)

    local total_cves=0
    if [[ -s "$cve_data_file" ]]; then
        total_cves=$(wc -l < "$cve_data_file")
    fi
    log "Found ${total_cves} unique CVEs"

    # ============================================
    # STEP 3: Build resolved, held, and deferred maps
    # ============================================
    build_resolved_maps
    build_held_map

    local pipeline_deferred
    pipeline_deferred=$(is_pipeline_deferred)
    log "Pipeline deferred: ${pipeline_deferred}"

    # ============================================
    # STEP 4: Classify each CVE
    # ============================================
    log "Classifying CVE states..."

    local cves_temp
    cves_temp=$(mktemp)

    local resolved_count=0
    local open_count=0
    local deferred_held_count=0
    local deferred_window_count=0
    local overdue_count=0

    # Counters for compliance score (critical + high only)
    local ch_resolved=0
    local ch_total=0

    if [[ -s "$cve_data_file" ]]; then
        while IFS='|' read -r cve_id pkg first_seen; do
            [[ -z "$cve_id" ]] && continue

            # Look up severity from the map
            local severity="unknown"
            if [[ -n "${severity_map[$cve_id]:-}" ]]; then
                severity="${severity_map[$cve_id]}"
            fi

            # Determine state
            local state="open"
            local resolved_at=""
            local justification=""

            if [[ -n "${resolved_map[$cve_id]:-}" ]]; then
                state="resolved"
                resolved_at="${resolved_at_map[$cve_id]:-}"
                justification="Resolved by package upgrade during patch run"
                resolved_count=$((resolved_count + 1))
            elif [[ -n "${held_map[$pkg]:-}" ]]; then
                state="deferred_held"
                justification="Package held pending review (see hold_management.json)"
                deferred_held_count=$((deferred_held_count + 1))
            elif [[ "$pipeline_deferred" == "true" ]]; then
                state="deferred_window"
                justification="Outside maintenance window; deferred to next scheduled window"
                deferred_window_count=$((deferred_window_count + 1))
            else
                state="open"
                justification="Open vulnerability awaiting remediation"
                open_count=$((open_count + 1))
            fi

            # Check overdue (only for open critical/high > 7 days)
            local overdue="false"
            if [[ "$state" == "open" ]]; then
                overdue=$(is_overdue "$first_seen" "$severity")
            fi

            if [[ "$overdue" == "true" ]]; then
                overdue_count=$((overdue_count + 1))
            fi

            # Track critical/high for compliance score
            if [[ "$severity" == "critical" ]] || [[ "$severity" == "high" ]]; then
                ch_total=$((ch_total + 1))
                if [[ "$state" == "resolved" ]]; then
                    ch_resolved=$((ch_resolved + 1))
                fi
            fi

            # Write CVE entry as compact JSON
            jq -nc \
                --arg id "$cve_id" \
                --arg pkg "$pkg" \
                --arg severity "$severity" \
                --arg state "$state" \
                --arg first_seen "$first_seen" \
                --arg resolved_at "$resolved_at" \
                --arg justification "$justification" \
                --arg overdue "$overdue" \
                '{
                    id: $id,
                    package: $pkg,
                    severity: $severity,
                    state: $state,
                    first_seen: (if $first_seen == "" then null else $first_seen end),
                    resolved_at: (if $resolved_at == "" then null else $resolved_at end),
                    justification: $justification,
                    overdue: ($overdue == "true")
                }' >> "$cves_temp"

        done < "$cve_data_file"
    fi

    # ============================================
    # STEP 5: Compute compliance score
    # ============================================
    local score="0.00"
    local target_score="95.00"

    if [[ "$ch_total" -gt 0 ]]; then
        score=$(awk -v r="$ch_resolved" -v t="$ch_total" 'BEGIN { printf "%.2f", (r / t) * 100 }')
    else
        score="100.00"
    fi

    log "Critical/High: ${ch_resolved}/${ch_total} resolved, score: ${score}% (target: ${target_score}%)"

    # ============================================
    # STEP 6: Build final JSON artifact
    # ============================================
    local cves_json
    if [[ -s "$cves_temp" ]]; then
        cves_json=$(jq -s '.' "$cves_temp" 2>/dev/null || echo '[]')
    else
        cves_json='[]'
    fi

    jq -n \
        --arg generated_at "$started_at" \
        --arg hostname "$hostname_val" \
        --arg kernel "$kernel_val" \
        --argjson resolved "$resolved_count" \
        --argjson open "$open_count" \
        --argjson deferred_held "$deferred_held_count" \
        --argjson deferred_window "$deferred_window_count" \
        --arg score "$score" \
        --arg target_score "$target_score" \
        --argjson overdue "$overdue_count" \
        --argjson total "$total_cves" \
        --slurpfile cves "$cves_temp" \
        '{
            generated_at: $generated_at,
            hostname: $hostname,
            kernel: $kernel,
            summary: {
                resolved: $resolved,
                open: $open,
                deferred_held: $deferred_held,
                deferred_window: $deferred_window,
                total: $total,
                score: ($score | tonumber),
                target_score: ($target_score | tonumber),
                overdue: $overdue
            },
            cves: $cves
        }' > "$OUTPUT_FILE"

    rm -f "$cve_data_file" "$cves_temp"

    # Print summary
    echo "resolved:          ${resolved_count}"
    echo "open:              ${open_count}"
    echo "deferred_held:     ${deferred_held_count}"
    echo "deferred_window:   ${deferred_window_count}"
    echo "score:             ${score}%"
    echo "target_score:      ${target_score}%"
    echo "overdue:           ${overdue_count}"
    log "Report saved to: $OUTPUT_FILE"

    # Exit 0 if score meets or exceeds target
    if awk -v s="$score" -v t="$target_score" 'BEGIN { exit (s >= t) ? 0 : 1 }'; then
        exit 0
    else
        exit 1
    fi
}

main "$@"
