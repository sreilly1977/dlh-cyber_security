#!/bin/bash
#
# Name:        8-linux_telemetry_quality.sh
# Purpose:     Analyze Linux telemetry quality and generate quality report JSON
# Author:      Steve - Cybersecurity Engineer
# Date:        August 8, 2026
#
# Reads: linux_events_export.json (NDJSON format)
# Outputs: linux_telemetry_quality.json with distribution, coverage, gaps, completeness, and quality score
# Uses: jq for JSON parsing and analysis, perl for preprocessing
# Reports: count and percentage of total for each event category and source type
# Metrics: events per hour, hours with events, hours without events, gap detection (>30 minutes), field completeness
# Field checks: timestamp, hostname, source_type, event_category, command_line for execve, source_ip and user for SSH events, path/operation/key for auditd file events

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

INPUT_FILE="${1:-linux_events_export.json}"
OUTPUT_FILE="linux_telemetry_quality.json"
MAX_GAP_MINUTES=30
FIXED_FILE="${INPUT_FILE}.fixed"

# ── Functions ─────────────────────────────────────────────────────────────────

log_info() {
    echo "[*] $*"
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

# ── Preprocess: repair broken NDJSON lines ────────────────────────────────────

fix_ndjson() {
    local input="$1"
    local output="$2"

    # Remove control chars, then rejoin lines that don't start with { or [ or "
    # This handles embedded newlines inside JSON string values
    perl -0777 -pe '
        s/[\x00-\x08\x0B\x0C\x0E-\x1F]//g;
        s/\}\n\{/}\n{/g;
    ' "$input" | perl -pe '
        chomp;
        if (!/^\{/) {
            s/\n/ /g;
        }
    ' > "$output"
}

# ── Main Analysis ─────────────────────────────────────────────────────────────

main() {
    if [[ ! -f "$INPUT_FILE" ]]; then
        die "Input file not found: $INPUT_FILE"
    fi

    log_info "Analyzing $INPUT_FILE..."

    # Repair the NDJSON file
    fix_ndjson "$INPUT_FILE" "$FIXED_FILE"

    local working_file="$FIXED_FILE"

    # Count total events
    local total_events
    total_events=$(jq -s 'length' "$working_file")

    if [[ "$total_events" -eq 0 ]]; then
        die "No valid JSON events found in $INPUT_FILE"
    fi

    log_info "Processing $total_events events..."

    # ── Event Distribution ────────────────────────────────────────────────────

    # Count per event category with percentage of total
    local category_counts_json
    category_counts_json=$(jq -s --argjson total "$total_events" '
        group_by(.event_category) | map({
            category: .[0].event_category,
            count: length,
            percentage: ((length * 100 / $total) | floor)
        }) | sort_by(-.count)
    ' "$working_file")

    # Count per source type with percentage of total
    local source_counts_json
    source_counts_json=$(jq -s --argjson total "$total_events" '
        group_by(.source_type) | map({
            source: .[0].source_type,
            count: length,
            percentage: ((length * 100 / $total) | floor)
        }) | sort_by(-.count)
    ' "$working_file")

    # ── Time Coverage ─────────────────────────────────────────────────────────

    # Extract all valid timestamps to a temp file
    local ts_file="${working_file}.ts"
    jq -rs '[.[] | .timestamp | select(. != null and . != "unknown" and . != "")] | sort | .[]' "$working_file" > "$ts_file"

    local first_ts last_ts
    first_ts=$(head -1 "$ts_file" 2>/dev/null || echo "")
    last_ts=$(tail -1 "$ts_file" 2>/dev/null || echo "")

    # Count unique hours with events
    local hours_with_events
    hours_with_events=$(jq -rs '[.[] | .timestamp | select(. != null and . != "unknown" and . != "") | .[11:13]] | unique | length' "$working_file")

    local hours_without_events=0
    local events_per_hour=0

    if [[ -n "$first_ts" ]] && [[ -n "$last_ts" ]]; then
        local first_epoch last_epoch total_hours
        first_epoch=$(date -d "${first_ts/Z/+00:00}" +%s 2>/dev/null) || first_epoch=0
        last_epoch=$(date -d "${last_ts/Z/+00:00}" +%s 2>/dev/null) || last_epoch=0

        if [[ "$first_epoch" -gt 0 ]] && [[ "$last_epoch" -gt 0 ]]; then
            total_hours=$(( (last_epoch - first_epoch) / 3600 + 1 ))
            hours_without_events=$(( total_hours - hours_with_events ))
            [[ "$hours_without_events" -lt 0 ]] && hours_without_events=0
            [[ "$hours_with_events" -gt 0 ]] && events_per_hour=$(( total_events / hours_with_events ))
        fi
    fi

    # ── Gap Detection ─────────────────────────────────────────────────────────

    # Detect any period longer than 30 minutes with no events
    local max_gap_minutes=0
    local gap_detected=false

    if [[ -s "$ts_file" ]]; then
        local prev_epoch=0
        while IFS= read -r ts; do
            [[ -z "$ts" ]] && continue
            local curr_epoch
            curr_epoch=$(date -d "${ts/Z/+00:00}" +%s 2>/dev/null) || continue

            if [[ "$prev_epoch" -gt 0 ]]; then
                local diff=$(( (curr_epoch - prev_epoch) / 60 ))
                [[ "$diff" -lt 0 ]] && diff=$((-diff))

                if [[ "$diff" -gt "$max_gap_minutes" ]]; then
                    max_gap_minutes=$diff
                fi
                if [[ "$diff" -gt "$MAX_GAP_MINUTES" ]]; then
                    gap_detected=true
                fi
            fi
            prev_epoch=$curr_epoch
        done < "$ts_file"
    fi
    rm -f "$ts_file"

    # ── Field Completeness ────────────────────────────────────────────────────

    local timestamp_completeness hostname_completeness source_type_completeness event_category_completeness
    timestamp_completeness=$(jq -rs '([.[] | select(.timestamp != null and .timestamp != "" and .timestamp != "unknown")] | length) * 100 / length' "$working_file")
    hostname_completeness=$(jq -rs '([.[] | select(.hostname != null and .hostname != "")] | length) * 100 / length' "$working_file")
    source_type_completeness=$(jq -rs '([.[] | select(.source_type != null and .source_type != "")] | length) * 100 / length' "$working_file")
    event_category_completeness=$(jq -rs '([.[] | select(.event_category != null and .event_category != "")] | length) * 100 / length' "$working_file")

    # execve command_line completeness
    local execve_completeness=0 execve_total execve_with_cmd
    execve_total=$(jq -rs '[.[] | select(.source_type == "audit.log" and .event_category == "execve")] | length' "$working_file")
    if [[ "$execve_total" -gt 0 ]]; then
        execve_with_cmd=$(jq -rs '[.[] | select(.source_type == "audit.log" and .event_category == "execve") | select(.command != null and .command != "")] | length' "$working_file")
        execve_completeness=$(( execve_with_cmd * 100 / execve_total ))
    fi

    # SSH source_ip and user completeness - check both fields for SSH events
    local ssh_ip_completeness=0 ssh_user_completeness=0 ssh_total ssh_with_ip ssh_with_user
    ssh_total=$(jq -rs '[.[] | select(.event_category | contains("ssh"))] | length' "$working_file")
    if [[ "$ssh_total" -gt 0 ]]; then
        ssh_with_ip=$(jq -rs '[.[] | select(.event_category | contains("ssh")) | select(.src_ip != null and .src_ip != "" and .src_ip != "unknown")] | length' "$working_file")
        ssh_ip_completeness=$(( ssh_with_ip * 100 / ssh_total ))

        ssh_with_user=$(jq -rs '[.[] | select(.event_category | contains("ssh")) | select(.user != null and .user != "")] | length' "$working_file")
        ssh_user_completeness=$(( ssh_with_user * 100 / ssh_total ))
    fi

    # auditd file path completeness
    local file_path_completeness=0 file_access_total file_access_with_path
    file_access_total=$(jq -rs '[.[] | select(.source_type == "audit.log" and .event_category == "file_access")] | length' "$working_file")
    if [[ "$file_access_total" -gt 0 ]]; then
        file_access_with_path=$(jq -rs '[.[] | select(.source_type == "audit.log" and .event_category == "file_access") | select(.path != null and .path != "")] | length' "$working_file")
        file_path_completeness=$(( file_access_with_path * 100 / file_access_total ))
    fi

    # ── Quality Score Calculation ─────────────────────────────────────────────

    local base_completeness
    base_completeness=$(( (timestamp_completeness + hostname_completeness + source_type_completeness + event_category_completeness) / 4 ))

    local quality_score
    quality_score=$((
        (base_completeness * 40 / 100) +
        (execve_completeness * 15 / 100) +
        (ssh_ip_completeness * 10 / 100) +
        (ssh_user_completeness * 5 / 100) +
        (file_path_completeness * 10 / 100) +
        (hours_with_events * 10 / 100)
    ))

    if [[ "$gap_detected" == true ]]; then
        quality_score=$(( quality_score - ((max_gap_minutes - MAX_GAP_MINUTES) / 30) * 2 ))
        [[ "$quality_score" -lt 0 ]] && quality_score=0
    fi

    local assessment
    if [[ "$quality_score" -ge 90 ]]; then
        assessment="good"
    elif [[ "$quality_score" -ge 70 ]]; then
        assessment="acceptable"
    else
        assessment="poor"
    fi

    # ── Generate Output JSON ──────────────────────────────────────────────────

    jq -n \
        --argjson total_events "$total_events" \
        --argjson category_counts "$category_counts_json" \
        --argjson source_counts "$source_counts_json" \
        --argjson events_per_hour "$events_per_hour" \
        --argjson hours_with_events "$hours_with_events" \
        --argjson hours_without_events "$hours_without_events" \
        --argjson max_gap_minutes "$max_gap_minutes" \
        --argjson gap_detected "$gap_detected" \
        --argjson timestamp_completeness "$timestamp_completeness" \
        --argjson hostname_completeness "$hostname_completeness" \
        --argjson source_type_completeness "$source_type_completeness" \
        --argjson event_category_completeness "$event_category_completeness" \
        --argjson execve_completeness "$execve_completeness" \
        --argjson ssh_ip_completeness "$ssh_ip_completeness" \
        --argjson ssh_user_completeness "$ssh_user_completeness" \
        --argjson file_path_completeness "$file_path_completeness" \
        --argjson quality_score "$quality_score" \
        --arg assessment "$assessment" \
        '{
            summary: {
                total_events: $total_events,
                quality_score: $quality_score,
                assessment: $assessment
            },
            event_distribution: {
                per_category: $category_counts,
                per_source: $source_counts
            },
            time_coverage: {
                events_per_hour: $events_per_hour,
                hours_with_events: $hours_with_events,
                hours_without_events: $hours_without_events,
                max_gap_minutes: $max_gap_minutes,
                gaps_detected: $gap_detected
            },
            field_completeness: {
                timestamp: $timestamp_completeness,
                hostname: $hostname_completeness,
                source_type: $source_type_completeness,
                event_category: $event_category_completeness,
                execve_command_line: $execve_completeness,
                ssh_source_ip: $ssh_ip_completeness,
                ssh_user: $ssh_user_completeness,
                auditd_file_path: $file_path_completeness
            }
        }' > "$OUTPUT_FILE"

    # Clean up temporary files
    rm -f "$FIXED_FILE"

    # ── Console Output ────────────────────────────────────────────────────────

    echo "Total events: $total_events"
    echo "Hours with events: ${hours_with_events}"
    if [[ "$gap_detected" == true ]]; then
        echo "Gaps detected: largest ${max_gap_minutes} minutes (>${MAX_GAP_MINUTES} min threshold)"
    else
        echo "No gaps detected"
    fi

    [[ "$execve_total" -gt 0 ]] && echo "execve command_line completeness: ${execve_completeness}%"
    [[ "$ssh_total" -gt 0 ]] && echo "SSH source_ip completeness: ${ssh_ip_completeness}%"
    [[ "$ssh_total" -gt 0 ]] && echo "SSH user completeness: ${ssh_user_completeness}%"
    [[ "$file_access_total" -gt 0 ]] && echo "auditd file path completeness: ${file_path_completeness}%"

    echo "Quality score: ${quality_score}% ($assessment)"
    echo "Report saved to: $OUTPUT_FILE"
}

main "$@"
