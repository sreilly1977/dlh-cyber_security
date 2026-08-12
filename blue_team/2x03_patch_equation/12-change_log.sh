#!/bin/bash
#
# Name:        12-change_log.sh
# Purpose:     Parse apt history logs, group into events, enrich with
#              maintenance window, execution log, and CVE data
# Author:      Steve - Cybersecurity Engineer
# Date:        August 12, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly OUTPUT_FILE="${BASE_DIR}/patch_change_log.json"
readonly VULN_INVENTORY="${BASE_DIR}/vulnerability_inventory.json"
readonly CVE_FEED="${BASE_DIR}/cve_feed.json"
readonly WINDOW_SCRIPT="${BASE_DIR}/11-maintenance_window.sh"
readonly EXECUTION_LOG="${BASE_DIR}/patch_execution_log.json"
readonly WINDOWS_FILE="${BASE_DIR}/maintenance_windows.json"

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

# ============================================
# CONVERT ISO TIMESTAMP TO EPOCH
# ============================================
to_epoch() {
    local ts="$1"
    date -d "$ts" '+%s' 2>/dev/null || echo 0
}

# ============================================
# EXTRACT PACKAGE NAMES FROM APT HISTORY FIELD
# ============================================
extract_package_names() {
    local field="$1"

    if [[ -z "$field" ]]; then
        echo ""
        return
    fi

    # Split by "), " then strip everything from "(" onwards, then strip ":arch" suffix
    echo "$field" | sed 's/), /\n/g' | sed 's/(.*//' | sed 's/:.*//' | sed 's/^[ \t]*//;s/[ \t]*$//' | grep -v '^$' | sort -u
}

# ============================================
# CHECK MAINTENANCE WINDOW FOR A TIMESTAMP
# ============================================
check_maintenance_window() {
    local iso_ts="$1"

    if [[ -x "$WINDOW_SCRIPT" ]] || [[ -f "$WINDOW_SCRIPT" ]]; then
        :
    fi

    local event_epoch
    event_epoch=$(to_epoch "$iso_ts")

    if [[ ! -f "$WINDOWS_FILE" ]]; then
        echo "unknown"
        return
    fi

    local tz
    tz=$(jq -r '.timezone // "UTC"' "$WINDOWS_FILE" 2>/dev/null)

    local tz_day_num tz_hour tz_minute
    tz_day_num=$(TZ="$tz" date -d "@$event_epoch" '+%u' 2>/dev/null || echo "0")
    tz_hour=$(TZ="$tz" date -d "@$event_epoch" '+%H' 2>/dev/null | sed 's/^0//' || echo "0")
    tz_minute=$(TZ="$tz" date -d "@$event_epoch" '+%M' 2>/dev/null | sed 's/^0//' || echo "0")

    [[ -z "$tz_hour" ]] && tz_hour=0
    [[ -z "$tz_minute" ]] && tz_minute=0

    local result="outside"
    local emergency_only=false

    while IFS= read -r window; do
        [[ -z "$window" ]] && continue

        local window_name has_always
        window_name=$(echo "$window" | jq -r '.name // "unknown"')
        has_always=$(echo "$window" | jq -r '.always // false')

        if [[ "$has_always" == "true" ]]; then
            emergency_only=true
            continue
        fi

        local days_json
        days_json=$(echo "$window" | jq -r '.days // []')
        local day_match=false

        while IFS= read -r day; do
            [[ -z "$day" ]] && continue
            case "$day" in
                Mon)  [[ "$tz_day_num" -eq 1 ]] && day_match=true ;;
                Tue)  [[ "$tz_day_num" -eq 2 ]] && day_match=true ;;
                Wed)  [[ "$tz_day_num" -eq 3 ]] && day_match=true ;;
                Thu)  [[ "$tz_day_num" -eq 4 ]] && day_match=true ;;
                Fri)  [[ "$tz_day_num" -eq 5 ]] && day_match=true ;;
                Sat)  [[ "$tz_day_num" -eq 6 ]] && day_match=true ;;
                Sun)  [[ "$tz_day_num" -eq 7 ]] && day_match=true ;;
            esac
        done < <(echo "$days_json" | jq -r '.[]' 2>/dev/null)

        if [[ "$day_match" != "true" ]]; then
            continue
        fi

        local week_of_month
        week_of_month=$(echo "$window" | jq -r '.week_of_month // empty')
        if [[ -n "$week_of_month" ]]; then
            local day_of_month
            day_of_month=$(TZ="$tz" date -d "@$event_epoch" '+%d' 2>/dev/null | sed 's/^0//' || echo "1")
            local current_week
            current_week=$(( (day_of_month - 1) / 7 + 1 ))
            if [[ "$current_week" != "$week_of_month" ]]; then
                continue
            fi
        fi

        local start_time end_time
        start_time=$(echo "$window" | jq -r '.start // "00:00"')
        end_time=$(echo "$window" | jq -r '.end // "23:59"')

        local start_hour start_min end_hour end_min
        start_hour=$(echo "$start_time" | cut -d: -f1 | sed 's/^0//')
        start_min=$(echo "$start_time" | cut -d: -f2 | sed 's/^0//')
        end_hour=$(echo "$end_time" | cut -d: -f1 | sed 's/^0//')
        end_min=$(echo "$end_time" | cut -d: -f2 | sed 's/^0//')

        [[ -z "$start_hour" ]] && start_hour=0
        [[ -z "$start_min" ]] && start_min=0
        [[ -z "$end_hour" ]] && end_hour=23
        [[ -z "$end_min" ]] && end_min=59

        local now_mins start_mins end_mins
        now_mins=$((tz_hour * 60 + tz_minute))
        start_mins=$((start_hour * 60 + start_min))
        end_mins=$((end_hour * 60 + end_min))

        if [[ "$now_mins" -ge "$start_mins" ]] && [[ "$now_mins" -le "$end_mins" ]]; then
            result="inside"
            break
        fi

    done < <(jq -c '.windows[]' "$WINDOWS_FILE" 2>/dev/null)

    if [[ "$result" == "outside" ]] && [[ "$emergency_only" == "true" ]]; then
        result="emergency_only"
    fi

    echo "$result"
}

# ============================================
# CHECK FOR LINKED EXECUTION LOG
# ============================================
check_linked_execution_log() {
    local start_epoch="$1"
    local end_epoch="$2"

    if [[ ! -f "$EXECUTION_LOG" ]]; then
        echo ""
        return
    fi

    local linked
    linked=$(jq -r --argjson start "$start_epoch" --argjson end "$end_epoch" '
        .executions[]? |
        select(
            ((.started | todate | fromdate) >= $start and (.started | todate | fromdate) <= $end)
        ) |
        .log_file // .id // empty
    ' "$EXECUTION_LOG" 2>/dev/null | head -1 || echo "")

    echo "$linked"
}

# ============================================
# PARSE APT HISTORY LOG ENTRIES
# ============================================
parse_apt_history() {
    local temp_file
    temp_file=$(mktemp)

    local hist_files=()
    if [[ -f /var/log/apt/history.log ]]; then
        hist_files+=(/var/log/apt/history.log)
    fi
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        hist_files+=("$f")
    done < <(ls /var/log/apt/history.log.* 2>/dev/null | sort -r || true)

    for hist_file in "${hist_files[@]:-}"; do
        [[ -z "$hist_file" ]] && continue
        [[ ! -f "$hist_file" ]] && continue

        local cat_cmd="cat"
        if [[ "$hist_file" == *.gz ]]; then
            cat_cmd="zcat"
        fi

        local content
        content=$($cat_cmd "$hist_file" 2>/dev/null || true)

        local in_record=false
        local start_date=""
        local end_date=""
        local cmd=""
        local user="root"
        local tx_count=0
        local upgrades=""
        local installs=""

        while IFS= read -r line; do
            case "$line" in
                Start-Date:*)
                    if [[ "$in_record" == "true" ]] && [[ -n "$start_date" ]]; then
                        local epoch_start epoch_end
                        epoch_start=$(to_epoch "$start_date")
                        epoch_end=$(to_epoch "$end_date")

                        local pkg_names="$upgrades"
                        if [[ -n "$installs" ]]; then
                            if [[ -n "$pkg_names" ]]; then
                                pkg_names="${pkg_names},${installs}"
                            else
                                pkg_names="$installs"
                            fi
                        fi

                        if [[ "$tx_count" -gt 0 ]]; then
                            printf '%s\t%s\t%s\t%s\t%s\n' \
                                "$epoch_start" "$epoch_end" "$user" "$tx_count" "$pkg_names" >> "$temp_file"
                        fi
                    fi

                    in_record=true
                    start_date=$(echo "$line" | sed 's/^Start-Date: *//')
                    end_date=""
                    cmd=""
                    user="root"
                    tx_count=0
                    upgrades=""
                    installs=""
                    ;;
                End-Date:*)
                    end_date=$(echo "$line" | sed 's/^End-Date: *//')
                    ;;
                Commandline:*)
                    cmd=$(echo "$line" | sed 's/^Commandline: *//')
                    ;;
                Requested-By:*)
                    user=$(echo "$line" | sed 's/^Requested-By: *//' | sed 's/ *$//' | tr -d '(')
                    ;;
                Upgrade:*|Install:*|Remove:*)
                    tx_count=$((tx_count + 1))
                    local pkg_line
                    pkg_line=$(echo "$line" | sed 's/^[^:]*: *//')

                    if [[ "$line" == Upgrade:* ]]; then
                        if [[ -n "$upgrades" ]]; then
                            upgrades="${upgrades},${pkg_line}"
                        else
                            upgrades="$pkg_line"
                        fi
                    elif [[ "$line" == Install:* ]]; then
                        if [[ -n "$installs" ]]; then
                            installs="${installs},${pkg_line}"
                        else
                            installs="$pkg_line"
                        fi
                    fi
                    ;;
            esac
        done <<< "$content"

        # Save final record
        if [[ "$in_record" == "true" ]] && [[ -n "$start_date" ]]; then
            local epoch_start epoch_end
            epoch_start=$(to_epoch "$start_date")
            epoch_end=$(to_epoch "$end_date")

            local pkg_names="$upgrades"
            if [[ -n "$installs" ]]; then
                if [[ -n "$pkg_names" ]]; then
                    pkg_names="${pkg_names},${installs}"
                else
                    pkg_names="$installs"
                fi
            fi

            if [[ "$tx_count" -gt 0 ]]; then
                printf '%s\t%s\t%s\t%s\t%s\n' \
                    "$epoch_start" "$epoch_end" "$user" "$tx_count" "$pkg_names" >> "$temp_file"
            fi
        fi
    done

    echo "$temp_file"
}

# ============================================
# GROUP TRANSACTIONS INTO EVENTS
# ============================================
group_into_events() {
    local parsed_file="$1"
    local events_file
    events_file=$(mktemp)

    if [[ ! -s "$parsed_file" ]]; then
        echo "$events_file"
        return
    fi

    # Sort by start timestamp, then group transactions within 15 minutes
    sort -t$'\t' -k1,1n "$parsed_file" | awk -F'\t' '
    BEGIN {
        OFS="\t"
        event_start=0
        event_end=0
        event_user=""
        tx_count=0
        all_upgrades=""
        first=1
    }
    {
        curr_start=$1
        curr_end=$2
        curr_user=$3
        curr_tx=$4
        curr_packages=$5

        if (first) {
            event_start=curr_start
            event_end=curr_end
            event_user=curr_user
            tx_count=curr_tx
            all_packages=curr_packages
            first=0
        } else if ((curr_start - event_end) <= 900) {
            if (curr_end > event_end) event_end=curr_end
            tx_count += curr_tx
            if (curr_packages != "") {
                if (all_packages != "") all_packages=all_packages "," curr_packages
                else all_packages=curr_packages
            }
        } else {
            print event_start, event_end, event_user, tx_count, all_packages
            event_start=curr_start
            event_end=curr_end
            event_user=curr_user
            tx_count=curr_tx
            all_packages=curr_packages
        }
    }
    END {
        if (!first) {
            print event_start, event_end, event_user, tx_count, all_packages
        }
    }
    ' > "$events_file" 2>/dev/null

    echo "$events_file"
}

# ============================================
# BUILD EVENTS JSON WITH ENRICHMENT
# ============================================
build_events_json() {
    local events_file="$1"

    if [[ ! -s "$events_file" ]]; then
        echo '[]'
        return
    fi

    local events_temp
    events_temp=$(mktemp)

    while IFS=$'\t' read -r start_epoch end_epoch user tx_count packages; do
        [[ -z "$start_epoch" ]] && continue
        [[ "$start_epoch" == "0" ]] && continue

        local iso_start iso_end
        iso_start=$(date -d "@$start_epoch" -Iseconds 2>/dev/null || echo "")
        iso_end=$(date -d "@$end_epoch" -Iseconds 2>/dev/null || echo "")

        local within_window
        within_window=$(check_maintenance_window "$iso_start")

        local window_label="outside"
        if [[ "$within_window" == "inside" ]]; then
            window_label="inside"
        fi

        local linked_log
        linked_log=$(check_linked_execution_log "$start_epoch" "$end_epoch")

        local cves_resolved='[]'
        local cves_count=0

        if [[ -n "$packages" ]]; then
            local pkg_list_temp
            pkg_list_temp=$(mktemp)
            echo "$packages" | tr ',' '\n' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/:.*$//' | grep -v '^$' | sort -u > "$pkg_list_temp"

            log "  Searching CVEs for: $(cat "$pkg_list_temp" | tr '\n' ' ')" >&2

            local all_cves_temp
            all_cves_temp=$(mktemp)

            while IFS= read -r search_pkg; do
                [[ -z "$search_pkg" ]] && continue

                local found_cves
                found_cves=$(jq -r --arg p "$search_pkg" '
                    [.packages[]? |
                     select(.package == $p or (.package | split(":")[0]) == $p) |
                     .cves[]?] | unique | .[]
                ' "$VULN_INVENTORY" 2>/dev/null || echo "")

                if [[ -n "$found_cves" ]]; then
                    echo "$found_cves" >> "$all_cves_temp"
                fi

                local feed_cves
                if [[ -f "$CVE_FEED" ]]; then
                    feed_cves=$(jq -r --arg p "$search_pkg" '
                        .cves | to_entries[] |
                        select(any(.value.affected_packages[]?; . == $p or (split(":")[0]) == $p)) |
                        .key
                    ' "$CVE_FEED" 2>/dev/null || echo "")
                fi

                if [[ -n "$feed_cves" ]]; then
                    echo "$feed_cves" >> "$all_cves_temp"
                fi

            done < "$pkg_list_temp"

            if [[ -s "$all_cves_temp" ]]; then
                cves_resolved=$(sort -u "$all_cves_temp" | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo '[]')
            else
                cves_resolved='[]'
            fi

            rm -f "$pkg_list_temp" "$all_cves_temp"

            if ! echo "$cves_resolved" | jq empty 2>/dev/null; then
                cves_resolved='[]'
            fi

            cves_count=$(echo "$cves_resolved" | jq 'length' 2>/dev/null || echo 0)
            log "  Found ${cves_count} unique CVEs" >&2
        fi

        jq -nc \
            --arg started "$iso_start" \
            --arg ended "$iso_end" \
            --arg user "$user" \
            --arg within_window "$window_label" \
            --arg linked_log "$linked_log" \
            --argjson tx_count "$tx_count" \
            --argjson cves_count "$cves_count" \
            --argjson cves "$cves_resolved" \
            '{
                started: $started,
                ended: $ended,
                user: $user,
                within_window: $within_window,
                transactions: $tx_count,
                linked_execution_log: (if $linked_log == "" then null else $linked_log end),
                cves_resolved: $cves,
                cves_resolved_count: $cves_count
            }' >> "$events_temp"

    done < "$events_file"

    if [[ -s "$events_temp" ]]; then
        jq -s '.' "$events_temp" 2>/dev/null || echo '[]'
    else
        echo '[]'
    fi

    rm -f "$events_temp"
}

# ============================================
# MAIN
# ============================================
main() {
    log "Building change log from apt history logs..."

    log "Parsing /var/log/apt/history.log*..."
    local parsed_file
    parsed_file=$(parse_apt_history)

    local tx_count=0
    if [[ -s "$parsed_file" ]]; then
        tx_count=$(wc -l < "$parsed_file")
    fi
    log "Parsed ${tx_count} transactions"

    log "Grouping transactions into events (15-min proximity)..."
    local events_file
    events_file=$(group_into_events "$parsed_file")

    local event_count=0
    if [[ -s "$events_file" ]]; then
        event_count=$(wc -l < "$events_file")
    fi
    log "Found ${event_count} change events"

    log "Enriching events with window, execution log, and CVE data..."
    local events_json
    events_json=$(build_events_json "$events_file")

    local inside_count outside_count total_cves
    inside_count=$(echo "$events_json" | jq '[.[] | select(.within_window == "inside")] | length' 2>/dev/null || echo 0)
    outside_count=$(echo "$events_json" | jq '[.[] | select(.within_window == "outside")] | length' 2>/dev/null || echo 0)
    total_cves=$(echo "$events_json" | jq '[.[]?.cves_resolved[]?] | unique | length' 2>/dev/null || echo 0)

    local generated_at
    generated_at=$(date -u -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')

    local hostname_val
    hostname_val=$(hostname 2>/dev/null || echo "unknown")

    jq -n \
        --arg generated_at "$generated_at" \
        --arg hostname "$hostname_val" \
        --argjson total_events "$event_count" \
        --argjson inside_count "$inside_count" \
        --argjson outside_count "$outside_count" \
        --argjson total_cves "$total_cves" \
        --argjson events "$events_json" \
        '{
            generated_at: $generated_at,
            hostname: $hostname,
            summary: {
                total_events: $total_events,
                inside_window: $inside_count,
                outside_window: $outside_count,
                cves_resolved: $total_cves
            },
            events: $events
        }' > "$OUTPUT_FILE"

    rm -f "$parsed_file" "$events_file"

    log "Change log saved to: $OUTPUT_FILE"
    log "  Total events:    ${event_count}"
    log "  Inside window:   ${inside_count}"
    log "  Outside window:  ${outside_count}"
    log "  CVEs resolved:   ${total_cves}"
}

main "$@"
