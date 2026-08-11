#!/bin/bash
#
# Name:        12-change_log.sh
# Purpose:     Produce a canonical change log from apt history logs and prior
#              task artifacts, enriched with maintenance window and CVE data
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly APT_HISTORY_GLOB="/var/log/apt/history.log*"
readonly DPKG_LOG="/var/log/dpkg.log"
readonly EXECUTION_LOG="${BASE_DIR}/patch_execution_log.json"
readonly VULN_INVENTORY="${BASE_DIR}/vulnerability_inventory.json"
readonly WINDOW_SCRIPT="${BASE_DIR}/11-maintenance_window.sh"
readonly OUTPUT_FILE="${BASE_DIR}/patch_change_log.json"

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
# PARSE APT HISTORY LOGS
# ============================================
parse_apt_history() {
    local temp_file
    temp_file=$(mktemp)

    # Process all history log files including rotated (.1, .2, etc.)
    for hist_file in $APT_HISTORY_GLOB; do
        [[ ! -f "$hist_file" ]] && continue

        # Decompress .gz files
        if [[ "$hist_file" == *.gz ]]; then
            zcat "$hist_file" 2>/dev/null
        else
            cat "$hist_file" 2>/dev/null
        fi
    done | awk '
    BEGIN {
        in_transaction = 0
        start_date = ""
        commandline = ""
        requested_by = ""
        upgrades = ""
        installs = ""
        removes = ""
    }

    /^Start-Date:/ {
        if (in_transaction == 1) {
            print start_date "\t" commandline "\t" requested_by "\t" upgrades "\t" installs "\t" removes
        }
        in_transaction = 1
        start_date = substr($0, 13)
        gsub(/^[ \t]+/, "", start_date)
        commandline = ""
        requested_by = ""
        upgrades = ""
        installs = ""
        removes = ""
        next
    }

    /^Commandline:/ {
        commandline = substr($0, 13)
        gsub(/^[ \t]+/, "", commandline)
        next
    }

    /^Requested-By:/ {
        requested_by = substr($0, 15)
        gsub(/^[ \t]+/, "", requested_by)
        next
    }

    /^Upgrade:/ {
        upgrades = substr($0, 10)
        gsub(/^[ \t]+/, "", upgrades)
        next
    }

    /^Install:/ {
        installs = substr($0, 10)
        gsub(/^[ \t]+/, "", installs)
        next
    }

    /^Remove:/ {
        removes = substr($0, 9)
        gsub(/^[ \t]+/, "", removes)
        next
    }

    /^End-Date:/ {
        if (in_transaction == 1) {
            print start_date "\t" commandline "\t" requested_by "\t" upgrades "\t" installs "\t" removes
        }
        in_transaction = 0
        next
    }
    ' >> "$temp_file"

    echo "$temp_file"
}

# ============================================
# CONVERT TIMESTAMP TO ISO 8601
# ============================================
normalize_timestamp() {
    local raw="$1"
    # apt history uses: 2026-03-28  02:03:12
    local cleaned
    cleaned=$(echo "$raw" | sed 's/  */ /g' | xargs)
    date -d "$cleaned" -Iseconds 2>/dev/null || echo "$raw"
}

# Convert to epoch seconds for grouping
to_epoch() {
    local iso_ts="$1"
    date -d "$iso_ts" '+%s' 2>/dev/null || echo 0
}

# ============================================
# EXTRACT USER FROM REQUESTED-BY FIELD
# ============================================
extract_user() {
    local requested_by="$1"

    if [[ -z "$requested_by" ]]; then
        echo "system"
        return
    fi

    # Format is typically: "user (uid)" or just "user"
    local user
    user=$(echo "$requested_by" | sed 's/ (.*//' | sed 's/^[ \t]*//')
    [[ -z "$user" ]] && user="system"
    echo "$user"
}

# ============================================
# COUNT PACKAGES IN A TRANSACTION
# ============================================
count_packages() {
    local upgrades="$1"
    local installs="$2"
    local removes="$3"
    local count=0

    # Count entries in each field (comma-separated within parentheses)
    if [[ -n "$upgrades" ]] && [[ "$upgrades" != "" ]]; then
        local u
        u=$(echo "$upgrades" | grep -oE '\([^)]*\)' | wc -l || true)
        [[ -z "$u" ]] && u=0
        count=$((count + u))
    fi

    if [[ -n "$installs" ]] && [[ "$installs" != "" ]]; then
        local i
        i=$(echo "$installs" | grep -oE '\([^)]*\)' | wc -l || true)
        [[ -z "$i" ]] && i=0
        count=$((count + i))
    fi

    if [[ -n "$removes" ]] && [[ "$removes" != "" ]]; then
        local r
        r=$(echo "$removes" | grep -oE '\([^)]*\)' | wc -l || true)
        [[ -z "$r" ]] && r=0
        count=$((count + r))
    fi

    echo "$count"
}

# ============================================
# EXTRACT PACKAGE NAMES FROM TRANSACTION FIELDS
# ============================================
extract_package_names() {
    local field="$1"

    if [[ -z "$field" ]]; then
        echo ""
        return
    fi

    # apt history format: "pkgname:arch (oldver, newver), pkgname2:arch (oldver, newver)"
    # Split by "), " then strip everything from "(" onwards, then strip ":arch" suffix
    echo "$field" | sed 's/), /\n/g' | sed 's/(.*//' | sed 's/:.*//' | sed 's/^[ \t]*//;s/[ \t]*$//' | grep -v '^$' | sort -u
}

# ============================================
# CHECK MAINTENANCE WINDOW FOR A TIMESTAMP
# ============================================
check_maintenance_window() {
    local iso_ts="$1"

    if [[ ! -x "$WINDOW_SCRIPT" ]] && [[ ! -f "$WINDOW_SCRIPT" ]]; then
        echo "unknown"
        return
    fi

    # The window script reads current system time, not a provided timestamp.
    # We evaluate the decision based on the event timestamp components.
    local event_epoch event_day event_hour event_minute
    event_epoch=$(to_epoch "$iso_ts")

    local event_date
    event_date=$(date -d "@$event_epoch" '+%Y-%m-%d' 2>/dev/null || echo "")
    local event_day_num
    event_day_num=$(date -d "@$event_epoch" '+%u' 2>/dev/null || echo "0")
    event_hour=$(date -d "@$event_epoch" '+%H' 2>/dev/null | sed 's/^0//' || echo "0")
    event_minute=$(date -d "@$event_epoch" '+%M' 2>/dev/null | sed 's/^0//' || echo "0")

    [[ -z "$event_hour" ]] && event_hour=0
    [[ -z "$event_minute" ]] && event_minute=0

    local windows_file="${BASE_DIR}/maintenance_windows.json"
    if [[ ! -f "$windows_file" ]]; then
        echo "unknown"
        return
    fi

    local tz
    tz=$(jq -r '.timezone // "UTC"' "$windows_file" 2>/dev/null)

    # Evaluate in the configured timezone
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

        # Check day match
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

        # Check week_of_month if specified
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

        # Check time window
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

    done < <(jq -c '.windows[]' "$windows_file" 2>/dev/null)

    if [[ "$result" == "outside" ]] && [[ "$emergency_only" == "true" ]]; then
        result="emergency_only"
    fi

    echo "$result"
}

# ============================================
# CHECK LINKED EXECUTION LOG
# ============================================
check_linked_execution_log() {
    local event_epoch="$1"
    local event_end_epoch="$2"

    if [[ ! -f "$EXECUTION_LOG" ]]; then
        echo ""
        return
    fi

    # Check if any entry in the execution log has a timestamp within 15 min of the event
    local has_match
    has_match=$(jq -r '
        .entries[]? |
        .timestamp // .executed_at // .start_time // empty
    ' "$EXECUTION_LOG" 2>/dev/null | head -1 || echo "")

    if [[ -z "$has_match" ]]; then
        # If we can not parse timestamps, just link if file exists
        echo "$EXECUTION_LOG"
        return
    fi

    # Try to match timestamps
    local log_epoch
    while IFS= read -r ts; do
        [[ -z "$ts" ]] && continue
        log_epoch=$(date -d "$ts" '+%s' 2>/dev/null || echo 0)
        if [[ "$log_epoch" -gt 0 ]]; then
            local diff=$((log_epoch - event_epoch))
            if [[ ${diff#-} -le 900 ]]; then
                echo "$EXECUTION_LOG"
                return
            fi
        fi
    done < <(jq -r '.entries[]? | .timestamp // .executed_at // .start_time // empty' "$EXECUTION_LOG" 2>/dev/null)

    echo ""
}

# ============================================
# CROSS-REFERENCE CVEs RESOLVED
# ============================================
get_cves_resolved() {
    local package_names="$1"

    if [[ ! -f "$VULN_INVENTORY" ]]; then
        echo "[]"
        return
    fi

    local cves_json='[]'

    while IFS= read -r pkg; do
        [[ -z "$pkg" ]] && continue

        # Look up CVEs for this package in the vulnerability inventory
        local pkg_cves
        pkg_cves=$(jq -c --arg p "$pkg" '
            [.vulnerabilities[]? | select(.package == $p) | .cve // empty] | unique
        ' "$VULN_INVENTORY" 2>/dev/null || echo '[]')

        if [[ "$pkg_cves" != "[]" ]] && [[ -n "$pkg_cves" ]]; then
            cves_json=$(echo "$cves_json" | jq ". + $pkg_cves" 2>/dev/null || echo "$cves_json")
        fi

    done <<< "$package_names"

    # Deduplicate
    cves_json=$(echo "$cves_json" | jq 'unique' 2>/dev/null || echo '[]')

    echo "$cves_json"
}

# ============================================
# GROUP TRANSACTIONS INTO CHANGE EVENTS
# ============================================
group_into_events() {
    local parsed_file="$1"

    local events_temp
    events_temp=$(mktemp)

    local prev_epoch=0
    local current_event_start=""
    local current_event_end_epoch=0
    local current_user=""
    local current_tx_count=0
    local current_packages=""

    while IFS=$'\t' read -r start_date cmdline req_by upgrades installs removes; do
        local iso_ts
        iso_ts=$(normalize_timestamp "$start_date")
        local epoch
        epoch=$(to_epoch "$iso_ts")

        if [[ "$epoch" -eq 0 ]]; then
            continue
        fi

        # Grouping: if within 15 minutes (900 sec) of previous transaction, same event
        local diff=$((epoch - prev_epoch))
        if [[ $diff -le 900 ]] && [[ $diff -ge 0 ]] && [[ $prev_epoch -gt 0 ]]; then
            # Same event — accumulate
            current_event_end_epoch="$epoch"
            current_tx_count=$((current_tx_count + 1))
            # Append package names
            local pkg_names
            pkg_names=$(extract_package_names "${upgrades} ${installs}")
            [[ -n "$pkg_names" ]] && current_packages="${current_packages}"$'\n'"${pkg_names}"
        else
            # New event — flush previous if exists
            if [[ $prev_epoch -gt 0 ]] && [[ -n "$current_event_start" ]]; then
                local event_user
                event_user=$(extract_user "$current_user")
                local start_epoch_val
                start_epoch_val=$(to_epoch "$current_event_start")
                # Sort packages unique and join with comma
                local pkgs_joined
                pkgs_joined=$(echo "$current_packages" | sort -u | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
                printf '%s\t%s\t%s\t%s\t%s\n' "$start_epoch_val" "$current_event_end_epoch" "$event_user" "$current_tx_count" "$pkgs_joined" >> "$events_temp"
            fi

            # Start new event
            current_event_start="$iso_ts"
            current_event_end_epoch="$epoch"
            current_user="$req_by"
            current_tx_count=1
            current_packages=$(extract_package_names "${upgrades}${installs}")
        fi

        prev_epoch="$epoch"
    done < <(sort -t$'\t' -k1,1 "$parsed_file")

    # Flush last event
    if [[ $prev_epoch -gt 0 ]] && [[ -n "$current_event_start" ]]; then
        local event_user
        event_user=$(extract_user "$current_user")
        local start_epoch_val
        start_epoch_val=$(to_epoch "$current_event_start")
        local pkgs_joined
        pkgs_joined=$(echo "$current_packages" | sort -u | grep -v '^$' | tr '\n' ',' | sed 's/,$//')
        printf '%s\t%s\t%s\t%s\t%s\n' "$start_epoch_val" "$current_event_end_epoch" "$event_user" "$current_tx_count" "$pkgs_joined" >> "$events_temp"
    fi

    echo "$events_temp"
}

# ============================================
# BUILD EVENTS JSON
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

        local iso_start iso_end
        iso_start=$(date -d "@$start_epoch" -Iseconds 2>/dev/null || echo "")
        iso_end=$(date -d "@$end_epoch" -Iseconds 2>/dev/null || echo "")

        # Check maintenance window
        local within_window
        within_window=$(check_maintenance_window "$iso_start")

        # Map to inside/outside for summary
        local window_label="outside"
        if [[ "$within_window" == "inside" ]]; then
            window_label="inside"
        fi

        # Check linked execution log
        local linked_log
        linked_log=$(check_linked_execution_log "$start_epoch" "$end_epoch")

                # Get CVEs resolved from packages list - querying .packages (not .vulnerable_packages)
        local cves_resolved='[]'
        local cves_count=0

        if [[ -f "$VULN_INVENTORY" ]] && [[ -n "$packages" ]]; then
            # Create temp file with normalized package names (strip :arch suffix)
            local pkg_list_temp
            pkg_list_temp=$(mktemp)
            echo "$packages" | tr ',' '\n' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed 's/:.*$//' | grep -v '^$' | sort -u > "$pkg_list_temp"

            log "  Searching CVEs for: $(cat "$pkg_list_temp" | tr '\n' ' ')" >&2

            # Query vulnerability inventory for matching CVEs
            # Note: Uses .packages[], not .vulnerable_packages (which is just a count)
            local all_cves_temp
            all_cves_temp=$(mktemp)

            while IFS= read -r search_pkg; do
                [[ -z "$search_pkg" ]] && continue

                # Query .packages array for CVEs matching this package name
                local found_cves
                found_cves=$(jq -r --arg p "$search_pkg" '
                    [.packages[]? |
                     select(.package == $p or (.package | split(":")[0]) == $p) |
                     .cves[]?] | unique | .[]
                ' "$VULN_INVENTORY" 2>/dev/null || echo "")

                if [[ -n "$found_cves" ]]; then
                    echo "$found_cves" >> "$all_cves_temp"
                fi
            done < "$pkg_list_temp"

            # Deduplicate and format as JSON array
            if [[ -s "$all_cves_temp" ]]; then
                cves_resolved=$(sort -u "$all_cves_temp" | jq -R -s 'split("\n") | map(select(length > 0))' 2>/dev/null || echo '[]')
            else
                cves_resolved='[]'
            fi

            rm -f "$pkg_list_temp" "$all_cves_temp"

            # Ensure valid JSON
            if ! echo "$cves_resolved" | jq empty 2>/dev/null; then
                cves_resolved='[]'
            fi

            cves_count=$(echo "$cves_resolved" | jq 'length' 2>/dev/null || echo 0)
            log "  Found ${cves_count} unique CVEs" >&2
        fi

        # Build event JSON (compact, single line)
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

    # Read all event lines and build array
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

    # ============================================
    # STEP 1: Parse apt history logs
    # ============================================
    log "Parsing /var/log/apt/history.log*..."
    local parsed_file
    parsed_file=$(parse_apt_history)

    local tx_count
    tx_count=$(grep -c . "$parsed_file" 2>/dev/null || true)
    [[ -z "$tx_count" ]] && tx_count=0
    log "Parsed ${tx_count} transactions"

    # ============================================
    # STEP 2: Group into change events
    # ============================================
    log "Grouping transactions into events (15-min proximity)..."
    local events_file
    events_file=$(group_into_events "$parsed_file")

    local event_count
    event_count=0
    if [[ -s "$events_file" ]]; then
        event_count=$(grep -c . "$events_file" 2>/dev/null || true)
        [[ -z "$event_count" ]] && event_count=0
    fi
    log "Found ${event_count} change events"

    # ============================================
    # STEP 3: Build enriched events JSON
    # ============================================
    log "Enriching events with window, execution log, and CVE data..."
    local events_json
    events_json=$(build_events_json "$events_file")

    # ============================================
    # STEP 4: Compute period and summary
    # ============================================
    local period_start="null"
    local period_end="null"
    local total_events=0
    local inside_window=0
    local outside_window=0
    local cves_resolved_total=0

    total_events=$(echo "$events_json" | jq 'length' 2>/dev/null || echo 0)

    if [[ "$total_events" -gt 0 ]]; then
        period_start=$(echo "$events_json" | jq -r '.[0].started' 2>/dev/null || echo "null")
        period_end=$(echo "$events_json" | jq -r '.[-1].ended // .[-1].started' 2>/dev/null || echo "null")
        inside_window=$(echo "$events_json" | jq '[.[] | select(.within_window == "inside")] | length' 2>/dev/null || echo 0)
        outside_window=$(echo "$events_json" | jq '[.[] | select(.within_window == "outside")] | length' 2>/dev/null || echo 0)
        cves_resolved_total=$(echo "$events_json" | jq '[.[].cves_resolved[]?] | unique | length' 2>/dev/null || echo 0)
    fi

    # ============================================
    # STEP 5: Emit patch_change_log.json
    # ============================================
    local events_input
    events_input=$(echo "$events_json")

    echo "$events_input" | jq \
        --arg period_start "$period_start" \
        --arg period_end "$period_end" \
        --argjson total "$total_events" \
        --argjson inside "$inside_window" \
        --argjson outside "$outside_window" \
        --argjson cves "$cves_resolved_total" \
        '{
            period_start: (if $period_start == "null" then null else $period_start end),
            period_end: (if $period_end == "null" then null else $period_end end),
            events: .,
            summary: {
                total_events: $total,
                inside_window: $inside,
                outside_window: $outside,
                cves_resolved: $cves
            }
        }' > "$OUTPUT_FILE"

    rm -f "$parsed_file" "$events_file"

    log "Change log saved to: $OUTPUT_FILE"
    log "  Total events:    ${total_events}"
    log "  Inside window:   ${inside_window}"
    log "  Outside window:  ${outside_window}"
    log "  CVEs resolved:   ${cves_resolved_total}"
}

main "$@"
