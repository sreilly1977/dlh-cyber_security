#!/bin/bash
#
# Name:        11-maintenance_window.sh
# Purpose:     Maintenance window guard that controls patch operations based on
#              defined time windows (timezone-aware, declarative config)
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#
# Window Types:
#   - standard: Regular weekly maintenance window (e.g., Saturday 02:00-06:00)
#   - extended: Extended window with optional week_of_month constraint (e.g., first Saturday 00:00-08:00)
#   - emergency: Always-open window requiring MEDDEFENSE_EMERGENCY=1 to use
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly WINDOWS_FILE="${BASE_DIR}/maintenance_windows.json"
readonly OUTPUT_FILE="${BASE_DIR}/maintenance_window.json"

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
# USAGE
# ============================================
usage() {
    echo "Usage: $SCRIPT_NAME [--check|--wait <seconds>|--report]"
    echo ""
    echo "Modes:"
    echo "  --check         Check if inside maintenance window, exit with code"
    echo "                  0=proceed, 10=emergency only (needs MEDDEFENSE_EMERGENCY=1),"
    echo "                  20=defer (outside all windows)"
    echo "  --wait <sec>    Poll until a window opens or timeout occurs"
    echo "  --report        Emit JSON report without changing exit code"
    echo ""
    echo "Configuration:"
    echo "  maintenance_windows.json defines windows with timezone and schedule"
    exit 1
}

# ============================================
# PREREQUISITES
# ============================================
validate_prerequisites() {
    if [[ ! -f "$WINDOWS_FILE" ]]; then
        warn "Maintenance windows file not found: $WINDOWS_FILE"
        warn "Create a maintenance_windows.json file with the required schema."
        exit 1
    fi

    if ! jq empty "$WINDOWS_FILE" 2>/dev/null; then
        warn "Invalid JSON in maintenance_windows.json"
        exit 1
    fi
}

# ============================================
# TIMEZONE HANDLING
# ============================================
get_timezone() {
    jq -r '.timezone // "UTC"' "$WINDOWS_FILE" 2>/dev/null
}

# Get current datetime in configured timezone
get_now_tz() {
    local tz="$1"
    TZ="$tz" date '+%Y-%m-%d %H:%M'
}

# Get current day of week in configured timezone (1=Mon, 7=Sun)
get_day_of_week() {
    local tz="$1"
    TZ="$tz" date '+%u'
}

# Get current hour in configured timezone
get_hour() {
    local tz="$1"
    TZ="$tz" date '+%H' | sed 's/^0//'
}

# Get current minute in configured timezone
get_minute() {
    local tz="$1"
    TZ="$tz" date '+%M' | sed 's/^0//'
}

# Get current ISO timestamp in configured timezone
get_iso_timestamp() {
    local tz="$1"
    TZ="$tz" date -Iseconds 2>/dev/null || TZ="$tz" date '+%Y-%m-%dT%H:%M:%S%z'
}

# Calculate week of month (1-5)
get_week_of_month() {
    local day_of_month
    day_of_month=$(date '+%d' | sed 's/^0//')

    # Week 1 = days 1-7, Week 2 = days 8-14, etc.
    local week=$(( (day_of_month - 1) / 7 + 1 ))
    echo "$week"
}

# ============================================
# CHECK IF IN WINDOW
# ============================================
is_in_window() {
    local window="$1"
    local tz="$2"
    local now_day="$3"
    local now_hour="$4"
    local now_minute="$5"

    # Emergency window - always true
    local has_always
    has_always=$(echo "$window" | jq -r '.always // false')
    if [[ "$has_always" == "true" ]]; then
        echo "true"
        return
    fi

    # Check day of week
    local days_json
    days_json=$(echo "$window" | jq -r '.days // []')
    local in_day=false

    while IFS= read -r day; do
        [[ -z "$day" ]] && continue

        case "$day" in
            Mon)  [[ "$now_day" -eq 1 ]] && in_day=true ;;
            Tue)  [[ "$now_day" -eq 2 ]] && in_day=true ;;
            Wed)  [[ "$now_day" -eq 3 ]] && in_day=true ;;
            Thu)  [[ "$now_day" -eq 4 ]] && in_day=true ;;
            Fri)  [[ "$now_day" -eq 5 ]] && in_day=true ;;
            Sat)  [[ "$now_day" -eq 6 ]] && in_day=true ;;
            Sun)  [[ "$now_day" -eq 7 ]] && in_day=true ;;
        esac
    done < <(echo "$days_json" | jq -r '.[]' 2>/dev/null)

    if [[ "$in_day" != "true" ]]; then
        echo "false"
        return
    fi

    # Check week of month if specified
    local week_of_month
    week_of_month=$(echo "$window" | jq -r '.week_of_month // empty')
    if [[ -n "$week_of_month" ]]; then
        local current_week
        current_week=$(get_week_of_month)
        if [[ "$current_week" != "$week_of_month" ]]; then
            echo "false"
            return
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

    # Handle empty values
    [[ -z "$start_hour" ]] && start_hour=0
    [[ -z "$start_min" ]] && start_min=0
    [[ -z "$end_hour" ]] && end_hour=23
    [[ -z "$end_min" ]] && end_min=59
    [[ -z "$now_hour" ]] && now_hour=0
    [[ -z "$now_minute" ]] && now_minute=0

    # Convert to minutes for comparison
    local now_mins start_mins end_mins
    now_mins=$((now_hour * 60 + now_minute))
    start_mins=$((start_hour * 60 + start_min))
    end_mins=$((end_hour * 60 + end_min))

    if [[ "$now_mins" -ge "$start_mins" ]] && [[ "$now_mins" -le "$end_mins" ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# ============================================
# FIND NEXT WINDOW
# ============================================
find_next_window() {
    local tz="$1"
    local now_epoch="$2"
    local next_window=""
    local next_epoch=999999999999
    local next_name=""

    # Parse windows and calculate next occurrence for each
    while IFS= read -r window; do
        [[ -z "$window" ]] && continue

        local window_name has_always
        window_name=$(echo "$window" | jq -r '.name // "unknown"')
        has_always=$(echo "$window" | jq -r '.always // false')

        if [[ "$has_always" == "true" ]]; then
            # Emergency window - technically now
            if [[ "$next_epoch" -gt "$now_epoch" ]]; then
                next_epoch="$now_epoch"
                next_name="$window_name"
            fi
            continue
        fi

        local days_json start_time end_time week_of_month
        days_json=$(echo "$window" | jq -r '.days // []')
        start_time=$(echo "$window" | jq -r '.start // "00:00"')
        end_time=$(echo "$window" | jq -r '.end // "23:59"')
        week_of_month=$(echo "$window" | jq -r '.week_of_month // empty')

        # Extract hour/min from start time
        local start_hour start_min
        start_hour=$(echo "$start_time" | cut -d: -f1 | sed 's/^0//')
        start_min=$(echo "$start_time" | cut -d: -f2 | sed 's/^0//')
        [[ -z "$start_hour" ]] && start_hour=0
        [[ -z "$start_min" ]] && start_min=0

        # Calculate next occurrence for each day
        while IFS= read -r day; do
            [[ -z "$day" ]] && continue

            local target_day_num
            case "$day" in
                Mon)  target_day_num=1 ;;
                Tue)  target_day_num=2 ;;
                Wed)  target_day_num=3 ;;
                Thu)  target_day_num=4 ;;
                Fri)  target_day_num=5 ;;
                Sat)  target_day_num=6 ;;
                Sun)  target_day_num=7 ;;
                *)    continue ;;
            esac

            # Calculate next occurrence starting from tomorrow
            local current_day_num
            current_day_num=$(TZ="$tz" date '+%u')

            local days_until=$((target_day_num - current_day_num))
            [[ "$days_until" -le 0 ]] && days_until=$((days_until + 7))

            # Base date for next occurrence
            local next_date
            next_date=$(date -d "+${days_until} days" '+%Y-%m-%d')

            # Add week_of_month constraint if applicable
            if [[ -n "$week_of_month" ]]; then
                local current_week
                current_week=$(date -d "$next_date" '+%d' | sed 's/^0//')
                local base_day=$(( (week_of_month - 1) * 7 + 1 ))

                # Adjust date if needed
                if [[ "$base_day" -gt "$current_week" ]]; then
                    local extra_days=$(( (week_of_month - 1) * 7 ))
                    next_date=$(date -d "+${extra_days} days" '+%Y-%m-%d')
                fi
            fi

            # Combine date with start time
            local next_datetime="${next_date}T${start_hour}:${start_min}:00"
            local candidate_epoch
            candidate_epoch=$(TZ="$tz" date -d "$next_datetime" '+%s' 2>/dev/null || echo 999999999999)

            if [[ "$candidate_epoch" -lt "$next_epoch" ]] && [[ "$candidate_epoch" -gt "$now_epoch" ]]; then
                next_epoch="$candidate_epoch"
                next_name="$window_name"
            fi

        done < <(echo "$days_json" | jq -r '.[]' 2>/dev/null)

    done < <(jq -c '.windows[]' "$WINDOWS_FILE" 2>/dev/null)

    echo "${next_name}|${next_epoch}"
}

# ============================================
# EVALUATE ALL WINDOWS
# ============================================
evaluate_windows() {
    local tz="$1"
    local now_day="$2"
    local now_hour="$3"
    local now_minute="$4"
    local emergency_override="$5"

    local active_window=""
    local window_priority=0
    local emergency_only=false

    # Evaluate each window in priority order
    while IFS= read -r window; do
        [[ -z "$window" ]] && continue

        local window_name has_always
        window_name=$(echo "$window" | jq -r '.name // "unknown"')
        has_always=$(echo "$window" | jq -r '.always // false')

        local in_window
        in_window=$(is_in_window "$window" "$tz" "$now_day" "$now_hour" "$now_minute")

        if [[ "$in_window" == "true" ]]; then
            if [[ "$has_always" == "true" ]]; then
                # Emergency window active
                active_window="$window_name"
                emergency_only=true
            else
                # Standard or extended window - take precedence
                active_window="$window_name"
                emergency_only=false
                break
            fi
        fi

    done < <(jq -c '.windows[]' "$WINDOWS_FILE" 2>/dev/null)

    # Determine decision
    local decision exit_code
    if [[ -n "$active_window" ]] && [[ "$emergency_only" != "true" ]]; then
        decision="proceed"
        exit_code=0
    elif [[ "$emergency_only" == "true" ]]; then
        if [[ "$emergency_override" == "1" ]]; then
            decision="proceed_emergency"
            exit_code=0
        else
            decision="emergency_requires_override"
            exit_code=10
        fi
    else
        decision="defer"
        exit_code=20
    fi

    echo "${active_window}|${decision}|${exit_code}"
}

# ============================================
# GENERATE REPORT
# ============================================
generate_report() {
    local tz="$1"
    local active_window="$2"
    local decision="$3"
    local exit_code="$4"
    local next_info="$5"
    local seconds_until="$6"

    local now_iso
    now_iso=$(get_iso_timestamp "$tz")

    local now_display
    now_display=$(get_now_tz "$tz")
    local day_name
    day_name=$(TZ="$tz" date '+%a')

    local next_window_name next_window_ts
    next_window_name=$(echo "$next_info" | cut -d'|' -f1)
    next_window_ts=$(echo "$next_info" | cut -d'|' -f2)

    if [[ "$next_window_name" == "" ]]; then
        next_window_name="null"
        next_window_ts="null"
    fi

    local next_window_iso
    if [[ "$next_window_ts" != "null" ]] && [[ "$next_window_ts" != "" ]]; then
        next_window_iso=$(TZ="$tz" date -d "@${next_window_ts}" -Iseconds 2>/dev/null || echo "null")
    else
        next_window_iso="null"
    fi

    jq -n \
        --arg now "$now_iso" \
        --arg now_display "$now_display ($day_name)" \
        --arg tz "$tz" \
        --arg active_window "$active_window" \
        --arg decision "$decision" \
        --argjson seconds_until "$seconds_until" \
        --argjson exit_code "$exit_code" \
        --arg next_window "$next_window_name" \
        --arg next_window_ts "$next_window_iso" \
        '{
            now: $now,
            now_display: $now_display,
            timezone: $tz,
            active_window: (if $active_window == "" or $active_window == "null" then null else $active_window end),
            decision: $decision,
            next_window: (if $next_window == "null" or $next_window == "" then null else {name: $next_window, at: $next_window_ts} end),
            seconds_until_next: (if $seconds_until == "null" or $seconds_until == "" then null else ($seconds_until | tonumber) end),
            exit_code: $exit_code
        }' > "$OUTPUT_FILE"
}

# ============================================
# WAIT MODE
# ============================================
do_wait() {
    local timeout_sec="$1"
    local tz
    tz=$(get_timezone)

    local waited=0
    local interval=30

    while [[ "$waited" -lt "$timeout_sec" ]]; do
        local now_epoch
        now_epoch=$(TZ="$tz" date '+%s')
        local now_day now_hour now_minute
        now_day=$(get_day_of_week "$tz")
        now_hour=$(get_hour "$tz")
        now_minute=$(get_minute "$tz")

        local result
        result=$(evaluate_windows "$tz" "$now_day" "$now_hour" "$now_minute" "${MEDDEFENSE_EMERGENCY:-0}")
        local active_window decision exit_code
        active_window=$(echo "$result" | cut -d'|' -f1)
        decision=$(echo "$result" | cut -d'|' -f2)
        exit_code=$(echo "$result" | cut -d'|' -f3)

        if [[ "$exit_code" -eq 0 ]]; then
            log "Window opened: ${active_window}"
            log "Proceeding..."
            exit 0
        fi

        log "Not in window (${decision}). Waiting ${interval}s..."
        sleep "$interval"
        waited=$((waited + interval))
    done

    log "Timeout reached. Still outside maintenance window."

    # Generate final report before exit
    local next_info seconds_until
    local next_data
    next_data=$(find_next_window "$tz" "$now_epoch")
    next_info=$(echo "$next_data" | cut -d'|' -f1)
    seconds_until=$(echo "$next_data" | cut -d'|' -f2)

    generate_report "$tz" "$active_window" "$decision" "$exit_code" "$next_info" "$seconds_until"

    exit 20
}

# ============================================
# CHECK MODE
# ============================================
do_check() {
    local tz
    tz=$(get_timezone)

    local now_epoch
    now_epoch=$(TZ="$tz" date '+%s')
    local now_day now_hour now_minute
    now_day=$(get_day_of_week "$tz")
    now_hour=$(get_hour "$tz")
    now_minute=$(get_minute "$tz")

    local result
    result=$(evaluate_windows "$tz" "$now_day" "$now_hour" "$now_minute" "${MEDDEFENSE_EMERGENCY:-0}")
    local active_window decision exit_code
    active_window=$(echo "$result" | cut -d'|' -f1)
    decision=$(echo "$result" | cut -d'|' -f2)
    exit_code=$(echo "$result" | cut -d'|' -f3)

    # Find next window if not currently active
    local next_info next_window_name seconds_until
    local next_data
    next_data=$(find_next_window "$tz" "$now_epoch")
    next_window_name=$(echo "$next_data" | cut -d'|' -f1)
    local next_epoch
    next_epoch=$(echo "$next_data" | cut -d'|' -f2)

    if [[ "$next_epoch" != "999999999999" ]] && [[ "$next_epoch" != "" ]]; then
        seconds_until=$((next_epoch - now_epoch))
    else
        seconds_until=""
    fi

    # Display info
    local now_display day_name
    now_display=$(get_now_tz "$tz")
    day_name=$(TZ="$tz" date '+%a')

    echo "now:            ${now_display} ${day_name}"
    if [[ -n "$active_window" ]]; then
        echo "active window:  ${active_window}"
    else
        echo "active window:  (none)"
    fi

    if [[ -n "$next_window_name" ]]; then
        local next_ts_display
        if [[ "$next_epoch" != "999999999999" ]] && [[ "$next_epoch" != "" ]]; then
            next_ts_display=$(TZ="$tz" date -d "@${next_epoch}" '+%Y-%m-%d %H:%M')
            echo "next window:    ${next_window_name} at ${next_ts_display}"
            echo "seconds until:  ${seconds_until}"
        fi
    fi

    echo "decision:       ${decision}"

    # Generate JSON report
    generate_report "$tz" "$active_window" "$decision" "$exit_code" "$next_window_name" "$seconds_until"
    log "Report saved to: $OUTPUT_FILE"

    exit "$exit_code"
}

# ============================================
# REPORT MODE
# ============================================
do_report() {
    local tz
    tz=$(get_timezone)

    local now_epoch
    now_epoch=$(TZ="$tz" date '+%s')
    local now_day now_hour now_minute
    now_day=$(get_day_of_week "$tz")
    now_hour=$(get_hour "$tz")
    now_minute=$(get_minute "$tz")

    local result
    result=$(evaluate_windows "$tz" "$now_day" "$now_hour" "$now_minute" "${MEDDEFENSE_EMERGENCY:-0}")
    local active_window decision exit_code
    active_window=$(echo "$result" | cut -d'|' -f1)
    decision=$(echo "$result" | cut -d'|' -f2)
    exit_code=$(echo "$result" | cut -d'|' -f3)

    local next_info next_window_name seconds_until
    local next_data
    next_data=$(find_next_window "$tz" "$now_epoch")
    next_window_name=$(echo "$next_data" | cut -d'|' -f1)
    local next_epoch
    next_epoch=$(echo "$next_data" | cut -d'|' -f2)

    if [[ "$next_epoch" != "999999999999" ]] && [[ "$next_epoch" != "" ]]; then
        seconds_until=$((next_epoch - now_epoch))
    else
        seconds_until=""
    fi

    generate_report "$tz" "$active_window" "$decision" "$exit_code" "$next_window_name" "$seconds_until"
    log "Report saved to: $OUTPUT_FILE"

    exit 0
}

# ============================================
# MAIN
# ============================================
main() {
    validate_prerequisites

    # Parse arguments
    local mode="" wait_seconds=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check)
                mode="check"
                shift
                ;;
            --wait)
                mode="wait"
                shift
                if [[ $# -eq 0 ]]; then
                    warn "Error: --wait requires a seconds argument"
                    usage
                fi
                wait_seconds="$1"
                shift
                ;;
            --report)
                mode="report"
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                warn "Unknown argument: $1"
                usage
                ;;
        esac
    done

    if [[ -z "$mode" ]]; then
        warn "Error: No mode specified"
        usage
    fi

    # Execute mode
    case "$mode" in
        check)
            do_check
            ;;
        wait)
            do_wait "$wait_seconds"
            ;;
        report)
            do_report
            ;;
        *)
            warn "Unknown mode: $mode"
            usage
            ;;
    esac
}

main "$@"
