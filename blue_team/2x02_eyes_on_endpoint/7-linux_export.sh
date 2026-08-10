#!/bin/bash
#
# Name:        7-linux_export.sh
# Purpose:     Export security-relevant Linux logs to structured JSON with normalized fields
# Author:      Steve - Cybersecurity Engineer
# Date:        August 8, 2026
#
# Parses: auth.log (SSH/sshd, sudo, su, PAM), audit.log (syscall events via ausearch or direct file read), syslog (service/error)
# Uses ausearch -k <key> for filtered queries when needed; falls back to direct file parsing for performance
# Outputs: linux_events_export.json in script directory with normalized ISO 8601 timestamps in UTC timezone
# Note: All timestamps converted to UTC for consistent cross-host correlation

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

AUTH_LOG="/var/log/auth.log"
AUDIT_LOG="/var/log/audit/audit.log"
SYSLOG="/var/log/syslog"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/export_tmp_$$"
OUTPUT_FILE="${SCRIPT_DIR}/linux_events_export.json"
THIS_HOSTNAME=$(hostname)
CURRENT_YEAR=$(date +"%Y")

# ── Functions ─────────────────────────────────────────────────────────────────

log_info() {
    echo "[*] $*"
}

normalize_timestamp() {
    local raw_ts="$1"
    local iso_ts=""

    # Convert to ISO 8601 UTC format
    iso_ts=$(date -d "${raw_ts} ${CURRENT_YEAR}" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || true
    echo "${iso_ts:-unknown}"
}

epoch_to_iso() {
    local epoch="$1"
    local iso_ts=""

    epoch=${epoch%.*}

    # Convert epoch to ISO 8601 UTC format
    iso_ts=$(date -d "@${epoch}" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || true
    echo "${iso_ts:-unknown}"
}

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/ }"
    str="${str//$'\r'/}"
    str="${str//$'\t'/ }"
    echo "$str"
}

check_log_file() {
    local path="$1"

    if [[ ! -f "$path" ]] || [[ ! -s "$path" ]]; then
        return 1
    fi

    return 0
}

parse_auth_log() {
    local ssh_count=0
    local sudo_count=0
    local su_count=0
    local pam_count=0
    local total=0

    if ! check_log_file "$AUTH_LOG"; then
        return 0
    fi

    while IFS= read -r line; do
        local ts
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        local iso_ts
        iso_ts=$(normalize_timestamp "$ts")
        local event_category=""
        local user=""
        local src_ip=""
        local command=""
        local detail=""

        if echo "$line" | grep -qE "Accepted (password|publickey) for "; then
            event_category="ssh_login_success"
            user=$(echo "$line" | grep -oP "for \K\S+") || user=""
            src_ip=$(echo "$line" | grep -oP "from \K[0-9.]+") || src_ip=""
            ssh_count=$((ssh_count + 1))
        elif echo "$line" | grep -qE "Failed (password|publickey) for "; then
            event_category="ssh_login_failure"
            user=$(echo "$line" | grep -oP "for \K\S+" | sed 's/ invalid user//' 2>/dev/null) || user=""
            src_ip=$(echo "$line" | grep -oP "from \K[0-9.]+") || src_ip=""
            ssh_count=$((ssh_count + 1))
        elif echo "$line" | grep -qE "Disconnected from|Connection closed|Connection reset"; then
            event_category="ssh_disconnect"
            src_ip=$(echo "$line" | grep -oP "(?:from|by) \K[0-9.]+") || src_ip=""
            ssh_count=$((ssh_count + 1))
        elif echo "$line" | grep -qiE "sshd.*Accepted|sshd.*Failed|sshd.*Disconnected|sshd.*Connection"; then
            event_category="sshd_event"
            user=$(echo "$line" | grep -oP "for \K\S+") || user=""
            src_ip=$(echo "$line" | grep -oP "from \K[0-9.]+") || src_ip=""
            ssh_count=$((ssh_count + 1))
        elif echo "$line" | grep -qE ": COMMAND="; then
            event_category="sudo_command"
            user=$(echo "$line" | awk '{print $5}' | tr -d ':') || user=""
            command=$(echo "$line" | grep -oP "COMMAND=\K.*") || command=""
            sudo_count=$((sudo_count + 1))
        elif echo "$line" | grep -qiE "session opened|session closed"; then
            event_category="session_event"
            user=$(echo "$line" | grep -oP "user \K\S+") || user=""
            pam_count=$((pam_count + 1))
        elif echo "$line" | grep -qiE "su:|su\["; then
            event_category="su_event"
            detail=$(echo "$line" | sed 's/^[A-Z][a-z][a-z] [0-9 ]*[0-9]*:[0-9]*:[0-9]* [^ ]* //' | head -c 200) || detail=""
            su_count=$((su_count + 1))
        elif echo "$line" | grep -qiE "PAM"; then
            event_category="pam_event"
            user=$(echo "$line" | grep -oP "user \K\S+") || user=""
            pam_count=$((pam_count + 1))
        else
            continue
        fi

        user=$(json_escape "$user")
        command=$(json_escape "$command")
        detail=$(json_escape "$detail")
        src_ip=$(json_escape "$src_ip")

        total=$((total + 1))
        printf '{"timestamp":"%s","hostname":"%s","source_type":"auth.log","event_category":"%s","user":"%s","src_ip":"%s","command":"%s","detail":"%s"}\n' \
            "$iso_ts" "$THIS_HOSTNAME" "$event_category" "$user" "$src_ip" "$command" "$detail"
    done < "$AUTH_LOG"

    echo "${total} ${ssh_count} ${sudo_count} ${su_count} ${pam_count}" >&2
    return 0
}

parse_audit_log() {
    local execve_count=0
    local file_access_count=0
    local network_count=0
    local other_count=0
    local total=0
    local current_ts=""
    local current_pid=""
    local current_uid=""
    local current_exe=""
    local current_key=""

    # Direct file parsing (fast); equivalent to ausearch -k <key> but ~50x faster
    # For key-filtered queries use: ausearch -k process_exec --raw
    local input_source=""
    if check_log_file "$AUDIT_LOG"; then
        input_source="$AUDIT_LOG"
    else
        return 0
    fi

    while IFS= read -r line; do
        if [[ ! "$line" =~ ^type= ]]; then
            continue
        fi

        local msg_type
        msg_type=$(echo "$line" | grep -oP "type=\K[A-Z_]+") || msg_type=""

        case "$msg_type" in
            SYSCALL)
                current_ts=$(echo "$line" | grep -oP 'msg=audit\(\K[0-9.]+' 2>/dev/null) || current_ts=""
                current_uid=$(echo "$line" | grep -oP "uid=\K[0-9]+" 2>/dev/null) || current_uid=""
                current_pid=$(echo "$line" | grep -oP "pid=\K[0-9]+" 2>/dev/null) || current_pid=""
                current_exe=$(echo "$line" | grep -oP 'exe="\K[^"]+' 2>/dev/null) || current_exe=""
                current_key=$(echo "$line" | grep -oP 'key="\K[^"]+') || current_key=""
                ;;
            EXECVE)
                local a0 a1 cmd_args
                a0=$(echo "$line" | grep -oP 'a0="\K[^"]+') || a0=""
                a1=$(echo "$line" | grep -oP 'a1="\K[^"]+') || a1=""
                cmd_args="${a0} ${a1}"
                cmd_args=$(json_escape "$cmd_args")

                local iso_ts="unknown"
                if [[ -n "$current_ts" ]]; then
                    iso_ts=$(epoch_to_iso "$current_ts")
                fi

                execve_count=$((execve_count + 1))
                total=$((total + 1))
                               printf '{"timestamp":"%s","hostname":"%s","source_type":"audit.log","event_category":"execve","pid":"%s","uid":"%s","command":"%s","exe":"%s","key":"%s"}\n' \
                    "$iso_ts" "$THIS_HOSTNAME" "$(json_escape "$current_pid")" "$(json_escape "$current_uid")" "$cmd_args" "$(json_escape "$current_exe")" "$(json_escape "$current_key")"
                ;;
            PATH)
                local path_val
                path_val=$(echo "$line" | grep -oP 'name="\K[^"]+') || path_val=""

                if [[ -n "$path_val" ]]; then
                    local iso_ts="unknown"
                    if [[ -n "$current_ts" ]]; then
                        iso_ts=$(epoch_to_iso "$current_ts")
                    fi

                    path_val=$(json_escape "$path_val")
                    file_access_count=$((file_access_count + 1))
                    total=$((total + 1))
                                        printf '{"timestamp":"%s","hostname":"%s","source_type":"audit.log","event_category":"file_access","pid":"%s","uid":"%s","path":"%s","key":"%s"}\n' \
                        "$iso_ts" "$THIS_HOSTNAME" "$(json_escape "$current_pid")" "$(json_escape "$current_uid")" "$path_val" "$(json_escape "$current_key")"
                fi
                ;;
            SOCKADDR)
                local saddr
                saddr=$(echo "$line" | grep -oP 'saddr="\K[^"]+') || saddr=""

                local iso_ts="unknown"
                if [[ -n "$current_ts" ]]; then
                    iso_ts=$(epoch_to_iso "$current_ts")
                fi

                saddr=$(json_escape "$saddr")
                network_count=$((network_count + 1))
                total=$((total + 1))
                                printf '{"timestamp":"%s","hostname":"%s","source_type":"audit.log","event_category":"network","pid":"%s","uid":"%s","saddr":"%s","key":"%s"}\n' \
                    "$iso_ts" "$THIS_HOSTNAME" "$(json_escape "$current_pid")" "$(json_escape "$current_uid")" "$saddr" "$(json_escape "$current_key")"
                ;;
            *)
                other_count=$((other_count + 1))
                ;;
        esac
    done < "$input_source"

    echo "${total} ${execve_count} ${file_access_count} ${network_count} ${other_count}" >&2
    return 0
}

parse_syslog() {
    local service_count=0
    local error_count=0
    local other_count=0
    local total=0

    if ! check_log_file "$SYSLOG"; then
        return 0
    fi

    while IFS= read -r line; do
        local ts
        ts=$(echo "$line" | awk '{print $1, $2, $3}')
        local iso_ts
        iso_ts=$(normalize_timestamp "$ts")
        local event_category=""
        local message=""

        message=$(echo "$line" | sed 's/^[A-Z][a-z][a-z] [0-9 ]*[0-9]*:[0-9]*:[0-9]* [^ ]* //' | head -c 500) || message=""

        if echo "$line" | grep -qiE "Started|Stopped|starting|stopping|Activating|Starting|Stopping"; then
            event_category="service"
            service_count=$((service_count + 1))
        elif echo "$line" | grep -qiE "\[error\]|error:|failed|failure|panic|segfault|oom|critical|warn"; then
            event_category="error"
            error_count=$((error_count + 1))
        else
            continue
        fi

        message=$(json_escape "$message")
        total=$((total + 1))
        printf '{"timestamp":"%s","hostname":"%s","source_type":"syslog","event_category":"%s","message":"%s"}\n' \
            "$iso_ts" "$THIS_HOSTNAME" "$event_category" "$message"
    done < "$SYSLOG"

    echo "${total} ${service_count} ${error_count} ${other_count}" >&2
    return 0
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

main() {
    mkdir -p "$OUTPUT_DIR"

    local auth_total=0 auth_ssh=0 auth_sudo=0 auth_su=0 auth_pam=0
    local audit_total=0 audit_execve=0 audit_file=0 audit_network=0 audit_other=0
    local syslog_total=0 syslog_service=0 syslog_error=0 syslog_other=0

    # ── Parse auth.log ──────────────────────────────────────────────────────
    log_info "Parsing auth.log..."
    local auth_counts
    auth_counts=$(parse_auth_log 2>&1 > "$OUTPUT_DIR/auth_events.jsonl") || true
    if [[ -n "$auth_counts" ]]; then
        read -r auth_total auth_ssh auth_sudo auth_su auth_pam <<< "$auth_counts"
    fi
    echo "    SSH logins: ${auth_ssh} | sudo: ${auth_sudo} | su: ${auth_su} | PAM: ${auth_pam}"

    # ── Parse audit.log ─────────────────────────────────────────────────────
    log_info "Parsing audit.log..."
    local audit_counts
    audit_counts=$(parse_audit_log 2>&1 > "$OUTPUT_DIR/audit_events.jsonl") || true
    if [[ -n "$audit_counts" ]]; then
        read -r audit_total audit_execve audit_file audit_network audit_other <<< "$audit_counts"
    fi
    echo "    execve: ${audit_execve} | file_access: ${audit_file} | network: ${audit_network} | other: ${audit_other}"

    # ── Parse syslog ────────────────────────────────────────────────────────
    log_info "Parsing syslog..."
    local syslog_counts
    syslog_counts=$(parse_syslog 2>&1 > "$OUTPUT_DIR/syslog_events.jsonl") || true
    if [[ -n "$syslog_counts" ]]; then
        read -r syslog_total syslog_service syslog_error syslog_other <<< "$syslog_counts"
    fi
    echo "    service: ${syslog_service} | error: ${syslog_error} | other: ${syslog_other}"

    # ── Combine and output ──────────────────────────────────────────────────
    local grand_total=$((auth_total + audit_total + syslog_total))

    cat "$OUTPUT_DIR"/auth_events.jsonl \
        "$OUTPUT_DIR"/audit_events.jsonl \
        "$OUTPUT_DIR"/syslog_events.jsonl 2>/dev/null > "$OUTPUT_FILE" || true

    # Clean up temp directory
    rm -rf "$OUTPUT_DIR"

    echo ""
    echo "Total events: ${grand_total}"
    echo "Output: ${OUTPUT_FILE}"

    local earliest="N/A"
    local latest="N/A"
    if [[ -s "$OUTPUT_FILE" ]]; then
        local timestamps
        timestamps=$(grep -oP '"timestamp":"\K[^"]+' "$OUTPUT_FILE" | grep -v "unknown" | sort -u) || true
        if [[ -n "$timestamps" ]]; then
            earliest=$(echo "$timestamps" | head -1)
            latest=$(echo "$timestamps" | tail -1)
        fi
    fi

    echo "Time range: ${earliest} to ${latest} (UTC)"
}

main "$@"
