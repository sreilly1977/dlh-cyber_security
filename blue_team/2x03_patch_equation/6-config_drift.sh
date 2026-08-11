#!/bin/bash
#
# Name:        6-config_drift.sh
# Purpose:     Detect configuration file drift caused by the patch run
# Author:      Steve - Cybersecurity Engineer
# Date:        August 11, 2026
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

readonly PRE_STATE_FILE="${BASE_DIR}/pre_patch_state.json"
readonly EXECUTION_LOG="${BASE_DIR}/patch_execution_log.json"
readonly OUTPUT_FILE="${BASE_DIR}/config_drift.json"

log() {
    echo "[*] $*"
}

warn() {
    echo "[!] $*" >&2
}

validate_prerequisites() {
    local missing=0

    if [[ ! -f "$PRE_STATE_FILE" ]]; then
        warn "Pre-patch state file not found: $PRE_STATE_FILE"
        missing=1
    fi

    if [[ ! -f "$EXECUTION_LOG" ]]; then
        warn "Execution log not found: $EXECUTION_LOG"
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        log "ERROR: Missing prerequisite files. Exiting."
        exit 1
    fi
}

compute_sha256() {
    local filepath="$1"
    if [[ -f "$filepath" ]]; then
        sha256sum "$filepath" 2>/dev/null | awk '{print $1}'
    else
        echo ""
    fi
}

get_current_conffiles() {
    for cf in /var/lib/dpkg/info/*.conffiles; do
        [[ ! -f "$cf" ]] && continue
        local pkg
        pkg=$(basename "$cf" .conffiles)
        while IFS= read -r path; do
            [[ -z "$path" ]] && continue
            printf '%s\t%s\n' "$path" "$pkg"
        done < "$cf"
    done
}

get_upgraded_packages() {
    jq -r '[.entries[]? | select(.status == "success") | .package] | unique | .[]' "$EXECUTION_LOG" 2>/dev/null || echo ''
}

was_package_upgraded() {
    local package="$1"
    local upgraded_list="$2"

    echo "$upgraded_list" | grep -qx "$package" && return 0 || return 1
}

produce_diff() {
    local filepath="$1"

    local dist_file="${filepath}.dpkg-dist"
    if [[ -f "$dist_file" ]]; then
        diff -u "$dist_file" "$filepath" 2>/dev/null | head -40 || true
        return
    fi

    local old_file="${filepath}.dpkg-old"
    if [[ -f "$old_file" ]]; then
        diff -u "$old_file" "$filepath" 2>/dev/null | head -40 || true
        return
    fi

    local ucf_new="${filepath}.ucf-new"
    if [[ -f "$ucf_new" ]]; then
        diff -u "$ucf_new" "$filepath" 2>/dev/null | head -40 || true
        return
    fi

    local ucf_old="${filepath}.ucf-old"
    if [[ -f "$ucf_old" ]]; then
        diff -u "$ucf_old" "$filepath" 2>/dev/null | head -40 || true
        return
    fi

    local owning_pkg
    owning_pkg=$(dpkg-query -S "$filepath" 2>/dev/null | cut -d: -f1 | head -1 || echo "")
    if [[ -n "$owning_pkg" ]]; then
        local deb_file
        deb_file=$(ls -t /var/cache/apt/archives/${owning_pkg}_*.deb 2>/dev/null | head -1 || echo "")
        if [[ -n "$deb_file" ]] && [[ -f "$deb_file" ]]; then
            local temp_dir
            temp_dir=$(mktemp -d)
            if dpkg-deb --fsys-tarfile "$deb_file" 2>/dev/null | \
               tar -xf - -C "$temp_dir" "${filepath#/}" 2>/dev/null; then
                local extracted="${temp_dir}${filepath}"
                if [[ -f "$extracted" ]]; then
                    diff -u "$extracted" "$filepath" 2>/dev/null | head -40 || true
                    rm -rf "$temp_dir"
                    return
                fi
            fi
            rm -rf "$temp_dir"
        fi
    fi

    echo "diff_unavailable"
}

perform_drift_detection() {
    local unchanged_count=0
    local modified_count=0
    local missing_count=0
    local new_count=0
    local expected_drift=0
    local unexpected_drift=0

    local files_temp
    files_temp=$(mktemp)
    echo '[' > "$files_temp"
    local first_entry=true

    # ============================================
    # STEP 1: Load conffile hashes from pre_patch_state.json
    # Structure: { count: N, list: [{ package, file, sha256 }] }
    # ============================================
    log "Loading conffile hashes from pre_patch_state.json..."

    local pre_conffiles_json
    pre_conffiles_json=$(jq '.conffile_hashes.list // []' "$PRE_STATE_FILE" 2>/dev/null || echo '[]')

    local pre_count
    pre_count=$(echo "$pre_conffiles_json" | jq 'length' 2>/dev/null || echo 0)

    log "Pre-patch conffiles: ${pre_count}"

    # ============================================
    # STEP 2: Get list of upgraded packages from execution log
    # ============================================
    local upgraded_pkgs
    upgraded_pkgs=$(get_upgraded_packages)
    local upgraded_count
    upgraded_count=$(echo "$upgraded_pkgs" | grep -c . 2>/dev/null || echo 0)
    log "Packages upgraded in this run: ${upgraded_count}"

    # ============================================
    # STEP 3: Build current conffile lookup (path -> package)
    # ============================================
    declare -A current_conffile_owners
    while IFS=$'\t' read -r path pkg; do
        [[ -z "$path" ]] && continue
        current_conffile_owners["$path"]="$pkg"
    done < <(get_current_conffiles)

    # ============================================
    # STEP 4: Compare each pre-patch conffile against current state
    # ============================================
    log "Comparing conffile hashes..."

    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue

        local path pre_hash owning_pkg current_hash
        path=$(echo "$entry" | jq -r '.file')
        pre_hash=$(echo "$entry" | jq -r '.sha256 // ""')
        owning_pkg=$(echo "$entry" | jq -r '.package // ""')

        # If no owning package stored, try to determine it
        if [[ -z "$owning_pkg" ]]; then
            owning_pkg="${current_conffile_owners[$path]:-}"
            if [[ -z "$owning_pkg" ]]; then
                owning_pkg=$(dpkg-query -S "$path" 2>/dev/null | cut -d: -f1 | head -1 || echo "")
            fi
        fi

        local classification="unchanged"
        local current_hash=""
        local diff_content=""
        local expected=false

        if [[ ! -f "$path" ]]; then
            classification="missing"
            missing_count=$((missing_count + 1))
        else
            current_hash=$(compute_sha256 "$path")

            if [[ "$current_hash" == "$pre_hash" ]]; then
                classification="unchanged"
                unchanged_count=$((unchanged_count + 1))
            else
                classification="modified"
                modified_count=$((modified_count + 1))

                diff_content=$(produce_diff "$path")

                if [[ -n "$owning_pkg" ]] && was_package_upgraded "$owning_pkg" "$upgraded_pkgs"; then
                    expected=true
                    expected_drift=$((expected_drift + 1))
                else
                    expected=false
                    unexpected_drift=$((unexpected_drift + 1))
                fi
            fi
        fi

        local file_entry
        file_entry=$(jq -n \
            --arg path "$path" \
            --arg pkg "$owning_pkg" \
            --arg classification "$classification" \
            --arg pre_hash "$pre_hash" \
            --arg cur_hash "$current_hash" \
            --argjson expected "$expected" \
            --arg diff "$diff_content" \
            '{
                path: $path,
                owning_package: $pkg,
                classification: $classification,
                expected: $expected,
                pre_hash: $pre_hash,
                current_hash: $cur_hash,
                diff: $diff
            }')

        if [[ "$first_entry" == true ]]; then
            echo "$file_entry" >> "$files_temp"
            first_entry=false
        else
            echo ",$file_entry" >> "$files_temp"
        fi

    done < <(echo "$pre_conffiles_json" | jq -c '.[]')

    # ============================================
    # STEP 5: Detect new conffiles added by the patch
    # ============================================
    log "Detecting new conffiles..."

    local pre_paths
    pre_paths=$(echo "$pre_conffiles_json" | jq -r '.[].file' | sort -u)

    while IFS=$'\t' read -r path pkg; do
        [[ -z "$path" ]] && continue

        if echo "$pre_paths" | grep -qx "$path"; then
            continue
        fi

        new_count=$((new_count + 1))

        local current_hash
        current_hash=$(compute_sha256 "$path")

        if [[ -n "$pkg" ]] && was_package_upgraded "$pkg" "$upgraded_pkgs"; then
            expected=true
            expected_drift=$((expected_drift + 1))
        else
            expected=false
            unexpected_drift=$((unexpected_drift + 1))
        fi

        local file_entry
        file_entry=$(jq -n \
            --arg path "$path" \
            --arg pkg "$pkg" \
            --arg classification "new" \
            --arg pre_hash "" \
            --arg cur_hash "$current_hash" \
            --argjson expected "$expected" \
            --arg diff "" \
            '{
                path: $path,
                owning_package: $pkg,
                classification: "new",
                expected: $expected,
                pre_hash: $pre_hash,
                current_hash: $cur_hash,
                diff: $diff
            }')

        if [[ "$first_entry" == true ]]; then
            echo "$file_entry" >> "$files_temp"
            first_entry=false
        else
            echo ",$file_entry" >> "$files_temp"
        fi

    done < <(get_current_conffiles)

    echo ']' >> "$files_temp"

    # ============================================
    # STEP 6: Emit config_drift.json
    # ============================================
    local total=$((unchanged_count + modified_count + missing_count + new_count))

    log "Config drift detection complete."
    log "  Unchanged: ${unchanged_count}"
    log "  Modified:  ${modified_count}"
    log "  Missing:   ${missing_count}"
    log "  New:       ${new_count}"
    log "  Expected drift:     ${expected_drift}"
    log "  Unexpected drift:   ${unexpected_drift}"

    # Pipe files via stdin to avoid ARG_MAX limits
    cat "$files_temp" | jq \
        --argjson total "$total" \
        --argjson unchanged "$unchanged_count" \
        --argjson modified "$modified_count" \
        --argjson missing "$missing_count" \
        --argjson new "$new_count" \
        --argjson expected "$expected_drift" \
        --argjson unexpected "$unexpected_drift" \
        '{
            summary: {
                total: $total,
                unchanged: $unchanged,
                modified: $modified,
                missing: $missing,
                new: $new,
                expected_drift: $expected,
                unexpected_drift: $unexpected
            },
            files: .
        }' > "$OUTPUT_FILE" || echo '{"summary":{"total":0,"unchanged":0,"modified":0,"missing":0,"new":0,"expected_drift":0,"unexpected_drift":0},"files":[]}' > "$OUTPUT_FILE"

    rm -f "$files_temp"

    log "Report saved to: $OUTPUT_FILE"

    if [[ $unexpected_drift -gt 0 ]]; then
        return 1
    fi
    return 0
}

main() {
    log "Starting configuration drift detection..."

    validate_prerequisites

    if perform_drift_detection; then
        log "No unexpected drift detected."
        exit 0
    else
        warn "Unexpected drift detected!"
        exit 1
    fi
}

main "$@"
