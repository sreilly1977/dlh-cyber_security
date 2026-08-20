#!/bin/bash
#
# Name: 2-target_state.sh
# Purpose: Emit the target state contract as machine-readable JSON
#          Capstone task T2 - Defensible Endpoint Package
# Author: Steve - Cybersecurity Engineer
# Date: 20 August 2026
# Exit Codes: 0=success, 1=controlled failure, 2=environment error
#
# Outputs (relative to script directory):
#   capstone/target_state.json - the target state contract
#

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
readonly CAPSTONE_DIR="${SCRIPT_DIR}/capstone"
readonly TARGET_FILE="${CAPSTONE_DIR}/target_state.json"

cleanup() {
    local exit_code="$?"
    if [[ $exit_code -ne 0 ]]; then
        echo "[$SCRIPT_NAME] Script exited with code $exit_code" >&2
    fi
    exit "$exit_code"
}

trap cleanup EXIT

log_info() {
    echo "[$SCRIPT_NAME][INFO] $*" >&2
}

log_error() {
    echo "[$SCRIPT_NAME][ERROR] $*" >&2
}

validate_environment() {
    log_info "Validating execution environment..."

    if ! command -v jq >/dev/null 2>&1; then
        log_error "jq is not installed - required for JSON output"
        exit 2
    fi

    log_info "Environment validation complete"
}

ensure_directories() {
    log_info "Ensuring capstone directory exists..."

    mkdir -p "$CAPSTONE_DIR" || {
        log_error "Failed to create capstone directory: $CAPSTONE_DIR"
        exit 2
    }

    log_info "Directory ready: $CAPSTONE_DIR"
}

check_force_flag() {
    if [[ -f "$TARGET_FILE" ]]; then
        if [[ "${1:-}" != "--force" ]]; then
            log_error "target_state.json already exists. Use --force to overwrite."
            exit 1
        fi
        log_info "--force flag detected, overwriting existing target_state.json"
    fi
}

emit_controls() {
    local controls_json

    controls_json=$(jq -n \
        --arg ts "$TIMESTAMP" \
        '
        # ── Linux hardening controls ──────────────────────────────
        [
          {
            id: "LNX-SSH-01",
            platform: "linux",
            family: "hardening",
            description: "SSH must disallow root login via password.",
            check_type: "grep_match",
            check_target: "/etc/ssh/sshd_config",
            expected_value: "^PermitRootLogin\\s+no",
            source_project: "2x00_locking_the_gates",
            severity: "critical"
          },
          {
            id: "LNX-SSH-02",
            platform: "linux",
            family: "hardening",
            description: "SSH must refuse password authentication.",
            check_type: "grep_match",
            check_target: "/etc/ssh/sshd_config",
            expected_value: "^PasswordAuthentication\\s+no",
            source_project: "2x00_locking_the_gates",
            severity: "critical"
          },
          {
            id: "LNX-SYS-01",
            platform: "linux",
            family: "hardening",
            description: "IPv4 forwarding must be disabled.",
            check_type: "command_exit_zero",
            check_target: "sysctl net.ipv4.ip_forward | grep -q \"net.ipv4.ip_forward = 0\"",
            expected_value: "0",
            source_project: "2x03_patch_equation",
            severity: "high"
          },
          {
            id: "LNX-SYS-02",
            platform: "linux",
            family: "hardening",
            description: "Kernel address space randomization must be set to 2.",
            check_type: "command_exit_zero",
            check_target: "sysctl kernel.randomize_va_space | grep -q \"kernel.randomize_va_space = 2\"",
            expected_value: "2",
            source_project: "2x03_patch_equation",
            severity: "high"
          },
          {
            id: "LNX-AUD-01",
            platform: "linux",
            family: "telemetry",
            description: "auditd must be active and running.",
            check_type: "command_exit_zero",
            check_target: "systemctl is-active --quiet auditd",
            expected_value: "0",
            source_project: "2x02_eyes_on_endpoint",
            severity: "critical"
          },
          {
            id: "LNX-AUD-02",
            platform: "linux",
            family: "telemetry",
            description: "auditd rules file must be present and loaded.",
            check_type: "file_exists",
            check_target: "/etc/audit/rules.d/hawthorne.rules",
            expected_value: "exists",
            source_project: "2x02_eyes_on_endpoint",
            severity: "high"
          },
          {
            id: "LNX-MAC-01",
            platform: "linux",
            family: "hardening",
            description: "AppArmor must be in enforce mode.",
            check_type: "command_exit_zero",
            check_target: "aa-status --enabled",
            expected_value: "0",
            source_project: "2x01_windows_fortress",
            severity: "high"
          },

        # ── Linux baseline delta ───────────────────────────────────
          {
            id: "LNX-LYN-01",
            platform: "linux",
            family: "hardening",
            description: "Lynis hardening index must be at least 80.",
            check_type: "json_field_gte",
            check_target: "capstone/baseline/baseline_linux.json:hardening_index",
            expected_value: 80,
            source_project: "2x03_patch_equation",
            severity: "medium"
          },

        # ── Linux structured export ────────────────────────────────
          {
            id: "LNX-EXP-01",
            platform: "linux",
            family: "handoff",
            description: "Structured JSON export path must exist.",
            check_type: "file_exists",
            check_target: "capstone/exports/linux_export.json",
            expected_value: "exists",
            source_project: "2x02_eyes_on_endpoint",
            severity: "high"
          },

        # ── Windows hardening controls ────────────────────────────
          {
            id: "WIN-FW-01",
            platform: "windows",
            family: "hardening",
            description: "Windows Firewall must default-deny inbound on every profile.",
            check_type: "command_exit_zero",
            check_target: "powershell -Command \"Get-NetFirewallProfile | Where-Object { $_.DefaultInboundAction -ne \\\"Block\\\" } | Measure-Object | Select-Object -ExpandProperty Count | Select-Object -First 1\" | grep -q \"^0$\"",
            expected_value: "0",
            source_project: "2x01_windows_fortress",
            severity: "critical"
          },
          {
            id: "WIN-PWR-01",
            platform: "windows",
            family: "telemetry",
            description: "PowerShell Script Block Logging must be enabled.",
            check_type: "grep_match",
            check_target: "reg query \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging",
            expected_value: "0x1",
            source_project: "2x02_eyes_on_endpoint",
            severity: "high"
          },
          {
            id: "WIN-SYS-01",
            platform: "windows",
            family: "telemetry",
            description: "Sysmon service must be installed and running.",
            check_type: "command_exit_zero",
            check_target: "powershell -Command \"Get-Service Sysmon | Where-Object { $_.Status -ne \\\"Running\\\" } | Measure-Object | Select-Object -ExpandProperty Count\" | grep -q \"^0$\"",
            expected_value: "0",
            source_project: "2x02_eyes_on_endpoint",
            severity: "critical"
          },
          {
            id: "WIN-SYS-02",
            platform: "windows",
            family: "telemetry",
            description: "Sysmon event count must be greater than zero in the last 10 minutes.",
            check_type: "json_field_gte",
            check_target: "capstone/exports/windows_sysmon_events.json:event_count",
            expected_value: 1,
            source_project: "2x02_eyes_on_endpoint",
            severity: "medium"
          },
          {
            id: "WIN-SYS-03",
            platform: "windows",
            family: "telemetry",
            description: "Script Block Logging event channel size must be greater than zero.",
            check_type: "json_field_gte",
            check_target: "capstone/exports/windows_sbl_channel.json:channel_size",
            expected_value: 1,
            source_project: "2x02_eyes_on_endpoint",
            severity: "medium"
          },
          {
            id: "WIN-AUD-01",
            platform: "windows",
            family: "telemetry",
            description: "Audit policy must cover Account Logon, Logon, Object Access and Privilege Use subcategories.",
            check_type: "json_field_equals",
            check_target: "capstone/exports/windows_audit_summary.json:required_categories_present",
            expected_value: true,
            source_project: "2x02_eyes_on_endpoint",
            severity: "high"
          },

        # ── Windows baseline delta ─────────────────────────────────
          {
            id: "WIN-CIS-01",
            platform: "windows",
            family: "hardening",
            description: "CIS Level 1 pass rate must be at least 85 percent.",
            check_type: "json_field_gte",
            check_target: "capstone/baseline/baseline_windows.json:pass_rate_percent",
            expected_value: 85,
            source_project: "2x03_patch_equation",
            severity: "medium"
          },

        # ── Patching controls ──────────────────────────────────────
          {
            id: "PAT-INV-01",
            platform: "both",
            family: "patching",
            description: "vulnerability_inventory.json must be present.",
            check_type: "file_exists",
            check_target: "capstone/patching/vulnerability_inventory.json",
            expected_value: "exists",
            source_project: "2x03_patch_equation",
            severity: "high"
          },
          {
            id: "PAT-PLAN-01",
            platform: "both",
            family: "patching",
            description: "patch_plan.json must be present.",
            check_type: "file_exists",
            check_target: "capstone/patching/patch_plan.json",
            expected_value: "exists",
            source_project: "2x03_patch_equation",
            severity: "high"
          },
          {
            id: "PAT-EXEC-01",
            platform: "both",
            family: "patching",
            description: "patch_execution_log.json must be present with zero entries in failed state.",
            check_type: "json_field_equals",
            check_target: "capstone/patching/patch_execution_log.json:failed_count",
            expected_value: 0,
            source_project: "2x03_patch_equation",
            severity: "critical"
          },
          {
            id: "PAT-BLK-01",
            platform: "linux",
            family: "patching",
            description: "unattended-upgrades must be configured with the mandated blacklist.",
            check_type: "grep_match",
            check_target: "/etc/apt/apt.conf.d/50unattended-upgrades",
            expected_value: "Unattended-Upgrade::Package-Blacklist",
            source_project: "2x03_patch_equation",
            severity: "medium"
          },

        # ── Network controls ──────────────────────────────────────
          {
            id: "NET-NFT-01",
            platform: "linux",
            family: "network",
            description: "nftables input chain must default to drop.",
            check_type: "command_exit_zero",
            check_target: "nft list ruleset | grep -qE \"chain input.*policy drop\"",
            expected_value: "0",
            source_project: "2x04_perimeter_defense",
            severity: "critical"
          },
          {
            id: "NET-SEG-01",
            platform: "both",
            family: "network",
            description: "segmentation_rules.json must be present.",
            check_type: "file_exists",
            check_target: "capstone/network/segmentation_rules.json",
            expected_value: "exists",
            source_project: "2x04_perimeter_defense",
            severity: "high"
          },
          {
            id: "NET-SUR-01",
            platform: "linux",
            family: "network",
            description: "Suricata custom rule file must be loaded with at least six rules.",
            check_type: "json_field_gte",
            check_target: "capstone/network/suricata_rule_count.json:rule_count",
            expected_value: 6,
            source_project: "2x04_perimeter_defense",
            severity: "high"
          },
          {
            id: "NET-SUR-02",
            platform: "linux",
            family: "network",
            description: "Suricata rule validation report must show every rule fired against its target PCAP.",
            check_type: "json_field_equals",
            check_target: "capstone/network/suricata_validation_report.json:all_rules_fired",
            expected_value: true,
            source_project: "2x04_perimeter_defense",
            severity: "medium"
          },
          {
            id: "NET-DNS-01",
            platform: "both",
            family: "network",
            description: "DNS filter must be active.",
            check_type: "json_field_equals",
            check_target: "capstone/network/dns_filter_status.json:active",
            expected_value: true,
            source_project: "2x04_perimeter_defense",
            severity: "high"
          },

        # ── Handoff controls ───────────────────────────────────────
          {
            id: "HDF-CMP-01",
            platform: "both",
            family: "handoff",
            description: "compliance.json must be present.",
            check_type: "file_exists",
            check_target: "capstone/compliance.json",
            expected_value: "exists",
            source_project: "2x05_defensible_endpoint",
            severity: "critical"
          },
          {
            id: "HDF-MAN-01",
            platform: "both",
            family: "handoff",
            description: "manifest.json must be present with SHA-256 per file.",
            check_type: "file_exists",
            check_target: "capstone/manifest.json",
            expected_value: "exists",
            source_project: "2x05_defensible_endpoint",
            severity: "critical"
          },
          {
            id: "HDF-TEL-01",
            platform: "both",
            family: "handoff",
            description: "Telemetry export package must exist and be tarballed.",
            check_type: "file_exists",
            check_target: "capstone/exports/telemetry_export.tar.gz",
            expected_value: "exists",
            source_project: "2x02_eyes_on_endpoint",
            severity: "high"
          },
          {
            id: "HDF-RUN-01",
            platform: "both",
            family: "handoff",
            description: "Runbook script must be present and executable.",
            check_type: "file_exists",
            check_target: "capstone/runbook.sh",
            expected_value: "executable",
            source_project: "2x05_defensible_endpoint",
            severity: "critical"
          }
        ]

        # ── Assemble the final document ───────────────────────────
        | {
            schema_version: "1.0",
            generated_at: $ts,
            controls: .
          }
        '

    )

    if ! echo "$controls_json" | jq '.' > "$TARGET_FILE" 2>/dev/null; then
        log_error "Failed to write valid JSON to $TARGET_FILE"
        exit 1
    fi

    local control_count
    control_count="$(jq '.controls | length' "$TARGET_FILE")"

    log_info "Target state written: $TARGET_FILE"
    log_info "Controls declared: $control_count"
    log_info "Record hash: $(sha256sum "$TARGET_FILE" | cut -d' ' -f1)"
}

main() {
    log_info "Starting capstone target state definition..."
    log_info "Timestamp: $TIMESTAMP"

    validate_environment
    ensure_directories
    check_force_flag "${1:-}"
    emit_controls

    log_info "Capstone target state definition completed successfully"
    exit 0
}

main "$@"
