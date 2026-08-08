#!/bin/bash
#
# Name:        5-auditd_refine.sh
# Purpose:     Refine auditd configuration with detection-focused rules and validate
# Author:      Steve - Cybersecurity Engineer
# Date:        August 8, 2026
#

set -ueo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

readonly RULE_FILE="/etc/audit/rules.d/meddefense.rules"

# ── Functions ─────────────────────────────────────────────────────────────────

log_info()    { echo "[*] $*"; }
log_added()   { echo "    $* [ADDED]"; }
log_captured(){ echo "    $* [CAPTURED]"; }
log_failed()  { echo "    $* [FAILED]"; }

get_rule_count() {
    auditctl -l 2>/dev/null | wc -l
}

find_ssh_dirs() {
    local ssh_dirs=()

    if [[ -d /root/.ssh ]]; then
        ssh_dirs+=("/root/.ssh")
    fi

    while IFS= read -r -d '' dir; do
        ssh_dirs+=("$dir")
    done < <(find /home -maxdepth 2 -type d -name '.ssh' -print0 2>/dev/null)

    if [[ ${#ssh_dirs[@]} -eq 0 ]]; then
        mkdir -p /root/.ssh 2>/dev/null || true
        chmod 700 /root/.ssh 2>/dev/null || true
        ssh_dirs+=("/root/.ssh")
    fi

    printf '%s\n' "${ssh_dirs[@]}"
}

validate_rule() {
    local key="$1"
    local test_cmd="$2"

    # Count events before test
    local before
    before=$(ausearch -k "$key" 2>/dev/null | grep -c "type=" || true)

    # Run test action
    eval "$test_cmd" >/dev/null 2>&1 || true
    sleep 2

    # Count events after test
    local after
    after=$(ausearch -k "$key" 2>/dev/null | grep -c "type=" || true)

    if [[ "$after" -gt "$before" ]]; then
        return 0
    fi
    return 1
}

cleanup_test_files() {
    rm -f /etc/cron.d/test_audit_validate 2>/dev/null || true
    rm -f /etc/sudoers.d/test_audit_validate 2>/dev/null || true
    find /root/.ssh /home/*/.ssh -name 'test_audit_key' -delete 2>/dev/null || true
}

# ── MAIN ──────────────────────────────────────────────────────────────────────

main() {
    if [[ $EUID -ne 0 ]]; then
        echo "[!] This script must be run as root (sudo)"
        exit 1
    fi

    # Step 1: Count current rules
    local initial_count
    initial_count=$(get_rule_count)
    log_info "Current auditd rules: $initial_count"

    # Step 2: Discover SSH directories and write rules file
    log_info "Adding detection-focused rules..."

    local ssh_dirs
    ssh_dirs=$(find_ssh_dirs)
    local ssh_count
    ssh_count=$(echo "$ssh_dirs" | wc -l)

    # Write clean rules file
    {
        echo "# MedDefense Audit Rules - /etc/audit/rules.d/meddefense.rules"
        echo ""
        echo "# --- Identity Files ---"
        echo "-w /etc/passwd -p wa -k identity"
        echo "-w /etc/shadow -p rwa -k identity"
        echo "-w /etc/group -p wa -k identity"
        echo ""
        echo "# --- Authentication Configuration ---"
        echo "-w /etc/pam.d/ -p wa -k pam_config"
        echo ""
        echo "# --- SSH Configuration ---"
        echo "-w /etc/ssh/sshd_config -p wa -k sshd_config"
        echo ""
        echo "# --- Privilege Escalation ---"
        echo "-w /usr/bin/sudo -p x -k priv_esc"
        echo "-w /usr/bin/su -p x -k priv_esc"
        echo "-w /etc/sudoers -p wa -k sudoers"
        echo ""
        echo "# --- Suspicious Tool Execution ---"
        echo "-w /usr/bin/wget -p x -k suspicious_download"
        echo "-w /usr/bin/curl -p x -k suspicious_netcat"
        echo ""
        echo "# --- MedDefense Application Integrity ---"
        echo "-w /var/lib/mysql/ -p wa -k meddefense_db"
        echo "-w /etc/apache2/ -p wa -k meddefense_web"
        echo "-w /etc/init.d/ -p wa -k startup_scripts"
        echo ""
        echo "# --- Kernel Security ---"
        echo "-w /etc/sysctl.conf -p wa -k kernel_config"
        echo "-w /sbin/modprobe -p x -k kernel_modules"
        echo ""
        echo "# --- System Call Auditing ---"
        echo "-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc_syscall"
        echo "-a always,exit -F arch=b64 -S ptrace -k process_injection"
        echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -k file_deletion"
        echo ""
        echo "# --- Detection-Focused Rules (added by 5-auditd_refine.sh) ---"
        echo ""
        echo "# Process execution via execve"
        echo "-a always,exit -F arch=b64 -S execve -k process_exec"
        echo "-a always,exit -F arch=b32 -S execve -k process_exec"
        echo ""
        echo "# Network socket creation"
        echo "-a always,exit -F arch=b64 -S socket -S connect -k network_connect"
        echo "-a always,exit -F arch=b32 -S socket -S connect -k network_connect"
        echo ""
        echo "# SSH key file access (${ssh_count} directory/directories discovered)"
        while IFS= read -r dir; do
            echo "-w ${dir}/ -p rwa -k ssh_keys"
        done <<< "$ssh_dirs"
        echo ""
        echo "# Cron directory modifications"
        echo "-w /etc/cron.d/ -p wa -k cron_persist"
        echo "-w /var/spool/cron/ -p wa -k cron_persist"
        echo ""
        echo "# Sudo configuration access"
        echo "-w /etc/sudoers.d/ -p wa -k sudoers"
    } > "$RULE_FILE"

    log_added "execve syscall tracking"
    log_added "socket/connect syscall tracking"
    echo "    SSH key file monitoring (${ssh_count} dir(s): $(echo "$ssh_dirs" | tr '\n' ' '))"
    log_added "Cron directory monitoring"
    log_added "sudoers.d monitoring"

    # Step 3: Load rules with augenrules (NOT service restart)
    log_info "Loading rules..."
    augenrules --load 2>&1 | tail -1
    echo "    augenrules --load: OK"

    # Step 4: Count total rules
    local final_count
    final_count=$(get_rule_count)
    log_info "Total rules: $final_count"

    # Step 5: Validate each new rule fires
    log_info "Validating new rules..."
    local validated=0
    local passed=0

    # Validate execve
    validated=$((validated + 1))
    if validate_rule "process_exec" "/usr/bin/id"; then
        log_captured "execve: ran /usr/bin/id -> ausearch -k process_exec"
        passed=$((passed + 1))
    else
        log_failed "execve: did not capture test event"
    fi

    # Validate socket/connect
    validated=$((validated + 1))
    if validate_rule "network_connect" "curl -s -o /dev/null http://127.0.0.1:80 2>/dev/null; true"; then
        log_captured "socket: curl localhost -> ausearch -k network_connect"
        passed=$((passed + 1))
    else
        log_failed "socket: did not capture test event"
    fi

    # Validate ssh_keys
    validated=$((validated + 1))
    local test_ssh_dir
    test_ssh_dir=$(echo "$ssh_dirs" | head -1)
    if validate_rule "ssh_keys" "touch ${test_ssh_dir}/test_audit_key && rm -f ${test_ssh_dir}/test_audit_key"; then
        log_captured "ssh_keys: touch ${test_ssh_dir}/test -> ausearch -k ssh_keys"
        passed=$((passed + 1))
    else
        log_failed "ssh_keys: did not capture test event"
    fi

    # Validate cron_persist
    validated=$((validated + 1))
    if validate_rule "cron_persist" "touch /etc/cron.d/test_audit_validate && rm -f /etc/cron.d/test_audit_validate"; then
        log_captured "cron: touch /etc/cron.d/test -> ausearch -k cron_persist"
        passed=$((passed + 1))
    else
        log_failed "cron: did not capture test event"
    fi

    # Validate sudoers
    validated=$((validated + 1))
    if validate_rule "sudoers" "touch /etc/sudoers.d/test_audit_validate && rm -f /etc/sudoers.d/test_audit_validate"; then
        log_captured "sudoers: touch /etc/sudoers.d/test -> ausearch -k sudoers"
        passed=$((passed + 1))
    else
        log_failed "sudoers: did not capture test event"
    fi

    cleanup_test_files

    echo "Rules added: 5 | Validation: $passed/$validated PASS"

    if [[ $passed -lt $validated ]]; then
        exit 1
    fi
}

main "$@"
