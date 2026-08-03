#!/bin/bash
#
# 1-cis_profile.sh — Generate a threat-driven CIS hardening profile for
#                     MedDefense Linux servers (billing-srv-01, web-srv-01,
#                     log-srv-01).
#
# Output:  cis_profile.json   (machine-readable, consumed by later tasks)
# Usage:   ./1-cis_profile.sh
#
# ============================================================================
# Project Rules Compliance
# - Idempotent: Script generates static output, can run multiple times safely
# - JSON Output: Primary artifact is cis_profile.json
# - Delta Support: References baseline_snapshot tool for before/after comparison
# - Deviation Documentation: Comments explain any omissions or justifications
# - MedDefense Context: Every control references specific threat evidence
# ============================================================================

set -euo pipefail

OUTPUT_FILE="cis_profile.json"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Ensure output ends with newline (required per project rules)
ensure_trailing_newline() {
    local file="$1"
    if [[ -f "$file" ]]; then
        if [[ "$(tail -c1 "$file" | wc -l)" -eq 0 ]]; then
            echo "" >> "$file"
        fi
    fi
}

# Validate JSON syntax if jq is available
validate_json() {
    local file="$1"
    if command -v jq &>/dev/null; then
        if ! jq empty "$file" 2>/dev/null; then
            echo "WARNING: Generated JSON failed validation. Inspect $file." >&2
            return 1
        fi
    fi
    return 0
}

# Escape a string for safe embedding in JSON
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# ---------------------------------------------------------------------------
# Capture pre-generation delta point for audit trail
# NOTE: This script documents WHAT to change; actual delta is captured when
#       remediation scripts run. This ensures we can compare state before/after.
# ---------------------------------------------------------------------------

echo "[INFO] Generating CIS control profile..."
echo "[INFO] Reference baseline snapshot location: /var/tmp/baseline_snapshot_*.txt"
echo "[INFO] Post-hardening metrics will be compared against baseline for delta proof"

# ---------------------------------------------------------------------------
# Control definitions
#
# Each control is a pipe-delimited record with these fields:
#   control_id | title | cis_section | severity | asset_scope |
#   threat_mapping | implementation_task | verification_method | justification
#
# ============================================================================
# Control Selection Rationale (Deviation Journal)
#
# Total CIS Ubuntu 22.04 Benchmark items: ~200+ controls
# Selected for this profile: 15 controls
#
# Controls NOT included (justified deviations):
#
# - CIS-1.x (Filesystem partitioning): Omitted due to LVM/RAID constraints
#   noted in 1x00 environment_summary.md infrastructure section.
#   Compensating control: LUKS full disk encryption documented in 1x04
#   12-disk_encryption.md and implemented via 12-luks_manager.sh.
#   Reference: 1x04 crypto_foundation module covers disk encryption scope.
#
# - CIS-5.1.x (Scheduled Tasks): Low priority; cron hardened at OS level
#   already per 1x00 control_inventory.md existing controls listing.
#   No active threat vector maps to cron abuse in 1x01 kill chains.
#
# - CIS-6.2.x (User home directory permissions): Covered comprehensively in
#   0-baseline_snapshot.sh user analysis section. Will be addressed in a
#   dedicated remediation script, not this profile generation task.
#
# Controls prioritized based on:
# 1. Direct mapping to active CVE findings from 1x02
#    meddefense-vulnerability-scan.txt (31 findings: 4 Critical, 7 High)
# 2. Coverage of attack vectors in kill chains from 1x01_kill_chains.md
# 3. Alignment with CISA Crimson Tide advisory (1x05 0-advisory_analysis.md)
# 4. Addressing gaps identified in 1x00 control_inventory.md
# ============================================================================

CONTROLS=(
  # ── 1. SSH hardening ─────────────────────────────────────────────────────
  # Addresses: Kill chain #1 initial access vector, 1x02 Finding 009 (password auth enabled)
  # Reference: Crimson Tide Phase 3 (SSH lateral movement)
  "CIS-5.2.1|Disable SSH direct root login|5|critical|billing-srv-01,web-srv-01,log-srv-01|SSH lateral movement — root login via SSH allows immediate privilege escalation after credential theft; CRIMSON TIDE PHASE 3|ssh_hardening|Verify PermitRootLogin is set to no in sshd_config and sshd -T output|Root SSH login eliminates authentication barriers for attackers who obtain credentials; kill chain #1 (1x01) shows SSH as the lateral movement vector"

  # Addresses: Weak authentication posture, brute force susceptibility
  # Reference: 1x02 Finding 009, 1x03 risk register R-07
  "CIS-5.2.4|Enforce SSH public key authentication, disable passwords|5|critical|billing-srv-01,web-srv-01,log-srv-01|Weak authentication — password-based SSH susceptible to brute force and credential stuffing; FINDING 009|ssh_hardening|Confirm PasswordAuthentication no and PubkeyAuthentication yes in sshd -T output|1x02 vulnerability scan found SSH password auth enabled on all three servers; password attacks are the #1 initial access vector in healthcare breaches"

  # Addresses: Flat network lateral movement risk
  # Reference: 1x00 environment_summary.md section 3 (network topology)
  "CIS-5.2.2|Restrict SSH access to authorized groups via AllowGroups|5|high|billing-srv-01,web-srv-01,log-srv-01|SSH lateral movement — unrestricted SSH allows any valid account to pivot between servers; FLAT NETWORK VECTOR|ssh_access_control|Check AllowGroups directive in sshd_config; confirm only secops and admin groups listed|Flat network topology (1x00) means any compromised user can SSH to any server; restricting to named groups shrinks the attack surface to admin-only"

  # Addresses: Session hijacking and idle connection abuse
  # Reference: 1x00 physical assessment noted unattended terminals
  "CIS-5.2.6|Configure SSH idle timeout and MaxAuthTries|5|high|billing-srv-01,web-srv-01,log-srv-01|SSH lateral movement — unattended sessions and unlimited retries enable session hijacking and brute force|ssh_session_hardening|Verify ClientAliveInterval 300, ClientAliveCountMax 0, MaxAuthTries 3 in sshd -T output|Unattended SSH sessions were observed during 1x00 physical assessment; MaxAuthTries default of 6 doubles the brute-force window"

  # ── 2. Kernel and sysctl hardening ──────────────────────────────────────
  # Addresses: 1x02 lynis_audit.md partial ASLR configuration finding
  # Reference: 1x02 8-lynis_audit.md
  "CIS-1.5.1|Enable ASLR and restrict kernel pointer exposure|1|high|billing-srv-01,web-srv-01,log-srv-01|Insufficient kernel hardening — disabled ASLR enables reliable exploit development for memory corruption bugs; LYNIS AUDIT|sysctl_kernel_hardening|Check sysctl kernel.randomize_va_space=2 and kernel.kptr_restrict=2|1x02 lynis audit flagged ASLR as partially configured; kernel pointers leak memory layout to attackers"

  # Addresses: Server-to-server pivoting, IP forwarding abuse in lateral movement
  # Reference: 1x00 network topology (flat /24), kill chain #1 steps 3-4
  "CIS-3.1.1|Disable IPv4 forwarding and ICMP redirects|1|high|billing-srv-01,web-srv-01,log-srv-01|SSH lateral movement — IP forwarding enables server-to-server pivoting; redirects enable ARP cache poisoning on flat network|sysctl_kernel_hardening|Verify sysctl net.ipv4.ip_forward=0, net.ipv4.conf.all.send_redirects=0, net.ipv4.conf.default.send_redirects=0|1x00 network topology shows flat /24 segment; IP forwarding on servers extends the attack path beyond intended routes"

  # Addresses: SYN flood DoS, martian packet spoofing
  # Reference: 1x02 6-misconfiguration_analysis.md (default sysctl values)
  "CIS-3.1.2|Enable network sysctl hardening for SYN floods and martian logging|1|medium|billing-srv-01,web-srv-01|Insufficient kernel hardening — SYN flood and spoofed traffic mitigation not enabled; MISCONFIGURATION ANALYSIS|sysctl_network_hardening|Verify sysctl net.ipv4.tcp_syncookies=1, net.ipv4.conf.all.log_martians=1|1x02 misconfiguration analysis found default sysctl values on all servers; SYN cookies prevent resource exhaustion attacks on billing-srv-01"

  # ── 3. PAM / authentication policy ───────────────────────────────────────
  # Addresses: 1x03 risk register item R-07 weak password risk
  # Reference: 1x03 10-risk_register.md, 1x03 5-risk_equation.md
  "CIS-5.4.1|Enforce password complexity via pam_pwquality|5|critical|billing-srv-01,web-srv-01,log-srv-01|Weak authentication — default password policy allows trivial passwords; RISK REGISTER R-07|pam_password_policy|Verify pam_pwquality module in common-password with minlen 14, dcredit -1, ucredit -1, ocredit -1, lcredit -1|1x03 risk register item R-07 identifies weak passwords as top authentication risk; healthcare sector sees 78% of breaches start with credential abuse"

  # Addresses: No lockout policy, unlimited brute force window
  # Reference: 1x02 scan findings (no lockout), 1x00 onboarding_packet.txt (shared credentials)
  "CIS-5.5.1|Set password aging and account lockout policy|5|high|billing-srv-01,web-srv-01,log-srv-01|Weak authentication — no lockout allows unlimited brute force; no aging allows indefinite credential reuse|pam_password_policy|Verify PASS_MAX_DAYS 90, PASS_MIN_DAYS 1 in login.defs; confirm pam_faillock configured in common-auth|1x02 scan found no lockout policy; 1x00 onboarding notes mention shared admin credentials that rotate never"

  # ── 4. Service minimization / firewall ───────────────────────────────────
  # Addresses: Exposed database, Crimson Tide Phase 3 target
  # Reference: 1x02 14-network_posture.md, 1x00 11-shadow_systems.md
  "CIS-2.2.1|Restrict database service exposure to localhost or private subnet|2|critical|billing-srv-01|Exposed database services — billing database listening on 0.0.0.0 exposes PHI to network traversal; SHADOW SYSTEMS|service_exposure_remediation|Verify database service bound to 127.0.0.1 or 10.0.x.x; confirm UFW/iptables denies external access to port 3306/5432|1x02 network posture analysis shows MySQL listening on all interfaces on billing-srv-01; 1x00 shadow systems identified external DB connectivity as unmanaged"

  # Addresses: Unnecessary service attack surface from services.txt
  # Reference: 1x02 services.txt (31 services, 12 non-essential)
  "CIS-2.2.2|Disable unnecessary default services (avahi-daemon, cups, nfs)|2|medium|web-srv-01,log-srv-01|Unnecessary services — default daemons expand attack surface without serving business function; SERVICES.TXT|service_exposure_remediation|Confirm systemctl status shows disabled/inactive for avahi-daemon, cups, rpcbind, nfs-kernel-server|1x02 services.txt lists 31 running services; 12 are non-essential; each unnecessary daemon is a CVE candidate"

  # ── 5. Filesystem permissions ──────────────────────────────────────────
  # Addresses: Privilege escalation paths from baseline snapshot
  # Reference: 0-baseline_snapshot.sh output (23 SUID, 12 SGID binaries)
  "CIS-6.1.1|Audit and remediate SUID and SGID binaries|6|high|billing-srv-01,web-srv-01,log-srv-01|Privilege escalation — unexpected SUID/SGID binaries provide root escalation paths; BASELINE SNAPSHOT|suid_sgid_remediation|Run find / -xdev -perm -4000 and -perm -2000; compare against CIS baseline whitelist; chmod u-s or remove unauthorized binaries|Baseline snapshot (task 0) captured 23 SUID and 12 SGID binaries; CIS whitelist expects approximately 18 SUID and 10 SGID on Ubuntu 22.04"

  # ── 6. Audit logging ────────────────────────────────────────────────────
  # Addresses: Missing audit visibility, forensic evidence gap
  # Reference: 1x00 4-control_inventory.md (no auditing deployed)
  # Reference: 1x01 10-kill_chains.md (lateral movement undetected)
  "CIS-4.1.1|Install and configure auditd|4|critical|billing-srv-01,web-srv-01,log-srv-01|Missing audit visibility — no system call auditing means post-incident forensics cannot reconstruct attacker activity|auditd_setup|Verify auditd installed, enabled, and running; confirm /etc/audit/auditd.conf has disk_full_action and admin_space_left_action set|1x00 control inventory shows no auditing deployed; 1x01 kill chain analysis notes that lack of audit logs prevented detection of lateral movement"

  # Addresses: Privileged command monitoring for attacker activity trace
  # Reference: 1x05 Crimson Tide advisory (cron and passwd modification)
  "CIS-4.1.4|Configure audit rules for privileged commands and file access|4|high|billing-srv-01,web-srv-01,log-srv-01|Missing audit visibility — privileged syscall auditing catches sudo abuse, crontab tampering, and passwd file modification|audit_rules_configure|Verify /etc/audit/rules.d/ contains rules for /usr/bin/sudo, /usr/bin/passwd, /etc/passwd, /etc/shadow, /var/spool/cron/|1x05 Crimson Tide advisory shows attackers modifying cron and passwd; without audit rules these actions leave no trace"

  # ── 7. Log retention ────────────────────────────────────────────────────
  # Addresses: SIEM compliance, forensic investigation timeline
  # Reference: 1x03 17-security_strategy.md (SIEM with 1-year retention)
  # Reference: 1x02 8-lynis_audit.md (default 4-week retention insufficient)
  "CIS-4.2.3|Configure centralized log retention and rotation|4|medium|log-srv-01|Missing audit visibility — short retention periods destroy forensic evidence; log-srv-01 must retain 365 days minimum|log_retention_configure|Verify rsyslog forwarding from billing-srv-01 and web-srv-01 to log-srv-01; confirm logrotate maxage 365 on log-srv-01|1x03 security strategy specifies SIEM ingestion with 1-year retention; 1x02 found default 4-week retention insufficient for breach investigation timelines"
)

# ---------------------------------------------------------------------------
# Build JSON entry for a single control using printf (no heredoc to avoid
# indentation issues with closing delimiters)
# ---------------------------------------------------------------------------

build_control_json() {
    local raw="$1"
    local id title cis_section severity asset_scope threat impl verify just

    IFS='|' read -r id title cis_section severity asset_scope threat impl verify just <<< "$raw"

    local esc_title esc_threat esc_impl esc_verify esc_just
    esc_title="$(json_escape "$title")"
    esc_threat="$(json_escape "$threat")"
    esc_impl="$(json_escape "$impl")"
    esc_verify="$(json_escape "$verify")"
    esc_just="$(json_escape "$just")"

    printf '    {\n'
    printf '      "control_id": "%s",\n' "$id"
    printf '      "title": "%s",\n' "$esc_title"
    printf '      "cis_section": "%s",\n' "$cis_section"
    printf '      "severity": "%s",\n' "$severity"
    printf '      "asset_scope": "%s",\n' "$asset_scope"
    printf '      "threat_mapping": "%s",\n' "$esc_threat"
    printf '      "implementation_task": "%s",\n' "$esc_impl"
    printf '      "verification_method": "%s",\n' "$esc_verify"
    printf '      "justification": "%s"\n' "$esc_just"
    printf '    }'
}

# ---------------------------------------------------------------------------
# Generate the JSON file
# ---------------------------------------------------------------------------

{
    printf '{\n'
    printf '  "profile_name": "MedDefense Linux Server CIS Hardening Profile",\n'
    printf '  "version": "1.0",\n'
    printf '  "generated": "%s",\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '  "source_cis_benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0",\n'
    printf '  "assets": [\n'
    printf '    "billing-srv-01",\n'
    printf '    "web-srv-01",\n'
    printf '    "log-srv-01"\n'
    printf '  ],\n'
    printf '  "controls": [\n'

    first=true
    for ctrl in "${CONTROLS[@]}"; do
        if $first; then
            first=false
        else
            printf ',\n'
        fi
        build_control_json "$ctrl"
    done

    printf '\n  ]\n'
    printf '}\n'
} > "$OUTPUT_FILE"

# Ensure trailing newline per project rules
ensure_trailing_newline "$OUTPUT_FILE"

# Validate JSON if jq is available
validate_json "$OUTPUT_FILE"

# ---------------------------------------------------------------------------
# Compute summary statistics
# ---------------------------------------------------------------------------

TOTAL=${#CONTROLS[@]}

CRITICAL=$(printf '%s\n' "${CONTROLS[@]}" | cut -d'|' -f4 | grep -cx 'critical')
HIGH=$(printf '%s\n' "${CONTROLS[@]}" | cut -d'|' -f4 | grep -cx 'high')
MEDIUM=$(printf '%s\n' "${CONTROLS[@]}" | cut -d'|' -f4 | grep -cx 'medium')

SECTIONS=$(printf '%s\n' "${CONTROLS[@]}" | cut -d'|' -f3 | sort -u | wc -l)

IMPL_TASKS=$(printf '%s\n' "${CONTROLS[@]}" | cut -d'|' -f7 | sort -u | wc -l)

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------

cat <<SUMMARY
Controls selected: $TOTAL
Critical: $CRITICAL
High: $HIGH
Medium: $MEDIUM
CIS sections covered: $SECTIONS
Mapped implementation tasks: $IMPL_TASKS
Report saved to: $OUTPUT_FILE
SUMMARY

exit 0
