#!/usr/bin/env bash
#
# 0-baseline_snapshot.sh — Capture the complete security baseline of a Linux system
#
# Usage:  sudo ./0-baseline_snapshot.sh
#
# Produces:
#   - stdout summary (one-liner per category with counts)
#   - Detailed report at /var/tmp/baseline_snapshot_<timestamp>.txt
#
# ============================================================================

set -euo pipefail

# ------------------------------------------------------------------
# Pre-flight checks
# ------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT="/var/tmp/baseline_snapshot_${TIMESTAMP}.txt"

# ------------------------------------------------------------------
# Helper: write a section banner to the report file
# ------------------------------------------------------------------
banner() {
    local title="$1"
    printf '\n=%.0s' {1..78} >> "$REPORT"
    printf '\n%s\n' "$title" >> "$REPORT"
    printf '=%.0s' {1..78} >> "$REPORT"
    printf '\n' >> "$REPORT"
}

# ------------------------------------------------------------------
# Initialise report
# ------------------------------------------------------------------
{
    echo "Security Baseline Snapshot"
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "Report file: $REPORT"
} > "$REPORT"

# ==================================================================
# 1. System Identification
# ==================================================================
banner "1. SYSTEM IDENTIFICATION"

HOSTNAME_VAL="$(hostname)"

# OS — try /etc/os-release first (works on most modern distros)
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_PRETTY="${PRETTY_NAME:-unknown}"
else
    OS_PRETTY="unknown (/etc/os-release not found)"
fi

KERNEL_VAL="$(uname -r)"
UPTIME_VAL="$(uptime -p 2>/dev/null || uptime)"

{
    echo "Hostname : $HOSTNAME_VAL"
    echo "OS       : $OS_PRETTY"
    echo "Kernel   : $KERNEL_VAL"
    echo "Uptime   : $UPTIME_VAL"
    echo "Arch     : $(uname -m)"
    echo "Date     : $(date)"
} >> "$REPORT"

# ==================================================================
# 2. Running Services and Their State
# ==================================================================
banner "2. RUNNING SERVICES"

# Use systemctl if available (systemd), otherwise fall back to service(8)
if command -v systemctl &>/dev/null && systemctl list-units &>/dev/null 2>&1; then
    systemctl list-units --type=service --all --no-pager --no-legend \
        | awk '{print $1, $3, $4}' >> "$REPORT" 2>&1
    SVC_COUNT=$(systemctl list-units --type=service --state=running \
                --no-pager --no-legend 2>/dev/null | wc -l)
else
    # Non-systemd fallback
    service --status-all 2>/dev/null >> "$REPORT" || echo "(service command unavailable)" >> "$REPORT"
    SVC_COUNT=$(service --status-all 2>/dev/null | grep -c '\[ + \]' || echo 0)
fi

echo "Running services captured." >> "$REPORT"

# ==================================================================
# 3. Open Ports and Listening Sockets
# ==================================================================
banner "3. OPEN PORTS AND LISTENING SOCKETS"

if command -v ss &>/dev/null; then
    ss -tulnp >> "$REPORT" 2>&1
    PORT_COUNT=$(ss -tulnH 2>/dev/null | wc -l)
elif command -v netstat &>/dev/null; then
    netstat -tulnp >> "$REPORT" 2>&1
    PORT_COUNT=$(netstat -tulnH 2>/dev/null | wc -l)
else
    echo "(Neither ss nor netstat available)" >> "$REPORT"
    PORT_COUNT=0
fi

echo "Listening sockets captured." >> "$REPORT"

# ==================================================================
# 4. SUID Binaries
# ==================================================================
banner "4. SUID BINARIES"

# find SUID files (numeric-permission test: 4000 bit set)
mapfile -t SUID_LIST < <(find / -xdev -type f -perm -4000 -exec ls -l {} \; 2>/dev/null \
                         || true)
printf '%s\n' "${SUID_LIST[@]}" >> "$REPORT"
SUID_COUNT=${#SUID_LIST[@]}

# ==================================================================
# 5. SGID Binaries
# ==================================================================
banner "5. SGID BINARIES"

mapfile -t SGID_LIST < <(find / -xdev -type f -perm -2000 -exec ls -l {} \; 2>/dev/null \
                         || true)
printf '%s\n' "${SGID_LIST[@]}" >> "$REPORT"
SGID_COUNT=${#SGID_LIST[@]}

# ==================================================================
# 6. World-Writable Files (excluding /proc, /sys, /dev)
# ==================================================================
banner "6. WORLD-WRITABLE FILES"

mapfile -t WW_LIST < <(
    find / -xdev -type f -perm -0002 \
        ! -path '/proc/*' \
        ! -path '/sys/*' \
        ! -path '/dev/*' \
        -exec ls -l {} \; 2>/dev/null \
    || true
)
printf '%s\n' "${WW_LIST[@]}" >> "$REPORT"
WW_COUNT=${#WW_LIST[@]}

# ==================================================================
# 7. Sysctl Security-Relevant Parameters
# ==================================================================
banner "7. SYSCTL SECURITY PARAMETERS"

# Curated list of security-relevant keys (will silently skip any that
# don't exist on this kernel).
SYSCTL_KEYS=(
    # --- IP networking ---
    net.ipv4.ip_forward
    net.ipv4.conf.all.send_redirects
    net.ipv4.conf.default.send_redirects
    net.ipv4.conf.all.accept_redirects
    net.ipv4.conf.default.accept_redirects
    net.ipv4.conf.all.accept_source_route
    net.ipv4.conf.default.accept_source_route
    net.ipv4.conf.all.log_martians
    net.ipv4.conf.default.log_martians
    net.ipv4.icmp_echo_ignore_broadcasts
    net.ipv4.tcp_syncookies
    net.ipv6.conf.all.accept_ra
    net.ipv6.conf.default.accept_ra
    net.ipv6.conf.all.accept_redirects
    net.ipv6.conf.default.accept_redirects
    net.ipv6.conf.all.disable_ipv6

    # --- Kernel hardening ---
    kernel.randomize_va_space
    kernel.kptr_restrict
    kernel.dmesg_restrict
    kernel.perf_event_paranoid
    kernel.yama.ptrace_scope
    kernel.exec-shield

    # --- Filesystem protections ---
    fs.suid_dumpable
    fs.protected_hardlinks
    fs.protected_symlinks
    fs.protected_fifos
    fs.protected_regular

    # --- User limits ---
    kernel.core_uses_pid
)

for key in "${SYSCTL_KEYS[@]}"; do
    val="$(sysctl -n "$key" 2>/dev/null || echo '<not available>')"
    printf '%-55s = %s\n' "$key" "$val" >> "$REPORT"
done

echo "--- Full sysctl dump follows ---" >> "$REPORT"
sysctl -a 2>/dev/null >> "$REPORT" || echo "(sysctl -a failed)" >> "$REPORT"

# ==================================================================
# 8. SSH Configuration
# ==================================================================
banner "8. SSH CONFIGURATION"

SSH_CONFIG="/etc/ssh/sshd_config"
SSHD_DIR="/etc/ssh/sshd_config.d"

if [[ -f "$SSH_CONFIG" ]]; then
    # Show the effective config: main file plus any Include'd snippets,
    # stripped of comments and blank lines.
    {
        echo "--- $SSH_CONFIG (non-comment, non-blank) ---"
        grep -vE '^\s*#|^\s*$' "$SSH_CONFIG" 2>/dev/null || echo "(empty or unreadable)"
    } >> "$REPORT"

    if [[ -d "$SSHD_DIR" ]]; then
        echo "" >> "$REPORT"
        echo "--- $SSHD_DIR/*.conf (non-comment, non-blank) ---" >> "$REPORT"
        for f in "$SSHD_DIR"/*.conf; do
            [[ -f "$f" ]] || continue
            echo ">>> $f" >> "$REPORT"
            grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null >> "$REPORT" || true
        done
    fi
else
    echo "(sshd_config not found at $SSH_CONFIG)" >> "$REPORT"
fi

# Also capture the effective runtime config if sshd supports -T
if command -v sshd &>/dev/null; then
    echo "" >> "$REPORT"
    echo "--- Effective runtime config (sshd -T) ---" >> "$REPORT"
    sshd -T 2>>"$REPORT" >> "$REPORT" || echo "(sshd -T not available or sshd not running)" >> "$REPORT"
fi

# ==================================================================
# 9. User Accounts and Sudo Group Membership
# ==================================================================
banner "9. USER ACCOUNTS AND SUDO GROUP MEMBERSHIP"

# --- Normal user accounts (UID >= 1000 on most distros) ---
{
    echo "--- Users with login shells (UID >= 1000) ---"
    awk -F: '($3 >= 1000) && ($7 !~ /(nologin|false|sync|shutdown|halt)/) {printf "  %-20s UID=%-6s shell=%s\n", $1, $3, $7}' /etc/passwd
    echo ""
    echo "--- All accounts with UID 0 (root-equivalent) ---"
    awk -F: '$3 == 0 {printf "  %-20s UID=%s\n", $1, $3}' /etc/passwd
    echo ""
    echo "--- Sudo / wheel / admin group membership ---"
    for grp in sudo wheel admin; do
        members="$(getent group "$grp" 2>/dev/null | cut -d: -f4 || true)"
        if [[ -n "$members" ]]; then
            echo "  Group '$grp': $members"
        fi
    done
    echo ""
    echo "--- Password policy (aging defaults) ---"
    if [[ -f /etc/login.defs ]]; then
        grep -E '^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD)' /etc/login.defs 2>/dev/null \
            | sed 's/^/  /'
    else
        echo "  (/etc/login.defs not found)"
    fi
} >> "$REPORT"

USER_COUNT=$(awk -F: '($3 >= 1000) && ($7 !~ /(nologin|false|sync|shutdown|halt)/)' /etc/passwd | wc -l)

# ==================================================================
# Summary — stdout
# ==================================================================

cat <<EOF

Baseline snapshot complete.
Detailed report: $REPORT

Hostname: $HOSTNAME_VAL
OS: $OS_PRETTY
Kernel: $KERNEL_VAL
Uptime: $UPTIME_VAL
Running services: $SVC_COUNT
Open ports: $PORT_COUNT
SUID binaries: $SUID_COUNT
SGID binaries: $SGID_COUNT
World-writable files: $WW_COUNT
Login-shell users: $USER_COUNT
EOF

# ==================================================================
# Exit cleanly
# ==================================================================
exit 0
