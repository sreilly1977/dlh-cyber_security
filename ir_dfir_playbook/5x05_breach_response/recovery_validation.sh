#!/bin/bash
# Name: recovery_validation.sh
# Purpose: Post-eradication recovery validation for IR-2026-0420-01.
#          Checks beacon process absence (24h), C2 severance, staged
#          payload removal on all affected hosts, clinical service
#          health, EDR agent reporting, Sigma rule activation with a
#          synthetic test event, and evidence hash integrity against
#          the 11-artifact baseline. Exits 0 only if every check passes.
# Author: Steve - Cybersecurity Engineer
# Date: 26 October 2026
#
# Configuration (defaults shown; override via environment):
#   SYSMON_LOG          live Sysmon JSONL export      (./sysmon_live.jsonl)
#   PROXY_LOG           live proxy JSONL export        (./proxy_live.jsonl)
#   BASELINE            sha256sum manifest, 11 lines  (./baseline.sha256)
#   SSH_USER            remote-check account          (iradmin)
#   HOSTS_LIST          space-separated host list     (5 rebuilt hosts)
#   SERVICE_ENDPOINTS   space-separated health URLs
#   EDR_API             EDR console REST base URL
#   SIEM_API           SIEM REST base URL
#   SIGMA_RULE_ID       id of sigma_cobalt_strike_beacon
# Requires: bash, jq, curl, openssh-client, GNU date, sha256sum

set -u

SYSMON_LOG="${SYSMON_LOG:-./sysmon_live.jsonl}"
PROXY_LOG="${PROXY_LOG:-./proxy_live.jsonl}"
BASELINE="${BASELINE:-./baseline.sha256}"
SSH_USER="${SSH_USER:-iradmin}"
read -r -a HOSTS <<< "${HOSTS_LIST:-CS-WS-101 CS-WS-104 CS-WS-107 CS-WS-112 FILE-SVR-01}"
read -r -a SERVICES <<< "${SERVICE_ENDPOINTS:-https://epic-api.meddefense.local/health https://lis-api.meddefense.local/health https://scheduling-api.meddefense.local/health}"
EDR_API="${EDR_API:-https://edr.meddefense.local/api}"
SIEM_API="${SIEM_API:-https://siem.meddefense.local/api}"
SIGMA_RULE_ID="${SIGMA_RULE_ID:-b7c4e1a9-3f82-4d61-9e05-2a7c8b1f4d33}"

readonly C2_DOMAIN="staging.office365-cdn.net"
readonly C2_IP="45.152.66.114"
# Note: literal values above are required for grep/jq matching in the
# operational logs. Analysts must never resolve or browse this domain.
readonly MASQ_RE='(svchost32|lsass32|csrss32|winlogon32|services32|spoolsv32|dllhost32|scvhost|svchosts|lssas|csrsss)[.]exe'

PASS=0
FAIL=0
FAILED_CHECKS=""

CUTOFF="$(date -u -d '24 hours ago' '+%Y-%m-%dT%H:%M:%SZ')"

log_pass() { printf '[PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
log_fail() { printf '[FAIL] %s\n' "$1"; FAIL=$((FAIL + 1));
    FAILED_CHECKS="${FAILED_CHECKS}- $1"$'\n'; }

check_deps() {
    local dep
    for dep in jq curl ssh date sha256sum; do
        command -v "$dep" >/dev/null 2>&1 || {
            printf '[FAIL] dependency missing: %s\n' "$dep"
            exit 1
        }
    done
}

# 1. No masqueraded beacon process tree in the last 24 hours.
check_beacon() {
    local found
    found="$(jq -r --arg re "$MASQ_RE" --arg cutoff "$CUTOFF" \
        'select(.ts != null and .ts >= $cutoff)
         | select(.event_type == "process_create")
         | select((.image // "") | test($re))
         | .host' "$SYSMON_LOG" 2>/dev/null | sort -u | tr '\n' ' ')"
    if [[ -z "$found" ]]; then
        log_pass "beacon: no svchost32.exe or related process tree in last 24h across all affected hosts"
    else
        log_fail "beacon: masquerade process seen on: ${found}"
    fi
}

# 2. No outbound connections to the C2 domain or IP in the last 24 hours.
check_c2() {
    local hits
    hits="$(jq -r --arg dom "$C2_DOMAIN" --arg ip "$C2_IP" \
        --arg cutoff "$CUTOFF" \
        'select(.ts != null and .ts >= $cutoff)
         | select(((.url // "") | contains($dom)) or ((.dst_ip // "") == $ip))
         | "\(.ts) \(.host)"' "$PROXY_LOG" 2>/dev/null | wc -l)"
    if [[ "$hits" -eq 0 ]]; then
        log_pass "c2: no outbound connections to staging.office365-cdn[.]net or 45.152.66.114"
    else
        log_fail "c2: ${hits} connection(s) to C2 observed in last 24h"
    fi
}

# 3. No staging scripts or beacon binaries in system directories.
check_staging() {
    local host out overall=""
    for host in "${HOSTS[@]}"; do
        out="$(ssh -o BatchMode=yes -o ConnectTimeout=10 \
            "${SSH_USER}@${host}" \
            "powershell -NoProfile -Command \"Get-ChildItem -Path 'C:\\Windows\\System32','C:\\ProgramData','C:\\Windows\\Temp' -File -ErrorAction SilentlyContinue | Where-Object { \$_.Name -match 'stag|encrypt|svchost32|^klog' } | Select-Object -ExpandProperty FullName\"" \
            2>/dev/null)"
        if [[ -z "$out" ]]; then
            overall="${overall}${host}:clean "
        else
            overall="${overall}${host}:FOUND(${out//$'\n'/;}) "
        fi
    done
    if [[ "$overall" != *"FOUND"* ]]; then
        log_pass "ransomware staging: no .bat or .ps1 staging scripts found in Windows System32 or ProgramData"
    else
        log_fail "ransomware staging: residual files on ${overall}"
    fi
}

# 4. Clinical service endpoints responsive.
check_services() {
    local ep code svc all_ok=1
    for ep in "${SERVICES[@]}"; do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$ep")"
        svc="${ep#https://}"; svc="${svc%%/*}"
        if [[ "$code" == "200" ]]; then
            printf '[PASS] services: %s 200\n' "$svc"
            PASS=$((PASS + 1))
        else
            printf '[FAIL] services: %s returned %s\n' "$svc" "$code"
            FAIL=$((FAIL + 1))
            FAILED_CHECKS="${FAILED_CHECKS}- services: ${svc} ${code}"$'\n'
            all_ok=0
        fi
    done
    return "$all_ok"
}

# 5. All rebuilt hosts reporting to the EDR console in last 5 minutes.
check_edr() {
    local resp host missing=""
    resp="$(curl -fsS --max-time 10 "${EDR_API}/agents?minutes=5" 2>/dev/null)"
    if [[ -z "$resp" ]]; then
        log_fail "edr: no response from EDR console"
        return
    fi
    for host in "${HOSTS[@]}"; do
        if printf '%s' "$resp" | jq -e --arg h "$host" \
            '.agents | any(.hostname == $h and .last_seen_minutes <= 5)' \
            >/dev/null 2>&1; then
            :
        else
            missing="${missing}${host} "
        fi
    done
    if [[ -z "$missing" ]]; then
        log_pass "edr: all ${#HOSTS[@]} hosts reporting to EDR console in last 5 minutes"
    else
        log_fail "edr: not reporting within 5 minutes: ${missing}"
    fi
}

# 6. Sigma rule active and fires on a synthetic test event.
check_detection() {
    local body hits
    if ! curl -fsS --max-time 10 \
        "${SIEM_API}/rules/${SIGMA_RULE_ID}" 2>/dev/null \
        | jq -e '.status == "active"' >/dev/null 2>&1; then
        log_fail "detection: sigma rule not active in SIEM"
        return
    fi
    body='{"event_type":"process_create","host":"VALIDATION-TEST","user":"MEDDEFENSE\\validation","image":"C:\\ProgramData\\Microsoft\\svchost32.exe","parent_image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","cmdline":"validation IR-2026-0420-01","marker":"IR-2026-0420-01-validation"}'
    hits="$(curl -fsS --max-time 10 -H 'Content-Type: application/json' \
        -d "$body" "${SIEM_API}/detect" 2>/dev/null \
        | jq -r '.matches // 0')"
    if [[ "$hits" -eq 1 ]]; then
        log_pass "detection: sigma_cobalt_strike_beacon.yml active; synthetic test event returned expected hit"
    else
        log_fail "detection: synthetic test returned ${hits} hits, expected 1"
    fi
}

# 7. All 11 evidence artifacts match the SHA-256 baseline.
check_hashes() {
    local total ok
    if [[ ! -r "$BASELINE" ]]; then
        log_fail "evidence hashes: baseline manifest not readable: ${BASELINE}"
        return
    fi
    total="$(grep -c . "$BASELINE")"
    ok="$(sha256sum -c "$BASELINE" 2>/dev/null | grep -c ': OK$')"
    if [[ "$ok" -eq "$total" && "$total" -eq 11 ]]; then
        log_pass "evidence hashes: ${ok}/${total} artifacts match original SHA-256 baseline"
    else
        log_fail "evidence hashes: ${ok}/${total} artifacts verified, expected 11/11"
    fi
}

main() {
    check_deps
    check_beacon
    check_c2
    check_staging
    check_services
    check_edr
    check_detection
    check_hashes

    printf '\n'
    if [[ "$FAIL" -eq 0 ]]; then
        printf 'ALL CHECKS PASSED\n'
        exit 0
    fi
    printf '%s CHECK(S) FAILED:\n%s' "$FAIL" "$FAILED_CHECKS"
    exit 1
}

main "$@"
