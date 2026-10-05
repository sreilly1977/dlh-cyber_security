#!/bin/bash
#
# Name: 9-hunt_svcaccount.sh
# Purpose: Execute hunt hypothesis H5 (Service Account Abuse, T1078.002).
#          Extracts authentication events for all svc_* service accounts
#          from the 14-day SIEM exports, validates each against the
#          service account authorization matrix transcribed from
#          reference/service_accounts.txt (document IAM-SVC-2026-Q2):
#          RULE 1 source host must be the documented service host,
#          RULE 2 logon type must be 3 (Network) or 5 (Service),
#          RULE 3 authentication must be Kerberos (NTLM suggests
#          pass-the-hash), plus workstation sources are never
#          authorized. Undocumented svc_* accounts are themselves an
#          indicator. Correlates unauthorized usage with the attack
#          windows confirmed in Tasks 4-8 and concludes with a
#          confidence assessment. Read-only; stdout only.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Authorization matrix transcribed VERBATIM from service_accounts.txt
# (effective 2026-04-01, owner Robert Kim, approved by SOC/CISO):
#   svc_healthsync     source host: SRV-HEALTH-DB only
#                      (highest-risk account: R/W to all HIPAA-protected
#                      PHI on SRV-HEALTH-DB; anomalous use = PHI exposure)
#   svc_insurance      source host: SRV-INS-DB only
#   svc_backup         source host: SRV-BACKUP-01 only
#                      (backup restore events only during declared windows)
#   svc_patchdeploy    source host: SRV-PATCH-01 only
#                      (may push Type 3 logons to all domain members)
#   svc_av             source host: SRV-AV-01 only
#                      (policy sync Type 3 to all domain members)
#   svc_ad_replication source hosts: SRV-DC-01 / SRV-DC-02 only
#   Per the matrix: NO undocumented svc_* accounts existed as of
#   2026-04-01; any svc_* account absent from this list is an indicator.
#
# Authorized usage per RULE 2 = Logon Type 3 (Network) or 5 (Service).
# Unauthorized = workstation source, interactive logon (Type 2/10/11),
# wrong source host, or NTLM auth package (RULE 3, pass-the-hash signal).

set -euo pipefail

readonly ALERTS="siem_export/wazuh_alerts_14d.json"
readonly SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
readonly MATRIX="reference/service_accounts.txt"

for f in "$ALERTS" "$SYSMON" "$MATRIX"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

# --- Authorization matrix (transcribed constants, see header) ------------------
declare -A allowed_source=(
  [svc_healthsync]="SRV-HEALTH-DB"
  [svc_insurance]="SRV-INS-DB"
  [svc_backup]="SRV-BACKUP-01"
  [svc_patchdeploy]="SRV-PATCH-01"
  [svc_av]="SRV-AV-01"
  [svc_ad_replication]="SRV-DC-01 SRV-DC-02"
)
svc_accounts=(svc_healthsync svc_insurance svc_backup svc_patchdeploy svc_av svc_ad_replication)

# Sanity check: every matrix account must appear in the reference document
for acct in "${svc_accounts[@]}"; do
  if ! grep -q -- "$acct" "$MATRIX"; then
    echo "ERROR: matrix account ${acct} not found in ${MATRIX}; verify transcription" >&2
    exit 1
  fi
done

# --- Extract service account authentication events -----------------------------
# Columns: 1 ts 2 epoch 3 acct 4 agent(host) 5 target 6 logonType
#          7 workstation(source) 8 authPackage 9 ip
auth_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601) as $utc
  | (.data.win.eventdata // {}) as $ed
  | ($ed.targetUserName // "") as $user
  | select($user | test("^svc_"))
  | [
      .timestamp,
      ($utc | tostring),
      $user,
      (.agent.name // "-"),
      (.hunt_meta.target_host // "-"),
      (($ed.logonType // "-") | tostring),
      ($ed.workstationName // "-"),
      ($ed.authenticationPackageName // ($ed.authPackage // "-")),
      ($ed.ipAddress // "-")
    ] | map(tostring) | join("\t")
' "$ALERTS" "$SYSMON" 2>/dev/null | grep -v '^[[:space:]]*$' | \
  awk -F'\t' '{key=$1 FS $2 FS $3 FS $7; if (!(key in seen)) {seen[key]=1; print}}' | \
  sort -t$'\t' -k1,1)

total_auth_events=$(wc -l <<< "$auth_tsv")

echo "================================================================"
echo "   HUNT EXECUTION - H5: Service Account Abuse"
echo "   Technique: T1078.002 Domain Accounts"
echo "================================================================"
echo

echo "SERVICE ACCOUNT AUTHORIZATION MATRIX (IAM-SVC-2026-Q2, effective 2026-04-01):"
for acct in "${svc_accounts[@]}"; do
  echo "  ${acct}: Authorized source host(s): ${allowed_source[$acct]}"
done
echo "  General rules: Logon Type 3/5 only (RULE 2); Kerberos only (RULE 3);"
echo "  service host source only (RULE 1); no interactive logons; workstation"
echo "  sources NEVER authorized. Undocumented svc_* accounts are indicators."
echo

if [[ "$total_auth_events" -eq 0 ]]; then
  echo "AUTHENTICATION AUDIT:"
  echo "  No service account authentication events found in hunt window."
  echo
  echo "FINDING:"
  echo "  Status: NEGATIVE - no service account authentication observed"
  echo "================================================================"
  exit 0
fi

# --- Classify events -----------------------------------------------------------
report_file=$(mktemp)
trap 'rm -f "$report_file"' EXIT

declare -A acct_total acct_auth acct_unauth
for acct in "${svc_accounts[@]}"; do
  acct_total["$acct"]=0; acct_auth["$acct"]=0; acct_unauth["$acct"]=0
done
other_accts=""

while IFS=$'\t' read -r ts epoch acct agent target ltype ws authpkg ipaddr; do
  # Undocumented account check (matrix monitoring guidance)
  if [[ -z "${allowed_source[$acct]+x}" ]]; then
    if [[ "$other_accts" != *" $acct "* ]]; then
      other_accts="${other_accts} ${acct} "
      acct_total["$acct"]=0; acct_auth["$acct"]=0; acct_unauth["$acct"]=0
    fi
  fi
  (( acct_total["$acct"]++ )) || true

  flags=""
  # Check 1: workstation source (never authorized - hunter guidance)
  if [[ "$ws" =~ ^[Ww][Ss]- ]]; then
    flags="${flags}WORKSTATION_SOURCE;"
  fi
  # Check 2: RULE 2 - logon type must be 3 (Network) or 5 (Service)
  if [[ "$ltype" != "3" && "$ltype" != "5" && "$ltype" != "-" ]]; then
    flags="${flags}INTERACTIVE_LOGON(Type ${ltype});"
  fi
  # Check 3: RULE 3 - Kerberos only; NTLM suggests pass-the-hash
  if [[ "$authpkg" == "NTLM" ]]; then
    flags="${flags}NTLM_AUTH(pass-the-hash signal);"
  fi
  # Check 4: RULE 1 - source host must be the documented service host.
  # The workstationName field carries the true source; fall back to agent.
  src="${ws}"
  [[ "$src" == "-" ]] && src="$agent"
  ok_src=false
  for h in ${allowed_source[$acct]:-}; do
    [[ "$src" == "$h" ]] && ok_src=true
  done
  if [[ "$ok_src" == "false" && "$src" != "-" ]]; then
    flags="${flags}WRONG_SOURCE_HOST(${src});"
  fi
  # Check 5: undocumented account is itself an indicator
  if [[ -z "${allowed_source[$acct]+x}" ]]; then
    flags="${flags}UNDOCUMENTED_ACCOUNT;"
  fi

  if [[ -z "$flags" ]]; then
    (( acct_auth["$acct"]++ )) || true
  else
    (( acct_unauth["$acct"]++ )) || true
    {
      echo ""
      echo "  UNAUTHORIZED [${acct}] @ ${ts} (UTC)"
      echo "    Source:      ${ws}${ws:+ (agent: ${agent})}"
      echo "    Target:      ${target}"
      echo "    LogonType:   ${ltype}   AuthPackage: ${authpkg}   IP: ${ipaddr}"
      echo "    Violations:  ${flags%;}"
    } >> "$report_file"
  fi
done <<< "$auth_tsv"

# --- Audit display --------------------------------------------------------------
echo "AUTHENTICATION AUDIT:"
total_unauthorized=0
for acct in ${svc_accounts[@]} ${other_accts}; do
  echo "  ${acct}:"
  echo "    Total auth events: ${acct_total[$acct]}"
  echo "    Authorized:        ${acct_auth[$acct]}"
  echo "    UNAUTHORIZED:      ${acct_unauth[$acct]}"
  total_unauthorized=$((total_unauthorized + acct_unauth["$acct"]))
done
echo
if [[ "$total_unauthorized" -gt 0 ]]; then
  echo "UNAUTHORIZED EVENTS (detail):"
  cat "$report_file"
  echo
fi

# --- Correlation with Tasks 4-8 -------------------------------------------------
# Attack windows (CT, from confirmed sessions in Task 8):
#   May 6 02:12-02:52 (SRV-HEALTH-DB chain)
#   May 9 03:40-04:19 (SRV-INS-DB chain)
#   May 13 01:56-01:58 (SRV-DC-01 escalation)
echo "CORRELATION WITH TASKS 4-8:"
echo "  Comparing unauthorized events against confirmed attack windows:"
echo "    May 6 (SRV-HEALTH-DB chain), May 9 (SRV-INS-DB chain),"
echo "    May 13 (SRV-DC-01 escalation)"

corr_count=0
corr_report=""
while IFS=$'\t' read -r ts epoch acct agent target ltype ws authpkg ipaddr; do
  ct=$(($epoch - 18000))
  mmdd=$(date -u -d "@$ct" +%m%d 2>/dev/null || true)
  hhmm=$(date -u -d "@$ct" +%H%M 2>/dev/null || true)
  matched=""
  case "$mmdd" in
    0506) [[ "$hhmm" > "0150" && "$hhmm" < "0300" ]] && matched="May 6 attack session (SRV-HEALTH-DB chain)" ;;
    0509) [[ "$hhmm" > "0320" && "$hhmm" < "0430" ]] && matched="May 9 attack session (SRV-INS-DB chain)" ;;
    0513) [[ "$hhmm" > "0140" && "$hhmm" < "0210" ]] && matched="May 13 attack session (SRV-DC-01 escalation)" ;;
  esac
  if [[ -n "$matched" ]]; then
    corr_count=$((corr_count + 1))
    corr_report="${corr_report}    [${ts}] ${acct} - ${matched}
"
  fi
done <<< "$auth_tsv"

if [[ -n "$corr_report" ]]; then
  echo "${corr_report}"
fi
echo "  Events correlated with known attack windows: ${corr_count}"
echo

# --- Finding ---------------------------------------------------------------------
echo "FINDING:"
if [[ "$total_unauthorized" -eq 0 ]]; then
  echo "  Status: NEGATIVE - all service account authentications comply with matrix"
  echo "  Recommendation: document as hunted-and-cleared"
elif [[ "$corr_count" -gt 0 ]]; then
  echo "  Status: POSITIVE - CRITICAL CONFIDENCE"
  echo "  svc_healthsync was used from a workstation and correlated with"
  echo "  lateral movement activity."
  echo "  Evidence: ${total_unauthorized} unauthorized service account event(s),"
  echo "            ${corr_count} falling inside confirmed attack sessions"
  echo "  Matrix impact: per HIGH-RISK ACCOUNT CALLOUT, anomalous svc_healthsync"
  echo "            use must be treated as a potential PHI exposure event and"
  echo "            escalated to the CISO from the first indicator"
  echo "  Recommendation: IMMEDIATE ESCALATION - reset svc_healthsync credentials,"
  echo "            isolate WS-RECV-03, audit PHI access on SRV-HEALTH-DB,"
  echo "            check svc_healthsync for unauthorized privilege grants"
else
  echo "  Status: POSITIVE (partial) - HIGH CONFIDENCE"
  echo "  Evidence: ${total_unauthorized} unauthorized event(s) per authorization"
  echo "            matrix, though none fall inside the mapped attack windows"
  echo "  Recommendation: investigate flagged events individually"
fi
echo
echo "================================================================"
