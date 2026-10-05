#!/bin/bash
#
# Name: 2-baseline_profile.sh
# Purpose: Profile Robert Kim's legitimate administrative activity from
#          baseline/robert_kim_activity.json (Wazuh Sysmon JSONL export),
#          producing the false-positive filter for all subsequent hunts:
#          tool usage, source hosts, time-of-day (Central Time), day-of-week,
#          target hosts, user accounts, a baseline summary and anomaly
#          detection criteria. Every event is additionally validated
#          against the admin_schedule.txt work rules (Mon-Fri 08:00-18:00
#          Central, WS-ADMIN-01, MEDDEFENSE\robert.kim, authorized=true).
#          Read-only; output to stdout.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Timestamp handling: the baseline timestamps are full ISO 8601 with
# milliseconds and +00:00 offset (e.g. 2026-05-04T13:47:23.000+00:00).
# jq's fromdateiso8601 requires "YYYY-MM-DDTHH:MM:SSZ", so the
# millisecond fraction and offset are normalized to a literal "Z" before
# parsing. May 2026 falls in daylight saving time (CDT = UTC-5), so
# Central wall-clock time is derived by subtracting 18000 seconds from
# the UTC epoch before formatting. Rows are joined with join("\t")
# rather than @tsv, which would escape the backslash in domain
# account names (MEDDEFENSE\robert.kim). The account string contains
# a backslash that awk's -v interprets as an escape sequence (\r), so
# it is passed via the environment and read with ENVIRON in the
# validator, which avoids escape processing.

set -euo pipefail

readonly BASELINE="baseline/robert_kim_activity.json"
readonly SCHEDULE="reference/admin_schedule.txt"

for f in "$BASELINE" "$SCHEDULE"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

# Schedule-derived expectations (admin_schedule.txt, Q2 2026):
#   Work hours:      Mon-Fri, 08:00-18:00 Central Time
#   Primary host:    WS-ADMIN-01 (WS-ADMIN-02 = failover only, not active)
#   Account:         MEDDEFENSE\robert.kim
#   Overtime:        none approved in Q2 2026
readonly EXPECTED_SOURCE="WS-ADMIN-01"
readonly EXPECTED_USER="MEDDEFENSE\\robert.kim"
readonly BUSINESS_START=480     # 08:00 CT in minutes since midnight
readonly BUSINESS_END=1080     # 18:00 CT

# --- Normalize JSONL events to TSV --------------------------------------------
# Columns: 1 ts(UTC) 2 date(CT) 3 weekday(CT) 4 hh:mm(CT) 5 minutes(CT)
#          6 tool 7 source 8 target 9 user 10 authorization
events_tsv=$(jq -r '
  (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601) as $utc
  | ($utc - 18000) as $ct
  | [
      .timestamp,
      ($ct | strftime("%Y-%m-%d")),
      ($ct | strftime("%A")),
      ($ct | strftime("%H:%M")),
      (($ct % 86400) / 60 | floor),
      (.hunt_meta.tool // "UNKNOWN"),
      (.hunt_meta.source_host // .agent.name // "UNKNOWN"),
      (.hunt_meta.target_host // "-"),
      (.data.win.eventdata.user // "-"),
      (if (.hunt_meta.authorized // false) then "authorized" else "NOT-AUTHORIZED" end)
    ] | map(tostring) | join("\t")
' "$BASELINE")

if [[ -z "$events_tsv" ]]; then
  echo "ERROR: no events parsed from $BASELINE" >&2
  exit 1
fi
total_events=$(wc -l <<< "$events_tsv")

# Helper: count occurrences by TSV column, sorted by key.
count_by() {
  awk -F'\t' -v c="$1" '{
    n = $c; sub(/^[ \t]+/, "", n); sub(/[ \t]+$/, "", n)
    counts[n]++
  } END {
    for (k in counts) printf "%s\t%d\n", k, counts[k]
  }' <<< "$events_tsv" | sort
}

# Helper: comma-separated list of unique values in a TSV column.
list_column() {
  count_by "$1" | cut -f1 | awk 'NR==1 {s=$1} NR>1 {s=s", "$1} END {print s}'
}

echo "================================================================"
echo "   BASELINE PROFILE - Robert Kim (IT Administrator)"
echo "   Source: baseline/robert_kim_activity.json"
echo "================================================================"
echo

# --- 1. Tool usage -------------------------------------------------------------
echo "TOOL USAGE SUMMARY:"
while IFS=$'\t' read -r tool count; do
  printf '  %-12s events: %s\n' "$tool" "$count"
done < <(count_by 6)
printf '  %-12s events: %s\n' "Total" "$total_events"
echo

# --- 2. Source host analysis -----------------------------------------------------
echo "SOURCE HOSTS:"
other_sources=0
while IFS=$'\t' read -r host count; do
  printf '  %-14s events: %s\n' "$host" "$count"
  if [[ "$host" != "$EXPECTED_SOURCE" ]]; then
    other_sources=$((other_sources + 1))
  fi
done < <(count_by 7)
if [[ "$other_sources" -eq 0 ]]; then
  echo "  -> BASELINE: All admin activity originates from ${EXPECTED_SOURCE}"
else
  echo "  [!] Activity from ${other_sources} host(s) other than ${EXPECTED_SOURCE} (see validation below)"
fi
echo

# --- 3. Time-of-day distribution (Central Time) --------------------------------
in_hours=$(awk -F'\t' -v s="$BUSINESS_START" -v e="$BUSINESS_END" \
  '$5 >= s && $5 <= e' <<< "$events_tsv" | wc -l)
after_hours=$(( total_events - in_hours ))
echo "TIME DISTRIBUTION (Central Time, schedule: Mon-Fri 08:00-18:00):"
echo "  Within 08:00-18:00 CT: ${in_hours}"
echo "  Outside 08:00-18:00 CT: ${after_hours}"
if [[ "$after_hours" -eq 0 ]]; then
  echo "  -> BASELINE: Zero admin activity outside business hours"
else
  echo "  [!] ${after_hours} event(s) outside business hours (see validation below)"
fi
echo

# --- 4. Day-of-week distribution -------------------------------------------------
echo "DAY-OF-WEEK DISTRIBUTION:"
weekend_events=0
while IFS=$'\t' read -r day count; do
  printf '  %-10s events: %s\n' "$day" "$count"
  if [[ "$day" == "Saturday" || "$day" == "Sunday" ]]; then
    weekend_events=$((weekend_events + count))
  fi
done < <(count_by 3)
if [[ "$weekend_events" -eq 0 ]]; then
  echo "  -> BASELINE: No weekend activity (Mon-Fri work week)"
else
  echo "  [!] Weekend activity detected: ${weekend_events} event(s)"
fi
echo

# --- 5. Target host analysis -------------------------------------------------------
echo "TARGET HOSTS:"
while IFS=$'\t' read -r target count; do
  printf '  %-16s events: %s\n' "$target" "$count"
done < <(count_by 8)
echo

# --- 6. User account analysis --------------------------------------------------------
echo "USER ACCOUNTS:"
svc_acct_events=0
while IFS=$'\t' read -r user count; do
  printf '  %-28s events: %s\n' "$user" "$count"
  if [[ "$user" != "$EXPECTED_USER" ]]; then
    svc_acct_events=$((svc_acct_events + count))
  fi
done < <(count_by 9)
if [[ "$svc_acct_events" -eq 0 ]]; then
  echo "  -> BASELINE: Uses named account only, never service accounts"
else
  echo "  [!] ${svc_acct_events} event(s) under accounts other than ${EXPECTED_USER}"
fi
echo

# --- 7. Baseline summary --------------------------------------------------------------
echo "BASELINE SUMMARY:"
echo "  Normal source host:  ${EXPECTED_SOURCE} (sole origin of all admin activity)"
echo "  Normal time window:  Mon-Fri 08:00-18:00 Central Time (CDT, UTC-5 in May 2026)"
echo "  Normal account:      ${EXPECTED_USER}"
echo "  Normal tools:        $(list_column 6)"
echo "  Normal targets:      $(list_column 8)"
echo

# --- 8. Validation against schedule + anomaly criteria -------------------------------
# The expected account contains a backslash; awk's -v performs escape-sequence
# processing on assigned values (\r would become a carriage return), so the
# account is passed via the environment and read with ENVIRON, which does not.
violations="$(acct="$EXPECTED_USER" awk -F'\t' -v src="$EXPECTED_SOURCE" \
  -v s="$BUSINESS_START" -v e="$BUSINESS_END" '
  $7 != src || $5 < s || $5 > e || $3 == "Saturday" || $3 == "Sunday" \
    || $9 != ENVIRON["acct"] || $10 != "authorized" {
      printf "    [!] %s  tool=%s  src=%s -> tgt=%s  user=%s  %s CT  %s\n", \
        $1, $6, $7, $8, $9, $4, $10
  }' <<< "$events_tsv")"

if [[ -z "$violations" ]]; then
  echo "SCHEDULE VALIDATION: all ${total_events} baseline events conform to admin_schedule.txt"
else
  echo "SCHEDULE VALIDATION VIOLATIONS:"
  echo "$violations"
fi
echo
echo "ANOMALY DETECTION CRITERIA (for all subsequent hunts):"
echo "  [!] Admin tool from any host other than ${EXPECTED_SOURCE}"
echo "      (WS-ADMIN-02 is failover only; no activation is on record for the hunt window)"
echo "  [!] Admin tool usage outside Mon-Fri 08:00-18:00 Central Time"
echo "  [!] Weekend admin tool usage"
echo "  [!] Any account other than ${EXPECTED_USER} using admin tools"
echo "  [!] Service account used interactively from a workstation host"
echo "  [!] WMI/PSRemoting/PsExec targeting hosts absent from the target list above"
echo "  [!] hunt_meta.authorized = false, or events missing authorized metadata"
echo
echo "================================================================"
