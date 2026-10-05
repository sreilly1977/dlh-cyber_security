#!/bin/bash
#
# Name: 3-data_recon.sh
# Purpose: Profile the complete 14-day MedDefense SIEM export
#          (siem_export/wazuh_alerts_14d.json and
#          siem_export/wazuh_raw_sysmon_14d.json, Wazuh JSONL): dataset
#          metadata (totals, time range, duration, format), top event types,
#          events per agent, rule severity distribution, 24-hour histogram
#          in Central Time, and a hypothesis coverage matrix (H1-H5) whose
#          entries are computed from actual observable matches in the data.
#          Read-only; stdout only.
# Author: Steve - Cybersecurity Engineer
# Date: 05 October 2026
#
# Notes learned from recon of the actual files:
#   - hunt_meta may be null on ordinary events; only baseline/triage-relevant
#     events carry it. Classification therefore uses data.win.eventdata
#     observables, not hunt_meta.
#   - Service accounts appear in targetUserName WITHOUT a domain prefix
#     (e.g. "svc_insurance") on authentication events, and in user with the
#     MEDDEFENSE\ prefix on process events. H5 checks both forms.
#   - The lsass.exe processName on normal logon events is NOT an LSASS-
#     access indicator; H2 therefore keys on Sysmon TargetImage only.

set -euo pipefail

readonly ALERTS="siem_export/wazuh_alerts_14d.json"
readonly SYSMON="siem_export/wazuh_raw_sysmon_14d.json"
readonly SVCREF="reference/service_accounts.txt"

for f in "$ALERTS" "$SYSMON"; do
  if [[ ! -r "$f" ]]; then
    echo "ERROR: required file not readable: $f" >&2
    exit 1
  fi
done

# --- Service account names for the H5 reference note ---------------------------
svc_names=""
if [[ -r "$SVCREF" ]]; then
  svc_names=$(grep -oE '\bsvc_[a-zA-Z0-9_]+' "$SVCREF" | sort -u)
fi
svc_count=$(wc -l <<< "$svc_names")

# --- Classify one JSONL file to TSV (jq processes every line) ------------------
# Columns: 1 ts 2 hour(CT) 3 ruleid 4 rulename 5 agent 6 level
#          7 h1(PsExec) 8 h2(LSASS) 9 h3(WMI) 10 h4(PSRemoting) 11 h5(svc-acct)
classify() {
  jq -r '
    (.timestamp | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601 - 18000) as $ct
    | (.data.win.eventdata // {}) as $ed
    | ([$ed.image, $ed.commandLine, $ed.parentImage, $ed.parentCommandLine]
       | map(. // "") | join(" ") | ascii_downcase) as $blob
    | ([$ed.user, $ed.parentUser, $ed.subjectUserName, $ed.targetUserName]
       | map(. // "") | join(" ") | ascii_downcase) as $ublob
    | [
        .timestamp,
        ($ct | strftime("%H")),
        (.rule.id // "0"),
        (.rule.description // "unknown rule"),
        (.agent.name // "-"),
        (.rule.level // 0),
        (if ($blob | test("psexec")) then "1" else "0" end),
        (if (($ed.targetImage // "") | test("lsass"; "i")) then "1" else "0" end),
        (if ($blob | test("wmic|wmiprvse")) then "1" else "0" end),
        (if ($blob | test("wsmprovhost|winrm|pssession")) then "1" else "0" end),
        (if ($ublob | test("svc_")) then "1" else "0" end)
      ] | map(tostring) | join("\t")
  ' "$1"
}

echo "Parsing siem_export/wazuh_alerts_14d.json..." >&2
alerts_tsv=$(classify "$ALERTS")
echo "Parsing siem_export/wazuh_raw_sysmon_14d.json..." >&2
sysmon_tsv=$(classify "$SYSMON")

events_tsv="${alerts_tsv}
${sysmon_tsv}"
events_tsv=$(grep -v '^[[:space:]]*$' <<< "$events_tsv")

if [[ -z "${events_tsv//[[:space:]]/}" ]]; then
  echo "ERROR: no events parsed from either dataset" >&2
  exit 1
fi

total_parsed=$(wc -l <<< "$events_tsv")
total_alerts=$(wc -l < "$ALERTS")
total_sysmon=$(wc -l < "$SYSMON")
echo "Parsed ${total_parsed} events (${total_alerts} + ${total_sysmon} source lines)" >&2

count_col() {
  awk -F'\t' -v c="$1" 'NF >= c && length($c) > 0 {
    n = $c; sub(/^[ \t]+/, "", n); sub(/[ \t]+$/, "", n)
    counts[n]++
  } END {
    for (k in counts) printf "%s\t%d\n", k, counts[k]
  }' <<< "$events_tsv" | sort
}

hyp_count() {
  awk -F'\t' -v c="$1" '$c == "1"' <<< "$events_tsv" | wc -l
}

epoch_of() {
  jq -rn --arg t "$1" '$t | sub("\\.[0-9]+\\+00:00$"; "Z") | fromdateiso8601'
}

echo "================================================================"
echo "   DATA RECONNAISSANCE - MedDefense SIEM Export"
echo "================================================================"
echo

# --- 1. Dataset metadata ---------------------------------------------------------
timestamps=$(cut -f1 <<< "$events_tsv" | sort)
first_ts=$(sed -n '1p' <<< "$timestamps")
last_ts=$(sed -n '$p' <<< "$timestamps")
span_days=$(( ( $(epoch_of "$last_ts") - $(epoch_of "$first_ts") ) / 86400 ))

echo "DATASET METADATA:"
echo "  Total events:   ${total_parsed}  (alerts: ${total_alerts}, raw sysmon: ${total_sysmon})"
echo "  Time range:     ${first_ts}"
echo "                 to ${last_ts}"
echo "  Duration:       ${span_days} day(s)"
echo "  Format:         JSON Lines (Wazuh alert envelopes, UTF-8)"
echo

# --- 2. Top 10 event types ---------------------------------------------------------
echo "TOP 10 EVENT TYPES (rule id / description):"
awk -F'\t' 'NF >= 4 { key = $3 "\t" $4; counts[key]++ }
  END { for (k in counts) printf "%s\t%d\n", k, counts[k] }' <<< "$events_tsv" \
  | sort -t$'\t' -k3,3rn | sed -n '1,10p' \
  | while IFS=$'\t' read -r rid desc cnt; do
      printf '  %-7s %-50s (count: %s)\n' "$rid" "$desc" "$cnt"
    done
echo

# --- 3. Source host distribution ---------------------------------------------------
echo "SOURCE HOST DISTRIBUTION (events per agent):"
count_col 5 | sort -t$'\t' -k2,2nr \
  | while IFS=$'\t' read -r host cnt; do
      printf '  %-16s %s\n' "$host:" "$cnt"
    done
echo

# --- 4. Severity distribution -------------------------------------------------------
echo "SEVERITY DISTRIBUTION (events by rule.level):"
count_col 6 | sort -t$'\t' -k1,1n \
  | while IFS=$'\t' read -r lvl cnt; do
      printf '  Level %-3s %s\n' "$lvl" "$cnt"
    done
echo

# --- 5. Hourly distribution (Central Time) ------------------------------------------
echo "HOURLY DISTRIBUTION (Central Time, all 24 hours):"
hist=$(count_col 2)
max_count=$(cut -f2 <<< "$hist" | sort -rn | sed -n '1p')
max_count=${max_count:-0}
if [[ "$max_count" -eq 0 ]]; then max_count=1; fi
for h in $(seq -w 0 23); do
  cnt=$(awk -F'\t' -v h="$h" '$1 == h { print $2 }' <<< "$hist")
  cnt=${cnt:-0}
  bar_len=$(( cnt * 40 / max_count ))
  bar=$(printf '%*s' "$bar_len" '' | tr ' ' '#')
  printf '  %s:00  %6d  %s\n' "$h" "$cnt" "$bar"
done
echo

# --- 6. Hypothesis coverage matrix ---------------------------------------------------
h1=$(hyp_count 7); h2=$(hyp_count 8); h3=$(hyp_count 9)
h4=$(hyp_count 10); h5=$(hyp_count 11)

status_of() {
  if [[ "$1" -gt 0 ]]; then
    echo "OK - ${1} observable event(s) present, hypothesis testable"
  else
    echo "NO - no observable events, hypothesis NOT testable with this data"
  fi
}

echo "HYPOTHESIS COVERAGE MATRIX:"
echo "  H1 (PsExec):       $(status_of "$h1")"
echo "  H2 (LSASS):        $(status_of "$h2")"
echo "  H3 (WMI):          $(status_of "$h3")"
echo "  H4 (PSRemoting):   $(status_of "$h4")"
echo "  H5 (Svc Accounts): $(status_of "$h5")"
echo "  H5 reference: ${svc_count} svc_* accounts documented in service_accounts.txt"
echo
echo "================================================================"
