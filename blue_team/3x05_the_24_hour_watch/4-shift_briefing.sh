#!/bin/bash
# Name: 4-shift_briefing.sh
# Purpose: Assemble the shift briefing reference object that consolidates the
#          HC-RED7 advisory, IOC feed, change tickets, prior shift notes, and
#          baseline deviation data into a single machine-readable document
#          for use by triage and later shift scripts.
# Author: Steve - Cybersecurity Engineer
# Date: 14 September 2026

set -u

log() { printf '[brief] %s\n' "$*"; }
die() { printf '[brief][ERROR] %s\n' "$*" >&2; exit 1; }

for var in SHIFT_WORKSPACE ASSETS_DIR; do
    if [[ -z "${!var:-}" ]]; then
        die "environment variable $var is not set - source the environment contract first"
    fi
done

ADVISORY_FILE="$ASSETS_DIR/hc_red7_advisory.md"
IOC_FILE="$ASSETS_DIR/ioc_feed.json"
TICKETS_FILE="$ASSETS_DIR/change_tickets.json"
NOTES_FILE="$ASSETS_DIR/prior_shift_notes.md"
BASELINE_FILE="$SHIFT_WORKSPACE/runtime/baseline_run.json"
ALERTS_DIR="$SHIFT_WORKSPACE/alerts"
BRIEFING_FILE="$ALERTS_DIR/shift_briefing.json"

# shift_start.json candidates (Task 0 output lives under runtime/)
shift_start_file=""
for cand in "$SHIFT_WORKSPACE/runtime/shift_start.json" \
            "$SHIFT_WORKSPACE/shift_start.json"; do
    if [[ -f "$cand" ]]; then
        shift_start_file="$cand"
        break
    fi
done

# ---------------------------------------------------------------------------
# 1. Validate required input files
# ---------------------------------------------------------------------------
log "checking input files..."
for f in "$ADVISORY_FILE" "$IOC_FILE" "$TICKETS_FILE" "$NOTES_FILE" \
         "$BASELINE_FILE"; do
    if [[ ! -f "$f" ]]; then
        die "required file missing: $f"
    fi
done
if [[ -z "$shift_start_file" ]]; then
    die "shift_start.json not found (looked in runtime/ and workspace root)"
fi
log "checking input files... OK"

# ---------------------------------------------------------------------------
# 2. Cluster ID extraction and cross-check
#    Advisory format: "**Cluster ID:** HC-RED7"
#    shift_start.json: .advisory_cluster_id
# ---------------------------------------------------------------------------
shift_cluster_id=$(jq -r '.advisory_cluster_id // empty' "$shift_start_file")
if [[ -z "$shift_cluster_id" ]]; then
    die "could not read advisory_cluster_id from $shift_start_file"
fi

advisory_cluster_id=$(grep -oiE 'HC-[A-Z0-9-]+' "$ADVISORY_FILE" | head -1)
if [[ -z "$advisory_cluster_id" ]]; then
    die "could not extract cluster ID from $ADVISORY_FILE"
fi

if [[ "$shift_cluster_id" != "$advisory_cluster_id" ]]; then
    die "cluster ID cross-check failed: shift_start.json='$shift_cluster_id' advisory='$advisory_cluster_id'"
fi

# ---------------------------------------------------------------------------
# 3. Parse advisory (tactics, note count) and prior shift notes (open items)
#    Tactics: T1xxx(.yyy) tokens anywhere in the advisory, reduced to base
#    technique IDs and deduplicated preserving first occurrence.
#    Open items: numbered multi-line paragraphs under an "Open Items" heading.
# ---------------------------------------------------------------------------
parsed_md=$(python3 - "$ADVISORY_FILE" "$NOTES_FILE" << 'PYEOF'
import json
import re
import sys

advisory_path, notes_path = sys.argv[1:3]

with open(advisory_path, errors="replace") as f:
    adv_lines = f.read().splitlines()
adv_text = "\n".join(adv_lines)

# Tactics: full technique IDs, reduce to base (drop sub-technique suffix)
tactics = []
for m in re.finditer(r"\bT1\d{3}(?:\.\d{3})?\b", adv_text):
    base = m.group(0).split(".")[0]
    if base not in tactics:
        tactics.append(base)

# Note count: bullet lines under any heading whose title mentions "notes"
note_count = 0
in_notes = False
for line in adv_lines:
    h = re.match(r"^#{1,6}\s+(.*)$", line)
    if h:
        in_notes = "notes" in h.group(1).lower()
        continue
    if in_notes and re.match(r"^\s*[-*]\s+", line):
        note_count += 1

# Prior shift open items: numbered multi-line paragraphs
open_items = []
with open(notes_path, errors="replace") as f:
    notes_lines = f.read().splitlines()

heading_re = re.compile(r"^#{1,6}\s+")
num_re = re.compile(r"^\s*\d+\.\s+(.*)$")
in_section = False
current = None

for line in notes_lines:
    if heading_re.match(line):
        if in_section:
            break
        in_section = "open items" in line.lower()
        continue
    if not in_section:
        continue
    m = num_re.match(line)
    if m:
        if current is not None:
            open_items.append(current)
        current = m.group(1).strip()
    else:
        stripped = line.strip()
        if not stripped:
            if current is not None:
                open_items.append(current)
                current = None
        elif current is not None:
            current = (current + " " + stripped).strip()
if current is not None:
    open_items.append(current)

# Strip markdown emphasis from item text
open_items = [re.sub(r"\*+", "", item) for item in open_items]

print(json.dumps({
    "tactics": tactics,
    "note_count": note_count,
    "open_items": open_items,
}))
PYEOF
) || die "failed to parse advisory and prior shift notes"

cluster_tactics=$(jq -c '.tactics' <<<"$parsed_md")
note_count=$(jq -r '.note_count' <<<"$parsed_md")
open_items=$(jq -c '.open_items' <<<"$parsed_md")

log "cluster ${advisory_cluster_id} loaded"
log "tactics: $(jq -r '.tactics | join(" ")' <<<"$parsed_md")"

# ---------------------------------------------------------------------------
# 4. Parse IOC feed: total, by type, flat values list
# ---------------------------------------------------------------------------
ioc_count=$(jq '.iocs | length' "$IOC_FILE")
ioc_ip=$(jq '[.iocs[] | select(.type == "ip")] | length' "$IOC_FILE")
ioc_domain=$(jq '[.iocs[] | select(.type == "domain")] | length' "$IOC_FILE")
ioc_hash=$(jq '[.iocs[] | select(.type == "hash")] | length' "$IOC_FILE")
ioc_account=$(jq '[.iocs[] | select(.type == "account")] | length' "$IOC_FILE")
ioc_service=$(jq '[.iocs[] | select(.type == "service_name")] | length' "$IOC_FILE")
ioc_port=$(jq '[.iocs[] | select(.type == "port")] | length' "$IOC_FILE")
ioc_values=$(jq -c '[.iocs[].value]' "$IOC_FILE")

log "IOCs: ip=$ioc_ip domain=$ioc_domain hash=$ioc_hash account=$ioc_account service_name=$ioc_service port=$ioc_port total=$ioc_count"

# ---------------------------------------------------------------------------
# 5. Active change tickets overlapping the detection window
#    Tickets carry a single window string "start/end" - split into
#    window_start / window_end and keep those overlapping the window.
# ---------------------------------------------------------------------------
eval_start=$(jq -r '.overall.first_event // empty' \
    "$SHIFT_WORKSPACE/enriched/source_stats.json" 2>/dev/null)
eval_end=$(jq -r '.overall.last_event // empty' \
    "$SHIFT_WORKSPACE/enriched/source_stats.json" 2>/dev/null)
if [[ -z "$eval_start" || -z "$eval_end" ]]; then
    eval_start="2026-03-31T18:00:09Z"
    eval_end="2026-04-08T23:59:57Z"
fi

active_tickets=$(python3 - "$TICKETS_FILE" "$eval_start" "$eval_end" << 'PYEOF'
import json
import sys

tickets_path, win_start, win_end = sys.argv[1:4]

with open(tickets_path) as f:
    feed = json.load(f)

tickets = feed.get("tickets", [])
active = []
for t in tickets:
    window = t.get("window", "")
    parts = window.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        continue
    t_start, t_end = parts[0], parts[1]
    # Keep tickets whose window overlaps the detection window
    if t_start <= win_end and t_end >= win_start:
        active.append({
            "ticket_id": t.get("ticket_id"),
            "window_start": t_start,
            "window_end": t_end,
            "hosts": t.get("hosts", []),
            "owner": t.get("owner"),
            "approved_activity": t.get("approved_activity"),
        })

print(json.dumps(active))
PYEOF
) || die "failed to process change tickets"

active_ticket_count=$(jq 'length' <<<"$active_tickets")
log "active change tickets in window: $active_ticket_count"

# ---------------------------------------------------------------------------
# 6. Prior shift open items and baseline deviation data
# ---------------------------------------------------------------------------
open_item_count=$(jq 'length' <<<"$open_items")
log "prior shift open items: $open_item_count"

hot_hosts=$(jq -c '.hot_hosts // []' "$BASELINE_FILE")
hot_host_count=$(jq '.hot_hosts | length // 0' "$BASELINE_FILE")
hosts_with_deviations=$(jq -r '.hosts_with_deviations // 0' "$BASELINE_FILE")

log "baseline hot hosts: $hot_host_count"
log "cluster ID cross-check: OK"

# ---------------------------------------------------------------------------
# 7. Write shift_briefing.json
# ---------------------------------------------------------------------------
mkdir -p "$ALERTS_DIR"

jq -n \
    --arg cluster_id "$advisory_cluster_id" \
    --argjson cluster_tactics "$cluster_tactics" \
    --argjson ioc_count "$ioc_count" \
    --argjson ioc_ip "$ioc_ip" \
    --argjson ioc_domain "$ioc_domain" \
    --argjson ioc_hash "$ioc_hash" \
    --argjson ioc_account "$ioc_account" \
    --argjson ioc_service "$ioc_service" \
    --argjson ioc_port "$ioc_port" \
    --argjson ioc_values "$ioc_values" \
    --argjson active_tickets "$active_tickets" \
    --argjson open_items "$open_items" \
    --argjson hot_hosts "$hot_hosts" \
    --argjson hosts_with_deviations "$hosts_with_deviations" \
    '{
        cluster_id: $cluster_id,
        cluster_tactics: $cluster_tactics,
        ioc_count: $ioc_count,
        ioc_by_type: {
            ip: $ioc_ip,
            domain: $ioc_domain,
            hash: $ioc_hash,
            account: $ioc_account,
            service_name: $ioc_service,
            port: $ioc_port
        },
        ioc_values: $ioc_values,
        active_change_tickets: $active_tickets,
        prior_shift_open_items: $open_items,
        baseline_hot_hosts: $hot_hosts,
        hosts_with_deviations: $hosts_with_deviations
    }' > "$BRIEFING_FILE" || die "failed to write $BRIEFING_FILE"

log "shift_briefing.json written"

exit 0
