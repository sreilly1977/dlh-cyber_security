#!/bin/bash
#
# Name:        7-firewall_log_analysis.sh
# Purpose:     Parse firewall log and extract patterns (denied sources, ports, scan signatures)
# Author:      Steve - Cybersecurity Engineer
# Date:        August 15, 2026
#

set -euo pipefail

# ==============================================================================
# Configuration
# ==============================================================================

# Default log file: /home/analyst/MedDefense_Lab/firewall_samples/ufw.log
# Override with: $1 (first argument passed to script)
LOG_FILE="${1:-/home/analyst/MedDefense_Lab/firewall_samples/ufw.log}"
OUTPUT_FILE="firewall_analysis.json"  # Parse with: jq . firewall_analysis.json

# ==============================================================================
# Pre-flight checks
# ==============================================================================

if [[ ! -f "$LOG_FILE" ]]; then
    echo "[!] Missing $LOG_FILE" >&2
    exit 1
fi

echo "[*] Parsing firewall log: $LOG_FILE"

export LOG_FILE
export OUTPUT_FILE

# ==============================================================================
# Python helper for parsing and analysis
# ==============================================================================

python3 << 'PYEOF'
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta

log_file = os.environ["LOG_FILE"]
output_file = os.environ["OUTPUT_FILE"]

# Parse UFW log lines by extracting key=value pairs
def parse_log_line(line):
    """Parse a UFW log line into structured fields."""
    # Match timestamp: "Aug 14 00:01:47"
    ts_match = re.match(r'^(\w+\s+\d+\s+\d+:\d+:\d+)', line)
    if not ts_match:
        return None
    timestamp = ts_match.group(1)

    # Extract action (UFW_BLOCK or UFW_ALLOW)
    action_match = re.search(r'UFW_(\w+)', line)
    if not action_match:
        return None
    action = action_match.group(1)

    # Extract key=value pairs
    fields = {}
    for match in re.finditer(r'(\w+)=(\S+)', line):
        key = match.group(1)
        val = match.group(2)
        fields[key] = val

    # Required fields
    if 'SRC' not in fields or 'DST' not in fields:
        return None
    if 'SPT' not in fields or 'DPT' not in fields:
        return None

    return {
        'timestamp': timestamp,
        'iface_in': fields.get('IN', ''),
        'iface_out': fields.get('OUT', ''),
        'src_ip': fields['SRC'],
        'dst_ip': fields['DST'],
        'proto': fields.get('PROTO', ''),
        'spt': int(fields['SPT']),
        'dpt': int(fields['DPT']),
        'action': action
    }

# Read and parse log
events = []
line_count = 0
parsed_count = 0

with open(log_file, 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        line_count += 1
        parsed = parse_log_line(line)
        if parsed:
            parsed_count += 1
            events.append(parsed)

# Aggregations
denied_src_counts = defaultdict(int)
denied_dst_counts = defaultdict(int)
hourly_buckets = defaultdict(int)

def parse_ts(ts_str):
    try:
        # Replace first space with dash to match format: 2026-Aug-14 00:01:47
        return datetime.strptime(f"2026-{ts_str.replace(' ', '-', 1)}", "%Y-%b-%d %H:%M:%S")
    except:
        return None

for e in events:
    if e['action'] == 'BLOCK':
        denied_src_counts[e['src_ip']] += 1
        denied_dst_counts[e['dpt']] += 1
        dt = parse_ts(e['timestamp'])
        if dt:
            hourly_buckets[dt.hour] += 1

# Top 10 denied sources
top_denied_sources = sorted(denied_src_counts.items(), key=lambda x: -x[1])[:10]
top_denied_sources = [{'ip': ip, 'count': cnt} for ip, cnt in top_denied_sources]

# Top 10 denied ports
top_denied_ports = sorted(denied_dst_counts.items(), key=lambda x: -x[1])[:10]
top_denied_ports = [{'port': port, 'count': cnt} for port, cnt in top_denied_ports]

# Scan detection: 20+ distinct ports within 60-second window
events_sorted = sorted(events, key=lambda e: parse_ts(e['timestamp']) or datetime.min)

scan_candidates = []
src_events = defaultdict(list)

for e in events_sorted:
    if e['action'] == 'BLOCK':
        ts = parse_ts(e['timestamp'])
        if ts:
            src_events[e['src_ip']].append((ts, e['dpt'], e['dst_ip']))

WINDOW_SECONDS = 60
MIN_PORTS = 20

for src_ip, evts in src_events.items():
    evts.sort(key=lambda x: x[0])

    i = 0
    while i < len(evts):
        window_start = evts[i][0]
        ports_in_window = set()
        dst_ips = set()
        window_end_actual = window_start

        j = i
        while j < len(evts) and (evts[j][0] - window_start).total_seconds() <= WINDOW_SECONDS:
            ports_in_window.add(evts[j][1])
            dst_ips.add(evts[j][2])
            window_end_actual = evts[j][0]
            j += 1

        if len(ports_in_window) >= MIN_PORTS:
            scan_candidates.append({
                'src_ip': src_ip,
                'window_start': window_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                'window_end': window_end_actual.strftime("%Y-%m-%dT%H:%M:%SZ"),
                'ports_touched': len(ports_in_window),
                'dst_count': len(dst_ips)
            })
            i = j
        else:
            i += 1

# Outbound anomalies: denied outbound connections from private to public IPs
def is_private_ip(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except:
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False

outbound_anomalies = []
seen_beacons = set()

for e in events:
    if e['action'] == 'BLOCK':
        src_ip = e['src_ip']
        dst_ip = e['dst_ip']
        if is_private_ip(src_ip) and not is_private_ip(dst_ip):
            key = f"{src_ip}->{dst_ip}:{e['dpt']}"
            if key not in seen_beacons:
                seen_beacons.add(key)
                outbound_anomalies.append({
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': e['dpt'],
                    'timestamp': e['timestamp']
                })

# Build hourly histogram (0-23)
hourly_histogram = [hourly_buckets.get(h, 0) for h in range(24)]

# Build final JSON
result = {
    'source_file': log_file,
    'line_count': line_count,
    'parsed_count': parsed_count,
    'top_denied_sources': top_denied_sources,
    'top_denied_ports': top_denied_ports,
    'scan_candidates': scan_candidates,
    'outbound_anomalies': outbound_anomalies,
    'hourly_histogram': hourly_histogram
}

with open(output_file, 'w') as f:
    json.dump(result, f, indent=2)

# Print summary
print(f"\n[*] Summary:")
print(f"    Lines processed: {line_count}")
print(f"    Events parsed: {parsed_count}")
print(f"    Top denied sources: {len(top_denied_sources)}")
print(f"    Top denied ports: {len(top_denied_ports)}")
print(f"    Scan candidates: {len(scan_candidates)}")
print(f"    Outbound anomalies: {len(outbound_anomalies)}")
print(f"\n[*] Report saved to: {output_file}")
PYEOF

echo ""
echo "[*] Done."
