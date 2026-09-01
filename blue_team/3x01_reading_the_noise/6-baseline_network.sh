#!/bin/bash
#
# Name: 6-baseline_network.sh
# Purpose: Compute network baseline (expected destinations, ports, zone flows, external IPs)
# Author: Steve - Cybersecurity Engineer
# Date: 31 August 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

LABELED_EVENTS="${BASELINE_PKG}/labeled_events.json"
ZONE_CONTEXT="${HANDOFF_DIR}/context/network_zones.json"

if [[ ! -f "${LABELED_EVENTS}" ]]; then
    echo "ERROR: Labeled events file not found at ${LABELED_EVENTS}" >&2
    echo "Run 3-event_taxonomy.sh first." >&2
    exit 1
fi

if [[ ! -f "${ZONE_CONTEXT}" ]]; then
    echo "ERROR: Zone context file not found at ${ZONE_CONTEXT}" >&2
    exit 1
fi

export LABELED_EVENTS BASELINE_DAYS BASELINE_PKG ZONE_CONTEXT

python3 -W error - << 'PYEOF'
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

NETWORK_LABELS = {
    "network_connection_outbound",
    "network_connection_inbound",
    "network_alert",
    "network_blocked",
}

RFC1918_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def load_zone_table(path):
    """Build (network, zone_id) pairs sorted for longest-prefix matching.
    Excludes zero-prefix (catch-all) CIDRs; INTERNET is handled by the resolver fallback."""
    table = []
    with open(path, "r") as f:
        data = json.load(f)
    for zone in data.get("zones", []):
        zone_id = zone.get("zone_id")
        for cidr in zone.get("cidrs", []):
            try:
                net = ip_network(cidr, strict=False)
            except ValueError:
                print(f"WARNING: Invalid CIDR skipped: {cidr}", file=sys.stderr)
                continue
            if net.prefixlen == 0:
                # Catch-all INTERNET definition: handled by resolver fallback instead
                continue
            table.append((net, zone_id))
    table.sort(key=lambda pair: pair[0].prefixlen, reverse=True)
    return table

def resolve_zone(ip, zone_table):
    """Resolve an IP to a zone via longest-prefix match.
    Unmatched RFC1918 IPs -> INTERNAL_UNTAGGED; everything else
    (including TEST-NET ranges) -> INTERNET."""
    if not ip:
        return None
    try:
        addr = ip_address(str(ip))
    except ValueError:
        return None
    for network, zone_id in zone_table:
        if addr in network:
            return zone_id
    if any(addr in net for net in RFC1918_NETWORKS):
        return "INTERNAL_UNTAGGED"
    return "INTERNET"

def main():
    labeled_path = os.environ["LABELED_EVENTS"]
    baseline_pkg = os.environ["BASELINE_PKG"]

    baseline_days = int(os.environ.get("BASELINE_DAYS", "7"))
    if baseline_days < 1:
        print("ERROR: BASELINE_DAYS must be >= 1", file=sys.stderr)
        sys.exit(1)

    zone_table = load_zone_table(os.environ["ZONE_CONTEXT"])

    # Pass 1: find earliest timestamp for window derivation
    min_ts = None
    with open(labeled_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(event.get("timestamp"))
            if ts and (min_ts is None or ts < min_ts):
                min_ts = ts

    if min_ts is None:
        print("ERROR: No parsable events found", file=sys.stderr)
        sys.exit(1)

    window_start = min_ts.replace(hour=0, minute=0, second=0, microsecond=0)
    window_end = window_start + timedelta(days=baseline_days)
    start_str = window_start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = window_end.strftime("%Y-%m-%dT%H:%M:%SZ")

    host_dests = defaultdict(Counter)
    host_ports = defaultdict(Counter)
    zone_flows = Counter()
    external_ips = Counter()
    port_hosts = defaultdict(set)

    with open(labeled_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            label = event.get("canonical_label")
            if label not in NETWORK_LABELS:
                continue

            ts = parse_ts(event.get("timestamp"))
            if ts is None or ts < window_start or ts >= window_end:
                continue

            host = event.get("hostname") or "unknown"
            src_ip = event.get("src_ip")
            dst_ip = event.get("dst_ip")
            dst_port = event.get("dst_port")

            src_zone = resolve_zone(src_ip, zone_table) or "unknown"
            dst_zone = resolve_zone(dst_ip, zone_table) or "unknown"

            if dst_ip:
                host_dests[host][dst_ip] += 1

            if dst_port is not None:
                port_key = str(dst_port)
                host_ports[host][port_key] += 1
                port_hosts[port_key].add(host)

            zone_flows[(src_zone, dst_zone)] += 1

            if dst_zone == "INTERNET" and dst_ip:
                external_ips[dst_ip] += 1

    per_host_destinations = {
        host: dict(sorted(dests.items(), key=lambda x: (-x[1], x[0])))
        for host, dests in sorted(host_dests.items())
    }

    per_host_ports = {
        host: dict(sorted(ports.items(), key=lambda x: (-x[1], x[0])))
        for host, ports in sorted(host_ports.items())
    }

    zone_flows_out = [
        {"src_zone": sz, "dst_zone": dz, "count": count}
        for (sz, dz), count in sorted(zone_flows.items(), key=lambda x: (-x[1], x[0]))
    ]

    known_external_ips = [
        {"ip": ip, "count": count}
        for ip, count in sorted(external_ips.items(), key=lambda x: (-x[1], x[0]))
    ]

    service_profiles = {
        port: sorted(hosts)
        for port, hosts in sorted(port_hosts.items())
    }

    results = {
        "window": {"start": start_str, "end": end_str, "days": baseline_days},
        "per_host_destinations": per_host_destinations,
        "per_host_ports": per_host_ports,
        "zone_flows": zone_flows_out,
        "known_external_ips": known_external_ips,
        "service_profiles": service_profiles,
    }

    output_file = os.path.join(baseline_pkg, "baseline_network.json")
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    all_dst_ips = set()
    for dests in host_dests.values():
        all_dst_ips.update(dests.keys())

    all_dst_ports = set()
    for ports in host_ports.values():
        all_dst_ports.update(ports.keys())

    print(f"baseline window   : {start_str} -> {end_str}")
    print(f"hosts with network activity : {len(host_dests)}")
    print(f"distinct dst_ip           : {len(all_dst_ips)}")
    print(f"distinct dst_port         : {len(all_dst_ports)}")
    print(f"zone flows recorded       : {len(zone_flows_out)}")
    print(f"known external IPs        : {len(known_external_ips)}")
    print("baseline_network.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
