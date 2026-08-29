#!/bin/bash
#
# Name: 9-enrich.sh
# Purpose: Enrich cleaned events with asset inventory and network zone context.
#          Reads asset_inventory.json and network_zones.json, attaches asset
#          metadata and zone resolution to every event.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
INPUT_FILE="${WORKDIR}/cleaned_events.json"
OUTPUT_FILE="${WORKDIR}/enriched_events.json"
ASSET_INVENTORY="${EVIDENCE_PACK}/context/asset_inventory.json"
NETWORK_ZONES="${EVIDENCE_PACK}/context/network_zones.json"

python3 - "${WORKDIR}" "${INPUT_FILE}" "${OUTPUT_FILE}" "${ASSET_INVENTORY}" "${NETWORK_ZONES}" <<'PYTHON_EOF'
import ipaddress
import json
import os
import sys

workdir = sys.argv[1]
input_file = sys.argv[2]
output_file = sys.argv[3]
asset_inventory_file = sys.argv[4]
network_zones_file = sys.argv[5]

# --- Load asset inventory ----------------------------------------------------
if not os.path.isfile(asset_inventory_file):
    sys.stderr.write(f"ERROR: asset inventory not found: {asset_inventory_file}\n")
    sys.exit(1)

with open(asset_inventory_file, "r", errors="replace") as f:
    asset_data = json.load(f)

# Build lookup dict: hostname_lower -> asset metadata
asset_lookup = {}
assets = asset_data if isinstance(asset_data, list) else asset_data.get("hosts", asset_data.get("assets", []))
if not assets and isinstance(asset_data, dict):
    for host, info in asset_data.items():
        if isinstance(info, dict):
            asset_lookup[host.lower()] = {
                "role": info.get("role", "unknown"),
                "criticality": info.get("criticality", "unknown"),
                "os": info.get("os", "unknown"),
                "owner": info.get("owner", "unknown"),
                "zone": info.get("zone", "unknown"),
            }

for asset in assets:
    hostname = asset.get("hostname") or asset.get("host") or asset.get("name")
    if hostname:
        asset_lookup[str(hostname).lower()] = {
            "role": asset.get("role", "unknown"),
            "criticality": asset.get("criticality", "unknown"),
            "os": asset.get("os", "unknown"),
            "owner": asset.get("owner", "unknown"),
            "zone": asset.get("zone", "unknown"),
        }

# --- Load network zones ------------------------------------------------------
if not os.path.isfile(network_zones_file):
    sys.stderr.write(f"ERROR: network zones not found: {network_zones_file}\n")
    sys.exit(1)

with open(network_zones_file, "r", errors="replace") as f:
    zone_data = json.load(f)

# Build list of (network_object, zone_id) for efficient lookup
zone_networks = []
zones = zone_data if isinstance(zone_data, list) else zone_data.get("zones", [])
if not zones and isinstance(zone_data, dict):
    for zone_name, cidrs in zone_data.items():
        if isinstance(cidrs, list):
            for cidr in cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    zone_networks.append((net, zone_name))
                except ValueError:
                    pass
        elif isinstance(cidrs, str):
            try:
                net = ipaddress.ip_network(cidrs, strict=False)
                zone_networks.append((net, zone_name))
            except ValueError:
                pass

for zone in zones:
    zone_name = zone.get("zone_id") or zone.get("name") or zone.get("zone", "unknown")
    cidrs = zone.get("cidrs", zone.get("ranges", zone.get("subnets", [])))
    if isinstance(cidrs, str):
        cidrs = [cidrs]
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            zone_networks.append((net, zone_name))
        except ValueError:
            sys.stderr.write(f"WARNING: invalid CIDR '{cidr}' in zone '{zone_name}'\n")

# Sort by prefix length DESCENDING (most specific match first)
# Ensures 10.1.1.0/24 matches before 0.0.0.0/0
zone_networks.sort(key=lambda x: (-x[0].prefixlen, x[0].network_address))

def lookup_zone(ip_str):
    """Look up which zone an IP belongs to. Returns zone name or 'unknown'."""
    if not ip_str or not isinstance(ip_str, str):
        return "unknown"
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    for net, zone_name in zone_networks:
        if ip in net:
            return zone_name
    return "unknown"

# --- Process events ----------------------------------------------------------
if not os.path.isfile(input_file):
    sys.stderr.write(f"ERROR: input file not found: {input_file}\n")
    sys.exit(1)

total_events = 0
asset_context_count = 0
src_zone_resolved = 0
dst_zone_resolved = 0
unknown_hosts = 0

with open(input_file, "r", errors="replace") as fin, \
     open(output_file, "w") as fout:
    for line in fin:
        stripped = line.strip()
        if not stripped:
            continue

        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            continue

        total_events += 1

        # Asset context enrichment
        hostname = event.get("hostname")
        asset_context = None
        if hostname:
            asset_context = asset_lookup.get(str(hostname).lower())

        if asset_context:
            event["asset"] = asset_context
            asset_context_count += 1
        else:
            event["asset"] = {
                "role": "unknown",
                "criticality": "unknown",
                "os": "unknown",
                "owner": "unknown",
                "zone": "unknown",
            }
            if hostname:
                unknown_hosts += 1

        # Network zone enrichment
        src_ip = event.get("src_ip")
        if src_ip:
            src_zone = lookup_zone(src_ip)
            event["src_zone"] = src_zone
            if src_zone != "unknown":
                src_zone_resolved += 1
        else:
            event["src_zone"] = "unknown"

        dst_ip = event.get("dst_ip")
        if dst_ip:
            dst_zone = lookup_zone(dst_ip)
            event["dst_zone"] = dst_zone
            if dst_zone != "unknown":
                dst_zone_resolved += 1
        else:
            event["dst_zone"] = "unknown"

        json.dump(event, fout, separators=(",", ":"), default=str)
        fout.write("\n")

# --- Report ------------------------------------------------------------------

asset_pct = (asset_context_count / total_events * 100) if total_events > 0 else 0
src_zone_pct = (src_zone_resolved / total_events * 100) if total_events > 0 else 0
dst_zone_pct = (dst_zone_resolved / total_events * 100) if total_events > 0 else 0

print(f"events processed    : {total_events}")
print(f"asset context added : {asset_context_count} ({asset_pct:.1f}%)")
print(f"src_zone resolved   : {src_zone_resolved} ({src_zone_pct:.1f}%)")
print(f"dst_zone resolved   : {dst_zone_resolved} ({dst_zone_pct:.1f}%)")
print(f"unknown hosts       : {unknown_hosts}")
print(f"enriched_events.json written")

PYTHON_EOF
