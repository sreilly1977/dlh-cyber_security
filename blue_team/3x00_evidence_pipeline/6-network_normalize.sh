#!/bin/bash
#
# Name: 6-network_normalize.sh
# Purpose: Parse firewall CSV, Suricata EVE JSON, and PCAP summary; normalize
#          them into the unified schema; append to normalized_events.json.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"

NETWORK_DIR="${EVIDENCE_PACK}/network"
NORMALIZED_FILE="${WORKDIR}/normalized_events.json"
NETWORK_EVENTS_FILE="${WORKDIR}/network_events.json"
SCHEMA_FILE="${WORKDIR}/event_schema.json"

if [[ ! -d "$NETWORK_DIR" ]]; then
    echo "ERROR: Network directory not found: $NETWORK_DIR" >&2
    exit 1
fi

python3 - "${WORKDIR}" "${NETWORK_DIR}" "${SCHEMA_FILE}" "${NORMALIZED_FILE}" "${NETWORK_EVENTS_FILE}" <<'PYTHON_EOF'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

workdir = sys.argv[1]
network_dir = sys.argv[2]
schema_file = sys.argv[3]
normalized_file = sys.argv[4]
network_events_file = sys.argv[5]

output_dir = os.path.dirname(normalized_file) or "."
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

MONTHS = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
          "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}

def normalize_timestamp(ts_raw, source_hint=None):
    """Convert various timestamp formats to ISO 8601 UTC."""
    if not ts_raw or not isinstance(ts_raw, str):
        return None

    ts = ts_raw.strip()

    # Already ISO 8601 Z
    if re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", ts):
        return ts

    # ISO with +00:00
    if ts.endswith("+00:00"):
        return ts[:-6] + "Z"

    # ISO with fractional seconds and Z
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+Z$", ts)
    if m:
        return m.group(1) + "Z"

    # ISO with +0000 offset (Suricata)
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+[+\-]\d{4}$", ts)
    if m:
        return m.group(1) + "Z"

    # MM/DD/YYYY HH:MM:SS AM/PM (pcap)
    if source_hint == "pcap":
        try:
            dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
            return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    # Epoch seconds (integer or float string)
    if source_hint == "unix_epoch":
        try:
            val = float(ts)
            if 1_000_000_000 < val < 2_000_000_000:
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError):
            pass

    # Mon DD HH:MM:SS syslog format
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", ts)
    if m:
        mon_name, day, hh, mm, ss = m.groups()
        mon = MONTHS.get(mon_name, "01")
        return f"2026-{mon}-{int(day):02d}T{hh}:{mm}:{ss}Z"

    return None

def normalize_record(fields):
    """Generate record_id as SHA-256 of the normalized record."""
    record_id = hashlib.sha256(
        json.dumps(fields, sort_keys=True, default=str).encode()
    ).hexdigest()
    fields["record_id"] = record_id
    return fields

# --- Parse firewall.csv --------------------------------------------------------
def parse_firewall_csv(filepath):
    """Parse firewall CSV file with Unix epoch timestamps."""
    records = []

    if not os.path.isfile(filepath):
        return []

    with open(filepath, "r", errors="replace") as f:
        lines = [l for l in f.readlines() if l.strip()]

    for i, line in enumerate(lines):
        if i == 0:
            continue  # skip header

        parts = line.strip().split(",")
        if len(parts) < 11:
            continue

        timestamp_raw = parts[0]
        timestamp = normalize_timestamp(timestamp_raw, source_hint="unix_epoch")

        src_ip = parts[1]
        src_port = None
        try:
            src_port = int(parts[2])
        except (ValueError, IndexError):
            pass

        dst_ip = parts[3]
        dst_port = None
        try:
            dst_port = int(parts[4])
        except (ValueError, IndexError):
            pass

        protocol = parts[5].upper() if len(parts) > 5 else None
        action = parts[6].upper() if len(parts) > 6 else None
        interface = parts[7] if len(parts) > 7 else None
        rule_id = parts[8] if len(parts) > 8 else None

        bytes_in = None
        bytes_out = None
        if len(parts) > 10:
            try:
                bytes_in = int(parts[9])
            except ValueError:
                pass
            try:
                bytes_out = int(parts[10])
            except ValueError:
                pass

        event_category = "network"
        severity = "low" if action == "BLOCK" else "info"

        event_data = {
            "interface": interface,
            "rule_id": rule_id,
        }

        normalized = {
            "timestamp": timestamp,
            "hostname": None,
            "source_type": "firewall",
            "event_category": event_category,
            "severity": severity,
            "user": None,
            "process_name": None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "raw_message": line.strip(),
            "event_id": None,
            "source_origin": "evidence_pack",
            "source_channel": None,
            "source_provider": None,
            "pid": None,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action,
            "signature": None,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "event_data": event_data,
        }

        normalize_record(normalized)
        records.append(normalized)

    return records

# --- Parse suricata_eve.json ---------------------------------------------------
def parse_suricata_json(filepath):
    """Parse Suricata EVE NDJSON alert records."""
    records = []

    if not os.path.isfile(filepath):
        return []

    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    # Try single JSON document first
    try:
        data = json.loads(content)
        if isinstance(data, list):
            objects = data
        elif isinstance(data, dict):
            objects = [data]
        else:
            objects = []
    except json.JSONDecodeError:
        # Fall back to NDJSON
        objects = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    objects.append(obj)
            except json.JSONDecodeError:
                continue

    for obj in objects:
        # Filter for alert events only
        event_type = obj.get("event_type", "")
        if event_type != "alert":
            continue

        timestamp_raw = obj.get("timestamp", "")
        timestamp = normalize_timestamp(timestamp_raw)

        src_ip = obj.get("src_ip")
        src_port = obj.get("src_port")
        dst_ip = obj.get("dest_ip") or obj.get("dst_ip")
        dst_port = obj.get("dest_port") or obj.get("dst_port")
        protocol = obj.get("proto", "").upper()

        alert = obj.get("alert", {})
        signature = alert.get("signature")
        severity_int = alert.get("severity", 3)

        # Map severity integer to severity string (per schema)
        if severity_int == 1:
            severity = "high"
        elif severity_int == 2:
            severity = "medium"
        elif severity_int == 3:
            severity = "low"
        else:
            severity = "info"

        action = alert.get("action")
        category = alert.get("category")

        flow = obj.get("flow", {})
        bytes_in = flow.get("bytes_toserver")
        bytes_out = flow.get("bytes_toclient")

        event_category = "network_alert"

        event_data = {
            "flow_id": obj.get("flow_id"),
            "in_iface": obj.get("in_iface"),
            "signature_id": alert.get("signature_id"),
            "rev": alert.get("rev"),
            "category": category,
            "gids": alert.get("gid"),
            "app_proto": obj.get("app_proto"),
        }

        normalized = {
            "timestamp": timestamp,
            "hostname": None,
            "source_type": "suricata",
            "event_category": event_category,
            "severity": severity,
            "user": None,
            "process_name": None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "raw_message": json.dumps(obj, separators=(",", ":"), default=str),
            "event_id": None,
            "source_origin": "evidence_pack",
            "source_channel": None,
            "source_provider": None,
            "pid": None,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": action,
            "signature": signature,
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
            "event_data": event_data,
        }

        normalize_record(normalized)
        records.append(normalized)

    return records

# --- Parse pcap_summary.json ---------------------------------------------------
def parse_pcap_json(filepath):
    """Parse PCAP summary NDJSON flow records."""
    records = []

    if not os.path.isfile(filepath):
        return []

    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    try:
        data = json.loads(content)
        if isinstance(data, list):
            objects = data
        elif isinstance(data, dict):
            objects = [data]
        else:
            objects = []
    except json.JSONDecodeError:
        objects = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    objects.append(obj)
            except json.JSONDecodeError:
                continue

    for obj in objects:
        # Use start_time as primary timestamp
        timestamp_raw = obj.get("start_time", "")
        timestamp = normalize_timestamp(timestamp_raw, source_hint="pcap")

        src_ip = obj.get("src_ip")
        src_port = obj.get("src_port")
        dst_ip = obj.get("dst_ip")
        dst_port = obj.get("dst_port")
        protocol = obj.get("protocol", "").upper()

        duration_seconds = obj.get("duration_seconds")
        packets = obj.get("packets")
        bytes_total = obj.get("bytes_total")
        flags = obj.get("flags")

        session_id = obj.get("session_id")

        event_category = "network_flow"
        severity = "info"

        event_data = {
            "session_id": session_id,
            "duration_seconds": duration_seconds,
            "packets": packets,
            "flags": flags,
        }

        normalized = {
            "timestamp": timestamp,
            "hostname": None,
            "source_type": "pcap_flow",
            "event_category": event_category,
            "severity": severity,
            "user": None,
            "process_name": None,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "raw_message": json.dumps(obj, separators=(",", ":"), default=str),
            "event_id": None,
            "source_origin": "evidence_pack",
            "source_channel": None,
            "source_provider": None,
            "pid": None,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "action": None,
            "signature": None,
            "bytes_in": bytes_total,
            "bytes_out": None,
            "event_data": event_data,
        }

        normalize_record(normalized)
        records.append(normalized)

    return records

# --- Main processing -----------------------------------------------------------
firewall_file = os.path.join(network_dir, "firewall.csv")
suricata_file = os.path.join(network_dir, "suricata_eve.json")
pcap_file = os.path.join(network_dir, "pcap_summary.json")

firewall_records = parse_firewall_csv(firewall_file)
suricata_records = parse_suricata_json(suricata_file)
pcap_records = parse_pcap_json(pcap_file)

all_network_records = firewall_records + suricata_records + pcap_records

# Append to existing normalized_events.json (no read-rewrite)
with open(normalized_file, "a") as f:
    for rec in all_network_records:
        json.dump(rec, f, separators=(",", ":"), default=str)
        f.write("\n")

# Write standalone network_events.json
with open(network_events_file, "w") as f:
    for rec in all_network_records:
        json.dump(rec, f, separators=(",", ":"), default=str)
        f.write("\n")

# --- Print summary ------------------------------------------------------------
print(f"{'firewall.csv':>18s}      : ~{len(firewall_records):>6d} records normalized")
print(f"{'suricata_eve.json':>18s} : ~{len(suricata_records):>6d} records normalized")
print(f"{'pcap_summary.json':>18s} : ~{len(pcap_records):>6d} records normalized")
print("appended to normalized_events.json")
print("network_events.json written")

PYTHON_EOF
