#!/bin/bash
#
# Name: 5-normalize.sh
# Purpose: Transform Windows and Linux intermediate JSON files into a single
#          normalized dataset conforming to event_schema.json. Quarantines
#          records that cannot be normalized.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
WINDOWS_INPUT="${WORKDIR}/windows_events.json"
LINUX_INPUT="${WORKDIR}/linux_events.json"
SCHEMA_FILE="${WORKDIR}/event_schema.json"
OUTPUT_FILE="${WORKDIR}/normalized_events.json"
QUARANTINE_FILE="${WORKDIR}/quarantine.json"

python3 - "${WORKDIR}" "${WINDOWS_INPUT}" "${LINUX_INPUT}" "${SCHEMA_FILE}" "${OUTPUT_FILE}" "${QUARANTINE_FILE}" <<'PYTHON_EOF'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

workdir = sys.argv[1]
windows_input = sys.argv[2]
linux_input = sys.argv[3]
schema_file = sys.argv[4]
output_file = sys.argv[5]
quarantine_file = sys.argv[6]

output_dir = os.path.dirname(output_file) or "."
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

REQUIRED_FIELDS = ["timestamp", "source_type", "event_category", "severity", "raw_message"]

# --- Event category mapping tables --------------------------------------------

WINDOWS_CATEGORY_MAP = {
    ("Security", 4624): "authentication",
    ("Security", 4625): "authentication",
    ("Security", 4634): "authentication",
    ("Security", 4648): "authentication",
    ("Security", 4720): "authentication",
    ("Security", 4726): "authentication",
    ("Security", 4698): "process",
    ("Security", 7045): "process",
}

SYSMON_CATEGORY_MAP = {
    1: "process",
    3: "network",
    11: "file",
}

AUDIT_TYPE_CATEGORY_MAP = {
    "USER_AUTH": "authentication",
    "USER_LOGIN": "authentication",
    "USER_ACCT": "authentication",
    "CRED_ACQ": "authentication",
    "USER_START": "authentication",
    "SYSCALL": "process",
    "SERVICE_START": "service",
    "SERVICE_STOP": "service",
    "PATH": "audit",
    "AVC": "audit",
    "PROCTITLE": "audit",
}

AUTHLOG_PROGRAM_CATEGORY_MAP = {
    "sshd": "authentication",
    "su": "authentication",
    "login": "authentication",
    "sudo": "process",
    "polkitd": "authentication",
    "CRON": "process",
    "systemd-logind": "authentication",
}

SYSLOG_PROGRAM_CATEGORY_MAP = {
    "kernel": "network",
    "ntpd": "audit",
    "dhclient": "audit",
    "suricata": "network",
    "freshclam": "audit",
    "cron": "process",
    "systemd": "audit",
    "rsyslogd": "audit",
}

# --- Severity derivation ------------------------------------------------------

def windows_severity(event_id, channel):
    if event_id == 4625:
        return "medium"
    if event_id in (4720, 7045, 4698):
        return "high"
    if event_id in (4624, 4634):
        return "info"
    return "info"

def linux_severity(record, event_category):
    parsed = record.get("parsed_fields", {})
    res = parsed.get("res", "")
    if res == "failed":
        return "medium"
    raw = record.get("raw_message", "")
    if "Failed password" in raw:
        return "medium"
    if "Accepted password" in raw:
        return "info"
    if "session opened" in raw.lower():
        return "info"
    if "sudo" in raw.lower():
        return "low"
    return "info"

def firewall_severity(action):
    if action == "BLOCK":
        return "low"
    return "info"

def suricata_severity(sev_int):
    if sev_int == 1:
        return "high"
    if sev_int == 2:
        return "medium"
    if sev_int == 3:
        return "low"
    return "info"

# --- Timestamp normalization --------------------------------------------------

def normalize_timestamp(ts_raw):
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

    # MM/DD/YYYY HH:MM:SS AM/PM
    try:
        dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Epoch seconds (integer or float string)
    try:
        val = float(ts)
        if 1_000_000_000 < val < 2_000_000_000:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Mon DD HH:MM:SS syslog format
    months = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
              "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", ts)
    if m:
        mon_name, day, hh, mm, ss = m.groups()
        mon = months.get(mon_name, "01")
        return f"2026-{mon}-{int(day):02d}T{hh}:{mm}:{ss}Z"

    return None

# --- IP extraction ------------------------------------------------------------

IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

def extract_ips_from_text(text):
    """Find all IPv4 addresses in a text string."""
    return IPV4_RE.findall(text)

# --- Normalization functions --------------------------------------------------

def normalize_windows_record(record):
    """Normalize a Windows intermediate record to the unified schema."""
    ed = record.get("event_data", {}) or {}

    # Timestamp
    ts_raw = record.get("timestamp_raw", "")
    timestamp = normalize_timestamp(ts_raw)

    # Hostname
    hostname = record.get("hostname")

    # Source type
    source_type = "windows_json"

    # Event category
    channel = record.get("channel", "") or ""
    event_id = record.get("event_id")
    event_category = None

    if event_id is not None:
        # Try exact channel + event_id match first
        event_category = WINDOWS_CATEGORY_MAP.get((channel, event_id))
        if not event_category and "Sysmon" in channel:
            event_category = SYSMON_CATEGORY_MAP.get(event_id)
        if not event_category and "PowerShell" in channel:
            event_category = "powershell"
        if not event_category and channel == "Security":
            event_category = "authentication"
        if not event_category:
            event_category = "process"

    # Severity
    severity = windows_severity(event_id, channel) if event_id is not None else "info"

    # User
    user = ed.get("TargetUserName") or ed.get("User")
    if user and "\\" in str(user):
        user = str(user).split("\\")[-1]

    # Process name
    process_name = None
    image = ed.get("Image")
    if image:
        process_name = str(image).split("\\")[-1]
    elif ed.get("ProcessName"):
        process_name = ed.get("ProcessName")

    # Source IP
    src_ip = ed.get("IpAddress") or ed.get("SourceIp")

    # Destination IP
    dst_ip = ed.get("DestinationIp")

    # Raw message
    raw_message = record.get("raw_message", "")

    # PID
    pid = None
    for pid_field in ("ProcessId", "Pid"):
        if ed.get(pid_field) is not None:
            try:
                pid = int(ed[pid_field])
            except (ValueError, TypeError):
                pass

    # Source port
    src_port = None
    if ed.get("SourcePort") is not None:
        try:
            src_port = int(ed["SourcePort"])
        except (ValueError, TypeError):
            pass

    # Destination port
    dst_port = None
    if ed.get("DestinationPort") is not None:
        try:
            dst_port = int(ed["DestinationPort"])
        except (ValueError, TypeError):
            pass

    # Protocol
    protocol = ed.get("Protocol")
    if protocol:
        protocol = str(protocol).upper()

    normalized = {
        "timestamp": timestamp,
        "hostname": hostname if hostname else None,
        "source_type": source_type,
        "event_category": event_category,
        "severity": severity,
        "user": user if user else None,
        "process_name": process_name,
        "src_ip": src_ip if src_ip else None,
        "dst_ip": dst_ip if dst_ip else None,
        "raw_message": raw_message,
        "event_id": event_id if event_id is not None else None,
        "source_origin": record.get("source_origin", "evidence_pack"),
        "source_channel": channel if channel else None,
        "source_provider": record.get("provider") if record.get("provider") else None,
        "pid": pid,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "action": None,
        "signature": None,
        "bytes_in": None,
        "bytes_out": None,
        "event_data": ed if ed else {},
    }

    # Generate record_id
    record_id = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, default=str).encode()
    ).hexdigest()
    normalized["record_id"] = record_id

    return normalized

def normalize_linux_record(record):
    """Normalize a Linux intermediate record to the unified schema."""
    ts_raw = record.get("timestamp_raw", "")
    timestamp = normalize_timestamp(ts_raw)

    hostname = record.get("hostname")
    source_type = "linux_text"

    # Determine event category
    audit_type = record.get("audit_type")
    program = record.get("program")
    parsed = record.get("parsed_fields", {}) or {}

    event_category = None
    if audit_type:
        event_category = AUDIT_TYPE_CATEGORY_MAP.get(audit_type, "audit")
    elif program:
        event_category = AUTHLOG_PROGRAM_CATEGORY_MAP.get(program)
        if not event_category:
            event_category = SYSLOG_PROGRAM_CATEGORY_MAP.get(program, "audit")

    if not event_category:
        event_category = "audit"

    severity = linux_severity(record, event_category)

    user = record.get("user")
    process_name = program or audit_type

    # Extract IPs
    raw_message = record.get("raw_message", "")
    ips = extract_ips_from_text(raw_message)
    src_ip = None
    dst_ip = None

    # For audit records, prefer addr field
    addr = parsed.get("addr")
    if addr:
        src_ip = addr

    # If no addr, try to find IPs in the message
    if not src_ip and ips:
        src_ip = ips[0]
    if ips and len(ips) > 1:
        dst_ip = ips[1]
    elif ips and len(ips) == 1 and not src_ip:
        src_ip = ips[0]

    pid = record.get("pid")

    normalized = {
        "timestamp": timestamp,
        "hostname": hostname if hostname else None,
        "source_type": source_type,
        "event_category": event_category,
        "severity": severity,
        "user": user if user else None,
        "process_name": process_name if process_name else None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "raw_message": raw_message,
        "event_id": None,
        "source_origin": record.get("source_origin", "evidence_pack"),
        "source_channel": None,
        "source_provider": None,
        "pid": pid,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "action": parsed.get("res") if parsed.get("res") else None,
        "signature": None,
        "bytes_in": None,
        "bytes_out": None,
        "event_data": parsed if parsed else {},
    }

    record_id = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, default=str).encode()
    ).hexdigest()
    normalized["record_id"] = record_id

    return normalized

# --- Read intermediate files --------------------------------------------------

def read_ndjson(filepath):
    """Read NDJSON or JSON array file, returning list of dicts."""
    if not os.path.isfile(filepath):
        return []

    with open(filepath, "r", errors="replace") as f:
        content = f.read()

    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [obj for obj in data if isinstance(obj, dict)]
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    records = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            sys.stderr.write(f"WARNING: malformed line skipped in {filepath}\n")
    return records

# --- Main processing ----------------------------------------------------------

normalized_records = []
quarantine_records = []
stats = {"windows_json": {"normalized": 0, "quarantined": 0},
         "linux_text": {"normalized": 0, "quarantined": 0}}

# Process Windows events
windows_records = read_ndjson(windows_input)
for rec in windows_records:
    try:
        normalized = normalize_windows_record(rec)
        missing = [f for f in REQUIRED_FIELDS if not normalized.get(f)]
        if missing:
            quarantine_records.append({
                "quarantine_reason": f"missing required fields: {', '.join(missing)}",
                "original_record": rec,
                "source_type": "windows_json",
            })
            stats["windows_json"]["quarantined"] += 1
            continue
        normalized_records.append(normalized)
        stats["windows_json"]["normalized"] += 1
    except Exception as e:
        quarantine_records.append({
            "quarantine_reason": f"normalization error: {str(e)}",
            "original_record": rec,
            "source_type": "windows_json",
        })
        stats["windows_json"]["quarantined"] += 1

# Process Linux events
linux_records = read_ndjson(linux_input)
for rec in linux_records:
    try:
        normalized = normalize_linux_record(rec)
        missing = [f for f in REQUIRED_FIELDS if not normalized.get(f)]
        if missing:
            quarantine_records.append({
                "quarantine_reason": f"missing required fields: {', '.join(missing)}",
                "original_record": rec,
                "source_type": "linux_text",
            })
            stats["linux_text"]["quarantined"] += 1
            continue
        normalized_records.append(normalized)
        stats["linux_text"]["normalized"] += 1
    except Exception as e:
        quarantine_records.append({
            "quarantine_reason": f"normalization error: {str(e)}",
            "original_record": rec,
            "source_type": "linux_text",
        })
        stats["linux_text"]["quarantined"] += 1

# --- Write outputs -------------------------------------------------------------

with open(output_file, "w") as f:
    for rec in normalized_records:
        json.dump(rec, f, separators=(",", ":"), default=str)
        f.write("\n")

with open(quarantine_file, "w") as f:
    for rec in quarantine_records:
        json.dump(rec, f, separators=(",", ":"), default=str)
        f.write("\n")

# --- Print summary -------------------------------------------------------------

total_norm = stats["windows_json"]["normalized"] + stats["linux_text"]["normalized"]
total_quar = stats["windows_json"]["quarantined"] + stats["linux_text"]["quarantined"]

print(f"windows_json     : {stats['windows_json']['normalized']:>6d} normalized    {stats['windows_json']['quarantined']:>6d} quarantined")
print(f"linux_text       : {stats['linux_text']['normalized']:>6d} normalized    {stats['linux_text']['quarantined']:>6d} quarantined")
print(f"total            : {total_norm:>6d} normalized    {total_quar:>6d} quarantined")
print(f"normalized_events.json written")
print(f"quarantine.json  written")

PYTHON_EOF
