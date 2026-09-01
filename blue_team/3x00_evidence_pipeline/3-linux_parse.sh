#!/bin/bash
#
# Name: 3-linux_parse.sh
# Purpose: Parse auth.log, audit.log, and syslog into structured JSON records
#          with consistent intermediate fields; append student telemetry.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"

LINUX_DIR="${EVIDENCE_PACK}/linux"
STUDENT_DIR="${EVIDENCE_PACK}/student_telemetry"

OUTPUT_FILE="${WORKDIR}/linux_events.json"

if [[ ! -d "$LINUX_DIR" ]]; then
    echo "ERROR: Linux directory not found: $LINUX_DIR" >&2
    exit 1
fi

if [[ ! -d "$STUDENT_DIR" ]]; then
    echo "ERROR: Student telemetry directory not found: $STUDENT_DIR" >&2
    exit 1
fi

python3 - "${WORKDIR}" "${LINUX_DIR}" "${STUDENT_DIR}" "${OUTPUT_FILE}" <<'PYTHON_EOF'
import json
import os
import re
import sys
from datetime import datetime, timezone

workdir = sys.argv[1]
linux_dir = sys.argv[2]
student_dir = sys.argv[3]
output_file = sys.argv[4]

output_dir = os.path.dirname(output_file) or "."
if output_dir and not os.path.exists(output_dir):
    os.makedirs(output_dir, exist_ok=True)

MONTHS = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
          "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}

def parse_syslog_timestamp(line):
    """Parse 'Mon DD HH:MM:SS' syslog timestamp, assume 2026 UTC.
    Rejects lines whose month token is not a valid abbreviation."""
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if m:
        month_name, day, hh, mm, ss = m.groups()
        if month_name not in MONTHS:
            return None   # unknown month token: refuse to guess
        mon = MONTHS[month_name]
        return f"2026-{mon}-{int(day):02d}T{hh}:{mm}:{ss}Z"
    return None

def extract_hostname_program(line):
    """Extract hostname and program[pid] from syslog line."""
    m = re.match(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$", line)
    if m:
        hostname, program, pid, message = m.groups()
        return hostname, program, pid, message
    return None, None, None, None

def extract_key_values(line):
    """Extract key=value pairs from a line."""
    pairs = {}
    for m in re.finditer(r"(\w+)=(?:'([^']*)'|\"([^\"]*)\"|(\S+))", line):
        key = m.group(1)
        value = m.group(2) or m.group(3) or m.group(4)
        pairs[key] = value
    return pairs

def count_lines(filepath):
    """Count non-empty lines in a file."""
    with open(filepath, "r", errors="replace") as f:
        return sum(1 for l in f if l.strip())

def parse_auth_log(filepath):
    """Parse auth.log syslog format."""
    records = []
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue

            ts = parse_syslog_timestamp(line)
            hostname, program, pid, message = extract_hostname_program(line)

            if hostname and hostname.isdigit():
                # Malformed syslog line: numeric token grabbed as hostname.
                sys.stderr.write(f"WARNING: skipping malformed syslog line: {line[:80]}\n")
                continue

            user = None

            user_match = re.search(r"user[= ]+(\w+)", line, re.IGNORECASE)
            if user_match:
                user = user_match.group(1)

            parsed = {
                "timestamp_raw": ts or "",
                "hostname": hostname or "",
                "program": program or "",
                "pid": int(pid) if pid else None,
                "user": user,
                "raw_message": line,
                "parsed_fields": {
                    "message": message or "",
                },
                "source_origin": "evidence_pack",
            }

            records.append(parsed)
    return records

def parse_audit_log(filepath):
    """Parse audit.log key=value format with multiline grouping."""
    records = []
    groups = {}

    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue

            msg_match = re.search(r"msg=audit\(([\d.]+):(\d+)\)", line)
            if msg_match:
                msg_id = msg_match.group(2)
                if msg_id not in groups:
                    groups[msg_id] = {"epoch": float(msg_match.group(1)), "lines": []}
                groups[msg_id]["lines"].append(line)

    total_lines = sum(len(g["lines"]) for g in groups.values())

    for msg_id, group_data in sorted(groups.items()):
        epoch = group_data["epoch"]
        lines = group_data["lines"]
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        merged_kv = {}
        all_hostnames = set()
        all_users = set()
        program = None
        pid = None

        for line in lines:
            kv = extract_key_values(line)
            merged_kv.update(kv)

            if "type" in merged_kv and not program:
                program = merged_kv["type"]

            if "hostname" in kv:
                all_hostnames.add(kv["hostname"])
            if "acct" in kv:
                all_users.add(kv["acct"])
            if "pid" in kv:
                try:
                    pid = int(kv["pid"])
                except ValueError:
                    pass

        hostname = ""
        for line in lines:
            h, prog, _, _ = extract_hostname_program(line)
            if h:
                hostname = h
                break

        if not hostname and all_hostnames:
            hostname = sorted(all_hostnames)[0]

        user = sorted(all_users)[0] if all_users else None

        record = {
            "timestamp_raw": ts,
            "hostname": hostname,
            "audit_type": merged_kv.get("type", ""),
            "pid": pid,
            "user": user,
            "raw_message": "\n".join(lines),
            "parsed_fields": merged_kv,
            "source_origin": "evidence_pack",
        }
        record["parsed_fields"]["audit_group_id"] = msg_id
        records.append(record)

    return records, total_lines

def parse_syslog(filepath):
    """Parse generic syslog format."""
    records = []
    with open(filepath, "r", errors="replace") as f:
         for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue

            ts = parse_syslog_timestamp(line)
            hostname, program, pid, message = extract_hostname_program(line)

            if hostname and hostname.isdigit():
                # Malformed syslog line: numeric token grabbed as hostname.
                sys.stderr.write(f"WARNING: skipping malformed syslog line: {line[:80]}\n")
                continue

            user = None

            user_match = re.search(r"user[= ]+(\w+)", line, re.IGNORECASE)
            if user_match:
                user = user_match.group(1)

            parsed = {
                "timestamp_raw": ts or "",
                "hostname": hostname or "",
                "program": program or "",
                "pid": int(pid) if pid else None,
                "user": user,
                "raw_message": line,
                "parsed_fields": {
                    "message": message or "",
                },
                "source_origin": "evidence_pack",
            }

            records.append(parsed)
    return records

# --- Parse each Linux source ---------------------------------------------------
auth_file = os.path.join(linux_dir, "auth.log")
audit_file = os.path.join(linux_dir, "audit.log")
syslog_file = os.path.join(linux_dir, "syslog")

auth_lines = count_lines(auth_file) if os.path.exists(auth_file) else 0
auth_records = parse_auth_log(auth_file) if os.path.exists(auth_file) else []

audit_records, audit_lines = parse_audit_log(audit_file) if os.path.exists(audit_file) else ([], 0)

syslog_lines = count_lines(syslog_file) if os.path.exists(syslog_file) else 0
syslog_records = parse_syslog(syslog_file) if os.path.exists(syslog_file) else []

combined = auth_records + audit_records + syslog_records

# --- Append student telemetry --------------------------------------------------
student_file = os.path.join(student_dir, "linux_events.json")
student_records = 0

if os.path.isfile(student_file):
    with open(student_file, "r", errors="replace") as f:
        content = f.read()

    try:
        data = json.loads(content)
        if isinstance(data, list):
            records = data
        elif isinstance(data, dict):
            records = [data]
        else:
            records = []
    except json.JSONDecodeError:
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
                continue

    for rec in records:
        if "source_origin" not in rec or rec["source_origin"] is None:
            rec["source_origin"] = "student_telemetry"
        combined.append(rec)
    student_records = len(records)

total_records = len(combined)

# --- Write output --------------------------------------------------------------
with open(output_file, "w") as f:
    for rec in combined:
        json.dump(rec, f, separators=(",", ":"))
        f.write("\n")

# --- Print summary ------------------------------------------------------------
print(f"parsing auth.log      ... {auth_lines:>6d} lines  -> ~{len(auth_records):d} records")
print(f"parsing audit.log     ... {audit_lines:>6d} lines  -> ~{len(audit_records):d} records (grouped)")
print(f"parsing syslog        ... {syslog_lines:>6d} lines  -> ~{len(syslog_records):d} records")
print(f"appending student telemetry ... {student_records:>6d} records")
print(f"linux_events.json: written")

PYTHON_EOF
