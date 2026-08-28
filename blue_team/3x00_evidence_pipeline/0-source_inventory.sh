#!/bin/bash
#
# Name: 0-source_inventory.sh
# Purpose: Inventory all source files in the evidence pack and produce
#          a structured manifest (source_inventory.json) plus a human-readable
#          summary on stdout.
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
EVIDENCE_PACK="${EVIDENCE_PACK:-$HOME/evidence_pack_primary}"
OUTPUT_FILE="${WORKDIR}/source_inventory.json"

# --- validate inputs ----------------------------------------------------------
if [[ ! -d "$EVIDENCE_PACK" ]]; then
    echo "ERROR: evidence pack directory not found: $EVIDENCE_PACK" >&2
    exit 1
fi

for subdir in windows linux network; do
    if [[ ! -d "${EVIDENCE_PACK}/${subdir}" ]]; then
        echo "WARNING: ${EVIDENCE_PACK}/${subdir}/ not found, skipping" >&2
    fi
done

# --- helper: determine source_type from directory + extension -----------------
get_source_type() {
    local dir="$1" ext="$2"
    case "$dir" in
        windows) echo "windows_json" ;;
        linux)   echo "linux_text" ;;
        network)
            case "$ext" in
                csv) echo "network_csv" ;;
                *)   echo "network_json" ;;
            esac
            ;;
    esac
}

# --- walk each category and build file list ------------------------------------
declare -a WIN_FILES=()
declare -a LIN_FILES=()
declare -a NET_FILES=()

while IFS= read -r -d '' f; do
    WIN_FILES+=("$f")
done < <(find "${EVIDENCE_PACK}/windows" -maxdepth 1 -type f 2>/dev/null | sort -z)

while IFS= read -r -d '' f; do
    LIN_FILES+=("$f")
done < <(find "${EVIDENCE_PACK}/linux" -maxdepth 1 -type f 2>/dev/null | sort -z)

while IFS= read -r -d '' f; do
    NET_FILES+=("$f")
done < <(find "${EVIDENCE_PACK}/network" -maxdepth 1 -type f 2>/dev/null | sort -z)

# --- build JSON manifest using Python for robust parsing -----------------------
python3 - "${WORKDIR}" "${EVIDENCE_PACK}" "${OUTPUT_FILE}" <<'PYTHON_EOF'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

workdir = sys.argv[1]
evidence_pack = sys.argv[2]
output_file = sys.argv[3]

def sha256_of(filepath):
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def file_size(filepath):
    return os.path.getsize(filepath)

def classify(dir_name, filename):
    if dir_name == "windows":
        return "windows_json"
    if dir_name == "linux":
        return "linux_text"
    if dir_name == "network":
        if filename.endswith(".csv"):
            return "network_csv"
        return "network_json"
    return "unknown"

def extract_timestamp_windows(line):
    """Extract timestamp_raw from a Windows NDJSON line."""
    try:
        rec = json.loads(line)
        ts = rec.get("timestamp_raw", "")
        if ts:
            return ts.replace("+00:00", "Z")
    except (json.JSONDecodeError, AttributeError):
        pass
    return None

def extract_timestamp_auditd(line):
    """Extract epoch timestamp from auditd msg=audit(EPOCH.SECS:ID)."""
    m = re.search(r"msg=audit\((\d+\.\d+):\d+\)", line)
    if m:
        epoch = float(m.group(1))
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return None

def extract_timestamp_syslog(line):
    """Parse 'Mon DD HH:MM:SS' syslog timestamp, assume 2026 UTC."""
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d{2})\s+(\d{2}):(\d{2}):(\d{2})", line)
    if m:
        month_name, day, hh, mm, ss = m.groups()
        months = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
                  "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
        mon = months.get(month_name, "01")
        return f"2026-{mon}-{day}{int(day)-int(day):>02d}T{hh}:{mm}:{ss}Z".replace(f"-{day}", f"-{int(day):02d}")
    return None

def extract_timestamp_firewall_csv(lines):
    """Extract first/last epoch timestamps from firewall CSV data rows."""
    first_ts = last_ts = None
    for i, line in enumerate(lines):
        if i == 0:
            continue  # skip header
        parts = line.strip().split(",")
        if len(parts) >= 1 and parts[0].strip().isdigit():
            dt = datetime.fromtimestamp(int(parts[0].strip()), tz=timezone.utc)
            iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            if first_ts is None:
                first_ts = iso
            last_ts = iso
    return first_ts, last_ts

def extract_timestamp_suricata(line):
    """Extract ISO timestamp from Suricata EVE JSON."""
    try:
        rec = json.loads(line)
        ts = rec.get("timestamp", "")
        if ts:
            # Format: 2026-03-18T00:00:31.026524+0000
            dt = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (json.JSONDecodeError, ValueError):
        pass
    return None

def extract_timestamp_pcap(line):
    """Extract start_time from pcap summary JSON (MM/DD/YYYY HH:MM:SS AM/PM)."""
    try:
        rec = json.loads(line)
        ts = rec.get("start_time", "")
        if ts:
            dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (json.JSONDecodeError, ValueError):
        pass
    return None

def process_file(filepath, dir_name):
    """Process a single file and return its metadata dict."""
    rel_path = os.path.relpath(filepath, evidence_pack)
    filename = os.path.basename(filepath)
    source_type = classify(dir_name, filename)
    size_bytes = file_size(filepath)
    sha = sha256_of(filepath)

    first_event_time = None
    last_event_time = None
    line_count = 0
    record_count = 0

    with open(filepath, "r", errors="replace") as f:
        lines = f.readlines()

    line_count = len([l for l in lines if l.strip()])

    if source_type == "windows_json":
        record_count = 0
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            record_count += 1
            ts = extract_timestamp_windows(stripped)
            if ts:
                if first_event_time is None:
                    first_event_time = ts
                last_event_time = ts

    elif source_type == "linux_text":
        record_count = line_count
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            ts = None
            if "msg=audit(" in stripped:
                ts = extract_timestamp_auditd(stripped)
            if ts is None:
                ts = extract_timestamp_syslog(stripped)
            if ts:
                if first_event_time is None:
                    first_event_time = ts
                last_event_time = ts

    elif source_type == "network_csv":
        record_count = max(len(lines) - 1, 0)  # minus header
        first_event_time, last_event_time = extract_timestamp_firewall_csv(lines)

    elif source_type == "network_json":
        record_count = 0
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            record_count += 1
            ts = None
            if filename == "suricata_eve.json":
                ts = extract_timestamp_suricata(stripped)
            elif filename == "pcap_summary.json":
                ts = extract_timestamp_pcap(stripped)
            if ts:
                if first_event_time is None:
                    first_event_time = ts
                last_event_time = ts

    entry = {
        "path": rel_path,
        "source_type": source_type,
        "size_bytes": size_bytes,
        "sha256": sha,
        "line_count": line_count,
        "record_count": record_count,
        "first_event_time": first_event_time,
        "last_event_time": last_event_time,
    }
    return entry

categories = [
    ("windows", "windows"),
    ("linux", "linux"),
    ("network", "network"),
]

manifest_files = []
category_stats = {}

for dir_name, _ in categories:
    dir_path = os.path.join(evidence_pack, dir_name)
    if not os.path.isdir(dir_path):
        continue
    entries = []
    total_bytes = 0
    for fname in sorted(os.listdir(dir_path)):
        fpath = os.path.join(dir_path, fname)
        if not os.path.isfile(fpath):
            continue
        entry = process_file(fpath, dir_name)
        entries.append(entry)
        total_bytes += entry["size_bytes"]
    manifest_files.extend(entries)
    category_stats[dir_name] = {"file_count": len(entries), "total_bytes": total_bytes}

# --- write manifest ------------------------------------------------------------
manifest = {
    "evidence_pack": evidence_pack,
    "file_count": len(manifest_files),
    "files": manifest_files,
    "summary": category_stats,
}

with open(output_file, "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")

# --- print human-readable summary ----------------------------------------------
def fmt_bytes(n):
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f} GB"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f} MB"
    if n >= 1_000:
        return f"{n / 1_000:.1f} KB"
    return f"{n} B"

labels = {"windows": "windows", "linux": "linux", "network": "network"}
total_files = 0
total_bytes = 0

for cat in ["windows", "linux", "network"]:
    stats = category_stats.get(cat, {"file_count": 0, "total_bytes": 0})
    total_files += stats["file_count"]
    total_bytes += stats["total_bytes"]
    print(f"{cat:8s}: {stats['file_count']:3d} files | {fmt_bytes(stats['total_bytes']):>8s}")

print(f"{'total':8s}: {total_files:3d} files | {fmt_bytes(total_bytes):>8s}")
print(f"manifest written to source_inventory.json")

PYTHON_EOF
