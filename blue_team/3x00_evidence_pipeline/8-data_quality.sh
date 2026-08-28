#!/bin/bash
#
# Name: 8-data_quality.sh
# Purpose: Detect and repair intentional quality defects in normalized_events.json.
#          Produces cleaned_events.json plus cleaning_log.json with one entry
#          per correction (defect_type, original_value, corrected_value,
#          record_id, reason).
# Author: Steve - Cybersecurity Engineer
# Date: 28 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
INPUT_FILE="${WORKDIR}/normalized_events.json"
OUTPUT_FILE="${WORKDIR}/cleaned_events.json"
LOG_FILE="${WORKDIR}/cleaning_log.json"

python3 - "${WORKDIR}" "${INPUT_FILE}" "${OUTPUT_FILE}" "${LOG_FILE}" <<'PYTHON_EOF'
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta

workdir = sys.argv[1]
input_file = sys.argv[2]
output_file = sys.argv[3]
log_file = sys.argv[4]

for d in (os.path.dirname(output_file) or ".", os.path.dirname(log_file) or "."):
    if d and not os.path.exists(d):
        os.makedirs(d, exist_ok=True)

if not os.path.isfile(input_file):
    sys.stderr.write(f"ERROR: input file not found: {input_file}\n")
    sys.exit(1)

# Evidence pack date range: March 2026
EXPECTED_START = datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
EXPECTED_END = datetime(2026, 3, 31, 23, 59, 59, tzinfo=timezone.utc)
TZ_TOLERANCE = timedelta(hours=12)

ISO_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ISO_MS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z$")
ISO_OFFSET_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([+\-])(\d{2}):?(\d{2})$")
SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
MONTHS = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
          "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}

REPLACEMENT_CHAR = "\ufffd"

def parse_timestamp(ts_raw):
    """Parse timestamp string into datetime in UTC.
    Properly converts timezone offsets to UTC.
    Returns (datetime_utc, method) or (None, None)."""
    if not ts_raw or not isinstance(ts_raw, str):
        return None, None
    ts = ts_raw.strip()

    # Method 1: Valid ISO 8601 Z
    if ISO_Z_RE.match(ts):
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc), "valid_iso_z"
        except ValueError:
            pass

    # Method 2: ISO with milliseconds
    m = ISO_MS_RE.match(ts)
    if m:
        try:
            year, mon, day, hh, mm, ss = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6))
            dt = datetime(year, mon, day, hh, mm, ss, tzinfo=timezone.utc)
            return dt, "stripped_ms"
        except ValueError:
            pass

    # Method 3: ISO with timezone offset - PROPERLY convert to UTC
    m = ISO_OFFSET_RE.match(ts)
    if m:
        try:
            year = int(m.group(1))
            mon = int(m.group(2))
            day = int(m.group(3))
            hh = int(m.group(4))
            mm = int(m.group(5))
            ss = int(m.group(6))
            sign = m.group(8)
            off_hh = int(m.group(9))
            off_mm = int(m.group(10))

            # Create the datetime with the original offset
            offset = timedelta(hours=off_hh, minutes=off_mm)
            if sign == "-":
                offset = -offset

            dt = datetime(year, mon, day, hh, mm, ss, tzinfo=timezone(offset))

            # Convert to UTC
            dt_utc = dt.astimezone(timezone.utc)
            return dt_utc, "converted_offset_to_utc"
        except ValueError:
            pass

    # Method 4: Syslog format
    m = SYSLOG_RE.match(ts)
    if m:
        mon = MONTHS.get(m.group(1), "01")
        ts_str = f"2026-{mon}-{int(m.group(2)):02d}T{m.group(3)}:{m.group(4)}:{m.group(5)}Z"
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc), "syslog"
        except ValueError:
            pass

    # Method 5: pcap format
    try:
        dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=timezone.utc), "pcap"
    except ValueError:
        pass

    # Method 6: Unix epoch
    try:
        val = float(ts)
        if 1_000_000_000 < val < 2_000_000_000:
            return datetime.fromtimestamp(val, tz=timezone.utc), "epoch"
    except (ValueError, OSError):
        pass

    return None, None

def fmt_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def has_encoding_issue(text):
    if not text:
        return False
    return REPLACEMENT_CHAR in text

def attempt_latin1_repair(text):
    """Repair mojibake by reversing a Latin-1-as-UTF-8 double encoding.
    The standard pattern: text was encoded as UTF-8, then incorrectly decoded
    as Latin-1, producing mojibake. Reverse: encode as Latin-1, decode as UTF-8."""
    if not has_encoding_issue(text):
        return text, False
    try:
        repaired = text.encode("latin-1").decode("utf-8")
        if REPLACEMENT_CHAR not in repaired:
            return repaired, True
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return text, False

def dedup_hash_original(timestamp, hostname, source_type, raw_message):
    """Compute dedup hash from ORIGINAL values before any mutations."""
    key = f"{timestamp}|{hostname or ''}|{source_type or ''}|{raw_message or ''}"
    return hashlib.md5(key.encode("utf-8", errors="replace")).hexdigest()

stats_mal_detected = 0
stats_mal_repaired = 0
stats_mal_dropped = 0
stats_dup_detected = 0
stats_dup_removed = 0
stats_hostname = 0
stats_enc_detected = 0
stats_enc_repaired = 0
stats_tz_flagged = 0

cleaning_log = []
seen_hashes = set()

with open(input_file, "r", errors="replace") as fin, \
     open(output_file, "w") as fout:

    for line_num, line in enumerate(fin, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as e:
            stats_mal_dropped += 1
            cleaning_log.append({
                "defect_type": "json_parse_error",
                "original_value": stripped[:200],
                "corrected_value": None,
                "record_id": "unknown",
                "reason": f"Line {line_num}: JSON parse error - {e}",
            })
            continue

        record_id = record.get("record_id", "unknown")

        # Capture ORIGINAL values for dedup BEFORE any mutations
        orig_timestamp = record.get("timestamp", "")
        orig_hostname = record.get("hostname")
        orig_source_type = record.get("source_type", "")
        orig_raw_message = record.get("raw_message", "")

        # 1. Hostname case normalization
        hostname = record.get("hostname")
        if hostname and isinstance(hostname, str) and hostname != hostname.lower():
            record["hostname"] = hostname.lower()
            stats_hostname += 1
            cleaning_log.append({
                "defect_type": "hostname_case",
                "original_value": hostname,
                "corrected_value": hostname.lower(),
                "record_id": record_id,
                "reason": "Normalized hostname to lowercase for consistency",
            })

        # 2. Encoding repair
        raw_msg = record.get("raw_message", "")
        if raw_msg and has_encoding_issue(raw_msg):
            stats_enc_detected += 1
            repaired, ok = attempt_latin1_repair(raw_msg)
            if ok:
                record["raw_message"] = repaired
                stats_enc_repaired += 1
                cleaning_log.append({
                    "defect_type": "encoding_error",
                    "original_value": raw_msg[:200],
                    "corrected_value": repaired[:200],
                    "record_id": record_id,
                    "reason": "Re-decoded from Latin-1 to UTF-8",
                })
            else:
                cleaning_log.append({
                    "defect_type": "encoding_error",
                    "original_value": raw_msg[:200],
                    "corrected_value": None,
                    "record_id": record_id,
                    "reason": "Encoding issue detected but repair failed",
                })

        # 3. Timestamp validation and repair
        original_ts = record.get("timestamp", "")
        dt, method = parse_timestamp(original_ts)

        if not dt:
            stats_mal_detected += 1

            # Attempt repair: strip non-standard chars
            cleaned_ts = re.sub(r"[^0-9TZ:.\-+]", "", original_ts)
            if cleaned_ts and cleaned_ts != original_ts:
                repaired_dt, _ = parse_timestamp(cleaned_ts)
                if repaired_dt:
                    repaired_ts = fmt_ts(repaired_dt)
                    record["timestamp"] = repaired_ts
                    stats_mal_repaired += 1
                    cleaning_log.append({
                        "defect_type": "malformed_timestamp",
                        "original_value": original_ts,
                        "corrected_value": repaired_ts,
                        "record_id": record_id,
                        "reason": "Stripped invalid characters and reparsed",
                    })
                    dt = repaired_dt

            if not dt:
                stats_mal_dropped += 1
                cleaning_log.append({
                    "defect_type": "unrepairable_timestamp",
                    "original_value": original_ts,
                    "corrected_value": None,
                    "record_id": record_id,
                    "reason": f"Could not parse timestamp. Record dropped.",
                })
                continue
        elif method == "converted_offset_to_utc":
            # If the offset was converted, update the timestamp to UTC form
            utc_ts = fmt_ts(dt)
            if utc_ts != original_ts:
                record["timestamp"] = utc_ts
                cleaning_log.append({
                    "defect_type": "timezone_offset_normalized",
                    "original_value": original_ts,
                    "corrected_value": utc_ts,
                    "record_id": record_id,
                    "reason": f"Converted timezone offset to UTC: {original_ts} -> {utc_ts}",
                })

        # 4. Timezone anomaly check
        if dt < EXPECTED_START - TZ_TOLERANCE or dt > EXPECTED_END + TZ_TOLERANCE:
            stats_tz_flagged += 1
            cleaning_log.append({
                "defect_type": "suspected_wrong_tz",
                "original_value": original_ts,
                "corrected_value": record.get("timestamp", original_ts),
                "record_id": record_id,
                "reason": f"Timestamp falls outside expected evidence pack date range (March 2026) by more than 12 hours",
            })

        # 5. Deduplication - using ORIGINAL values for forensic integrity
        dhash = dedup_hash_original(orig_timestamp, orig_hostname, orig_source_type, orig_raw_message)
        if dhash in seen_hashes:
            stats_dup_detected += 1
            stats_dup_removed += 1
            cleaning_log.append({
                "defect_type": "duplicate",
                "original_value": orig_timestamp,
                "corrected_value": None,
                "record_id": record_id,
                "reason": "Duplicate of earlier record (same original timestamp, hostname, source_type, raw_message)",
            })
            continue

        seen_hashes.add(dhash)

        # Write cleaned record immediately (streaming output)
        json.dump(record, fout, separators=(",", ":"), default=str)
        fout.write("\n")

# --- Write cleaning log ------------------------------------------------------

with open(log_file, "w") as f:
    json.dump(cleaning_log, f, indent=2)
    f.write("\n")

# --- Print summary ------------------------------------------------------------

print(f"malformed timestamps   :  detected {stats_mal_detected:>6} repaired {stats_mal_repaired:>6} dropped {stats_mal_dropped:>6}")
print(f"duplicates             :  detected {stats_dup_detected:>6} removed {stats_dup_removed:>6}")
print(f"hostname case          :  normalized {stats_hostname:>6}")
print(f"encoding errors        :  detected {stats_enc_detected:>6} repaired {stats_enc_repaired:>6}")
print(f"suspected wrong tz     :  flagged {stats_tz_flagged:>6}")
print(f"")
print(f"cleaned_events.json    written")
print(f"cleaning_log.json      written")

PYTHON_EOF
