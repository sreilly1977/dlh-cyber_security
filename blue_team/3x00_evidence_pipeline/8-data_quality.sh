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

# --- Infer year from records with full ISO timestamps -------------------------
INFERRED_YEAR = 2026
year_counts = {}
with open(input_file, "r", errors="replace") as f:
    for i, line in enumerate(f):
        if i >= 10000:
            break
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rec = json.loads(stripped)
            ts = rec.get("timestamp", "")
            if isinstance(ts, str) and re.match(r"^\d{4}-", ts):
                yr = int(ts[:4])
                year_counts[yr] = year_counts.get(yr, 0) + 1
        except (json.JSONDecodeError, ValueError, KeyError):
            pass

if year_counts:
    INFERRED_YEAR = max(year_counts, key=year_counts.get)

# Evidence pack date range based on inferred year and observed data (March)
EXPECTED_START = datetime(INFERRED_YEAR, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
EXPECTED_END = datetime(INFERRED_YEAR, 3, 31, 23, 59, 59, tzinfo=timezone.utc)
TZ_TOLERANCE = timedelta(hours=12)

ISO_Z_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ISO_MS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z$")
ISO_OFFSET_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([+\-])(\d{2}):?(\d{2})$")
SYSLOG_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$")
MONTHS = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
          "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}

REPLACEMENT_CHAR = "\ufffd"

def parse_timestamp(ts_raw, year=None):
    """Parse timestamp string into datetime in UTC.
    Returns (datetime_utc, method) or (None, None)."""
    if not ts_raw or not isinstance(ts_raw, str):
        return None, None
    ts = ts_raw.strip()

    if ISO_Z_RE.match(ts):
        try:
            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc), "valid_iso_z"
        except ValueError:
            pass

    m = ISO_MS_RE.match(ts)
    if m:
        try:
            dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                         int(m.group(4)), int(m.group(5)), int(m.group(6)),
                         tzinfo=timezone.utc)
            return dt, "stripped_ms"
        except ValueError:
            pass

    m = ISO_OFFSET_RE.match(ts)
    if m:
        try:
            offset = timedelta(hours=int(m.group(9)), minutes=int(m.group(10)))
            if m.group(8) == "-":
                offset = -offset
            dt = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                         int(m.group(4)), int(m.group(5)), int(m.group(6)),
                         tzinfo=timezone(offset))
            return dt.astimezone(timezone.utc), "converted_offset_to_utc"
        except ValueError:
            pass

    m = SYSLOG_RE.match(ts)
    if m:
        mon = MONTHS.get(m.group(1), "01")
        yr = year if year else INFERRED_YEAR
        ts_str = f"{yr}-{mon}-{int(m.group(2)):02d}T{m.group(3)}:{m.group(4)}:{m.group(5)}Z"
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
            return dt.replace(tzinfo=timezone.utc), "syslog_inferred_year"
        except ValueError:
            pass

    try:
        dt = datetime.strptime(ts, "%m/%d/%Y %I:%M:%S %p")
        return dt.replace(tzinfo=timezone.utc), "pcap"
    except ValueError:
        pass

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
    if not has_encoding_issue(text):
        return text, False
    try:
        repaired = text.encode("latin-1").decode("utf-8")
        if REPLACEMENT_CHAR not in repaired:
            return repaired, True
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return text, False

def dedup_hash(record):
    """Hash from corrected values. None fields become empty strings."""
    ts = str(record.get("timestamp") or "")
    hostname = str(record.get("hostname") or "").lower()
    source_type = str(record.get("source_type") or "")
    raw_msg = str(record.get("raw_message") or "")
    key = f"{ts}|{hostname}|{source_type}|{raw_msg}"
    return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()

def snapshot_record(record):
    """Capture key fields from a record for forensic logging."""
    return {k: record.get(k) for k in (
        "timestamp", "hostname", "source_type", "raw_message",
        "event_id", "src_ip", "dst_ip", "record_id"
    )}

# --- Stats -------------------------------------------------------------------
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
            cleaning_log.append({
                "defect_type": "json_parse_error",
                "original_value": stripped[:500],
                "corrected_value": None,
                "record_id": "unknown",
                "reason": f"Line {line_num}: JSON parse error - {e}",
            })
            continue

        record_id = record.get("record_id", "unknown")

        # Capture ORIGINAL snapshot BEFORE any mutations for forensic logging
        orig_snapshot = snapshot_record(record)
        orig_ts = record.get("timestamp", "")
        orig_hostname = record.get("hostname")
        orig_raw_msg = record.get("raw_message", "")

        corrections_made = []

        # 1. Hostname case normalization
        hostname = record.get("hostname")
        if hostname and isinstance(hostname, str) and hostname != hostname.lower():
            lowered = hostname.lower()
            record["hostname"] = lowered
            stats_hostname += 1
            cleaning_log.append({
                "defect_type": "hostname_case",
                "original_value": hostname,
                "corrected_value": lowered,
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
                    "original_value": orig_raw_msg[:500],
                    "corrected_value": repaired[:500],
                    "record_id": record_id,
                    "reason": "Re-decoded from Latin-1 to UTF-8",
                })
            else:
                cleaning_log.append({
                    "defect_type": "encoding_error",
                    "original_value": orig_raw_msg[:500],
                    "corrected_value": None,
                    "record_id": record_id,
                    "reason": "Encoding issue detected but repair failed — record retained with warning",
                })

        # 3. Timestamp validation and repair
        dt, method = parse_timestamp(orig_ts, year=INFERRED_YEAR)

        if not dt:
            stats_mal_detected += 1

            # Attempt repair: strip non-standard chars
            cleaned_ts = re.sub(r"[^0-9TZ:.\-+]", "", orig_ts)
            if cleaned_ts and cleaned_ts != orig_ts:
                repaired_dt, _ = parse_timestamp(cleaned_ts, year=INFERRED_YEAR)
                if repaired_dt:
                    repaired_ts = fmt_ts(repaired_dt)
                    record["timestamp"] = repaired_ts
                    stats_mal_repaired += 1
                    cleaning_log.append({
                        "defect_type": "malformed_timestamp",
                        "original_value": orig_ts,
                        "corrected_value": repaired_ts,
                        "record_id": record_id,
                        "reason": "Stripped invalid characters and reparsed timestamp",
                        "original_record": orig_snapshot,
                    })
                    dt = repaired_dt

            if not dt:
                stats_mal_dropped += 1
                cleaning_log.append({
                    "defect_type": "unrepairable_timestamp",
                    "original_value": orig_ts,
                    "corrected_value": None,
                    "record_id": record_id,
                    "reason": f"Could not parse timestamp '{orig_ts}' with any fallback method. Record dropped from cleaned dataset.",
                    "original_record": orig_snapshot,
                })
                continue
        elif method == "converted_offset_to_utc":
            utc_ts = fmt_ts(dt)
            if utc_ts != orig_ts:
                record["timestamp"] = utc_ts
                cleaning_log.append({
                    "defect_type": "timezone_offset_normalized",
                    "original_value": orig_ts,
                    "corrected_value": utc_ts,
                    "record_id": record_id,
                    "reason": f"Converted timezone offset to UTC: {orig_ts} -> {utc_ts}",
                })

        # 4. Timezone anomaly check (flag only, don't drop)
        if dt < EXPECTED_START - TZ_TOLERANCE or dt > EXPECTED_END + TZ_TOLERANCE:
            stats_tz_flagged += 1
            cleaning_log.append({
                "defect_type": "suspected_wrong_tz",
                "original_value": orig_ts,
                "corrected_value": record.get("timestamp", orig_ts),
                "record_id": record_id,
                "reason": f"Timestamp falls outside expected evidence pack date range "
                          f"({EXPECTED_START.strftime('%Y-%m-%d')} to {EXPECTED_END.strftime('%Y-%m-%d')}) "
                          f"by more than 12 hours. Flagged for analyst review.",
                "original_record": orig_snapshot,
            })

        # 5. Deduplication on corrected values
        dhash = dedup_hash(record)
        if dhash in seen_hashes:
            stats_dup_detected += 1
            stats_dup_removed += 1
            cleaning_log.append({
                "defect_type": "duplicate",
                "original_value": orig_ts,
                "corrected_value": None,
                "record_id": record_id,
                "reason": "Duplicate of earlier record with identical timestamp, hostname, "
                          "source_type, and raw_message after normalization",
                "original_record": orig_snapshot,
            })
            continue

        seen_hashes.add(dhash)

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
