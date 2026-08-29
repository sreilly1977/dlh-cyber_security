#!/bin/bash
#
# Name: 10-timeline.sh
# Purpose: Produce a sorted chronological timeline index from enriched events.
#          Extracts key fields, builds human-readable summaries per event
#          category, and deduplicates consecutive identical entries within
#          a one-second window.
# Author: Steve - Cybersecurity Engineer
# Date: 29 August 2026
#
set -euo pipefail

WORKDIR="${WORKDIR:-$(pwd)}"
INPUT_FILE="${WORKDIR}/enriched_events.json"
OUTPUT_FILE="${WORKDIR}/timeline_index.json"

python3 - "${INPUT_FILE}" "${OUTPUT_FILE}" <<'PYTHON_EOF'
import json
import os
import re
import sys
from datetime import datetime, timezone

input_file = sys.argv[1]
output_file = sys.argv[2]

if not os.path.isfile(input_file):
    sys.stderr.write(f"ERROR: input file not found: {input_file}\n")
    sys.exit(1)

# --- Windows Event ID classification ------------------------------------------

AUTH_SUCCESS_IDS = {"4624"}
AUTH_FAIL_IDS = {"4625"}
AUTH_EVENT_IDS = AUTH_SUCCESS_IDS | AUTH_FAIL_IDS | {
    "4634", "4647", "4648", "4672",
    "4720", "4722", "4724", "4725", "4726", "4738",
    "4740", "4767", "4768", "4769", "4771", "4776",
    "4778", "4779", "4781", "4719", "4825",
}

PROCESS_EVENT_IDS = {"4688", "1", "3", "5"}

NETWORK_EVENT_IDS = {"5152", "5154", "5155", "5156", "5157"}

def derive_category(source_type, event):
    ec = event.get("event_category")
    if ec:
        return ec

    event_id = str(event.get("event_id", "") or "")
    if event_id in AUTH_EVENT_IDS:
        return "authentication"
    if event_id in PROCESS_EVENT_IDS:
        return "process"
    if event_id in NETWORK_EVENT_IDS:
        return "network"

    raw = (event.get("raw_message") or "").lower()

    if source_type == "linux_text":
        if any(kw in raw for kw in ("sshd", "sudo", "su:", "pam_",
                                    "authentication", "logon", "logoff",
                                    "failed password", "accepted password",
                                    "session opened", "session closed")):
            return "authentication"
        if any(kw in raw for kw in ("cron", "systemd", "started", "stopped",
                                    "process", "exec", "command")):
            return "process"
        return "audit"

    if source_type in ("firewall", "suricata", "pcap_flow"):
        if source_type == "suricata":
            return "network_alert"
        return "network"

    if source_type == "windows_json":
        if event_id in AUTH_EVENT_IDS:
            return "authentication"
        if event_id in PROCESS_EVENT_IDS:
            return "process"
        return "windows_event"

    return "other"

def derive_severity(event_category, event):
    sev = event.get("severity")
    if sev:
        return sev

    if event_category == "authentication":
        event_id = str(event.get("event_id", "") or "")
        if event_id in AUTH_FAIL_IDS:
            return "medium"
        raw = (event.get("raw_message") or "").lower()
        if "fail" in raw or "denied" in raw:
            return "medium"
        return "info"

    if event_category == "network_alert":
        return "high"

    return "info"

# --- Helper functions ---------------------------------------------------------

def get_field(event, *names):
    for name in names:
        val = event.get(name)
        if val is not None and str(val).strip():
            return str(val)
    return ""

def truncate(s, maxlen=80):
    if len(s) > maxlen:
        return s[:maxlen - 3] + "..."
    return s

def parse_raw_json(event):
    """Try to parse raw_message as JSON, return dict or None."""
    raw = event.get("raw_message")
    if not raw or not isinstance(raw, str):
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None

def parse_timestamp(ts_str, source_type=None, raw_message=None):
    """Parse various timestamp formats into datetime UTC object.
    Returns tuple: (datetime_utc, formatted_iso_string)"""
    if not ts_str or not isinstance(ts_str, str):
        # Try to extract from raw_message
        if raw_message:
            # Suricata style: "2026-03-18T00:00:31.026524+0000"
            match = re.search(r'"timestamp"\s*:\s*"([^"]+)"', raw_message)
            if match:
                ts_str = match.group(1)
        if not ts_str:
            return None, ""

    ts_str = ts_str.strip()

    # Try ISO with milliseconds and offset
    try:
        if "." in ts_str and "+" in ts_str:
            # Format: 2026-03-18T00:00:31.026524+0000
            base, offset_part = ts_str.rsplit("+", 1)
            offset_hours = int(offset_part[:2])
            offset_mins = int(offset_part[2:4]) if len(offset_part) >= 4 else 0
            dt = datetime.strptime(base.split(".")[0], "%Y-%m-%dT%H:%M:%S")
            from datetime import timedelta
            offset = timedelta(hours=offset_hours, minutes=offset_mins)
            dt = dt.replace(tzinfo=timezone(offset))
            return dt.astimezone(timezone.utc), dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        pass

    # Try ISO with Z suffix (with or without milliseconds)
    try:
        if "T" in ts_str:
            # Remove milliseconds if present
            base = re.sub(r'\.\d+', '', ts_str)
            if base.endswith("Z"):
                base = base[:-1]
            dt = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S")
            return dt.replace(tzinfo=timezone.utc), dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        pass

    # Try epoch seconds
    try:
        val = float(ts_str)
        if 1_000_000_000 < val < 2_000_000_000:
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt, dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError, OSError):
        pass

    return None, ts_str

# --- Summary generation ------------------------------------------------------

def build_summary(event_category, event):
    """Build a one-line human-readable summary per event category."""

    if event_category == "authentication":
        user = get_field(event, "user", "username", "account",
                        "target_user", "sam_accountname",
                        "subject_username", "target_username")
        result = get_field(event, "result", "outcome", "status")
        if not result:
            event_id = str(event.get("event_id", "") or "")
            if event_id in AUTH_SUCCESS_IDS:
                result = "success"
            elif event_id in AUTH_FAIL_IDS:
                result = "failed"
            else:
                raw = (event.get("raw_message") or "").lower()
                if "success" in raw or "granted" in raw or "accepted" in raw:
                    result = "success"
                elif "fail" in raw or "denied" in raw or "incorrect" in raw:
                    result = "failed"
                else:
                    result = "completed"
        action = get_field(event, "action", "event_action")
        if not action:
            raw = (event.get("raw_message") or "").lower()
            if "logoff" in raw or "logout" in raw or "closed" in raw:
                action = "logoff"
            else:
                action = "login"
        if user:
            return f"{user} {action} - {result}"
        return f"authentication {action} - {result}"

    if event_category == "process":
        proc = get_field(event, "process", "process_name", "image",
                        "exe", "command_line", "program", "target_process")
        if proc:
            if "/" in proc or "\\" in proc:
                proc = proc.split("/")[-1].split("\\")[-1]
            return f"Process {truncate(proc, 50)}"
        action = get_field(event, "action", "event_action")
        if action:
            return f"Process {action}"
        return "Process activity"

    if event_category == "powershell":
        event_data = event.get("event_data")
        if isinstance(event_data, dict):
            sb = event_data.get("ScriptBlockText")
            if sb:
                return f"PowerShell: {truncate(sb.strip(), 70)}"
        raw = event.get("raw_message", "")
        if raw and ": " in raw:
            match = re.search(r"characters\):\\n(.+)", raw)
            if match:
                return f"PowerShell: {truncate(match.group(1).strip(), 70)}"
            parts = raw.split("\n", 1)
            if len(parts) > 1:
                return f"PowerShell: {truncate(parts[1].strip(), 70)}"
        return "PowerShell activity"

    if event_category == "network_alert":
        sig = event.get("signature")
        if sig and isinstance(sig, str) and sig.strip():
            return truncate(f"IDS Alert: {sig}", 80)
        raw_obj = parse_raw_json(event)
        if raw_obj and isinstance(raw_obj, dict):
            alert = raw_obj.get("alert", {})
            if isinstance(alert, dict):
                sig = alert.get("signature", alert.get("msg", ""))
                if sig:
                    return truncate(f"IDS Alert: {sig}", 80)
        return "IDS Alert"

    if event_category == "network_flow":
        session_id = get_field(event, "session_id", "flow_id", "connection_id")
        src = get_field(event, "src_ip", "source_ip")
        dst = get_field(event, "dst_ip", "dest_ip", "destination_ip")
        proto = get_field(event, "protocol", "proto")
        duration = get_field(event, "duration_seconds", "duration")

        parts = []
        if src:
            parts.append(src)
        if dst:
            parts.append(f"-> {dst}")
        if proto:
            parts.append(f"({proto})")

        summary = " ".join(parts)
        if session_id:
            summary += f" [#{session_id}]"
        if duration:
            summary += f" ({duration}s)"
        return summary

    if event_category == "network":
        src = get_field(event, "src_ip", "source_ip")
        dst = get_field(event, "dst_ip", "dest_ip", "destination_ip")
        src_port = get_field(event, "src_port", "source_port")
        dst_port = get_field(event, "dst_port", "dest_port", "destination_port")
        proto = get_field(event, "protocol", "proto")

        parts = []
        if src:
            if src_port:
                parts.append(f"{src}:{src_port}")
            else:
                parts.append(src)
        else:
            parts.append("?")

        parts.append("->")

        if dst:
            if dst_port:
                parts.append(f"{dst}:{dst_port}")
            else:
                parts.append(dst)
        else:
            parts.append("?")

        summary = " ".join(parts)
        if proto:
            summary += f" ({proto})"

        action = get_field(event, "action")
        if action:
            summary += f" - {action}"

        return summary

    if event_category == "file":
        path = get_field(event, "path", "filepath", "filename", "target_file", "file_name")
        action = get_field(event, "action", "operation")
        if path:
            if "/" in path or "\\" in path:
                path = path.split("/")[-1].split("\\")[-1]
            summary = f"File {path}"
            if action:
                summary += f" {action}"
            return summary
        if action:
            return f"File {action}"
        return "File activity"

    if event_category == "audit":
        raw = event.get("raw_message", "")
        if not raw:
            return "Audit event"

        event_data = event.get("event_data")
        if isinstance(event_data, dict):
            msg = event_data.get("message", "")
            if msg:
                raw = msg

        proc_match = re.search(r'(\w+)\[(\d+)\]:\s*(.+)', raw)
        if proc_match:
            proc_name = proc_match.group(1)
            detail = proc_match.group(3)

            cmd_match = re.search(r'COMMAND=(.+)', detail)
            if cmd_match:
                cmd = cmd_match.group(1).strip()
                if "/" in cmd:
                    cmd = cmd.split("/")[-1]
                return f"Audit: {proc_name} {cmd}"

            user_match = re.search(r'user\s*[:=]\s*(\S+)', detail)
            if user_match:
                return f"Audit: {proc_name} user={user_match.group(1)}"

            if "session opened" in detail:
                sess_user_match = re.search(r'session opened for user (\S+)', detail)
                if sess_user_match:
                    return f"Audit: {proc_name} session opened for {sess_user_match.group(1)}"
                return f"Audit: {proc_name} session opened"
            if "session closed" in detail:
                return f"Audit: {proc_name} session closed"

            if "sudo" in proc_name.lower():
                user_match = re.search(r'^(\S+)\s*:', detail)
                if user_match:
                    return f"Audit: {proc_name} executed by {user_match.group(1)}"

            return f"Audit: {proc_name} {truncate(detail[:50], 50)}"

        proc_simple = re.search(r'\s(\w+)\s*\[(\d+)\]', raw)
        if proc_simple:
            return f"Audit: {proc_simple.group(1)}"

        return truncate(raw[:60], 60)

    if event_category == "service":
        svc = get_field(event, "service", "service_name", "name")
        action = get_field(event, "action", "state", "event_action")
        if svc:
            if action:
                return f"Service {svc} {action}"
            return f"Service {svc}"
        return "Service activity"

    msg = get_field(event, "raw_message")
    if msg:
        return truncate(msg, 80)
    return f"{event_category} event"

# --- Main processing ---------------------------------------------------------

entries = []

with open(input_file, "r", errors="replace") as f:
    for line_num, line in enumerate(f, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError:
            continue

        timestamp_raw = event.get("timestamp", "")
        hostname = event.get("hostname") or ""
        source_type = event.get("source_type") or ""

        # Parse timestamp properly for sorting
        dt, timestamp_normalized = parse_timestamp(timestamp_raw, source_type, event.get("raw_message"))

        event_category = derive_category(source_type, event)
        severity = derive_severity(event_category, event)
        summary = build_summary(event_category, event)

        entry = {
            "_sort_key": dt,  # Internal sort key, will be removed
            "timestamp": timestamp_normalized if timestamp_normalized else timestamp_raw,
            "hostname": hostname,
            "source_type": source_type,
            "event_category": event_category,
            "severity": severity,
            "summary": summary,
            "event_ref": line_num,
        }
        entries.append(entry)

# Sort ascending by parsed datetime, not raw string
entries.sort(key=lambda x: (x["_sort_key"] or datetime.min.replace(tzinfo=timezone.utc), x["event_ref"]))

# Deduplicate consecutive identical entries within one-second window
deduplicated = []
collapsed_count = 0
from datetime import timedelta

for i, entry in enumerate(entries):
    if deduplicated:
        prev = deduplicated[-1]
        prev_dt = prev["_sort_key"]
        curr_dt = entry["_sort_key"]

        if prev_dt and curr_dt:
            delta_seconds = abs((curr_dt - prev_dt).total_seconds())
        else:
            delta_seconds = float('inf')

        identical = (
            prev["hostname"] == entry["hostname"]
            and prev["source_type"] == entry["source_type"]
            and prev["event_category"] == entry["event_category"]
            and prev["severity"] == entry["severity"]
            and prev["summary"] == entry["summary"]
        )

        within_window = delta_seconds <= 1.0

        if identical and within_window:
            if "count" not in prev:
                prev["count"] = 1
            prev["count"] += 1
            collapsed_count += 1
            continue

    deduplicated.append(entry)

# Remove internal sort keys before writing output
for entry in deduplicated:
    del entry["_sort_key"]

# Write output
with open(output_file, "w") as f:
    for entry in deduplicated:
        json.dump(entry, f, separators=(",", ":"), default=str)
        f.write("\n")

# Report
total_read = len(entries)
total_written = len(deduplicated)
first_ts = deduplicated[0]["timestamp"] if deduplicated else ""
last_ts = deduplicated[-1]["timestamp"] if deduplicated else ""

print(f"enriched events read : {total_read}")
print(f"collapsed duplicates : {collapsed_count}")
print(f"timeline entries     : {total_written}")
print(f"first entry          : {first_ts}")
print(f"last entry           : {last_ts}")
print(f"timeline_index.json written")

PYTHON_EOF
