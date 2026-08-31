#!/bin/bash
#
# Name: 3-event_taxonomy.sh
# Purpose: Build MedDefense event type taxonomy mapping raw events to canonical labels
# Author: Steve - Cybersecurity Engineer
# Date: 31 August 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
ENRICHED_EVENTS="${HANDOFF_DIR}/data/enriched_events.json"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

if [[ ! -f "${ENRICHED_EVENTS}" ]]; then
    echo "ERROR: Enriched events file not found at ${ENRICHED_EVENTS}" >&2
    exit 1
fi

export ENRICHED_EVENTS BASELINE_PKG

python3 -W error - << 'PYEOF'
import json
import os
import sys
from collections import Counter

CANONICAL_LABELS = [
    "login_success",
    "login_failure",
    "logout",
    "account_lockout",
    "privilege_escalation",
    "process_start",
    "process_stop",
    "child_process_spawn",
    "file_read_sensitive",
    "file_write_sensitive",
    "file_permission_change",
    "network_connection_outbound",
    "network_connection_inbound",
    "network_alert",
    "network_blocked",
]

TAXONOMY_RULES = [
    # --- Windows: Sysmon-style IDs ---
    {"source_type": "windows_json", "match": {"event_id": 1},
     "label": "process_start"},
    {"source_type": "windows_json", "match": {"event_id": 3},
     "label": "network_connection_outbound"},
    {"source_type": "windows_json", "match": {"event_id": 7},
     "label": "process_start"},
    {"source_type": "windows_json", "match": {"event_id": 11},
     "label": "file_write_sensitive"},
    {"source_type": "windows_json", "match": {"event_id": 23},
     "label": "file_write_sensitive"},
    {"source_type": "windows_json", "match": {"event_id": 13},
     "label": "file_permission_change"},
    {"source_type": "windows_json", "match": {"event_id": 12},
     "label": "file_permission_change"},
    {"source_type": "windows_json", "match": {"event_id": 22},
     "label": "file_permission_change"},
    {"source_type": "windows_json", "match": {"event_id": 4104},
     "label": "child_process_spawn"},
    {"source_type": "windows_json", "match": {"event_id": 4698},
     "label": "process_start"},
    {"source_type": "windows_json", "match": {"event_id": 4702},
     "label": "process_start"},
    {"source_type": "windows_json", "match": {"event_id": 5140},
     "label": "network_connection_inbound"},
    {"source_type": "windows_json", "match": {"event_id": 5156},
     "label": "network_connection_outbound"},
    {"source_type": "windows_json", "match": {"event_id": 4722},
     "label": "privilege_escalation"},
    {"source_type": "windows_json", "match": {"event_id": 4726},
     "label": "logout"},

    # --- Windows: classic Security event IDs ---
    {"source_type": "windows_json", "match": {"event_id": 4624}, "label": "login_success"},
    {"source_type": "windows_json", "match": {"event_id": 4625}, "label": "login_failure"},
    {"source_type": "windows_json", "match": {"event_id": 4634}, "label": "logout"},
    {"source_type": "windows_json", "match": {"event_id": 4647}, "label": "logout"},
    {"source_type": "windows_json", "match": {"event_id": 4672}, "label": "privilege_escalation"},
    {"source_type": "windows_json", "match": {"event_id": 4740}, "label": "account_lockout"},
    {"source_type": "windows_json", "match": {"event_id": 4728}, "label": "privilege_escalation"},
    {"source_type": "windows_json", "match": {"event_id": 4720}, "label": "privilege_escalation"},
    {"source_type": "windows_json", "match": {"event_id": 4688}, "label": "process_start"},
    {"source_type": "windows_json", "match": {"event_id": 4689}, "label": "process_stop"},
    {"source_type": "windows_json", "match": {"event_id": 4663}, "label": "file_read_sensitive"},
    {"source_type": "windows_json", "match": {"event_id": 4660}, "label": "file_read_sensitive"},
    {"source_type": "windows_json", "match": {"event_id": 4656}, "label": "file_write_sensitive"},
    {"source_type": "windows_json", "match": {"event_id": 4670}, "label": "file_permission_change"},
    {"source_type": "windows_json", "match": {"event_id": 4657}, "label": "file_permission_change"},
    {"source_type": "windows_json", "match": {"event_id": 7045}, "label": "process_start"},

    # --- Linux syslog: failures first, then specific successes ---
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "Failed password"}},
     "label": "login_failure"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "Invalid user"}},
     "label": "login_failure"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "authentication failure"}},
     "label": "login_failure"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "Accepted password"}},
     "label": "login_success"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "Accepted publickey"}},
     "label": "login_success"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "imap-login"}},
     "label": "login_success"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "session opened"}},
     "label": "login_success"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "(svc_backup)"}},
     "label": "login_success"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "systemd-logind"}},
     "label": "login_success"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "session closed"}},
     "label": "logout"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "disconnect"}},
     "label": "logout"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "sudo"}},
     "label": "privilege_escalation"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": " su:"}},
     "label": "privilege_escalation"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "polkitd"}},
     "label": "privilege_escalation"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "useradd"}},
     "label": "privilege_escalation"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "usermod"}},
     "label": "privilege_escalation"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "CRON"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "systemd"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "ClamAV"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "daily.cvd"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "Suricata version"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "capture threads are running"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "builtin:omfwd"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "rsyslogd"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "CMD ("}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "systemd: Started"}},
     "label": "process_start"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "chmod"}},
     "label": "file_permission_change"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "UFW"}},
     "label": "network_blocked"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "bound to"}},
     "label": "network_connection_inbound"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "connect"}},
     "label": "network_connection_outbound"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "synchronized"}},
     "label": "network_connection_outbound"},
    {"source_type": "linux_text",
     "match": {"raw_message": {"__contains": "sshd"}},
     "label": "login_success"},

    # --- Firewall ---
    {"source_type": "firewall", "match": {"action": "BLOCK"}, "label": "network_blocked"},
    {"source_type": "firewall",
     "match": {"action": "ALLOW", "src_zone": "INTERNET"},
     "label": "network_connection_inbound"},
    {"source_type": "firewall", "match": {"action": "ALLOW"},
     "label": "network_connection_outbound"},

    # --- Suricata ---
    {"source_type": "suricata", "match": {"event_category": "network_alert"},
     "label": "network_alert"},

    # --- PCAP flows ---
    {"source_type": "pcap_flow", "match": {"src_zone": "INTERNET"},
     "label": "network_connection_inbound"},
    {"source_type": "pcap_flow", "match": {"dst_zone": "INTERNET"},
     "label": "network_connection_outbound"},
    {"source_type": "pcap_flow", "match": {"event_category": "network_flow"},
     "label": "network_connection_outbound"},
]

RULES_BY_SOURCE = {}
for rule in TAXONOMY_RULES:
    RULES_BY_SOURCE.setdefault(rule["source_type"], []).append(rule)

def field_matches(actual, expected):
    """Match a field value: exact equality or {'__contains': substr}."""
    if isinstance(expected, dict) and "__contains" in expected:
        needle = expected["__contains"]
        return actual is not None and needle in str(actual)
    return str(actual) == str(expected)

def label_event(event):
    """Apply taxonomy rules to determine canonical label."""
    source_type = event.get("source_type", "unknown")

    for rule in RULES_BY_SOURCE.get(source_type, []):
        if all(field_matches(event.get(f), v) for f, v in rule["match"].items()):
            return rule["label"]

    return "unlabeled"

def main():
    enriched_path = os.environ["ENRICHED_EVENTS"]
    baseline_pkg = os.environ["BASELINE_PKG"]

    taxonomy = {label: [] for label in CANONICAL_LABELS}
    for rule in TAXONOMY_RULES:
        taxonomy[rule["label"]].append({
            "source_type": rule["source_type"],
            "match": rule["match"],
            "label": rule["label"],
        })

    label_counts = Counter()

    labeled_file = os.path.join(baseline_pkg, "labeled_events.json")
    os.makedirs(os.path.dirname(labeled_file), exist_ok=True)

    with open(enriched_path, "r") as fin, open(labeled_file, "w") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            canonical_label = label_event(event)
            event["canonical_label"] = canonical_label
            label_counts[canonical_label] += 1

            fout.write(json.dumps(event, separators=(",", ":")) + "\n")

    total_records = sum(label_counts.values())

    taxonomy_file = os.path.join(baseline_pkg, "event_taxonomy.json")
    with open(taxonomy_file, "w") as f:
        json.dump(taxonomy, f, indent=2)

    unlabeled_count = label_counts.get("unlabeled", 0)
    print(f"taxonomy rules         : {len(TAXONOMY_RULES)}")
    print(f"records labeled        : {total_records - unlabeled_count}")
    print(f"records unlabeled      : {unlabeled_count}")
    print("canonical label distribution (top 10):")
    for label, count in label_counts.most_common(10):
        print(f"  {label:<30} {count:>8}")
    print("event_taxonomy.json written")
    print("labeled_events.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
