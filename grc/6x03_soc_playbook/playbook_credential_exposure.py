#!/usr/bin/env python3
# Name: playbook_credential_exposure.py
# Purpose: Executable credential exposure playbook for the 6x03 SOC Playbook.
#          Enriches the alert source IP via enrich_ioc, checks the involved
#          account against privileged_accounts.json, applies the credential
#          exposure decision matrix, creates a pre-enriched case, and flags
#          hosts to isolation_queue.json for HUMAN-authorized action only.
#          The playbook never isolates a host and never calls an EDR API.
# Author: Steve - Cybersecurity Engineer
# Date: 08 November 2026

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from enrich_ioc import enrich_ioc
import case_manager

AUDIT_LOG = "playbook_audit.log"
FEED_PATH = "ioc_feed.json"
PRIV_ACCOUNTS_PATH = "privileged_accounts.json"
ISOLATION_QUEUE_PATH = "isolation_queue.json"

# MITRE ATT&CK enrichment for techniques observed in MedDefense endpoint alerts.
MITRE_TECHNIQUES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1550.002": "Use Alternate Authentication Material: Pass the Hash",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
}

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def warn(message: str) -> None:
    print(f"[warning] {message}", file=sys.stderr)

def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)

def check_privilege(username: str, inventory: dict) -> str:
    """Return 'Domain Admin', 'Server Admin' or 'Standard' for the account."""
    if username in inventory.get("domain_admins", []):
        return "Domain Admin"
    if username in inventory.get("server_admins", []):
        return "Server Admin"
    return "Standard"

def decide(ip_verdict: str, privilege: str) -> dict:
    """Credential exposure decision matrix.

    Returns playbook_verdict, case_severity, case_status and whether the
    host is written to the isolation queue (human authorization still
    required before any actual isolation).
    """
    is_da = privilege == "Domain Admin"
    is_sa = privilege == "Server Admin"

    if ip_verdict == "BLOCK":
        # Known-bad source: escalate regardless of account privilege.
        return {"verdict": "ESCALATE", "severity": "Critical",
                "status": "escalated", "queue": True}
    if ip_verdict == "INVESTIGATE":
        if is_da:
            return {"verdict": "ESCALATE", "severity": "Critical",
                    "status": "escalated", "queue": True}
        # SA or standard account: High, manual review, no queue.
        return {"verdict": "MANUAL_REVIEW", "severity": "High",
                "status": "open", "queue": False}
    # ALLOW: internal or benign source; privilege drives the outcome.
    if is_da:
        # Privileged account anomaly escalates even from an internal IP,
        # but the source is not known-bad, so no isolation flag.
        return {"verdict": "ESCALATE", "severity": "High",
                "status": "escalated", "queue": False}
    return {"verdict": "MANUAL_REVIEW",
            "severity": "High" if is_sa else "Medium",
            "status": "open", "queue": False}

def queue_reason(alert: dict, privilege: str, ip_result: dict) -> str:
    technique = alert["raw_log"].get("mitre_technique", "unknown technique")
    return (f"{technique} from {ip_result['verdict']}-verdict source IP "
            f"{alert['raw_log'].get('source_ip')} by {privilege} account "
            f"{alert['raw_log'].get('username')}")

def append_to_isolation_queue(entry: dict) -> None:
    """Append an entry to isolation_queue.json, creating the file with an
    empty list if it does not exist. This is a HUMAN authorization queue;
    no isolation action is performed by this playbook."""
    queue_path = Path(ISOLATION_QUEUE_PATH)
    if queue_path.exists():
        queue = json.loads(queue_path.read_text(encoding="utf-8"))
    else:
        queue = []
    queue.append(entry)
    queue_path.write_text(json.dumps(queue, indent=2) + "\n", encoding="utf-8")

def append_audit(run_ts: str, alert_id: str, host: str, username: str,
                 ip_result: dict, privilege: str, decision: dict,
                 case_id: str) -> None:
    line = (f"{run_ts} | CREDENTIAL_EXPOSURE | {alert_id} | Host:{host} | "
            f"User:{username} | IPVerdict:{ip_result['verdict']} | "
            f"Privilege:{privilege} | Case:{case_id} | "
            f"Severity:{decision['severity']} | "
            f"IsolationQueued:{'yes' if decision['queue'] else 'no'}\n")
    with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
        fh.write(line)

def print_summary(run_ts: str, alert: dict, host: str, username: str,
                  privilege: str, ip_result: dict, technique_desc: str,
                  decision: dict, case_id: str) -> None:
    print(f"[{run_ts}] CREDENTIAL EXPOSURE PLAYBOOK")
    print(f"Alert      : {alert['alert_id']}")
    print(f"Host       : {host}")
    print(f"User       : {username}  Privilege: {privilege}")
    print(f"Source IP  : {alert['raw_log'].get('source_ip')}  "
          f"Verdict: {ip_result['verdict']}  Score: {ip_result['score']}")
    print(f"MITRE      : {technique_desc}")
    print(f"Verdict    : {decision['verdict']}")
    print(f"Case       : {case_id}  Severity: {decision['severity']}  "
          f"Status: {decision['status']}")
    if decision["queue"]:
        print("Action     : Host written to isolation_queue.json for analyst authorization")
    else:
        print("Action     : Case queued for analyst review; no isolation flag raised")

def run_playbook(alert_path: str) -> int:
    alert = load_json(alert_path)
    run_ts = utc_now()

    raw = alert.get("raw_log", {})
    alert_id = alert["alert_id"]
    source_ip = raw.get("source_ip")
    username = raw.get("username")
    host = raw.get("host")
    technique = raw.get("mitre_technique")

    missing = [name for name, val in
               (("source_ip", source_ip), ("username", username), ("host", host))
               if not val]
    if missing:
        raise ValueError(f"missing required raw_log field(s): {', '.join(missing)}")

    # Enrich the source IP.
    try:
        ip_result = enrich_ioc(source_ip, FEED_PATH)
    except Exception as exc:
        warn(f"enrichment failed for {source_ip}: {exc}; defaulting to INVESTIGATE")
        ip_result = {"ioc": source_ip, "type": "ipv4", "score": 30,
                     "verdict": "INVESTIGATE",
                     "feed_result": {"in_malicious_feed": False,
                                     "in_benign_list": False}}

    inventory = load_json(PRIV_ACCOUNTS_PATH)
    privilege = check_privilege(username, inventory)
    technique_desc = (f"{technique} {MITRE_TECHNIQUES.get(technique, 'Unknown technique')}"
                      if technique else "No technique provided")

    decision = decide(ip_result["verdict"], privilege)

    description = (f"Automated credential exposure triage for {alert_id} "
                   f"(rule: {alert.get('rule_name', 'n/a')}). Source IP "
                   f"{source_ip} verdict {ip_result['verdict']}/"
                   f"{ip_result['score']}; account {username} is {privilege}.")
    case_id = case_manager.create_case(
        alert_id=alert_id,
        severity=decision["severity"],
        title=f"Credential Exposure: {technique_desc}",
        description=description,
        iocs=[{
            "ioc_value": ip_result["ioc"],
            "ioc_type": ip_result["type"],
            "verdict": ip_result["verdict"],
            "score": ip_result["score"],
        }],
    )

    note = (f"Playbook verdict: {decision['verdict']}. "
            f"Source IP {source_ip}: verdict {ip_result['verdict']}, "
            f"score {ip_result['score']}, class {ip_result.get('ip_class', 'N/A')}, "
            f"feed category {ip_result.get('feed_result', {}).get('category', 'none')}. "
            f"Account {username}: {privilege}. MITRE: {technique_desc}. "
            f"Reasoning: {decision['severity']} per decision matrix "
            f"(IP {ip_result['verdict']}, privilege {privilege}).")
    if decision["queue"]:
        note += (f" Host {host} written to isolation_queue.json; analyst must "
                 f"authorize isolation via EDR console.")
    case_manager.add_case_note(case_id, note)

    if decision["verdict"] == "ESCALATE":
        case_manager.update_case_status(case_id, "escalated")

    if decision["queue"]:
        append_to_isolation_queue({
            "queued_at": run_ts,
            "host": host,
            "alert_id": alert_id,
            "case_id": case_id,
            "reason": queue_reason(alert, privilege, ip_result),
            "action_required": "Analyst must authorize isolation via EDR console before execution",
            "status": "pending_authorization",
        })

    append_audit(run_ts, alert_id, host, username, ip_result, privilege,
                 decision, case_id)
    print_summary(run_ts, alert, host, username, privilege, ip_result,
                  technique_desc, decision, case_id)
    return 0

def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 playbook_credential_exposure.py <alert.json>",
              file=sys.stderr)
        return 1
    try:
        return run_playbook(sys.argv[1])
    except (json.JSONDecodeError, ValueError, FileNotFoundError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[error] unrecoverable playbook failure: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
