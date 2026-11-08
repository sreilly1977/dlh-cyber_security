#!/usr/bin/env python3
# Name: playbook_phishing_triage.py
# Purpose: Executable phishing triage playbook for the 6x03 SOC Playbook.
#          Extracts IOCs from a phishing alert (sender IP, sender email
#          domain, body URL hostnames), enriches them via enrich_ioc,
#          applies the deterministic decision ladder (ESCALATE / REVIEW /
#          CLOSE), creates a case via case_manager, and appends a full
#          audit line to playbook_audit.log.
# Author: Steve - Cybersecurity Engineer
# Date: 08 November 2026

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from enrich_ioc import enrich_ioc
import case_manager

AUDIT_LOG = "playbook_audit.log"
FEED_PATH = "ioc_feed.json"

# Decision ladder: BLOCK beats INVESTIGATE beats ALLOW.
LADDER = [
    ("BLOCK", "ESCALATE", "Critical", "escalated"),
    ("INVESTIGATE", "REVIEW", "High", "open"),
    ("ALLOW", "CLOSE", "Low", "closed"),
]


def warn(message: str) -> None:
    """Warnings go to stderr so stdout stays clean for the structured summary."""
    print(f"[warning] {message}", file=sys.stderr)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_alert(path: str) -> dict:
    alert_file = Path(path)
    if not alert_file.exists():
        raise FileNotFoundError(f"alert file not found: {path}")
    with alert_file.open(encoding="utf-8") as fh:
        alert = json.load(fh)
    for field in ("alert_id", "rule_name", "raw_log"):
        if field not in alert:
            raise ValueError(f"missing required field in alert: {field}")
    return alert


def extract_iocs(raw_log: dict) -> list:
    """Return a list of extraction records preserving order and duplicates.

    Each record: {"value": <ioc>, "kind": "from_ip"|"email_domain"|"url_host",
                  "dedup": False}. Later candidates whose value was already
    extracted are marked dedup=True and are not enriched a second time.
    """
    candidates = []

    from_ip = raw_log.get("from_ip")
    if from_ip:
        candidates.append({"value": from_ip, "kind": "from_ip"})
    else:
        warn("missing from_ip field; skipping sender IP enrichment")

    sender = raw_log.get("from", "")
    if "@" in sender:
        domain = sender.split("@", 1)[1].strip().lower()
        if domain:
            candidates.append({"value": domain, "kind": "email_domain"})
    else:
        warn(f"cannot parse email domain from from field: {sender!r}; skipping")

    for url in raw_log.get("body_urls") or []:
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                raise ValueError("no hostname")
        except Exception as exc:
            warn(f"malformed URL in body_urls ({url}): {exc}; skipping")
            continue
        candidates.append({"value": hostname, "kind": "url_host"})

    seen = set()
    records = []
    for cand in candidates:
        rec = dict(cand)
        if cand["value"].lower() in seen:
            rec["dedup"] = True
        else:
            rec["dedup"] = False
            seen.add(cand["value"].lower())
        records.append(rec)
    return records


def enrich_all(records: list) -> list:
    """Enrich non-duplicate records. An enrich_ioc() exception degrades that
    IOC to INVESTIGATE/30 rather than aborting the run."""
    enriched = []
    for rec in records:
        if rec["dedup"]:
            continue
        try:
            result = enrich_ioc(rec["value"], FEED_PATH)
        except Exception as exc:
            warn(f"enrichment failed for {rec['value']}: {exc}; defaulting to INVESTIGATE")
            result = {
                "ioc": rec["value"],
                "type": "domain",
                "score": 30,
                "verdict": "INVESTIGATE",
                "feed_result": {"in_malicious_feed": False, "in_benign_list": False},
                "note": f"enrichment error: {exc}",
            }
        rec["result"] = result
        enriched.append(rec)
    return enriched


def decide(enriched: list) -> dict:
    """Apply the decision ladder over enriched IOC verdicts."""
    verdicts = {r["result"]["verdict"] for r in enriched}
    for ioc_verdict, playbook_verdict, severity, status in LADDER:
        if ioc_verdict in verdicts:
            return {
                "playbook_verdict": playbook_verdict,
                "case_severity": severity,
                "case_status": status,
                "trigger": ioc_verdict,
            }
    # Empty IOC set cannot happen ( CLOSE would fire on {} ) but stay safe:
    return {"playbook_verdict": "CLOSE", "case_severity": "Low",
            "case_status": "closed", "trigger": "NONE"}

def build_case_iocs(enriched: list) -> list:
    """Shape enrichment results into case_iocs rows for case_manager."""
    return [
        {
            "ioc_value": r["result"]["ioc"],
            "ioc_type": r["result"]["type"],
            "verdict": r["result"]["verdict"],
            "score": r["result"]["score"],
        }
        for r in enriched
    ]


def case_title(decision: dict) -> str:
    return {
        "ESCALATE": "Phishing: Known malicious IOC escalated",
        "REVIEW": "Phishing: Suspicious sender review",
        "CLOSE": "Phishing: No indicators of compromise",
    }[decision["playbook_verdict"]]


def action_line(playbook_verdict: str) -> str:
    return {
        "ESCALATE": "SOC notification queued for on-call analyst",
        "REVIEW": "Case queued for analyst review",
        "CLOSE": "Case closed automatically: no indicators of compromise",
    }[playbook_verdict]


def append_audit(run_ts: str, alert_id: str, counts: dict, enriched_count: int,
                 decision: dict, case_id: str) -> None:
    tally = (f"BLOCK:{counts.get('BLOCK', 0)},"
             f"INVESTIGATE:{counts.get('INVESTIGATE', 0)},"
             f"ALLOW:{counts.get('ALLOW', 0)}")
    line = (f"{run_ts} | PHISHING_TRIAGE | {alert_id} | IOCs:{enriched_count} | "
            f"{tally} | Verdict:{decision['playbook_verdict']} | "
            f"Case:{case_id} | Severity:{decision['case_severity']}\n")
    with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
        fh.write(line)


def print_summary(run_ts: str, alert: dict, records: list, enriched: list,
                  decision: dict, case_id: str) -> None:
    print(f"[{run_ts}] PHISHING TRIAGE PLAYBOOK")
    print(f"Alert      : {alert['alert_id']}")
    print(f"Rule       : {alert['rule_name']}")
    dedup_count = sum(1 for r in records if r["dedup"])
    print(f"IOCs       : {len(records)} extracted, {len(enriched)} enriched"
          + (f", {dedup_count} dedup skipped" if dedup_count else ""))
    for rec in records:
        if rec["dedup"]:
            print(f"  {rec['value']:<24} [dedup, skipped]")
        else:
            res = rec["result"]
            tags = ",".join(res.get("feed_result", {}).get("tags", []))
            detail = f"({tags})" if tags else ""
            print(f"  {res['ioc']:<24} {res['type']:<8} {res['verdict']:<10} "
                  f"score={res['score']}  {detail}".rstrip())
    print(f"Verdict    : {decision['playbook_verdict']}")
    print(f"Case       : {case_id}  Severity: {decision['case_severity']}  "
          f"Status: {decision['case_status']}")
    print(f"Action     : {action_line(decision['playbook_verdict'])}")


def run_playbook(alert_path: str) -> int:
    alert = load_alert(alert_path)
    run_ts = utc_now()

    records = extract_iocs(alert["raw_log"])
    enriched = enrich_all(records)
    decision = decide(enriched)

    counts = {}
    for r in enriched:
        verdict = r["result"]["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1

    description = (f"Automated phishing triage for {alert['alert_id']} "
                   f"(rule: {alert['rule_name']}). Verdict: "
                   f"{decision['playbook_verdict']} triggered by "
                   f"{decision['trigger']} IOC verdict.")
    case_id = case_manager.create_case(
        alert_id=alert["alert_id"],
        severity=decision["case_severity"],
        title=case_title(decision),
        description=description,
        iocs=build_case_iocs(enriched),
    )

    if decision["playbook_verdict"] == "CLOSE":
        case_manager.close_case(case_id, "no_indicators_of_compromise")
    elif decision["playbook_verdict"] == "ESCALATE":
        case_manager.update_case_status(case_id, "escalated")
        block_iocs = ", ".join(
            f"{r['result']['ioc']} ({r['result']['verdict']}/{r['result']['score']})"
            for r in enriched if r["result"]["verdict"] == "BLOCK"
        )
        case_manager.add_case_note(
            case_id,
            f"Playbook verdict: ESCALATE. IOCs: {block_iocs}",
        )

    append_audit(run_ts, alert["alert_id"], counts, len(enriched), decision, case_id)
    print_summary(run_ts, alert, records, enriched, decision, case_id)
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 playbook_phishing_triage.py <alert.json>", file=sys.stderr)
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
