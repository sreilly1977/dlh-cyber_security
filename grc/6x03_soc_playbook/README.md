# Introduction

> "Automation applied to an inefficient operation will magnify the inefficiency."
> 
> — Bill Gates

During the Cobalt Strike incident, Mike Torres spent 45 minutes manually enriching a single IP address: checking the reputation against three separate browser tabs, reading WHOIS output, cross-referencing with known C2 infrastructure documented in a previous threat intel report. By the time he had a verdict, the attacker had moved laterally to two additional hosts. The enrichment was not wrong. It was not bad analysis. It was just 40 minutes too slow because it was done entirely by hand.

MedDefense processes between 120 and 180 SIEM alerts per day. The security team has two analysts on any given shift. At an average of 8 minutes per alert for manual triage, that is 18 hours of analyst time required daily for work that in large part involves looking things up, not thinking. Enrichment is not a skill. Enrichment is a query. Queries should be run by computers, not people.

This project builds the automation infrastructure that should have existed before the incident. You will write a modular IOC enrichment engine in Python that queries a threat intel feed, performs DNS and IP classification and produces a structured verdict. You will write a lightweight SQLite-backed case manager that serves as the output system for all automated decisions. Then you will write two executable automation playbooks: one for phishing triage and one for credential exposure alerts. Every script must run. Every playbook must produce output. The automation strategy document is last, because the professional who has built working automation writes better strategy than the one who plans it abstractly.

## Why this matters

Automation is the career differentiator between an analyst who handles 40 alerts and one who handles 200. Every mature SOC automates enrichment, deduplication and initial triage. The analyst who can write the enrichment script, design the playbook logic and wire up the case creation is doing the work of two analysts and producing a system that scales. That capability appears directly in SOC engineer, detection engineer and security automation engineer roles, and increasingly in senior analyst roles where scripting is expected.

The specific skills built here transfer directly to SOAR platforms: the playbook logic you write in Python maps cleanly to Palo Alto XSOAR, Splunk SOAR and Microsoft Sentinel playbooks. The concepts are the same. The syntax changes.

## Context

James Chen opened the team meeting with a number: "Last month, our two analysts spent a combined 312 hours on alert triage. I pulled the data. 68 percent of that time was on enrichment activity: IP lookups, domain checks, URL analysis, hash lookups. Work a script should do."

Dr. Morales asked the follow-up question: "What is the risk of automating it?"

Robert Kim answered honestly: "If we automate on a bad rule, we auto-close malicious alerts. If we automate block actions on a high false-positive rule, we block legitimate traffic. The risk is not in automation. The risk is in automating without measuring the false positive rate first, and without building in a human checkpoint for any action that is destructive or irreversible."

That is the design constraint this project operates under. Every playbook you write must distinguish between enrichment and classification (safe to automate) and actions like blocking, isolating or closing (require measured false-positive rates and override mechanisms). The phishing triage playbook creates cases and escalates findings. It does not block senders or quarantine mailboxes automatically. The credential exposure playbook flags hosts for isolation and writes to an isolation queue, but the queue is consumed by a human action, not an automated one.

Mike Torres, who has been building his own one-off bash scripts since the incident, summarized it best: "Build it right once, and it helps every alert. Build it wrong once, and it hurts every alert."

---

# 0. Quiz

---

# [1. Build the IOC Enrichment Engine](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x03_soc_playbook/enrich_ioc.py)

## Goal: 

Write enrich_ioc.py, a Python module and CLI tool that accepts an IP address or domain, classifies it using a local threat intel feed and standard library network introspection and returns a structured enrichment verdict.

## Context: 

Mike Torres's current enrichment process is three browser tabs, a copy-paste workflow and a mental model of which tabs are current. The enrichment engine replaces all of that with a single function call that returns a JSON verdict in under two seconds, is version-controlled, and produces the same output every time for the same input. When the phishing playbook needs to know whether a sender IP is malicious, it calls enrich_ioc(). No tabs. No copy-paste. No judgment required for a lookup.

## Instructions: 

Write enrich_ioc.py and use ioc_feed.json. The script must function as both an importable module (from enrich_ioc import enrich_ioc) and as a standalone CLI tool (python3 enrich_ioc.py 198.51.100.42).

### Use These Materials

Use the following files from the provided material folder:

threat_intel/ioc_feed.json
threat_intel/enrichment_validation_set.csv
threat_intel/ioc_scoring_reference.md
threat_intel/reverse_dns_expected_behavior.md

Copy the feed into the project root before testing:

cp /opt/meddefense/materials/threat_intel/ioc_feed.json ./ioc_feed.json

The ioc_feed.json content must remain compatible with the task requirements and checker anchors. Use the validation CSV to confirm the five expected verdicts before moving to Task 2.

### Script requirements

enrich_ioc.py must implement the following functions. Do not use external packages; json, socket, ipaddress, re, datetime and urllib.request cover everything needed.

detect_ioc_type(value: str) -> str: returns "ipv4", "ipv6", "domain" or "url". For URLs, extract the hostname for further classification.

classify_ip(ip: str) -> str: uses ipaddress.ip_address() to return "private", "loopback", "link_local", "documentation", "multicast" or "public". The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) must be handled explicitly since ipaddress does not classify them separately from public addresses.

reverse_dns(ip: str) -> str: attempts socket.gethostbyaddr(ip), returns the hostname string on success or "NXDOMAIN" on socket.herror, and "TIMEOUT" on socket.timeout. Set the timeout using socket.setdefaulttimeout(3).

check_feed(value: str, feed: dict) -> dict: looks up the value in malicious_ips, malicious_domains, benign_ips and benign_domains. Returns a dict with keys in_malicious_feed, in_benign_list, and the feed entry data if found.

score_ioc(feed_result: dict, ip_class: str) -> tuple[int, str]: returns (score, verdict) where verdict is one of "BLOCK", "INVESTIGATE" or "ALLOW". Scoring logic:

    Private or loopback IP: score 0, verdict "ALLOW" (with note in the output)
    In benign list: score 0, verdict "ALLOW"
    In malicious feed with confidence >= 80: score = confidence, verdict "BLOCK"
    In malicious feed with confidence < 80: score = confidence, verdict "INVESTIGATE"
    Not in any feed, public IP or unknown domain: score 30, verdict "INVESTIGATE"

enrich_ioc(value: str, feed_path: str = "ioc_feed.json") -> dict: the main function; loads the feed, calls all helpers and returns the complete enrichment result.

### Output format: 

every call to enrich_ioc() must return this structure:

```json
{
  "ioc": "198.51.100.42",
  "type": "ipv4",
  "ip_class": "documentation",
  "reverse_dns": "NXDOMAIN",
  "feed_result": {
    "in_malicious_feed": true,
    "in_benign_list": false,
    "confidence": 95,
    "category": "c2",
    "tags": ["cobalt_strike", "beacon"],
    "first_seen": "2026-03-12",
    "last_seen": "2026-04-27",
    "source": "meddefense-internal"
  },
  "score": 95,
  "verdict": "BLOCK",
  "enriched_at": "2026-04-28T10:00:00Z"
}
```

### CLI behavior

Single IOC: python3 enrich_ioc.py 198.51.100.42 (prints the enrichment JSON to stdout).

Batch mode: python3 enrich_ioc.py --batch iocs.txt --output results.json where iocs.txt contains one IOC per line. Writes a JSON array of enrichment results to results.json and prints a summary: Processed: X | BLOCK: X | INVESTIGATE: X | ALLOW: X.

### Validation

Run the script against these five values and confirm the verdicts match before proceeding to Task 2. If they do not, the playbooks in Tasks 3 and 4 will produce incorrect outcomes.

|IOC | Expected verdict |
| --- | --- |
| 198.51.100.42 | BLOCK |
| cobalt-beacon.shop | BLOCK |
| 203.0.113.99 | INVESTIGATE |
| 192.168.1.100 | ALLOW |
| 8.8.8.8 | ALLOW |

**Expected output**
```bash
$ python3 enrich_ioc.py 198.51.100.42
```

```jason
{
  "ioc": "198.51.100.42",
  "type": "ipv4",
  "ip_class": "documentation",
  "reverse_dns": "NXDOMAIN",
  "feed_result": {
    "in_malicious_feed": true,
    "in_benign_list": false,
    "confidence": 95,
    "category": "c2",
    "tags": ["cobalt_strike", "beacon"],
    "first_seen": "2026-03-12",
    "last_seen": "2026-04-27",
    "source": "meddefense-internal"
  },
  "score": 95,
  "verdict": "BLOCK",
  "enriched_at": "2026-04-28T10:15:44Z"
}
```

```bash
$ python3 enrich_ioc.py 192.168.1.100
```

```json
{
  "ioc": "192.168.1.100",
  "type": "ipv4",
  "ip_class": "private",
  "reverse_dns": "NXDOMAIN",
  "feed_result": {
    "in_malicious_feed": false,
    "in_benign_list": false
  },
  "score": 0,
  "verdict": "ALLOW",
  "note": "Private address range; internal network traffic",
  "enriched_at": "2026-04-28T10:15:47Z"
}
```

---

# [2. Build the Case Manager](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x03_soc_playbook/case_manager.py)

## Goal: 

Write case_manager.py, a Python module and CLI tool that creates and manages security cases in a local SQLite database, serving as the output system for all automated playbook decisions.

## Context: 

When a playbook reaches a verdict, something must happen with it. In enterprise environments, that something is a SIEM ticket, a Jira issue or a TheHive case. At MedDefense today, it is a message in a Slack channel that nobody follows up on systematically. The case manager built here is lightweight enough to run anywhere Python runs, persistent enough to survive process restarts, queryable enough to show open cases at a glance and structured enough that every case has a complete audit trail from creation through closure. It becomes the single source of truth for all automated triage decisions.

## Instructions: 

Write case_manager.py implementing the schema and functions below. The module must create cases.db in the current directory on first import if it does not already exist.

### Use These Materials

Use the following files from the provided material folder:

case_management/case_schema_reference.sql
case_management/case_id_generation_notes.md
case_management/sample_case_output.json

The schema in your case_manager.py must match the reference SQL. The sample output is provided only to clarify formatting and nested case structure; your script must generate real cases in cases.db.

### Required functions

init_db(db_path: str = "cases.db") -> None: creates the database and all three tables if they do not exist. Called automatically on module import.

generate_case_id() -> str: returns a unique case ID in the format CASE-YYYYMMDD-NNN where NNN is zero-padded sequential within the day (e.g., CASE-20260428-001). Derives the sequence from the count of cases created today stored in cases.db.

create_case(alert_id: str, severity: str, title: str, description: str, iocs: list[dict]) -> str: inserts a new row into cases, inserts each IOC dict from the iocs list into case_iocs, returns the case_id. The iocs list contains dicts with keys ioc_value, ioc_type, verdict and score, matching the output format of enrich_ioc().

add_case_note(case_id: str, note: str) -> bool: inserts a row into case_notes, updates cases.updated_at, returns True on success or False if the case does not exist.

update_case_status(case_id: str, status: str) -> bool: updates cases.status and cases.updated_at. Valid status values: "open", "investigating", "escalated", "closed". Returns False for invalid status values without raising an exception.

close_case(case_id: str, resolution: str) -> bool: sets status = "closed" and resolution = resolution, returns True on success.

get_case(case_id: str) -> dict: returns a dict representation of the case including all notes and IOCs, or None if not found. Notes and IOCs are nested lists in the returned dict.

list_cases(status: str = None) -> list[dict]: returns a list of case summary dicts (no notes, no IOCs). If status is provided, filters by that status. Each dict contains case_id, alert_id, severity, title, status and created_at.

### CLI behavior

python3 case_manager.py list: prints all open cases in a formatted table.

python3 case_manager.py list --status escalated: filters by status.

python3 case_manager.py get CASE-20260428-001: prints the full case dict including notes and IOCs.

python3 case_manager.py close CASE-20260428-001 "benign; confirmed newsletter sender": closes a case with the provided resolution.

**Expected output**

```bash
$ python3 case_manager.py list
+---------------------+---------------------+----------+----------------------------------------+-----------+
| Case ID             | Alert ID            | Severity | Title                                  | Status    |
+---------------------+---------------------+----------+----------------------------------------+-----------+
| CASE-20260428-001   | ALT-20260428-001    | Critical | Phishing: Known C2 IP Escalated        | escalated |
| CASE-20260428-002   | ALT-20260428-002    | High     | Phishing: Suspicious sender review     | open      |
+---------------------+---------------------+----------+----------------------------------------+-----------+
2 cases (filter: open + escalated)

$ python3 case_manager.py get CASE-20260428-001
// `case_management/sample_case_output.json`
```

---

# [3. Write the Phishing Triage Playbook](https://github.com/sreilly1977/dlh-cyber_security/blob/main/grc/6x03_soc_playbook/playbook_phishing_triage.py)

## Goal: 

Write playbook_phishing_triage.py, an executable automation playbook that ingests a structured phishing alert, enriches all extracted IOCs, applies decision logic and creates a case with a full audit trail.

## Context: 

Phishing alerts are the highest-volume alert type at MedDefense: between 80 and 100 per day. The triage decision for most of them is deterministic: if the sender IP is in the threat intel feed as C2 infrastructure, the case is Critical and gets escalated to the on-call analyst immediately. If all IOCs are unknown, it gets queued for manual review at lower priority. The analyst judgment is needed only when IOCs are partially known or contradictory. This playbook handles the deterministic cases automatically, creating cases that are pre-enriched and pre-prioritized so analysts spend their time on investigation, not lookups.

## Instructions: 

Write playbook_phishing_triage.py. The script imports enrich_ioc and case_manager from the same directory; both must be complete before this task can be executed.

### Use These Materials

Use the following files from the provided material folder:

alerts/phishing/ALT-20260428-001.json
alerts/phishing/ALT-20260428-002.json
alerts/phishing/ALT-20260428-003.json
playbooks/phishing_triage_decision_logic.md
playbooks/audit_log_format_reference.md
integration/expected_outcomes.csv

Create an alerts/ directory in your project and copy the phishing alerts there for testing:

mkdir -p alerts
cp /opt/meddefense/materials/alerts/phishing/*.json alerts/

The playbook must still accept any alert path as a CLI argument. The provided alerts are deterministic test fixtures for development and integration testing.

### Alert input format

The playbook accepts a single JSON file path as a CLI argument: python3 playbook_phishing_triage.py alerts/ALT-20260428-001.json

### IOC extraction

Extract the following IOCs from the alert:

    raw_log.from_ip: classified as ipv4

    Email domain from raw_log.from (the part after @): classified as domain

    For each URL in raw_log.body_urls: extract the hostname (strip scheme and path) and classify it as ipv4 or domain. Deduplicate: if a hostname was already extracted from from_ip or the email domain, do not enrich it twice.

### Decision logic

After enriching all extracted IOCs, apply this logic in order:

    If any IOC has verdict "BLOCK": playbook_verdict = "ESCALATE", case_severity = "Critical", case_status = "escalated"

    Else if any IOC has verdict "INVESTIGATE": playbook_verdict = "REVIEW", case_severity = "High", case_status = "open"

    Else (all "ALLOW"): playbook_verdict = "CLOSE", case_severity = "Low", case_status = "closed", resolution = "no_indicators_of_compromise"

### Case creation and audit logging

For all verdicts including "CLOSE": create a case via case_manager.create_case().

For "CLOSE" verdict: immediately call case_manager.close_case() with the resolution above.

For "ESCALATE" verdict: call case_manager.update_case_status() to "escalated" and add a case note via case_manager.add_case_note() summarizing which IOC triggered escalation.

Append one line per playbook execution to playbook_audit.log in this format:

2026-04-28T10:15:48Z | PHISHING_TRIAGE | ALT-20260428-001 | IOCs:3 | BLOCK:2,INVESTIGATE:0,ALLOW:1 | Verdict:ESCALATE | Case:CASE-20260428-001 | Severity:Critical

Print a structured summary to stdout:

```bash
[2026-04-28T10:15:48Z] PHISHING TRIAGE PLAYBOOK
Alert      : ALT-20260428-001
Rule       : phishing_email_suspicious_sender
IOCs       : 3 extracted, 3 enriched
  198.51.100.42          ipv4    BLOCK       score=95  (c2, cobalt_strike)
  meddefense-secure.net  domain  BLOCK       score=97  (typosquat, phishing)
  198.51.100.42          [dedup, skipped]
Verdict    : ESCALATE
Case       : CASE-20260428-001  Severity: Critical  Status: escalated
Action     : SOC notification queued for on-call analyst
```

The script must exit with code 0 on successful execution regardless of the verdict. Exit code 1 only on unrecoverable errors (malformed JSON, missing required fields, database write failure).

### Error handling requirements

Handle the following conditions without crashing: missing from_ip field (skip that IOC), malformed URL in body_urls (log a warning and skip), enrichment enrich_ioc() raising an exception (log the exception, set verdict to "INVESTIGATE" for that IOC, continue). Never let a missing IOC field abort the entire playbook run.

---
