#!/usr/bin/env python3
# Name: case_manager.py
# Purpose: Lightweight SQLite-backed case manager for the 6x03 SOC Playbook.
#          Serves as the persistent output system for automated playbook
#          decisions: creates cases from verdicts, tracks notes and IOCs,
#          and supports status transitions through to closure.
# Author: Steve - Cybersecurity Engineer
# Date: 08 November 2026

import argparse
import json
import sqlite3
from datetime import datetime, timezone

DB_PATH = "cases.db"

VALID_STATUSES = ("open", "investigating", "escalated", "closed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    case_id     TEXT PRIMARY KEY,
    alert_id    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    resolution  TEXT
);

CREATE TABLE IF NOT EXISTS case_notes (
    note_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    note        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS case_iocs (
    ioc_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     TEXT NOT NULL,
    ioc_value   TEXT NOT NULL,
    ioc_type    TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    score       INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(case_id)
);
"""

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _connect(db_path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: str = DB_PATH) -> None:
    """Create the database and all three tables if they do not exist."""
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)

def generate_case_id(db_path: str = DB_PATH) -> str:
    """Return the next CASE-YYYYMMDD-NNN id, sequenced within the day."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    prefix = f"CASE-{today}-%"
    with _connect(db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM cases WHERE case_id LIKE ?", (prefix,)
        ).fetchone()[0]
    return f"CASE-{today}-{count + 1:03d}"

def create_case(alert_id: str, severity: str, title: str, description: str,
                iocs: list, db_path: str = DB_PATH) -> str:
    """Insert a case and its IOCs. Returns the new case_id."""
    case_id = generate_case_id(db_path)
    now = _now()
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT INTO cases (case_id, alert_id, severity, title, description,"
            " status, created_at, updated_at, resolution)"
            " VALUES (?, ?, ?, ?, ?, 'open', ?, ?, NULL)",
            (case_id, alert_id, severity, title, description, now, now),
        )
        for ioc in iocs:
            conn.execute(
                "INSERT INTO case_iocs (case_id, ioc_value, ioc_type, verdict, score)"
                " VALUES (?, ?, ?, ?, ?)",
                (case_id, ioc["ioc_value"], ioc["ioc_type"],
                 ioc["verdict"], int(ioc["score"])),
            )
    return case_id

def add_case_note(case_id: str, note: str, db_path: str = DB_PATH) -> bool:
    """Append a note to a case and refresh updated_at. False if not found."""
    now = _now()
    with _connect(db_path) as conn:
        exists = conn.execute(
            "SELECT 1 FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if exists is None:
            return False
        conn.execute(
            "INSERT INTO case_notes (case_id, note, created_at) VALUES (?, ?, ?)",
            (case_id, note, now),
        )
        conn.execute(
            "UPDATE cases SET updated_at = ? WHERE case_id = ?",
            (now, case_id),
        )
    return True

def update_case_status(case_id: str, status: str, db_path: str = DB_PATH) -> bool:
    """Transition a case status. False for invalid status or missing case."""
    if status not in VALID_STATUSES:
        return False
    with _connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?",
            (status, _now(), case_id),
        )
    return cur.rowcount > 0

def close_case(case_id: str, resolution: str, db_path: str = DB_PATH) -> bool:
    """Close a case with a resolution. False if the case does not exist."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            "UPDATE cases SET status = 'closed', resolution = ?, updated_at = ?"
            " WHERE case_id = ?",
            (resolution, _now(), case_id),
        )
    return cur.rowcount > 0

def get_case(case_id: str, db_path: str = DB_PATH):
    """Return the full case dict with nested notes and IOCs, or None."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM cases WHERE case_id = ?", (case_id,)
        ).fetchone()
        if row is None:
            return None
        case = dict(row)
        notes = conn.execute(
            "SELECT note, created_at FROM case_notes WHERE case_id = ?"
            " ORDER BY note_id",
            (case_id,),
        ).fetchall()
        iocs = conn.execute(
            "SELECT ioc_value, ioc_type, verdict, score FROM case_iocs"
            " WHERE case_id = ? ORDER BY ioc_id",
            (case_id,),
        ).fetchall()
    case["notes"] = [dict(n) for n in notes]
    case["iocs"] = [dict(i) for i in iocs]
    return case

def list_cases(status: str = None, db_path: str = DB_PATH) -> list:
    """Return case summaries (no notes/IOCs), optionally filtered by status."""
    with _connect(db_path) as conn:
        if status is not None:
            rows = conn.execute(
                "SELECT case_id, alert_id, severity, title, status, created_at"
                " FROM cases WHERE status = ? ORDER BY case_id",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT case_id, alert_id, severity, title, status, created_at"
                " FROM cases ORDER BY case_id"
            ).fetchall()
    return [dict(r) for r in rows]

def _print_table(cases: list, filter_label: str) -> None:
    headers = ["Case ID", "Alert ID", "Severity", "Title", "Status"]
    rows = [[c["case_id"], c["alert_id"], c["severity"], c["title"], c["status"]]
            for c in cases]
    widths = []
    for idx, header in enumerate(headers):
        col_width = max([len(header)] + [len(r[idx]) for r in rows]) if rows \
            else len(header)
        widths.append(col_width)
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = "| " + " | ".join("{:<%d}" % w for w in widths) + " |"
    print(border)
    print(fmt.format(*headers))
    print(border)
    for row in rows:
        print(fmt.format(*row))
    print(border)
    print(f"{len(cases)} cases (filter: {filter_label})")

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SQLite-backed case manager for automated playbook output."
    )
    parser.add_argument("command", choices=["list", "get", "close"])
    parser.add_argument("case_id", nargs="?", help="case id for get/close")
    parser.add_argument("resolution", nargs="?", help="resolution text for close")
    parser.add_argument("--status", help="filter list by status")
    parser.add_argument("--db", default=DB_PATH, help="path to cases database")
    args = parser.parse_args()

    init_db(args.db)

    if args.command == "list":
        if args.status:
            cases = list_cases(args.status, args.db)
            _print_table(cases, args.status)
        else:
            # Active casework view: everything not yet resolved.
            cases = [c for c in list_cases(None, args.db) if c["status"] != "closed"]
            _print_table(cases, "open + escalated")
    elif args.command == "get":
        if not args.case_id:
            parser.error("get requires a case id")
        case = get_case(args.case_id, args.db)
        if case is None:
            print(f"Case not found: {args.case_id}")
        else:
            print(json.dumps(case, indent=2))
    elif args.command == "close":
        if not args.case_id or args.resolution is None:
            parser.error('close requires a case id and a resolution, e.g.'
                         ' close CASE-20260428-001 "benign newsletter"')
        if close_case(args.case_id, args.resolution, args.db):
            print(f"Closed {args.case_id}: {args.resolution}")
        else:
            print(f"Case not found: {args.case_id}")

# The database and tables are created on first import so the module
# can be imported directly by the playbooks.
init_db()

if __name__ == "__main__":
    main()
