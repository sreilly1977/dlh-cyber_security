#!/bin/bash
#
# Name: 3-sigma_runner.sh
# Purpose: Execute Sigma detection rules against flat NDJSON evidence from the 3x00
#          pipeline; interprets the detection block (selections, modifiers, boolean
#          conditions, timeframe aggregations) and emits a JSON result object.
# Author: Steve - Cybersecurity Engineer
# Date: 05 September 2026
#
# Usage: 3-sigma_runner.sh <rule.yml> [evidence.ndjson] [--dry-run] [--count-only]
#                           [--window <start_iso>,<end_iso>]
#
# Behavior:
#   - Evidence defaults to $HANDOFF_DIR/data/normalized_events.json
#   - If a rule selects on canonical_label and the evidence is the default
#     normalized stream, the runner substitutes $BASELINE_PKG/labeled_events.json
#     (the only dataset carrying canonical_label), noting this on stderr.
#     Pass an evidence file explicitly to pin the exact input.
#   - --dry-run     : validate rule structure, print VALID or the error
#   - --count-only  : print only the integer match count
#   - --window      : restrict evaluation to [start, end) ISO timestamps
#   - Runtime-computed fields (documented in-rule, not present in raw records):
#       hour_of_day        UTC hour (0-23) of the event timestamp
#       parent_process_name basename of event_data.ParentImage
#       baseline_seen      boolean; true iff (hostname, process_name) appears in
#                          $BASELINE_PKG/baselines/baseline_process.json per_host
#       baseline_known_destination
#                          boolean; true iff (hostname, dst_ip) appears in
#                          baseline_network.json per_host_destinations
#       baseline_known_port
#                          boolean; true iff (hostname, dst_port) appears in
#                          baseline_network.json per_host_ports (port compared
#                          as string on both sides)
#   - All hostname-keyed joins canonicalize hostnames (lowercase, - and _
#     stripped) so dataset spelling variants (bill-db-01 / bill_db_01 /
#     billdb01) resolve to a single merged baseline entry.

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"
DEFAULT_EVIDENCE="$HANDOFF_DIR/data/normalized_events.json"
LABELED_EVENTS="$BASELINE_PKG/labeled_events.json"
BASELINE_PROCESS="$BASELINE_PKG/baselines/baseline_process.json"
NETWORK_BASELINE="$BASELINE_PKG/baselines/baseline_network.json"

usage() {
    cat <<EOF
Usage: $(basename "$0") <rule.yml> [evidence.ndjson] [options]

Options:
  --dry-run              validate rule YAML and structure only; prints VALID
  --count-only           print only the match count
  --window START,END     restrict evaluation to ISO8601 time range (end exclusive)
  -h, --help             show this help

Environment:
  HANDOFF_DIR   default $HOME/3x00_handoff/evidence_handoff
  BASELINE_PKG   default $HOME/3x01_package/baseline_package
EOF
}

RULE=""
EVIDENCE=""
DRY_RUN=0
COUNT_ONLY=0
WINDOW=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)   DRY_RUN=1 ;;
        --count-only) COUNT_ONLY=1 ;;
        --window)
            if [ $# -lt 2 ]; then
                echo "ERROR: --window requires START,END argument" >&2
                exit 1
            fi
            WINDOW="$2"
            shift
            ;;
        -h|--help)   usage; exit 0 ;;
        --*)         echo "ERROR: unknown option: $1" >&2; usage >&2; exit 1 ;;
        *)
            if [ -z "$RULE" ]; then
                RULE="$1"
            elif [ -z "$EVIDENCE" ]; then
                EVIDENCE="$1"
            else
                echo "ERROR: unexpected extra argument: $1" >&2
                usage >&2
                exit 1
            fi
            ;;
    esac
    shift
done

if [ -z "$RULE" ]; then
    echo "ERROR: rule file required" >&2
    usage >&2
    exit 1
fi

if [ ! -r "$RULE" ]; then
    echo "ERROR: rule file not readable: $RULE" >&2
    exit 1
fi

if [ -z "$EVIDENCE" ]; then
    EVIDENCE="$DEFAULT_EVIDENCE"
fi

python3 - "$RULE" "$EVIDENCE" "$LABELED_EVENTS" "$BASELINE_PROCESS" "$NETWORK_BASELINE" \
    "$DRY_RUN" "$COUNT_ONLY" "$WINDOW" <<'PY'
import fnmatch
import json
import re
import sys
import time as timemod
from datetime import datetime, timedelta

rule_path, evidence_path, labeled_path, baseline_process_path, network_baseline_path = sys.argv[1:6]
dry_run, count_only, window_arg = sys.argv[6] == "1", sys.argv[7] == "1", sys.argv[8]

import yaml

REQUIRED_KEYS = ("title", "id", "status", "description", "logsource",
                 "detection", "falsepositives", "level", "tags")
LEVELS = {"informational", "low", "medium", "high", "critical"}
TIMEFRAME_RE = re.compile(r"^(\d+)\s*([smhd])$")
AGG_RE = re.compile(
    r"^\s*count(?:\s*\(\s*\))?(?:\s+by\s+([A-Za-z_][A-Za-z0-9_.]*))?"
    r"\s*(>=|<=|==|>|<)\s*(\d+)\s*$", re.IGNORECASE)
TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")

def fail(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def parse_ts(value):
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)

def load_rule(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except OSError as exc:
        fail(f"cannot read rule {path}: {exc}")
    except yaml.YAMLError as exc:
        fail(f"YAML parse error in {path}: {exc}")
    if not isinstance(doc, dict):
        fail(f"{path}: rule must be a YAML mapping")
    return doc

def validate_rule(doc):
    missing = [k for k in REQUIRED_KEYS if k not in doc]
    if missing:
        fail(f"{rule_path}: missing required keys: {', '.join(missing)}")
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        fail(f"{rule_path}: detection block must be a mapping with a condition")
    if doc.get("level") not in LEVELS:
        fail(f"{rule_path}: invalid level: {doc.get('level')!r}")
    cond = det["condition"]
    if not isinstance(cond, str):
        fail(f"{rule_path}: condition must be a string")
    tf = det.get("timeframe")
    if tf is not None and not TIMEFRAME_RE.match(str(tf)):
        fail(f"{rule_path}: unparsable timeframe: {tf!r}")
    base = cond.split("|", 1)[0].strip()
    for token in TOKEN_RE.findall(base):
        if token in ("(", ")"):
            continue
        if token.lower() not in ("and", "or", "not") and token not in det:
            fail(f"{rule_path}: condition references unknown selection: {token}")
    return doc

# --------------------------------------------------------------------------
# Derived-field support (fields computed by the runner, not in raw records)
# --------------------------------------------------------------------------
def canonical_hostname(host):
    """Canonicalize hostname keys: lowercase, strip - and _ separators.

    Collapses dataset variants like bill-db-01 / bill_db_01 / billdb01
    into a single key so baselines are not fragmented by spelling.
    """
    if not isinstance(host, str):
        return ""
    return host.strip().lower().replace("-", "").replace("_", "")

_baseline_table = None

def load_baseline(path):
    """Lazy-load per-host expected process table, with hostname canonicalization.

    Merges all spelling variants of a host (dashes/underscores removed)
    so a per_host baseline is a union of all its key variants' processes.
    """
    global _baseline_table
    if _baseline_table is None:
        _baseline_table = {}
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            per_host = doc.get("per_host", {}) if isinstance(doc, dict) else {}
            for host, procs in per_host.items():
                if not isinstance(procs, dict):
                    continue
                canon = canonical_hostname(host)
                merged = _baseline_table.setdefault(canon, {})
                for proc in procs:
                    # first variant wins on collision; identical keys across
                    # variants carry the same process list content
                    merged.setdefault(proc, procs[proc])
        except (OSError, ValueError):
            _baseline_table = {}
    return _baseline_table

_net_tables = None

def load_network_baseline(path):
    """Lazy-load per-host destination and port tables from baseline_network.json.

    Converts {host: {value: count}} structures into canonical-hostname-keyed
    sets, union-merging hostname spelling variants as in the process baseline.
    """
    global _net_tables
    if _net_tables is None:
        _net_tables = {"destinations": {}, "ports": {}}
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            if isinstance(doc, dict):
                for host, entries in doc.get("per_host_destinations", {}).items():
                    if not isinstance(entries, dict):
                        continue
                    canon = canonical_hostname(host)
                    _net_tables["destinations"].setdefault(canon, set()).update(entries.keys())
                for host, entries in doc.get("per_host_ports", {}).items():
                    if not isinstance(entries, dict):
                        continue
                    canon = canonical_hostname(host)
                    _net_tables["ports"].setdefault(canon, set()).update(entries.keys())
        except (OSError, ValueError):
            pass
    return _net_tables

def resolve_field(record, field, hour_cache):
    if field == "hour_of_day":
        ts = record.get("timestamp")
        if ts is None:
            return None
        if id(record) not in hour_cache:
            hour_cache[id(record)] = parse_ts(ts).hour
        return hour_cache[id(record)]
    if field == "parent_process_name":
        ed = record.get("event_data")
        pi = ed.get("ParentImage") if isinstance(ed, dict) else None
        if not isinstance(pi, str) or not pi.strip():
            return None
        return pi.replace("\\", "/").rsplit("/", 1)[-1]
    if field == "baseline_seen":
        table = load_baseline(baseline_process_path)
        host = canonical_hostname(record.get("hostname"))
        proc = record.get("process_name")
        host_procs = table.get(host, {})
        return isinstance(proc, str) and proc in host_procs
    if field == "baseline_known_destination":
        tables = load_network_baseline(network_baseline_path)
        host = canonical_hostname(record.get("hostname"))
        dip = record.get("dst_ip")
        return isinstance(dip, str) and dip in tables["destinations"].get(host, set())
    if field == "baseline_known_port":
        tables = load_network_baseline(network_baseline_path)
        host = canonical_hostname(record.get("hostname"))
        dport = record.get("dst_port")
        if dport is None:
            return False
        return str(dport) in tables["ports"].get(host, set())
    cur = record
    for part in field.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

def as_num(value):
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None

def match_value(actual, expected, mods):
    if actual is None:
        return False
    # explicit boolean comparison (e.g. baseline_seen: false)
    if isinstance(expected, bool) or isinstance(actual, bool):
        if not isinstance(expected, bool) or not isinstance(actual, bool):
            return False
        return expected == actual
    # modifier-driven matching: every listed modifier must hold, no implicit equality
    if mods:
        for mod in mods:
            if mod == "contains":
                if str(expected).lower() not in str(actual).lower():
                    return False
            elif mod == "startswith":
                if not str(actual).lower().startswith(str(expected).lower()):
                    return False
            elif mod == "endswith":
                if not str(actual).lower().endswith(str(expected).lower()):
                    return False
            elif mod == "re":
                if not re.search(str(expected), str(actual)):
                    return False
            elif mod in ("gte", "gt", "lte", "lt"):
                a, b = as_num(actual), as_num(expected)
                if a is None or b is None:
                    return False
                if mod == "gte" and not a >= b:
                    return False
                if mod == "gt" and not a > b:
                    return False
                if mod == "lte" and not a <= b:
                    return False
                if mod == "lt" and not a < b:
                    return False
            elif mod in ("all", "base", "exists"):
                continue
            else:
                return False
        return True
    # plain equality (or wildcard match) only when no modifiers are present
    if isinstance(expected, (dict, list)) or isinstance(actual, (dict, list)):
        return False
    pat, act = str(expected), str(actual)
    if "*" in pat or "?" in pat:
        return fnmatch.fnmatchcase(act.lower(), pat.lower())
    return pat == act

def match_constraint(record, key, expected, hour_cache):
    parts = key.split("|")
    field, mods = parts[0], [m for m in parts[1:] if m]
    actual = resolve_field(record, field, hour_cache)
    if isinstance(expected, list):
        return any(match_value(actual, item, mods) for item in expected)
    return match_value(actual, expected, mods)

def match_selection(record, selection, hour_cache):
    if isinstance(selection, list):
        return any(match_selection(record, sub, hour_cache) for sub in selection)
    if not isinstance(selection, dict):
        return False
    return all(match_constraint(record, k, v, hour_cache)
               for k, v in selection.items())

# --------------------------------------------------------------------------
# Boolean condition evaluation (recursive descent over and/or/not/parens)
# --------------------------------------------------------------------------
class CondEvaluator:
    def __init__(self, detection, hour_cache):
        self.detection = detection
        self.hour_cache = hour_cache

    def evaluate(self, record, tokens, pos=0):
        result, pos = self._parse_or(record, tokens, 0)
        if pos != len(tokens):
            raise ValueError(f"trailing tokens in condition: {tokens[pos:]}")
        return result

    def _parse_or(self, record, tokens, pos):
        result, pos = self._parse_and(record, tokens, pos)
        while pos < len(tokens) and tokens[pos].lower() == "or":
            rhs, pos = self._parse_and(record, tokens, pos + 1)
            result = result or rhs
        return result, pos

    def _parse_and(self, record, tokens, pos):
        result, pos = self._parse_unary(record, tokens, pos)
        while pos < len(tokens) and tokens[pos].lower() == "and":
            rhs, pos = self._parse_unary(record, tokens, pos + 1)
            result = result and rhs
        return result, pos

    def _parse_unary(self, record, tokens, pos):
        if pos >= len(tokens):
            raise ValueError("unexpected end of condition")
        if tokens[pos].lower() == "not":
            rhs, pos = self._parse_unary(record, tokens, pos + 1)
            return not rhs, pos
        if tokens[pos] == "(":
            result, pos = self._parse_or(record, tokens, pos + 1)
            if pos >= len(tokens) or tokens[pos] != ")":
                raise ValueError("unbalanced parenthesis in condition")
            return result, pos + 1
        if tokens[pos] in self.detection:
            return match_selection(record, self.detection[tokens[pos]], self.hour_cache), pos + 1
        raise ValueError(f"unknown selection in condition: {tokens[pos]}")

# --------------------------------------------------------------------------
# Aggregation: count() by <field> <op> <n> within timeframe
# --------------------------------------------------------------------------
def parse_timeframe(text):
    m = TIMEFRAME_RE.match(str(text))
    if not m:
        return None
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})

AGG_OPS = {">": lambda a, b: a > b, ">=": lambda a, b: a >= b,
           "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
           "==": lambda a, b: a == b}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
t0 = timemod.perf_counter()

rule = load_rule(rule_path)
validate_rule(rule)

if dry_run:
    print("VALID")
    sys.exit(0)

detection = rule["detection"]
condition = detection["condition"]
hour_cache = {}
evaluator = CondEvaluator(detection, hour_cache)

base_condition, agg = condition, None
if "|" in condition:
    base_condition, agg_part = condition.split("|", 1)
    m = AGG_RE.match(agg_part)
    if not m:
        fail(f"{rule_path}: unsupported aggregation syntax: {agg_part.strip()!r}")
    agg = {"by": m.group(1), "op": m.group(2), "n": int(m.group(3))}
    base_condition = base_condition.strip()

tokens = TOKEN_RE.findall(base_condition)

win_start = win_end = None
if window_arg:
    try:
        s, e = window_arg.split(",", 1)
        win_start, win_end = parse_ts(s), parse_ts(e)
    except ValueError as exc:
        fail(f"--window expects START,END ISO timestamps: {exc}")

# Evidence selection: substitute labeled dataset for canonical_label rules
referenced_fields = set()
for sel in detection.values():
    if isinstance(sel, dict):
        referenced_fields.update(k.split("|")[0] for k in sel)
    elif isinstance(sel, list):
        for sub in sel:
            if isinstance(sub, dict):
                referenced_fields.update(k.split("|")[0] for k in sub)
if "canonical_label" in referenced_fields \
        and evidence_path.endswith("normalized_events.json") \
        and labeled_path.endswith("labeled_events.json"):
    import os
    if os.path.isfile(labeled_path):
        print(f"NOTE: rule selects on canonical_label; using labeled dataset: {labeled_path}",
              file=sys.stderr)
        evidence_path = labeled_path

try:
    fh = open(evidence_path, encoding="utf-8")
except OSError as exc:
    fail(f"cannot read evidence {evidence_path}: {exc}")

base_matches = []
with fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if win_start is not None:
            try:
                ts = parse_ts(rec.get("timestamp"))
            except (ValueError, TypeError):
                continue
            if not (win_start <= ts < win_end):
                continue
        try:
            if evaluator.evaluate(rec, tokens):
                base_matches.append(rec)
        except ValueError as exc:
            fail(f"{rule_path}: condition evaluation error: {exc}")

if agg is None:
    matched = base_matches
else:
    tf = parse_timeframe(detection.get("timeframe", ""))
    keyed = []
    for rec in base_matches:
        try:
            ts = parse_ts(rec.get("timestamp"))
        except (ValueError, TypeError):
            continue
        key = resolve_field(rec, agg["by"], hour_cache) if agg["by"] else None
        keyed.append((key, ts, rec))
    cmp_fn = AGG_OPS[agg["op"]]
    flagged_ids = set()
    groups = {}
    for i, (key, ts, rec) in enumerate(keyed):
        groups.setdefault(key, []).append(i)
    for _, idxs in groups.items():
        entries = sorted(((keyed[i][1], i) for i in idxs))
        times = [e[0] for e in entries]
        i = 0
        while i < len(times):
            j = i
            if tf is not None:
                while j < len(times) and times[j] - times[i] <= tf:
                    j += 1
            else:
                j = len(times)
            if cmp_fn(j - i, agg["n"]):
                flagged_ids.update(entries[k][1] for k in range(i, j))
            i += 1
    matched = [keyed[i][2] for i in sorted(flagged_ids)]

elapsed_ms = int(round((timemod.perf_counter() - t0) * 1000))

if count_only:
    print(len(matched))
    sys.exit(0)

matched.sort(key=lambda r: str(r.get("timestamp")))
MAX_MATCHES = 10000
truncated = len(matched) > MAX_MATCHES
result = {
    "rule_id": rule.get("id"),
    "rule_title": rule.get("title"),
    "level": rule.get("level"),
    "evidence_path": evidence_path,
    "match_count": len(matched),
    "matches": [
        {
            "timestamp": r.get("timestamp"),
            "hostname": r.get("hostname"),
            "event_ref": r.get("event_ref") if r.get("event_ref") is not None else r.get("record_id"),
        }
        for r in matched[:MAX_MATCHES]
    ],
    "matches_truncated": truncated,
    "execution_time_ms": elapsed_ms,
}
print(json.dumps(result, indent=2, ensure_ascii=False))
PY
