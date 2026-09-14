#!/bin/bash
# Name: 6-correlate_alerts.sh
# Purpose: Cluster true-positive alerts from triage_log.jsonl into candidate
#          incidents using the fixed 3x03 grouping rules, applied in order:
#            1. temporal - same host (lowercase-normalised) within 15 minutes
#            2. shared_user - same non-null user, regardless of host or time
#            3. ioc_match - shared entry in matches_ioc
#            4. residual - remaining TPs form single-alert candidates
#          Because triage_log.jsonl carries no event timestamps, each alert
#          is joined back to alert_queue.json on alert_id to recover
#          event_summary.timestamp for the temporal rule (fail-loud if the
#          join misses). Labels: a cluster's grouping_rule is the phase that
#          last merged it (phase-1 clusters untouched later keep "temporal";
#          singletons are "residual"). Incident IDs INC-YYYYMMDD-A.. are
#          assigned to clusters ordered by first_seen then lowest alert_id.
#          tentative_category is the majority member rule_id mapped via
#          002->credential_abuse, 005->persistence, 009->lateral_movement.
#          confidence: high if >=5 alerts or any IOC, medium if 2-4, low if 1.
#          unmatched_tp_count counts TP alerts in residual singletons.
#          Exits non-zero if fewer than 3 incidents are formed.
# Author: Steve - Cybersecurity Engineer
# Date: 14 September 2026

set -u

log() { printf '[group] %s\n' "$*"; }
die() { printf '[group][ERROR] %s\n' "$*" >&2; exit 1; }

if [[ -z "${SHIFT_WORKSPACE:-}" ]]; then
    die "environment variable SHIFT_WORKSPACE is not set - source the environment contract first"
fi

LOG_FILE="$SHIFT_WORKSPACE/alerts/triage_log.jsonl"
QUEUE_FILE="$SHIFT_WORKSPACE/alerts/alert_queue.json"
OUT_FILE="$SHIFT_WORKSPACE/alerts/incidents.json"
START_FILE="$SHIFT_WORKSPACE/runtime/shift_start.json"

for f in "$LOG_FILE" "$QUEUE_FILE"; do
    [[ -f "$f" ]] || die "required input missing: $f"
done

today=$(date -u +%Y%m%d)

python3 - "$LOG_FILE" "$QUEUE_FILE" "$OUT_FILE" "$START_FILE" "$today" << 'PY' \
    || die "incident grouping failed"
import datetime
import json
import string
import sys
from collections import Counter, defaultdict

log_path, queue_path, out_path, start_path, today = sys.argv[1:6]

def parse_ts(s):
    if not isinstance(s, str) or not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None

# --- event timestamps from the alert queue (join on alert_id) --------------
with open(queue_path, encoding="utf-8") as fh:
    queue = json.load(fh)
if isinstance(queue, dict):
    queue = queue.get("alerts", [])
ts_by_id = {}
for a in queue:
    if not isinstance(a, dict):
        continue
    es = a.get("event_summary") or {}
    ts_by_id[a.get("alert_id")] = parse_ts(es.get("timestamp"))

# --- true positives from the triage log -------------------------------------
tp = []
with open(log_path, encoding="utf-8", errors="replace") as fh:
    for lineno, line in enumerate(fh, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.exit("triage_log line {}: invalid JSON ({})".format(lineno, exc))
        if rec.get("classification") != "TP":
            continue
        aid = rec.get("alert_id")
        if not ts_by_id and aid not in ts_by_id:
            sys.exit("alert {} not found in alert_queue.json - cannot recover timestamp".format(aid))
        raw_ts = None
        if aid in ts_by_id:
            for a in queue:
                if a.get("alert_id") == aid:
                    raw_ts = (a.get("event_summary") or {}).get("timestamp")
                    break
        tp.append({
            "aid": aid,
            "host": (str(rec["host"]).lower() if rec.get("host") else None),
            "user": rec.get("user") if isinstance(rec.get("user"), str) else None,
            "iocs": set(rec.get("matches_ioc") or []),
            "rule_id": rec.get("rule_id"),
            "ts": ts_by_id.get(aid),
            "raw_ts": raw_ts,
            "classified_at": rec.get("classified_at"),
        })

n = len(tp)
if n == 0:
    sys.exit("no TP alerts found in triage log")

print("[group] TP alerts: {}".format(n))
print("[group] grouping by temporal proximity, shared user, IOC match")

# --- union-find with per-cluster rule labels ---------------------------------
parent = list(range(n))
label = ["residual"] * n

def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x

def union(x, y, rule):
    rx, ry = find(x), find(y)
    if rx == ry:
        return
    parent[ry] = rx
    label[rx] = rule

# Phase 1: temporal - same host, consecutive-gap chaining within 900s
by_host = defaultdict(list)
for i, t in enumerate(tp):
    if t["host"] and t["ts"] is not None:
        by_host[t["host"]].append(i)
for host, idxs in by_host.items():
    idxs.sort(key=lambda i: (tp[i]["ts"], tp[i]["aid"] or ""))
    for k in range(1, len(idxs)):
        gap = (tp[idxs[k]]["ts"] - tp[idxs[k - 1]]["ts"]).total_seconds()
        if gap <= 900:
            union(idxs[k - 1], idxs[k], "temporal")

# Phase 2: shared user - chain every non-null user's alerts into one cluster
by_user = defaultdict(list)
for i, t in enumerate(tp):
    if t["user"]:
        by_user[t["user"]].append(i)
for user, idxs in by_user.items():
    idxs.sort(key=lambda i: tp[i]["aid"] or "")
    for k in range(1, len(idxs)):
        union(idxs[k - 1], idxs[k], "shared_user")

# Phase 3: IOC match - chain every shared indicator value
by_ioc = defaultdict(list)
for i, t in enumerate(tp):
    for v in t["iocs"]:
        by_ioc[v].append(i)
for value, idxs in sorted(by_ioc.items()):
    idxs.sort(key=lambda i: tp[i]["aid"] or "")
    for k in range(1, len(idxs)):
        union(idxs[k - 1], idxs[k], "ioc_match")

# --- assemble clusters --------------------------------------------------------
comps = defaultdict(list)
for i in range(n):
    comps[find(i)].append(i)

def category(rule_id):
    r = str(rule_id or "")
    if "002" in r:
        return "credential_abuse"
    if "005" in r:
        return "persistence"
    if "009" in r:
        return "lateral_movement"
    return "unknown"

clusters = []
for root, members in comps.items():
    dated = [tp[i] for i in members if tp[i]["ts"] is not None]
    if dated:
        first = min(dated, key=lambda t: (t["ts"], t["aid"] or ""))
        last = max(dated, key=lambda t: (t["ts"], t["aid"] or ""))
        first_seen, last_seen = first["raw_ts"], last["raw_ts"]
        sort_key = (first["ts"], min(tp[i]["aid"] or "" for i in members))
    else:
        cas = [tp[i]["classified_at"] for i in members if tp[i]["classified_at"]]
        first_seen = last_seen = min(cas) if cas else None
        sort_key = (datetime.datetime.max.replace(tzinfo=datetime.timezone.utc),
                    min(tp[i]["aid"] or "" for i in members))
    cats = Counter(category(tp[i]["rule_id"]) for i in members)
    best = max(cats.items(), key=lambda kv: (kv[1], kv[0]))[0]
    iocs = sorted(set().union(*(tp[i]["iocs"] for i in members)))
    clusters.append({
        "members": members,
        "hosts": sorted({tp[i]["host"] for i in members if tp[i]["host"]}),
        "users": sorted({tp[i]["user"] for i in members if tp[i]["user"]}),
        "iocs": iocs,
        "rule": label[root],
        "category": best,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sort_key": sort_key,
    })

clusters.sort(key=lambda c: c["sort_key"])

incidents = []
unmatched = 0
for idx, c in enumerate(clusters):
    letter = string.ascii_uppercase[idx] if idx < 26 else str(idx)
    inc_id = "INC-{}-{}".format(today, letter)
    aids = sorted(tp[i]["aid"] for i in c["members"])
    if len(c["members"]) == 1:
        conf = "low"
        unmatched += 1
    elif c["iocs"] or len(c["members"]) >= 5:
        conf = "high"
    else:
        conf = "medium"
    incidents.append({
        "incident_id": inc_id,
        "host_list": c["hosts"],
        "user_list": c["users"],
        "ioc_list": c["iocs"],
        "alert_ids": aids,
        "first_seen": c["first_seen"],
        "last_seen": c["last_seen"],
        "grouping_rule": c["rule"],
        "tentative_category": c["category"],
        "confidence": conf,
    })
    print("[group] {}: {} alerts  host={}  rule={}".format(
        inc_id, len(aids), ",".join(c["hosts"][:3]) or "(none)", c["rule"]))

shift_id = None
try:
    with open(start_path, encoding="utf-8") as fh:
        sj = json.load(fh)
    if isinstance(sj, dict):
        shift_id = sj.get("shift_id") or sj.get("id")
except (OSError, json.JSONDecodeError):
    pass
if not shift_id:
    shift_id = "3x05-" + today

doc = {
    "shift_id": shift_id,
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"),
    "incidents": incidents,
    "incident_count": len(incidents),
    "unmatched_tp_count": unmatched,
}

with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2)
    fh.write("\n")
PY

incident_count=$(jq -r '.incident_count' "$OUT_FILE")
log "incident_count=$incident_count"
if (( incident_count < 3 )); then
    die "incident_count=$incident_count is below the required minimum of 3 - re-examine the triage step"
fi
log "incidents.json written"
exit 0
