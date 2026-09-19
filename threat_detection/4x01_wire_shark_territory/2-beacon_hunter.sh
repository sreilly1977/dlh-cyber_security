#!/bin/bash
# Name: 2-beacon_hunter.sh
# Purpose: Identify and characterize command-and-control beaconing in
#          c2_beaconing.pcap through session-pattern analysis: per-destination
#          connection counts, inter-connection interval mean/stddev,
#          regularity (coefficient of variation), session durations and
#          payload volumes. Demonstrates why periodic automated C2 traffic is
#          invisible to signature-based detection (nothing in any single
#          session is 'bad') yet obvious in timing statistics. Compares
#          findings against the Task 0 baseline (baseline_clinical.json).
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./2-beacon_hunter.sh c2_beaconing.pcap [victim_ip]
#          victim_ip defaults to 10.10.2.15 (WS-NURSE-04, per briefing)
# Output:  Console report + c2_beacon_evidence.json
#
# ---------------------------------------------------------------------------
# DOCUMENTED FILTER REFERENCE
# ---------------------------------------------------------------------------
# Outbound sessions (SYNs) .... tcp.flags.syn == 1 && tcp.flags.ack == 0
#                               && ip.src == $VICTIM
#                               && not (ip.dst == 10.0.0.0/8 ||
#                                       ip.dst == 172.16.0.0/12 ||
#                                       ip.dst == 192.168.0.0/16)
#   (an outbound connection = one client SYN carrying a unique tcp.stream)
# Per-frame stream data ........ no display filter; fields:
#                               tcp.stream, frame.time_epoch, ip.src,
#                               ip.dst, tcp.len
#   (first/last epoch per stream => session duration; tcp.len sums =>
#    directional payload volumes)
# DNS queries by victim ........ dns.flags.response == 0 && ip.src == $VICTIM
# DNS answers resolving to a
#   given external IP ........... dns.flags.response == 1 && dns.a == <ip>
# BEACON CRITERION (behavioral, not signature-based):
#   connections >= 5 AND interval stddev / mean (CV) < 0.10
#   => machine-timed regularity incompatible with human browsing
# ROBUSTNESS: optional extractions carry `|| true`; first-line selection uses
#             awk, not head (SIGPIPE hazard under pipefail).
# ---------------------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 <pcap-file> [victim_ip]" >&2
    exit 1
fi

PCAP="$1"
VICTIM="${2:-10.10.2.15}"

[[ -f "$PCAP" ]] || { echo "Error: file not found: $PCAP" >&2; exit 1; }

OUT_JSON="c2_beacon_evidence.json"
BASELINE_JSON="baseline_clinical.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ts() {
    tshark -r "$PCAP" "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# EXTRACTION 1: outbound session initiations (SYNs) from victim to external IPs
# ---------------------------------------------------------------------------
SYNS_TSV="$TMP/syns.tsv"
ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == $VICTIM && \
        not (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16)" \
   -T fields -e tcp.stream -e ip.dst -e frame.time_epoch -e frame.time \
   > "$SYNS_TSV" || true

TOTAL_SESSIONS=$(wc -l < "$SYNS_TSV" | tr -d ' ')
if [[ "$TOTAL_SESSIONS" -eq 0 ]]; then
    echo "[!] No outbound sessions from $VICTIM to external IPs found in $PCAP" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# EXTRACTION 2: per-frame stream data (durations + payload volumes)
# ---------------------------------------------------------------------------
FRAMES_TSV="$TMP/frames.tsv"
ts -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst -e tcp.len \
   > "$FRAMES_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 3: DNS queries by the victim (pre-beacon resolution check)
# ---------------------------------------------------------------------------
DNS_Q_TSV="$TMP/dns_queries.tsv"
ts -Y "dns.flags.response == 0 && ip.src == $VICTIM" \
   -T fields -e frame.time_epoch -e dns.qry.name > "$DNS_Q_TSV" || true

DNS_A_TSV="$TMP/dns_answers.tsv"
ts -Y "dns.flags.response == 1" \
   -T fields -e frame.time_epoch -e dns.a -e dns.qry.name > "$DNS_A_TSV" || true

# ---------------------------------------------------------------------------
# ANALYSIS: statistics, beacon identification, baseline comparison
# ---------------------------------------------------------------------------
python3 - "$SYNS_TSV" "$FRAMES_TSV" "$DNS_Q_TSV" "$DNS_A_TSV" \
           "$VICTIM" "$OUT_JSON" "$BASELINE_JSON" "$TOTAL_SESSIONS" <<'PYEOF'
import json, math, sys
from datetime import datetime, timezone

syns_tsv, frames_tsv, dnsq_tsv, dnsa_tsv = sys.argv[1:5]
victim, out_json, baseline_json, total_sessions = sys.argv[5:9]

def read_tsv(path):
    try:
        with open(path) as fh:
            return [ln.rstrip("\n").split("\t") for ln in fh if ln.strip()]
    except OSError:
        return []

def fmt_ts(epoch):
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc) \
            .strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"
    except (ValueError, OSError):
        return "<unknown>"

# --- session initiations ----------------------------------------------------
syn_rows = read_tsv(syns_tsv)
sessions = []  # (stream, dst, start_epoch)
for row in syn_rows:
    if len(row) >= 3 and row[0]:
        sessions.append((int(row[0]), row[1], float(row[2])))

# --- per-stream first/last epoch and directional payload -------------------
frames = read_tsv(frames_tsv)
first, last = {}, {}
c_bytes, s_bytes = {}, {}
for row in frames:
    if len(row) < 5 or not row[0]:
        continue
    stream = int(row[0])
    epoch = float(row[1])
    src, dst, tlen = row[2], row[3], row[4]
    first.setdefault(stream, epoch)
    last[stream] = epoch
    if tlen:
        n = int(tlen)
        if src == victim:
            c_bytes[stream] = c_bytes.get(stream, 0) + n
        elif dst == victim:
            s_bytes[stream] = s_bytes.get(stream, 0) + n

# --- aggregate per destination ----------------------------------------------
dests = {}
for stream, dst, start in sessions:
    d = dests.setdefault(dst, {"starts": [], "durations": [], "cbytes": [],
                               "sbytes": [], "streams": []})
    d["starts"].append(start)
    if stream in first and stream in last:
        d["durations"].append(last[stream] - first[stream])
    d["cbytes"].append(c_bytes.get(stream, 0))
    d["sbytes"].append(s_bytes.get(stream, 0))
    d["streams"].append(stream)

def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0

def stdev(xs):
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))

for d in dests.values():
    d["starts"].sort()

print("=== OUTBOUND CONNECTIONS FROM %s ===" % victim)
print("Total unique destination IPs: %d" % len(dests))
print("Total outbound connections: %s" % total_sessions)
print()
print("%-16s | %5s | %12s | %8s | %s" %
      ("Dest IP", "Count", "Avg Interval", "StdDev", "Regularity"))
print("%-16s-+-%5s-+-%12s-+-%8s-+-%s" %
      ("-" * 16, "-" * 5, "-" * 12, "-" * 8, "-" * 16))

beacons = []
for dst in sorted(dests, key=lambda k: -len(dests[k]["starts"])):
    d = dests[dst]
    starts = d["starts"]
    n = len(starts)
    intervals = [b - a for a, b in zip(starts, starts[1:])] if n > 1 else []
    avg_i = mean(intervals)
    sd_i = stdev(intervals)
    cv = (sd_i / avg_i * 100) if avg_i > 0 else float("inf")
    regularity = "%.1f%%" % cv
    if n >= 5 and avg_i > 0 and cv < 10.0:
        regularity += " [!!!]"
        beacons.append(dst)
    print("%-16s | %5d | %10.1f s | %6.1f s | %s" %
          (dst, n, avg_i, sd_i, regularity))

# --- beacon characterization -------------------------------------------------
print()
if not beacons:
    print("=== C2 BEACON IDENTIFIED ===")
    print("(no destination meets the behavioral criterion: >=5 connections "
          "AND interval CV < 10%)")
else:
    for dst in beacons:
        d = dests[dst]
        starts = d["starts"]
        n = len(starts)
        intervals = [b - a for a, b in zip(starts, starts[1:])]
        avg_i = mean(intervals)
        sd_i = stdev(intervals)
        print("=== C2 BEACON IDENTIFIED ===")
        print("Destination: %s" % dst)
        print("First beacon: %s" % fmt_ts(starts[0]))
        print("Last beacon:  %s" % fmt_ts(starts[-1]))
        print("Total beacons: %d" % n)
        print("Interval: %.1f seconds (+/- %.1f seconds jitter)" % (avg_i, sd_i))
        print("Regularity: %.1f%% coefficient of variation [%s]" %
              (sd_i / avg_i * 100 if avg_i else 0.0,
               "HIGHLY AUTOMATED" if sd_i / avg_i * 100 < 5 else "AUTOMATED"))
        print()
        if d["durations"]:
            print("Per-beacon statistics:")
            print("  Session duration: %.1f - %.1f seconds (avg %.1f sec)" %
                  (min(d["durations"]), max(d["durations"]), mean(d["durations"])))
        if d["cbytes"]:
            nz = [b for b in d["cbytes"]]
            print("  Client payload: %d - %d bytes (avg %d bytes)" %
                  (min(nz), max(nz), mean(nz)))
        if d["sbytes"]:
            print("  Server payload: %d - %d bytes (avg %d bytes)" %
                  (min(d["sbytes"]), max(d["sbytes"]), mean(d["sbytes"])))

    # --- behavioral comparison against Task 0 baseline ---------------------
    print()
    print("=== BEHAVIORAL COMPARISON ===")
    try:
        with open(baseline_json) as fh:
            baseline = json.load(fh)
    except OSError:
        baseline = {}

    for dst in beacons:
        d = dests[dst]
        starts = d["starts"]
        intervals = [b - a for a, b in zip(starts, starts[1:])]
        avg_i = mean(intervals)
        cv = stdev(intervals) / avg_i * 100 if avg_i else 0.0
        in_baseline = dst in baseline.get("external_ips_contacted", [])

        # DNS pre-query: any answer resolving to this dst anywhere in capture?
        dns_hits = [r for r in read_tsv(dnsa_tsv)
                    if len(r) >= 2 and r[1] and dst in r[1].split(",")]

        hour = datetime.fromtimestamp(starts[0], tz=timezone.utc).hour

        print("Destination %s:" % dst)
        print("  In Task 0 baseline external contacts: %s" %
              ("YES (unexpected)" if in_baseline else "NO"))
        print("  Interval regularity: %.1f%% CV vs baseline "
              "'high variance / organic'" % cv)
        print("  DNS pre-resolution observed for this IP: %s (%d answer frames)" %
              ("yes" if dns_hits else "absent or cached", len(dns_hits)))
        print("  First beacon at %02d:00 UTC — %s" %
              (hour, "outside typical business activity"
               if hour < 7 or hour > 19 else "during business hours"))

    # --- total data exchanged ------------------------------------------------
    print()
    print("=== TOTAL DATA EXCHANGED ===")
    out_b = sum(sum(d["cbytes"]) for d in (dests[x] for x in beacons))
    in_b = sum(sum(d["sbytes"]) for d in (dests[x] for x in beacons))
    print("Outbound (client -> C2): %s bytes" % f"{out_b:,}")
    print("Inbound (C2 -> client):  %s bytes" % f"{in_b:,}")
    print("Total: %s bytes (~%d KB)" % (f"{out_b + in_b:,}", (out_b + in_b) // 1024))

    print()
    print("=== CONCLUSION ===")
    print("The repeated HTTPS sessions to %s show timing regularity" % ", ".join(beacons))
    print("consistent with automated command-and-control beaconing.")
    print("Behavioral, not signature, evidence: each individual session is an")
    print("ordinary TLS exchange; only the interval statistics (machine-grade")
    print("periodicity) expose the automation.")

    # --- serialize evidence ---------------------------------------------------
    evidence = {
        "capture_beacons": {
            dst: {
                "total_beacons": len(dests[dst]["starts"]),
                "first_beacon_epoch": dests[dst]["starts"][0],
                "last_beacon_epoch": dests[dst]["starts"][-1],
                "avg_interval_s": round(mean([b - a for a, b in
                    zip(dests[dst]["starts"], dests[dst]["starts"][1:])]), 2),
                "interval_stddev_s": round(stdev([b - a for a, b in
                    zip(dests[dst]["starts"], dests[dst]["starts"][1:])]), 2),
                "regularity_cv_pct": round(stdev([b - a for a, b in
                    zip(dests[dst]["starts"], dests[dst]["starts"][1:])]) /
                    mean([b - a for a, b in zip(dests[dst]["starts"],
                    dests[dst]["starts"][1:])]) * 100, 2) if len(dests[dst]["starts"]) > 1 else None,
                "avg_session_duration_s": round(mean(dests[dst]["durations"]), 2)
                    if dests[dst]["durations"] else None,
                "avg_client_bytes": round(mean(dests[dst]["cbytes"]))
                    if dests[dst]["cbytes"] else None,
                "avg_server_bytes": round(mean(dests[dst]["sbytes"]))
                    if dests[dst]["sbytes"] else None,
                "in_task0_baseline": dst in baseline.get("external_ips_contacted", []),
            } for dst in beacons
        },
        "victim": victim,
        "all_destinations": {
            dst: {"connections": len(dests[dst]["starts"])} for dst in dests
        },
        "detection_method": (
            "behavioral: inter-session interval coefficient of variation < 10% "
            "across >= 5 connections; no content or signature used"
        ),
    }
    with open(out_json, "w") as fh:
        json.dump(evidence, fh, indent=2)
        fh.write("\n")
    print()
    print("EVIDENCE SAVED: " + out_json)
PYEOF
