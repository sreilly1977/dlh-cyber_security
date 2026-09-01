#!/bin/bash
#
# Name: 12-anomalies_network.sh
# Purpose: Detect network anomalies in the evaluation window against per-host baseline
# Author: Steve - Cybersecurity Engineer
# Date: 1 September 2026
#

set -euo pipefail

HANDOFF_DIR="${HANDOFF_DIR:-$HOME/3x00_handoff/evidence_handoff}"
BASELINE_PKG="${BASELINE_PKG:-$HOME/3x01_package/baseline_package}"

BASELINE_SUMMARY="${BASELINE_PKG}/baseline_summary.json"
LABELED_EVENTS="${BASELINE_PKG}/labeled_events.json"

for f in "${BASELINE_SUMMARY}" "${LABELED_EVENTS}"; do
    if [[ ! -f "${f}" ]]; then
        echo "ERROR: Required input not found: ${f}" >&2
        exit 1
    fi
done

export BASELINE_SUMMARY LABELED_EVENTS BASELINE_PKG HANDOFF_DIR

python3 -W error - << 'PYEOF'
import json
import os
from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address, ip_network

NET_LABELS = {"network_connection_outbound", "network_connection_inbound",
              "network_blocked", "network_alert"}
OUT_LABELS = {"network_connection_outbound", "network_blocked"}

# --- Severity rubric ---
SEVERITY = {
    "unknown_destination_for_host": "medium",
    "unknown_port_for_host": "medium",
    "unexpected_zone_flow": "medium",
    "volume_burst": "high",
    "external_destination_new": "high",
}

# True RFC1918 private space. TEST-NET and other special-purpose ranges
# are deliberately NOT treated as private: they classify as INTERNET.
# This matches resolve_zone() in 6-baseline_network.sh.
RFC1918_NETWORKS = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)

def parse_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def build_zone_table(handoff_dir):
    """Zone CIDR table, longest-prefix first; catch-all entries excluded."""
    path = os.path.join(handoff_dir, "context", "network_zones.json")
    table = []
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        for zone in data.get("zones", []):
            zid = zone.get("zone_id")
            for cidr in zone.get("cidrs", []):
                try:
                    n = ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if n.prefixlen > 0:
                    table.append((n, zid))
        table.sort(key=lambda p: p[0].prefixlen, reverse=True)
    return table

def zone_of(ip_str, table):
    """Longest-prefix match; unmatched RFC1918 -> INTERNAL_UNTAGGED;
    everything else (incl. TEST-NET) -> INTERNET."""
    if not ip_str:
        return "unknown"
    try:
        addr = ip_address(str(ip_str))
    except ValueError:
        return "unknown"
    for network, zid in table:
        if addr in network:
            return zid
    if any(addr in net for net in RFC1918_NETWORKS):
        return "INTERNAL_UNTAGGED"
    return "INTERNET"

def entries_from_value(val, name_keys):
    """Normalize one per-host baseline value into {name: count}."""
    entries = {}
    if isinstance(val, dict):
        for k, v in val.items():
            if isinstance(v, dict):
                name = None
                for cand in name_keys:
                    if v.get(cand) is not None:
                        name = str(v[cand])
                        break
                if not name:
                    name = str(k)
                cnt = v.get("count", 1)
            else:
                name, cnt = str(k), v
            try:
                cnt = int(cnt)
            except (ValueError, TypeError):
                cnt = 1
            entries[name] = cnt
    elif isinstance(val, list):
        for item in val:
            if isinstance(item, dict):
                name = None
                for cand in name_keys:
                    if item.get(cand) is not None:
                        name = str(item[cand])
                        break
                try:
                    cnt = int(item.get("count", 1))
                except (ValueError, TypeError):
                    cnt = 1
                if name:
                    entries[name] = cnt
            elif isinstance(item, str):
                entries[item] = 1
            elif isinstance(item, (int, float)):
                entries[str(item)] = 1
    return entries

def main():
    with open(os.environ["BASELINE_SUMMARY"]) as f:
        summary = json.load(f)

    base_end = datetime.fromisoformat(
        summary["baseline_window"]["end"].replace("Z", "+00:00"))
    eval_start = datetime.fromisoformat(
        summary["evaluation_window"]["start"].replace("Z", "+00:00"))
    eval_end = datetime.fromisoformat(
        summary["evaluation_window"]["end"].replace("Z", "+00:00"))
    baseline_hours = int(summary["baseline_window"].get("duration_days", 7)) * 24

    net_b = summary.get("network", {})
    thresholds = summary.get("thresholds", {})
    vol_mult = int(thresholds.get("temporal_deviation_multiplier", {})
                   .get("value", 3))

    # Known external IPs: list of strings or dicts
    known_external = set()
    for item in net_b.get("known_external_ips", []):
        if isinstance(item, dict):
            ip = item.get("ip")
            if ip:
                known_external.add(str(ip))
        elif isinstance(item, str):
            known_external.add(item)

    # Per-host destinations and ports
    dests = {}
    for host, val in (net_b.get("per_host_destinations") or {}).items():
        e = entries_from_value(val, ("ip", "dst_ip", "destination"))
        if e:
            dests[host] = e

    ports = {}
    for host, val in (net_b.get("per_host_ports") or {}).items():
        e = entries_from_value(val, ("port",))
        if e:
            ports[host] = e

    # Baseline zone pairs
    base_zone_pairs = set()
    for zf in net_b.get("zone_flows", []):
        base_zone_pairs.add((str(zf.get("src_zone")), str(zf.get("dst_zone"))))

    zone_table = build_zone_table(os.environ["HANDOFF_DIR"])

    # --- Pass 1: baseline outbound volume per host (burst mean) ---
    base_out = defaultdict(int)
    with open(os.environ["LABELED_EVENTS"]) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(ev.get("timestamp"))
            if ts is None or ts >= base_end:
                continue
            if ev.get("canonical_label") in OUT_LABELS:
                base_out[ev.get("hostname") or "unknown"] += 1

    # --- Evaluation window scan ---
    counts = defaultdict(int)
    anomalies = []

    new_dst = {}     # (host, ip) -> {"ts","refs","n","port"}
    new_port = {}    # (host, port) -> entry
    zone_anom = {}   # (src_zone, dst_zone) -> entry
    ext_new = {}     # (host, ip) -> entry
    out_times = defaultdict(list)  # host -> [ts] outbound events in eval

    with open(os.environ["LABELED_EVENTS"]) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_ts(ev.get("timestamp"))
            if ts is None or not (eval_start <= ts < eval_end):
                continue
            label = ev.get("canonical_label")
            if label not in NET_LABELS:
                continue

            host = ev.get("hostname") or "unknown"
            dst_ip = str(ev["dst_ip"]) if ev.get("dst_ip") else ""
            dst_port = ev.get("dst_port")
            src_ip = str(ev["src_ip"]) if ev.get("src_ip") else ""
            ref = ev.get("record_id") or ""
            is_out = label in OUT_LABELS
            src_zone = ev.get("src_zone") or zone_of(src_ip, zone_table)
            dst_zone = ev.get("dst_zone") or zone_of(dst_ip, zone_table)

            if not is_out:
                continue

            out_times[host].append(ts)

            # 1. unknown_destination_for_host
            if dst_ip and dst_ip not in dests.get(host, {}):
                ent = new_dst.setdefault((host, dst_ip),
                                         {"ts": ts, "refs": [], "n": 0,
                                          "port": dst_port})
                ent["n"] += 1
                if ref and len(ent["refs"]) < 20:
                    ent["refs"].append(ref)

            # 2. unknown_port_for_host
            if dst_port is not None:
                pkey = str(dst_port)
                if pkey not in ports.get(host, {}):
                    ent = new_port.setdefault((host, pkey),
                                              {"ts": ts, "refs": [], "n": 0})
                    ent["n"] += 1
                    if ref and len(ent["refs"]) < 20:
                        ent["refs"].append(ref)

            # 3. unexpected_zone_flow
            if (src_zone, dst_zone) not in base_zone_pairs:
                ent = zone_anom.setdefault((src_zone, dst_zone),
                                           {"ts": ts, "refs": [], "n": 0,
                                            "host": host})
                ent["n"] += 1
                if ref and len(ent["refs"]) < 20:
                    ent["refs"].append(ref)

            # 5. external_destination_new
            if dst_ip and dst_zone == "INTERNET" and dst_ip not in known_external:
                ent = ext_new.setdefault((host, dst_ip),
                                         {"ts": ts, "refs": [], "n": 0})
                ent["n"] += 1
                if ref and len(ent["refs"]) < 20:
                    ent["refs"].append(ref)

    # --- Emit: unknown_destination_for_host ---
    for (host, ip), ent in sorted(new_dst.items()):
        counts["unknown_destination_for_host"] += 1
        anomalies.append({
            "timestamp": iso(ent["ts"]), "host": host,
            "src_ip": "n/a", "dst_ip": ip,
            "dst_port": ent["port"] if ent["port"] is not None else "n/a",
            "src_zone": "n/a", "dst_zone": zone_of(ip, zone_table),
            "anomaly_type": "unknown_destination_for_host",
            "severity": SEVERITY["unknown_destination_for_host"],
            "baseline_value": 0, "observed_value": ent["n"],
            "event_refs": ent["refs"],
        })

    # --- Emit: unknown_port_for_host ---
    for (host, p), ent in sorted(new_port.items()):
        counts["unknown_port_for_host"] += 1
        anomalies.append({
            "timestamp": iso(ent["ts"]), "host": host,
            "src_ip": "n/a", "dst_ip": "n/a", "dst_port": p,
            "src_zone": "n/a", "dst_zone": "n/a",
            "anomaly_type": "unknown_port_for_host",
            "severity": SEVERITY["unknown_port_for_host"],
            "baseline_value": 0, "observed_value": ent["n"],
            "event_refs": ent["refs"],
        })

    # --- Emit: unexpected_zone_flow ---
    for (sz, dz), ent in sorted(zone_anom.items()):
        counts["unexpected_zone_flow"] += 1
        anomalies.append({
            "timestamp": iso(ent["ts"]), "host": ent["host"],
            "src_ip": "n/a", "dst_ip": "n/a", "dst_port": "n/a",
            "src_zone": sz, "dst_zone": dz,
            "anomaly_type": "unexpected_zone_flow",
            "severity": SEVERITY["unexpected_zone_flow"],
            "baseline_value": "pair never seen in baseline zone_flows",
            "observed_value": ent["n"],
            "event_refs": ent["refs"],
        })

    # --- Emit: external_destination_new ---
    for (host, ip), ent in sorted(ext_new.items()):
        counts["external_destination_new"] += 1
        anomalies.append({
            "timestamp": iso(ent["ts"]), "host": host,
            "src_ip": "n/a", "dst_ip": ip, "dst_port": "n/a",
            "src_zone": "n/a", "dst_zone": "INTERNET",
            "anomaly_type": "external_destination_new",
            "severity": SEVERITY["external_destination_new"],
            "baseline_value": "not in known_external_ips",
            "observed_value": ent["n"],
            "event_refs": ent["refs"],
        })

    # --- Emit: volume_burst (densest 1h window per host vs baseline mean) ---
    for host, times in out_times.items():
        mean_per_hour = base_out.get(host, 0) / baseline_hours
        if mean_per_hour <= 0:
            continue
        limit = mean_per_hour * vol_mult
        times.sort()
        n = len(times)
        best_count = 0
        best_i = 0
        i = 0
        while i < n:
            j = i
            while j < n and (times[j] - times[i]).total_seconds() < 3600:
                j += 1
            if (j - i) > best_count:
                best_count = j - i
                best_i = i
            i += 1
        if best_count > limit:
            counts["volume_burst"] += 1
            anomalies.append({
                "timestamp": iso(times[best_i]), "host": host,
                "src_ip": "n/a", "dst_ip": "n/a", "dst_port": "n/a",
                "src_zone": "n/a", "dst_zone": "n/a",
                "anomaly_type": "volume_burst",
                "severity": SEVERITY["volume_burst"],
                "baseline_value": round(mean_per_hour, 2),
                "observed_value":
                    f"{best_count} outbound in 1h (limit {round(limit, 1)})",
                "event_refs": [],
            })

    anomalies.sort(key=lambda a: a["timestamp"])

    out_path = os.path.join(os.environ["BASELINE_PKG"],
                            "anomalies_network.json")
    with open(out_path, "w") as f:
        json.dump({
            "evaluation_window": {"start": iso(eval_start),
                                  "end": iso(eval_end)},
            "total_anomalies": len(anomalies),
            "anomalies": anomalies,
        }, f, indent=2)

    print(f"evaluation window : {iso(eval_start)} -> {iso(eval_end)}")
    print(f"unknown_destination_for_host : {counts['unknown_destination_for_host']}")
    print(f"unknown_port_for_host        : {counts['unknown_port_for_host']}")
    print(f"unexpected_zone_flow         : {counts['unexpected_zone_flow']}")
    print(f"volume_burst                 : {counts['volume_burst']}")
    print(f"external_destination_new     : {counts['external_destination_new']}")
    print(f"total anomalies              : {len(anomalies)}")
    print("anomalies_network.json written")

if __name__ == "__main__":
    main()
PYEOF

exit 0
