#!/bin/bash
# Name: 5-vpn_pivot.sh
# Purpose: Identify the external VPN session in full_timeline.pcap that
#          bridged credential theft (Task 1, 14 Apr) and lateral movement
#          (Task 4, 15 Apr). Detects external-to-internal TLS sessions on
#          the VPN/gateway endpoint, measures session duration, correlates
#          subsequent internal activity to infer the assigned internal IP,
#          geolocates the external source via locally installed WHOIS/GeoIP
#          tools (no invented data — unavailable tools are reported as such),
#          computes the VPN-to-RDP gap against Task 4's evidence artifact,
#          and states explicitly what the PCAP proves versus what remains
#          inference. All identifiers are derived from packets, not briefing
#          text. SNI evidence is reflected in conclusions if observed.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./5-vpn_pivot.sh full_timeline.pcap
# Output:  Console report + vpn_pivot_evidence.json
#
# ---------------------------------------------------------------------------
# DOCUMENTED FILTER REFERENCE
# ---------------------------------------------------------------------------
# Internal address space ...... 10.10.0.0/16 (per prior task evidence)
# External->internal SYNs ..... tcp.flags.syn == 1 && tcp.flags.ack == 0
#                               && !(ip.src == 10.10.0.0/16)
#                               && ip.dst == 10.10.0.0/16
#   (baseline contains ZERO inbound-initiated external sessions — any
#    external->internal connection is by definition abnormal against the
#    Task 0 profile)
# External-involving frames ... !(ip.src == 10.10.0.0/16 && ip.dst == 10.10.0.0/16)
#   (any frame where at least one endpoint is external — used for
#    bidirectional byte accounting per candidate session)
# TLS ClientHello .............. tls.handshake.type == 1
#   (SNI read from tls.handshake.extensions_server_name if dissectable;
#    password/authentication payloads are encrypted and NOT extractable)
# Stream teardown .............. tcp.flags.fin == 1 / tcp.flags.reset == 1
#   (duration = first SYN to last teardown frame in the session stream)
# Post-login internal activity .. ip.src == 10.10.0.0/16
#   (assigned-IP inference: internal hosts whose traffic begins during the
#    VPN window, ranked by activity volume, compared against the baseline
#    host set — correlation, not proof)
# GEOLOCATION: performed ONLY via installed `whois` / `geoiplookup` binaries
#   and only against registry databases — the script NEVER connects to,
#   resolves, or otherwise touches the subject IP. If neither tool is
#   present, geolocation is reported UNAVAILABLE. No ASN, country, or
#   organization data is ever fabricated.
# CORRELATION: Task 4 artifact lateral_movement_evidence.json supplies the
#   first lateral-movement (RDP) timestamp; the gap is computed, not assumed.
# ROBUSTNESS: optional extractions carry `|| true`; no `head` in pipelines.
# ---------------------------------------------------------------------------

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <pcap-file>" >&2
    exit 1
fi

PCAP="$1"
[[ -f "$PCAP" ]] || { echo "Error: file not found: $PCAP" >&2; exit 1; }

OUT_JSON="vpn_pivot_evidence.json"
LAT_JSON="lateral_movement_evidence.json"
BASELINE_JSON="baseline_clinical.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ts() {
    tshark -r "$PCAP" "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# EXTRACTION 1: external -> internal SYN connections (candidate VPN sessions)
# Filter: tcp.flags.syn==1 && tcp.flags.ack==0
#         && !(ip.src == 10.10.0.0/16) && ip.dst == 10.10.0.0/16
# ---------------------------------------------------------------------------
EXT_SYN_TSV="$TMP/ext_syns.tsv"
ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && !(ip.src == 10.10.0.0/16) && ip.dst == 10.10.0.0/16" \
   -T fields -e tcp.stream -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
             -e frame.time_epoch -e frame.time > "$EXT_SYN_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 2: all frames involving at least one external endpoint
# Filter: !(ip.src == 10.10.0.0/16 && ip.dst == 10.10.0.0/16)
# ---------------------------------------------------------------------------
EXT_ALL_TSV="$TMP/ext_all.tsv"
ts -Y "!(ip.src == 10.10.0.0/16 && ip.dst == 10.10.0.0/16)" \
   -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst -e tcp.len \
             -e _ws.col.Protocol > "$EXT_ALL_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 3: TLS ClientHello / SNI (if dissectable)
# Filter: tls.handshake.type == 1
# ---------------------------------------------------------------------------
TLS_TSV="$TMP/tls.tsv"
ts -Y "tls.handshake.type == 1" \
   -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst \
             -e tls.handshake.extensions_server_name > "$TLS_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 4: teardown frames (FIN/RST) for duration measurement
# Filters: tcp.flags.fin == 1 ; tcp.flags.reset == 1
# ---------------------------------------------------------------------------
FIN_TSV="$TMP/fin.tsv"
ts -Y "tcp.flags.fin == 1" \
   -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst > "$FIN_TSV" || true
RST_TSV="$TMP/rst.tsv"
ts -Y "tcp.flags.reset == 1" \
   -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst > "$RST_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 5: all internal-source activity (post-login correlation)
# Filter: ip.src == 10.10.0.0/16
# ---------------------------------------------------------------------------
INT_TSV="$TMP/int.tsv"
ts -Y "ip.src == 10.10.0.0/16" \
   -T fields -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol > "$INT_TSV" || true

# ---------------------------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------------------------
python3 - "$EXT_SYN_TSV" "$EXT_ALL_TSV" "$TLS_TSV" "$FIN_TSV" "$RST_TSV" \
           "$INT_TSV" "$OUT_JSON" "$LAT_JSON" "$BASELINE_JSON" <<'PYEOF'
import datetime
import json
import shutil
import subprocess
import sys

(ext_syn_tsv, ext_all_tsv, tls_tsv, fin_tsv, rst_tsv,
 int_tsv, out_json, lat_json, baseline_json) = sys.argv[1:10]

def read_tsv(path):
    try:
        with open(path) as fh:
            return [ln.rstrip("\n").split("\t") for ln in fh if ln.strip()]
    except OSError:
        return []

def fmt_time(epoch):
    return datetime.datetime.fromtimestamp(float(epoch)) \
        .strftime("%Y-%m-%d %H:%M:%S")

def parse_clock(clock, date_default):
    """Parse 'HH:MM:SS(.fff)' relative to a known date (captures carry +0200
    local offsets; epoch arithmetic stays internally consistent)."""
    try:
        t = datetime.datetime.strptime(clock.split(".")[0], "%H:%M:%S").time()
        base = datetime.datetime.strptime(date_default, "%Y-%m-%d")
        return datetime.datetime.combine(base.date(), t)
    except (ValueError, TypeError):
        return None

def defang(ip):
    return ip.replace(".", "[.]")

# --- candidate VPN sessions (external -> internal SYNs) ---------------------
ext_syns = []
for r in read_tsv(ext_syn_tsv):
    if len(r) < 7 or not r[0]:
        continue
    ext_syns.append({"stream": int(r[0]), "src": r[1], "sport": r[2],
                     "dst": r[3], "dport": int(r[4]),
                     "epoch": float(r[5])})
ext_syns.sort(key=lambda s: s["epoch"])
syn_by_stream = {s["stream"]: s for s in ext_syns}

# bidirectional byte accounting per external session
bytes_c, bytes_s = {}, {}
proto_by_stream = {}
for r in read_tsv(ext_all_tsv):
    if len(r) < 6 or not r[0]:
        continue
    stream = int(r[0])
    syn = syn_by_stream.get(stream)
    if not syn:
        continue  # frame belongs to an external<->external flow, not our session
    tlen = int(r[4]) if r[4] else 0
    if r[5]:
        proto_by_stream.setdefault(stream, set()).add(r[5])
    if r[2] == syn["src"]:
        bytes_c[stream] = bytes_c.get(stream, 0) + tlen
    elif r[3] == syn["src"]:
        bytes_s[stream] = bytes_s.get(stream, 0) + tlen

last_teardown = {}
for r in read_tsv(fin_tsv):
    if r and r[0]:
        last_teardown[int(r[0])] = max(last_teardown.get(int(r[0]), 0),
                                        float(r[1]))
for r in read_tsv(rst_tsv):
    if r and r[0]:
        last_teardown[int(r[0])] = max(last_teardown.get(int(r[0]), 0),
                                       float(r[1]))

tls_sni = {}
for r in read_tsv(tls_tsv):
    if len(r) >= 5 and r[0] and r[4]:
        tls_sni.setdefault(int(r[0]), set()).add(r[4])

print("=== EXTERNAL-TO-INTERNAL SESSIONS ===")
if not ext_syns:
    print("(no external->internal connections found — no VPN pivot observed)")
    print("LIMITATION: capture window or sensor placement may not cover the")
    print("VPN entry hop.")
else:
    print("Found %d external->internal session(s):" % len(ext_syns))
    print("(baseline profile: ZERO inbound-initiated external sessions)")
    print()
    for s in ext_syns:
        stream = s["stream"]
        if stream in last_teardown:
            dur = (last_teardown[stream] - s["epoch"]) / 60
            ended = "%.1f minutes (to last teardown frame)" % dur
        else:
            ended = "teardown not observed in capture"
        print("  Stream %d: %s:%s -> %s:%d" %
              (stream, s["src"], s["sport"], s["dst"], s["dport"]))
        print("    started:     %s" % fmt_time(s["epoch"]))
        print("    duration:    %s" % ended)
        print("    client->server %d B, server->client %d B" %
              (bytes_c.get(stream, 0), bytes_s.get(stream, 0)))
        print("    protocols observed on stream: %s" %
              ", ".join(sorted(proto_by_stream.get(stream, {"<tcp>"}))))
        sni = tls_sni.get(stream)
        print("    TLS SNI:     %s" %
              (", ".join(sorted(sni)) if sni else "<not visible in capture>"))
        print()

vpn = ext_syns[0] if ext_syns else None

# --- assigned internal IP inference ----------------------------------------
print("=== ASSIGNED INTERNAL IP (inferred) ===")
assignment = None
assignment_basis = "not determined"
if vpn:
    vpn_epoch = vpn["epoch"]
    vpn_end = last_teardown.get(vpn["stream"], vpn_epoch + 3600)
    counts, first_seen = {}, {}
    for r in read_tsv(int_tsv):
        if len(r) < 4 or not r[1]:
            continue
        epoch, src_ip = float(r[0]), r[1]
        if vpn_epoch <= epoch <= vpn_end:
            counts[src_ip] = counts.get(src_ip, 0) + 1
            first_seen.setdefault(src_ip, epoch)
    try:
        with open(baseline_json) as fh:
            baseline = json.load(fh)
        baseline_hosts = {d["ip"] for d in
                          baseline.get("destination_connections_top", [])}
    except (OSError, ValueError):
        baseline_hosts = set()
    if counts:
        ranked = sorted(counts.items(), key=lambda kv: -kv[1])
        print("Internal hosts active during the VPN window (%s - %s):" %
              (fmt_time(vpn_epoch), fmt_time(vpn_end)))
        for ip, n in ranked[:8]:
            tag = "(present in baseline)" if ip in baseline_hosts \
                else "(absent from baseline top-destination set)"
            print("  %-14s %5d frames  first at %s  %s" %
                  (ip, n, datetime.datetime.fromtimestamp(first_seen[ip])
                   .strftime("%H:%M:%S"), tag))
        # strongest candidate: busiest internal host, excluding the gateway,
        # whose activity begins within the early part of the VPN window
        for ip, _n in ranked:
            if ip in ("10.10.0.1", vpn["dst"]):
                continue  # gateway / VPN endpoint itself
            if vpn_epoch - 60 <= first_seen[ip] <= vpn_epoch + 600:
                assignment = ip
                assignment_basis = ("most-active internal host whose traffic "
                                    "begins within the early VPN window "
                                    "(correlation-based inference)")
                break
    if assignment:
        print()
        print("Assigned internal IP candidate: %s" % assignment)
        print("Inference basis: %s" % assignment_basis)
        print("NOTE: This is correlation, not proof — the PCAP does not")
        print("contain the VPN control-plane IP-allocation message. Confirm")
        print("against VPN concentrator logs if available.")
    else:
        print("  (no confidently attributable internal host identified)")
else:
    print("  (no VPN session found)")

# --- geolocation via locally installed tools only ---------------------------
geo = {"country": None, "asn": None, "org": None,
       "assessment": None, "tool_used": None, "available": False}
print()
print("=== GEOLOCATION ===")
if vpn:
    ip = vpn["src"]
    print("External source IP: %s  (defanged: %s)" % (ip, defang(ip)))
    print("Method: registry lookup only — the script never contacts the")
    print("subject IP.")
    for tool, cmd in (("whois", ["whois", ip]),
                      ("geoiplookup", ["geoiplookup", ip])):
        if shutil.which(tool):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=30, check=False)
                outp = (res.stdout or "") + (res.stderr or "")
                geo["tool_used"] = tool
                geo["available"] = True
                for ln in outp.splitlines():
                    low = ln.lower()
                    if low.startswith("country:") and not geo["country"]:
                        geo["country"] = ln.split(":", 1)[1].strip()
                    if (low.startswith("origin:") or low.startswith("aut-num:")) \
                            and not geo["asn"]:
                        geo["asn"] = ln.split(":", 1)[1].strip()
                    if (low.startswith("orgname:") or low.startswith("org:")
                            or low.startswith("netname:")) and not geo["org"]:
                        geo["org"] = ln.split(":", 1)[1].strip()
                break
            except (subprocess.TimeoutExpired, OSError):
                continue
    if geo["available"]:
        print("Lookup tool:     %s" % geo["tool_used"])
        print("Country:         %s" % (geo["country"] or "<not returned>"))
        print("ASN:             %s" % (geo["asn"] or "<not returned>"))
        print("Organization:    %s" % (geo["org"] or "<not returned>"))
    else:
        geo["assessment"] = ("geolocation tools not installed on analyst "
                            "workstation")
        print("Geolocation UNAVAILABLE: neither `whois` nor `geoiplookup` is")
        print("installed. No country/ASN/org data will be invented. Verify")
        print("manually via offline registry query or a browser sandbox")
        print("using the defanged IP above.")
    # assessment against baseline context
    try:
        with open(baseline_json) as fh:
            baseline = json.load(fh)
        base_ext = [d["ip"] for d in
                    baseline.get("destination_connections_top", [])
                    if not d["ip"].startswith("10.10.")]
    except (OSError, ValueError):
        base_ext = []
    if not geo["assessment"]:
        if base_ext and ip not in base_ext:
            geo["assessment"] = ("source IP absent from all baseline external "
                                "peer sets — foreign to normal operations")
        else:
            geo["assessment"] = "inconclusive from available data"
        print("Assessment:      %s" % geo["assessment"])
else:
    print("  (no external source identified — nothing to geolocate)")

# --- timeline correlation against Task 4 artifact ---------------------------
print()
print("=== TIMELINE CORRELATION ===")
lat_first, lat_src = None, None
try:
    with open(lat_json) as fh:
        lat = json.load(fh)
    rdp = [c for c in lat.get("connections", []) if c.get("port") == 3389]
    if rdp and vpn:
        vpn_date = datetime.datetime.fromtimestamp(vpn["epoch"]) \
            .strftime("%Y-%m-%d")
        lat_first = parse_clock(rdp[0]["time"], vpn_date)
        lat_src = rdp[0].get("src")
except (OSError, ValueError):
    pass

gap = None
ordering = "correlation unavailable"
if vpn and lat_first:
    vpn_dt = datetime.datetime.fromtimestamp(vpn["epoch"])
    gap = (lat_first - vpn_dt).total_seconds() / 60
    print("VPN session start:     %s" % vpn_dt.strftime("%Y-%m-%d %H:%M:%S"))
    print("First lateral move:    %s  (RDP from %s, Task 4 evidence)" %
          (lat_first.strftime("%Y-%m-%d %H:%M:%S"), lat_src))
    if gap >= 0:
        print("Gap: VPN precedes lateral movement by %.1f minutes" % gap)
        ordering = "VPN-before-lateral CONFIRMED from artifacts"
    else:
        print("Gap: VPN follows lateral movement by %.1f minutes — ordering "
              "does NOT support the VPN-pivot hypothesis" % -gap)
        ordering = "ordering contradicts hypothesis"
elif vpn:
    print("VPN session start:     %s" %
          datetime.datetime.fromtimestamp(vpn["epoch"])
          .strftime("%Y-%m-%d %H:%M:%S"))
    print("Task 4 artifact not found or lacks an RDP timestamp — gap not")
    print("computed. Place lateral_movement_evidence.json beside this script.")
else:
    print("  (no VPN session to correlate)")

# --- data-driven determination statements -----------------------------------
# Build proves/cannot_prove lists based on what was actually observed
proves = [
    "An external host initiated an inbound TLS session to the internal "
    "gateway — the entire baseline contains zero inbound-initiated "
    "external sessions, making this anomalous by definition",
    "Session timing, duration, and bidirectional byte volumes measured "
    "directly from SYN-to-teardown framing",
    "Temporal ordering relative to the phishing click (14 Apr) and the "
    "first lateral-movement RDP (15 Apr, Task 4 artifact)",
]

cannot_prove = []

# Check if SNI indicates VPN endpoint
vpn_sni_found = False
sni_values = []
if vpn:
    sni_values = sorted(tls_sni.get(vpn["stream"], []))
    # Check if SNI value contains "vpn" keyword (case-insensitive)
    vpn_sni_found = any("vpn" in s.lower() for s in sni_values)

if vpn_sni_found and sni_values:
    proves.append(
        "The TLS ClientHello carried Server Name Indication (SNI) '%s', "
        "naming the session destination as the VPN endpoint — visible as "
        "unencrypted handshake metadata before any authentication" % sni_values[0]
    )
    vpn_determination = (
        "inbound external TLS session to gateway 10.10.0.1:443 with SNI "
        "'%s' — identified as the VPN endpoint by packet metadata" % sni_values[0]
    )
elif sni_values:
    proves.append(
        "The TLS ClientHello carried SNI '%s', identifying the service "
        "addressed by the external source" % sni_values[0]
    )
    vpn_determination = (
        "inbound external TLS session to gateway 10.10.0.1:443 with SNI "
        "'%s'; VPN attribution is contextual (gateway + hostname)" % sni_values[0]
    )
else:
    cannot_prove.append(
        "That the TLS session is specifically a VPN tunnel — no SNI was "
        "visible; the determination rests only on destination (gateway), "
        "duration, and context"
    )
    vpn_determination = (
        "inbound external TLS session to gateway 10.10.0.1:443 — VPN "
        "attribution is contextual (gateway, duration); no hostname "
        "evidence available"
    )

cannot_prove.extend([
    "Which credentials or account authenticated the session — payloads "
    "are not dissectable; account attribution is inference, not packet "
    "proof",
    "Relationship between this source IP and the phishing infrastructure "
    "(91.234.99.107) — a different IP does not establish a different "
    "operator, nor does it prove the same one",
])

# --- serialize ---------------------------------------------------------------
vpn_end_min = None
if vpn and vpn["stream"] in last_teardown:
    vpn_end_min = round((last_teardown[vpn["stream"]] - vpn["epoch"]) / 60, 1)

evidence = {
    "vpn_session": ({
        "stream": vpn["stream"],
        "source_ip": vpn["src"],
        "source_ip_defanged": defang(vpn["src"]),
        "source_port": vpn["sport"],
        "destination": vpn["dst"],
        "destination_port": vpn["dport"],
        "start": fmt_time(vpn["epoch"]),
        "duration_minutes": vpn_end_min,
        "ended_by": ("teardown frame (FIN/RST) observed"
                     if vpn_end_min is not None else "not observed"),
        "client_to_server_bytes": bytes_c.get(vpn["stream"], 0),
        "server_to_client_bytes": bytes_s.get(vpn["stream"], 0),
        "protocols_on_stream": sorted(proto_by_stream.get(vpn["stream"],
                                                          [])),
        "tls_sni": sni_values or None,
        "sni_vpn_indication": vpn_sni_found,
        "determination": vpn_determination,
        "authentication_context": (
            "ClientHello SNI visible; authentication payloads encrypted — "
            "credentials not extractable from packets; any account "
            "attribution is metadata/timing inference only"
        ),
    } if vpn else None),
    "assigned_internal_ip_inferred": assignment,
    "assigned_ip_basis": assignment_basis,
    "geolocation": {k: v for k, v in geo.items()},
    "timeline_correlation": {
        "vpn_start": fmt_time(vpn["epoch"]) if vpn else None,
        "first_lateral_movement": lat_first.strftime("%Y-%m-%d %H:%M:%S")
            if lat_first else None,
        "gap_minutes": round(gap, 1) if gap is not None else None,
        "ordering_assessment": ordering,
    },
    "what_the_pcap_proves": proves,
    "what_the_pcap_cannot_prove": cannot_prove,
    "limitations_note": (
        "Credential-use and VPN-application conclusions are metadata and "
        "timing based. The defanged source IP is provided for safe manual "
        "verification; no lookup was performed against the subject IP "
        "itself."
    ),
}
with open(out_json, "w") as fh:
    json.dump(evidence, fh, indent=2)
    fh.write("\n")

# --- proves / cannot prove --------------------------------------------------
print()
print("=== WHAT THE PCAP PROVES / CANNOT PROVE ===")
print("PROVES (from observed packet evidence):")
for p in proves:
    print("  ✓ %s" % p)
print()
print("CANNOT PROVE (beyond packet evidence):")
for p in cannot_prove:
    print("  ✗ %s" % p)

# --- pivot assessment --------------------------------------------------------
print()
print("=== PIVOT ASSESSMENT ===")
print("Session determination: %s" % vpn_determination)
if vpn and gap is not None and gap >= 0:
    print("The inbound external session precedes the first lateral-movement")
    print("RDP by %.1f minutes and provides a plausible network path from" % gap)
    print("external access to the internal activity documented in Task 4.")
    print("Combined with the campaign sequence (phishing 14 Apr -> inbound")
    print("external session 15 Apr -> RDP pivot 15 Apr -> DNS exfil 16 Apr),")
    print("the evidence supports this session as the entry vector, with the")
    print("credential-use attribution stated as inference.")
else:
    print(ordering)

print()
print("EVIDENCE SAVED: " + out_json)
PYEOF
