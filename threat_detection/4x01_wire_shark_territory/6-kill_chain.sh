#!/bin/bash
# Name: 6-kill_chain.sh
# Purpose: Assemble the complete MedDefense kill chain from the six serialized
#          evidence artifacts (Tasks 0-5), producing a unified UTC-normalized
#          master timeline, phase-by-phase MITRE ATT&CK mapping with per-item
#          packet-evidence vs analytical-inference tagging, a defense-layer
#          test sequence, dwell-time computation, critical pivot points,
#          impact assessment, and a confirmed-vs-unconfirmed separation.
#          Phase 1 (email delivery) is context from the 4x00 phishing
#          dissection (7-click_investigation.md), explicitly labeled as
#          non-packet evidence. Absolute exfil-window anchors are re-derived
#          from dns_exfil.pcap via tshark when the file is present, because
#          dns_tunnel_evidence.json records span but not absolute start time.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./6-kill_chain.sh            (expects the 6 JSON artifacts and
#                                       optionally the PCAPs in the working
#                                       directory)
# Output:  Console report + kill_chain_evidence.json
#
# ---------------------------------------------------------------------------
# INPUT ARTIFACTS (produced by Tasks 0-5)
#   baseline_clinical.json          (0-baseline_analysis.sh)
#   phishing_click_evidence.json    (1-phishing_click.sh)
#   c2_beacon_evidence.json         (2-beacon_hunter.sh)
#   dns_tunnel_evidence.json        (3-dns_tunnel.sh)
#   lateral_movement_evidence.json  (4-lateral_movement.sh)
#   vpn_pivot_evidence.json         (5-vpn_pivot.sh)
#
# DOCUMENTED FILTER REFERENCE (optional tshark anchors)
#   Tunnel window anchor .......... dns.qry.name contains "data-sync.meddefense-portal.com"
#                                   && !dns.flags.response
#     (queries only; first/last epoch delimit the exfil window in UTC)
#
# TIME CONVENTION
#   All times are naive UTC internally. PCAP artifacts record wall-clock
#   times in a +0200 local frame (per frame.time evidence in Tasks 4/5
#   diagnostics); naive artifact timestamps are converted by subtracting 2
#   hours. Unix epochs are converted with a fixed epoch-origin constructor
#   (no system-timezone dependence). The 4x00 report labels the click
#   15:02:33 CDT; the PCAP's 17:02:33+0200 equals 15:02:33 UTC — both
#   artifacts describe the same click event, anchored on the packet epoch.
#
# PHASE 1 SOURCE (context, not packet evidence)
#   4x00_phishing_dissection / 7-click_investigation.md:
#     - E2 spearphishing email to dmarsh@meddefense.com
#     - click at 15:02:33 from WS-NURSE-04 (10.10.2.15)
#     - click occurred "roughly 15 minutes after E2 was delivered"
#     - URL parameters id=dmarsh, token=a8f3e2d1 (per-victim attribution)
#     - 4x00 report itself: compromise status UNKNOWN from email evidence
#   Email delivery time = click time minus 15 minutes (context-derived).
#
# ROBUSTNESS: optional extractions carry `|| true`; missing artifacts cause
#   per-phase degradation warnings, never silent fabrication.
# ---------------------------------------------------------------------------

set -euo pipefail

OUT_JSON="kill_chain_evidence.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ARTIFACTS=(baseline_clinical.json phishing_click_evidence.json \
           c2_beacon_evidence.json dns_tunnel_evidence.json \
           lateral_movement_evidence.json vpn_pivot_evidence.json)

MISSING=0
for f in "${ARTIFACTS[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "WARNING: artifact $f not found in working directory" >&2
        MISSING=1
    fi
done
if [[ "$MISSING" -eq 1 ]]; then
    echo "WARNING: proceeding with degraded phases for missing artifacts" >&2
fi

# --- optional tshark anchor: exfil tunnel window (absolute epochs) ---------
# NOTE: dns.flags.response is a bitfield boolean — negating it with '!'
#       silently matches zero frames. Always compare explicitly: == 0.
TUNNEL_EPOCHS=""
if [[ -f dns_exfil.pcap ]] && command -v tshark >/dev/null 2>&1; then
    tshark -r dns_exfil.pcap \
        -Y 'dns.qry.name contains "data-sync.meddefense-portal.com" && dns.flags.response == 0' \
        -T fields -e frame.time_epoch > "$TMP/tunnel_epochs.tsv" 2>/dev/null || true
    if [[ -s "$TMP/tunnel_epochs.tsv" ]]; then
        TUNNEL_EPOCHS="$TMP/tunnel_epochs.tsv"
        echo "ANCHOR SOURCE: dns_exfil.pcap ($(wc -l < "$TMP/tunnel_epochs.tsv") matching queries)"
    else
        echo "WARNING: dns_exfil.pcap present but tunnel filter matched 0 queries" >&2
    fi
fi

python3 - "$(pwd)" "$TUNNEL_EPOCHS" "$OUT_JSON" <<'PYEOF'
import datetime
import json
import os
import re
import sys

workdir, tunnel_epochs_path, out_json = sys.argv[1], sys.argv[2], sys.argv[3]

LOCAL_OFFSET = datetime.timedelta(hours=2)  # PCAP wall-clock frame (+0200)
EPOCH_ORIGIN = datetime.datetime(1970, 1, 1)  # naive UTC

# --- 4x00 context constants (7-click_investigation.md) ----------------------
CTX = {
    "source_file": "4x00_phishing_dissection/7-click_investigation.md",
    "recipient": "dmarsh@meddefense.com",
    "email_id": "E2",
    "minutes_before_click": 15,
    "url_params": "id=dmarsh, token=a8f3e2d1",
    "status": ("4x00 verdict: CONFIRMED CLICK — compromise status UNKNOWN "
               "from email evidence alone"),
}

def load(name):
    try:
        with open(os.path.join(workdir, name)) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None

baseline = load("baseline_clinical.json")
phish = load("phishing_click_evidence.json")
beacon = load("c2_beacon_evidence.json")
tunnel = load("dns_tunnel_evidence.json")
lateral = load("lateral_movement_evidence.json")
vpn = load("vpn_pivot_evidence.json")

ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d+))?"
    r"(?:([+-])(\d{2})(\d{2}))?$")

def parse_iso(s):
    """Parse ISO timestamp with optional 9-digit fraction and offset.
    Returns naive UTC datetime."""
    if not s:
        return None
    m = ISO_RE.match(str(s).strip())
    if not m:
        return None
    frac = (m.group(3) or "0")[:6].ljust(6, "0")
    dt = datetime.datetime.strptime(
        m.group(1) + " " + m.group(2), "%Y-%m-%d %H:%M:%S")
    dt = dt.replace(microsecond=int(frac))
    if m.group(4):  # explicit offset -> convert to UTC
        delta = datetime.timedelta(hours=int(m.group(5)),
                                   minutes=int(m.group(6)))
        dt = dt - delta if m.group(4) == "+" else dt + delta
    return dt

def utc(epoch):
    """Unix epoch -> naive UTC datetime (timezone-independent, no
    deprecation)."""
    return EPOCH_ORIGIN + datetime.timedelta(seconds=float(epoch))

def naive_local_to_utc(dt):
    """Artifact wall-clock (+0200) -> naive UTC."""
    if dt is None:
        return None
    return dt - LOCAL_OFFSET

def parse_clock_date(clock, datestr):
    """'16:30:12.445' on date '2026-04-15' -> naive local datetime."""
    try:
        t = datetime.datetime.strptime(clock.split(".")[0], "%H:%M:%S")
        base = datetime.datetime.strptime(datestr, "%Y-%m-%d")
        return base.replace(hour=t.hour, minute=t.minute, second=t.second)
    except (ValueError, TypeError):
        return None

def fmt(dt):
    """Format a naive UTC datetime."""
    if dt is None:
        return "<unknown>"
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def hhmm(seconds):
    if seconds is None:
        return "<unknown>"
    m = int(round(seconds / 60))
    return "%dh %02dm" % (m // 60, m % 60)

# ---------------------------------------------------------------------------
# PARSE ARTIFACTS INTO TIMELINE ANCHORS
# ---------------------------------------------------------------------------
events = []  # (dt, phase, label, kind) kind: CONTEXT | PACKET | INFERENCE

# --- Phase 1/2: phishing email + click --------------------------------------
click_dt = None
click_end_dt = None
if phish:
    click_dt = parse_iso(phish["connection_start"])
    click_end_dt = parse_iso(phish.get("connection_end"))
if click_dt:
    email_dt = click_dt - datetime.timedelta(
        minutes=CTX["minutes_before_click"])
    events.append((email_dt, 1, "phishing email E2 delivered to "
                  + CTX["recipient"], "CONTEXT"))
    events.append((click_dt, 2, "victim connected to "
                  + str(phish.get("phishing_domain", "?")) + " ("
                  + str(phish.get("phishing_ip", "?")) + ") from "
                  + str(phish.get("victim_workstation", "?")), "PACKET"))
    if click_end_dt:
        events.append((click_end_dt, 2, "credential-harvest session closed "
                      "(%.1fs)" % phish.get("session_duration_s", 0),
                      "PACKET"))

# --- Phase 3: C2 beaconing ---------------------------------------------------
beacon_first = beacon_last = None
b = {}
beacon_ip = None
if beacon and beacon.get("capture_beacons"):
    beacon_ip, b = next(iter(beacon["capture_beacons"].items()))
    beacon_first = utc(b["first_beacon_epoch"])
    beacon_last = utc(b["last_beacon_epoch"])
    events.append((beacon_first, 3, "first C2 beacon (behavioral detection,"
                  " CV %.2f%%)" % b["regularity_cv_pct"], "PACKET"))
    events.append((beacon_last, 3, "last observed C2 beacon (%d total, "
                  "avg %.1fs interval)" % (b["total_beacons"],
                  b["avg_interval_s"]), "PACKET"))

# --- Phase 4: VPN pivot ------------------------------------------------------
vpn_start = vpn_end = None
v = vpn.get("vpn_session") if vpn else None
if v:
    vpn_start = naive_local_to_utc(parse_iso(v["start"].replace(" ", "T")))
    if vpn_start and v.get("duration_minutes") is not None:
        vpn_end = vpn_start + datetime.timedelta(
            minutes=v["duration_minutes"])
    if vpn_start:
        sni_part = ""
        if v.get("tls_sni") and len(v["tls_sni"]) > 0:
            sni_part = " (SNI: %s)" % v["tls_sni"][0]
        events.append((vpn_start, 4, "inbound external TLS session from "
                      + v["source_ip"] + " to " + v["destination"]
                      + ":" + str(v["destination_port"]) + sni_part,
                      "PACKET"))
        if vpn_end:
            events.append((vpn_end, 4, "VPN session teardown (%.1f min "
                          "duration)" % v["duration_minutes"], "PACKET"))

# --- Phase 5/6: lateral movement ----------------------------------------------
lat_date = "2026-04-15"
if vpn and vpn.get("timeline_correlation", {}).get("first_lateral_movement"):
    lat_date = vpn["timeline_correlation"]["first_lateral_movement"][:10]

rdp_dt = None
rdp_c = {}
smb_dts = []        # list of (dt, connection dict)
tls_dts = []        # list of (dt, connection dict)
no_resp_dsts = []   # list of (dt, dst)
smb_completed_dsts = set()
if lateral:
    for c in lateral.get("connections", []):
        if not c.get("time"):
            continue
        dt = naive_local_to_utc(parse_clock_date(c["time"], lat_date))
        if not dt:
            continue
        if c.get("port") == 3389:
            rdp_dt = dt
            rdp_c = c
            events.append((dt, 5, "RDP pivot %s -> %s (cross-subnet, "
                          "%d B exchanged)" % (c["src"], c["dst"],
                          c.get("client_bytes", 0)
                          + c.get("server_bytes", 0)), "PACKET"))
        elif c.get("port") == 445:
            smb_dts.append((dt, c))
            if "WITHOUT RESPONSE" in c.get("outcome", ""):
                no_resp_dsts.append((dt, c["dst"]))
            else:
                smb_completed_dsts.add(c["dst"])
        elif c.get("port") == 443:
            tls_dts.append((dt, c))
    if smb_dts:
        first_smb_dt = min(dt for dt, _c in smb_dts)
        events.append((first_smb_dt, 6, "SMB enumeration begins from "
                      + smb_dts[0][1]["src"] + " ("
                      + str(len(smb_dts)) + " SMB sessions)", "PACKET"))
    if tls_dts:
        events.append((tls_dts[0][0], 5, "first of "
                      + str(len(tls_dts)) + " internal TLS sessions to "
                      + tls_dts[0][1]["dst"] + " (legitimate portal host, "
                      "credential-validation consistent)", "INFERENCE"))
    for dt, dst in no_resp_dsts:
        events.append((dt, 6, "SMB attempt to " + dst
                      + " received no response — segmentation held",
                      "PACKET"))

# --- Phase 7: DNS exfiltration ------------------------------------------------
exfil_first = exfil_last = None
if tunnel_epochs_path and os.path.exists(tunnel_epochs_path):
    epochs = []
    try:
        with open(tunnel_epochs_path) as fh:
            epochs = [float(ln.strip()) for ln in fh if ln.strip()]
    except (OSError, ValueError):
        epochs = []
    if epochs:
        exfil_first = utc(min(epochs))
        exfil_last = utc(max(epochs))
elif tunnel:
    print("WARNING: dns_exfil.pcap not available — Phase 7 window lacks "
          "absolute anchor", file=sys.stderr)
if tunnel:
    label_txt = "DNS TXT tunnel queries from " + str(tunnel.get("source_host"))
    if exfil_first:
        events.append((exfil_first, 7, label_txt + " begin (window anchor "
                      "from dns_exfil.pcap tshark filter)", "PACKET"))
        events.append((exfil_last, 7, "last anomalous tunnel query ("
                      + str(tunnel.get("anomalous_query_count"))
                      + " queries, %.2f min span)"
                      % tunnel.get("span_minutes", 0), "PACKET"))
    else:
        events.append((None, 7, label_txt + " (absolute start not in artifact "
                      "and dns_exfil.pcap unavailable)", "PACKET"))

# --- derived values used by multiple sections --------------------------------
decoded_classes = []
ex = {}
cmds = []
if tunnel:
    for d in tunnel.get("sample_decodes", []):
        txt = d.get("decoded_text")
        if txt is not None:
            txt_str = str(txt)
            if not txt_str.startswith("CMD"):
                decoded_classes.append(txt_str.split(":")[0])
            else:
                cmds.append(txt_str)
    decoded_classes = sorted(set(decoded_classes))
    ex = tunnel.get("estimated_exfil", {}) or {}

baseline_dsts = set()
base_txt_rate = 0.0
if baseline:
    baseline_dsts = {d["ip"] for d in
                     baseline.get("destination_connections_top", [])}
    base_txt_rate = (baseline.get("dns", {}).get("txt_queries", 0)
                     / baseline.get("duration_minutes", 1)) \
        if baseline.get("duration_minutes") else 0.0

events = [e for e in events if e[0] is not None]
events.sort(key=lambda e: e[0])

# ---------------------------------------------------------------------------
# HEADER + DWELL TIME
# ---------------------------------------------------------------------------
period_start = events[0][0] if events else None
period_end = events[-1][0] if events else None

print("=" * 64)
print("   COMPLETE KILL CHAIN RECONSTRUCTION")
print("   Incident: Phishing -> Credential Harvest -> VPN Pivot -> "
      "Lateral Movement -> DNS Exfiltration")
print("   Period (UTC): %s to %s" % (fmt(period_start), fmt(period_end)))
if click_dt and exfil_last:
    dwell_pkt = (exfil_last - click_dt).total_seconds()
    print("   Dwell time (packet-anchored, click -> last exfil): %s"
          % hhmm(dwell_pkt))
    if period_start and period_start < click_dt:
        dwell_ctx = (exfil_last - period_start).total_seconds()
        print("   Dwell time (context-extended, email delivery anchor): %s"
              "  [E2 delivery = context, not packet evidence]"
              % hhmm(dwell_ctx))
elif period_start and period_end:
    print("   Dwell time: not computable (exfil window anchor unavailable)")
print("=" * 64)

# ---------------------------------------------------------------------------
# PHASE DETAIL
# ---------------------------------------------------------------------------
print()
print("PHASE 1: INITIAL ACCESS (T1566.002 Spearphishing Link)")
print("  Time:   %s  [CONTEXT]"
      % fmt(click_dt - datetime.timedelta(minutes=CTX["minutes_before_click"])
            if click_dt else None))
print("  Source: %s (4x00 email evidence, not packet evidence)"
      % CTX["source_file"])
print("  Action: spearphishing email %s delivered to %s; lure impersonated"
      % (CTX["email_id"], CTX["recipient"]))
print("          MedDefense IT with a fabricated 24-hour re-verification"
      " deadline")
print("  Detail: URL parameters %s (per-victim attribution)"
      % CTX["url_params"])
print("  Verdict: %s" % CTX["status"])

if phish:
    print()
    print("PHASE 2: CREDENTIAL HARVESTING SESSION (T1566.002 / "
          "T1056.003 Web Portal Capture)")
    print("  Time:   %s to %s  [PACKET EVIDENCE]"
          % (fmt(click_dt), fmt(click_end_dt)))
    print("  PCAP:   %s" % phish.get("capture"))
    print("  Flow:   %s -> %s (%s)"
          % (phish.get("victim_workstation"), phish.get("phishing_domain"),
             phish.get("phishing_ip")))
    rec = phish.get("largest_client_tls_record", {})
    print("  Evidence: largest client TLS record %s bytes at %s; session"
          " %ss, %d client bytes / %d server bytes"
          % (rec.get("bytes"), rec.get("time"),
             phish.get("session_duration_s"), phish.get("client_bytes"),
             phish.get("server_bytes")))
    print("  Assessment [INFERENCE]: %s"
          % phish.get("credential_submission_verdict"))

if b:
    print()
    print("PHASE 3: COMMAND AND CONTROL BEACONING "
          "(T1071.001 Web Protocols)")
    print("  Time:   %s to %s (UTC)  [PACKET EVIDENCE]"
          % (fmt(beacon_first), fmt(beacon_last)))
    print("  PCAP:   c2_beaconing.pcap")
    print("  Flow:   %s -> %s" % (beacon.get("victim"), beacon_ip))
    print("  Pattern: %d sessions, %.2fs avg interval, stddev %.2fs,"
          " CV %.2f%%" % (b["total_beacons"], b["avg_interval_s"],
                          b["interval_stddev_s"], b["regularity_cv_pct"]))
    print("  Baseline: destination not in Task 0 baseline (in_task0_baseline:"
          " %s)" % b.get("in_task0_baseline"))
    print("  Method:  %s" % beacon.get("detection_method"))

if v:
    g = vpn.get("geolocation", {})
    print()
    print("PHASE 4: EXTERNAL ACCESS / VPN PIVOT "
          "(T1133 External Remote Services)")
    print("  Time:   %s to %s (UTC), %.1f min  [PACKET EVIDENCE]"
          % (fmt(vpn_start), fmt(vpn_end), v.get("duration_minutes") or 0))
    print("  PCAP:   full_timeline.pcap")
    sni_display = ""
    if v.get("tls_sni") and len(v["tls_sni"]) > 0:
        sni_display = " (SNI: %s)" % v["tls_sni"][0]
    print("  Flow:   %s:%s -> %s:%s%s"
          % (v["source_ip"], v["source_port"], v["destination"],
             v["destination_port"], sni_display))
    if g.get("available"):
        print("  Origin: %s / %s / %s  [WHOIS: %s]"
              % (g.get("country"), g.get("asn"), g.get("org"),
                 g.get("tool_used")))
        print("  %s" % g.get("assessment"))
    print("  Determination: %s" % v.get("determination"))
    print("  Credential use: INFERENCE ONLY — payloads encrypted (%s)"
          % v.get("authentication_context", ""))

if lateral:
    print()
    print("PHASE 5: LATERAL MOVEMENT "
          "(T1021.001 Remote Desktop Protocol)")
    print("  Time:   %s (UTC)  [PACKET EVIDENCE]" % fmt(rdp_dt))
    print("  PCAP:   lateral_movement.pcap")
    print("  Flow:   %s -> %s [cross-subnet]"
          % (rdp_c.get("src"), rdp_c.get("dst")))
    print("  Volume: %d B client / %d B server — interactive session,"
          " clean FIN teardown"
          % (rdp_c.get("client_bytes", 0), rdp_c.get("server_bytes", 0)))
    print("  Account: not visible in packet capture (NBSS/RDP payloads"
          " below dissection depth) — account attribution is inference")
    if tls_dts:
        print("  Related: %d internal TLS sessions to %s (portal host per"
              " Task 1 DNS correlation) during the pivot window"
              % (len(tls_dts), tls_dts[0][1]["dst"]))
        print("  [INFERENCE: consistent with harvested-credential"
              " validation]")

    print()
    print("PHASE 6: DISCOVERY / INTERNAL SPREAD "
          "(T1135, T1021.002, T1083)")
    if smb_dts:
        print("  Time:   %s to %s (UTC)  [PACKET EVIDENCE]"
              % (fmt(min(dt for dt, _c in smb_dts)),
                 fmt(max(dt for dt, _c in smb_dts))))
        print("  PCAP:   lateral_movement.pcap")
        print("  SMB spread from %s:" % smb_dts[0][1]["src"])
        for dst in sorted(smb_completed_dsts):
            sess = [c for _t, c in smb_dts if c["dst"] == dst]
            nbss = sum(c.get("nbss_frames", 0) for c in sess)
            vol = sum(c.get("client_bytes", 0)
                      + c.get("server_bytes", 0) for c in sess)
            print("    %-14s  sessions completed, %d NBSS frames, %d B"
                  % (dst, nbss, vol))
    if no_resp_dsts:
        print("  Segmentation held:")
        for dt, dst in no_resp_dsts:
            print("    %s — no response; diagnostic tshark showed RST"
                  " from gateway 10.10.0.1 (network-layer enforcement)"
                  % dst)

if tunnel:
    print()
    print("PHASE 7: EXFILTRATION (T1048.003 Exfiltration Over Alternative"
          " Protocol)")
    print("  Time:   %s to %s (UTC)  [PACKET EVIDENCE]"
          % (fmt(exfil_first), fmt(exfil_last)))
    print("  PCAP:   dns_exfil.pcap")
    print("  Flow:   %s -> authoritative DNS (TXT) via %s"
          % (tunnel.get("source_host"), tunnel.get("tunnel_base_domain")))
    print("  Volume: %d anomalous queries in %.2f min (%.2f/min); "
          "labels %s chars; entropy %.1f bits/char"
          % (tunnel.get("anomalous_query_count"), tunnel.get("span_minutes"),
             tunnel.get("rate_per_min"),
             "-".join(str(x) for x in tunnel.get("label_length_range", [])),
             tunnel.get("avg_label_entropy_bits", 0)))
    if ex:
        print("  Estimate: %s encoded bytes -> %s raw bytes if base32"
              " [INFERENCE from decoding]"
              % (ex.get("total_encoded_bytes"), ex.get("raw_if_base32")))
    print("  Decoded data classes (sample): %s"
          % (", ".join(decoded_classes) if decoded_classes
             else "<none decoded>"))
    if cmds:
        print("  Orchestration evidence: %s" % "; ".join(cmds))

# ---------------------------------------------------------------------------
# DEFENSE LAYER TEST SEQUENCE
# ---------------------------------------------------------------------------
print()
print("=" * 64)
print("   VISIBILITY / DEFENSE SCORECARD")
print("=" * 64)

print("HELD / RESISTED:")
if no_resp_dsts:
    for _dt, dst in no_resp_dsts:
        print("  - 10.10.4.x restricted subnet: SMB to %s returned no "
              "response (gateway RST per diagnostics)" % dst)
else:
    print("  (none observed)")

print()
print("FAILED OR BYPASSED:")
if phish:
    print("  - User reached lookalike domain %s (session completed, "
          "%.1fs)" % (phish.get("phishing_domain"),
                      phish.get("session_duration_s", 0)))
if b:
    print("  - C2 beaconing ran unimpeded: %d sessions, CV %.2f%% — "
          "no egress interruption observed"
          % (b["total_beacons"], b["regularity_cv_pct"]))
if v:
    print("  - Inbound external VPN session established: sole "
          "inbound-initiated external session vs zero in baseline")
if rdp_dt and rdp_c:
    print("  - Cross-subnet RDP from clinical (%s) to server (%s) "
          "completed" % (rdp_c.get("src"), rdp_c.get("dst")))
if tunnel and base_txt_rate:
    factor = tunnel.get("rate_per_min", 0) / base_txt_rate
    print("  - DNS TXT tunnel operated %.1fx above baseline TXT rate "
          "(%.2f/min vs %.2f/min baseline)"
          % (factor, tunnel.get("rate_per_min", 0), base_txt_rate))

print()
print("ABSENT OR UNCONFIRMED FROM PCAP ALONE:")
if vpn:
    for item in vpn.get("what_the_pcap_cannot_prove", []):
        print("  - %s" % item)
if lateral:
    for lim in lateral.get("capture_depth_limitations", []):
        print("  - %s" % lim)
print("  - Endpoint malware execution, MFA status, SIEM alerting:"
      " no telemetry in any capture")
if tunnel:
    decoded_count = sum(1 for d in tunnel.get("sample_decodes", [])
                        if d.get("decoded_text") is not None)
    total_count = len(tunnel.get("sample_decodes", []))
    print("  - Full exfiltrated content: %d of %d sampled labels decoded "
          "successfully" % (decoded_count, total_count))

# ---------------------------------------------------------------------------
# PIVOT POINTS (analyst assessment layer)
# ---------------------------------------------------------------------------
print()
print("=" * 64)
print("   CRITICAL PIVOT POINTS — INTERVENTION OPPORTUNITIES")
print("=" * 64)
print("  [Analyst assessment layered on packet-anchored timestamps]")
pivot_points = []
if click_dt:
    pivot_points.append((
        click_dt - datetime.timedelta(minutes=CTX["minutes_before_click"]),
        "Mail-gateway / email-authentication filtering of E2 "
        "(4x00 context: lure relied on lookalike domain)"))
    pivot_points.append((
        click_dt,
        "DNS filtering or sinkholing of %s before the browser session"
        % (phish.get("phishing_domain") if phish else "<domain>")))
if beacon_first:
    pivot_points.append((
        beacon_first,
        "Egress allow-listing / interval-regularity detection during the "
        "beacon window (CV %.2f%%)" % b["regularity_cv_pct"]))
if vpn_start:
    pivot_points.append((
        vpn_start,
        "VPN controls: source-IP geo/reputation screening (%s dynamic "
        "block), MFA status unconfirmed"
        % (vpn.get("geolocation", {}).get("asn", "") if vpn else "")))
if rdp_dt:
    pivot_points.append((
        rdp_dt,
        "Clinical-to-server VLAN segmentation for RDP/3389 — this "
        "crossing was NOT blocked"))
if smb_dts:
    pivot_points.append((
        min(dt for dt, _c in smb_dts),
        "Restricting SMB admin-share access and server-to-server spread"))
if exfil_first:
    pivot_points.append((
        exfil_first,
        "DNS TXT rate-limiting / response monitoring at the resolver "
        "(baseline %.2f/min vs observed %.2f/min)"
        % (base_txt_rate, tunnel.get("rate_per_min", 0) if tunnel else 0)))
for dt, action in pivot_points:
    print("  %s  %s" % (fmt(dt), action))

# ---------------------------------------------------------------------------
# IMPACT ASSESSMENT
# ---------------------------------------------------------------------------
print()
print("=" * 64)
print("   IMPACT ASSESSMENT")
print("=" * 64)
print("Systems accessed (packet-confirmed sessions):")
print("  - 10.10.2.15 (WS-NURSE-04) — phished victim, RDP origin")
for dst in sorted(smb_completed_dsts):
    tag = " (baseline peer)" if dst in baseline_dsts else ""
    print("  - %s — SMB session completed%s" % (dst, tag))
print("  - 10.10.1.10 (billing-srv-01) — RDP target and exfil source")
print("Systems that resisted access:")
if no_resp_dsts:
    for _dt, dst in no_resp_dsts:
        print("  - %s — no response, segmentation held" % dst)
else:
    print("  (none observed)")
print("Data likely exfiltrated [INFERENCE from decodes]:")
decoded_str = ", ".join(decoded_classes) if decoded_classes else "<none decoded>"
raw_bytes = ex.get("raw_if_base32", "?") if ex else "?"
print("  - %s — sample-decoded classes; ~%s raw bytes if base32"
      % (decoded_str, raw_bytes))
print("Remains unconfirmed:")
print("  - Credential submission content, VPN account used, MFA posture,")
print("    endpoint execution artifacts, SIEM alerting, full data content")

# ---------------------------------------------------------------------------
# SERIALIZATION
# ---------------------------------------------------------------------------
attck_mapping = [
    {"phase": 1, "technique": "T1566.002", "name": "Spearphishing Link",
     "class": "CONTEXT (4x00 email evidence)"},
    {"phase": 2, "technique": "T1566.002", "name": "Spearphishing Link",
     "class": "PACKET EVIDENCE (session observed)"},
    {"phase": 2, "technique": "T1056.003",
     "name": "Input Capture: Web Portal Capture",
     "class": "INFERENCE (submission metadata-consistent, unproven)"},
]
if b:
    attck_mapping.append({
        "phase": 3, "technique": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "class": "PACKET EVIDENCE (behavioral, CV %.2f%%)"
        % b["regularity_cv_pct"]})
if v:
    sni_confirmed = (v.get("sni_vpn_indication") is True and
                     v.get("tls_sni") and len(v.get("tls_sni", [])) > 0)
    attck_mapping.append({
        "phase": 4, "technique": "T1133",
        "name": "External Remote Services",
        "class": "PACKET EVIDENCE (SNI vpn.meddefense.com)"
        if sni_confirmed
        else "PACKET EVIDENCE (session), VPN attribution contextual"})
    attck_mapping.append({
        "phase": 4, "technique": "T1078.002",
        "name": "Valid Accounts: Domain Accounts",
        "class": "INFERENCE (credential use not dissectable)"})
if rdp_dt:
    attck_mapping.append({
        "phase": 5, "technique": "T1021.001",
        "name": "Remote Desktop Protocol",
        "class": "PACKET EVIDENCE"})
if smb_dts:
    attck_mapping.append({
        "phase": 6, "technique": "T1135",
        "name": "Network Share Discovery",
        "class": "PACKET EVIDENCE"})
    attck_mapping.append({
        "phase": 6, "technique": "T1021.002",
        "name": "SMB/Windows Admin Shares",
        "class": "PACKET EVIDENCE"})
    attck_mapping.append({
        "phase": 6, "technique": "T1083",
        "name": "File and Directory Discovery",
        "class": "PARTIAL (NBSS sessions confirmed; directory detail not "
                 "dissectable)"})
if tunnel:
    attck_mapping.append({
        "phase": 7, "technique": "T1048.003",
        "name": "Exfiltration Over Alternative Protocol: DNS",
        "class": "PACKET EVIDENCE (decoded labels)"})

kill_chain = {
    "time_convention": ("all times UTC (naive internally); PCAP artifacts "
                        "carry +0200 local wall-clock (converted); 4x00 "
                        "context anchored on packet epoch"),
    "master_timeline": [
        {"time": fmt(dt), "phase": phase, "event": label,
         "evidence_class": kind}
        for dt, phase, label, kind in events],
    "dwell_time": {
        "packet_anchored_seconds": int((exfil_last - click_dt)
                                        .total_seconds())
            if click_dt and exfil_last else None,
        "context_extended_seconds": int((exfil_last - period_start)
                                        .total_seconds())
            if period_start and exfil_last else None,
        "from": fmt(click_dt) if click_dt else fmt(period_start),
        "to": fmt(exfil_last) if exfil_last else None,
    },
    "phase1_context": CTX,
    "attck_mapping": attck_mapping,
    "pivot_points": [
        {"time": fmt(dt), "intervention": action}
        for dt, action in pivot_points],
    "impact": {
        "systems_accessed": ["10.10.2.15 (WS-NURSE-04)"]
            + sorted(smb_completed_dsts)
            + ["10.10.1.10 (billing-srv-01)"],
        "systems_resisted": [dst for _dt, dst in no_resp_dsts],
        "data_classes_sample_decoded": decoded_classes,
        "estimated_raw_bytes_base32": ex.get("raw_if_base32"),
        "unconfirmed": [
            "credential submission content",
            "VPN account used (encrypted)",
            "MFA posture", "endpoint execution",
            "SIEM alerting", "full exfiltrated content",
        ],
    },
}

with open(out_json, "w") as fh:
    json.dump(kill_chain, fh, indent=2)
    fh.write("\n")

print()
print("EVIDENCE SAVED: " + out_json)
PYEOF
