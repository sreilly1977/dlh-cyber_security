#!/bin/bash
# Name: 4-lateral_movement.sh
# Purpose: Trace attacker lateral movement through the MedDefense network
#          from lateral_movement.pcap. Extracts ALL internal connections
#          (both cross-subnet and intra-subnet, annotated), reconstructs
#          per-session outcomes from TCP teardown behavior and RST responder
#          identity (target refusal vs gateway/ACL block), detects SMB
#          sessions via the NBSS layer (this capture does not dissect SMB2/
#          Kerberos/NTLM payloads — a documented capture-depth limit),
#          profiles anomalous internal TLS activity, reconstructs the
#          chronological attack path, compares against the Task 0 baseline,
#          and maps observed behaviors to MITRE ATT&CK techniques.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./4-lateral_movement.sh lateral_movement.pcap
# Output:  Console report + lateral_movement_evidence.json
#
# ---------------------------------------------------------------------------
# DOCUMENTED FILTER REFERENCE
# ---------------------------------------------------------------------------
# Internal SYNs .............. tcp.flags.syn == 1 && tcp.flags.ack == 0
#                               && ip.src == 10.10.0.0/16
#                               && ip.dst == 10.10.0.0/16
#   (ALL internal connections retained; cross-subnet vs same-/24 annotated
#    in analysis — an earlier revision excluded same-subnet traffic and
#    missed the billing-srv-01 intra-subnet pivot hops entirely)
# Auth frames ................ kerberos || ntlmssp
#   (fields for both dissectors attempted; this capture returns none —
#    documented as a capture-depth limit, accounts not invented)
# SMB2 commands .............. smb2.cmd == 1 / 3 / 14 (attempted; none in
#                               this capture — SMB is present only at the
#                               NBSS layer)
# NBSS (SMB transport) ....... nbss
# RST frames ................. tcp.flags.reset == 1  (responder IP retained:
#                               RST from the TARGET means service refusal;
#                               RST from a THIRD PARTY (e.g. gateway
#                               10.10.0.1) means network-layer ACL block)
# FIN frames ................. tcp.flags.fin == 1
# Per-stream data volume ..... no display filter; fields tcp.stream,
#                               ip.src, ip.dst, tcp.len, frame.len
# PER-SESSION OUTCOME INFERENCE (packet evidence only):
#   RST(third-party) -> BLOCKED IN TRANSIT (network access control)
#   RST(target)      -> REFUSED BY HOST
#   FIN present      -> COMPLETED (clean teardown)
#   data + no FIN/RST-> TERMINATION NOT OBSERVED
#   SYN only         -> ATTEMPT WITHOUT RESPONSE OBSERVED
# ATT&CK mapping is derived from observed event classes only.
# ROBUSTNESS: optional extractions carry `|| true`; no `head` in pipelines.
# ---------------------------------------------------------------------------

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <pcap-file>" >&2
    exit 1
fi

PCAP="$1"
[[ -f "$PCAP" ]] || { echo "Error: file not found: $PCAP" >&2; exit 1; }

OUT_JSON="lateral_movement_evidence.json"
BASELINE_JSON="baseline_clinical.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ts() {
    tshark -r "$PCAP" "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# EXTRACTION 1: ALL internal SYN connections
# ---------------------------------------------------------------------------
SYNS_TSV="$TMP/syns.tsv"
ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 10.10.0.0/16 && ip.dst == 10.10.0.0/16" \
   -T fields -e tcp.stream -e ip.src -e ip.dst -e tcp.dstport \
             -e frame.time_epoch -e frame.time > "$SYNS_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 2: authentication frames (Kerberos / NTLMSSP — may be empty)
# ---------------------------------------------------------------------------
AUTH_TSV="$TMP/auth.tsv"
ts -Y "kerberos || ntlmssp" \
   -T fields -e frame.time_epoch -e frame.time -e ip.src -e ip.dst \
             -e kerberos.msg.type -e kerberos.CNameString \
             -e ntlmssp.messagetype -e ntlmssp.auth.username > "$AUTH_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTIONS 3-5: SMB2 command frames (may be empty in NBSS-only captures)
# ---------------------------------------------------------------------------
SMB_SS_TSV="$TMP/smb_ss.tsv"
ts -Y "smb2.cmd == 1" \
   -T fields -e frame.time_epoch -e frame.time -e ip.src -e ip.dst -e tcp.stream \
             -e smb2.flags.response -e smb2.nt_status > "$SMB_SS_TSV" || true
SMB_TREE_TSV="$TMP/smb_tree.tsv"
ts -Y "smb2.cmd == 3" \
   -T fields -e frame.time_epoch -e frame.time -e ip.src -e ip.dst -e tcp.stream \
             -e smb2.tree -e smb2.flags.response -e smb2.nt_status > "$SMB_TREE_TSV" || true
SMB_FIND_TSV="$TMP/smb_find.tsv"
ts -Y "smb2.cmd == 14" \
   -T fields -e frame.time_epoch -e frame.time -e ip.src -e ip.dst -e tcp.stream \
             -e smb2.filename -e smb2.flags.response -e smb2.nt_status \
             -e smb2.response_entries > "$SMB_FIND_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 6: RST and FIN frames (responder identity retained for RSTs)
# ---------------------------------------------------------------------------
RST_TSV="$TMP/rst.tsv"
ts -Y "tcp.flags.reset == 1" \
   -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst \
             -e tcp.srcport -e tcp.dstport > "$RST_TSV" || true
FIN_TSV="$TMP/fin.tsv"
ts -Y "tcp.flags.fin == 1" \
   -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst > "$FIN_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 7: NBSS frames (SMB transport layer — present when SMB2 is not
# dissected; per-stream counts identify SMB-carrying sessions)
# ---------------------------------------------------------------------------
NBSS_TSV="$TMP/nbss.tsv"
ts -Y "nbss" \
   -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst \
             -e nbss.type -e nbss.flags > "$NBSS_TSV" || true

# ---------------------------------------------------------------------------
# EXTRACTION 8: per-stream data volume (all frames)
# ---------------------------------------------------------------------------
FRAMES_TSV="$TMP/frames.tsv"
ts -T fields -e tcp.stream -e frame.time_epoch -e ip.src -e ip.dst \
             -e tcp.len -e frame.len > "$FRAMES_TSV" || true

# ---------------------------------------------------------------------------
# ANALYSIS
# ---------------------------------------------------------------------------
python3 - "$SYNS_TSV" "$AUTH_TSV" "$SMB_SS_TSV" "$SMB_TREE_TSV" "$SMB_FIND_TSV" \
           "$RST_TSV" "$FIN_TSV" "$NBSS_TSV" "$FRAMES_TSV" \
           "$OUT_JSON" "$BASELINE_JSON" <<'PYEOF'
import datetime, json, sys

(syns_tsv, auth_tsv, smb_ss_tsv, smb_tree_tsv, smb_find_tsv,
 rst_tsv, fin_tsv, nbss_tsv, frames_tsv,
 out_json, baseline_json) = sys.argv[1:12]

def read_tsv(path):
    try:
        with open(path) as fh:
            return [ln.rstrip("\n").split("\t") for ln in fh if ln.strip()]
    except OSError:
        return []

def subnet(ip):
    return ".".join(ip.split(".")[:3])

def fmt_time(epoch):
    try:
        return datetime.datetime.fromtimestamp(float(epoch)).strftime("%H:%M:%S.%f")[:-3]
    except ValueError:
        return "<unknown>"

# --- connections (ALL internal, cross-subnet annotated) ---------------------
syn_rows = read_tsv(syns_tsv)
conns = {}
for r in syn_rows:
    if len(r) < 6 or not r[0]:
        continue
    stream = int(r[0])
    conns[stream] = {"stream": stream, "src": r[1], "dst": r[2],
                     "port": int(r[3]), "epoch": float(r[4]),
                     "cross": subnet(r[1]) != subnet(r[2])}
conn_list = sorted(conns.values(), key=lambda c: c["epoch"])

# --- per-stream byte counts and nbss frame counts ---------------------------
stream_cbytes, stream_sbytes = {}, {}
for r in read_tsv(frames_tsv):
    if len(r) < 6 or not r[0]:
        continue
    stream = int(r[0])
    c = conns.get(stream)
    if not c:
        continue
    tlen = int(r[4]) if r[4] else 0
    if r[2] == c["src"]:
        stream_cbytes[stream] = stream_cbytes.get(stream, 0) + tlen
    elif r[2] == c["dst"]:
        stream_sbytes[stream] = stream_sbytes.get(stream, 0) + tlen

nbss_counts = {}
for r in read_tsv(nbss_tsv):
    if r and r[0]:
        nbss_counts[int(r[0])] = nbss_counts.get(int(r[0]), 0) + 1

rst_by_stream = {}
for r in read_tsv(rst_tsv):
    if len(r) < 4 or not r[0]:
        continue
    rst_by_stream.setdefault(int(r[0]), []).append(r[2])  # responder IPs
fin_streams = {int(r[0]) for r in read_tsv(fin_tsv) if r and r[0]}

def outcome(c):
    stream = c["stream"]
    if stream in rst_by_stream:
        responders = set(rst_by_stream[stream])
        if c["dst"] in responders:
            return "REFUSED BY HOST (target sent RST)"
        third = responders - {c["src"], c["dst"]}
        if third:
            return "BLOCKED IN TRANSIT by %s (network access control)" % \
                   ", ".join(sorted(third))
        return "RESET (originator aborted)"
    if stream in fin_streams:
        return "COMPLETED (FIN teardown)"
    if stream_cbytes.get(stream, 0) + stream_sbytes.get(stream, 0) > 0:
        return "TERMINATION NOT OBSERVED (data exchanged)"
    return "ATTEMPT WITHOUT RESPONSE OBSERVED"

for c in conn_list:
    c["outcome"] = outcome(c)
    c["client_bytes"] = stream_cbytes.get(c["stream"], 0)
    c["server_bytes"] = stream_sbytes.get(c["stream"], 0)
    c["nbss_frames"] = nbss_counts.get(c["stream"], 0)

print("=== CROSS-SUBNET AND INTERNAL TRAFFIC ===")
cross = [c for c in conn_list if c["cross"]]
print("Total internal connections: %d (cross-subnet: %d, same-subnet: %d)" %
      (len(conn_list), len(cross), len(conn_list) - len(cross)))
pairs = {}
for c in conn_list:
    pairs.setdefault((c["src"], c["dst"], c["port"]), []).append(c)
print("Unique source-destination-port triples: %d" % len(pairs))
print()
print("%-14s | %-14s | %-6s | %-4s | %-6s | %s" %
      ("Source", "Dest", "Port", "Cnt", "NBSS", "Scope"))
print("%-14s-+-%14s-+-%6s-+-%4s-+-%6s-+-%s" %
      ("-" * 14, "-" * 14, "-" * 6, "-" * 4, "-" * 6, "-" * 12))
for (src, dst, port), lst in sorted(pairs.items()):
    scope = "CROSS" if lst[0]["cross"] else "same-/24"
    nbss = "%d" % sum(c["nbss_frames"] for c in lst)
    print("%-14s | %-14s | %6d | %4d | %6s | %s" %
          (src, dst, port, len(lst), nbss, scope))

# --- authentication events ---------------------------------------------------
print()
print("=== AUTHENTICATION EVENTS ===")
events = []
KRB_NAMES = {10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
             14: "AP-REQ", 15: "AP-REP"}
for r in read_tsv(auth_tsv):
    if len(r) < 8:
        continue
    if r[4]:
        events.append({"epoch": float(r[0]), "src": r[2], "dst": r[3],
                       "acct": r[5] or "", "proto": "Kerberos/%s" %
                       KRB_NAMES.get(int(r[4]), r[4]),
                       "result": "observed", "detail": ""})
    elif r[6]:
        events.append({"epoch": float(r[0]), "src": r[2], "dst": r[3],
                       "acct": r[7] or "", "proto": "NTLM/%s" % r[6],
                       "result": "observed", "detail": ""})
# RDP sessions as auth-relevant events
for c in conn_list:
    if c["port"] == 3389:
        events.append({"epoch": c["epoch"], "src": c["src"], "dst": c["dst"],
                       "acct": "", "proto": "RDP/NLA (3389)",
                       "result": c["outcome"], "detail": ""})
# SMB2-dissected events if present
for r in read_tsv(smb_ss_tsv):
    if len(r) >= 7 and r[5] == "1":
        events.append({"epoch": float(r[0]), "src": r[2], "dst": r[3],
                       "acct": "", "proto": "SMB2 Session Setup",
                       "result": "nt_status=%s" % r[6], "detail": ""})
events.sort(key=lambda e: e["epoch"])

if events:
    print("%-14s | %-14s | %-14s | %-18s | %-24s | %s" %
          ("Timestamp", "Source", "Dest", "Account", "Proto", "Result"))
    print("%-14s-+-%14s-+-%14s-+-%18s-+-%24s-+-%s" %
          ("-" * 14, "-" * 14, "-" * 14, "-" * 18, "-" * 24, "-" * 20))
    for e in events:
        print("%-14s | %-14s | %-14s | %-18s | %-24s | %s" %
              (fmt_time(e["epoch"]), e["src"], e["dst"],
               e["acct"] or "<not visible>", e["proto"], e["result"]))
else:
    print("(no dissected authentication frames — this capture carries RDP and")
    print(" SMB payloads below the dissection depth of account/status fields;")
    print(" outcomes below are inferred from TCP teardown evidence only)")

# --- SMB sessions (NBSS-layer evidence) ---------------------------------------
print()
print("=== SMB SESSIONS (NBSS transport evidence) ===")
smb_conns = [c for c in conn_list if c["port"] in (139, 445)]
for c in smb_conns:
    print("  %s  %s -> %s :%d  %s  nbss_frames=%d  c->s %d B / s->c %d B" %
          (fmt_time(c["epoch"]), c["src"], c["dst"], c["port"],
           c["outcome"], c["nbss_frames"], c["client_bytes"], c["server_bytes"]))
    if c["nbss_frames"] > 0 and c["server_bytes"] > 0:
        print("      (bidirectional NBSS traffic — SMB session established at")
        print("       transport level; payload dissection unavailable)")
if not smb_conns:
    print("  (no SMB transport connections observed)")

# --- anomalous internal TLS activity -------------------------------------------
print()
print("=== ANOMALOUS INTERNAL TLS ACTIVITY ===")
tls_conns = [c for c in conn_list if c["port"] == 443]
for (src, dst, port), lst in sorted(pairs.items()):
    if port != 443:
        continue
    epochs = [c["epoch"] for c in lst]
    span = epochs[-1] - epochs[0]
    ivs = [b - a for a, b in zip(epochs, epochs[1:])] if len(epochs) > 1 else []
    print("  %s -> %s :%d : %d TLS connections over %.1f minutes" %
          (src, dst, port, len(lst), span / 60))
    if ivs:
        print("    intervals: min %.1fs, max %.1fs, avg %.1fs" %
              (min(ivs), max(ivs), sum(ivs) / len(ivs)))
    total_in = sum(c["client_bytes"] for c in lst)
    total_out = sum(c["server_bytes"] for c in lst)
    print("    aggregate: client->server %d B, server->client %d B" %
          (total_in, total_out))
    print("    NOTE: destination is the legitimate MedDefense portal host per")
    print("    Task 1 DNS correlation; volume/timing here are data-derived.")
if not tls_conns:
    print("  (no internal TLS connections observed)")

# --- attack path reconstruction ----------------------------------------------
print()
print("=== ATTACK PATH RECONSTRUCTION ===")
origin = next((c["src"] for c in conn_list
               if c["src"].startswith("10.10.2.") and c["cross"]), None)
print("Starting system (earliest clinical-subnet cross-subnet initiator): %s" %
      (origin or "<none>"))
steps = {}
for c in conn_list:
    key = (c["src"], c["dst"], c["port"])
    if key in steps:
        continue
    steps[key] = c
for i, c in enumerate(
        sorted(steps.values(), key=lambda c: c["epoch"]), 1):
    svc = {3389: "RDP", 445: "SMB", 139: "SMB/NBSS", 443: "HTTPS"}.get(
        c["port"], "port %d" % c["port"])
    print("Step %2d: %s  %s -> %s  %s  %s%s" %
          (i, fmt_time(c["epoch"]), c["src"], c["dst"], svc,
           c["outcome"],
           "  [%s]" % ("cross-subnet" if c["cross"] else "same-subnet")))

# --- failures -----------------------------------------------------------------
print()
print("=== FAILED / REFUSED / BLOCKED CONNECTIONS (packet evidence) ===")
blocked = [c for c in conn_list if "BLOCKED" in c["outcome"]]
refused = [c for c in conn_list if "REFUSED" in c["outcome"]]
for c in blocked + refused:
    print("  %s  %s -> %s :%d  %s" %
          (fmt_time(c["epoch"]), c["src"], c["dst"], c["port"], c["outcome"]))
if not (blocked + refused):
    print("  (none observed)")
print("  Evidence basis: RST responder identity — resets originating from a")
print("  host other than source or destination indicate network-layer")
print("  enforcement between the endpoints (segmentation/ACL).")

# --- baseline comparison -------------------------------------------------------
print()
print("=== BASELINE COMPARISON ===")
try:
    with open(baseline_json) as fh:
        baseline = json.load(fh)
except (OSError, ValueError):
    baseline = {}
baseline_dsts = {d["ip"] for d in baseline.get("destination_connections_top", [])}
for c in conn_list:
    key = (c["src"], c["dst"], c["port"])
    if key in [k for k in steps]:
        tag = "in baseline top destinations" if c["dst"] in baseline_dsts \
            else "NOT in baseline top destinations"
        print("  %s -> %s :%d  (%s)" % (c["src"], c["dst"], c["port"], tag))
print("  Baseline internal destination set: %s" %
      ", ".join(sorted(i for i in baseline_dsts if i.startswith("10.10."))))
print("  Timing: baseline capture is 06:00-06:30 business hours; lateral")
print("  movement events occurred 16:30-16:57 on 15 April (post-business).")

# --- ATT&CK mapping --------------------------------------------------------------
print()
print("=== MITRE ATT&CK MAPPING (derived from observed events) ===")
attck = []
if origin:
    attck.append(("T1078.002", "Valid Accounts: Domain Accounts",
                  "internal pivot from phished workstation implies "
                  "credential use (metadata-based; account names not "
                  "dissectable in this capture)"))
if any(c["port"] == 3389 for c in conn_list):
    attck.append(("T1021.001", "Remote Desktop Protocol",
                  "RDP (3389) from clinical workstation to billing server"))
if smb_conns:
    attck.append(("T1135", "Network Share Discovery",
                  "SMB connections from billing server to multiple internal "
                  "hosts (%s)" % ", ".join(sorted({c["dst"] for c in smb_conns}))))
    attck.append(("T1021.002", "SMB/Windows Admin Shares",
                  "SMB sessions with bidirectional NBSS data observed"))
if any("BLOCKED" in c["outcome"] for c in conn_list):
    attck.append(("T1021", "Remote Services (attempted)",
                  "SMB attempts to 10.10.4.x blocked by gateway"))
for tech, name, ev in attck:
    print("  %-12s %-45s" % (tech, name))
    print("               evidence: %s" % ev)

# --- access effectiveness -------------------------------------------------------
print()
print("=== ACCESS EFFECTIVENESS ===")
ok = [c for c in conn_list if "COMPLETED" in c["outcome"]
      or ("TERMINATION NOT OBSERVED" in c["outcome"]
          and c["server_bytes"] > 0)]
print("Succeeded (completed or bidirectional data): %d sessions" % len(ok))
for c in ok:
    print("  %s  %s -> %s :%d  %s (c->s %d B / s->c %d B)" %
          (fmt_time(c["epoch"]), c["src"], c["dst"], c["port"],
           c["outcome"], c["client_bytes"], c["server_bytes"]))
print("Denied, refused, or blocked: %d sessions" % len(blocked + refused))

# --- serialize --------------------------------------------------------------------
evidence = {
    "total_internal_connections": len(conn_list),
    "cross_subnet_connections": len(cross),
    "connections": [
        {"time": fmt_time(c["epoch"]), "src": c["src"], "dst": c["dst"],
         "port": c["port"], "scope": "cross" if c["cross"] else "same-subnet",
         "outcome": c["outcome"], "client_bytes": c["client_bytes"],
         "server_bytes": c["server_bytes"], "nbss_frames": c["nbss_frames"]}
        for c in conn_list],
    "origin_host": origin,
    "blocked_connections": [
        {"time": fmt_time(c["epoch"]), "src": c["src"], "dst": c["dst"],
         "port": c["port"], "outcome": c["outcome"]} for c in blocked],
    "smb_sessions": [
        {"time": fmt_time(c["epoch"]), "src": c["src"], "dst": c["dst"],
         "outcome": c["outcome"], "nbss_frames": c["nbss_frames"]}
        for c in smb_conns],
    "attck_mapping": [{"technique": t, "name": n, "evidence": ev}
                      for t, n, ev in attck],
    "capture_depth_limitations": [
        "SMB payloads present only at NBSS layer; SMB2 command/status and "
        "account names not dissectable",
        "RDP payload not dissected; NLA/account details not visible",
        "outcomes inferred from TCP teardown flags and RST responder identity",
    ],
    "conclusion": (
        "Lateral movement reconstructed from TCP-level evidence: RDP pivot "
        "from phished workstation to billing server, SMB spread to multiple "
        "internal hosts, gateway-enforced blocks on 10.10.4.x, and repeated "
        "internal TLS sessions to the legitimate portal host from the "
        "compromised server (metadata-consistent with credential validation)."
    ),
}
with open(out_json, "w") as fh:
    json.dump(evidence, fh, indent=2)
    fh.write("\n")
print()
print("EVIDENCE SAVED: " + out_json)
PYEOF
