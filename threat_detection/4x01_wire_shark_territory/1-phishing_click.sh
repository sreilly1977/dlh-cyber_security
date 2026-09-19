#!/bin/bash
# Name: 1-phishing_click.sh
# Purpose: Dissect phishing_click.pcap — the exact phishing-click event. Extract
#          DNS resolution of the credential-harvesting domain, TLS ClientHello
#          metadata, server certificate (where dissected), bidirectional data
#          exchange volumes, precise session timeline, and post-click user
#          behavior. Correlates all findings with the 4x00 IOC set and the
#          Task 0 baseline (baseline_clinical.json). All analysis uses tshark;
#          every filter is documented here and inline for reproducibility.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./1-phishing_click.sh phishing_click.pcap
# Output:  Console report + phishing_click_evidence.json
#
# ---------------------------------------------------------------------------
# DOCUMENTED FILTER REFERENCE
# ---------------------------------------------------------------------------
# Phishing DNS query ....... dns.qry.name contains "meddefense-portal"
#                            (seed IOC from 4x00; resolved IP taken from the
#                             actual dns.a response, never assumed)
# DNS response frames ....... dns.flags.response == 1 (answers)
# TCP handshake .............. tcp.flags.syn == 1 (SYN and SYN-ACK)
# TLS ClientHello ........... tls.handshake.type == 1
# TLS version offered ....... tls.handshake.version (legacy field)
#                            + tls.handshake.extensions.supported_version
#                            (NOTE: dotted form — correct for tshark 4.7.3)
# Cipher suites ............. tls.handshake.ciphersuite (list)
# SNI ........................ tls.handshake.extensions_server_name
# Certificate ................ tls.handshake.type == 11
#                            + x509af.serialNumber, x509af.validity_notBefore,
#                              x509af.validity_notAfter,
#                              x509ce.dNSName / x509sat.printableString
# Client data segments ....... tcp.len > 0 && ip.src == $VICTIM
#                                              && ip.dst == $PHISH_IP
# Server data segments ....... tcp.len > 0 && ip.src == $PHISH_IP
#                                              && ip.dst == $VICTIM
# TLS records ................ tls.record.length (record sizes)
# Session teardown ........... tcp.flags.fin == 1 || tcp.flags.reset == 1
# Post-click legit query .... dns.qry.name == "meddefense.com"
#                            (queries AFTER the phishing session ends)
# ROBUSTNESS NOTES:
#   * Extractions that may legitimately return nothing are suffixed with
#     `|| true` so empty evidence is reported, not fatal (set -e).
#   * First-line selection uses `awk 'NR == 1 { print; exit }'` rather than
#     `head -n 1`, which can SIGPIPE tshark (exit 141) under pipefail.
#   * The ts() wrapper suppresses tshark stderr; for interactive debugging
#     run the underlying tshark commands manually without redirection.
# ---------------------------------------------------------------------------

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <pcap-file>" >&2
    exit 1
fi

PCAP="$1"
[[ -f "$PCAP" ]] || { echo "Error: file not found: $PCAP" >&2; exit 1; }

# 4x00 IOC seed (context only — the script verifies every match in-packet)
IOC_DOMAIN_SEED="meddefense-portal"
LEGIT_PORTAL="meddefense.com"

OUT_JSON="phishing_click_evidence.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ts() {
    tshark -r "$PCAP" "$@" 2>/dev/null
}

fmt_time() { echo "$1" | cut -dT -f2 | cut -d+ -f1; }

# ---------------------------------------------------------------------------
# 1. DNS RESOLUTION of the phishing domain
#    Filter: dns.qry.name contains "<seed>"
#    REQUIRED CHAIN: strict failure if the seed domain is absent.
# ---------------------------------------------------------------------------
echo "=== DNS RESOLUTION ==="

DNS_Q_TSV="$TMP/dns_query.tsv"
ts -Y "dns.qry.name contains \"$IOC_DOMAIN_SEED\" && dns.flags.response == 0" \
   -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name > "$DNS_Q_TSV"

if [[ -s "$DNS_Q_TSV" ]]; then
    QUERY_TIME=$(awk -F'\t' 'NR == 1 { print $1 }' "$DNS_Q_TSV")
    QUERY_NAME=$(awk -F'\t' 'NR == 1 { print $4 }' "$DNS_Q_TSV")
    VICTIM=$(awk -F'\t' 'NR == 1 { print $2 }' "$DNS_Q_TSV")
    DNS_RESOLVER=$(awk -F'\t' 'NR == 1 { print $3 }' "$DNS_Q_TSV")
else
    echo "[!] No DNS query matching '$IOC_DOMAIN_SEED' found — cannot proceed with click analysis" >&2
    exit 1
fi

DNS_R_TSV="$TMP/dns_response.tsv"
ts -Y "dns.qry.name contains \"$IOC_DOMAIN_SEED\" && dns.flags.response == 1" \
   -T fields -e frame.time -e dns.a -e dns.resp.ttl > "$DNS_R_TSV" || true

RESP_TIME=$(awk -F'\t' 'NR == 1 { print $1 }' "$DNS_R_TSV")
PHISH_IP=$(awk -F'\t' 'NR == 1 { split($2, a, ","); print a[1] }' "$DNS_R_TSV")
DNS_TTL=$(awk -F'\t' 'NR == 1 { print $3 }' "$DNS_R_TSV")

printf '%s  Query: %s\n' "$(fmt_time "$QUERY_TIME")" "$QUERY_NAME"
printf '%s  Response: %s\n' "$(fmt_time "$RESP_TIME")" "$PHISH_IP"
echo "TTL: $DNS_TTL"
echo "Source: $VICTIM -> $DNS_RESOLVER"
echo "(resolved from $QUERY_NAME)"

# ---------------------------------------------------------------------------
# 2. TLS HANDSHAKE (connection to the resolved phishing IP)
#    Filters: tcp.flags.syn == 1 (SYN / SYN-ACK) / tls.handshake.type == 1
# ---------------------------------------------------------------------------
echo
echo "=== TLS HANDSHAKE ==="

set +o pipefail
SYN_TSV="$TMP/syn.tsv"
ts -Y "tcp.flags.syn == 1 && ip.src == $VICTIM && ip.dst == $PHISH_IP" \
   -T fields -e frame.time -e frame.number -e tcp.flags.ack > "$SYN_TSV" || true
SYNACK_TSV="$TMP/synack.tsv"
ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.src == $PHISH_IP && ip.dst == $VICTIM" \
   -T fields -e frame.time -e frame.number > "$SYNACK_TSV" || true
set -o pipefail

# Evidence retention: the tcp.stream index of the click session
CONN_STREAM=$(ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == $VICTIM && ip.dst == $PHISH_IP" \
   -T fields -e tcp.stream | awk 'NR == 1 { print; exit }') || true

if [[ -s "$SYN_TSV" ]]; then
    echo "$(fmt_time "$(awk -F'\t' 'NR == 1 { print $1 }' "$SYN_TSV")")  SYN -> $PHISH_IP:443"
fi
if [[ -s "$SYNACK_TSV" ]]; then
    echo "$(fmt_time "$(awk -F'\t' 'NR == 1 { print $1 }' "$SYNACK_TSV")")  SYN-ACK"
fi

CLIENTHELLO_TSV="$TMP/clienthello.tsv"
ts -Y "tls.handshake.type == 1 && ip.src == $VICTIM && ip.dst == $PHISH_IP" \
   -T fields -e frame.time \
   -e tls.handshake.extensions_server_name \
   -e tls.handshake.version \
   -e tls.handshake.extensions.supported_version \
   -e tls.handshake.ciphersuite > "$CLIENTHELLO_TSV" || true

if [[ -s "$CLIENTHELLO_TSV" ]]; then
    echo "$(fmt_time "$(awk -F'\t' 'NR == 1 { print $1 }' "$CLIENTHELLO_TSV")")  ClientHello"
    CH_SNI=$(awk -F'\t' 'NR == 1 { print $2 }' "$CLIENTHELLO_TSV")
    CH_VERSION=$(awk -F'\t' 'NR == 1 { print $3 }' "$CLIENTHELLO_TSV")
    CH_SUPP_VERSION=$(awk -F'\t' 'NR == 1 { print $4 }' "$CLIENTHELLO_TSV")
    CIPHERS=$(awk -F'\t' 'NR == 1 { n = split($5, c, ","); print n }' "$CLIENTHELLO_TSV")
    echo "  SNI: ${CH_SNI:-<none>}"
    echo "  TLS version offered: ${CH_SUPP_VERSION:-$CH_VERSION}"
    echo "  Cipher suites offered: ${CIPHERS:-0}"
    awk -F'\t' 'NR == 1 { n = split($5, c, ","); for (i = 1; i <= n && i <= 3; i++) printf "    - %s\n", c[i] }' "$CLIENTHELLO_TSV"
    if [[ "${CIPHERS:-0}" -gt 3 ]]; then
        echo "    ... (remaining suites suppressed for brevity)"
    fi
else
    echo "[!] No ClientHello to $PHISH_IP found (handshake may not be dissected)"
fi

# ---------------------------------------------------------------------------
# 3. SERVER CERTIFICATE (only if Certificate messages exist in this capture)
#    Filter: tls.handshake.type == 11
# ---------------------------------------------------------------------------
echo
echo "=== SERVER CERTIFICATE ==="

CERT_TSV="$TMP/cert.tsv"
ts -Y "tls.handshake.type == 11 && ip.src == $PHISH_IP" \
   -T fields -e frame.time \
   -e x509af.serialNumber \
   -e x509af.validity_notBefore \
   -e x509af.validity_notAfter \
   -e x509sat.printableString \
   -e x509ce.dNSName > "$CERT_TSV" || true

if [[ -s "$CERT_TSV" ]]; then
    echo "$(fmt_time "$(awk -F'\t' 'NR == 1 { print $1 }' "$CERT_TSV")")  Certificate"
    echo "  Serial: $(awk -F'\t' 'NR == 1 { print $2 }' "$CERT_TSV")"
    echo "  Valid from: $(awk -F'\t' 'NR == 1 { print $3 }' "$CERT_TSV")"
    echo "  Valid until: $(awk -F'\t' 'NR == 1 { print $4 }' "$CERT_TSV")"
    echo "  Subject/Issuer strings:"
    awk -F'\t' 'NR == 1 { print $5 }' "$CERT_TSV" | tr ',' '\n' | sed 's/^/    /'
    echo "  SAN dNSName: $(awk -F'\t' 'NR == 1 { print $6 }' "$CERT_TSV")"
else
    echo "(no Certificate messages in capture — server-side TLS records not dissected;"
    echo " conclusion must remain metadata-based, see Data Exchange section)"
fi

# ---------------------------------------------------------------------------
# 4. DATA EXCHANGE (per-direction bytes and segment counts)
#    Filters: tcp.len > 0 restricted by direction
# ---------------------------------------------------------------------------
echo
echo "=== DATA EXCHANGE ==="

CLIENT_DATA_TSV="$TMP/client_data.tsv"
ts -Y "tcp.len > 0 && ip.src == $VICTIM && ip.dst == $PHISH_IP" \
   -T fields -e frame.time -e tcp.len > "$CLIENT_DATA_TSV" || true
SERVER_DATA_TSV="$TMP/server_data.tsv"
ts -Y "tcp.len > 0 && ip.src == $PHISH_IP && ip.dst == $VICTIM" \
   -T fields -e frame.time -e tcp.len > "$SERVER_DATA_TSV" || true

CBYTES=$(awk -F'\t' '{ s += $2 } END { print s + 0 }' "$CLIENT_DATA_TSV")
CSEGS=$(wc -l < "$CLIENT_DATA_TSV" | tr -d ' ')
SBYTES=$(awk -F'\t' '{ s += $2 } END { print s + 0 }' "$SERVER_DATA_TSV")
SSEGS=$(wc -l < "$SERVER_DATA_TSV" | tr -d ' ')

# Session timeline: connection start, data start/end, close
CONN_START=$(ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == $VICTIM && ip.dst == $PHISH_IP" \
   -T fields -e frame.time | awk 'NR == 1 { print; exit }') || true
DATA_START=$(awk -F'\t' 'NR == 1 { print $1 }' "$CLIENT_DATA_TSV")
DATA_END=$(tail -n 1 "$SERVER_DATA_TSV" | cut -f1)
CONN_END=$(ts -Y "(tcp.flags.fin == 1 || tcp.flags.reset == 1) && ip.addr == $VICTIM && ip.addr == $PHISH_IP" \
   -T fields -e frame.time | awk 'NR == 1 { print; exit }') || true

# Duration computed numerically from epochs of the boundary frames
EPOCH_START=$(ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == $VICTIM && ip.dst == $PHISH_IP" \
   -T fields -e frame.time_epoch | awk 'NR == 1 { print; exit }') || true
EPOCH_END=$(ts -Y "(tcp.flags.fin == 1 || tcp.flags.reset == 1) && ip.addr == $VICTIM && ip.addr == $PHISH_IP" \
   -T fields -e frame.time_epoch | awk 'NR == 1 { print; exit }') || true
SESSION_SECONDS=$(awk -v a="${EPOCH_START:-0}" -v b="${EPOCH_END:-0}" \
    'BEGIN { printf "%.1f", b - a }')

echo "Duration: ${SESSION_SECONDS}s ($(fmt_time "$CONN_START") to $(fmt_time "$CONN_END"))"
echo "Client ($VICTIM) -> Server: $CBYTES bytes across $CSEGS TCP segments"
echo "Server -> Client: $SBYTES bytes across $SSEGS TCP segments"

# Largest client TLS record (record sizes, direction-aware)
RECORDS_TSV="$TMP/tls_records.tsv"
ts -Y "tls.record.length && ip.src == $VICTIM && ip.dst == $PHISH_IP" \
   -T fields -e frame.time -e tls.record.length > "$RECORDS_TSV" || true

MAX_REC_LEN=""
MAX_REC_TIME=""
if [[ -s "$RECORDS_TSV" ]]; then
    MAX_REC_ROW=$(sort -t$'\t' -k2,2gr "$RECORDS_TSV" | awk 'NR == 1 { print }')
    MAX_REC_LEN=$(awk -F'\t' '{ print $2 }' <<<"$MAX_REC_ROW")
    MAX_REC_TIME=$(fmt_time "$(awk -F'\t' '{ print $1 }' <<<"$MAX_REC_ROW")")
    echo "Largest client TLS record: $MAX_REC_LEN bytes at $MAX_REC_TIME"
fi

echo
echo "[*] Analysis:"
echo "    The content is encrypted, so the exact form fields are not visible."
if [[ -n "$MAX_REC_LEN" ]]; then
    echo "    The largest client->server record of ${MAX_REC_LEN} bytes is consistent"
    echo "    with a small HTTPS form submission (credential-sized payload), but the"
    echo "    packet contents do not prove what data was submitted."
else
    echo "    Client record sizes were not dissectable; only segment-level volumes"
    echo "    are available. ${CBYTES} bytes client->server across ${CSEGS} segments."
fi

# ---------------------------------------------------------------------------
# 5. POST-CLICK BEHAVIOR (legitimate portal query after the phishing session)
#    Filter: dns.qry.name == "meddefense.com" occurring after session end
# ---------------------------------------------------------------------------
echo
echo "=== POST-CLICK BEHAVIOR ==="
POST_CUTOFF="${EPOCH_END:-0}"

POST_DNS_TSV="$TMP/post_dns.tsv"
ts -Y "dns.qry.name == \"$LEGIT_PORTAL\" && dns.flags.response == 0" \
   -T fields -e frame.time -e frame.time_epoch -e ip.src > "$POST_DNS_TSV" || true

POST_DNS_FOUND=0
while IFS=$'\t' read -r ptime pepoch psrc; do
    [[ -z "$pepoch" ]] && continue
    IS_AFTER=$(awk -v a="$pepoch" -v b="$POST_CUTOFF" 'BEGIN { print (a >= b) ? "1" : "0" }')
    if [[ "$IS_AFTER" == "1" ]]; then
        echo "$(fmt_time "$ptime")  DNS query: $LEGIT_PORTAL (from $psrc)"
        POST_DNS_FOUND=1

        LEGIT_RESP_TSV="$TMP/legit_resp.tsv"
        ts -Y "dns.qry.name == \"$LEGIT_PORTAL\" && dns.flags.response == 1" \
           -T fields -e frame.time -e dns.a > "$LEGIT_RESP_TSV" || true
        if [[ -s "$LEGIT_RESP_TSV" ]]; then
            LR_ROW=$(awk -F'\t' 'NR == 1 { print }' "$LEGIT_RESP_TSV")
            echo "$(fmt_time "$(awk -F'\t' '{ print $1 }' <<<"$LR_ROW")")  DNS response: $(awk -F'\t' '{ print $2 }' <<<"$LR_ROW")"
            LEGIT_IP=$(awk -F'\t' '{ split($2, a, ","); print a[1] }' <<<"$LR_ROW")

            LEGIT_CONN_TSV="$TMP/legit_conn.tsv"
            ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == $LEGIT_IP && tcp.dstport == 443" \
               -T fields -e frame.time -e ip.dst > "$LEGIT_CONN_TSV" || true
            if [[ -s "$LEGIT_CONN_TSV" ]]; then
                LC_ROW=$(awk -F'\t' 'NR == 1 { print }' "$LEGIT_CONN_TSV")
                echo "$(fmt_time "$(awk -F'\t' '{ print $1 }' <<<"$LC_ROW")")  HTTPS connection to $(awk -F'\t' '{ print $2 }' <<<"$LC_ROW"):443"
            fi
        fi
        break
    fi
done < "$POST_DNS_TSV"

if [[ "$POST_DNS_FOUND" -eq 0 ]]; then
    echo "(no $LEGIT_PORTAL query observed after the phishing session in this capture)"
fi

# ---------------------------------------------------------------------------
# 6. 4x00 CORRELATION (verified against packet data + Task 0 baseline)
# ---------------------------------------------------------------------------
echo
echo "=== 4x00 CORRELATION ==="
IOC_DOMAIN_MATCH="$QUERY_NAME"
IOC_IP_IN_BASELINE=0
if [[ -f "baseline_clinical.json" ]]; then
    IOC_IP_IN_BASELINE=$(python3 -c "
import json
try:
    with open('baseline_clinical.json') as fh:
        b = json.load(fh)
    print(1 if '${PHISH_IP:-}' in b.get('external_ips_contacted', []) else 0)
except Exception:
    print(0)") || IOC_IP_IN_BASELINE=0
fi
echo "IOC domain match: $IOC_DOMAIN_MATCH (queried by $VICTIM at $(fmt_time "$QUERY_TIME"))"
echo "Resolved IP: $PHISH_IP"
if [[ "$IOC_IP_IN_BASELINE" == "0" ]]; then
    echo "Baseline check: $PHISH_IP does NOT appear in baseline external contacts (zero matches)"
else
    echo "WARNING: $PHISH_IP DOES appear in the known-good baseline set — investigate further"
fi
echo "Conclusion: PCAP confirms $VICTIM contacted the phishing infrastructure."

# ---------------------------------------------------------------------------
# 7. SERIALISE EVIDENCE
# ---------------------------------------------------------------------------
python3 - "$PCAP" "$OUT_JSON" "$VICTIM" "$PHISH_IP" "$IOC_DOMAIN_MATCH" "$DNS_TTL" \
          "$CONN_START" "$CONN_END" "$SESSION_SECONDS" "$CBYTES" "$CSEGS" \
          "$SBYTES" "$SSEGS" "$MAX_REC_LEN" "$MAX_REC_TIME" <<'PYEOF'
import json, sys

pcap, out_json = sys.argv[1:3]
victim, phish_ip, dom, ttl = sys.argv[3:7]
conn_start, conn_end, dur = sys.argv[7:10]
cbytes, csegs, sbytes, ssegs = sys.argv[10:14]
max_len, max_time = sys.argv[14:16]

def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None

evidence = {
    "capture": pcap,
    "victim_workstation": victim,
    "phishing_domain": dom,
    "phishing_ip": phish_ip,
    "dns_ttl": ttl,
    "connection_start": conn_start,
    "connection_end": conn_end,
    "session_duration_s": float(dur) if dur else None,
    "client_bytes": to_int(cbytes),
    "client_segments": to_int(csegs),
    "server_bytes": to_int(sbytes),
    "server_segments": to_int(ssegs),
    "largest_client_tls_record": {"bytes": to_int(max_len), "time": max_time},
    "credential_submission_verdict": (
        "metadata-consistent with a small HTTPS form submission; "
        "contents encrypted and unproven from packet data"
    ),
}
with open(out_json, "w") as fh:
    json.dump(evidence, fh, indent=2)
    fh.write("\n")
print()
print("EVIDENCE SAVED: " + out_json)
PYEOF
