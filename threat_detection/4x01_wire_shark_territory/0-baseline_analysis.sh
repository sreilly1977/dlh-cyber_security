#!/bin/bash
# Name: 0-baseline_analysis.sh
# Purpose: Build a comprehensive traffic baseline profile from a clinical VLAN
#          PCAP (30 minutes of known-good traffic). Produces a console report
#          and baseline_clinical.json, the reference point against which all
#          suspicious captures in this investigation will be compared.
#          All analysis is performed with tshark; every filter used is
#          documented below and inline so the investigation is reproducible.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./0-baseline_analysis.sh normal_baseline_clinical.pcap
# Output:  Console report + baseline_clinical.json in the working directory
#
# ---------------------------------------------------------------------------
# DOCUMENTED FILTER REFERENCE (analysis via tshark only, GUI not used)
# ---------------------------------------------------------------------------
# Protocol distribution ... no display filter ....... -T fields -e ip.proto
# Application breakdown ... no display filter ....... -e tcp.dstport -e udp.dstport
#                                                          -e ip.proto (port map)
# Top talkers (bytes) ..... no display filter ....... -T fields -e frame.len -e ip.src
# Top destinations (conns). tcp.flags.syn==1 && tcp.flags.ack==0
#                                                ... -e tcp.stream -e ip.dst
#                          (a "connection" = a unique tcp.stream carrying a
#                           client SYN, deduplicated)
# DNS query profile ........ dns.flags.response == 0 (queries only)
#                                                ... -e dns.qry.name -e dns.qry.type
# Stream durations .......... no display filter ... -e tcp.stream -e frame.time_epoch
# TLS SNI .................... tls.handshake.extensions_server_name
# TLS versions ............... tls.handshake.type == 2 (ServerHello)
#                                                  -e tls.handshake.version
#                                                  -e tls.handshake.negotiated_version
# Certificate issuers ....... tls.handshake.type == 11 (Certificate)
#                                                  -e x509sat.uTF8String
#                                                  -e x509sat.printableString
# Temporal pattern ........... no display filter ... -e frame.time_epoch (60s bins)
# External IP contacts ....... tcp.flags.syn==1 && tcp.flags.ack==0 &&
#                              not (ip.dst == 10.0.0.0/8 ||
#                                   ip.dst == 172.16.0.0/12 ||
#                                   ip.dst == 192.168.0.0/16)
# ---------------------------------------------------------------------------

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <pcap-file>" >&2
    exit 1
fi

PCAP="$1"

if [[ ! -f "$PCAP" ]]; then
    echo "Error: file not found: $PCAP" >&2
    exit 1
fi

OUT_JSON="baseline_clinical.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Thin wrapper so the reader sees the tshark invocation in one place.
ts() {
    tshark -r "$PCAP" "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Capture envelope (first/last packet times, needed for per-minute rates)
# ---------------------------------------------------------------------------
read -r CAP_START CAP_END < <(ts -T fields -e frame.time_epoch \
    | awk 'NR == 1 { f = $1 } { l = $1 } END { print f, l }')
DUR_MIN=$(awk -v f="$CAP_START" -v l="$CAP_END" 'BEGIN { d = (l - f) / 60; if (d < 0) d = 0; printf "%.2f", d }')

echo "=== CAPTURE ENVELOPE ==="
ts -T fields -e frame.time_epoch | wc -l | awk -v d="$DUR_MIN" \
    '{ printf "Packets: %d | Duration: %.2f minutes | Start epoch: %.0f\n", $1, d, '"$CAP_START"' }'

# ---------------------------------------------------------------------------
# 1. PROTOCOL DISTRIBUTION (ip.proto; frames without an IP layer, e.g. ARP,
#    are counted as "Other")
# ---------------------------------------------------------------------------
PROTO_TSV="$TMP/proto.tsv"
ts -T fields -e ip.proto | awk '
    { total++; if ($1 == "6") tcp++; else if ($1 == "17") udp++; else if ($1 == "1") icmp++ }
    END {
        printf "TCP\t%d\n", tcp + 0
        printf "UDP\t%d\n", udp + 0
        printf "ICMP\t%d\n", icmp + 0
        printf "Other\t%d\n", total - tcp - udp - icmp
        printf "TOTAL\t%d\n", total
    }' > "$PROTO_TSV"

TOTAL_PKTS=$(awk -F'\t' '$1 == "TOTAL" { print $2 }' "$PROTO_TSV")

echo
echo "=== PROTOCOL DISTRIBUTION ==="
awk -F'\t' -v tot="$TOTAL_PKTS" \
    '$1 != "TOTAL" { printf "%-5s %6.1f%%  (%s packets)\n", $1, ($2 / tot) * 100, $2 }' "$PROTO_TSV"

# ---------------------------------------------------------------------------
# 2. APPLICATION BREAKDOWN (packets classified by transport protocol and
#    destination port; anything not matching a known service falls to Other)
# ---------------------------------------------------------------------------
echo
echo "=== APPLICATION BREAKDOWN ==="
ts -Y "ip" -T fields -e ip.proto -e tcp.dstport -e udp.dstport | awk -F'\t' '
    function cls(proto, port,  p) {
        p = port + 0
        if (proto == "6") {
            if (p == 443)  return "HTTPS (443)"
            if (p == 80)  return "HTTP (80)"
            if (p == 88)  return "Kerberos (88)"
            if (p == 389 || p == 636) return "LDAP (389/636)"
            if (p == 445) return "SMB (445)"
            if (p == 9100) return "Printing (9100)"
            return "Other"
        } else if (proto == "17") {
            if (p == 53)  return "DNS (53)"
            if (p == 88)  return "Kerberos (88)"
            if (p == 123) return "NTP (123)"
            if (p == 389) return "LDAP (389)"
            return "Other"
        }
        return "Other"
    }
    { c[cls($1, ($1 == "6" ? $2 : $3))]++; total++ }
    END {
        for (k in c) printf "%.6f\t%s\t%d\n", (c[k] / total) * 100, k, c[k]
    }' | sort -t$'\t' -k1,1gr | awk -F'\t' \
        '{ printf "%-18s %6.1f%%  (%d packets)\n", $2, $1, $3 }'

# ---------------------------------------------------------------------------
# 3. TOP 10 TALKERS (source IPs ranked by summed frame.len as attributed bytes)
#    Note: hostname labels are not invented; they would need to be correlated
#    from DHCP/NBNS evidence if present in the capture.
# ---------------------------------------------------------------------------
TALKERS_TSV="$TMP/talkers.tsv"
ts -T fields -e frame.len -e ip.src | awk -F'\t' '
    NF == 2 && $2 != "" { b[$2] += $1 }
    END { for (i in b) printf "%.0f\t%s\n", b[i], i }' | sort -rn | head -n 10 > "$TALKERS_TSV"

echo
echo "=== TOP 10 SOURCE IPS (by attributed bytes) ==="
awk -F'\t' '{ printf "  %2d. %-16s %8.2f MB\n", NR, $2, $1 / 1048576 }' "$TALKERS_TSV"

# ---------------------------------------------------------------------------
# 4. TOP 10 DESTINATIONS (unique TCP streams per destination; private IPs
#    annotated as internal, everything else external)
# ---------------------------------------------------------------------------
DESTS_TSV="$TMP/dests.tsv"
ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
   -T fields -e tcp.stream -e ip.dst | sort -u | awk -F'\t' '
    { c[$2]++ }
    END { for (i in c) printf "%d\t%s\n", c[i], i }' \
    | sort -rn | head -n 10 > "$DESTS_TSV"

echo
echo "=== TOP 10 DESTINATION IPS (by connections) ==="
awk -F'\t' '
    function zone(ip,   a) {
        split(ip, a, ".")
        if (a[1] == "10") return "internal"
        if (a[1] == "192" && a[2] == "168") return "internal"
        if (a[1] == "172" && a[2] >= 16 && a[2] <= 31) return "internal"
        return "external"
    }
    { printf "  %2d. %-16s %5d connections  (%s)\n", NR, $2, $1, zone($2) }' "$DESTS_TSV"

# ---------------------------------------------------------------------------
# 5. DNS QUERY PROFILE (queries only: dns.flags.response == 0)
# ---------------------------------------------------------------------------
DNS_TSV="$TMP/dns.tsv"
ts -Y "dns.flags.response == 0" -T fields -e dns.qry.name -e dns.qry.type > "$DNS_TSV"
DNS_TOTAL=$(wc -l < "$DNS_TSV" | tr -d ' ')
DNS_RATE=$(awk -v n="$DNS_TOTAL" -v d="$DUR_MIN" 'BEGIN { if (d > 0) printf "%.1f", n / d; else printf "n/a" }')

echo
echo "=== DNS QUERY PROFILE ==="
echo "Total queries: ${DNS_TOTAL} (${DNS_RATE}/min average over ${DUR_MIN} minutes)"
echo "Top domains:"
sort "$DNS_TSV" | awk -F'\t' '{ n = tolower($1); c[n]++ } END { for (i in c) printf "%d\t%s\n", c[i], i }' \
    | sort -rn | head -n 20 | awk -F'\t' '{ printf "  %2d. %-40s %d queries\n", NR, $2, $1 }'

echo "Query types:"
awk -F'\t' '
    $2 == 1  { a++ }
    $2 == 28 { aaaa++ }
    $2 == 15 { mx++ }
    $2 == 16 { txt++ }
    END {
        t = a + aaaa + mx + txt + 0
        for (i = 1; i <= t; i++) ; # no-op, keep awk quiet on empty sets
        if (t > 0) {
            printf "  A:    %d (%.0f%%)\n", a + 0, (a / t) * 100
            printf "  AAAA: %d (%.0f%%)\n", aaaa + 0, (aaaa / t) * 100
            printf "  MX:   %d (%.0f%%)\n", mx + 0, (mx / t) * 100
            printf "  TXT:  %d (%.0f%%)\n", txt + 0, (txt / t) * 100
            printf "  Other types: %d (%.0f%%)\n", t - a - aaaa - mx - txt, ((t - a - aaaa - mx - txt) / t) * 100
        }
    }' "$DNS_TSV"

# TXT-specific profile: who is being TXT-queried and how often
# (this establishes the "very low TXT volume" baseline signature)
echo "TXT queries (queries only):"
TXT_DOMAINS="$TMP/txt_domains.tsv"
grep -P '\t16(\t|$)' "$DNS_TSV" | cut -f1 | sort | uniq -c | sort -rn > "$TXT_DOMAINS"
if [[ -s "$TXT_DOMAINS" ]]; then
    awk '{ printf "  %s  %d queries\n", $2, $1 }' "$TXT_DOMAINS"
else
    echo "  (none observed in baseline)"
fi

# ---------------------------------------------------------------------------
# 6. CONNECTION DURATION DISTRIBUTION (short <1s, medium 1-30s, long >30s)
#    Method: per tcp.stream, first and last frame timestamp; duration bucketed
#    in seconds. Filter used: none beyond "ip" (all TCP streams included).
# ---------------------------------------------------------------------------
DUR_TSV="$TMP/stream_durations.tsv"
ts -Y "ip" -T fields -e tcp.stream -e frame.time_epoch | awk -F'\t' '
    NF == 2 && $1 != "" {
        if (!seen[$1]++) first[$1] = $2
        last[$1] = $2
    }
    END { for (s in first) printf "%d\t%.6f\n", s, last[s] - first[s] }' > "$DUR_TSV"

echo
echo "=== CONNECTION DURATION DISTRIBUTION ==="
awk -F'\t' '
    { t++
      if ($2 < 1)       short++
      else if ($2 <= 30) med++
      else               long++
    }
    END {
        t += 0; short += 0; med += 0; long += 0
        if (t > 0)
            printf "  Short (<1s):     %d%%  (%d streams)\n  Medium (1-30s): %d%%  (%d streams)\n  Long (>30s):    %d%%  (%d streams)\n", \
                (short / t) * 100, short, (med / t) * 100, med, (long / t) * 100, long
    }' "$DUR_TSV"

# ---------------------------------------------------------------------------
# 7. TLS ANALYSIS
#    SNI:          tls.handshake.extensions_server_name (ClientHello)
#    TLS versions: ServerHello negotiated version (tls.handshake.type == 2)
#    Issuers:      x509 subject fields from Certificate messages (type == 11)
#    NOTE: pipefail disabled around tshark calls because non-zero exit (empty
#          results) would otherwise abort the script despite awk succeeding.
# ---------------------------------------------------------------------------
echo
echo "=== TLS ANALYSIS ==="

echo "Observed SNI values:"
set +o pipefail
SNI_TSV="$TMP/sni.tsv"
ts -Y "tls.handshake.extensions_server_name" \
   -T fields -e tls.handshake.extensions_server_name \
   | awk -F'\t' '
        {
            n = split($0, names, ",")
            for (i = 1; i <= n; i++)
                if (names[i] != "") print names[i]
        }' | sort | uniq -c | sort -rn > "$SNI_TSV"
set -o pipefail
if [[ -s "$SNI_TSV" ]]; then
    awk '{ printf "  %-45s %d observations\n", $2, $1 }' "$SNI_TSV"
else
    echo "  (no SNI extensions observed)"
fi

echo "TLS versions (ServerHello negotiated):"
set +o pipefail
TLSVER_TSV="$TMP/tls_versions.tsv"
ts -Y "tls.handshake.type == 2" \
   -T fields -e tls.handshake.version -e tls.handshake.negotiated_version \
   | awk -F'\t' '
        {
            v = ($2 != "" ? $2 : $1)
            if (v != "") print v
        }' | sort | uniq -c | sort -rn > "$TLSVER_TSV"
set -o pipefail
if [[ -s "$TLSVER_TSV" ]]; then
    awk '{ printf "  %-35s %d handshakes\n", $2, $1 }' "$TLSVER_TSV"
else
    echo "  (no ServerHello version fields observed — capture may lack negotiated_version)"
fi

echo "Observed certificate issuers:"
set +o pipefail
CERT_TSV="$TMP/cert_issuers.tsv"
ts -Y "tls.handshake.type == 11" \
   -T fields -e x509sat.uTF8String -e x509sat.printableString \
   | awk -F'\t' '
        {
            gsub(/,/, "\n", $0)
            n = split($0, lines, "\n")
            for (i = 1; i <= n; i++)
                if (lines[i] != "") print lines[i]
        }' | sort -u > "$CERT_TSV"
set -o pipefail
if [[ -s "$CERT_TSV" ]]; then
    awk '{ printf "  %s\n", $0 }' "$CERT_TSV"
else
    echo "  (no certificate issuer fields observed)"
fi

# ---------------------------------------------------------------------------
# 8. TEMPORAL PATTERN (per-minute bins of frame counts and bytes)
# ---------------------------------------------------------------------------
BIN_TSV="$TMP/bins.tsv"
ts -T fields -e frame.time_epoch -e frame.len | awk -F'\t' '
    { b = int(($1 - '"$CAP_START"') / 60); pkts[b]++; bytes[b] += $2 }
    END { for (b in pkts) printf "%d\t%d\t%d\n", b, pkts[b], bytes[b] }' \
    | sort -n > "$BIN_TSV"

echo
echo "=== TEMPORAL PATTERN (per-minute bins, minutes elapsed since capture start) ==="
awk -F'\t' '
    { printf "  +%02d min: %6d packets  %8.2f KB\n", $1, $2, $3 / 1024 }' "$BIN_TSV"

# ---------------------------------------------------------------------------
# 9. BASELINE SIGNATURES FOR LATER COMPARISON
# ---------------------------------------------------------------------------
EXT_CONNS="$TMP/ext_conns.tsv"
ts -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0 && not (ip.dst == 10.0.0.0/8 || ip.dst == 172.16.0.0/12 || ip.dst == 192.168.0.0/16)" \
   -T fields -e ip.dst | sort | uniq -c | sort -rn > "$EXT_CONNS"
EXT_DST_COUNT=$(wc -l < "$EXT_CONNS" | tr -d ' ')

TXT_TOTAL=$(awk -F'\t' '$2 == 16 { n++ } END { print n + 0 }' "$DNS_TSV")

echo
echo "=== BASELINE SIGNATURES ==="
echo "Normal DNS rate:            $(awk -v n="$DNS_TOTAL" -v d="$DUR_MIN" 'BEGIN { printf "%.1f", n / d }') queries/min total"
echo "Normal TXT query rate:      ${TXT_TOTAL} TXT queries in ${DUR_MIN} min ($(awk -v n="$TXT_TOTAL" -v d="$DUR_MIN" 'BEGIN { if (d > 0) printf "%.2f", n / d; else printf "0" }')/min)"
echo "External destinations:      ${EXT_DST_COUNT} distinct external IPs contacted"
echo "Top external destination:   $(head -n 1 "$EXT_CONNS" | awk '{ print $2, "(" $1 " connection attempts)" }')"
echo "Normal packet volume range: $(awk -F'\t' 'NR == 1 { lo = hi = $2 } { if ($2 < lo) lo = $2; if ($2 > hi) hi = $2 } END { printf "%d-%d packets/min", lo, hi }' "$BIN_TSV")"

# Baseline reference lists (used by later comparison tasks)
awk -F'\t' '{ print $1 }' "$DNS_TSV" | sort -u > "$TMP/known_dns_domains.txt"
awk '{ print $2 }' "$EXT_CONNS" | sort -u > "$TMP/known_external_ips.txt"

# ---------------------------------------------------------------------------
# 10. SERIALISE BASELINE TO JSON (baseline_clinical.json)
# ---------------------------------------------------------------------------
python3 - "$PCAP" "$OUT_JSON" "$DUR_MIN" "$DNS_TOTAL" "$DNS_RATE" "$TXT_TOTAL" \
          "$TMP" <<'PYEOF'
import json, sys, os

pcap, out_json = sys.argv[1], sys.argv[2]
dur_min, dns_total, dns_rate, txt_total = sys.argv[3:7]
tmp = sys.argv[7]

def read_rows(path, sep="\t"):
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        return [ln.rstrip("\n").split(sep) for ln in fh if ln.strip()]

def col(rows, i, cast=str):
    out = []
    for r in rows:
        try:
            out.append(cast(r[i]))
        except (IndexError, ValueError):
            pass
    return out

baseline = {
    "capture": pcap,
    "duration_minutes": float(dur_min),
    "dns": {
        "total_queries": int(dns_total),
        "queries_per_minute": float(dns_rate),
        "txt_queries": int(txt_total),
    },
    "talkers_top_bytes": [
        {"ip": r[1], "bytes": int(float(r[0]))}
        for r in read_rows(os.path.join(tmp, "talkers.tsv"))
    ],
    "destination_connections_top": [
        {"ip": r[1], "connections": int(r[0])}
        for r in read_rows(os.path.join(tmp, "dests.tsv"))
    ],
    "stream_duration_buckets_pct": None,  # computed below
    "per_minute_bins": [
        {"minute_offset": int(r[0]), "packets": int(r[1]), "bytes": int(r[2])}
        for r in read_rows(os.path.join(tmp, "bins.tsv"))
    ],
    "dns_domains_observed": sorted(
        ln.strip() for ln in open(os.path.join(tmp, "known_dns_domains.txt"))
    ),
    "external_ips_contacted": sorted(
        ln.strip() for ln in open(os.path.join(tmp, "known_external_ips.txt"))
    ),
}

durs = col(read_rows(os.path.join(tmp, "stream_durations.tsv")), 1, float)
t = len(durs)
buckets = {}
if t:
    buckets = {
        "short_under_1s": sum(1 for d in durs if d < 1) / t * 100,
        "medium_1_to_30s": sum(1 for d in durs if 1 <= d <= 30) / t * 100,
        "long_over_30s": sum(1 for d in durs if d > 30) / t * 100,
    }
baseline["stream_duration_buckets_pct"] = {k: round(v, 1) for k, v in buckets.items()}

with open(out_json, "w") as fh:
    json.dump(baseline, fh, indent=2)
    fh.write("\n")

print ("")
print ("BASELINE SAVED: " + out_json)
PYEOF
