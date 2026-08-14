#!/bin/bash
#
# Name:        11-pcap_investigation.sh
# Purpose:     Investigate a suspicious PCAP session and extract conversation timeline, protocols, DNS, and file transfers
# Author:      Steve - Cybersecurity Engineer
# Date:        August 14, 2026
#

set -euo pipefail

# Configuration
DEFAULT_PCAP="/home/analyst/MedDefense_Lab/PCAPs/suspicious_session.pcap"

# Accept PCAP path as argument (default: suspicious_session.pcap)
if [[ -n "${1:-}" ]]; then
    PCAP_PATH="$1"
else
    PCAP_PATH="$DEFAULT_PCAP"
fi

OUTPUT_JSON="pcap_investigation.json"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Verify inputs
if [[ ! -f "$PCAP_PATH" ]]; then
    echo "Error: PCAP file not found: $PCAP_PATH" >&2
    exit 1
fi

if ! command -v tshark &>/dev/null; then
    echo "Error: tshark is not installed. Install with: apt-get install tshark" >&2
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "Error: jq is not installed." >&2
    exit 1
fi

echo "[*] PCAP: $PCAP_PATH"

# ---------------------------------------------------------------
# 1. Capture PCAP metadata: duration and packet count
# ---------------------------------------------------------------
PACKET_COUNT=$(tshark -r "$PCAP_PATH" -T fields -e frame.number 2>/dev/null | wc -l | tr -d '[:space:]')
PACKET_COUNT=${PACKET_COUNT:-0}

FIRST_TS=$(tshark -r "$PCAP_PATH" -T fields -e frame.time_epoch 2>/dev/null | head -1 || true)
LAST_TS=$(tshark -r "$PCAP_PATH" -T fields -e frame.time_epoch 2>/dev/null | tail -1 || true)

DURATION_SECONDS=0
if [[ -n "$FIRST_TS" && -n "$LAST_TS" ]]; then
    DURATION_SECONDS=$(awk "BEGIN {printf \"%.2f\", ${LAST_TS} - ${FIRST_TS}}" 2>/dev/null || echo "0")
fi

echo "[*] Duration: ${DURATION_SECONDS}s     Packets: ${PACKET_COUNT}"

# ---------------------------------------------------------------
# Helper: safely get JSON array length
# ---------------------------------------------------------------
json_length() {
    local json="$1"
    local result
    result=$(echo "$json" | jq 'length' 2>/dev/null || echo "0")
    if [[ ! "$result" =~ ^[0-9]+$ ]]; then
        result=0
    fi
    echo "$result"
}

# ---------------------------------------------------------------
# 2. Extract TCP conversations via tshark -q -z conv,tcp
# ---------------------------------------------------------------
echo "[*] Extracting TCP conversations..."

TCP_CONV_JSON="[]"
TCP_RAW=$(tshark -r "$PCAP_PATH" -q -z conv,tcp 2>/dev/null || true)

if [[ -n "$TCP_RAW" ]]; then
    # Get the top 10 TCP conversations by packet count
    TCP_CONVS=$(echo "$TCP_RAW" | grep '<->' | head -10 | sed 's/bytes//g' | awk '
    {
        for(i=1; i<=NF; i++) {
            if($i == "<->") {
                src = $(i-1)
                dst = $(i+1)

                n_src = split(src, a, ":")
                src_addr = a[1]
                src_port = a[n_src]

                n_dst = split(dst, b, ":")
                dst_addr = b[1]
                dst_port = b[n_dst]

                total_fr = $(NF-5)
                total_bytes = $(NF-4)

                if(total_fr ~ /^[0-9]+$/ && total_bytes ~ /^[0-9]+$/) {
                    printf "{\"src_addr\":\"%s\",\"src_port\":%s,\"dst_addr\":\"%s\",\"dst_port\":%s,\"total_packets\":%s,\"total_bytes\":%s}\n", src_addr, src_port, dst_addr, dst_port, total_fr, total_bytes
                }
                break
            }
        }
    }' || true)

    if [[ -n "$TCP_CONVS" ]]; then
        TCP_CONV_JSON=$(echo "$TCP_CONVS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

TCP_CONV_COUNT=$(json_length "$TCP_CONV_JSON")
echo "      (${TCP_CONV_COUNT})"

# ---------------------------------------------------------------
# 3. Extract UDP conversations via tshark -q -z conv,udp
# ---------------------------------------------------------------
echo "[*] Extracting UDP conversations..."

UDP_CONV_JSON="[]"
UDP_RAW=$(tshark -r "$PCAP_PATH" -q -z conv,udp 2>/dev/null || true)

if [[ -n "$UDP_RAW" ]]; then
    # Get the top 10 UDP conversations by packet count
    UDP_CONVS=$(echo "$UDP_RAW" | grep '<->' | head -10 | sed 's/bytes//g' | awk '
    {
        for(i=1; i<=NF; i++) {
            if($i == "<->") {
                src = $(i-1)
                dst = $(i+1)

                n_src = split(src, a, ":")
                src_addr = a[1]
                src_port = a[n_src]

                n_dst = split(dst, b, ":")
                dst_addr = b[1]
                dst_port = b[n_dst]

                total_fr = $(NF-5)
                total_bytes = $(NF-4)

                if(total_fr ~ /^[0-9]+$/ && total_bytes ~ /^[0-9]+$/) {
                    printf "{\"src_addr\":\"%s\",\"src_port\":%s,\"dst_addr\":\"%s\",\"dst_port\":%s,\"total_packets\":%s,\"total_bytes\":%s}\n", src_addr, src_port, dst_addr, dst_port, total_fr, total_bytes
                }
                break
            }
        }
    }' || true)

    if [[ -n "$UDP_CONVS" ]]; then
        UDP_CONV_JSON=$(echo "$UDP_CONVS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

UDP_CONV_COUNT=$(json_length "$UDP_CONV_JSON")
echo "      (${UDP_CONV_COUNT})"

# ---------------------------------------------------------------
# 4. Extract DNS queries via tshark -Y dns.flags.response==0
# ---------------------------------------------------------------
echo "[*] Extracting DNS queries..."

DNS_QUERIES_JSON="[]"
DNS_RAW=$(tshark -r "$PCAP_PATH" -Y "dns.flags.response==0" -T fields -e frame.time_epoch -e ip.src -e dns.qry.name -e dns.qry.type 2>/dev/null || true)

if [[ -n "$DNS_RAW" ]]; then
    DNS_CONVS=$(echo "$DNS_RAW" | awk -F'\t' '
    {
        if($3 != "") {
            ts = $1; gsub(/"/, "\\\"", ts)
            src = $2; gsub(/"/, "\\\"", src)
            qry = $3; gsub(/"/, "\\\"", qry)
            typ = $4; gsub(/"/, "\\\"", typ)
            printf "{\"timestamp\":\"%s\",\"src_ip\":\"%s\",\"query_name\":\"%s\",\"query_type\":\"%s\"}\n", ts, src, qry, typ
        }
    }' || true)

    if [[ -n "$DNS_CONVS" ]]; then
        DNS_QUERIES_JSON=$(echo "$DNS_CONVS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

DNS_QUERY_COUNT=$(json_length "$DNS_QUERIES_JSON")
echo "      (${DNS_QUERY_COUNT})"

# ---------------------------------------------------------------
# 5. Extract HTTP requests via tshark -Y http.request
# ---------------------------------------------------------------
echo "[*] Extracting HTTP requests..."

HTTP_REQUESTS_JSON="[]"
HTTP_RAW=$(tshark -r "$PCAP_PATH" -Y "http.request" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri 2>/dev/null || true)

if [[ -n "$HTTP_RAW" ]]; then
    HTTP_CONVS=$(echo "$HTTP_RAW" | awk -F'\t' '
    {
        if($5 != "" || $6 != "") {
            ts = $1; gsub(/"/, "\\\"", ts)
            src = $2; gsub(/"/, "\\\"", src)
            dst = $3; gsub(/"/, "\\\"", dst)
            host = $4; gsub(/"/, "\\\"", host)
            method = $5; gsub(/"/, "\\\"", method)
            uri = $6; gsub(/"/, "\\\"", uri)
            printf "{\"timestamp\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"host\":\"%s\",\"method\":\"%s\",\"uri\":\"%s\"}\n", ts, src, dst, host, method, uri
        }
    }' || true)

    if [[ -n "$HTTP_CONVS" ]]; then
        HTTP_REQUESTS_JSON=$(echo "$HTTP_CONVS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

HTTP_COUNT=$(json_length "$HTTP_REQUESTS_JSON")
echo "      (${HTTP_COUNT})"

# ---------------------------------------------------------------
# 6. Extract TLS SNI via tshark -Y tls.handshake.type==1
# ---------------------------------------------------------------
echo "[*] Extracting TLS SNI..."

TLS_SNI_JSON="[]"
TLS_RAW=$(tshark -r "$PCAP_PATH" -Y "tls.handshake.type==1" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2>/dev/null || true)

if [[ -n "$TLS_RAW" ]]; then
    TLS_CONVS=$(echo "$TLS_RAW" | awk -F'\t' '
    {
        if($4 != "") {
            ts = $1; gsub(/"/, "\\\"", ts)
            src = $2; gsub(/"/, "\\\"", src)
            dst = $3; gsub(/"/, "\\\"", dst)
            sni = $4; gsub(/"/, "\\\"", sni)
            printf "{\"timestamp\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"server_name\":\"%s\"}\n", ts, src, dst, sni
        }
    }' || true)

    if [[ -n "$TLS_CONVS" ]]; then
        TLS_SNI_JSON=$(echo "$TLS_CONVS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

TLS_COUNT=$(json_length "$TLS_SNI_JSON")
echo "      (${TLS_COUNT})"

# ---------------------------------------------------------------
# 7. Extract file transfers via tshark -Y "http.content_type or http.request.uri or smb2.filename"
# ---------------------------------------------------------------
echo "[*] Extracting file transfers..."

FILE_TRANSFERS_JSON="[]"
FILE_RAW=$(tshark -r "$PCAP_PATH" -Y "http.content_type or http.request.uri or smb2.filename" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e http.request.uri -e http.content_type -e http.content_length -e smb2.filename 2>/dev/null || true)

if [[ -n "$FILE_RAW" ]]; then
    FILE_CONVS=$(echo "$FILE_RAW" | awk -F'\t' '
    {
        if($4 != "" || $5 != "" || $7 != "") {
            ts = $1; gsub(/"/, "\\\"", ts)
            src = $2; gsub(/"/, "\\\"", src)
            dst = $3; gsub(/"/, "\\\"", dst)
            uri = $4; gsub(/"/, "\\\"", uri)
            content_type = $5; gsub(/"/, "\\\"", content_type)
            content_len = $6; gsub(/[^0-9]/, "", content_len)
            if(content_len == "") { content_len = "0" }
            smb_file = $7; gsub(/"/, "\\\"", smb_file)
            printf "{\"timestamp\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"uri\":\"%s\",\"content_type\":\"%s\",\"content_length\":%s,\"smb_filename\":\"%s\"}\n", ts, src, dst, uri, content_type, content_len, smb_file
        }
    }' || true)

    if [[ -n "$FILE_CONVS" ]]; then
        FILE_TRANSFERS_JSON=$(echo "$FILE_CONVS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

FILE_COUNT=$(json_length "$FILE_TRANSFERS_JSON")
echo "      (${FILE_COUNT})"

# ---------------------------------------------------------------
# 8. Extract protocol distribution via tshark -q -z io,phs
# ---------------------------------------------------------------
echo "[*] Protocol distribution..."

PROTOCOL_DIST_JSON="[]"
PHS_RAW=$(tshark -r "$PCAP_PATH" -q -z io,phs 2>/dev/null || true)

if [[ -n "$PHS_RAW" ]]; then
    PROTO_CONVS=$(echo "$PHS_RAW" | grep -E '^\s*[a-z]' | awk '
    {
        proto = $1
        frames = 0
        bytes = 0

        for(i=2; i<=NF; i++) {
            if($i ~ /^frames:/) {
                gsub(/frames:/, "", $i)
                frames = $i
            }
            if($i ~ /^bytes:/) {
                gsub(/bytes:/, "", $i)
                bytes = $i
            }
        }

        if(frames ~ /^[0-9]+$/ && bytes ~ /^[0-9]+$/) {
            printf "{\"protocol\":\"%s\",\"frames\":%s,\"bytes\":%s}\n", proto, frames, bytes
        }
    }' || true)

    if [[ -n "$PROTO_CONVS" ]]; then
        PROTOCOL_DIST_JSON=$(echo "$PROTO_CONVS" | jq -s '.' 2>/dev/null || echo "[]")
    fi
fi

# Compute percentage summary for stdout using eth as total
PROTO_SUMMARY="unknown"
TOTAL_FRAMES=$(echo "$PROTOCOL_DIST_JSON" | jq -r '[.[] | select(.protocol == "eth") | .frames] | .[0] // 0' 2>/dev/null || echo "0")
TOTAL_FRAMES=${TOTAL_FRAMES:-0}

if [[ "$TOTAL_FRAMES" -gt 0 ]] 2>/dev/null; then
    TCP_FRAMES=$(echo "$PROTOCOL_DIST_JSON" | jq -r '[.[] | select(.protocol == "tcp") | .frames] | .[0] // 0' 2>/dev/null || echo "0")
    UDP_FRAMES=$(echo "$PROTOCOL_DIST_JSON" | jq -r '[.[] | select(.protocol == "udp") | .frames] | .[0] // 0' 2>/dev/null || echo "0")
    ICMP_FRAMES=$(echo "$PROTOCOL_DIST_JSON" | jq -r '[.[] | select(.protocol == "icmp") | .frames] | .[0] // 0' 2>/dev/null || echo "0")

    TCP_FRAMES=${TCP_FRAMES:-0}
    UDP_FRAMES=${UDP_FRAMES:-0}
    ICMP_FRAMES=${ICMP_FRAMES:-0}

    TCP_CALC=$(awk "BEGIN {printf \"%d\", ${TCP_FRAMES} * 100 / ${TOTAL_FRAMES}}" 2>/dev/null || echo "0")
    UDP_CALC=$(awk "BEGIN {printf \"%d\", ${UDP_FRAMES} * 100 / ${TOTAL_FRAMES}}" 2>/dev/null || echo "0")
    ICMP_CALC=$(awk "BEGIN {printf \"%d\", ${ICMP_FRAMES} * 100 / ${TOTAL_FRAMES}}" 2>/dev/null || echo "0")
    OTHER_FRAMES=$((TOTAL_FRAMES - TCP_FRAMES - UDP_FRAMES - ICMP_FRAMES))
    [[ $OTHER_FRAMES -lt 0 ]] && OTHER_FRAMES=0
    OTHER_CALC=$(awk "BEGIN {printf \"%d\", ${OTHER_FRAMES} * 100 / ${TOTAL_FRAMES}}" 2>/dev/null || echo "0")

    PROTO_SUMMARY="tcp ${TCP_CALC}%, udp ${UDP_CALC}%, icmp ${ICMP_CALC}%, other ${OTHER_CALC}%"
fi
echo "      (${PROTO_SUMMARY})"

# ---------------------------------------------------------------
# 9. Construct final pcap_investigation.json
# ---------------------------------------------------------------
FINAL_JSON=$(jq -n \
    --arg ts "$TIMESTAMP" \
    --arg pcap "$PCAP_PATH" \
    --argjson duration "${DURATION_SECONDS:-0}" \
    --argjson pkts "${PACKET_COUNT:-0}" \
    --argjson tcp_conv "$TCP_CONV_JSON" \
    --argjson udp_conv "$UDP_CONV_JSON" \
    --argjson dns_q "$DNS_QUERIES_JSON" \
    --argjson http_req "$HTTP_REQUESTS_JSON" \
    --argjson tls_sni "$TLS_SNI_JSON" \
    --argjson files "$FILE_TRANSFERS_JSON" \
    --argjson proto_dist "$PROTOCOL_DIST_JSON" \
    '{
        timestamp: $ts,
        pcap: $pcap,
        duration_seconds: $duration,
        packet_count: $pkts,
        tcp_conversations: $tcp_conv,
        udp_conversations: $udp_conv,
        dns_queries: $dns_q,
        http_requests: $http_req,
        tls_sni: $tls_sni,
        file_transfers: $files,
        protocol_distribution: $proto_dist
    }')

echo "$FINAL_JSON" > "$OUTPUT_JSON"

# ---------------------------------------------------------------
# 10. Human-readable stdout summary
# ---------------------------------------------------------------
echo ""
echo "Top conversations:"
jq -rn --argjson tcp "$TCP_CONV_JSON" --argjson udp "$UDP_CONV_JSON" '
    $tcp + $udp
    | sort_by(-.total_packets)
    | .[:5][]
    | "  \(.src_addr) <-> \(.dst_addr)  \(.total_packets) pkts  \(.total_bytes) bytes"
' 2>/dev/null || echo "  (none)"

echo ""
echo "Long DNS labels (> 50 chars):"
echo "$DNS_QUERIES_JSON" | jq -r '
    .[] | (.query_name | split(".")[0] | length) as $len | select($len > 50) | "  \(.query_name)  (\($len) chars)"
' 2>/dev/null || echo "  (none)"

echo ""
echo "Output: $OUTPUT_JSON"
