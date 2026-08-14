#!/bin/bash
#
# Name:        0-network_baseline.sh
# Purpose:     Capture local network topology, routing, neighbors, sockets, and DNS config as a JSON baseline
# Author:      Steve - Cybersecurity Engineer
# Date:        August 14, 2026
#

set -euo pipefail

# Configuration
OUTPUT_FILE="network_baseline.json"
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "${TEMP_DIR}"' EXIT

# 1. Timestamp and Hostname
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
HOSTNAME=$(hostname)

# 2. Interfaces (ip -j addr show)
if command -v jq &>/dev/null; then
    INTERFACES_JSON=$(ip -j addr show | jq '
        [
            .[] | {
                name: .ifname,
                mac: (
                    if .address then .address
                    elif .link_info.data.address then .link_info.data.address
                    elif .permaddr then .permaddr
                    else null
                    end
                ),
                state: (
                    if .operstate then .operstate
                    elif (.flags // [] | map(. | ascii_downcase) | any(. == "up")) then "UP"
                    else "UNKNOWN"
                    end
                ),
                addresses: [ (.addr_info[]? | .local) ]
            }
        ]
    ')
else
    echo "Warning: jq not found. Interface parsing may be limited." >&2
    INTERFACES_JSON="[]"
fi

# Extract list of up interface names for the summary
UP_INTERFACES=$(echo "$INTERFACES_JSON" | jq -r '.[] | select((.state | ascii_downcase) == "up") | .name' | jq -R . | jq -s .)

# 3. Routes (ip -j route show)
if command -v jq &>/dev/null; then
    ROUTES_JSON=$(ip -j route show | jq '
        [
            .[] | {
                destination: (if .dst then .dst else "default" end),
                gateway: (if .gateway then .gateway else null end),
                device: (if .dev then .dev else null end),
                protocol: (if .protocol then .protocol else null end),
                scope: (if .scope then .scope else null end),
                metric: (if .metric then .metric else null end)
            }
        ]
    ')
else
    ROUTES_JSON="[]"
fi

# 4. ARP Neighbors (ip -j neigh show)
if command -v jq &>/dev/null; then
    NEIGHBORS_JSON=$(ip -j neigh show | jq '
        [
            .[] | select(.lladdr != null) | {
                ip: .dst,
                mac: .lladdr,
                state: (if (.state | type) == "array" then .state[0] else .state end)
            }
        ]
    ')
else
    NEIGHBORS_JSON="[]"
fi

# 5. Determine if ss supports JSON output by testing it
HAS_SS_JSON=false
if ss -tulnpH -j 2>/dev/null | jq -e '.' >/dev/null 2>&1; then
    HAS_SS_JSON=true
fi

# ---------------------------------------------------------------
# Listening Sockets (ss -tulnpH)
# ---------------------------------------------------------------
LISTENING_JSON="[]"

if [[ "$HAS_SS_JSON" == "true" ]]; then
    LISTENING_JSON=$(ss -tulnpH -j 2>/dev/null | jq '
        [
            .[] |
            (if .listens then .listens else [] end)[] |
            {
                proto: (if .proto then .proto else "unknown" end),
                local_addr: (if .local_addr then .local_addr else null end),
                local_port: (if .local_port then .local_port else null end),
                pid: (if .pid then .pid else null end),
                process: (if .process then .process else null end)
            }
        ]
    ')
else
    LISTENING_JSON="[]"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^Netid ]] && continue

        proto=$(echo "$line" | awk '{print $1}')
        local_addr_port=$(echo "$line" | awk '{print $5}')

        if [[ "$local_addr_port" == *"]"* ]]; then
            local_addr=$(echo "$local_addr_port" | sed 's/\].*//' | sed 's/\[//')
            local_port=$(echo "$local_addr_port" | sed 's/.*\]://')
        else
            local_addr=$(echo "$local_addr_port" | rev | cut -d':' -f2- | rev)
            local_port=$(echo "$local_addr_port" | rev | cut -d':' -f1 | rev)
        fi

        process_info=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "")
        pid_info=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || echo "")

        sock_obj=$(jq -n \
            --arg proto "$proto" \
            --arg local_addr "$local_addr" \
            --arg local_port_str "$local_port" \
            --arg process "$process_info" \
            --arg pid_str "$pid_info" \
            '{
                proto: $proto,
                local_addr: $local_addr,
                local_port: (if ($local_port_str | test("^[0-9]+$")) then ($local_port_str | tonumber) else null end),
                process: $process,
                pid: (if ($pid_str | test("^[0-9]+$")) then ($pid_str | tonumber) else null end)
            }')

        LISTENING_JSON=$(echo "$LISTENING_JSON" | jq --argjson obj "$sock_obj" '. + [$obj]')
    done < <(ss -tulnpH)
fi

LISTENER_COUNT=$(echo "$LISTENING_JSON" | jq 'length')

# ---------------------------------------------------------------
# Established Connections (ss -tnpH state established)
# ---------------------------------------------------------------
ESTABLISHED_CONN_JSON="[]"

if [[ "$HAS_SS_JSON" == "true" ]]; then
    ESTABLISHED_CONN_JSON=$(ss -tnpH -j state established 2>/dev/null | jq '
        [
            .[] |
            (if .estab then .estab else (if .established then .established else [] end) end)[] |
            {
                local_addr: (if .local_addr then .local_addr else null end),
                local_port: (if .local_port then .local_port else null end),
                peer_addr: (if .peer_addr then .peer_addr else null end),
                peer_port: (if .peer_port then .peer_port else null end),
                pid: (if .pid then .pid else null end),
                process: (if .process then .process else null end)
            }
        ]
    ')
else
    ESTABLISHED_CONN_JSON="[]"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^State ]] && continue
        [[ "$line" =~ ^Netid ]] && continue

        local_addr_port=$(echo "$line" | awk '{print $4}')
        peer_addr_port=$(echo "$line" | awk '{print $5}')

        if [[ "$local_addr_port" == *"]"* ]]; then
            local_addr=$(echo "$local_addr_port" | sed 's/\].*//' | sed 's/\[//')
            local_port=$(echo "$local_addr_port" | sed 's/.*\]://')
        else
            local_addr=$(echo "$local_addr_port" | rev | cut -d':' -f2- | rev)
            local_port=$(echo "$local_addr_port" | rev | cut -d':' -f1 | rev)
        fi

        if [[ "$peer_addr_port" == *"]"* ]]; then
            peer_addr=$(echo "$peer_addr_port" | sed 's/\].*//' | sed 's/\[//')
            peer_port=$(echo "$peer_addr_port" | sed 's/.*\]://')
        else
            peer_addr=$(echo "$peer_addr_port" | rev | cut -d':' -f2- | rev)
            peer_port=$(echo "$peer_addr_port" | rev | cut -d':' -f1 | rev)
        fi

        process_info=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "")
        pid_info=$(echo "$line" | grep -oP 'pid=\K[0-9]+' || echo "")

        conn_obj=$(jq -n \
            --arg local_addr "$local_addr" \
            --arg local_port_str "$local_port" \
            --arg peer_addr "$peer_addr" \
            --arg peer_port_str "$peer_port" \
            --arg process "$process_info" \
            --arg pid_str "$pid_info" \
            '{
                local_addr: $local_addr,
                local_port: (if ($local_port_str | test("^[0-9]+$")) then ($local_port_str | tonumber) else null end),
                peer_addr: $peer_addr,
                peer_port: (if ($peer_port_str | test("^[0-9]+$")) then ($peer_port_str | tonumber) else null end),
                process: $process,
                pid: (if ($pid_str | test("^[0-9]+$")) then ($pid_str | tonumber) else null end)
            }')

        ESTABLISHED_CONN_JSON=$(echo "$ESTABLISHED_CONN_JSON" | jq --argjson obj "$conn_obj" '. + [$obj]')
    done < <(ss -tnpH state established)
fi

# ---------------------------------------------------------------
# 7. DNS Resolvers
# ---------------------------------------------------------------
DNS_RESOLVERS_JSON="[]"

if [[ -f /etc/resolv.conf ]]; then
    NAMESERVERS=$(grep -E "^nameserver" /etc/resolv.conf | awk '{print $2}')
    if [[ -n "$NAMESERVERS" ]]; then
        DNS_RESOLVERS_JSON=$(echo "$NAMESERVERS" | jq -R . | jq -s '.')
    fi
fi

# Check systemd-resolved
SYSTEMD_RESOLVED_STATUS="inactive"
if command -v resolvectl &>/dev/null; then
    if resolvectl status --no-pager &>/dev/null; then
        SYSTEMD_RESOLVED_STATUS="active"
    fi
fi

# ---------------------------------------------------------------
# 8. Construct Final JSON
# ---------------------------------------------------------------
FINAL_JSON=$(jq -n \
    --arg ts "$TIMESTAMP" \
    --arg hn "$HOSTNAME" \
    --argjson ifs "$INTERFACES_JSON" \
    --argjson rts "$ROUTES_JSON" \
    --argjson nbrs "$NEIGHBORS_JSON" \
    --argjson ls "$LISTENING_JSON" \
    --argjson ec "$ESTABLISHED_CONN_JSON" \
    --argjson dns "$DNS_RESOLVERS_JSON" \
    --argjson up_ifs "$UP_INTERFACES" \
    --argjson lc "$LISTENER_COUNT" \
    --arg rs "$SYSTEMD_RESOLVED_STATUS" \
    '{
        timestamp: $ts,
        hostname: $hn,
        interfaces: $ifs,
        routes: $rts,
        neighbors: $nbrs,
        listening_sockets: $ls,
        established_connections: $ec,
        dns_resolvers: $dns,
        summary: {
            up_interfaces: $up_ifs,
            listeners: $lc,
            resolved_status: $rs
        }
    }')

# Write to file
echo "$FINAL_JSON" > "$OUTPUT_FILE"

# Human-readable summary to stdout
echo "Network Baseline Captured Successfully"
echo "--------------------------------------"
echo "Timestamp:              $TIMESTAMP"
echo "Hostname:               $HOSTNAME"
echo "Up Interfaces:          $(echo "$UP_INTERFACES" | jq -r 'join(", ")')"
echo "Listening Sockets:      $LISTENER_COUNT"
echo "Established Connections: $(echo "$ESTABLISHED_CONN_JSON" | jq 'length')"
echo "DNS Resolvers:          $(echo "$DNS_RESOLVERS_JSON" | jq -r 'join(", ")')"
echo "Output:                 $OUTPUT_FILE"
