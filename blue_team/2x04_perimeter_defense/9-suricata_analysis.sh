#!/bin/bash
#
# Name:        9-suricata_analysis.sh
# Purpose:     Replay PCAP through Suricata, parse eve.json alerts, classify by severity and kind
# Author:      Steve - Cybersecurity Engineer
# Date:        August 14, 2026
#

set -euo pipefail

# Configuration
DEFAULT_PCAP="/home/analyst/MedDefense_Lab/PCAPs/mixed_traffic.pcap"
PCAP_PATH="${1:-$DEFAULT_PCAP}"
CONFIG_FILE="./suricata.yaml"
LAB_DIR="/home/analyst/MedDefense_Lab"
CATALOG_FILE="${LAB_DIR}/capstone/signature_categories.json"
OUTPUT_JSON="suricata_alerts.json"
TMPDIR_BASE="/tmp/suricata-analysis-$$"

# Verify inputs exist
if [[ ! -f "$PCAP_PATH" ]]; then
    echo "Error: PCAP file not found: $PCAP_PATH" >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: suricata.yaml not found. Run 8-suricata_setup.sh first." >&2
    exit 1
fi

if [[ ! -f "$CATALOG_FILE" ]]; then
    CATALOG_FILE="signature_categories.json"
fi

if [[ ! -f "$CATALOG_FILE" ]]; then
    echo "Error: signature_categories.json not found in $LAB_DIR/capstone/ or current directory." >&2
    exit 1
fi

echo "[*] PCAP: $PCAP_PATH"
echo "[*] Config: $CONFIG_FILE"
echo "[*] Catalog: $CATALOG_FILE"

# ---------------------------------------------------------------
# 1. Run suricata -c ./suricata.yaml -r <pcap> -l <tmpdir> and wait
# ---------------------------------------------------------------
mkdir -p "$TMPDIR_BASE"

STARTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[*] Starting Suricata replay at $STARTED_AT..."
echo "[*] Output directory: $TMPDIR_BASE"

suricata -c "$CONFIG_FILE" -r "$PCAP_PATH" -l "$TMPDIR_BASE" 2>&1 | tail -3
REPLAY_EXIT=$?

FINISHED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[*] Suricata replay finished at $FINISHED_AT (exit: $REPLAY_EXIT)"

EVE_FILE="${TMPDIR_BASE}/eve.json"
if [[ ! -f "$EVE_FILE" ]]; then
    echo "Error: eve.json not created at $EVE_FILE" >&2
    exit 1
fi

echo "[*] Found eve.json: $EVE_FILE"

# ---------------------------------------------------------------
# 2. Parse eve.json with jq, retaining only event_type=="alert" records
#    Extract: timestamp, src_ip, src_port, dst_ip, dst_port, proto,
#    alert.signature, alert.signature_id, alert.category, alert.severity
#    Classify each signature using signature_categories.json
# ---------------------------------------------------------------
echo "[*] Parsing alert records from eve.json..."

ALERTS_JSON=$(jq -s '
    def extract_alert:
        {
            timestamp: .timestamp,
            src_ip: (.src_ip // "unknown"),
            src_port: (.src_port // null),
            dst_ip: (.dest_ip // .dst_ip // "unknown"),
            dst_port: (.dest_port // .dst_port // null),
            proto: (.proto // "unknown"),
            signature: (.alert.signature // "unknown"),
            signature_id: (.alert.signature_id // "unknown"),
            category: (.alert.category // "unknown"),
            severity: (.alert.severity // 0)
        };

    . as $all
    | ($all | map(select(.event_type? == "alert")) | map(extract_alert)) as $alerts

    | {
        alerts: $alerts,
        total_alerts: ($alerts | length),
        unique_signatures: ($alerts | map(.signature) | unique | length),
        severity_distribution: (
            $alerts
            | group_by(.severity)
            | map({(.[0].severity | tostring): length})
            | add // {}
        ),
        by_signature: (
            $alerts
            | group_by(.signature_id)
            | map({signature_id: .[0].signature_id, count: length, severity: .[0].severity})
            | sort_by(-.count)
        ),
        top_sources: (
            $alerts
            | group_by(.src_ip)
            | map({src_ip: .[0].src_ip, count: length})
            | sort_by(-.count)
        ),
        top_destinations: (
            $alerts
            | group_by(.dst_ip)
            | map({dst_ip: .[0].dst_ip, count: length})
            | sort_by(-.count)
        )
    }
' --slurpfile catalog "$CATALOG_FILE" "$EVE_FILE" 2>/dev/null || echo '{"alerts":[],"total_alerts":0,"unique_signatures":0,"severity_distribution":{},"by_signature":[],"top_sources":[],"top_destinations":[]}')

# ---------------------------------------------------------------
# 3. Classify each signature into categories using the catalog
#    signature_categories.json maps signature_id (numeric string) to:
#    reconnaissance, exploit, lateral_movement, exfiltration,
#    malware_c2, policy_violation, other
# ---------------------------------------------------------------
echo "[*] Classifying alerts by category..."

CLASSIFIED_JSON=$(jq '
    . as $root
    | ($catalog[0]) as $cat

    # Build signature_id map from catalog
    | ($cat.signatures // {}) as $sig_map

    # Classify each alert by signature_id
    | $root.alerts as $alerts
    | $alerts
    | map(
        .signature_id as $sid
        | .category_class = ($sig_map[($sid | tostring)] // "other")
        | .
    ) as $classified

    | $root
    | .alerts = $classified
    | .by_category = (
        $classified
        | group_by(.category_class)
        | map({category: .[0].category_class, count: length})
        | sort_by(-.count)
    )
' --slurpfile catalog "$CATALOG_FILE" <<< "$ALERTS_JSON" 2>/dev/null || echo "$ALERTS_JSON")

# ---------------------------------------------------------------
# 4. Construct final suricata_alerts.json with required top-level keys
#    pcap, started_at, finished_at, total_alerts, unique_signatures,
#    severity_distribution, by_category, top_sources, top_destinations, alerts
# ---------------------------------------------------------------
TOTAL_ALERTS=$(echo "$CLASSIFIED_JSON" | jq -r '.total_alerts // 0')
UNIQUE_SIGS=$(echo "$CLASSIFIED_JSON" | jq -r '.unique_signatures // 0')
SEVERITY_DIST=$(echo "$CLASSIFIED_JSON" | jq -c '.severity_distribution // {}')
BY_CATEGORY=$(echo "$CLASSIFIED_JSON" | jq -c '.by_category // []')
TOP_SOURCES=$(echo "$CLASSIFIED_JSON" | jq -c '.top_sources // []')
TOP_DESTS=$(echo "$CLASSIFIED_JSON" | jq -c '.top_destinations // []')
ALERTS_ARRAY=$(echo "$CLASSIFIED_JSON" | jq -c '.alerts // []')

FINAL_JSON=$(jq -n \
    --arg pcap "$PCAP_PATH" \
    --arg sa "$STARTED_AT" \
    --arg fa "$FINISHED_AT" \
    --argjson ta "$TOTAL_ALERTS" \
    --argjson us "$UNIQUE_SIGS" \
    --argjson sd "$SEVERITY_DIST" \
    --argjson bc "$BY_CATEGORY" \
    --argjson ts "$TOP_SOURCES" \
    --argjson td "$TOP_DESTS" \
    --argjson al "$ALERTS_ARRAY" \
    '{
        pcap: $pcap,
        started_at: $sa,
        finished_at: $fa,
        total_alerts: $ta,
        unique_signatures: $us,
        severity_distribution: $sd,
        by_category: $bc,
        top_sources: $ts,
        top_destinations: $td,
        alerts: $al
    }')

echo "$FINAL_JSON" > "$OUTPUT_JSON"

# ---------------------------------------------------------------
# 5. Human-readable summary to stdout
#    Print key findings including top signatures, sources, and destinations
# ---------------------------------------------------------------
echo ""
echo "Suricata Replay Analysis Complete"
echo "================================="
echo "PCAP:               $PCAP_PATH"
echo "Started:            $STARTED_AT"
echo "Finished:           $FINISHED_AT"
echo "Total alerts:       $TOTAL_ALERTS"
echo "Unique signatures:  $UNIQUE_SIGS"
echo ""
echo "Severity distribution:"
echo "$SEVERITY_DIST" | jq -r 'to_entries[] | "  Severity \(.key): \(.value) alerts"' 2>/dev/null || echo "  (none)"
echo ""
echo "Alerts by category:"
echo "$BY_CATEGORY" | jq -r '.[] | "  \(.category): \(.count)"' 2>/dev/null || echo "  (none)"
echo ""
echo "Top source IPs:"
echo "$TOP_SOURCES" | jq -r '.[:5][] | "  \(.src_ip): \(.count) alerts"' 2>/dev/null || echo "  (none)"
echo ""
echo "Top destination IPs:"
echo "$TOP_DESTS" | jq -r '.[:5][] | "  \(.dst_ip): \(.count) alerts"' 2>/dev/null || echo "  (none)"
echo ""
echo "Top signatures:"
echo "$ALERTS_ARRAY" | jq -r 'group_by(.signature) | map({sig: .[0].signature, sid: .[0].signature_id, count: length, src: .[0].src_ip, dst: .[0].dst_ip}) | sort_by(-.count) | .[:5][] | "  sig=\(.sig)  id=\(.sid)  src=\(.src)  dst=\(.dst)  count=\(.count)"' 2>/dev/null || echo "  (none)"
echo ""
echo "Output: $OUTPUT_JSON"
echo ""
echo "Key findings (escalation-worthy):"

# Print escalation-worthy alerts (reconnaissance, exploit, lateral_movement, exfiltration, malware_c2)
echo "$ALERTS_ARRAY" | jq -r '
    group_by(.signature_id) | map({
        sig: .[0].signature,
        sid: .[0].signature_id,
        src: .[0].src_ip,
        dst: .[0].dst_ip,
        cat: .[0].category_class
    }) | sort_by(.sid) | .[] |
    select(.cat != "other" and .cat != "policy_violation") |
    "{\"sig\":\"\(.sig)\",\"src\":\"\(.src)\",\"dst\":\"\(.dst)\"}"
' 2>/dev/null | head -10 || echo "  (none)"

echo ""

# Cleanup
rm -rf "$TMPDIR_BASE"
