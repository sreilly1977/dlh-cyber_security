#!/bin/bash
#
# Name:        2-segmentation_rules.sh
# Purpose:     Emit structured segmentation rules JSON defining zones, flows, and deny_all rules
# Author:      Steve - Cybersecurity Engineer
# Date:        August 14, 2026
#

set -euo pipefail

# Configuration
OUTPUT_FILE="segmentation_rules.json"
GENERATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ---------------------------------------------------------------
# Define the four MedDefense zones
# ---------------------------------------------------------------
ZONES_JSON=$(jq -n '[
    {
        name: "DMZ",
        cidr: "10.10.2.0/24",
        purpose: "Public-facing services",
        default_inbound: "drop",
        default_outbound: "accept"
    },
    {
        name: "INTERNAL",
        cidr: "10.10.1.0/24",
        purpose: "Clinical applications and databases",
        default_inbound: "drop",
        default_outbound: "accept"
    },
    {
        name: "MGMT",
        cidr: "192.168.10.0/24",
        purpose: "Administration and management",
        default_inbound: "drop",
        default_outbound: "accept"
    },
    {
        name: "MEDDEV",
        cidr: "10.10.3.0/24",
        purpose: "Medical device VLAN",
        default_inbound: "drop",
        default_outbound: "accept",
        outbound_restrictions: ["no_dmz_access", "no_public_internet_access"]
    }
]')

# ---------------------------------------------------------------
# Define cross-zone and intra-zone allow flows plus deny_all rules
# Flows cover: ssh administration, clinical access, DICOM, EHR,
# database access, and DNS resolution to MGMT resolver.
# Deny_all rules enforce medical device isolation and segmentation.
# ---------------------------------------------------------------
FLOWS_JSON=$(jq -n '[
    # MGMT to INTERNAL - ssh administration
    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 22,
        justification: "Administration access to clinical servers"
    },
    # MGMT to DMZ - ssh administration
    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "DMZ",
        proto: "tcp",
        dport: 22,
        justification: "Administration access to DMZ hosts"
    },
    # INTERNAL clinical workstations to INTERNAL server hosts
    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 443,
        justification: "Clinical workstations to INTERNAL server hosts (HTTPS)"
    },
    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 3306,
        justification: "Clinical workstations to INTERNAL database servers"
    },
    # DMZ to INTERNAL - databases only from named DMZ application hosts
    {
        action: "allow",
        src_zone: "DMZ",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 3306,
        justification: "DMZ application hosts to INTERNAL databases",
        exception_for: "dmz_app_hosts_only",
        src_restriction: "named_dmz_application_hosts"
    },
    # MEDDEV to INTERNAL - DICOM imaging (tcp/4242) and EHR web (tcp/443)
    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 4242,
        justification: "DICOM imaging to PACS"
    },
    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "INTERNAL",
        proto: "tcp",
        dport: 443,
        justification: "EHR web integration for device display"
    },
    # ALL zones to MGMT resolver - DNS (udp/53 and tcp/53)
    {
        action: "allow",
        src_zone: "DMZ",
        dst_zone: "MGMT",
        proto: "udp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },
    {
        action: "allow",
        src_zone: "DMZ",
        dst_zone: "MGMT",
        proto: "tcp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },
    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "MGMT",
        proto: "udp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },
    {
        action: "allow",
        src_zone: "INTERNAL",
        dst_zone: "MGMT",
        proto: "tcp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },
    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "MGMT",
        proto: "udp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },
    {
        action: "allow",
        src_zone: "MEDDEV",
        dst_zone: "MGMT",
        proto: "tcp",
        dport: 53,
        justification: "DNS resolution to MGMT resolver"
    },
    # MGMT to MEDDEV - administration and DICOM management
    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "MEDDEV",
        proto: "tcp",
        dport: 22,
        justification: "Administration access to medical devices"
    },
    {
        action: "allow",
        src_zone: "MGMT",
        dst_zone: "MEDDEV",
        proto: "tcp",
        dport: 4242,
        justification: "DICOM management to medical devices"
    },
    # Explicit deny_all for zone pairs with no allow flows
    {
        action: "deny_all",
        src_zone: "DMZ",
        dst_zone: "MEDDEV",
        proto: "any",
        dport: 0,
        justification: "No flows from DMZ to MEDDEV (medical device isolation)"
    },
    {
        action: "deny_all",
        src_zone: "INTERNAL",
        dst_zone: "DMZ",
        proto: "any",
        dport: 0,
        justification: "No flows from INTERNAL to DMZ (segmentation enforcement)"
    },
    {
        action: "deny_all",
        src_zone: "INTERNAL",
        dst_zone: "MEDDEV",
        proto: "any",
        dport: 0,
        justification: "No flows from INTERNAL to MEDDEV (medical device isolation)"
    },
    {
        action: "deny_all",
        src_zone: "MEDDEV",
        dst_zone: "DMZ",
        proto: "any",
        dport: 0,
        justification: "No flows from MEDDEV to DMZ or public Internet"
    }
]')

# ---------------------------------------------------------------
# Build summary block
# ---------------------------------------------------------------
SUMMARY_JSON=$(echo "$FLOWS_JSON" | jq '{
    flow_count: length,
    allow_count: [.[] | select(.action == "allow")] | length,
    deny_count: [.[] | select(.action == "deny_all")] | length,
    cross_zone_pairs: 12
}')

# ---------------------------------------------------------------
# Construct and write final JSON
# ---------------------------------------------------------------
FINAL_JSON=$(jq -n \
    --arg ga "$GENERATED_AT" \
    --argjson zones "$ZONES_JSON" \
    --argjson flows "$FLOWS_JSON" \
    --argjson summary "$SUMMARY_JSON" \
    '{
        generated_at: $ga,
        zones: $zones,
        flows: $flows,
        summary: $summary
    }')

echo "$FINAL_JSON" > "$OUTPUT_FILE"

# Human-readable summary to stdout
echo "Segmentation Rules Generated"
echo "============================="
echo "Generated at:     $GENERATED_AT"
echo "Zones:            4 (DMZ, INTERNAL, MGMT, MEDDEV)"
echo "Total flows:      $(echo "$SUMMARY_JSON" | jq -r '.flow_count')"
echo "Allow rules:      $(echo "$SUMMARY_JSON" | jq -r '.allow_count')"
echo "Deny_all rules:   $(echo "$SUMMARY_JSON" | jq -r '.deny_count')"
echo "Cross-zone pairs: $(echo "$SUMMARY_JSON" | jq -r '.cross_zone_pairs')"
echo "Output:           $OUTPUT_FILE"
