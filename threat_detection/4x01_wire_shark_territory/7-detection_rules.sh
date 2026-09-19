#!/bin/bash
# Name: 7-detection_rules.sh
# Purpose: Create detection logic for each identified gap in the MedDefense
#          kill chain, transforming forensic findings into operational
#          defenses. Generates pseudocode and implementation guidance for
#          SIEM, Zeek, Python analytics, and NetFlow-based detection engines.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./7-detection_rules.sh
# Output:  Console report with detection matrix + detection_rules.json
#
# ---------------------------------------------------------------------------
# METHODOLOGY
#    Each detection rule derives directly from packet-anchored evidence in
#    Tasks 0-5. Implementation options cover SIEM (correlation/search rules),
#    Zeek (script hooks), Python (scheduled batch analysis), and NetFlow
#    (stream analytics). False positive handling always references baseline
#    profiles from Task 0 where applicable.
#
#    Bitfield filter note: dns.flags.response == 0, not !dns.flags.response
#    — negating bitfields silently matches zero frames (confirmed via tshark
#    diagnostic: ! form returned 0, == 0 returned 120).
# ---------------------------------------------------------------------------

set -euo pipefail

OUT_JSON="detection_rules.json"

python3 - "$OUT_JSON" << 'PYEOF'
import json
import sys

out_json = sys.argv[1]

detection_rules = [
    {
        "detection_id": "DET-001",
        "name": "C2 Beaconing Detection",
        "attack_phase": "Phase 3 — Command and Control Beaconing",
        "real_evidence": "10.10.2.15 → 91.234.99.107, 24 sessions, CV 1.81%, avg 299.84s",
        "type": "Frequency-based behavioral detection",
        "data_sources": [
            "Zeek conn.log (src_ip, dst_ip, duration, start_time)",
            "PCAP-derived session logs (tshark -T fields -e frame.time_epoch)",
            "NetFlow/IPFIX records (source/dest IP, start time delta)",
            "Proxy logs (if outbound HTTP/S traffic proxied)"
        ],
        "rule_logic_pseudocode": '''
function detect_c2_beaconing(events, window_seconds=3600, threshold_count=10):
    grouped = group_by(events, keys=["src_ip", "dst_ip"])

    alerts = []
    for pair, sessions in grouped.items():
        if len(sessions) < threshold_count:
            continue

        recent = [s for s in sessions
                  if s.timestamp >= now() - window_seconds]

        if len(recent) < threshold_count:
            continue

        times = sorted([s.timestamp for s in recent])
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]

        if len(intervals) == 0:
            continue

        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
        stddev = sqrt(variance)
        cv = (stddev / mean_interval) * 100 if mean_interval > 0 else float('inf')

        if cv < 15 and mean_interval > 60:
            alerts.append({
                "alert_type": "C2_BEACONING_SUSPECTED",
                "src_ip": pair.src_ip,
                "dst_ip": pair.dst_ip,
                "session_count": len(recent),
                "mean_interval_s": mean_interval,
                "cv_percent": cv,
                "severity": "HIGH" if cv < 5 else "MEDIUM"
            })

    return alerts
''',
        "siem_example": '''
index=netflow
| bucket _time span=1h
| stats count, values(_time) as times by src_ip dst_ip
| where count > 10
| eval intervals = mvdiff(times)
| eval mean = avg(intervals)
| eval stddev = stdev(intervals)
| eval cv = (stddev / mean) * 100
| where cv < 15 AND mean > 60
| table src_ip dst_ip count mean cv severity
''',
        "test_scenario": "Internal host 10.10.2.15 initiates 24 TCP connections to 91.234.99.107, each spaced at ~300 seconds ±5 seconds jitter",
        "would_detect": "Phase 3 beaconing in c2_beaconing.pcap",
        "false_positives": [
            "Software update clients (Windows Update, apt-get)",
            "Monitoring agents (Nagios, Zabbix)",
            "Backup synchronization tools (rsync, Duplicati)"
        ],
        "mitigation": "Baseline whitelist of known-good IPs/domains from Task 0 clinical profile"
    },
    {
        "detection_id": "DET-002",
        "name": "DNS Query Length Anomaly",
        "attack_phase": "Phase 7 — DNS Exfiltration",
        "real_evidence": "120 queries with 44-60 char labels, entropy 4.5 bits/char",
        "type": "Feature-based anomaly (label length + entropy + TXT frequency)",
        "data_sources": [
            "DNS resolver logs (BIND, Unbound, Windows DNS Server)",
            "Zeek dns.log (qname, qtype, responses)",
            "tshark PCAP analysis (dns.qry.name, dns.txt, dns.flags.response)",
            "Dedicated DNS security appliance logs"
        ],
        "rule_logic_pseudocode": '''
function detect_dns_anomaly(dns_queries, label_threshold=40,
                            entropy_threshold=3.5):
    alerts = []

    for query in dns_queries:
        if query.query_type != "TXT":
            continue

        qname_parts = query.qname.split(".")
        leftmost_label = qname_parts[0]

        label_len = len(leftmost_label)

        if label_len <= label_threshold:
            continue

        freq = Counter(leftmost_label)
        total = len(leftmost_label)
        entropy = -sum((count/total) * log2(count/total)
                       for count in freq.values())

        if entropy < entropy_threshold:
            continue

        base_domain = ".".join(qname_parts[-2:])
        if base_domain in KNOWN_GOOD_DOMAINS:
            continue

        window_count = count_txt_queries(base_domain, window_minutes=30)

        if window_count > 10:
            alerts.append({
                "alert_type": "DNS_TUNNEL_ANOMALY",
                "src_ip": query.src_ip,
                "qname": query.qname,
                "label_length": label_len,
                "entropy": entropy,
                "query_count_30min": window_count,
                "severity": "CRITICAL" if window_count > 50 else "HIGH"
            })

    return alerts
''',
        "test_scenario": "Host 10.10.1.10 sends 120 DNS TXT queries over 25 minutes with labels 44-60 characters (base32-encoded data)",
        "would_detect": "Phase 7 DNS exfiltration in dns_exfil.pcap",
        "false_positives": [
            "SPF/DKIM verification (TXT queries but short labels)",
            "Domain validation tokens (typically <40 chars)",
            "Legitimate CDN configuration queries"
        ],
        "mitigation": "Entropy filter (>3.5 bits/char excludes most administrative TXT), whitelist authoritative DNS zones"
    },
    {
        "detection_id": "DET-003",
        "name": "VPN Geo-Anomaly",
        "attack_phase": "Phase 4 — External Access / VPN Pivot",
        "real_evidence": "154.118.42.89 (Nigeria, AS37340 Spectranet) inbound to 10.10.0.1:443",
        "type": "Geographic reputation anomaly (geo-ASN mismatch + dynamic block)",
        "data_sources": [
            "VPN concentrator authentication logs (Cisco AnyConnect, FortiGate, Palo Alto)",
            "GeoIP lookup database (MaxMind GeoLite2, IP2Location)",
            "Threat intelligence feeds (dynamic/mobile block lists)",
            "TLS ClientHello metadata (SNI, JA3 fingerprint)"
        ],
        "rule_logic_pseudocode": '''
function detect_vpn_geo_anomaly(session, org_allowed_countries,
                                org_allowed_asns):
    src_ip = session.source_ip
    geo = geoip_lookup(src_ip)
    asn_info = asn_lookup(src_ip)

    country_match = geo.country_code in org_allowed_countries
    asn_match = asn_info.as_number in org_allowed_asns

    is_dynamic = asn_info.allocation_type in ["DYN", "MOBILE", "LTE"]

    login_history = get_account_login_history(session.account, days=30)
    geo_history = {log.country_code for log in login_history}

    if not country_match:
        return {
            "alert_type": "VPN_GEO_ANOMALY",
            "src_ip": src_ip,
            "country": geo.country,
            "asn": asn_info.as_number,
            "allocation": asn_info.allocation_type,
            "account": session.account,
            "history_countries": list(geo_history),
            "severity": "CRITICAL" if is_dynamic else "HIGH"
        }

    if not asn_match and not country_match:
        return {
            "alert_type": "VPN_NEW_ASN_DETECTED",
            "src_ip": src_ip,
            "asn": asn_info.as_number,
            "severity": "MEDIUM"
        }

    return None
''',
        "test_scenario": "User dmarsh@meddefense.com authenticates to VPN from 154.118.42.89 (Nigeria, AS37340), organization baseline expects US/CA/EU only",
        "would_detect": "Phase 4 VPN connection from 154.118.42.89",
        "false_positives": [
            "Legitimate remote workers traveling internationally",
            "Contractor accounts with approved travel authorization",
            "Mobile device users (if BYOD policy permits)"
        ],
        "mitigation": "Require pre-approved travel notification system integration, MFA push notification + secondary approval queue"
    },
    {
        "detection_id": "DET-004",
        "name": "Cross-Role RDP",
        "attack_phase": "Phase 5 — Lateral Movement (RDP Pivot)",
        "real_evidence": "10.10.2.15 (clinical subnet WS-NURSE-04) RDP to 10.10.1.10 (billing-srv-01)",
        "type": "Role-based access control violation detection",
        "data_sources": [
            "Active Directory security logs (Event ID 4624 - successful logon)",
            "Windows Event Forwarding (WEF) RDP-specific events (4624 logon_type=10)",
            "Network flow logs (3389/tcp, src subnet, dst subnet mapping)",
            "Identity-Aware Proxy or Privileged Access Management (PAM) logs"
        ],
        "rule_logic_pseudocode": '''
function detect_cross_role_rdp(rdp_event, role_mapping, subnet_roles):
    src_ip = rdp_event.source_ip
    dst_ip = rdp_event.dest_ip
    account = rdp_event.account_name

    src_asset_role = get_asset_role(src_ip, subnet_roles)
    dst_asset_role = get_asset_role(dst_ip, subnet_roles)
    user_roles = get_user_roles(account, role_mapping)

    ALLOWED_TRANSITIONS = {
        ("IT", "server"): True,
        ("IT", "admin"): True,
        ("clinical", "clinical"): True,
        ("clinical", "admin"): False,
        ("server", "server"): True,
    }

    transition_key = (max(user_roles), dst_asset_role)

    if not ALLOWED_TRANSITIONS.get(transition_key, False):
        if rdp_event.is_after_hours():
            severity = "CRITICAL"
        else:
            severity = "HIGH"

        return {
            "alert_type": "CROSS_ROLE_RDP_VIOLATION",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "account": account,
            "src_role": src_asset_role,
            "dst_role": dst_asset_role,
            "user_roles": list(user_roles),
            "session_duration_sec": rdp_event.duration,
            "bytes_exchanged": rdp_event.bytes_sent + rdp_event.bytes_recv,
            "severity": severity,
            "after_hours": rdp_event.is_after_hours()
        }

    return None
''',
        "test_scenario": "Account dmarsh (functional role: clinical) initiates RDP session from 10.10.2.15 to 10.10.1.10 (server subnet), 265KB exchanged",
        "would_detect": "Phase 5 RDP to billing-srv-01",
        "false_positives": [
            "IT admins managing clinical systems (need documented exceptions)",
            "Emergency maintenance windows (require pre-registration)",
            "Temporary contractors with approved cross-role access"
        ],
        "mitigation": "Integration with HR/AD role assignment, require PAM ticket for cross-role access, after-hours sessions trigger higher severity"
    },
    {
        "detection_id": "DET-005",
        "name": "DNS Tunneling TXT Query Pattern",
        "attack_phase": "Phase 7 — DNS Exfiltration",
        "real_evidence": "120 anomalous queries in 24.74 min (4.85/min), 20.8x baseline rate",
        "type": "Frequency + encoding pattern detection",
        "data_sources": [
            "DNS query logs with TXT record type",
            "Baseline TXT query rates per host (Task 0 baseline_clinical.json)",
            "Encoded label detection (base32/base64 characteristics)"
        ],
        "rule_logic_pseudocode": '''
function detect_dns_tunnel_txt(dns_events, baseline_rates):
    alerts = []

    # Group TXT queries by source IP and base domain
    grouped = group_by(dns_events, keys=["src_ip", "base_domain"])

    for key, queries in grouped.items():
        src_ip, base_domain = key

        # Get baseline rate for this host
        baseline_rate = baseline_rates.get(src_ip, {}).get("txt_queries_per_min", 0)

        if baseline_rate == 0:
            baseline_rate = 0.23  # Global default from Task 0

        # Calculate current rate in sliding window
        window_start = min(q.timestamp for q in queries)
        window_end = max(q.timestamp for q in queries)
        duration_mins = (window_end - window_start).total_seconds() / 60

        query_rate = len(queries) / duration_mins if duration_mins > 0 else 0

        # Check for encoded label patterns
        has_encoded_labels = any(
            is_base32_or_base64(query.leftmost_label)
            for query in queries
        )

        if query_rate > baseline_rate * 5 and has_encoded_labels:
            alerts.append({
                "alert_type": "DNS_TTUNNEL_HIGH_RATE",
                "src_ip": src_ip,
                "base_domain": base_domain,
                "query_count": len(queries),
                "query_rate_per_min": query_rate,
                "baseline_rate_per_min": baseline_rate,
                "multiplier": query_rate / baseline_rate,
                "severity": "CRITICAL" if query_rate / baseline_rate > 15 else "HIGH"
            })

    return alerts
''',
        "test_scenario": "Host 10.10.1.10 sends 120 TXT queries over 25 minutes to data-sync.meddefense-portal.com at 4.85/min (baseline 0.23/min = 20.8x)",
        "would_detect": "Phase 7 DNS exfiltration",
        "false_positives": [
            "Bulk mail server SPF checks",
            "Email security gateway DKIM verifications",
            "CDN failover DNS health checks"
        ],
        "mitigation": "Rate multiplier threshold tuned to baseline per host, require BOTH high rate AND encoded label presence"
    },
    {
        "detection_id": "DET-006",
        "name": "TLS to Recently Observed Lookalike Domain",
        "attack_phase": "Phase 2 — Credential Harvesting Session",
        "real_evidence": "Session to meddefense-portal.com (lookalike), TLS SNI visible, 47.2s duration",
        "type": "IOC-based detection with lookalike domain tracking",
        "data_sources": [
            "TLS handshake metadata (SNI from ClientHello)",
            "DNS query logs (domain first-seen timestamp)",
            "Threat intelligence IOC feeds (phishing campaign domains)",
            "Certificate transparency logs (new cert issuance monitoring)"
        ],
        "rule_logic_pseudocode": '''
function detect_tls_lookalike(sni_records, phishing_ioc_list, first_seen_db):
    alerts = []

    for record in sni_records:
        sni = record.sni
        src_ip = record.client_ip

        # Check against known phishing campaign IOCs
        if sni in phishing_ioc_list:
            alerts.append({
                "alert_type": "TLS_PHSISHING_IOC_MATCH",
                "sni": sni,
                "src_ip": src_ip,
                "match_type": "IOC_LIST",
                "campaign": find_campaign(sni, phishing_ioc_list),
                "severity": "CRITICAL"
            })
            continue

        # Check if domain was first-seen recently (within 7 days)
        first_seen = first_seen_db.get(sni)
        if first_seen and (now() - first_seen).days < 7:
            # Additional heuristics
            similarity_score = calculate_domain_similarity(sni, "meddefense.com")

            if similarity_score > 0.85:
                alerts.append({
                    "alert_type": "TLS_LOOKALIKE_DOMAIN",
                    "sni": sni,
                    "src_ip": src_ip,
                    "first_seen_days": (now() - first_seen).days,
                    "similarity_to_meddefense": similarity_score,
                    "severity": "HIGH"
                })

    return alerts
''',
        "test_scenario": "Host 10.10.2.15 connects to meddefense-portal.com via HTTPS, SNI visible in TLS ClientHello, session 47.2s with 482-byte client record",
        "would_detect": "Phase 2 phishing-click TLS session",
        "false_positives": [
            "Legitimate typosquatting domains with business justification",
            "Newly acquired company domains",
            "Third-party service providers with similar naming"
        ],
        "mitigation": "Maintain approved vendor domain registry, require business case for new domains under 7 days old, integrate with DMARC/BIMI verification"
    }
]

print("=" * 64)
print("   DETECTION ENGINEERING PLAN")
print("   Incident: MedDefense Phishing → Lateral Movement → DNS Exfiltration")
print("=" * 64)
print()

for det in detection_rules:
    print(f"[*] Detection {det['detection_id']}: {det['name']}")
    print(f"    Type: {det['type']}")
    print(f"    Phase: {det['attack_phase']}")
    print(f"    Real Evidence: {det['real_evidence']}")
    print(f"    Data Source:")
    for ds in det['data_sources']:
        print(f"      - {ds}")
    print(f"    Rule Logic: See pseudocode in script documentation")
    print(f"    Test Scenario: {det['test_scenario']}")
    print(f"    Would Detect: {det['would_detect']}")
    print(f"    False Positive Considerations:")
    for fp in det['false_positives']:
        print(f"      - {fp}")
    print(f"    Mitigation: {det['mitigation']}")
    print()

print("=" * 64)
print("   DETECTION COVERAGE SUMMARY")
print("=" * 64)
print()
print("BEFORE PACKET ANALYSIS:")
print("  - campaign visible only as email IOCs (4x00)")
print()
print("AFTER PACKET ANALYSIS:")
print("  - detections cover phishing click, beaconing, VPN pivot,")
print("    lateral movement, and DNS exfiltration")
print()
print("REMAINING GAPS:")
print("  - endpoint execution confirmation requires endpoint logs")
print("  - exact credential content cannot be recovered from encrypted TLS")
print("  - MFA status unobservable from network captures")
print()

# Write JSON artifact
with open(out_json, "w") as fh:
    json.dump({"detections": detection_rules}, fh, indent=2)
    fh.write("\n")

print(f"EVIDENCE SAVED: {out_json}")
PYEOF
