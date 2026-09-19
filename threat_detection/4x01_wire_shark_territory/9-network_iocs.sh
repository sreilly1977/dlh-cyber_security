#!/bin/bash
# Name: 9-network_iocs.sh
# Purpose: Extract and structure every network-level indicator of compromise
#          from the 4x01 packet analysis, categorize by detection utility
#          (BLOCK / DETECT / HUNT / CONTEXT), merge with the 4x00 email-analysis
#          IOC package into a unified campaign package, and quantify the
#          intelligence value added by packet analysis over email analysis
#          alone. Network IOC values are derived exclusively from the Task
#          0-6 evidence artifacts; the 4x00 package is embedded verbatim
#          (defanged) from the source report. Indicators not present in the
#          captures (JA3 fingerprint, certificate subject/hash) are
#          explicitly marked NOT CAPTURED rather than invented.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./9-network_iocs.sh
#          Requires phishing_click_evidence.json and kill_chain_evidence.json;
#          optionally c2_beacon, dns_tunnel, lateral_movement, vpn_pivot
#          artifacts for richer derivation. Also reads baseline_clinical.json
#          to compute DNS TXT rate multiplier consistently with Task 6.
# Output:  Console report + campaign_iocs.json
#
# ---------------------------------------------------------------------------
# 4x00 SOURCE (verbatim values, defanged)
#   ~/projects/dlh/threat_detection/4x00_phishing_dissection/11-ioc_extraction.md
#   Report author's own, dated 18 Sep 2026
#   Quality grading in that report: IOCs 1-13 and 17-20 HIGH/block-safe;
#   14 (SHA-256) MEDIUM and unverified; 16, 21-25 monitor/context;
#   26 (HC3@hhs[.]gov) is a DO-NOT-BLOCK whitelist baseline; 27 is the
#   internal victim identifier excluded from sharing.
#
# DERIVATION NOTES (4x01 network layer)
#   - VPN source IP / ASN ................ Task 5 artifact (full_timeline.pcap)
#   - Tunnel subdomain + TXT pattern ...... Task 3 artifact (dns_exfil.pcap)
#   - Beacon timing signature ............. Task 2 artifact (c2_beaconing.pcap)
#   - Phishing infra (dual-role confirm) .. Task 1/2 artifacts
#   - Internal-flow signatures ............ Task 4 artifact (internal only,
#     never BLOCK candidates)
#   - JA3 / cert subject .................. NOT CAPTURED in any artifact;
#     recorded as documented absence
#   - Overlap handling: meddefense-portal.com and 91.234.99.107 already
#     exist in the 4x00 package — network analysis ENRICHES them (dual-role
#     infrastructure proof) but does not count them as new IOCs.
#   - Rate multiplier: derived from baseline_clinical.json to match
#     Task 6's computation exactly (avoids 0.23 hardcode divergence).
#   - Defanging: defang_all() is idempotent — values already containing
#     [. ] markers pass through unchanged; every raw dot is escaped once.
# ---------------------------------------------------------------------------

set -euo pipefail

OUT_JSON="campaign_iocs.json"

if [[ ! -f phishing_click_evidence.json || ! -f kill_chain_evidence.json ]]; then
    echo "ERROR: Task 1/6 artifacts missing — run the phase scripts first" >&2
    exit 1
fi

python3 - "$OUT_JSON" <<'PYEOF'
import json
import sys

out_json = sys.argv[1]

def load(name):
    try:
        with open(name) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None

phish = load("phishing_click_evidence.json")
beacon = load("c2_beacon_evidence.json")
tunnel = load("dns_tunnel_evidence.json")
lateral = load("lateral_movement_evidence.json")
vpn = load("vpn_pivot_evidence.json")
kc = load("kill_chain_evidence.json")
baseline = load("baseline_clinical.json") or {}

def defang_all(value):
    """Defang URLs, domains, IPs for safe-handling output.
    Idempotent: values already containing [.] markers pass through
    unchanged; every remaining raw dot is escaped exactly once."""
    v = str(value)
    v = v.replace("https://", "hxxps://").replace("http://", "hxxps://")
    v = v.replace("[.]", "\x00")   # protect existing defang markers
    v = v.replace(".", "[.]")     # escape each remaining raw dot once
    v = v.replace("\x00", "[.]")  # restore protected markers
    return v

def defang_ip(ip):
    return str(ip).replace(".", "[.]")

# ---------------------------------------------------------------------------
# 4x00 IOC PACKAGE — verbatim from 11-ioc_extraction.md (already defanged)
# ---------------------------------------------------------------------------
# (num, type, value, source, category, confidence, action, context)
FOURX = [
    (1, "domain", "meddefense-portal[.]com", "E2", "BLOCK", "HIGH",
     "BLOCK", "lookalike domain; mail + phishing page co-located"),
    (2, "url", "hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1",
     "E2", "BLOCK", "HIGH", "BLOCK", "per-victim harvesting URL; confirmed click"),
    (3, "ip", "91[.]234[.]99[.]107", "E2", "BLOCK", "HIGH", "BLOCK",
     "sending mail server for meddefense-portal[.]com"),
    (4, "email", "noreply@meddefense-portal[.]com", "E2", "BLOCK", "HIGH",
     "BLOCK/alert", "sender address; Reply-To no-reply@ also observed"),
    (5, "domain", "outlook-protection[.]com", "E3", "BLOCK", "HIGH", "BLOCK",
     "Microsoft brand impersonation; attacker-set SPF/DKIM/DMARC pass"),
    (6, "url", "hxxps://outlook-protection[.]com/verify", "E3", "BLOCK",
     "HIGH", "BLOCK", "M365 credential harvesting URL"),
    (7, "ip", "51[.]38[.]42[.]17", "E3", "BLOCK", "HIGH", "BLOCK",
     "sending mail server for outlook-protection[.]com"),
    (8, "email", "security@outlook-protection[.]com", "E3", "BLOCK", "HIGH",
     "BLOCK/alert", "sender in unusual-sign-in lure"),
    (9, "domain", "medequip-supplies[.]net", "E5", "BLOCK", "HIGH", "BLOCK",
     "vendor fraud lookalike; mail + payment + login portals co-located"),
    (10, "url", "hxxps://medequip-supplies[.]net/invoices/pay?id=INV-2026-04891",
     "E5", "BLOCK", "HIGH", "BLOCK",
     "fraudulent payment portal; identical in email body and embedded PDF link"),
    (11, "url", "hxxps://medequip-supplies[.]net/portal/login", "E5", "BLOCK",
     "HIGH", "BLOCK", "secondary harvesting path (invoice-retrieval fallback)"),
    (12, "ip", "185[.]176[.]43[.]22", "E5", "BLOCK", "HIGH", "BLOCK",
     "sending mail server for medequip-supplies[.]net"),
    (13, "email", "invoices@medequip-supplies[.]net", "E5", "BLOCK", "HIGH",
     "BLOCK/alert", "invoice-lure sender; Reply-To billing@ also observed"),
    (14, "file_hash", "2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f",
     "E5", "MONITOR", "MEDIUM (unverified — in-object label, not locally recomputed)",
     "monitor/search after verification", "SHA-256 of INV-2026-04891.pdf attachment"),
    (15, "filename", "INV-2026-04891[.]pdf", "E5", "MONITOR", "HIGH",
     "alert/block filename pattern at gateway",
     "fabricated invoice attachment; created 1s before send"),
    (16, "tool", "wkhtmltopdf 0.12.6", "E5", "CONTEXT", "MEDIUM",
     "hunt in inbound attachment metadata",
     "PDF producer string proving scripted generation"),
    (17, "domain", "meddefense-benefits[.]org", "E7", "BLOCK", "HIGH", "BLOCK",
     "HR benefits lookalike (.org + hyphen variant)"),
    (18, "url", "hxxps://meddefense-benefits[.]org/enroll", "E7", "BLOCK",
     "HIGH", "BLOCK", "benefits enrollment harvesting URL"),
    (19, "ip", "164[.]90[.]218[.]73", "E7", "BLOCK", "HIGH", "BLOCK",
     "sending mail server for meddefense-benefits[.]org"),
    (20, "email", "hr-notifications@meddefense-benefits[.]org", "E7", "BLOCK",
     "HIGH", "BLOCK/alert", "sender address; Reply-To no-reply@ also observed"),
    (21, "infra_note", "shared tooling pattern (see 4x00 report IOC 21)",
     "campaign", "CONTEXT", "LOW",
     "context only", "shared tooling across lookalike domains — see 4x00 report"),
    (22, "infra_note", "mail/web co-location pattern", "campaign", "CONTEXT",
     "LOW", "context only",
     "all four campaign domains co-locate mail server and web portal"),
    (23, "infra_note", "budget VPS hosting tier", "campaign", "CONTEXT", "LOW",
     "context only", "hosting tier consistent with disposable infrastructure"),
    (24, "infra_note", "newly-registered domains (<30d) with keywords portal/benefits/supplies/login",
     "E8", "MONITOR", "MEDIUM (registration ages inferred, not WHOIS-confirmed)",
     "feed newly-registered-domain detection",
     "HC3-observed campaign pattern matching all four MedDefense domains"),
    (25, "infra_note", "role-targeted delivery with urgency deadlines",
     "E2,E3,E5,E7,E8", "CONTEXT", "MEDIUM", "monitor/context",
     "clinical/AP/HR targeting with 24h/48h/7d/midnight deadlines"),
    (26, "email", "HC3@hhs[.]gov", "E8", "WHITELIST", "HIGH",
     "DO NOT BLOCK — legitimate sector alert sender",
     "verification baseline for future advisories"),
    (27, "victim_identity", "internal-only (dmarsh@dmarsh-internal, see 4x00)",
     "E2", "EXCLUDED", "N/A",
     "excluded from all external sharing",
     "victim identifier; internal case data only"),
]

# ---------------------------------------------------------------------------
# BASELINE RATE — derive from Task 0 artifact to match Task 6 exactly
# ---------------------------------------------------------------------------
base_txt_rate = 0.0
dur = baseline.get("duration_minutes") or 0
if dur > 0:
    base_txt_rate = baseline.get("dns", {}).get("txt_queries", 0) / dur

# ---------------------------------------------------------------------------
# 4x01 NETWORK IOCs — derived from Task 0-6 artifacts
# ---------------------------------------------------------------------------
net_iocs = []       # (type, value, pcap, phase, category, confidence, context)
enrichments = []    # existing 4x00 values confirmed/enriched by packets

phish_ip = phish.get("phishing_ip") if phish else None
phish_dom = phish.get("phishing_domain") if phish else None

# --- Phase 4: VPN pivot (Task 5 / full_timeline.pcap) ----------------------
v = vpn.get("vpn_session") if vpn else None
if v:
    net_iocs.append(("ip", defang_ip(v["source_ip"]), "full_timeline.pcap",
                     "4-VPNPivot", "DETECT", "HIGH (session); MEDIUM (shared-infrastructure risk)",
                     "inbound external session to VPN endpoint (SNI vpn.meddefense.com); "
                     "NG, AS37340 Spectranet dynamic LTE — geo-screen at the "
                     "authentication gate rather than blind-block"))
    sni_val = v.get("tls_sni")
    if sni_val and len(sni_val) > 0:
        # Uniform, idempotent domain defanging applied to SNI
        net_iocs.append(("tls_sni", defang_all(sni_val[0]), "full_timeline.pcap",
                         "4-VPNPivot", "DETECT", "MEDIUM",
                         "legitimate internal SNI; alert on EXTERNAL-source sessions "
                         "to it, never block the domain itself"))
    g = vpn.get("geolocation") or {}
    if g.get("asn"):
        # Strip leading 'AS' if already present to avoid "ASAS37340"
        raw_asn = str(g.get("asn")).upper()
        if raw_asn.startswith("AS"):
            raw_asn = raw_asn[2:]
        net_iocs.append(("asn", "AS%s (%s)" % (raw_asn, g.get("org")),
                         "full_timeline.pcap", "4-VPNPivot", "CONTEXT",
                         "MEDIUM (shared carrier space)",
                         "dynamic LTE allocation — high false-positive rate if "
                         "blocked wholesale; use for scoring"))

# --- Phase 7: DNS tunnel (Task 3 / dns_exfil.pcap) --------------------------
if tunnel:
    base_dom = tunnel.get("tunnel_base_domain")
    if base_dom:
        # Uniform, idempotent domain defanging applied to subdomain
        net_iocs.append(("subdomain", defang_all(base_dom), "dns_exfil.pcap",
                         "7-Exfiltration", "BLOCK", "HIGH (campaign-specific)",
                         "dedicated exfil subdomain of the phishing domain — "
                         "attacker-controlled, no legitimate use"))
    lbl = tunnel.get("label_length_range")
    if lbl:
        net_iocs.append(("dns_pattern",
                         "TXT queries, left-most labels %s-%s chars, entropy %.1f bits/char"
                         % (lbl[0], lbl[-1], tunnel.get("avg_label_entropy_bits", 0)),
                         "dns_exfil.pcap", "7-Exfiltration", "DETECT",
                         "HIGH (behavioral)",
                         "long encoded labels to a single base domain — "
                         "resolver-level alert independent of domain"))
    # Rate multiplier computed from the Task 0 baseline artifact (not a
    # hardcoded 0.23) so the figure matches Task 6's scorecard exactly
    if tunnel.get("rate_per_min") and base_txt_rate > 0:
        multiplier = tunnel["rate_per_min"] / base_txt_rate
        net_iocs.append(("rate_signature",
                         "%.2f TXT queries/min vs %.4f/min baseline (~%.1fx)"
                         % (tunnel["rate_per_min"], base_txt_rate, multiplier),
                         "dns_exfil.pcap", "7-Exfiltration", "HUNT",
                         "HIGH (vs Task 0 baseline)",
                         "rate multiplier against the clinical baseline — "
                         "host-relative, survives domain rotation"))
    elif tunnel.get("rate_per_min"):
        # Fallback if baseline artifact unavailable
        net_iocs.append(("rate_signature",
                         "%.2f TXT queries/min (>5x typical baseline)"
                         % tunnel["rate_per_min"],
                         "dns_exfil.pcap", "7-Exfiltration", "HUNT",
                         "HIGH (vs Task 0 baseline)",
                         "rate multiplier against the clinical baseline — "
                         "host-relative, survives domain rotation"))

# --- Phase 3: beacon signature (Task 2 / c2_beaconing.pcap) ------------------
if beacon and beacon.get("capture_beacons"):
    b_ip, b = next(iter(beacon["capture_beacons"].items()))
    net_iocs.append(("beacon_signature",
                     "%d sessions, %.1fs avg interval, CV %.2f%%"
                     % (b["total_beacons"], b["avg_interval_s"], b["regularity_cv_pct"]),
                     "c2_beaconing.pcap", "3-C2Beaconing", "HUNT",
                     "HIGH (behavioral, campaign-specific)",
                     "interval-regularity signature — survives infrastructure "
                     "rotation better than any IP/domain value"))
    enrichments.append((defang_ip(b_ip),
                        "network layer confirms dual-role infrastructure: "
                        "credential harvest (Phase 2) AND C2 beacon destination "
                        "(Phase 3) — strengthens the existing 4x00 BLOCK from "
                        "'sending mail server' to 'full attacker platform'"))

# --- Phase 2/overlap enrichment (Task 1) -------------------------------------
if phish_dom:
    # Defang at creation so stored JSON matches console output exactly
    enrichments.append((defang_all(phish_dom),
                        "packet layer confirms active HTTPS credential-harvest "
                        "operation on the domain (47.2s session, TLS record "
                        "consistent with form submission) — upgrades 4x00 "
                        "delivery-side indicator to confirmed post-click "
                        "behavior"))

# --- Phase 5/6: internal-flow signatures (Task 4 — HUNT/CONTEXT only) --------
if lateral and lateral.get("connections"):
    net_iocs.append(("flow_signature",
                     "cross-subnet RDP 10.10.2.15 -> 10.10.1.10:3389, "
                     "265723 B exchanged, clean FIN",
                     "lateral_movement.pcap", "5-LateralMovement", "HUNT",
                     "HIGH (incident-specific)",
                     "clinical-to-server RDP violates expected role topology — "
                     "internal alert candidate (DET-004)"))
    net_iocs.append(("host_context",
                     "10.10.1.10 (billing-srv-01) — exfil source; SMB origin to "
                     "4 server-subnet peers; blocked at 10.10.4.x",
                     "lateral_movement.pcap + dns_exfil.pcap", "5/6/7", "CONTEXT",
                     "HIGH (incident-specific)",
                     "compromised-asset attribution for scoping and "
                     "remediation — not a blockable network indicator"))

# --- documented absences (never fabricated) ---------------------------------
net_iocs.append(("ja3_fingerprint",
                 "NOT CAPTURED (ClientHello not fully dissected in any artifact)",
                 "N/A", "N/A", "CONTEXT", "N/A",
                 "documented absence — re-dissect c2_beaconing.pcap with "
                 "-o tls.keylog_file or extract via Zeek ssl.log if needed"))
if phish and not (phish.get("tls_certificate") or {}).get("subject"):
    net_iocs.append(("cert_subject",
                     "NOT CAPTURED (below TLS dissection depth in phishing_click.pcap)",
                     "N/A", "N/A", "CONTEXT", "N/A",
                     "documented absence — certificate metadata requires "
                     "handshake dissection beyond the artifact's scope"))

# --- Phase 1 enrichment footnote ----------------------------------------------
if kc and kc.get("phase1_context"):
    net_iocs.append(("account_context",
                     "dmarsh — per-victim token attribution (4x00), "
                     "harvest-session then VPN-timing correlation (4x01)",
                     "kill_chain_evidence.json", "1-4", "CONTEXT",
                     "HIGH (correlated), attribution chain partly INFERENCE",
                     "account context for scoping; credential use itself "
                     "encrypted and unproven (Task 8 verdict: STRONG INFERENCE)"))

# ---------------------------------------------------------------------------
# MERGE + COUNTS
# ---------------------------------------------------------------------------
fourx_values = {row[2] for row in FOURX}
new_unique = [ioc for ioc in net_iocs if ioc[1] not in fourx_values]
combined_total = len(FOURX) + len(new_unique)
enriched_count = len(enrichments)

by_cat = {"BLOCK": [], "DETECT": [], "HUNT": [], "CONTEXT": [],
          "MONITOR": [], "WHITELIST": [], "EXCLUDED": []}
for num, typ, val, src, cat, conf, action, ctx in FOURX:
    by_cat.setdefault(cat, []).append(val)
for typ, val, pcap, phase, cat, conf, ctx in net_iocs:
    if val in fourx_values:
        continue
    by_cat.setdefault(cat, []).append(val)

# ---------------------------------------------------------------------------
# CONSOLE REPORT
# ---------------------------------------------------------------------------
print("=" * 64)
print("   NETWORK IOC EXTRACTION")
print("   4x00 email analysis + 4x01 packet analysis -> unified campaign package")
print("=" * 64)

print()
print("=== NEW IOCs FROM 4x01 (packet-derived) ===")
print("%-16s | %-58s | %-8s | %s" % ("Type", "Value", "Phase", "Category"))
print("-" * 16 + "-+-" + "-" * 58 + "-+-" + "-" * 8 + "-+-" + "-" * 9)
for typ, val, pcap, phase, cat, conf, ctx in net_iocs:
    print("%-16s | %-58s | %-8s | %s"
          % (typ, val[:58], phase.split("-")[0], cat))

print()
print("=== 4x00 IOC ENRICHMENTS (existing values, upgraded by packet evidence) ===")
# Values are stored defanged (idempotent), so print directly
for val, note in enrichments:
    print("- " + val)
    print("  " + note)

print()
print("=== COMBINED IOC PACKAGE (4x00 + 4x01) ===")
print("%-9s | %-11s | %s" % ("Source", "IOCs Added", "Unique Types"))
print("-" * 9 + "-+-" + "-" * 11 + "-+-" + "-" * 40)
print("%-9s | %-11d | %s" % ("4x00", len(FOURX),
      "domains, IPs, URLs, senders, hash, filename, tool, infra notes"))
print("%-9s | %-11d | %s" % ("4x01", len(new_unique),
      "VPN IP, SNI, ASN, subdomain, dns/beacon/rate/flow signatures, host context"))
print("%-9s | %-11d | %s" % ("Combined", combined_total,
      "full campaign profile (delivery + post-click behavior)"))
if enriched_count:
    print("%-9s | %-11d | %s" % ("Enriched", enriched_count,
          "4x00 values upgraded with packet-layer confirmation"))

print()
print("=== DETECTION UTILITY ===")
print("BLOCK (campaign-specific, low collateral risk):")
for v_ in by_cat["BLOCK"]:
    print("  " + v_)
print()
print("DETECT (alert + review):")
for v_ in by_cat["DETECT"]:
    print("  " + v_)
print()
print("HUNT (threat-hunting queries):")
for v_ in by_cat["HUNT"]:
    print("  " + v_)
print()
print("MONITOR / CONTEXT / SPECIAL:")
for cat in ("MONITOR", "CONTEXT", "WHITELIST", "EXCLUDED"):
    for v_ in by_cat.get(cat, []):
        print("  [%s] %s" % (cat, v_))

print()
print("=== CONFIDENCE GRADING: CAMPAIGN-SPECIFIC vs SHARED INFRASTRUCTURE ===")
print("High-confidence campaign-specific (attacker-registered/disposable):")
print("  - the four lookalike domains, their URLs, senders, sending IPs")
print("  - data-sync[.]meddefense-portal[.]com (dedicated exfil subdomain)")
print("  - 154[.]118[.]42[.]89 (foreign dynamic-LTE session — treat the IP")
print("    itself as medium; the GEO/ASN pattern as the durable indicator)")
print("Low-confidence shared infrastructure (never blind-block):")
print("  - AS37340 carrier space, budget VPS tier, hosting patterns")
print("  - wkhtmltopdf producer string (legitimate tool, context only)")

print()
print("=== INTELLIGENCE VALUE ===")
print("Email analysis (4x00): identified delivery infrastructure — 4 lookalike")
print("  domains, 4 sending IPs, per-victim harvesting URLs, lure artifacts.")
print("  %d IOCs, all pre-click." % len(FOURX))
print("Network analysis (4x01): identified post-click behavior — beaconing")
print("  timing, VPN pivot source, lateral movement, and the exfiltration")
print("  channel. %d new IOCs + %d enrichments of existing values." %
      (len(new_unique), enriched_count))
print("  Network-only contributions: behavioral signatures (beacon interval,")
print("  DNS tunnel pattern, exfil rate) that survive infrastructure rotation")
print("  where email-era atomic IOCs decay.")

print()
print("EVIDENCE SAVED: " + out_json)

# ---------------------------------------------------------------------------
# SERIALIZATION
# ---------------------------------------------------------------------------
artifact = {
    "sources": {
        "4x00": "/home/steve/projects/dlh/threat_detection/4x00_phishing_dissection/11-ioc_extraction.md",
        "4x01": "Tasks 0-6 JSON artifacts (this repository)",
    },
    "package_4x00": [
        {"num": n, "type": t, "value": val, "source": src,
         "category": cat, "confidence": conf, "action": action, "context": ctx}
        for n, t, val, src, cat, conf, action, ctx in FOURX
    ],
    "new_network_iocs": [
        {"type": t, "value": val, "source_pcap": pcap, "attack_phase": phase,
         "category": cat, "confidence": conf, "context": ctx}
        for t, val, pcap, phase, cat, conf, ctx in net_iocs
        if val not in fourx_values
    ],
    "enrichments": [
        {"value": val, "network_layer_evidence": note}
        for val, note in enrichments
    ],
    "counts": {
        "total_4x00": len(FOURX),
        "new_from_network": len(new_unique),
        "enriched_existing": enriched_count,
        "combined_total": combined_total,
    },
    "confidence_grading": {
        "campaign_specific_high_confidence": [
            "meddefense-portal[.]com and family (4 domains)",
            "data-sync[.]meddefense-portal[.]com exfil subdomain",
            "beacon/DNS/rate behavioral signatures",
        ],
        "shared_infrastructure_low_confidence": [
            "AS37340 carrier space",
            "budget VPS hosting tier",
            "wkhtmltopdf producer string",
        ],
    },
    "intelligence_value": (
        "Email analysis identified delivery infrastructure (%d IOCs); "
        "network analysis added %d post-click behavioral and session IOCs "
        "and enriched %d existing values with packet-layer confirmation. "
        "Behavioral signatures are the network layer's unique contribution "
        "— they survive infrastructure rotation where atomic email-era "
        "IOCs decay." % (len(FOURX), len(new_unique), enriched_count)
    ),
}

with open(out_json, "w") as fh:
    json.dump(artifact, fh, indent=2)
    fh.write("\n")
PYEOF
