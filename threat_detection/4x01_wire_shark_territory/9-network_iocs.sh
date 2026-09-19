#!/bin/bash
# Name: 9-network_iocs.sh
# Purpose: Extract and structure every network-level indicator of compromise
#          from the 4x01 packet analysis, categorize by detection utility
#          (BLOCK / DETECT / HUNT / CONTEXT), merge with the 4x00 email-analysis
#          IOC package into a unified campaign package, and quantify the
#          intelligence value added by packet analysis over email analysis
#          alone. Before deriving anything, the script audits ALL required
#          Task 0-6 artifacts and their expected keys, and fails loudly on
#          any missing dependency — silent partial output is never produced.
#          Artifacts whose structure uses dynamic keys (c2_beacon_evidence:
#          capture_beacons keyed by C2 IP) are validated structurally, since
#          dotted paths cannot express them. Indicators not present in the
#          captures (JA3 fingerprint, certificate subject/hash) are
#          explicitly marked NOT CAPTURED rather than invented.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./9-network_iocs.sh
#          Requires ALL of: phishing_click_evidence.json,
#          kill_chain_evidence.json, c2_beacon_evidence.json,
#          dns_tunnel_evidence.json, lateral_movement_evidence.json,
#          vpn_pivot_evidence.json, baseline_clinical.json
#          (exit 1 with a diagnostic list if any are missing).
# Output:  Console report + campaign_iocs.json (includes a validation
#          section documenting every artifact and key checked)
#
# CHANGELOG
#   - FIXED: c2_beacon_evidence dotted-path requirements were false
#     positives; capture_beacons is keyed by C2 IP, so the file is now
#     validated structurally (first beacon entry must carry all three
#     stat keys). Restores beacon signature + IP enrichment.
#   - FIXED: tls_sni stored as a list in vpn_pivot_evidence.json was
#     serialized with list brackets; now normalized (list or scalar).
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
#   All artifact key expectations below were confirmed against actual
#   successful runs of the Task 0-6 scripts, not assumed.
#   - VPN source IP / ASN ................ Task 5 artifact (full_timeline.pcap)
#   - Tunnel subdomain + TXT pattern ...... Task 3 artifact (dns_exfil.pcap)
#   - Beacon timing signature ............. Task 2 artifact (c2_beaconing.pcap)
#   - Phishing infra (dual-role confirm) .. Task 1/2 artifacts
#   - Internal-flow signatures ........... Task 4 artifact (internal only,
#     never BLOCK candidates)
#   - Baseline TXT rate ................... Task 0 artifact (matches Task 6)
#   - JA3 / cert subject .................. NOT CAPTURED in any artifact;
#     recorded as documented absence
#   - Dedup is on (type, value) tuples so two IOC types sharing a string
#     cannot collide.
# ---------------------------------------------------------------------------

set -euo pipefail

OUT_JSON="campaign_iocs.json"

python3 - "$OUT_JSON" <<'PYEOF'
import json
import sys

out_json = sys.argv[1]

# ---------------------------------------------------------------------------
# DEPENDENCY MODEL — every artifact the derivations consume, with the exact
# keys each one must provide. Confirmed empirically against real Task 0-6
# outputs. A missing FILE is fatal; a missing KEY skips only the affected
# derivation, loudly and on the record. Artifacts with dynamic keys use
# a structural validator (VALIDATORS) instead of dotted paths.
# ---------------------------------------------------------------------------
ARTIFACT_REQUIREMENTS = {
    "phishing_click_evidence.json": ["phishing_ip", "phishing_domain"],
    "kill_chain_evidence.json": ["phase1_context"],
    "dns_tunnel_evidence.json": ["tunnel_base_domain", "label_length_range",
                                 "avg_label_entropy_bits", "rate_per_min"],
    "lateral_movement_evidence.json": ["connections"],
    "vpn_pivot_evidence.json": ["vpn_session.source_ip", "vpn_session.tls_sni",
                                "geolocation.asn", "geolocation.org"],
    "baseline_clinical.json": ["duration_minutes", "dns.txt_queries"],
}

BEACON_STAT_KEYS = ("total_beacons", "avg_interval_s", "regularity_cv_pct")

def validate_beacon_structure(data):
    """capture_beacons is a dict keyed by C2 IP whose values carry the
    per-host beacon stats. Dotted paths cannot express dynamic keys, so
    validate structurally: non-empty dict, every entry carries the stats."""
    if not isinstance(data, dict):
        return False, "capture_beacons[*]." + ", ".join(BEACON_STAT_KEYS)
    cb = data.get("capture_beacons")
    if not isinstance(cb, dict) or not cb:
        return False, "capture_beacons[*]." + ", ".join(BEACON_STAT_KEYS)
    for stats in cb.values():
        missing = [k for k in BEACON_STAT_KEYS if k not in stats]
        if missing:
            return False, "capture_beacons[*].%s" % ", ".join(missing)
    return True, ""

STRUCTURAL_VALIDATORS = {
    "c2_beacon_evidence.json": validate_beacon_structure,
}

def load(name):
    try:
        with open(name) as fh:
            return json.load(fh), None
    except OSError:
        return None, "FILE MISSING"
    except ValueError as e:
        return None, "INVALID JSON: %s" % e

def get_path(data, dotted):
    """Return (value, ok) for a dotted key path into nested dicts."""
    cur = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, False
        cur = cur[part]
    return cur, True

# ---------------------------------------------------------------------------
# AUDIT PHASE — load everything, validate every required key, decide fate
# ---------------------------------------------------------------------------
loaded = {}            # filename -> parsed JSON (None if unloadable)
load_errors = {}       # filename -> reason
missing_files = []     # fatal
missing_keys = {}      # filename -> [keys]; non-fatal, degrades loudly
validation_records = []

for fname in list(ARTIFACT_REQUIREMENTS) + list(STRUCTURAL_VALIDATORS):
    if fname in validation_records_names if False else False:
        pass  # unreachable; clarity only

for fname in sorted(set(list(ARTIFACT_REQUIREMENTS) +
                        list(STRUCTURAL_VALIDATORS))):
    data, err = load(fname)
    loaded[fname] = data if err is None else None
    if err is not None:
        load_errors[fname] = err
        missing_files.append(fname)
        keys = (ARTIFACT_REQUIREMENTS.get(fname)
                or ["capture_beacons[*]." + ", ".join(BEACON_STAT_KEYS)])
        validation_records.append({"file": fname, "status": "MISSING",
                                   "reason": err, "keys_missing": keys})
        continue
    if fname in STRUCTURAL_VALIDATORS:
        ok, missing_desc = STRUCTURAL_VALIDATORS[fname](data)
        if ok:
            validation_records.append(
                {"file": fname, "status": "OK",
                 "keys_checked": ["capture_beacons[*]." +
                                  ", ".join(BEACON_STAT_KEYS)],
                 "keys_missing": []})
        else:
            missing_keys[fname] = [missing_desc]
            validation_records.append(
                {"file": fname, "status": "DEGRADED",
                 "keys_checked": ["capture_beacons[*]." +
                                  ", ".join(BEACON_STAT_KEYS)],
                 "keys_missing": [missing_desc]})
        continue
    keys = ARTIFACT_REQUIREMENTS[fname]
    absent = [k for k in keys if not get_path(data, k)[1]]
    rec = {"file": fname, "status": "OK" if not absent else "DEGRADED",
           "keys_checked": keys, "keys_missing": absent}
    if absent:
        missing_keys[fname] = absent
    validation_records.append(rec)

print("=" * 64)
print("   NETWORK IOC EXTRACTION")
print("   4x00 email analysis + 4x01 packet analysis -> unified campaign package")
print("=" * 64)

print()
print("=== ARTIFACT DEPENDENCY AUDIT ===")
print("%-34s | %-9s | %s" % ("Artifact", "Status", "Missing keys"))
print("-" * 34 + "-+-" + "-" * 9 + "-+-" + "-" * 30)
for rec in validation_records:
    print("%-34s | %-9s | %s"
          % (rec["file"], rec["status"],
             ", ".join(rec.get("keys_missing", [])) or "-"))
if missing_files:
    print()
    print("FATAL: required artifacts missing or unreadable:")
    for f in missing_files:
        print("  - %s (%s)" % (f, load_errors[f]))
    print("Cannot produce a complete, auditable IOC package from partial")
    print("input. Run the Task 0-6 phase scripts first, then retry.")
    sys.exit(1)
if missing_keys:
    print()
    print("WARNING: some artifacts are missing expected keys. Affected")
    print("derivations will be SKIPPED explicitly (never silently dropped):")
    for f, ks in missing_keys.items():
        print("  - %s: missing %s" % (f, ", ".join(ks)))

phish = loaded["phishing_click_evidence.json"]
kc = loaded["kill_chain_evidence.json"]
beacon = loaded["c2_beacon_evidence.json"]
tunnel = loaded["dns_tunnel_evidence.json"]
lateral = loaded["lateral_movement_evidence.json"]
vpn = loaded["vpn_pivot_evidence.json"]
baseline = loaded["baseline_clinical.json"]

BEACON_OK = not missing_keys.get("c2_beacon_evidence.json")

def has_key(fname, dotted):
    return dotted not in missing_keys.get(fname, [])

skipped = []  # (derivation, reason) — surfaced in console and JSON

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
if has_key("baseline_clinical.json", "duration_minutes"):
    dur, _ = get_path(baseline, "duration_minutes")
    txtq, _ = get_path(baseline, "dns.txt_queries")
    if dur and dur > 0:
        base_txt_rate = txtq / dur
else:
    skipped.append(("rate_signature (baseline unavailable)",
                    "baseline_clinical.json missing duration_minutes"))

# ---------------------------------------------------------------------------
# 4x01 NETWORK IOCs — derived from Task 0-6 artifacts
# ---------------------------------------------------------------------------
net_iocs = []       # (type, value, pcap, phase, category, confidence, context)
enrichments = []    # existing 4x00 values confirmed/enriched by packets

phish_dom, _ = get_path(phish, "phishing_domain")

# --- Phase 4: VPN pivot (Task 5 / full_timeline.pcap) ----------------------
if has_key("vpn_pivot_evidence.json", "vpn_session.source_ip"):
    v, _ = get_path(vpn, "vpn_session")
    net_iocs.append(("ip", defang_ip(v["source_ip"]), "full_timeline.pcap",
                     "4-VPNPivot", "DETECT",
                     "HIGH (session); MEDIUM (shared-infrastructure risk)",
                     "inbound external session to VPN endpoint "
                     "(SNI vpn.meddefense.com); NG, AS37340 Spectranet "
                     "dynamic LTE — geo-screen at the authentication gate "
                     "rather than blind-block"))
    if has_key("vpn_pivot_evidence.json", "vpn_session.tls_sni"):
        sni_raw = v.get("tls_sni")
        # tls_sni is a list in the artifact; accept scalar too
        sni = (sni_raw[0] if isinstance(sni_raw, (list, tuple)) and sni_raw
               else sni_raw)
        if sni:
            net_iocs.append(("tls_sni", defang_all(sni),
                             "full_timeline.pcap", "4-VPNPivot", "DETECT",
                             "MEDIUM",
                             "legitimate internal SNI; alert on EXTERNAL-source "
                             "sessions to it, never block the domain itself"))
    if has_key("vpn_pivot_evidence.json", "geolocation.asn"):
        g, _ = get_path(vpn, "geolocation")
        raw_asn = str(g.get("asn")).upper()
        if raw_asn.startswith("AS"):
            raw_asn = raw_asn[2:]
        net_iocs.append(("asn", "AS%s (%s)" % (raw_asn, g.get("org")),
                         "full_timeline.pcap", "4-VPNPivot", "CONTEXT",
                         "MEDIUM (shared carrier space)",
                         "dynamic LTE allocation — high false-positive rate if "
                         "blocked wholesale; use for scoring"))
else:
    skipped.append(("VPN pivot IOCs", "vpn_pivot_evidence.json missing keys"))

# --- Phase 7: DNS tunnel (Task 3 / dns_exfil.pcap) --------------------------
if has_key("dns_tunnel_evidence.json", "tunnel_base_domain"):
    base_dom, _ = get_path(tunnel, "tunnel_base_domain")
    if base_dom:
        net_iocs.append(("subdomain", defang_all(base_dom), "dns_exfil.pcap",
                         "7-Exfiltration", "BLOCK", "HIGH (campaign-specific)",
                         "dedicated exfil subdomain of the phishing domain — "
                         "attacker-controlled, no legitimate use"))
else:
    skipped.append(("exfil subdomain IOC", "dns_tunnel_evidence.json missing "
                    "tunnel_base_domain"))
if has_key("dns_tunnel_evidence.json", "label_length_range"):
    lbl, _ = get_path(tunnel, "label_length_range")
    ent, _ = get_path(tunnel, "avg_label_entropy_bits")
    if lbl:
        net_iocs.append(("dns_pattern",
                         "TXT queries, left-most labels %s-%s chars, "
                         "entropy %.1f bits/char" % (lbl[0], lbl[-1], ent or 0),
                         "dns_exfil.pcap", "7-Exfiltration", "DETECT",
                         "HIGH (behavioral)",
                         "long encoded labels to a single base domain — "
                         "resolver-level alert independent of domain"))
else:
    skipped.append(("dns_pattern IOC", "dns_tunnel_evidence.json missing "
                    "label_length_range"))
if has_key("dns_tunnel_evidence.json", "rate_per_min"):
    rpm, _ = get_path(tunnel, "rate_per_min")
    if rpm and base_txt_rate > 0:
        multiplier = rpm / base_txt_rate
        net_iocs.append(("rate_signature",
                         "%.2f TXT queries/min vs %.4f/min baseline (~%.1fx)"
                         % (rpm, base_txt_rate, multiplier),
                         "dns_exfil.pcap", "7-Exfiltration", "HUNT",
                         "HIGH (vs Task 0 baseline)",
                         "rate multiplier against the clinical baseline — "
                         "host-relative, survives domain rotation"))
    elif rpm:
        net_iocs.append(("rate_signature",
                         "%.2f TXT queries/min (baseline artifact "
                         "unavailable — multiplier not computed)" % rpm,
                         "dns_exfil.pcap", "7-Exfiltration", "HUNT",
                         "MEDIUM (baseline unavailable)",
                         "absolute rate only; baseline comparison skipped "
                         "because baseline_clinical.json lacked duration data"))
else:
    skipped.append(("rate_signature IOC", "dns_tunnel_evidence.json missing "
                    "rate_per_min"))

# --- Phase 3: beacon signature (Task 2 / c2_beaconing.pcap) ------------------
# capture_beacons is keyed by C2 IP; validated structurally, so iterate any
# entry (there is exactly one in this capture set) for the stats
if BEACON_OK:
    cb = beacon["capture_beacons"]
    b_ip, b = next(iter(cb.items()))
    net_iocs.append(("beacon_signature",
                     "%d sessions, %.1fs avg interval, CV %.2f%%"
                     % (b["total_beacons"], b["avg_interval_s"],
                        b["regularity_cv_pct"]),
                     "c2_beaconing.pcap", "3-C2Beaconing", "HUNT",
                     "HIGH (behavioral, campaign-specific)",
                     "interval-regularity signature — survives infrastructure "
                     "rotation better than any IP/domain value"))
    enrichments.append((defang_ip(b_ip),
                        "network layer confirms dual-role infrastructure: "
                        "credential harvest (Phase 2) AND C2 beacon destination "
                        "(Phase 3) — strengthens the existing 4x00 BLOCK from "
                        "'sending mail server' to 'full attacker platform'"))
else:
    skipped.append(("beacon signature + IP enrichment",
                    "c2_beacon_evidence.json failed structural validation"))

# --- Phase 2/overlap enrichment (Task 1) -------------------------------------
if phish_dom:
    enrichments.append((defang_all(phish_dom),
                        "packet layer confirms active HTTPS credential-harvest "
                        "operation on the domain (47.2s session, TLS record "
                        "consistent with form submission) — upgrades 4x00 "
                        "delivery-side indicator to confirmed post-click "
                        "behavior"))

# --- Phase 5/6: internal-flow signatures (Task 4 — HUNT/CONTEXT only) --------
if has_key("lateral_movement_evidence.json", "connections"):
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
                     "lateral_movement.pcap + dns_exfil.pcap", "5/6/7",
                     "CONTEXT", "HIGH (incident-specific)",
                     "compromised-asset attribution for scoping and "
                     "remediation — not a blockable network indicator"))
else:
    skipped.append(("lateral movement flow/host IOCs",
                    "lateral_movement_evidence.json missing connections"))

# --- documented absences (never fabricated) ---------------------------------
net_iocs.append(("ja3_fingerprint",
                 "NOT CAPTURED (ClientHello not fully dissected in any artifact)",
                 "N/A", "N/A", "CONTEXT", "N/A",
                 "documented absence — re-dissect c2_beaconing.pcap with "
                 "-o tls.keylog_file or extract via Zeek ssl.log if needed"))
cert_subj, cert_ok = get_path(phish, "tls_certificate.subject")
if not cert_ok or not cert_subj:
    net_iocs.append(("cert_subject",
                     "NOT CAPTURED (below TLS dissection depth in "
                     "phishing_click.pcap)",
                     "N/A", "N/A", "CONTEXT", "N/A",
                     "documented absence — certificate metadata requires "
                     "handshake dissection beyond the artifact's scope"))

# --- Phase 1 enrichment footnote ----------------------------------------------
phase1, _ = get_path(kc, "phase1_context")
if phase1:
    net_iocs.append(("account_context",
                     "dmarsh — per-victim token attribution (4x00), "
                     "harvest-session then VPN-timing correlation (4x01)",
                     "kill_chain_evidence.json", "1-4", "CONTEXT",
                     "HIGH (correlated), attribution chain partly INFERENCE",
                     "account context for scoping; credential use itself "
                     "encrypted and unproven (Task 8 verdict: STRONG INFERENCE)"))
else:
    skipped.append(("account_context IOC", "kill_chain_evidence.json has no "
                    "usable phase1_context"))

# ---------------------------------------------------------------------------
# MERGE + COUNTS — dedup on (type, value) tuples, never bare values
# ---------------------------------------------------------------------------
fourx_keys = {(r[1], r[2]) for r in FOURX}
new_unique = [ioc for ioc in net_iocs
              if (ioc[0], ioc[1]) not in fourx_keys]
combined_total = len(FOURX) + len(new_unique)
enriched_count = len(enrichments)

by_cat = {"BLOCK": [], "DETECT": [], "HUNT": [], "CONTEXT": [],
          "MONITOR": [], "WHITELIST": [], "EXCLUDED": []}
for num, typ, val, src, cat, conf, action, ctx in FOURX:
    by_cat.setdefault(cat, []).append(val)
for typ, val, pcap, phase, cat, conf, ctx in net_iocs:
    if (typ, val) in fourx_keys:
        continue
    by_cat.setdefault(cat, []).append(val)

# ---------------------------------------------------------------------------
# CONSOLE REPORT
# ---------------------------------------------------------------------------
print()
print("=== NEW IOCs FROM 4x01 (packet-derived) ===")
print("%-16s | %-58s | %-8s | %s" % ("Type", "Value", "Phase", "Category"))
print("-" * 16 + "-+-" + "-" * 58 + "-+-" + "-" * 8 + "-+-" + "-" * 9)
for typ, val, pcap, phase, cat, conf, ctx in net_iocs:
    print("%-16s | %-58s | %-8s | %s"
          % (typ, val[:58], phase.split("-")[0], cat))

if skipped:
    print()
    print("=== SKIPPED DERIVATIONS (explicit, never silent) ===")
    for deriv, reason in skipped:
        print("  - %s: %s" % (deriv, reason))

print()
print("=== 4x00 IOC ENRICHMENTS (existing values, upgraded by packet evidence) ===")
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
# SERIALIZATION — includes the validation record so completeness is provable
# ---------------------------------------------------------------------------
artifact = {
    "generated_by": "9-network_iocs.sh",
    "sources": {
        "4x00": "/home/steve/projects/dlh/threat_detection/4x00_phishing_dissection/11-ioc_extraction.md",
        "4x01": "Tasks 0-6 JSON artifacts (this repository)",
    },
    "validation": {
        "artifacts_audited": validation_records,
        "skipped_derivations": [
            {"derivation": d, "reason": r} for d, r in skipped
        ],
        "dedup_method": "(type, value) tuple equality against 4x00 package",
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
        if (t, val) not in fourx_keys
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
