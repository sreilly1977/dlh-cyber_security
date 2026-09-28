#!/bin/bash
# Name: 5-indicator_database.sh
# Purpose: Build indicator_database.json from validated HEALTHBANE indicators
#          (Tasks 0-4 outputs), with per-indicator provenance, confidence,
#          cluster, attack phase and recommended action. Prints summary
#          statistics and validates the JSON before exit.
# Author: Steve - Cybersecurity Engineer
# Date: 28 September 2026
# Source: Project 4x02 - Intelligence-Driven Defense

set -euo pipefail

OUTPUT_FILE="indicator_database.json"

# ============================================================================
# INDICATOR SET (48 unique from Task 1 triage, minus 15 NOISE indicators)
# NOISE (CDN/shared IPs, ML-cluster-only hashes/domains) is excluded per the
# Task 1 triage decision and is not represented in this database.
#
# Field order (pipe-delimited):
#   type|value|first_seen|last_seen|sources|confidence|category|cluster|
#   attack_phase|recommended_action|enrichment_summary
# ============================================================================
INDICATORS=(
    # --- Domains: confirmed Stage 1 phishing LPs ---
    "domain|meddefense-portal.com|2026-04-14|2026-04-26|HC3,Commercial,Researcher,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|Namecheap reg 2026-04-09; Hostinger 91.234.99.107; PHPMailer 6.6.0; clicked by dmarsh in 4x00"
    "domain|medequip-supplies.net|2026-04-14|2026-04-26|HC3,Commercial,Researcher,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|Namecheap reg 2026-04-08; Hostinger 185.176.43.22; PHPMailer 6.6.0; observed in 4x00 E5"
    "domain|meddefense-benefits.org|2026-04-15|2026-04-26|HC3,Commercial,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|Namecheap reg 2026-04-10; DigitalOcean 164.90.218.73; PHPMailer-6.6.0 custom build in 4x00 E7"
    "domain|outlook-protection.com|2026-04-14|2026-04-26|HC3,Commercial,Researcher|HIGH|ACTIONABLE|ms-impersonation|Stage 1|BLOCK|OVH 51.38.42.17; passes SPF/DKIM/DMARC via correct DNS; kit SMTP exfil route per researcher config.php"
    # --- Domains: Stage 2/3 operator C2 ---
    "domain|healthbane-c2.net|2026-04-16|2026-04-26|HC3,Commercial,Researcher|HIGH|ACTIONABLE|operator-c2|Stage 2|BLOCK|Njalla registrar; OVH 51.38.42.191; referenced in kit config.php EXFIL_ENDPOINT and OPS_CONTACT"
    "domain|data-sync.healthbane-c2.net|2026-04-23|2026-04-26|HC3|HIGH|ACTIONABLE|operator-c2|Stage 3|BLOCK|DNS TXT exfil endpoint; base32 subdomain labels 44-60 chars at 10-15s intervals per HC3 packet captures"
    # --- Domains: medium-confidence campaign additions ---
    "domain|update-healthbane.net|2026-04-16|2026-04-24|HC3,Commercial|MEDIUM|ACTIONABLE|secondary-c2|Stage 2|MONITOR|Stage 2 secondary C2 per HC3 MEDIUM; no researcher corroboration; no resolution data in sources"
    "domain|portal-secure-meddefense.com|unknown|unknown|HC3,Researcher|MEDIUM|ACTIONABLE|rotation-staged|Stage 1|MONITOR|Staged kit confirmed by researcher (92.118.232.14 Hostinger); not yet live; expected rotation-in domain"
    # --- Domains: contextual / prior campaign ---
    "domain|rx-benefits-portal.com|2026-03-28|2026-04-10|Commercial|LOW|CONTEXTUAL|prior-campaign|Unknown|MONITOR|Predates HEALTHBANE window by 16 days; same Namecheap+OVH pattern; possible earlier same-operator activity"
    "domain|healthcare-login.com|2026-03-30|2026-04-12|Commercial|LOW|CONTEXTUAL|prior-campaign|Unknown|MONITOR|Sinkholed 2026-04-18; historical correlation only"
    "domain|verify-health-portal.net|2026-04-05|2026-04-24|Commercial|LOW|CONTEXTUAL|naming-pattern|Unknown|MONITOR|Registered in campaign window with matching naming pattern; no observed phishing activity"
    # --- IPs: confirmed infrastructure ---
    "ip|91.234.99.107|2026-04-10|2026-04-26|HC3,Commercial,Researcher,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|AS47583 Hostinger; kit-confirmed LP host; four-way corroboration"
    "ip|185.176.43.22|2026-04-10|2026-04-26|HC3,Commercial,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|AS47583 Hostinger; observed directly in 4x00 email 02 Received header"
    "ip|164.90.218.73|2026-04-11|2026-04-26|HC3,Commercial,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|AS14061 DigitalOcean; dedicated staging host, not shared; observed in 4x00 email 03"
    "ip|51.38.42.17|2026-04-08|2026-04-26|HC3,Commercial,Researcher|HIGH|ACTIONABLE|ms-impersonation|Stage 1|BLOCK|AS16276 OVH; hosts outlook-protection.com; kit exfil route"
    "ip|51.38.42.191|2026-03-24|2026-04-26|HC3,Commercial,Researcher|HIGH|ACTIONABLE|operator-c2|Stage 3|BLOCK|AS16276 OVH; C2 and DNS-tunnel host from kit config.php and HC3; high-value containment target"
    "ip|45.77.218.9|2026-04-16|2026-04-24|HC3,Commercial|MEDIUM|ACTIONABLE|secondary-c2|Stage 2|MONITOR|AS20473; Brazil geographic anomaly; single-partner observation at HC3 MEDIUM"
    # --- Hashes: Stage 2 payloads and Stage 1 lure ---
    "hash|a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456|2026-04-16|2026-04-26|HC3,Commercial,Researcher|HIGH|ACTIONABLE|stage2-payloads|Stage 2|BLOCK|docm macro dropper HEALTHBANE_S2_invoice.docm; file size unknown; detection ratio unknown offline"
    "hash|b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654|2026-04-16|2026-04-26|HC3,Commercial|HIGH|ACTIONABLE|stage2-payloads|Stage 2|BLOCK|exe svchost_update.exe; persistence via scheduled task HealthSync Update Service and registry run key"
    "hash|c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6|2026-04-18|2026-04-26|HC3,Commercial,Researcher|HIGH|ACTIONABLE|stage2-payloads|Stage 2|BLOCK|ps1 sync_healthdata.ps1; deployed Stage 2, performs Stage 3 DNS TXT tunneling; extracted from kit tools dir by researcher"
    "hash|dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678|2026-04-16|2026-04-23|HC3,Commercial|MEDIUM|ACTIONABLE|stage2-payloads|Stage 2|MONITOR|Dropper variant; weakly sourced (single partner, source_count_external 1); hunt-only"
    "hash|2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f|2026-04-14|unknown|HC3,Commercial,Researcher,Internal|MEDIUM|ACTIONABLE|stage1-lure|Stage 1|BLOCK|PDF lure INV-2026-04891.pdf; benign format, no embedded code; four-way corroboration; YARA pattern more durable than hash"
    # --- Hashes: contextual ---
    "hash|ee1122334455667788990011223344556677889900aabbccddeeff0011223344|2026-04-17|2026-04-24|Commercial|MEDIUM|CONTEXTUAL|variant-watch|Stage 2|MONITOR|update_service_v2.exe trojan variant; not observed at MedDefense or by HC3; commercial feed only"
    "hash|ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899|unknown|unknown|Researcher|MEDIUM|CONTEXTUAL|kit-artifact|Unknown|MONITOR|kit_v2_healthbane.zip phishing kit archive; provenance unclear (operator-signed vs vendor-shipped); researcher MEDIUM"
    # --- URLs ---
    "url|https://meddefense-portal.com/verify/staff|2026-04-14|2026-04-26|HC3,Commercial,Researcher,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|Credential capture endpoint; clicked by dmarsh 4x00; query pattern id=user and 8-hex token"
    "url|https://medequip-supplies.net/invoices/pay|2026-04-14|2026-04-26|HC3,Commercial|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|Credential capture endpoint; invoice-number query pattern INV-YYYY-NNNNN"
    "url|https://meddefense-benefits.org/enroll|2026-04-15|2026-04-26|HC3,Commercial|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|BLOCK|Credential capture endpoint for benefits enrollment lure"
    "url|https://healthbane-c2.net/update/svchost_update.exe|2026-04-16|2026-04-26|HC3,Commercial|HIGH|ACTIONABLE|operator-c2|Stage 2|BLOCK|Stage 2 payload download endpoint; links Stage 1 compromise to Stage 2 C2"
    "url|https://outlook-protection.com/verify|2026-04-14|2026-04-26|Commercial|HIGH|ACTIONABLE|ms-impersonation|Stage 1|BLOCK|Microsoft impersonation endpoint; must block regardless of email authentication passing"
    "url|https://healthbane-c2.net/api/ingest|unknown|unknown|Researcher|MEDIUM|ACTIONABLE|operator-c2|Stage 2|MONITOR|Credential ingest endpoint from kit config.php; single-source researcher observation"
    # --- Email addresses ---
    "email|noreply@meddefense-portal.com|2026-04-14|unknown|Commercial,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|ALERT|Sender observed in 4x00 email 01; covered by domain block but retained for log correlation"
    "email|invoices@medequip-supplies.net|2026-04-14|unknown|Commercial,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|ALERT|Sender observed in 4x00 email 02; covered by domain block but retained for log correlation"
    "email|hr-notifications@meddefense-benefits.org|2026-04-14|unknown|Commercial,Internal|HIGH|ACTIONABLE|core-phishing-lp|Stage 1|ALERT|Sender observed in 4x00 email 03; covered by domain block but retained for log correlation"
)

# ============================================================================
# JSON GENERATION
# ============================================================================
write_json() {
    local first=true

    printf '{\n' > "$OUTPUT_FILE"
    printf '  "_metadata": {\n' >> "$OUTPUT_FILE"
    printf '    "database_id": "MD-4x02-IOCDB-001",\n' >> "$OUTPUT_FILE"
    printf '    "generated": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_FILE"
    printf '    "analyst": "Steve - Cybersecurity Engineer",\n' >> "$OUTPUT_FILE"
    printf '    "campaign": "HEALTHBANE",\n' >> "$OUTPUT_FILE"
    printf '    "aliases": ["VITALSCORE (commercial cluster label)", "APT-MEDAGENT (researcher actor hypothesis, MEDIUM)"],\n' >> "$OUTPUT_FILE"
    printf '    "note": "NOISE indicators (CDN/shared IPs, ML-cluster-only items) were excluded per Task 1 triage",\n' >> "$OUTPUT_FILE"
    printf '    "source_files": ["HC3_Advisory_HEALTHBANE_TLP_CLEAR.txt", "commercial_feed_extract.json", "researcher_blog_analysis.txt", "meddefense_4x00_findings.txt"]\n' >> "$OUTPUT_FILE"
    printf '  },\n' >> "$OUTPUT_FILE"
    printf '  "indicators": [\n' >> "$OUTPUT_FILE"

    for item in "${INDICATORS[@]}"; do
        IFS='|' read -r _type _value _first _last _sources _conf _cat _cluster _phase _action _enrich <<< "$item"
        if [[ "$first" == true ]]; then
            first=false
        else
            printf ',\n' >> "$OUTPUT_FILE"
        fi
        cat >> "$OUTPUT_FILE" <<EOF
    {
      "type": "${_type}",
      "value": "${_value}",
      "first_seen": "${_first}",
      "last_seen": "${_last}",
      "sources": "${_sources}",
      "confidence": "${_conf}",
      "category": "${_cat}",
      "cluster": "${_cluster}",
      "attack_phase": "${_phase}",
      "recommended_action": "${_action}",
      "enrichment_summary": "${_enrich}"
    }
EOF
    done

    printf '\n  ]\n}\n' >> "$OUTPUT_FILE"
}

# ============================================================================
# SUMMARY STATISTICS
# ============================================================================
print_summary() {
    local total=${#INDICATORS[@]}
    local domains=0 ips=0 hashes=0 urls=0 emails=0
    local high=0 medium=0 low=0
    local s1=0 s2=0 s3=0 unk=0
    local block=0 alert=0 monitor=0 none=0

    for item in "${INDICATORS[@]}"; do
        IFS='|' read -r _type _value _first _last _sources _conf _cat _cluster _phase _action _enrich <<< "$item"
        case "$_type" in
            domain) domains=$((domains + 1)) ;;
            ip)      ips=$((ips + 1)) ;;
            hash)    hashes=$((hashes + 1)) ;;
            url)     urls=$((urls + 1)) ;;
            email)   emails=$((emails + 1)) ;;
        esac
        case "$_conf" in
            HIGH)   high=$((high + 1)) ;;
            MEDIUM) medium=$((medium + 1)) ;;
            LOW)    low=$((low + 1)) ;;
        esac
        case "$_phase" in
            "Stage 1") s1=$((s1 + 1)) ;;
            "Stage 2") s2=$((s2 + 1)) ;;
            "Stage 3") s3=$((s3 + 1)) ;;
            Unknown)   unk=$((unk + 1)) ;;
        esac
        case "$_action" in
            BLOCK)   block=$((block + 1)) ;;
            ALERT)   alert=$((alert + 1)) ;;
            MONITOR) monitor=$((monitor + 1)) ;;
            NONE)    none=$((none + 1)) ;;
        esac
    done

    cat <<EOF
[*] Database written to: ${OUTPUT_FILE}
[*] Total indicators: ${total} (after deduplication and noise removal)

BY TYPE:
  Domains: ${domains}  |  IPs: ${ips}  |  Hashes: ${hashes}  |  URLs: ${urls}  |  Emails: ${emails}

BY CONFIDENCE:
  HIGH: ${high}  |  MEDIUM: ${medium}  |  LOW: ${low}

BY ATTACK PHASE:
  Stage 1 (Credential Harvest): ${s1}
  Stage 2 (Malware Delivery):   ${s2}
  Stage 3 (Data Exfiltration):  ${s3}
  Unknown:                      ${unk}

BY RECOMMENDED ACTION:
  BLOCK: ${block}  |  ALERT: ${alert}  |  MONITOR: ${monitor}  |  NONE: ${none}

Note: Reference totals in the task briefing (47) assume a different
dedup/noise split; this database is derived from the Task 1 triage of
the actual source data (48 unique, 15 NOISE excluded).
EOF
}

# ============================================================================
# VALIDATION
# ============================================================================
validate_json() {
    if command -v python3 >/dev/null 2>&1; then
        if python3 - "$OUTPUT_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    db = json.load(fh)

required = {
    "type", "value", "first_seen", "last_seen", "sources", "confidence",
    "category", "cluster", "attack_phase", "recommended_action",
    "enrichment_summary",
}
valid_type = {"domain", "ip", "hash", "url", "email"}
valid_conf = {"HIGH", "MEDIUM", "LOW"}
valid_cat = {"ACTIONABLE", "CONTEXTUAL"}
valid_phase = {"Stage 1", "Stage 2", "Stage 3", "Unknown"}
valid_action = {"BLOCK", "ALERT", "MONITOR", "NONE"}

errors = []
indicators = db.get("indicators", [])
if not indicators:
    errors.append("empty indicators array")

for idx, ind in enumerate(indicators):
    missing = required - set(ind.keys())
    if missing:
        errors.append(f"indicator {idx}: missing fields {sorted(missing)}")
        continue
    if ind["type"] not in valid_type:
        errors.append(f"indicator {idx}: bad type {ind['type']}")
    if ind["confidence"] not in valid_conf:
        errors.append(f"indicator {idx}: bad confidence {ind['confidence']}")
    if ind["category"] not in valid_cat:
        errors.append(f"indicator {idx}: bad category {ind['category']}")
    if ind["attack_phase"] not in valid_phase:
        errors.append(f"indicator {idx}: bad phase {ind['attack_phase']}")
    if ind["recommended_action"] not in valid_action:
        errors.append(f"indicator {idx}: bad action {ind['recommended_action']}")

if errors:
    for err in errors:
        print(f"VALIDATION ERROR: {err}", file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PY
        then
            echo "[*] Database validation: PASS"
            return 0
        else
            echo "[!] Database validation: FAIL" >&2
            return 1
        fi
    else
        echo "[!] python3 unavailable; falling back to jq"
        if command -v jq >/dev/null 2>&1; then
            if jq -e '.indicators | type == "array" and length > 0' "$OUTPUT_FILE" >/dev/null; then
                echo "[*] Database validation: PASS (jq structural check only)"
                return 0
            fi
            echo "[!] Database validation: FAIL" >&2
            return 1
        fi
        echo "[!] No JSON validator available; inspect ${OUTPUT_FILE} manually" >&2
        return 1
    fi
}

# ============================================================================
# MAIN
# ============================================================================
write_json
print_summary
validate_json
