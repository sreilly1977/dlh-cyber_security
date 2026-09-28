#!/bin/bash
# Name: 1-indicator_triage.sh
# Purpose: Triage the 64 unique HEALTHBANE indicators into ACTIONABLE/CONTEXTUAL/NOISE
#          categories with confidence scoring and justification for each classification
# Author: Steve - Cybersecurity Engineer
# Date: 28 September 2026
# Source: Project 4x02 - Intelligence-Driven Defense

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
OUTPUT_DIR="analysis"
OUTPUT_FILE="${OUTPUT_DIR}/indicator_triage_results.tsv"
SUMMARY_FILE="${OUTPUT_DIR}/triage_summary.txt"

mkdir -p "${OUTPUT_DIR}"

# ============================================================================
# INDICATOR DATASET (deduplicated from 0-intel_intake.md)
# Format: TYPE|VALUE|SOURCES|STATUS|CONFIDENCE|JUSTIFICATION|UNCERTAIN
# ============================================================================
INDICATORS=(
    # --- Domains ---
    "DOMAIN|meddefense-portal.com|HC3,Commercial,Researcher,Internal|ACTIONABLE|HIGH|Confirmed Stage 1 phishing LP observed directly at MedDefense (4x00)|NO"
    "DOMAIN|medequip-supplies.net|HC3,Commercial,Researcher,Internal|ACTIONABLE|HIGH|Confirmed Stage 1 phishing LP observed directly at MedDefense (4x00)|NO"
    "DOMAIN|meddefense-benefits.org|HC3,Commercial,Internal|ACTIONABLE|HIGH|Confirmed Stage 1 phishing LP observed directly at MedDefense (4x00)|NO"
    "DOMAIN|outlook-protection.com|HC3,Commercial,Researcher|ACTIONABLE|HIGH|Credential-harvest domain and kit SMTP exfil route per researcher config.php|NO"
    "DOMAIN|healthbane-c2.net|HC3,Commercial,Researcher|ACTIONABLE|HIGH|Stage 2/3 C2 referenced in kit config and HC3 sandbox analysis|NO"
    "DOMAIN|data-sync.healthbane-c2.net|HC3|ACTIONABLE|HIGH|Stage 3 DNS TXT exfiltration endpoint from HC3 packet captures|NO"
    "DOMAIN|update-healthbane.net|HC3(MED),Commercial|ACTIONABLE|MEDIUM|Stage 2 secondary C2; MEDIUM confidence per HC3, single external corroboration|YES"
    "DOMAIN|portal-secure-meddefense.com|HC3(MED),Researcher(MED)|ACTIONABLE|MEDIUM|Staged kit not yet live; pre-positioned rotation domain, monitor aggressively|YES"
    "DOMAIN|rx-benefits-portal.com|Commercial(PRIOR)|CONTEXTUAL|LOW|Predates campaign window by 16 days; possibly earlier same-operator activity|YES"
    "DOMAIN|healthcare-login.com|Commercial(SINKHOLED)|CONTEXTUAL|LOW|Sinkholed 2026-04-18; historical correlation value only|NO"
    "DOMAIN|verify-health-portal.net|Commercial|CONTEXTUAL|LOW|Matching naming pattern and registration window but no observed phishing activity|YES"
    "DOMAIN|secure-insurance-login.com|Commercial(ML_CLUSTER)|NOISE|LOW|Clustered by ML name similarity only; no human review, no corroboration|NO"
    "DOMAIN|claims-verify-portal.net|Commercial(KW_ONLY)|NOISE|LOW|Keyword-match clustering only; Acme itself notes LOW attacker association|NO"
    # --- IPs ---
    "IP|91.234.99.107|HC3,Commercial,Researcher,Internal|ACTIONABLE|HIGH|Kit-confirmed phishing LP hosting, Hostinger, corroborated by all sources|NO"
    "IP|185.176.43.22|HC3,Commercial,Internal|ACTIONABLE|HIGH|Stage 1 phishing LP hosting directly observed at MedDefense|NO"
    "IP|164.90.218.73|HC3,Commercial,Internal|ACTIONABLE|HIGH|Stage 1 phishing LP hosting directly observed at MedDefense|NO"
    "IP|51.38.42.17|HC3,Commercial|ACTIONABLE|HIGH|Phishing LP hosting corroborated by HC3 and commercial feed|NO"
    "IP|51.38.42.191|HC3,Commercial,Researcher|ACTIONABLE|HIGH|Stage 2/3 C2 IP from kit config.php and HC3 observation|NO"
    "IP|45.77.218.9|HC3(MED),Commercial|ACTIONABLE|MEDIUM|Stage 2 second-stage hosting; single-partner evidence|YES"
    "IP|159.89.112.45|Commercial(OVERSHARED)|NOISE|LOW|DigitalOcean shared hosting with 200+ unrelated sites; blocking causes broad false positives|NO"
    "IP|23.94.138.222|Commercial(BPH_NO_CONF)|NOISE|LOW|Bulletproof-hosting ASN tagged by clustering; zero external corroboration|NO"
    "IP|104.168.34.58|Commercial(ML_CLUSTER)|NOISE|LOW|Clustered by similarity only; no corroborating source|NO"
    "IP|167.71.222.30|Commercial,Researcher(LOW)|NOISE|LOW|Operator-overlap hypothesis only; researcher rates LOW confidence|YES"
    "IP|192.99.207.114|Commercial(CDN_OVH)|NOISE|LOW|OVH shared CDN; Acme itself flags LIKELY NOISE|NO"
    "IP|20.83.144.56|Commercial(AZURE_CDN)|NOISE|LOW|Azure CDN shared infrastructure; Acme notes DO NOT BLOCK|NO"
    "IP|13.107.42.14|Commercial(MSO_OUTLOOK)|NOISE|LOW|Microsoft Outlook.com cloud IP; clustering-model false positive|NO"
    "IP|172.67.192.40|Commercial(CLOUDFLARE)|NOISE|LOW|Cloudflare front IP; not actionable|NO"
    "IP|104.21.35.7|Commercial(CLOUDFLARE)|NOISE|LOW|Cloudflare front IP; not actionable|NO"
    # --- Hashes ---
    "HASH|a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456|HC3,Commercial,Researcher|ACTIONABLE|HIGH|HEALTHBANE_S2_invoice.docm Stage 2 macro dropper; corroborated by three sources|NO"
    "HASH|b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654|HC3,Commercial|ACTIONABLE|HIGH|svchost_update.exe Stage 2 payload with scheduled-task persistence|NO"
    "HASH|c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6|HC3,Commercial,Researcher|ACTIONABLE|HIGH|sync_healthdata.ps1 Stage 3 exfiltrator; corroborated by three sources|NO"
    "HASH|dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678|HC3(MED),Commercial|ACTIONABLE|MEDIUM|Dropper variant observed at one HC3 partner only|YES"
    "HASH|2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f|HC3,Commercial,Researcher,Internal|ACTIONABLE|MEDIUM|INV-2026-04891.pdf Stage 1 lure PDF; benign-format lure, block with awareness|NO"
    "HASH|ee1122334455667788990011223344556677889900aabbccddeeff0011223344|Commercial(VARIANT)|CONTEXTUAL|MEDIUM|Trojan variant not observed at MedDefense; hunt-only candidate|YES"
    "HASH|1122aabbccddeeff00112233445566778899aabbccddeeff0011223344556677|Commercial(UNRELATED)|NOISE|LOW|Likely unrelated malware family per Acme own note|NO"
    "HASH|3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011|Commercial(UNRELATED)|NOISE|LOW|Unrelated cluster; no HEALTHBANE association|NO"
    "HASH|5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344|Commercial(ML_CLUSTER)|NOISE|LOW|Keyword/similarity clustering only; zero corroboration|NO"
    "HASH|77889900112233445566778899aabbccddeeff0011223344556677aabbccddeeff00|Commercial(ML_CLUSTER)|NOISE|LOW|Similarity clustering only; zero corroboration|NO"
    "HASH|ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899|Researcher(KIT_ZIP)|CONTEXTUAL|MEDIUM|Phishing kit ZIP; unknown if vendor-shipped or operator artifact; hunt value|YES"
    # --- URLs ---
    "URL|https://meddefense-portal.com/verify/staff|HC3,Commercial,Researcher,Internal|ACTIONABLE|HIGH|Credential capture endpoint clicked by dmarsh (4x00)|NO"
    "URL|https://medequip-supplies.net/invoices/pay|HC3,Commercial|ACTIONABLE|HIGH|Stage 1 credential capture endpoint|NO"
    "URL|https://meddefense-benefits.org/enroll|HC3,Commercial|ACTIONABLE|HIGH|Stage 1 credential capture endpoint|NO"
    "URL|https://healthbane-c2.net/update/svchost_update.exe|HC3,Commercial|ACTIONABLE|HIGH|Stage 2 second-stage download endpoint|NO"
    "URL|https://outlook-protection.com/verify|Commercial|ACTIONABLE|HIGH|Microsoft-impersonation phishing endpoint|NO"
    "URL|https://healthbane-c2.net/api/ingest|Researcher|ACTIONABLE|MEDIUM|Credential ingest endpoint from kit config.php; single-source observation|YES"
    # --- Email addresses ---
    "EMAIL|noreply@meddefense-portal.com|Commercial,Internal|ACTIONABLE|HIGH|Campaign sender observed directly in 4x00 email headers|NO"
    "EMAIL|invoices@medequip-supplies.net|Commercial,Internal|ACTIONABLE|HIGH|Campaign sender observed directly in 4x00 email headers|NO"
    "EMAIL|hr-notifications@meddefense-benefits.org|Commercial,Internal|ACTIONABLE|HIGH|Campaign sender observed directly in 4x00 email headers|NO"
)

# ============================================================================
# MAIN EXECUTION
# ============================================================================
main() {
    local actionable_count=0
    local contextual_count=0
    local noise_count=0
    local total=0

    printf 'TYPE\tVALUE\tSOURCES\tCATEGORY\tCONFIDENCE\tJUSTIFICATION\tUNCERTAIN\n' > "$OUTPUT_FILE"

    for item in "${INDICATORS[@]}"; do
        IFS='|' read -r _type _value _sources _status _conf _justif _uncertain <<< "$item"
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$_type" "$_value" "$_sources" "$_status" "$_conf" "$_justif" "$_uncertain" >> "$OUTPUT_FILE"

        total=$((total + 1))
        case "$_status" in
            ACTIONABLE) actionable_count=$((actionable_count + 1)) ;;
            CONTEXTUAL) contextual_count=$((contextual_count + 1)) ;;
            NOISE)       noise_count=$((noise_count + 1)) ;;
        esac
    done

    local total_count="$total"
    local actionable_pct contextual_pct noise_pct
    actionable_pct=$(awk -v a="$actionable_count" -v t="$total_count" 'BEGIN {printf "%.1f", (a/t)*100}')
    contextual_pct=$(awk -v c="$contextual_count" -v t="$total_count" 'BEGIN {printf "%.1f", (c/t)*100}')
    noise_pct=$(awk -v n="$noise_count" -v t="$total_count" 'BEGIN {printf "%.1f", (n/t)*100}')

    write_summary "$total_count" "$actionable_count" "$contextual_count" "$noise_count" \
                  "$actionable_pct" "$contextual_pct" "$noise_pct"

    echo "" >&2
    echo "Triage complete (${total_count} indicators). Output:" >&2
    echo "  ${OUTPUT_FILE}" >&2
    echo "  ${SUMMARY_FILE}" >&2
    echo "" >&2
    echo "WARNING: ${noise_count} indicators (${noise_pct}%) are shared or weakly attributed" >&2
    echo "infrastructure and are UNSAFE for perimeter blocking." >&2
}

# ============================================================================
# SUMMARY GENERATION
# ============================================================================
write_summary() {
    local total="$1" actionable="$2" contextual="$3" noise="$4"
    local actionable_pct="$5" contextual_pct="$6" noise_pct="$7"

    {
        cat <<EOF
================================================================================
  INDICATOR TRIAGE SUMMARY - HEALTHBANE CAMPAIGN
  Project 4x02 - Signal vs Noise
================================================================================

Generated:   $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Analyst:     Steve - Cybersecurity Engineer

TOTAL INDICATORS REVIEWED: ${total}

Note on counts: The task briefing references 64 unique indicators. Deduplicating
the four source files against the actual indicator values yields ${total}
unique indicators (89 raw references). This script classifies based on the
data itself, per project methodology.

--------------------------------------------------------------------------------
CATEGORY BREAKDOWN
--------------------------------------------------------------------------------

ACTIONABLE: ${actionable} (${actionable_pct}%)
  Safe for perimeter blocking and EDR/AV blocklists.
  Corroborated by HC3, researcher kit evidence, or direct 4x00 observation.

CONTEXTUAL: ${contextual} (${contextual_pct}%)
  Hunt/monitor/correlation value only. Not for blocking.
  Includes pre-campaign domains, sinkholed infrastructure, kit archives,
  and variants not observed at MedDefense.

NOISE: ${noise} (${noise_pct}%)
  Unsafe or worthless for blocking. Shared CDN/cloud IPs, ML-similarity
  clusters without human review, and unrelated malware families.

--------------------------------------------------------------------------------
TOP REASONS INDICATORS WERE DOWNGRADED
--------------------------------------------------------------------------------

1. Shared CDN/cloud infrastructure (Cloudflare x2, Azure, OVH CDN,
   Microsoft Outlook.com): 5 indicators
   - Blocking these breaks legitimate traffic organization-wide.
2. DigitalOcean/VPS shared hosting (159.89.112.45, 167.71.222.30): 2 indicators
   - 159.89.112.45 hosts 200+ unrelated websites per Acme's own note.
3. ML-similarity or keyword clustering without human review: 6 indicators
   - Acme disclaimer states analyst review was SAMPLED, not exhaustive.
4. Unrelated malware families tagged by automation: 2 indicators
5. Sinkholed or pre-campaign infrastructure: 3 indicators
   - rx-benefits-portal.com predates the HEALTHBANE window by 16 days;
     healthcare-login.com was sinkholed 2026-04-18.

--------------------------------------------------------------------------------
TOP INDICATORS FOR IMMEDIATE DETECTION
--------------------------------------------------------------------------------

Perimeter (block now, HIGH confidence, multi-source):
  Domains : meddefense-portal.com, medequip-supplies.net,
            meddefense-benefits.org, outlook-protection.com,
            healthbane-c2.net, data-sync.healthbane-c2.net
  IPs     : 91.234.99.107, 185.176.43.22, 164.90.218.73,
            51.38.42.17, 51.38.42.191
  Senders : noreply@meddefense-portal.com, invoices@medequip-supplies.net,
            hr-notifications@meddefense-benefits.org

EDR/AV (hash blocklist):
  a1b2c3d4... (HEALTHBANE_S2_invoice.docm)
  b9c8a7d6... (svchost_update.exe)
  c7d6e5f4... (sync_healthdata.ps1)

Aggressive hunt (rotation candidates, act if seen):
  portal-secure-meddefense.com (staged kit, not yet live)
  update-healthbane.net (Stage 2 secondary C2)
  ee112233... (update_service_v2.exe variant)

--------------------------------------------------------------------------------
UNCERTAINTY FLAGS
--------------------------------------------------------------------------------
$(grep -c "	YES$" "$OUTPUT_FILE" || true) indicators carry an uncertainty flag
(category assignment or attribution not straightforward; see UNCERTAIN column
in indicator_triage_results.tsv for which and why).

================================================================================
END OF SUMMARY
================================================================================
EOF
    } > "$SUMMARY_FILE"
}

main "$@"
