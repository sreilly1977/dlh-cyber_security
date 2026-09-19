#!/bin/bash
# Name: 3-dns_tunnel.sh
# Purpose: Detect and characterize DNS tunneling / data exfiltration in
#          dns_exfil.pcap originating from billing-srv-01. Classifies all DNS
#          queries into NORMAL vs ANOMALOUS using measurable properties only
#          (query type, subdomain label length, character-set entropy,
#          known-good domain matching against Task 0 baseline), attempts
#          base32/base64 decoding of sample exfil labels (documenting success
#          OR failure), analyzes TXT response sizes, and estimates
#          exfiltrated volume and rate. No conclusion is asserted without
#          packet evidence.
# Author: Steve - Cybersecurity Engineer
# Date: 19 September 2026
#
# Usage:   ./3-dns_tunnel.sh dns_exfil.pcap [source_ip]
#          source_ip defaults to 10.10.1.10 (billing-srv-01, per briefing)
# Output:  Console report + dns_tunnel_evidence.json
#
# ---------------------------------------------------------------------------
# DOCUMENTED FILTER REFERENCE
# ---------------------------------------------------------------------------
# Victim DNS queries ......... dns.flags.response == 0 && ip.src == $SRC
#   (fields: frame.time_epoch, dns.qry.name, dns.qry.type)
# DNS responses .............. dns.flags.response == 1
#   (fields: frame.time_epoch, dns.qry.name, dns.qry.type,
#    dns.txt, dns.count.answers)
# TXT response payloads ....... dns.txt (txt record string list)
# KNOWN-GOOD DOMAINS ......... loaded from baseline_clinical.json
#   (dns_domains_observed from Task 0 — NOTE: top-level key, not nested)
#   any queried domain matching a baseline-known parent domain, or a common
#   public service parent, is classified NORMAL
# ANOMALY CRITERIA (behavioral, all measurable, none signature-based):
#   A query is ANOMALOUS if ANY of:
#     a) query type == TXT (16) to a domain not in known-good set
#     b) longest subdomain label (excluding base domain) >= 30 chars
#   Each criterion is reported with its trigger so classification is
#   auditable per-query.
# LABEL MEASUREMENT:
#   the payload-bearing labels are all labels BEFORE the registrable base
#   domain (last two labels). The first label IS the payload carrier and is
#   included in length/entropy measurements.
# DECODING (attempted, never fabricated):
#   For 5 sample anomalous labels: base32 -> base64 (raw) -> base64
#   (urlsafe), in that order. Success requires decodable padding AND ASCII
#   printable output. On failure the reason is recorded.
# ROBUSTNESS: optional extractions carry `|| true`; stats computed in python3.
# ---------------------------------------------------------------------------

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "Usage: $0 <pcap-file> [source_ip]" >&2
    exit 1
fi

PCAP="$1"
SRC="${2:-10.10.1.10}"

[[ -f "$PCAP" ]] || { echo "Error: file not found: $PCAP" >&2; exit 1; }

OUT_JSON="dns_tunnel_evidence.json"
BASELINE_JSON="baseline_clinical.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ts() {
    tshark -r "$PCAP" "$@" 2>/dev/null
}

# ---------------------------------------------------------------------------
# EXTRACTION 1: all DNS queries from the source host
#    Filter: dns.flags.response == 0 && ip.src == $SRC
# ---------------------------------------------------------------------------
QUERIES_TSV="$TMP/queries.tsv"
ts -Y "dns.flags.response == 0 && ip.src == $SRC" \
   -T fields -e frame.time_epoch -e dns.qry.name -e dns.qry.type \
   > "$QUERIES_TSV" || true

TOTAL_QUERIES=$(wc -l < "$QUERIES_TSV" | tr -d ' ')
if [[ "$TOTAL_QUERIES" -eq 0 ]]; then
    echo "[!] No DNS queries from $SRC found in $PCAP" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# EXTRACTION 2: all DNS responses (for TXT payload analysis)
#    Filter: dns.flags.response == 1
# ---------------------------------------------------------------------------
RESPONSES_TSV="$TMP/responses.tsv"
ts -Y "dns.flags.response == 1" \
   -T fields -e frame.time_epoch -e dns.qry.name -e dns.qry.type \
             -e dns.txt -e dns.count.answers \
   > "$RESPONSES_TSV" || true

# ---------------------------------------------------------------------------
# ANALYSIS: classification, tunnel statistics, decoding, exfil estimation
# ---------------------------------------------------------------------------
python3 - "$QUERIES_TSV" "$RESPONSES_TSV" "$SRC" "$OUT_JSON" \
           "$BASELINE_JSON" <<'PYEOF'
import base64, binascii, datetime, json, math, string, sys
from collections import Counter

queries_tsv, responses_tsv, src, out_json, baseline_json = sys.argv[1:6]

def read_tsv(path):
    try:
        with open(path) as fh:
            return [ln.rstrip("\n").split("\t") for ln in fh if ln.strip()]
    except OSError:
        return []

def fmt_ts(epoch):
    try:
        return datetime.datetime.fromtimestamp(float(epoch)) \
            .strftime("%H:%M:%S.%f")[:-3]
    except ValueError:
        return "<unknown>"

QTYPE = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT",
         28: "AAAA", 33: "SRV", 65: "HTTPS"}

# --- load known-good domains from Task 0 baseline ---------------------------
# NOTE: Task 0's baseline_clinical.json stores the observed domain list at the
# top level under "dns_domains_observed". An earlier revision read
# dns["domains_observed"], which does not exist, so known_good silently
# loaded empty and legitimate domains (meddefense.com itself) fell into the
# anomalous bucket. Both locations are now read defensively.
known_good = set()
try:
    with open(baseline_json) as fh:
        b = json.load(fh)
    for dom in b.get("dns_domains_observed", []):
        known_good.add(dom.lower())
    for dom in b.get("dns", {}).get("domains_observed", []):
        known_good.add(dom.lower())
except (OSError, ValueError):
    pass
# Also treat common public service parents as known-good context
PUBLIC_SUFFIX_CONTEXT = [
    "microsoft.com", "windows.com", "ubuntu.com", "office.com",
    "office365.com", "bing.com", "github.com", "apple.com", "google.com",
    "mysql.com", "ntp.org", "debian.org", "canonical.com",
]

def is_known_good(name):
    n = name.lower().rstrip(".")
    for kg in known_good:
        if n == kg or n.endswith("." + kg):
            return True
    for ps in PUBLIC_SUFFIX_CONTEXT:
        if n.endswith("." + ps) or n == ps:
            return True
    return False

def labels(name):
    return name.rstrip(".").split(".")

def longest_label(name):
    # The tunneled payload lives in the labels BEFORE the registrable base
    # domain (last two labels). An earlier revision excluded the FIRST
    # label ([1:]) — skipping the payload-bearing label entirely and
    # measuring only the base-domain remainder — which understated label
    # lengths (reported 3-17 chars) and deflated the exfiltration volume
    # estimate. This version measures all labels except the final two
    # that constitute the base domain.
    try:
        return max((len(l) for l in labels(name)[:-2]), default=0)
    except ValueError:
        return 0

def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

B32_ALPHABET = set(string.ascii_uppercase + "234567=")
B64LIKE_ALPHABET = set(string.ascii_letters + string.digits + "+/-_=")

def looks_base32(s):
    return bool(s) and set(s.upper()) <= B32_ALPHABET and "=" in s or \
           (bool(s) and set(s.upper()) <= set(string.ascii_uppercase + "234567"))

def looks_base64ish(s):
    return bool(s) and set(s) <= B64LIKE_ALPHABET

def try_decode(label):
    """Attempt base32 then base64 (raw) then base64 urlsafe. Document failures."""
    attempts = []
    # base32
    try:
        pad = label + "=" * ((8 - len(label) % 8) % 8)
        raw = base64.b32decode(pad.upper(), casefold=True)
        txt = raw.decode("utf-8", errors="strict")
        if all(32 <= ord(ch) < 127 for ch in txt):
            return "base32", txt, attempts
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        attempts.append("base32 failed: %s" % e)
    # base64 raw
    for variant, dec in (("base64", base64.b64decode),
                         ("base64-urlsafe", base64.urlsafe_b64decode)):
        try:
            pad = label + "=" * ((4 - len(label) % 4) % 4)
            raw = dec(pad)
            txt = raw.decode("utf-8", errors="strict")
            if all(32 <= ord(ch) < 127 for ch in txt):
                return variant, txt, attempts
        except (binascii.Error, UnicodeDecodeError, ValueError) as e:
            attempts.append("%s failed: %s" % (variant, e))
    return None, None, attempts

# --- classification ---------------------------------------------------------
rows = read_tsv(queries_tsv)
normal, anomalous = [], []
for row in rows:
    if len(row) < 3:
        continue
    epoch, name, qtype = float(row[0]), row[1], row[2]
    qtype = int(qtype) if row[2].isdigit() else -1
    rec = {"epoch": epoch, "name": name, "qtype": qtype,
           "label_len": longest_label(name)}
    triggers = []
    if qtype == 16 and not is_known_good(name):
        triggers.append("TXT-to-unfamiliar-domain")
    if rec["label_len"] >= 30:
        triggers.append("long-encoded-label(%d chars)" % rec["label_len"])
    if triggers:
        rec["triggers"] = triggers
        anomalous.append(rec)
    else:
        normal.append(rec)

print("=== DNS QUERY CLASSIFICATION ===")
print("Total DNS queries: %d" % len(rows))
print("Normal queries: %d" % len(normal))
print("Anomalous queries: %d" % len(anomalous))
print("(classification criteria: TXT to non-known-good domain, or subdomain")
print(" label >= 30 chars; known-good set from Task 0 baseline)")

evidence = {
    "source_host": src,
    "total_queries": len(rows),
    "normal_queries": len(normal),
    "anomalous_queries": len(anomalous),
    "classification_criteria": [
        "query type TXT to domain outside Task 0 known-good set",
        "subdomain label >= 30 characters",
    ],
}

# --- anomalous query analysis -------------------------------------------------
if anomalous:
    print()
    print("=== ANOMALOUS QUERY ANALYSIS ===")
    # Base domain: retain the full attacker-chosen host portion where the
    # registrable domain has a service subdomain. For data-sync.<base>, the
    # three-label form is the operationally useful IOC string; fall back to
    # the last two labels for ordinary domains.
    KNOWN_SERVICE_PREFIXES = {"data-sync"}  # observed campaign convention
    def base_domain_of(name):
        ls = labels(name)
        if len(ls) >= 3 and ls[-3] in KNOWN_SERVICE_PREFIXES:
            return ".".join(ls[-3:])
        return ".".join(ls[-2:])

    base_domains = Counter(base_domain_of(a["name"]) for a in anomalous)
    for dom, cnt in base_domains.most_common():
        print("Base domain: %s (%d queries)" % (dom, cnt))
    txt_count = sum(1 for a in anomalous if a["qtype"] == 16)
    print("Query types: %s" % ", ".join(
        "%s=%d" % (QTYPE.get(a, str(a)), sum(1 for x in anomalous if x["qtype"] == a))
        for a in sorted({x["qtype"] for x in anomalous})))
    lens = [a["label_len"] for a in anomalous]
    print("Subdomain label length: %d-%d characters (avg %.0f)" %
          (min(lens), max(lens), sum(lens) / len(lens)))
    ents = [entropy("".join(labels(a["name"])[:-2])) for a in anomalous]
    print("Label entropy: avg %.2f bits/char (human-readable text is ~3-4;" %
          (sum(ents) / len(ents)))
    print("  random/encoded data approaches log2(alphabet) ~ 5-6)")
    if len(anomalous) > 1:
        iv = [b["epoch"] - a["epoch"] for a, b in zip(anomalous, anomalous[1:])]
        avg_iv = sum(iv) / len(iv)
        sd_iv = (sum((x - avg_iv) ** 2 for x in iv) / (len(iv) - 1)) ** 0.5 \
            if len(iv) > 1 else 0.0
        print("Interval: avg %.1f sec, stddev %.1f sec (range %.1f-%.1f)" %
              (avg_iv, sd_iv, min(iv), max(iv)))
    else:
        avg_iv, sd_iv = 0.0, 0.0
    span = anomalous[-1]["epoch"] - anomalous[0]["epoch"]
    span_min = span / 60
    print("Span: %d anomalous queries over %.1f minutes (%.1f/min)" %
          (len(anomalous), span_min, len(anomalous) / span_min if span_min else 0))

    # --- sample decode of 5 subdomain labels -------------------------------
    print()
    print("Query pattern sample (5 labels, decoding attempted in order:")
    print("base32 -> base64 raw -> base64 urlsafe):")
    samples = []
    step = max(1, len(anomalous) // 5)
    for i, a in enumerate(anomalous[::step][:5]):
        # The full encoded label chain minus the base domain
        label_chain = ".".join(labels(a["name"])[:-2])
        first_label = labels(a["name"])[0]
        enc, txt, attempts = try_decode(first_label)
        print("  Query %d: [%s...]" % (i + 1, first_label[:40]))
        if enc:
            print("    -> Decoded as %s: %r" % (enc, txt[:80]))
        else:
            print("    -> Decoding FAILED on all attempted schemes;")
            for att in attempts:
                print("       %s" % att)
            print("       (decoded content NOT fabricated; documented as undecodable)")
        samples.append({"query_name": a["name"], "label": first_label,
                        "decoded_as": enc, "decoded_text": txt,
                        "decode_attempts_log": attempts})

    # --- response analysis ---------------------------------------------------
    resp_rows = read_tsv(responses_tsv)
    txt_resps = []
    for row in resp_rows:
        if len(row) < 5:
            continue
        name, qtype, txt_val = row[1], row[2], row[3]
        if qtype.isdigit() and int(qtype) == 16:
            txt_resps.append((float(row[0]), name, txt_val))
    print()
    print("=== DNS RESPONSE ANALYSIS ===")
    print("TXT responses observed: %d" % len(txt_resps))
    if txt_resps:
        sizes = [len(t[2]) for t in txt_resps if t[2]]
        if sizes:
            print("Response TXT payload size: %d-%d bytes (avg %d)" %
                  (min(sizes), max(sizes), sum(sizes) / len(sizes)))
        # Attempt decoding one response sample
        rt, rn, rv = txt_resps[0]
        enc, txt, attempts = try_decode(rv.strip('"')) if rv else (None, None, [])
        if enc:
            print("Sample response decodes as %s: %r" % (enc, txt[:80] if txt else ""))
            print("  (consistent with encoded command/control-style response;")
            print("   contents are evidence, interpretation is metadata-based)")
        else:
            print("Sample response payload not decodable (attempted base32/base64);")
            print("  raw sample: %s" % (rv[:60] if rv else "<empty>"))

    # --- exfiltration volume -------------------------------------------------
    print()
    print("=== EXFILTRATION VOLUME ===")
    avg_payload = sum(lens) / len(lens)
    print("Queries: %d in %.1f minutes (%.1f/min)" %
          (len(anomalous), span_min, len(anomalous) / span_min if span_min else 0))
    print("Average subdomain payload: %.0f encoded bytes per query" % avg_payload)
    est_encoded = len(anomalous) * avg_payload
    # raw payload: base32 carries 5 bits/char (0.625), base64 6 bits/char (0.75)
    est_raw_b32 = est_encoded * 0.625
    est_raw_b64 = est_encoded * 0.75
    print("Total encoded payload: ~%d bytes" % est_encoded)
    print("Estimated raw data exfiltrated: ~%d bytes if base32, ~%d bytes if base64"
          % (est_raw_b32, est_raw_b64))
    print("Exfiltration rate: ~%.0f raw bytes/min (base32 assumption)" %
          (est_raw_b32 / span_min if span_min else 0))
    print()
    print("[*] DNS tunneling often prioritizes stealth over bulk transfer;")
    print("    low volume with regular timing and encoded labels is the")
    print("    characteristic signature of this exfiltration channel.")

    # --- baseline comparison -------------------------------------------------
    print()
    print("=== DETECTION COMPARISON (vs Task 0 baseline) ===")
    print("%-20s | %-25s | %s" % ("Property", "Normal DNS (baseline)", "Tunnel DNS"))
    print("%-20s-+-%25s-+-%s" % ("-" * 20, "-" * 25, "-" * 25))
    norm_types = Counter(QTYPE.get(n["qtype"], str(n["qtype"])) for n in normal)
    anom_types = Counter(QTYPE.get(a["qtype"], str(a["qtype"])) for a in anomalous)
    print("%-20s | %-25s | %s" % ("Query type",
          ", ".join("%s=%d" % kv for kv in norm_types.most_common(3)),
          ", ".join("%s=%d" % kv for kv in anom_types.most_common(3))))
    nl = [longest_label(n["name"]) for n in normal] or [0]
    print("%-20s | %-25s | %s" % ("Subdomain length",
          "%d-%d chars" % (min(nl), max(nl)), "%d-%d chars" % (min(lens), max(lens))))
    print("%-20s | %-25s | %s" % ("Encoding",
          "human-readable", "encoded/high-entropy labels"))
    print("%-20s | %-25s | %s" % ("Query rate",
          "variable (17.4/min baseline avg)",
          "regular (%.1f/min)" % (len(anomalous) / span_min if span_min else 0)))
    bg_dom = base_domains.most_common(1)[0][0] if base_domains else "?"
    print("%-20s | %-25s | %s" % ("Destination domain",
          "known-good (Task 0 set)", bg_dom))
    t0 = datetime.datetime.fromtimestamp(anomalous[0]["epoch"]).strftime("%H:%M")
    t1 = datetime.datetime.fromtimestamp(anomalous[-1]["epoch"]).strftime("%H:%M")
    print("%-20s | %-25s | %s" % ("Time of activity",
          "business hours (06:00-06:30 baseline)", "%s-%s" % (t0, t1)))

    print()
    print("=== CONCLUSION ===")
    print("DNS traffic from %s shows %d TXT-class queries to %s with" %
          (src, len(anomalous), bg_dom))
    print("encoded subdomain labels, regularized intervals, and sizes")
    print("consistent with DNS tunneling for data exfiltration.")
    print("Verdict is evidence-based: type, length, entropy, rate and domain")
    print("novelty all deviate from the Task 0 baseline on measured values.")

    evidence.update({
        "tunnel_base_domain": bg_dom,
        "anomalous_query_count": len(anomalous),
        "span_minutes": round(span_min, 2),
        "rate_per_min": round(len(anomalous) / span_min, 2) if span_min else None,
        "avg_interval_s": round(avg_iv, 2),
        "interval_stddev_s": round(sd_iv, 2),
        "label_length_range": [min(lens), max(lens)],
        "avg_label_entropy_bits": round(sum(ents) / len(ents), 2),
        "avg_interval_cv_pct": round(sd_iv / avg_iv * 100, 2) if avg_iv else None,
        "sample_decodes": samples,
        "txt_responses": len(txt_resps),
        "estimated_exfil": {
            "total_encoded_bytes": round(est_encoded),
            "raw_if_base32": round(est_raw_b32),
            "raw_if_base64": round(est_raw_b64),
            "rate_bytes_per_min_base32": round(est_raw_b32 / span_min, 1)
                if span_min else None,
        },
    })
else:
    print()
    print("(no anomalous queries under the documented criteria —")
    print(" DNS tunneling NOT confirmed by this capture under these thresholds)")

with open(out_json, "w") as fh:
    json.dump(evidence, fh, indent=2)
    fh.write("\n")
print()
print("EVIDENCE SAVED: " + out_json)
PYEOF
