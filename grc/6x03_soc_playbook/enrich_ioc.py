#!/usr/bin/env python3
# Name: enrich_ioc.py
# Purpose: Modular IOC enrichment engine for the 6x03 SOC Playbook. Classifies an IP,
#          domain or URL against the local MedDefense threat intel feed (ioc_feed.json),
#          performs reverse DNS, and returns a structured score/verdict dict.
#          Verdicts: BLOCK (feed confidence >= 80), INVESTIGATE (< 80 or unknown),
#          ALLOW (benign list, private/loopback address).
# Author: Steve - Cybersecurity Engineer
# Date: 08 November 2026

import argparse
import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# RFC 5737 documentation ranges must be classified explicitly; ipaddress treats
# them as ordinary reserved space, not as a distinct class.
DOCUMENTATION_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.IGNORECASE
)


def detect_ioc_type(value: str) -> str:
    """Return 'ipv4', 'ipv6', 'domain' or 'url' for the given value."""
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        return "url"
    try:
        ipaddress.IPv4Address(value)
        return "ipv4"
    except ValueError:
        pass
    try:
        ipaddress.IPv6Address(value)
        return "ipv6"
    except ValueError:
        pass
    if DOMAIN_RE.match(value):
        return "domain"
    return "unknown"


def classify_ip(ip: str) -> str:
    """Classify an IP address as documentation, loopback, link_local,
    multicast, private or public. Documentation ranges are checked first
    because ipaddress folds them into is_private."""
    addr = ipaddress.ip_address(ip)
    for net in DOCUMENTATION_RANGES:
        if addr in net:
            return "documentation"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    return "public"


def reverse_dns(ip: str) -> str:
    """Reverse DNS lookup. Returns hostname, 'NXDOMAIN' on socket.herror
    or 'TIMEOUT' on socket.timeout. NXDOMAIN/TIMEOUT are expected for
    documentation IPs and must never fail the caller."""
    socket.setdefaulttimeout(3)
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "NXDOMAIN"
    except socket.timeout:
        return "TIMEOUT"


def check_feed(value: str, feed: dict) -> dict:
    """Look up value in the feed's malicious and benign collections.
    Returns membership flags plus flattened entry data when found."""
    result = {"in_malicious_feed": False, "in_benign_list": False}
    entry = feed.get("malicious_ips", {}).get(value)
    if entry is None:
        entry = feed.get("malicious_domains", {}).get(value)
    if entry is not None:
        result["in_malicious_feed"] = True
        for key in ("confidence", "category", "tags", "first_seen", "last_seen", "source"):
            if key in entry:
                result[key] = entry[key]
        return result
    if value in feed.get("benign_ips", []) or value in feed.get("benign_domains", []):
        result["in_benign_list"] = True
    return result


def score_ioc(feed_result: dict, ip_class: str) -> tuple:
    """Return (score, verdict) per the IOC scoring reference."""
    if feed_result.get("in_malicious_feed"):
        confidence = int(feed_result.get("confidence", 0))
        if confidence >= 80:
            return confidence, "BLOCK"
        return confidence, "INVESTIGATE"
    if feed_result.get("in_benign_list"):
        return 0, "ALLOW"
    if ip_class in ("private", "loopback"):
        return 0, "ALLOW"
    # Unknown public IP, unknown external domain, or any other
    # unclassified-but-parseable value.
    return 30, "INVESTIGATE"


def _load_feed(feed_path: str) -> dict:
    path = Path(feed_path)
    if not path.exists():
        # Fall back to the feed shipped alongside this module so the
        # playbook imports work regardless of the caller's cwd.
        alt = Path(__file__).resolve().parent / feed_path
        if alt.exists():
            path = alt
        else:
            raise FileNotFoundError(f"IOC feed not found: {feed_path}")
    return json.loads(path.read_text())


def enrich_ioc(value: str, feed_path: str = "ioc_feed.json") -> dict:
    """Main entry point. Returns the structured enrichment verdict for a
    single IOC. URLs are classified by their hostname; the original value
    is preserved in the 'ioc' field."""
    value = value.strip()
    ioc_type = detect_ioc_type(value)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Malformed input: preserve analyst review rather than fail silently.
    if ioc_type == "unknown":
        return {
            "ioc": value,
            "type": "unknown",
            "ip_class": "N/A",
            "reverse_dns": "N/A",
            "feed_result": {"in_malicious_feed": False, "in_benign_list": False},
            "score": 30,
            "verdict": "INVESTIGATE",
            "note": "Malformed or unrecognized IOC; manual review required",
            "enriched_at": now,
        }

    # Determine the classification/lookup target (hostname for URLs).
    hostname = urlparse(value).hostname if ioc_type == "url" else value
    hostname_type = detect_ioc_type(hostname)
    is_ip = hostname_type in ("ipv4", "ipv6")

    if is_ip:
        ip_class = classify_ip(hostname)
        reverse_dns_result = reverse_dns(hostname)
    else:
        ip_class = "N/A"
        reverse_dns_result = "N/A"

    feed_result = check_feed(hostname, _load_feed(feed_path))
    score, verdict = score_ioc(feed_result, ip_class)

    result = {
        "ioc": value,
        "type": ioc_type,
        "ip_class": ip_class,
        "reverse_dns": reverse_dns_result,
        "feed_result": feed_result,
        "score": score,
        "verdict": verdict,
    }
    if ip_class in ("private", "loopback"):
        result["note"] = "Private address range; internal network traffic"
    result["enriched_at"] = now
    return result


def _run_batch(batch_path: str, output_path: str, feed_path: str) -> None:
    """Enrich one IOC per line from batch_path; optionally write the JSON
    array of results to output_path and print a verdict summary."""
    with open(batch_path, encoding="utf-8") as fh:
        iocs = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    results = [enrich_ioc(ioc, feed_path) for ioc in iocs]

    if output_path:
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
            fh.write("\n")

    counts = {"BLOCK": 0, "INVESTIGATE": 0, "ALLOW": 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(
        f"Processed: {len(results)} | BLOCK: {counts['BLOCK']} | "
        f"INVESTIGATE: {counts['INVESTIGATE']} | ALLOW: {counts['ALLOW']}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IOC enrichment engine: classify an IP, domain or URL "
        "against the local MedDefense threat intel feed."
    )
    parser.add_argument("ioc", nargs="?", help="single IOC to enrich")
    parser.add_argument("--batch", metavar="FILE", help="file with one IOC per line")
    parser.add_argument("--output", metavar="FILE", help="write batch results as JSON")
    parser.add_argument("--feed", default="ioc_feed.json", help="path to ioc_feed.json")
    args = parser.parse_args()

    if args.batch:
        _run_batch(args.batch, args.output, args.feed)
    elif args.ioc:
        print(json.dumps(enrich_ioc(args.ioc, args.feed), indent=2))
    else:
        parser.error("provide an IOC or --batch FILE")


if __name__ == "__main__":
    main()
